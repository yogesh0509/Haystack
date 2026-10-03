//! The demo wallet's own wallet code: `bdk_wallet`'s `examples/electrum.rs` (the 3.1.0 release's
//! copy, which compiles unchanged against the 2.1.0 this repo builds on), with Haystack swapped in.
//!
//! The roadmap allows exactly five kinds of change (`docs/04-roadmap.md`, Week 2, "Public API"),
//! and each one is marked below with `CHANGE n`:
//!
//! 1. the client construction line, which also takes the decoy key, the dial, the ledger file and
//!    the saved cache file (and here the session log the live score reads);
//! 2. each `sync` call becomes a full scan;
//! 3. broadcasts go to a different server than the one the wallet syncs with;
//! 4. the transaction cache is never pre-filled from the wallet's own transactions;
//! 5. each scan also passes the wallet's expected unconfirmed transactions, so one that left the
//!    mempool leaves the balance, as after upstream's `sync`.
//!
//! Everything else keeps the example's calls: `Wallet::load` / `Wallet::create`,
//! `next_unused_address`, `start_full_scan`, `STOP_GAP`, `BATCH_SIZE`,
//! `apply_update`, `persist`, and the transaction builder. What is restructured is only the order:
//! the example runs top to bottom once, and the demo calls the same steps when the page or the
//! timer asks. `demo/README.md` lists every line against the example's.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bdk_wallet::bitcoin::{Amount, FeeRate, Network, ScriptBuf, Transaction, Txid};
use bdk_wallet::rusqlite::Connection;
use bdk_wallet::{KeychainKind, PersistedWallet, SignOptions, Wallet};
use haystack_electrum::cache_file::CacheFile;
use haystack_electrum::chain::ChainDecoys;
use haystack_electrum::client::HaystackElectrumClient;
use haystack_electrum::key::DecoyKey;
use haystack_electrum::ledger_file::LedgerFile;
use haystack_electrum::session::{JsonLinesFile, SessionLog, SessionRound};

use crate::transport::{self, CertStatus, Counter, Endpoint, PinFile};

// The example's own constants. BATCH_SIZE counts real addresses' worth per write, so at padding 10
// each write carries 50 scripts (`haystack-electrum/src/client.rs`, `full_scan`).
pub const STOP_GAP: usize = 50;
pub const BATCH_SIZE: usize = 5;

/// The example's `wallet`: a `Wallet` that persists to SQLite.
pub type DemoWallet = PersistedWallet<Connection>;

/// The wallet's two descriptors and network: the example's `EXTERNAL_DESC`, `INTERNAL_DESC` and
/// `NETWORK`, given at run time because the demo has two wallets.
#[derive(Clone)]
pub struct Descriptors {
    pub external: String,
    pub internal: String,
    pub network: Network,
}

/// Where one wallet profile keeps its files.
#[derive(Clone)]
pub struct Files {
    pub db: PathBuf,
    pub ledger: PathBuf,
    pub cache: PathBuf,
    pub session: PathBuf,
}

impl Files {
    pub fn in_dir(dir: &Path) -> Self {
        Self {
            db: dir.join("wallet.sqlite"),
            ledger: dir.join("ledger.json"),
            cache: dir.join("cache.json"),
            session: dir.join("session.jsonl"),
        }
    }
}

/// The example's lines 26–38, unchanged.
pub fn open(files: &Files, d: &Descriptors) -> anyhow::Result<(Connection, DemoWallet)> {
    let mut db = Connection::open(&files.db)?;
    let wallet_opt = Wallet::load()
        .descriptor(KeychainKind::External, Some(d.external.clone()))
        .descriptor(KeychainKind::Internal, Some(d.internal.clone()))
        .extract_keys()
        .check_network(d.network)
        .load_wallet(&mut db)?;
    let wallet = match wallet_opt {
        Some(wallet) => wallet,
        None => Wallet::create(d.external.clone(), d.internal.clone())
            .network(d.network)
            .create_wallet(&mut db)?,
    };
    Ok((db, wallet))
}

/// The example's lines 40–41, unchanged.
pub fn next_address(db: &mut Connection, wallet: &mut DemoWallet) -> anyhow::Result<ScriptBuf> {
    let address = wallet.next_unused_address(KeychainKind::External);
    wallet.persist(db)?;
    Ok(address.script_pubkey())
}

/// The Haystack settings that change 1 adds to the client construction line.
pub struct Haystack<'a> {
    pub endpoint: &'a Endpoint,
    pub pins: &'a PinFile,
    pub key: &'a DecoyKey,
    pub padding: u32,
    pub chain_share: f64,
}

/// What one sync did, for the page.
pub struct Synced {
    pub sent: u64,
    pub received: u64,
    pub queries: usize,
    pub reals: usize,
    pub cert: Option<CertStatus>,
}

/// A session log that also remembers the last round's counts.
struct Tee {
    file: JsonLinesFile,
    last: Arc<Mutex<Option<(usize, usize)>>>,
}

impl SessionLog for Tee {
    fn record(&self, round: &SessionRound) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let reals = round.queries.iter().filter(|q| q.decoy.is_none()).count();
        *self.last.lock().unwrap() = Some((round.queries.len(), reals));
        self.file.record(round)
    }
}

/// The example's full scan (lines 47–71), and each of its syncs (lines 101–120 and 154–167).
pub fn sync(
    db: &mut Connection,
    wallet: &mut DemoWallet,
    files: &Files,
    h: Haystack,
) -> anyhow::Result<Synced> {
    // CHANGE 1: the client construction line. Example line 48:
    //   let client = BdkElectrumClient::new(electrum_client::Client::new(ELECTRUM_URL)?);
    let counter = Counter::default();
    let last = Arc::new(Mutex::new(None));
    let (inner, cert) = transport::connect(h.endpoint, h.pins, counter.clone())?;
    let mut client = HaystackElectrumClient::new(inner, h.key.clone(), h.padding)
        .with_chain_decoys(ChainDecoys::new(h.chain_share))
        .with_store(LedgerFile::new(&files.ledger))
        .with_saved_cache(CacheFile::new(&files.cache).load()?)
        .with_cache_store(CacheFile::new(&files.cache))
        .with_session_log(Tee {
            file: JsonLinesFile::new(&files.session),
            last: last.clone(),
        });
    if let Some(ledger) = LedgerFile::new(&files.ledger).load(h.key)? {
        client = client
            .with_ledger(ledger)
            .map_err(|e| anyhow::anyhow!("the ledger file belongs to another wallet: {e:?}"))?;
    }

    // CHANGE 4: no `client.populate_tx_cache(...)` (example lines 52 and 116). The client's cache
    // is filled only by its own fetches and saved across restarts, for reals and decoys alike.

    // CHANGE 2: the example's syncs (lines 117 and 156) are full scans, like its first scan.
    let request = wallet.start_full_scan();
    // CHANGE 5: a full-scan request can't say which unconfirmed transactions the wallet counts, so
    // the request the example passed to `sync` goes along too, and an expected transaction the
    // server no longer lists is marked evicted. Nothing extra is sent.
    let expected = wallet.start_sync_with_revealed_spks();
    let update = client.full_scan_expecting(request, expected, STOP_GAP, BATCH_SIZE, false);
    let (sent, received) = counter.totals();
    let (queries, reals) = last.lock().unwrap().unwrap_or((0, 0));
    let update = update?;

    wallet.apply_update(update)?;
    wallet.persist(db)?;
    Ok(Synced {
        sent,
        received,
        queries,
        reals,
        cert,
    })
}

/// The example's spend (lines 86–99): build, sign, extract and broadcast.
pub fn send(
    wallet: &mut Wallet,
    to: ScriptBuf,
    amount: Amount,
    broadcast: impl FnOnce(&Transaction) -> anyhow::Result<Txid>,
) -> anyhow::Result<Txid> {
    let target_fee_rate = FeeRate::from_sat_per_vb(1).unwrap();
    let mut tx_builder = wallet.build_tx();
    tx_builder.add_recipient(to, amount);
    tx_builder.fee_rate(target_fee_rate);

    let mut psbt = tx_builder.finish()?;
    let finalized = wallet.sign(&mut psbt, SignOptions::default())?;
    assert!(finalized);
    let tx = psbt.extract_tx()?;
    // CHANGE 3: example line 97, `client.transaction_broadcast(&tx)?`, sends the transaction to
    // the server the wallet syncs with, which ties it to the session. The demo broadcasts through
    // a different server: on regtest, bitcoind's own RPC.
    broadcast(&tx)
}
