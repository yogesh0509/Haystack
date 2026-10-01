//! A real wallet history on a local regtest chain, for testing `haystack-electrum` against a real
//! Electrum server instead of an in-memory fake or the honeypot.
//!
//! `bdk_testenv` starts `bitcoind` in regtest mode and `electrs` indexing it — the same setup
//! upstream `bdk_electrum` is tested against. Both binaries are downloaded at build time and checked
//! against SHA-256 hashes pinned in the `bitcoind` and `electrsd` crates (see `regtest/README.md`).
//!
//! `build_history` gives a BIP84 wallet the history a real one has: receives, address reuse, a
//! batched payout, an unpaid gap, a used address deep in the range, a spend with two inputs and
//! change, and unconfirmed transactions in both directions. The node's own wallet plays everyone
//! else. Regtest coins are worthless, so the wallet keeps private keys and signs its own spends.

use std::str::FromStr;
use std::time::{Duration, Instant};

use bdk_electrum::BdkElectrumClient;
use bdk_testenv::bitcoincore_rpc::RpcApi;
use bdk_wallet::bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bdk_wallet::bitcoin::hashes::{sha256, Hash};
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, Network, Script, Txid};
use bdk_wallet::{KeychainKind, SignOptions, Wallet};
use electrum_client::ElectrumApi;
use haystack_electrum::key::DecoyKey;

pub use bdk_testenv::TestEnv;

pub mod population;
pub mod proxy;

pub type Error = Box<dyn std::error::Error>;

pub const DEMO_SEED: &str = "haystack-regtest-demo";
pub const STOP_GAP: usize = 50;
const WAIT: Duration = Duration::from_secs(60);

/// A wallet with a real history on the regtest chain.
pub struct RealWallet {
    pub external: String,
    pub internal: String,
    pub account: Xpub,
    /// What happened, in order.
    pub story: Vec<String>,
}

impl RealWallet {
    /// A fresh, never-synced copy of the wallet, as after a restore from its descriptors.
    pub fn wallet(&self) -> Wallet {
        Wallet::create(self.external.clone(), self.internal.clone())
            .network(Network::Regtest)
            .create_wallet_no_persist()
            .expect("descriptors are valid")
    }

    pub fn decoy_key(&self) -> DecoyKey {
        DecoyKey::from_xpubs([self.account]).expect("one account xpub")
    }
}

pub fn start() -> Result<TestEnv, Error> {
    Ok(TestEnv::new()?)
}

/// A new connection to electrs, using this workspace's `electrum-client` (0.24.1). `bdk_testenv`'s
/// own client is 0.20, a different crate as far as the compiler is concerned.
pub fn electrum(env: &TestEnv) -> Result<electrum_client::Client, Error> {
    Ok(electrum_client::Client::new(&env.electrsd.electrum_url)?)
}

/// Mine `n` blocks to the node's wallet, then wait until electrs has indexed the new tip.
pub fn mine(env: &TestEnv, n: usize) -> Result<(), Error> {
    env.mine_blocks(n, None)?;
    wait_for_tip(env)
}

/// Wait until electrs's tip is the node's tip. Compares hashes, not heights: after a reorg the
/// height is unchanged while the block is not.
pub fn wait_for_tip(env: &TestEnv) -> Result<(), Error> {
    let client = electrum(env)?;
    let target = env.bitcoind.client.get_best_block_hash()?;
    let start = Instant::now();
    while start.elapsed() < WAIT {
        env.electrsd.trigger()?;
        if client.block_headers_subscribe()?.header.block_hash() == target {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err("electrs didn't reach the node's tip".into())
}

/// Wait until electrs lists `txid` in the history of `script`, so a scan will find it.
pub fn wait_for_history(env: &TestEnv, script: &Script, txid: Txid) -> Result<(), Error> {
    let client = electrum(env)?;
    let start = Instant::now();
    while start.elapsed() < WAIT {
        env.electrsd.trigger()?;
        if client
            .script_get_history(script)?
            .iter()
            .any(|h| h.tx_hash == txid)
        {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(format!("electrs never indexed {txid}").into())
}

/// A plain `bdk_electrum` full scan, applied to `wallet`.
pub fn sync_plain(env: &TestEnv, wallet: &mut Wallet) -> Result<(), Error> {
    let client = BdkElectrumClient::new(electrum(env)?);
    let update = client.full_scan(wallet.start_full_scan(), STOP_GAP, 5, false)?;
    wallet.apply_update(update)?;
    Ok(())
}

/// Someone else pays `address`; waits until electrs has indexed the payment.
pub fn pay(env: &TestEnv, address: &Address, btc: f64) -> Result<Txid, Error> {
    let txid = env.send(address, sats(btc))?;
    wait_for_history(env, &address.script_pubkey(), txid)?;
    Ok(txid)
}

pub fn external(wallet: &Wallet, index: u32) -> Address {
    wallet.peek_address(KeychainKind::External, index).address
}

/// The wallet pays someone else `btc`, choosing its own coins and change, and signs it. Returns
/// the transaction and how many inputs it spent.
pub fn spend(env: &TestEnv, wallet: &mut Wallet, btc: f64) -> Result<(Txid, u32), Error> {
    let to = env
        .bitcoind
        .client
        .get_new_address(None, None)?
        .assume_checked();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(to.script_pubkey(), sats(btc))
        .fee_rate(FeeRate::from_sat_per_vb(2).expect("valid rate"));
    let mut psbt = builder.finish()?;
    if !wallet.sign(&mut psbt, SignOptions::default())? {
        return Err("the wallet couldn't sign its own spend".into());
    }
    let tx = psbt.extract_tx()?;
    let inputs = tx.input.len() as u32;
    let change = tx
        .output
        .iter()
        .find(|o| wallet.is_mine(o.script_pubkey.clone()))
        .ok_or("the spend has no change output")?
        .script_pubkey
        .clone();
    let txid = env.bitcoind.client.send_raw_transaction(&tx)?;
    wait_for_history(env, &change, txid)?;
    Ok((txid, inputs))
}

/// A never-synced BIP84 wallet from a public seed string, with no history yet.
pub fn new_wallet(seed: &str) -> Result<RealWallet, Error> {
    let (external, internal, account) = descriptors(seed)?;
    Ok(RealWallet {
        external,
        internal,
        account,
        story: Vec::new(),
    })
}

/// BIP84 descriptors with private keys, from a public seed string. Regtest only: anyone can
/// derive these keys, and regtest coins are worthless.
fn descriptors(seed: &str) -> Result<(String, String, Xpub), Error> {
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(
        Network::Regtest,
        sha256::Hash::hash(seed.as_bytes()).as_byte_array(),
    )?;
    let account = Xpub::from_priv(
        &secp,
        &master.derive_priv(&secp, &DerivationPath::from_str("m/84'/1'/0'")?)?,
    );
    Ok((
        format!("wpkh({master}/84'/1'/0'/0/*)"),
        format!("wpkh({master}/84'/1'/0'/1/*)"),
        account,
    ))
}

/// Give a fresh wallet from `seed` a real history, and return it. The final state: 8 transactions;
/// external addresses 0, 1, 2, 5, 6 and 30 used; internal 0 and 1 used as change; two
/// transactions unconfirmed.
pub fn build_history(env: &TestEnv, seed: &str) -> Result<RealWallet, Error> {
    let (external_desc, internal_desc, account) = descriptors(seed)?;
    let rw = RealWallet {
        external: external_desc,
        internal: internal_desc,
        account,
        story: Vec::new(),
    };
    let mut story = Vec::new();
    let mut wallet = rw.wallet();

    // Coinbase outputs mature after 100 blocks, so the node can pay others from block 101 on.
    mine(env, 101)?;

    pay(env, &external(&wallet, 0), 0.5)?;
    pay(env, &external(&wallet, 1), 0.2)?;
    mine(env, 1)?;
    story.push("received 0.5 at external 0 and 0.2 at external 1; confirmed".into());

    pay(env, &external(&wallet, 0), 0.1)?;
    let a2 = external(&wallet, 2);
    let a5 = external(&wallet, 5);
    let batched: Txid = env.bitcoind.client.call(
        "sendmany",
        &[
            serde_json::json!(""),
            serde_json::json!({ a2.to_string(): 0.3, a5.to_string(): 0.05 }),
        ],
    )?;
    wait_for_history(env, &a5.script_pubkey(), batched)?;
    mine(env, 2)?;
    story.push(
        "received 0.1 at external 0 again (address reuse), and one payout of 0.3 to external 2 \
         and 0.05 to external 5; externals 3 and 4 never paid; confirmed"
            .into(),
    );

    pay(env, &external(&wallet, 30), 0.01)?;
    mine(env, 1)?;
    story.push("received 0.01 at external 30; confirmed".into());

    sync_plain(env, &mut wallet)?;
    let (_, inputs) = spend(env, &mut wallet, 0.6)?;
    if inputs < 2 {
        return Err("the 0.6 spend should need two inputs".into());
    }
    mine(env, 1)?;
    story.push(format!(
        "spent 0.6 using {inputs} inputs, change to internal 0; confirmed"
    ));

    sync_plain(env, &mut wallet)?;
    spend(env, &mut wallet, 0.05)?;
    story.push("spent 0.05, change to internal 1; left unconfirmed".into());

    pay(env, &external(&wallet, 6), 0.02)?;
    story.push("received 0.02 at external 6; left unconfirmed".into());

    Ok(RealWallet { story, ..rw })
}

/// `btc` rounded to whole satoshis; `Amount::from_btc` refuses anything more precise.
fn sats(btc: f64) -> Amount {
    Amount::from_sat((btc * 1e8).round() as u64)
}
