//! `full_scan` against an in-memory Electrum server, compared with upstream's `BdkElectrumClient`.
//!
//! The wallet: payments to external 3, external 49 and internal 0, all unconfirmed, so the scan
//! needs no block headers or merkle proofs. External 49 sits at the edge of the first 50 positions,
//! so it forces a second stage. Upstream's walk reaches external 0–99 and internal 0–50: 151 real
//! positions.

use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bdk_core::bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bdk_core::bitcoin::consensus::serialize;
use bdk_core::bitcoin::hashes::Hash;
use bdk_core::bitcoin::secp256k1::Secp256k1;
use bdk_core::bitcoin::{
    absolute, transaction, Amount, Network, OutPoint, Script, ScriptBuf, Transaction, TxIn, TxOut,
    Txid, WPubkeyHash,
};
use bdk_core::spk_client::{FullScanRequest, FullScanResponse};
use bdk_electrum::BdkElectrumClient;
use electrum_client::{
    Batch, ElectrumApi, Error, GetBalanceRes, GetHeadersRes, GetHistoryRes, GetMerkleRes,
    ListUnspentRes, Param, RawHeaderNotification, ScriptStatus, ServerFeaturesRes,
    ToElectrumScriptHash, TxidFromPosRes,
};
use bdk_core::bitcoin::constants::genesis_block;
use haystack_electrum::chain::ChainDecoys;
use haystack_electrum::client::{HaystackElectrumClient, LedgerStore};
use haystack_electrum::decoy::decoy_script;
use haystack_electrum::key::DecoyKey;
use haystack_electrum::keychain::Keychain;
use haystack_electrum::ledger::Ledger;
use haystack_electrum::ledger_file::{export, import, LedgerFile};
use haystack_electrum::session::{SessionLog, SessionRound};

const STOP_GAP: usize = 50;
const PAID: [(Keychain, u32); 3] = [
    (Keychain::External, 3),
    (Keychain::External, 49),
    (Keychain::Internal, 0),
];
const REALS: usize = 100 + 51;

fn real_spk(k: Keychain, i: u32) -> ScriptBuf {
    let mut seed = k.as_bytes().to_vec();
    seed.extend(i.to_be_bytes());
    ScriptBuf::new_p2wpkh(&WPubkeyHash::hash(&seed))
}

fn request() -> FullScanRequest<Keychain> {
    let spks = |k: Keychain| (0u32..).map(move |i| (i, real_spk(k, i)));
    FullScanRequest::builder()
        .spks_for_keychain(Keychain::External, spks(Keychain::External))
        .spks_for_keychain(Keychain::Internal, spks(Keychain::Internal))
        .build()
}

fn key() -> DecoyKey {
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(Network::Bitcoin, b"haystack-test-seed").unwrap();
    let path = DerivationPath::from_str("m/84'/0'/0'").unwrap();
    DecoyKey::from_xpubs([Xpub::from_priv(
        &secp,
        &master.derive_priv(&secp, &path).unwrap(),
    )])
    .unwrap()
}

fn pay_to(script: &ScriptBuf, n: u8) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([n + 1; 32]), 0),
            ..Default::default()
        }],
        output: vec![TxOut {
            value: Amount::from_sat(10_000 + n as u64),
            script_pubkey: script.clone(),
        }],
    }
}

#[derive(Default)]
struct FakeServer {
    history: HashMap<ScriptBuf, Vec<GetHistoryRes>>,
    txs: HashMap<Txid, Transaction>,
    batches: Mutex<Vec<Vec<ScriptBuf>>>,
    batch_count: Arc<AtomicUsize>,
    tx_requests: Mutex<Vec<Txid>>,
    /// Receive this many batches, then drop the connection on the next.
    fail_after: Option<usize>,
    /// Transaction ids by height and position, for `txid_from_pos`; position 0 is the coinbase.
    blocks: Vec<Vec<Txid>>,
}

impl FakeServer {
    fn with_payments(scripts: impl IntoIterator<Item = ScriptBuf>) -> Self {
        let mut server = Self::default();
        for (n, script) in scripts.into_iter().enumerate() {
            let tx = pay_to(&script, n as u8);
            let txid = tx.compute_txid();
            server
                .history
                .entry(script)
                .or_default()
                .push(GetHistoryRes {
                    height: 0,
                    tx_hash: txid,
                    fee: None,
                });
            server.txs.insert(txid, tx);
        }
        server
    }

    fn wallet() -> Self {
        Self::with_payments(PAID.iter().map(|&(k, i)| real_spk(k, i)))
    }

    /// Other people's payments in `heights` blocks of `per_block` transactions each, unconfirmed
    /// so the scan needs no proofs. Every seventh recipient has 25 transactions, more than a chain
    /// decoy may have; the rest have one.
    fn with_chain(mut self, heights: u32, per_block: u32) -> Self {
        self.blocks.push(vec![Txid::all_zeros()]);
        for h in 1..=heights {
            let mut block = vec![Txid::all_zeros()];
            for p in 1..=per_block {
                let script = other_spk(h, p);
                let mut tx = pay_to(&script, 0);
                tx.input[0].previous_output = OutPoint::new(
                    Txid::hash(&[h.to_be_bytes(), p.to_be_bytes()].concat()),
                    0,
                );
                let txid = tx.compute_txid();
                let heavy = (h * per_block + p).is_multiple_of(7);
                let mut history = vec![GetHistoryRes { height: 0, tx_hash: txid, fee: None }];
                if heavy {
                    history.extend((1..25u32).map(|n| GetHistoryRes {
                        height: 0,
                        tx_hash: Txid::hash(&[txid.to_byte_array().as_slice(), &n.to_be_bytes()].concat()),
                        fee: None,
                    }));
                }
                self.history.insert(script, history);
                self.txs.insert(txid, tx);
                block.push(txid);
            }
            self.blocks.push(block);
        }
        self
    }

    fn queried(&self) -> Vec<ScriptBuf> {
        self.batches.lock().unwrap().concat()
    }
}

fn other_spk(height: u32, pos: u32) -> ScriptBuf {
    let seed = [b"someone else".as_slice(), &height.to_be_bytes(), &pos.to_be_bytes()].concat();
    ScriptBuf::new_p2wpkh(&WPubkeyHash::hash(&seed))
}

fn txids(r: &FullScanResponse<Keychain>) -> BTreeSet<Txid> {
    r.tx_update.txs.iter().map(|tx| tx.compute_txid()).collect()
}

fn seen(r: &FullScanResponse<Keychain>) -> BTreeSet<Txid> {
    r.tx_update.seen_ats.iter().map(|(txid, _)| *txid).collect()
}

#[test]
fn padded_scan_gives_upstreams_wallet_data() {
    let upstream = BdkElectrumClient::new(FakeServer::wallet())
        .full_scan(request(), STOP_GAP, 5, false)
        .unwrap();
    for padding in [1, 10] {
        let ours = HaystackElectrumClient::new(FakeServer::wallet(), key(), padding)
            .full_scan(request(), STOP_GAP, 50, false)
            .unwrap();
        assert_eq!(txids(&ours), txids(&upstream), "padding {padding}");
        assert_eq!(seen(&ours), seen(&upstream), "padding {padding}");
        assert_eq!(ours.tx_update.anchors, upstream.tx_update.anchors);
        assert_eq!(ours.last_active_indices, upstream.last_active_indices);
    }
    assert_eq!(
        upstream.last_active_indices,
        BTreeMap::from([(Keychain::External, 49), (Keychain::Internal, 0)])
    );
}

#[test]
fn padding_one_queries_exactly_upstreams_scripts() {
    // Upstream with batch size 1, so its batching sends nothing past the stop point.
    let up_server = FakeServer::wallet();
    let _ = BdkElectrumClient::new(&up_server)
        .full_scan(request(), STOP_GAP, 1, false)
        .unwrap();
    let our_server = FakeServer::wallet();
    let _ = HaystackElectrumClient::new(&our_server, key(), 1)
        .full_scan(request(), STOP_GAP, 50, false)
        .unwrap();
    let up: BTreeSet<_> = up_server.queried().into_iter().collect();
    let ours: BTreeSet<_> = our_server.queried().into_iter().collect();
    assert_eq!(up.len(), REALS);
    assert_eq!(ours, up);
}

fn all_reals() -> BTreeSet<ScriptBuf> {
    [(Keychain::External, 0..100), (Keychain::Internal, 0..51)]
        .into_iter()
        .flat_map(|(k, range)| range.map(move |i| real_spk(k, i)))
        .collect()
}

#[test]
fn server_sees_every_real_among_ten_times_as_many() {
    let server = FakeServer::wallet();
    let _ = HaystackElectrumClient::new(&server, key(), 10)
        .full_scan(request(), STOP_GAP, 50, false)
        .unwrap();
    let queried = server.queried();
    assert_eq!(queried.len(), REALS * 10);
    assert_eq!(queried.iter().collect::<BTreeSet<_>>().len(), REALS * 10);
    assert!(all_reals().iter().all(|r| queried.contains(r)));
    assert!(server.batches.lock().unwrap().iter().all(|b| b.len() <= 50));
}

#[test]
fn where_the_reals_sit_in_the_query_is_unpredictable() {
    // Any fixed order leaks: reals first, or each real followed by its own nine decoys (every
    // tenth script real). Two independent scans must put the reals in different places.
    let real_slots = || {
        let server = FakeServer::wallet();
        let _ = HaystackElectrumClient::new(&server, key(), 10)
            .full_scan(request(), STOP_GAP, 50, false)
            .unwrap();
        let reals = all_reals();
        server
            .queried()
            .iter()
            .enumerate()
            .filter(|(_, s)| reals.contains(*s))
            .map(|(i, _)| i)
            .collect::<Vec<_>>()
    };
    assert_ne!(real_slots(), real_slots());
}

#[test]
fn second_scan_sends_the_same_scripts() {
    let server = FakeServer::wallet();
    let client = HaystackElectrumClient::new(&server, key(), 10);
    let _ = client.full_scan(request(), STOP_GAP, 50, false).unwrap();
    let first: BTreeSet<_> = server.queried().into_iter().collect();
    server.batches.lock().unwrap().clear();
    let _ = client.full_scan(request(), STOP_GAP, 50, false).unwrap();
    let second: BTreeSet<_> = server.queried().into_iter().collect();
    // Nothing vanishes and nothing appears, so intersecting rounds removes no decoy.
    assert_eq!(first, second);
    assert_eq!(client.ledger().confirmed().count(), REALS);
}

#[test]
fn raising_the_dial_leaves_frozen_positions_alone() {
    let server = FakeServer::wallet();
    let ledger = {
        let client = HaystackElectrumClient::new(&server, key(), 10);
        let _ = client.full_scan(request(), STOP_GAP, 50, false).unwrap();
        let ledger = client.ledger();
        let mut copy = Ledger::new(&key());
        for (pos, n) in ledger.confirmed() {
            copy.freeze(pos, n);
        }
        copy
    };
    server.batches.lock().unwrap().clear();
    let _ = HaystackElectrumClient::new(&server, key(), 20)
        .with_ledger(ledger)
        .unwrap()
        .full_scan(request(), STOP_GAP, 50, false)
        .unwrap();
    assert_eq!(server.queried().len(), REALS * 10);
}

#[test]
fn a_ledger_from_another_key_is_refused() {
    let other = DecoyKey::from_xpubs([Xpub::from_priv(
        &Secp256k1::new(),
        &Xpriv::new_master(Network::Bitcoin, b"some-other-wallet!").unwrap(),
    )])
    .unwrap();
    let result = HaystackElectrumClient::new(FakeServer::wallet(), key(), 10)
        .with_ledger(Ledger::new(&other));
    assert!(result.is_err());
}

#[test]
fn a_decoy_with_history_is_fetched_like_a_real_and_then_dropped() {
    let decoy = decoy_script(
        &key(),
        &real_spk(Keychain::External, 7),
        Keychain::External,
        7,
        0,
    )
    .unwrap();
    let server = FakeServer::with_payments(
        PAID.iter()
            .map(|&(k, i)| real_spk(k, i))
            .chain([decoy.clone()]),
    );
    let decoy_txid = server.history[&decoy][0].tx_hash;
    let response = HaystackElectrumClient::new(&server, key(), 10)
        .full_scan(request(), STOP_GAP, 50, false)
        .unwrap();
    assert!(server.tx_requests.lock().unwrap().contains(&decoy_txid));
    assert!(!txids(&response).contains(&decoy_txid));
    assert!(!seen(&response).contains(&decoy_txid));
}

#[derive(Clone, Default)]
struct MemoryLog(Arc<Mutex<Vec<SessionRound>>>);

impl SessionLog for MemoryLog {
    fn record(&self, round: &SessionRound) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.0.lock().unwrap().push(round.clone());
        Ok(())
    }
}

#[test]
fn session_log_matches_what_the_server_received() {
    let server = FakeServer::wallet();
    let log = MemoryLog::default();
    let _ = HaystackElectrumClient::new(&server, key(), 10)
        .with_session_log(log.clone())
        .full_scan(request(), STOP_GAP, 50, false)
        .unwrap();
    let rounds = log.0.lock().unwrap();
    assert_eq!(rounds.len(), 1);
    let round = &rounds[0];
    assert_eq!((round.error.as_deref(), round.padding), (None, 10));

    // Query for query, in send order, the same scripthashes the server received.
    let sent: Vec<[u8; 32]> = server
        .queried()
        .iter()
        .map(|s| *s.to_electrum_scripthash())
        .collect();
    let logged: Vec<[u8; 32]> = round.queries.iter().map(|q| q.scripthash).collect();
    assert_eq!(logged, sent);

    // Tags: 151 reals, each with decoys 0-8.
    let mut per_position: BTreeMap<(Keychain, u32), Vec<Option<u32>>> = BTreeMap::new();
    for q in &round.queries {
        per_position
            .entry((q.keychain, q.index))
            .or_default()
            .push(q.decoy);
    }
    assert_eq!(per_position.len(), REALS);
    for tags in per_position.values_mut() {
        tags.sort();
        assert_eq!(
            *tags,
            [None]
                .into_iter()
                .chain((0..9).map(Some))
                .collect::<Vec<_>>()
        );
    }

    // Answers: one transaction for each paid real, none for anything else.
    for q in &round.queries {
        let paid = q.decoy.is_none() && PAID.contains(&(q.keychain, q.index));
        assert_eq!(q.tx_count, Some(usize::from(paid)), "{q:?}");
        assert_eq!(q.script_type, "p2wpkh");
    }

    // Stage 1 is 1,000 scripts, stage 2 the other 510; batches of at most 50, numbered in order.
    let in_stage = |n| round.queries.iter().filter(|q| q.stage == n).count();
    assert_eq!((in_stage(0), in_stage(1)), (1000, 510));
    let batches = server.batches.lock().unwrap();
    let mut offset = 0;
    for (b, batch) in batches.iter().enumerate() {
        assert!(round.queries[offset..offset + batch.len()]
            .iter()
            .all(|q| q.batch == b as u32));
        offset += batch.len();
    }
}

#[test]
fn a_failed_round_is_still_logged() {
    let server = FakeServer {
        fail_after: Some(3),
        ..FakeServer::wallet()
    };
    let log = MemoryLog::default();
    let result = HaystackElectrumClient::new(&server, key(), 10)
        .with_session_log(log.clone())
        .full_scan(request(), STOP_GAP, 50, false);
    assert!(result.is_err());
    let rounds = log.0.lock().unwrap();
    let round = &rounds[0];
    assert!(round
        .error
        .as_deref()
        .unwrap()
        .contains("connection dropped"));
    // Four batches reached the server; the fourth got no answer.
    assert_eq!(round.queries.len(), 200);
    assert!(round.queries[..150].iter().all(|q| q.tx_count.is_some()));
    assert!(round.queries[150..].iter().all(|q| q.tx_count.is_none()));
}

#[test]
fn the_ledger_file_carries_every_decoy_across_a_restart() {
    let dir = std::env::temp_dir().join(format!("haystack-restart-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ledger.json");
    let server = FakeServer::wallet();
    let scan = |client: HaystackElectrumClient<&FakeServer>| {
        server.batches.lock().unwrap().clear();
        let _ = client.full_scan(request(), STOP_GAP, 50, false).unwrap();
        server.queried().into_iter().collect::<BTreeSet<_>>()
    };

    let before =
        scan(HaystackElectrumClient::new(&server, key(), 10).with_store(LedgerFile::new(&path)));
    let file: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        file["keychains"]["external"],
        serde_json::json!([{ "from": 0, "to": 99, "decoys": 9 }])
    );
    assert_eq!(
        file["keychains"]["internal"],
        serde_json::json!([{ "from": 0, "to": 50, "decoys": 9 }])
    );

    // A restart with the file, even with the dial now lowered to 5: nothing changes on the wire.
    let restored = LedgerFile::new(&path).load(&key()).unwrap().unwrap();
    let with_file = scan(
        HaystackElectrumClient::new(&server, key(), 5)
            .with_ledger(restored)
            .unwrap(),
    );
    assert_eq!(with_file, before);

    // The same restart without the file: every position keeps decoys 0-3 and drops 4-8, so 5 of
    // its 9 decoys vanish — 151 × 5 = 755 withdrawals, each one exposed by intersecting rounds.
    let without_file = scan(HaystackElectrumClient::new(&server, key(), 5));
    assert!(without_file.is_subset(&before));
    assert_eq!(before.difference(&without_file).count(), REALS * 5);
    std::fs::remove_dir_all(&dir).unwrap();
}

struct RecordingStore {
    batches_sent: Arc<AtomicUsize>,
    saves: Arc<Mutex<Vec<(usize, usize)>>>,
}

impl LedgerStore for RecordingStore {
    fn save(&self, ledger: &Ledger) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.saves.lock().unwrap().push((
            self.batches_sent.load(Ordering::SeqCst),
            ledger.confirmed().count(),
        ));
        Ok(())
    }
}

#[test]
fn ledger_is_saved_before_the_batches_that_use_it() {
    let server = FakeServer::wallet();
    let saves = Arc::new(Mutex::new(Vec::new()));
    let _ = HaystackElectrumClient::new(&server, key(), 10)
        .with_store(RecordingStore {
            batches_sent: Arc::clone(&server.batch_count),
            saves: Arc::clone(&saves),
        })
        .full_scan(request(), STOP_GAP, 50, false)
        .unwrap();
    // Stage 1 freezes 100 positions before any batch; its 1,000 scripts go out as 20 batches of
    // 50; stage 2 freezes 51 more before its own batches.
    assert_eq!(*saves.lock().unwrap(), vec![(0, 100), (20, REALS)]);
}

impl ElectrumApi for FakeServer {
    fn batch_script_get_history<'s, I>(&self, scripts: I) -> Result<Vec<Vec<GetHistoryRes>>, Error>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<&'s Script>,
    {
        let scripts: Vec<ScriptBuf> = scripts
            .into_iter()
            .map(|s| (*s.borrow()).to_owned())
            .collect();
        let answers = scripts
            .iter()
            .map(|s| self.history.get(s).cloned().unwrap_or_default())
            .collect();
        self.batches.lock().unwrap().push(scripts);
        let received = self.batch_count.fetch_add(1, Ordering::SeqCst);
        if Some(received) == self.fail_after {
            return Err(Error::Message("connection dropped".into()));
        }
        Ok(answers)
    }

    fn transaction_get_raw(&self, txid: &Txid) -> Result<Vec<u8>, Error> {
        self.tx_requests.lock().unwrap().push(*txid);
        Ok(serialize(&self.txs[txid]))
    }

    fn batch_transaction_get_raw<'t, I>(&self, txids: I) -> Result<Vec<Vec<u8>>, Error>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<&'t Txid>,
    {
        txids
            .into_iter()
            .map(|t| self.transaction_get_raw(t.borrow()))
            .collect()
    }

    fn raw_call(
        &self,
        _: &str,
        _: impl IntoIterator<Item = Param>,
    ) -> Result<serde_json::Value, Error> {
        unimplemented!()
    }
    fn batch_call(&self, _: &Batch) -> Result<Vec<serde_json::Value>, Error> {
        unimplemented!()
    }
    fn block_headers_subscribe_raw(&self) -> Result<RawHeaderNotification, Error> {
        Ok(RawHeaderNotification {
            height: self.blocks.len().saturating_sub(1),
            header: serialize(&genesis_block(Network::Regtest).header),
        })
    }
    fn block_headers_pop_raw(&self) -> Result<Option<RawHeaderNotification>, Error> {
        unimplemented!()
    }
    fn block_header_raw(&self, _: usize) -> Result<Vec<u8>, Error> {
        unimplemented!()
    }
    fn block_headers(&self, _: usize, _: usize) -> Result<GetHeadersRes, Error> {
        unimplemented!()
    }
    fn estimate_fee(&self, _: usize) -> Result<f64, Error> {
        unimplemented!()
    }
    fn relay_fee(&self) -> Result<f64, Error> {
        unimplemented!()
    }
    fn script_subscribe(&self, _: &Script) -> Result<Option<ScriptStatus>, Error> {
        unimplemented!()
    }
    fn batch_script_subscribe<'s, I>(&self, _: I) -> Result<Vec<Option<ScriptStatus>>, Error>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<&'s Script>,
    {
        unimplemented!()
    }
    fn script_unsubscribe(&self, _: &Script) -> Result<bool, Error> {
        unimplemented!()
    }
    fn script_pop(&self, _: &Script) -> Result<Option<ScriptStatus>, Error> {
        unimplemented!()
    }
    fn script_get_balance(&self, _: &Script) -> Result<GetBalanceRes, Error> {
        unimplemented!()
    }
    fn batch_script_get_balance<'s, I>(&self, _: I) -> Result<Vec<GetBalanceRes>, Error>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<&'s Script>,
    {
        unimplemented!()
    }
    fn script_get_history(&self, script: &Script) -> Result<Vec<GetHistoryRes>, Error> {
        Ok(self.history.get(script).cloned().unwrap_or_default())
    }
    fn script_list_unspent(&self, _: &Script) -> Result<Vec<ListUnspentRes>, Error> {
        unimplemented!()
    }
    fn batch_script_list_unspent<'s, I>(&self, _: I) -> Result<Vec<Vec<ListUnspentRes>>, Error>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<&'s Script>,
    {
        unimplemented!()
    }
    fn batch_block_header_raw<I>(&self, _: I) -> Result<Vec<Vec<u8>>, Error>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<u32>,
    {
        unimplemented!()
    }
    fn batch_estimate_fee<I>(&self, _: I) -> Result<Vec<f64>, Error>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<usize>,
    {
        unimplemented!()
    }
    fn transaction_broadcast_raw(&self, _: &[u8]) -> Result<Txid, Error> {
        unimplemented!()
    }
    fn transaction_get_merkle(&self, _: &Txid, _: usize) -> Result<GetMerkleRes, Error> {
        unimplemented!()
    }
    fn batch_transaction_get_merkle<I>(&self, _: I) -> Result<Vec<GetMerkleRes>, Error>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<(Txid, usize)>,
    {
        unimplemented!()
    }
    fn txid_from_pos(&self, height: usize, pos: usize) -> Result<Txid, Error> {
        self.blocks
            .get(height)
            .and_then(|b| b.get(pos))
            .copied()
            .ok_or_else(|| Error::Protocol(serde_json::json!("no transaction at that position")))
    }
    fn txid_from_pos_with_merkle(&self, _: usize, _: usize) -> Result<TxidFromPosRes, Error> {
        unimplemented!()
    }
    fn server_features(&self) -> Result<ServerFeaturesRes, Error> {
        unimplemented!()
    }
    fn ping(&self) -> Result<(), Error> {
        unimplemented!()
    }
}

fn chain_server() -> FakeServer {
    FakeServer::wallet().with_chain(200, 10)
}

fn chain_client(server: &FakeServer) -> HaystackElectrumClient<&FakeServer> {
    HaystackElectrumClient::new(server, key(), 10).with_chain_decoys(ChainDecoys::new(0.3))
}

#[test]
fn chain_decoys_have_history_and_never_reach_the_wallet() {
    let upstream = BdkElectrumClient::new(FakeServer::wallet())
        .full_scan(request(), STOP_GAP, 5, false)
        .unwrap();
    let server = chain_server();
    let log = MemoryLog::default();
    let ours = chain_client(&server)
        .with_session_log(log.clone())
        .full_scan(request(), STOP_GAP, 50, false)
        .unwrap();
    assert_eq!(txids(&ours), txids(&upstream));
    assert_eq!(seen(&ours), seen(&upstream));
    assert_eq!(ours.last_active_indices, upstream.last_active_indices);

    let rounds = log.0.lock().unwrap();
    let round = &rounds[0];
    assert_eq!(round.chain_share, 0.3);
    let chain: Vec<_> = round
        .queries
        .iter()
        .filter(|q| q.source == Some("chain"))
        .collect();
    // 151 positions x 9 decoys x 0.3 = 407.7 expected, give or take the keyed rounding.
    assert!((350..=460).contains(&chain.len()), "{} chain decoys", chain.len());
    assert!(chain
        .iter()
        .all(|q| matches!(q.tx_count, Some(n) if (1..=ChainDecoys::DEFAULT_MAX_HISTORY).contains(&n))));
    assert_eq!(
        chain.iter().map(|q| q.scripthash).collect::<BTreeSet<_>>().len(),
        chain.len(),
        "no chain decoy is used twice"
    );
    // The leak this design accepts: the server checked each chain decoy's history before it
    // was queried, in a lookup no real wallet makes.
    let checked: BTreeSet<[u8; 32]> = round
        .probes
        .iter()
        .filter_map(|p| match p {
            haystack_electrum::chain::Probe::History { scripthash, kept: true, .. } => Some(*scripthash),
            _ => None,
        })
        .collect();
    assert!(chain.iter().all(|q| checked.contains(&q.scripthash)));
    assert!(round.probes.iter().any(|p| matches!(
        p,
        haystack_electrum::chain::Probe::History { tx_count: 25, kept: false, .. }
    )));
}

#[test]
fn chain_decoys_are_frozen_like_any_other() {
    let server = chain_server();
    let log = MemoryLog::default();
    let client = chain_client(&server).with_session_log(log.clone());
    let _ = client.full_scan(request(), STOP_GAP, 50, false).unwrap();
    let first: BTreeSet<_> = server.queried().into_iter().collect();
    server.batches.lock().unwrap().clear();
    let _ = client.full_scan(request(), STOP_GAP, 50, false).unwrap();
    let second: BTreeSet<_> = server.queried().into_iter().collect();
    assert_eq!(first, second);
    assert!(log.0.lock().unwrap()[1].probes.is_empty(), "nothing new to find");

    // Across a restart, through the ledger file.
    let text = export(&client.into_ledger());
    assert!(text.contains("haystack-ledger/2"));
    let restarted = chain_client(&server)
        .with_ledger(import(&text, &key()).unwrap())
        .unwrap();
    server.batches.lock().unwrap().clear();
    let _ = restarted.full_scan(request(), STOP_GAP, 50, false).unwrap();
    assert_eq!(server.queried().into_iter().collect::<BTreeSet<_>>(), first);
}

#[test]
fn chain_decoys_refuse_prevout_fetching() {
    let server = chain_server();
    assert!(chain_client(&server)
        .full_scan(request(), STOP_GAP, 50, true)
        .is_err());
    assert!(server.queried().is_empty());
}

#[derive(Clone, Default)]
struct MemoryCache(Arc<Mutex<Option<haystack_electrum::cache_file::SavedCache>>>);

impl haystack_electrum::cache_file::CacheStore for MemoryCache {
    fn save(
        &self,
        cache: &haystack_electrum::cache_file::SavedCache,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        *self.0.lock().unwrap() = Some(cache.clone());
        Ok(())
    }
}

#[test]
fn a_restart_with_the_saved_cache_refetches_nothing_real_or_decoy() {
    let server = chain_server();
    let store = MemoryCache::default();
    let first = chain_client(&server).with_cache_store(store.clone());
    let _ = first.full_scan(request(), STOP_GAP, 50, false).unwrap();
    let fetched: BTreeSet<Txid> = server.tx_requests.lock().unwrap().drain(..).collect();
    let real_txids: BTreeSet<Txid> = PAID
        .iter()
        .flat_map(|&(k, i)| server.history[&real_spk(k, i)].iter().map(|h| h.tx_hash))
        .collect();
    assert!(real_txids.is_subset(&fetched));
    assert!(fetched.len() > real_txids.len(), "decoy transactions were fetched too");
    let ledger = export(&first.into_ledger());

    // Restarted with the cache: the server sees no transaction fetch at all.
    let saved = store.0.lock().unwrap().clone().expect("saved after the scan");
    let _ = chain_client(&server)
        .with_ledger(import(&ledger, &key()).unwrap())
        .unwrap()
        .with_saved_cache(saved)
        .full_scan(request(), STOP_GAP, 50, false)
        .unwrap();
    assert!(server.tx_requests.lock().unwrap().is_empty());

    // Restarted without it: reals and decoys are refetched together, never one kind alone.
    let _ = chain_client(&server)
        .with_ledger(import(&ledger, &key()).unwrap())
        .unwrap()
        .full_scan(request(), STOP_GAP, 50, false)
        .unwrap();
    let refetched: BTreeSet<Txid> = server.tx_requests.lock().unwrap().drain(..).collect();
    // The probes' own transaction fetches came first and are gone; the follow-ups repeat exactly.
    assert!(real_txids.is_subset(&refetched));
    assert!(refetched.is_subset(&fetched));
}
