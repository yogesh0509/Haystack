//! `HaystackElectrumClient`: `BdkElectrumClient::full_scan` with decoys.
//!
//! Same caches, chain-tip handling and merkle-proof checks as `bdk_electrum` 0.23.2. It differs by
//! driving the scan in stages via the planner: each stage sends every real script together with its
//! frozen decoys in shuffled batches, and only real answers reach the response.
//!
//! No `sync` and no `transaction_broadcast`. Every sync is a full scan, since a revealed-only sync
//! would drop the unused tail and its decoys, and broadcasting through this session's server would
//! tie the transaction to it (`docs/01-threat-model.md`).

use std::sync::{Arc, Mutex, MutexGuard};

use bdk_core::bitcoin::{block::Header, BlockHash, ScriptBuf, Transaction, Txid};
use bdk_core::collections::{BTreeMap, HashMap, HashSet};
use bdk_core::spk_client::{FullScanRequest, FullScanResponse};
use bdk_core::{BlockId, CheckPoint, ConfirmationBlockTime, TxUpdate};
use electrum_client::{ElectrumApi, Error, HeaderNotification, ToElectrumScriptHash};
use rand::seq::SliceRandom;

use crate::decoy::decoys_for;
use crate::key::DecoyKey;
use crate::keychain::{DecoyKeychain, Keychain};
use crate::ledger::{KeyMismatch, Ledger, Position};
use crate::planner::RoundPlanner;
use crate::session::{script_type, LoggedQuery, SessionLog, SessionRound};

const CHAIN_SUFFIX_LENGTH: u32 = 8;

/// The `batch_size` to pass to `full_scan`: five reals' worth of scripts per write, matching
/// `bdk_wallet`'s own unpadded ratio (5 scripts per write). 50 at padding 10.
pub fn recommended_batch_size(padding: u32) -> usize {
    5 * padding.max(1) as usize
}

/// Durable storage for the ledger. `save` runs after new positions are frozen and before any batch
/// carrying them leaves the device, so a crash can't later hand a position a different decoy set.
pub trait LedgerStore: Send + Sync {
    fn save(&self, ledger: &Ledger) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

enum Tag {
    Real(Position),
    Decoy(Position, u32),
}

pub struct HaystackElectrumClient<E> {
    pub inner: E,
    decoy_key: DecoyKey,
    decoys_per_position: u32,
    ledger: Mutex<Ledger>,
    store: Option<Box<dyn LedgerStore>>,
    session_log: Option<Box<dyn SessionLog>>,
    padding: u32,
    tx_cache: Mutex<HashMap<Txid, Arc<Transaction>>>,
    block_header_cache: Mutex<HashMap<u32, Header>>,
    anchor_cache: Mutex<HashMap<(Txid, BlockHash), ConfirmationBlockTime>>,
}

impl<E: ElectrumApi> HaystackElectrumClient<E> {
    /// `padding` is the dial: scripts queried per real address. 1 is plain Electrum; 10 sends nine
    /// decoys with each real script. Starts with an empty ledger; `with_ledger` restores one.
    pub fn new(client: E, decoy_key: DecoyKey, padding: u32) -> Self {
        let ledger = Ledger::new(&decoy_key);
        Self {
            inner: client,
            decoy_key,
            decoys_per_position: padding.saturating_sub(1),
            ledger: Mutex::new(ledger),
            store: None,
            session_log: None,
            padding: padding.max(1),
            tx_cache: Default::default(),
            block_header_cache: Default::default(),
            anchor_cache: Default::default(),
        }
    }

    pub fn with_ledger(mut self, ledger: Ledger) -> Result<Self, KeyMismatch> {
        ledger.check_key(&self.decoy_key)?;
        self.ledger = Mutex::new(ledger);
        Ok(self)
    }

    pub fn with_store(mut self, store: impl LedgerStore + 'static) -> Self {
        self.store = Some(Box::new(store));
        self
    }

    pub fn with_session_log(mut self, log: impl SessionLog + 'static) -> Self {
        self.session_log = Some(Box::new(log));
        self
    }

    pub fn ledger(&self) -> MutexGuard<'_, Ledger> {
        self.ledger.lock().unwrap()
    }

    /// Hands the ledger back, e.g. to carry it to the client of the next connection.
    pub fn into_ledger(self) -> Ledger {
        self.ledger.into_inner().unwrap()
    }

    /// Same as `BdkElectrumClient::populate_tx_cache`.
    pub fn populate_tx_cache(&self, txs: impl IntoIterator<Item = impl Into<Arc<Transaction>>>) {
        let mut cache = self.tx_cache.lock().unwrap();
        for tx in txs {
            let tx = tx.into();
            cache.insert(tx.compute_txid(), tx);
        }
    }

    /// Same signature and meaning as `BdkElectrumClient::full_scan`. `batch_size` is scripts per
    /// request batch, reals and decoys together; see `recommended_batch_size`. With a session log set, the round is recorded
    /// whether or not it succeeds, and a failure to record it is returned as an error.
    pub fn full_scan<K: DecoyKeychain>(
        &self,
        request: impl Into<FullScanRequest<K>>,
        stop_gap: usize,
        batch_size: usize,
        fetch_prev_txouts: bool,
    ) -> Result<FullScanResponse<K>, Error> {
        let request: FullScanRequest<K> = request.into();
        let mut round = SessionRound {
            started: request.start_time(),
            padding: self.padding,
            stop_gap,
            batch_size,
            queries: Vec::new(),
            error: None,
        };
        let result = self.scan(request, stop_gap, batch_size, fetch_prev_txouts, &mut round);
        if let Some(log) = &self.session_log {
            if let Err(e) = &result {
                round.error = Some(e.to_string());
            }
            log.record(&round)
                .map_err(|e| message(format!("session log not written: {e}")))?;
        }
        result
    }

    fn scan<K: DecoyKeychain>(
        &self,
        mut request: FullScanRequest<K>,
        stop_gap: usize,
        batch_size: usize,
        fetch_prev_txouts: bool,
        round: &mut SessionRound,
    ) -> Result<FullScanResponse<K>, Error> {
        let start_time = request.start_time();

        let tip_and_latest_blocks = match request.chain_tip() {
            Some(chain_tip) => Some(fetch_tip_and_latest_blocks(&self.inner, chain_tip)?),
            None => None,
        };

        let mut keychains = BTreeMap::<Keychain, K>::new();
        for k in request.keychains() {
            if keychains.insert(k.keychain(), k).is_some() {
                return Err(message(
                    "two request keychains map to one Haystack keychain",
                ));
            }
        }

        let mut ledger = self.ledger.lock().unwrap();
        let mut planner = RoundPlanner::new(
            stop_gap,
            keychains.keys().copied(),
            &ledger,
            &self.decoy_key,
        )
        .map_err(|e| message(format!("cannot plan the round: {e:?}")))?;

        let mut spks = BTreeMap::<Keychain, Vec<ScriptBuf>>::new();
        let mut tx_update = TxUpdate::<ConfirmationBlockTime>::default();
        let mut real_anchors = Vec::<(Txid, usize)>::new();
        let mut decoy_anchors = Vec::<(Txid, usize)>::new();

        let mut batch_no = 0u32;
        for stage_no in 0u32.. {
            let stage = planner.next_stage();
            if stage.is_empty() {
                break;
            }

            let mut items = Vec::<(Tag, ScriptBuf)>::new();
            let mut froze_new = false;
            for (kc, index) in stage {
                let pulled = spks.entry(kc).or_default();
                let Some(real) = pull_spk(&mut request, &keychains[&kc], pulled, index)? else {
                    planner.exhausted(kc, pulled.len() as u32);
                    continue;
                };
                let frozen = ledger.get((kc, index));
                let count = frozen.unwrap_or(self.decoys_per_position);
                let decoys =
                    decoys_for(&self.decoy_key, &real, kc, index, count).ok_or_else(|| {
                        message(format!("no decoy shape for the script at {kc:?}/{index}"))
                    })?;
                if frozen.is_none() {
                    ledger.freeze((kc, index), count);
                    froze_new = true;
                }
                items.push((Tag::Real((kc, index)), real));
                items.extend(
                    (0u32..)
                        .zip(decoys)
                        .map(|(j, d)| (Tag::Decoy((kc, index), j), d)),
                );
            }

            if froze_new {
                if let Some(store) = &self.store {
                    store
                        .save(&ledger)
                        .map_err(|e| message(format!("ledger not saved, nothing sent: {e}")))?;
                }
            }

            items.shuffle(&mut rand::thread_rng());

            let mut real_txids = Vec::<Txid>::new();
            let mut decoy_txids = Vec::<Txid>::new();
            for chunk in items.chunks(batch_size.max(1)) {
                // Logged before sending: if the call fails, these still reached the server.
                let logged_from = round.queries.len();
                round.queries.extend(chunk.iter().map(|(tag, script)| {
                    let ((keychain, index), decoy) = match *tag {
                        Tag::Real(pos) => (pos, None),
                        Tag::Decoy(pos, j) => (pos, Some(j)),
                    };
                    LoggedQuery {
                        scripthash: *script.to_electrum_scripthash(),
                        stage: stage_no,
                        batch: batch_no,
                        keychain,
                        index,
                        decoy,
                        script_type: script_type(script),
                        tx_count: None,
                    }
                }));
                batch_no += 1;
                let histories = self
                    .inner
                    .batch_script_get_history(chunk.iter().map(|(_, s)| s.as_script()))?;
                if histories.len() != chunk.len() {
                    return Err(message("server answered a different number of scripts"));
                }
                for (q, history) in round.queries[logged_from..].iter_mut().zip(&histories) {
                    q.tx_count = Some(history.len());
                }
                for ((tag, _), history) in chunk.iter().zip(histories) {
                    match tag {
                        Tag::Real(pos) => {
                            planner.record(*pos, !history.is_empty());
                            for res in history {
                                real_txids.push(res.tx_hash);
                                match res.height.try_into() {
                                    // Heights 0 and -1 mean unconfirmed.
                                    Ok(height) if height > 0 => {
                                        real_anchors.push((res.tx_hash, height))
                                    }
                                    _ => {
                                        tx_update.seen_ats.insert((res.tx_hash, start_time));
                                    }
                                }
                            }
                        }
                        // A decoy hit gets the same follow-up fetches a real one would, so the
                        // call pattern doesn't separate them; its data is dropped here.
                        Tag::Decoy(..) => {
                            for res in history {
                                decoy_txids.push(res.tx_hash);
                                if let Ok(height) = usize::try_from(res.height) {
                                    if height > 0 {
                                        decoy_anchors.push((res.tx_hash, height));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let fetched = self.fetch_txs(real_txids.iter().chain(&decoy_txids))?;
            tx_update
                .txs
                .extend(real_txids.iter().map(|txid| Arc::clone(&fetched[txid])));
        }
        drop(ledger);

        if fetch_prev_txouts {
            self.fetch_prev_txouts(&mut tx_update)?;
        }

        if !real_anchors.is_empty() || !decoy_anchors.is_empty() {
            let real: HashSet<Txid> = real_anchors.iter().map(|(txid, _)| *txid).collect();
            let mut all = real_anchors;
            all.extend(decoy_anchors);
            for (txid, anchor) in self.batch_fetch_anchors(&all)? {
                if real.contains(&txid) {
                    tx_update.anchors.insert((anchor, txid));
                }
            }
        }

        let chain_update = match tip_and_latest_blocks {
            Some((chain_tip, latest_blocks)) => Some(chain_update(
                chain_tip,
                &latest_blocks,
                tx_update.anchors.iter().cloned(),
            )?),
            None => None,
        };

        let last_active_indices = planner
            .last_active_indices()
            .into_iter()
            .map(|(kc, index)| (keychains[&kc].clone(), index))
            .collect();

        Ok(FullScanResponse {
            tx_update,
            chain_update,
            last_active_indices,
        })
    }

    /// Cache hits first, then one batched request for the rest. Rejects a transaction whose id
    /// differs from the one asked for (ported from `bdk_electrum` master; 0.23.2 has no check).
    fn fetch_txs<'a>(
        &self,
        txids: impl Iterator<Item = &'a Txid>,
    ) -> Result<HashMap<Txid, Arc<Transaction>>, Error> {
        let mut found = HashMap::<Txid, Arc<Transaction>>::new();
        let mut missing = Vec::<Txid>::new();
        {
            let cache = self.tx_cache.lock().unwrap();
            let mut seen = HashSet::new();
            for &txid in txids {
                if !seen.insert(txid) {
                    continue;
                }
                match cache.get(&txid) {
                    Some(tx) => {
                        found.insert(txid, Arc::clone(tx));
                    }
                    None => missing.push(txid),
                }
            }
        }
        if missing.is_empty() {
            return Ok(found);
        }
        let txs = self.inner.batch_transaction_get(missing.iter())?;
        if txs.len() != missing.len() {
            return Err(message(
                "server answered a different number of transactions",
            ));
        }
        let mut cache = self.tx_cache.lock().unwrap();
        for (txid, tx) in missing.into_iter().zip(txs) {
            if tx.compute_txid() != txid {
                return Err(message(format!(
                    "server answered {txid} with a different transaction"
                )));
            }
            let tx = Arc::new(tx);
            cache.insert(txid, Arc::clone(&tx));
            found.insert(txid, tx);
        }
        Ok(found)
    }

    fn fetch_prev_txouts(
        &self,
        tx_update: &mut TxUpdate<ConfirmationBlockTime>,
    ) -> Result<(), Error> {
        let mut outpoints = Vec::new();
        let mut seen = HashSet::new();
        for tx in &tx_update.txs {
            if !tx.is_coinbase() && seen.insert(tx.compute_txid()) {
                outpoints.extend(tx.input.iter().map(|vin| vin.previous_output));
            }
        }
        let prev = self.fetch_txs(outpoints.iter().map(|op| &op.txid))?;
        for op in outpoints {
            let txout = prev[&op.txid]
                .output
                .get(op.vout as usize)
                .ok_or_else(|| message(format!("prevout {op} does not exist")))?
                .clone();
            tx_update.txouts.insert(op, txout);
        }
        Ok(())
    }

    /// Copied from `bdk_electrum` 0.23.2 `batch_fetch_anchors` (line 475).
    fn batch_fetch_anchors(
        &self,
        txs_with_heights: &[(Txid, usize)],
    ) -> Result<Vec<(Txid, ConfirmationBlockTime)>, Error> {
        let mut results = Vec::with_capacity(txs_with_heights.len());
        let mut to_fetch = Vec::new();

        let mut needed_heights: Vec<u32> =
            txs_with_heights.iter().map(|&(_, h)| h as u32).collect();
        needed_heights.sort_unstable();
        needed_heights.dedup();

        let mut height_to_hash = HashMap::with_capacity(needed_heights.len());
        {
            let mut cache = self.block_header_cache.lock().unwrap();
            let mut missing_heights = Vec::new();
            for &height in &needed_heights {
                if let Some(header) = cache.get(&height) {
                    height_to_hash.insert(height, header.block_hash());
                } else {
                    missing_heights.push(height);
                }
            }
            if !missing_heights.is_empty() {
                let headers = self.inner.batch_block_header(missing_heights.clone())?;
                for (height, header) in missing_heights.into_iter().zip(headers) {
                    height_to_hash.insert(height, header.block_hash());
                    cache.insert(height, header);
                }
            }
        }

        {
            let anchor_cache = self.anchor_cache.lock().unwrap();
            for &(txid, height) in txs_with_heights {
                let hash = height_to_hash[&(height as u32)];
                if let Some(anchor) = anchor_cache.get(&(txid, hash)) {
                    results.push((txid, *anchor));
                } else {
                    to_fetch.push((txid, height));
                }
            }
        }

        let proofs = self.inner.batch_transaction_get_merkle(to_fetch.iter())?;
        for ((txid, height), proof) in to_fetch.into_iter().zip(proofs) {
            let mut header = {
                let cache = self.block_header_cache.lock().unwrap();
                cache
                    .get(&(height as u32))
                    .copied()
                    .expect("header already fetched above")
            };
            let mut valid =
                electrum_client::utils::validate_merkle_proof(&txid, &header.merkle_root, &proof);
            if !valid {
                header = self.inner.block_header(height)?;
                self.block_header_cache
                    .lock()
                    .unwrap()
                    .insert(height as u32, header);
                valid = electrum_client::utils::validate_merkle_proof(
                    &txid,
                    &header.merkle_root,
                    &proof,
                );
            }
            if valid {
                let hash = header.block_hash();
                let anchor = ConfirmationBlockTime {
                    confirmation_time: header.time as u64,
                    block_id: BlockId {
                        height: height as u32,
                        hash,
                    },
                };
                self.anchor_cache
                    .lock()
                    .unwrap()
                    .insert((txid, hash), anchor);
                results.push((txid, anchor));
            }
        }
        Ok(results)
    }
}

/// The spk for `index`, pulling from the request's iterator as far as needed. `None` once the
/// descriptor has no more positions. The request must yield positions from 0 in steps of one;
/// anything else would misalign positions and the ledger.
fn pull_spk<K: DecoyKeychain>(
    request: &mut FullScanRequest<K>,
    keychain: &K,
    pulled: &mut Vec<ScriptBuf>,
    index: u32,
) -> Result<Option<ScriptBuf>, Error> {
    while pulled.len() <= index as usize {
        match request.next_spk(keychain.clone()) {
            Some((i, spk)) if i as usize == pulled.len() => pulled.push(spk),
            Some((i, _)) => {
                return Err(message(format!(
                    "request skipped from position {} to {i}",
                    pulled.len()
                )))
            }
            None => return Ok(None),
        }
    }
    Ok(Some(pulled[index as usize].clone()))
}

fn message(text: impl Into<String>) -> Error {
    Error::Message(text.into())
}

/// Copied from `bdk_electrum` 0.23.2 (line 608).
fn fetch_tip_and_latest_blocks(
    client: &impl ElectrumApi,
    prev_tip: CheckPoint,
) -> Result<(CheckPoint, BTreeMap<u32, BlockHash>), Error> {
    let HeaderNotification { height, .. } = client.block_headers_subscribe()?;
    let new_tip_height = height as u32;

    if new_tip_height < prev_tip.height() {
        return Ok((prev_tip, BTreeMap::new()));
    }

    let mut new_blocks = {
        let start_height = new_tip_height.saturating_sub(CHAIN_SUFFIX_LENGTH - 1);
        let hashes = client
            .block_headers(start_height as _, CHAIN_SUFFIX_LENGTH as _)?
            .headers
            .into_iter()
            .map(|h| h.block_hash());
        (start_height..).zip(hashes).collect::<BTreeMap<u32, _>>()
    };

    let agreement_cp = {
        let mut agreement_cp = Option::<CheckPoint>::None;
        for cp in prev_tip.iter() {
            let cp_block = cp.block_id();
            let hash = match new_blocks.get(&cp_block.height) {
                Some(&hash) => hash,
                None => {
                    assert!(
                        new_tip_height >= cp_block.height,
                        "already checked that electrum's tip cannot be smaller"
                    );
                    let hash = client.block_header(cp_block.height as _)?.block_hash();
                    new_blocks.insert(cp_block.height, hash);
                    hash
                }
            };
            if hash == cp_block.hash {
                agreement_cp = Some(cp);
                break;
            }
        }
        agreement_cp.ok_or_else(|| message("cannot find agreement block with server"))?
    };

    let extension = new_blocks
        .iter()
        .filter({
            let agreement_height = agreement_cp.height();
            move |(height, _)| **height > agreement_height
        })
        .map(|(&height, &hash)| BlockId { height, hash });
    let new_tip = agreement_cp
        .extend(extension)
        .expect("extension heights already checked to be greater than agreement height");

    Ok((new_tip, new_blocks))
}

/// Copied from `bdk_electrum` 0.23.2 (line 675).
fn chain_update(
    mut tip: CheckPoint,
    latest_blocks: &BTreeMap<u32, BlockHash>,
    anchors: impl Iterator<Item = (ConfirmationBlockTime, Txid)>,
) -> Result<CheckPoint, Error> {
    for (anchor, _txid) in anchors {
        let height = anchor.block_id.height;
        if tip.get(height).is_none() && height <= tip.height() {
            let hash = match latest_blocks.get(&height) {
                Some(&hash) => hash,
                None => anchor.block_id.hash,
            };
            tip = tip.insert(BlockId { hash, height });
        }
    }
    Ok(tip)
}
