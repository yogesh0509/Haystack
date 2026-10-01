//! Chain-sourced decoys, found through the sync server itself (decided).
//!
//! A decoy with history has to be a real address someone else used, so the client finds one on the
//! chain: a transaction at a random height and position, one of its outputs of the real script's
//! type, and that output's history, which must be between 1 and `max_history` transactions.
//!
//! **This leaks, and the leak is accepted for now.** Every lookup here goes to the server the wallet
//! syncs with, and a real wallet never makes them: it only fetches transactions that appeared in
//! its own addresses' histories. A server that reads its own log can match "fetched a random
//! transaction, checked an output's history" against "queried that output" and name every chain
//! decoy, which leaves a restored wallet's funded addresses as exposed as with HMAC-direct decoys
//! alone (`docs/02-design.md`, "Where decoys come from"). The lookups are recorded as `Probe`s in
//! the session log, so that attack can be written later; the harness doesn't read them yet.
//!
//! The draws are deterministic per position and decoy number, from the decoy key, but the result
//! also depends on the chain, so a chosen script is stored in the ledger rather than recomputed.

use bdk_core::bitcoin::hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
use bdk_core::bitcoin::{Script, ScriptBuf, Txid};
use bdk_core::collections::HashSet;
use electrum_client::{ElectrumApi, Error, ToElectrumScriptHash};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::key::DecoyKey;
use crate::keychain::Keychain;

/// How many blocks to try before giving up on one decoy and using an HMAC-direct one instead.
const BLOCKS_PER_DECOY: u32 = 16;
/// Highest transaction position tried first; halved after each miss, down to 1.
const FIRST_POSITION_BOUND: usize = 4096;

/// The dial for chain-sourced decoys.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ChainDecoys {
    /// Share of each new position's decoys taken from the chain, from 0 to 1.
    pub share: f64,
    /// A candidate with more history than this is refused. This also marks out where only reals
    /// can be: a funded real address with more history than this is never matched by a decoy.
    pub max_history: usize,
}

impl ChainDecoys {
    pub const DEFAULT_MAX_HISTORY: usize = 20;

    pub fn new(share: f64) -> Self {
        Self {
            share: share.clamp(0.0, 1.0),
            max_history: Self::DEFAULT_MAX_HISTORY,
        }
    }
}

/// One lookup the server saw while a decoy was being found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    /// `blockchain.transaction.id_from_pos`; `txid` is `None` if the server had no transaction there.
    Position { height: u32, pos: u32, txid: Option<Txid> },
    /// `blockchain.transaction.get` for the transaction just found.
    Transaction { txid: Txid },
    /// `blockchain.scripthash.get_history` for a candidate, and whether it became a decoy.
    History { scripthash: [u8; 32], tx_count: usize, kept: bool },
}

/// How many of a new position's `count` decoys come from the chain: `share × count`, with the
/// fractional part rounded up or down by a keyed draw, so the expected count is exact and the same
/// key always gives the same answer.
pub fn chain_count(key: &DecoyKey, keychain: Keychain, index: u32, count: u32, share: f64) -> u32 {
    let exact = share.clamp(0.0, 1.0) * count as f64;
    let whole = exact.floor() as u32;
    let u = rng(key, b"count", keychain, index, 0).gen::<f64>();
    (whole + u32::from(u < exact - whole as f64)).min(count)
}

/// Finds decoy `j` of a position on the chain, for a real script of `real`'s type. `None` if no
/// acceptable candidate turned up within `BLOCKS_PER_DECOY` blocks. A server refusal ("no
/// transaction at that position") is a miss; any other error is returned, ending the sync.
#[allow(clippy::too_many_arguments)]
pub fn find<E: ElectrumApi>(
    client: &E,
    key: &DecoyKey,
    real: &Script,
    keychain: Keychain,
    index: u32,
    j: u32,
    tip: u32,
    exclude: &HashSet<ScriptBuf>,
    config: ChainDecoys,
    probes: &mut Vec<Probe>,
) -> Result<Option<ScriptBuf>, Error> {
    if tip == 0 {
        return Ok(None);
    }
    let mut rng = rng(key, b"draw", keychain, index, j);
    for _ in 0..BLOCKS_PER_DECOY {
        let height = rng.gen_range(1..=tip);
        let Some(txid) = transaction_at(client, height, &mut rng, probes)? else {
            continue;
        };
        let tx = client.transaction_get(&txid)?;
        probes.push(Probe::Transaction { txid });
        let candidates: Vec<&ScriptBuf> = tx
            .output
            .iter()
            .map(|o| &o.script_pubkey)
            .filter(|s| same_type(s, real) && !exclude.contains(*s))
            .collect();
        if candidates.is_empty() {
            continue;
        }
        let candidate = candidates[rng.gen_range(0..candidates.len())].clone();
        let tx_count = client.script_get_history(&candidate)?.len();
        let kept = (1..=config.max_history).contains(&tx_count);
        probes.push(Probe::History {
            scripthash: *candidate.to_electrum_scripthash(),
            tx_count,
            kept,
        });
        if kept {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

/// A transaction other than the coinbase at `height`. Electrum can't say how many transactions a
/// block has, so this tries a random position below a bound and halves the bound after each miss.
fn transaction_at<E: ElectrumApi>(
    client: &E,
    height: u32,
    rng: &mut StdRng,
    probes: &mut Vec<Probe>,
) -> Result<Option<Txid>, Error> {
    let mut bound = FIRST_POSITION_BOUND;
    while bound >= 1 {
        let pos = rng.gen_range(1..=bound);
        match client.txid_from_pos(height as usize, pos) {
            Ok(txid) => {
                probes.push(Probe::Position { height, pos: pos as u32, txid: Some(txid) });
                return Ok(Some(txid));
            }
            Err(Error::Protocol(_)) => {
                probes.push(Probe::Position { height, pos: pos as u32, txid: None });
                bound /= 2;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

fn same_type(a: &Script, b: &Script) -> bool {
    (a.is_p2wpkh() && b.is_p2wpkh())
        || (a.is_p2wsh() && b.is_p2wsh())
        || (a.is_p2tr() && b.is_p2tr())
        || (a.is_p2pkh() && b.is_p2pkh())
        || (a.is_p2sh() && b.is_p2sh())
}

fn rng(key: &DecoyKey, purpose: &[u8], keychain: Keychain, index: u32, j: u32) -> StdRng {
    let mut engine = HmacEngine::<sha256::Hash>::new(key.as_bytes());
    engine.input(b"haystack/chain/");
    engine.input(purpose);
    engine.input(keychain.as_bytes());
    engine.input(&index.to_be_bytes());
    engine.input(&j.to_be_bytes());
    StdRng::from_seed(Hmac::<sha256::Hash>::from_engine(engine).to_byte_array())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_count_is_exact_in_expectation_and_reproducible() {
        let key = DecoyKey::for_tests(b"wallet");
        let total: u32 = (0..1000)
            .map(|i| chain_count(&key, Keychain::External, i, 9, 0.1))
            .sum();
        // 1000 positions x 9 decoys x 0.1 = 900 expected.
        assert!((850..=950).contains(&total), "{total}");
        for i in 0..20 {
            assert_eq!(
                chain_count(&key, Keychain::External, i, 9, 0.1),
                chain_count(&key, Keychain::External, i, 9, 0.1)
            );
        }
    }

    #[test]
    fn chain_count_bounds() {
        let key = DecoyKey::for_tests(b"wallet");
        for i in 0..50 {
            assert_eq!(chain_count(&key, Keychain::Internal, i, 9, 0.0), 0);
            assert_eq!(chain_count(&key, Keychain::Internal, i, 9, 1.0), 9);
            assert_eq!(chain_count(&key, Keychain::Internal, i, 0, 0.5), 0);
        }
    }
}
