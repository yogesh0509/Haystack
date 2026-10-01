//! The saved cache: every transaction and merkle proof the client has fetched, kept across
//! restarts, for reals and decoys alike (`docs/02-design.md`, "haystack-electrum").
//!
//! The cache exists for privacy, not speed. The client fetches only what its cache lacks. A cache
//! filled from the wallet's own stored transactions, as `bdk_wallet`'s example does, would hold
//! real transactions only. After a restart the client would then refetch every decoy transaction
//! and no real one, which picks out exactly the funded reals. So this cache is filled only by the
//! client itself, from what it actually fetched, and the crate has no `populate_tx_cache`.
//!
//! Block headers are not saved. They are cached by height, and after a reorganisation a saved
//! header would point a proof lookup at a block that is no longer on the chain. Proofs are saved
//! under their block's hash, so a reorganised block misses the cache and is proven again.
//!
//! ```text
//! {"format":"haystack-cache/1","txs":["<raw transaction hex>",…],
//!  "anchors":[{"txid":"…","block":"…","height":812,"time":1700000000},…]}
//! ```

use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use bdk_core::bitcoin::consensus::{deserialize, serialize};
use bdk_core::bitcoin::hex::{DisplayHex, FromHex};
use bdk_core::bitcoin::{BlockHash, Transaction, Txid};
use bdk_core::{BlockId, ConfirmationBlockTime};
use serde_json::{json, Value};

use crate::ledger_file::write_atomically;

const FORMAT: &str = "haystack-cache/1";

/// What the client has fetched, ready to save or to hand to a new client.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SavedCache {
    pub txs: Vec<Arc<Transaction>>,
    pub anchors: Vec<(Txid, ConfirmationBlockTime)>,
}

/// Durable storage for the cache. The client saves after every scan, finished or not.
pub trait CacheStore: Send + Sync {
    fn save(&self, cache: &SavedCache) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

#[derive(Debug)]
pub enum CacheFileError {
    Io(std::io::Error),
    Format(String),
}

impl fmt::Display for CacheFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "cache file: {e}"),
            Self::Format(why) => write!(f, "cache file: {why}"),
        }
    }
}

impl std::error::Error for CacheFileError {}

impl From<std::io::Error> for CacheFileError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

fn bad(why: impl Into<String>) -> CacheFileError {
    CacheFileError::Format(why.into())
}

pub fn export(cache: &SavedCache) -> String {
    let txs: Vec<Value> = cache
        .txs
        .iter()
        .map(|tx| Value::String(serialize(tx.as_ref()).to_lower_hex_string()))
        .collect();
    let anchors: Vec<Value> = cache
        .anchors
        .iter()
        .map(|(txid, a)| {
            json!({
                "txid": txid.to_string(),
                "block": a.block_id.hash.to_string(),
                "height": a.block_id.height,
                "time": a.confirmation_time,
            })
        })
        .collect();
    json!({ "format": FORMAT, "txs": txs, "anchors": anchors }).to_string()
}

/// Rebuild a cache from `export`'s output. Every transaction is stored whole, so its id is
/// recomputed rather than trusted.
pub fn import(text: &str) -> Result<SavedCache, CacheFileError> {
    let doc: Value = serde_json::from_str(text).map_err(|e| bad(format!("not JSON: {e}")))?;
    if doc["format"] != FORMAT {
        return Err(bad(format!("format is {}, expected {FORMAT}", doc["format"])));
    }
    let mut cache = SavedCache::default();
    for t in doc["txs"].as_array().ok_or_else(|| bad("txs is not a list"))? {
        let bytes = t
            .as_str()
            .and_then(|h| Vec::<u8>::from_hex(h).ok())
            .ok_or_else(|| bad("a transaction is not hex"))?;
        let tx: Transaction =
            deserialize(&bytes).map_err(|e| bad(format!("a transaction doesn't parse: {e}")))?;
        cache.txs.push(Arc::new(tx));
    }
    for a in doc["anchors"].as_array().ok_or_else(|| bad("anchors is not a list"))? {
        let txid = a["txid"]
            .as_str()
            .and_then(|s| Txid::from_str(s).ok())
            .ok_or_else(|| bad("an anchor has no valid txid"))?;
        let hash = a["block"]
            .as_str()
            .and_then(|s| BlockHash::from_str(s).ok())
            .ok_or_else(|| bad("an anchor has no valid block"))?;
        let height = a["height"]
            .as_u64()
            .and_then(|h| u32::try_from(h).ok())
            .ok_or_else(|| bad("an anchor has no valid height"))?;
        let time = a["time"].as_u64().ok_or_else(|| bad("an anchor has no valid time"))?;
        cache.anchors.push((
            txid,
            ConfirmationBlockTime {
                block_id: BlockId { height, hash },
                confirmation_time: time,
            },
        ));
    }
    Ok(cache)
}

/// The cache file at one path.
pub struct CacheFile {
    path: PathBuf,
}

impl CacheFile {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// An empty cache if there is no file yet.
    pub fn load(&self) -> Result<SavedCache, CacheFileError> {
        match fs::read_to_string(&self.path) {
            Ok(text) => import(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(SavedCache::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self, cache: &SavedCache) -> Result<(), CacheFileError> {
        write_atomically(&self.path, export(cache).as_bytes())?;
        Ok(())
    }
}

impl CacheStore for CacheFile {
    fn save(&self, cache: &SavedCache) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        CacheFile::save(self, cache).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_core::bitcoin::hashes::Hash;
    use bdk_core::bitcoin::{
        absolute, transaction, Amount, OutPoint, ScriptBuf, TxIn, TxOut, WPubkeyHash,
    };

    fn tx(n: u8) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([n; 32]), 0),
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000 + n as u64),
                script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([n; 20])),
            }],
        }
    }

    #[test]
    fn round_trips() {
        let a = tx(1);
        let cache = SavedCache {
            txs: vec![Arc::new(a.clone()), Arc::new(tx(2))],
            anchors: vec![(
                a.compute_txid(),
                ConfirmationBlockTime {
                    block_id: BlockId { height: 812, hash: BlockHash::from_byte_array([9; 32]) },
                    confirmation_time: 1_700_000_000,
                },
            )],
        };
        assert_eq!(import(&export(&cache)).unwrap(), cache);
    }

    #[test]
    fn refuses_another_format_and_bad_transactions() {
        let text = export(&SavedCache { txs: vec![Arc::new(tx(1))], anchors: vec![] });
        assert!(import(&text.replace(FORMAT, "haystack-cache/9")).is_err());
        assert!(import(&text.replace("\"txs\":[\"", "\"txs\":[\"zz")).is_err());
    }

    #[test]
    fn a_missing_file_is_an_empty_cache_and_a_saved_one_loads() {
        let dir = std::env::temp_dir().join(format!("haystack-cache-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let file = CacheFile::new(dir.join("cache.json"));
        assert_eq!(file.load().unwrap(), SavedCache::default());
        let cache = SavedCache { txs: vec![Arc::new(tx(3))], anchors: vec![] };
        file.save(&cache).unwrap();
        assert_eq!(file.load().unwrap(), cache);
        fs::remove_dir_all(&dir).unwrap();
    }
}
