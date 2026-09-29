//! The session log: what one sync sent, what the server answered, and which queries were real.
//!
//! The client is the only party that knows both the server's answers and which queries were real,
//! so it writes both halves of the attack harness's input into one record. `attack/observe.py`'s
//! `load_session` reads it.
//!
//! One JSON object per line, one line per round, appended (`haystack-session/1`):
//!
//! ```text
//! {"format":"haystack-session/1","started":…,"padding":10,"stop_gap":50,"batch_size":50,
//!  "error":null,"queries":[{"sh":"…","stage":0,"batch":0,"kc":"external","i":3,"j":null,
//!  "tx":0,"type":"p2wpkh"}, …]}
//! ```
//!
//! `queries` is in send order. `j` is `null` for a real script and the decoy's number otherwise.
//! `tx` is the number of history entries the server returned, or `null` if no answer arrived. A
//! failed round is still recorded, with `error` set: its queries reached the server whether or not
//! the sync finished.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use bdk_core::bitcoin::hex::DisplayHex;
use bdk_core::bitcoin::Script;
use serde_json::{json, Value};

use crate::keychain::Keychain;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggedQuery {
    /// Electrum's scripthash: `sha256(script)`, byte-reversed, exactly as sent.
    pub scripthash: [u8; 32],
    pub stage: u32,
    /// Counts every batch in the round, across stages.
    pub batch: u32,
    pub keychain: Keychain,
    pub index: u32,
    /// `None` for the real script at this position, `Some(j)` for decoy `j`.
    pub decoy: Option<u32>,
    pub script_type: &'static str,
    /// History entries the server returned; `None` if no answer arrived.
    pub tx_count: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRound {
    pub started: u64,
    pub padding: u32,
    pub stop_gap: usize,
    pub batch_size: usize,
    pub queries: Vec<LoggedQuery>,
    /// Why the round failed, if it did.
    pub error: Option<String>,
}

impl SessionRound {
    pub fn to_json_line(&self) -> String {
        let queries: Vec<Value> = self
            .queries
            .iter()
            .map(|q| {
                json!({
                    "sh": q.scripthash.to_lower_hex_string(),
                    "stage": q.stage,
                    "batch": q.batch,
                    "kc": std::str::from_utf8(q.keychain.as_bytes()).expect("ascii label"),
                    "i": q.index,
                    "j": q.decoy,
                    "tx": q.tx_count,
                    "type": q.script_type,
                })
            })
            .collect();
        json!({
            "format": "haystack-session/1",
            "started": self.started,
            "padding": self.padding,
            "stop_gap": self.stop_gap,
            "batch_size": self.batch_size,
            "error": self.error,
            "queries": queries,
        })
        .to_string()
    }
}

/// Where the client puts each round's record, successful or not.
pub trait SessionLog: Send + Sync {
    fn record(&self, round: &SessionRound) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// Appends one line per round to a file.
pub struct JsonLinesFile {
    path: PathBuf,
}

impl JsonLinesFile {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl SessionLog for JsonLinesFile {
    fn record(&self, round: &SessionRound) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{}", round.to_json_line())?;
        file.flush()?;
        Ok(())
    }
}

/// The names `attack/synth.py` uses for the five standard output types.
pub fn script_type(script: &Script) -> &'static str {
    if script.is_p2wpkh() {
        "p2wpkh"
    } else if script.is_p2wsh() {
        "p2wsh"
    } else if script.is_p2tr() {
        "p2tr"
    } else if script.is_p2pkh() {
        "p2pkh"
    } else if script.is_p2sh() {
        "p2sh"
    } else {
        "other"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_line_has_the_documented_shape() {
        let round = SessionRound {
            started: 7,
            padding: 10,
            stop_gap: 50,
            batch_size: 50,
            queries: vec![LoggedQuery {
                scripthash: [0xab; 32],
                stage: 0,
                batch: 2,
                keychain: Keychain::Internal,
                index: 3,
                decoy: Some(4),
                script_type: "p2wpkh",
                tx_count: None,
            }],
            error: Some("a \"quoted\" failure".into()),
        };
        let v: Value = serde_json::from_str(&round.to_json_line()).unwrap();
        assert_eq!(v["format"], "haystack-session/1");
        assert_eq!(v["error"], "a \"quoted\" failure");
        let q = &v["queries"][0];
        assert_eq!(q["sh"], "ab".repeat(32));
        assert_eq!(
            (q["kc"].as_str(), q["i"].as_u64()),
            (Some("internal"), Some(3))
        );
        assert_eq!((q["j"].as_u64(), q["batch"].as_u64()), (Some(4), Some(2)));
        assert!(q["tx"].is_null());
        assert!(!round.to_json_line().contains('\n'));
    }
}
