//! The ledger on disk, which is also the wallet's Haystack backup.
//!
//! The decoy key can be rebuilt from the xpubs, but the frozen decoy counts can't: they exist only
//! here. Restore a wallet without this file and pick a lower dial, and every position loses decoys
//! at once. So the format is meant to be kept and moved, not just cached: small, stable, versioned,
//! and written as position ranges.
//!
//! ```text
//! {"format":"haystack-ledger/1","key_fingerprint":"<16 hex>",
//!  "keychains":{"external":[{"from":0,"to":49,"decoys":9},{"from":50,"to":53,"decoys":19}],
//!               "internal":[{"from":0,"to":51,"decoys":9}]}}
//! ```
//!
//! A range covers positions `from` to `to`, both included, frozen with `decoys` decoys each. Each
//! keychain's ranges run from position 0 with no gaps or overlaps.
//!
//! A ledger holding chain-sourced decoys is written as `haystack-ledger/2`, which adds their scripts,
//! since they can't be rebuilt from the key: `"chain":{"external":[{"i":3,"j":0,"script":"0014…"}]}`.
//! A ledger without any is still written as `haystack-ledger/1`, and both are read. Saving writes a temporary file,
//! flushes it to disk, and renames it over the old one, so a crash leaves either the old ledger or
//! the new one, never a truncated one.

use std::fmt;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use bdk_core::bitcoin::hex::{DisplayHex, FromHex};
use serde_json::{json, Map, Value};

use crate::client::LedgerStore;
use crate::key::DecoyKey;
use crate::keychain::Keychain;
use crate::ledger::{KeyMismatch, Ledger};

const FORMAT: &str = "haystack-ledger/1";
const FORMAT_CHAIN: &str = "haystack-ledger/2";
const KEYCHAINS: [Keychain; 2] = [Keychain::External, Keychain::Internal];

#[derive(Debug)]
pub enum LedgerFileError {
    Io(std::io::Error),
    /// Not a readable `haystack-ledger/1` document, or its ranges don't describe a ledger.
    Format(String),
    /// The file belongs to a different decoy key: using it would replace every decoy at once.
    KeyMismatch(KeyMismatch),
}

impl fmt::Display for LedgerFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "ledger file: {e}"),
            Self::Format(why) => write!(f, "ledger file: {why}"),
            Self::KeyMismatch(m) => write!(
                f,
                "ledger file belongs to decoy key {}, not {}",
                m.ledger.to_lower_hex_string(),
                m.offered.to_lower_hex_string()
            ),
        }
    }
}

impl std::error::Error for LedgerFileError {}

impl From<std::io::Error> for LedgerFileError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

fn bad(why: impl Into<String>) -> LedgerFileError {
    LedgerFileError::Format(why.into())
}

/// The ledger as a `haystack-ledger/1` document.
pub fn export(ledger: &Ledger) -> String {
    let mut keychains = Map::new();
    for kc in KEYCHAINS {
        let mut ranges: Vec<(u32, u32, u32)> = Vec::new();
        for ((k, index), decoys) in ledger.confirmed() {
            if k != kc {
                continue;
            }
            match ranges.last_mut() {
                Some((_, to, n)) if *n == decoys && *to + 1 == index => *to = index,
                _ => ranges.push((index, index, decoys)),
            }
        }
        if !ranges.is_empty() {
            let ranges: Vec<Value> = ranges
                .into_iter()
                .map(|(from, to, decoys)| json!({ "from": from, "to": to, "decoys": decoys }))
                .collect();
            keychains.insert(label(kc).into(), Value::Array(ranges));
        }
    }
    let mut chain = Map::new();
    for ((kc, index), j, script) in ledger.all_chain_decoys() {
        chain
            .entry(label(kc))
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .expect("created as an array")
            .push(json!({ "i": index, "j": j, "script": script.as_bytes().to_lower_hex_string() }));
    }
    let mut doc = json!({
        "format": if chain.is_empty() { FORMAT } else { FORMAT_CHAIN },
        "key_fingerprint": ledger.key_fingerprint().to_lower_hex_string(),
        "keychains": keychains,
    });
    if !chain.is_empty() {
        doc["chain"] = Value::Object(chain);
    }
    doc.to_string()
}

/// Rebuild a ledger from `export`'s output, refusing one made with a different key or one whose
/// ranges leave a gap, overlap, or start anywhere but position 0.
pub fn import(text: &str, key: &DecoyKey) -> Result<Ledger, LedgerFileError> {
    let doc: Value = serde_json::from_str(text).map_err(|e| bad(format!("not JSON: {e}")))?;
    if doc["format"] != FORMAT && doc["format"] != FORMAT_CHAIN {
        return Err(bad(format!(
            "format is {}, expected {FORMAT} or {FORMAT_CHAIN}",
            doc["format"]
        )));
    }
    let stored = doc["key_fingerprint"]
        .as_str()
        .and_then(|h| <[u8; 8]>::from_hex(h).ok())
        .ok_or_else(|| bad("key_fingerprint is not 16 hex characters"))?;
    let offered = key.fingerprint();
    if stored != offered {
        return Err(LedgerFileError::KeyMismatch(KeyMismatch {
            ledger: stored,
            offered,
        }));
    }
    let keychains = doc["keychains"]
        .as_object()
        .ok_or_else(|| bad("keychains is not an object"))?;
    if let Some(unknown) = keychains
        .keys()
        .find(|k| !KEYCHAINS.iter().any(|kc| label(*kc) == k.as_str()))
    {
        return Err(bad(format!("unknown keychain {unknown}")));
    }

    let mut ledger = Ledger::new(key);
    for kc in KEYCHAINS {
        let Some(ranges) = keychains.get(label(kc)) else {
            continue;
        };
        let ranges = ranges
            .as_array()
            .ok_or_else(|| bad(format!("{} is not a list of ranges", label(kc))))?;
        let mut next = 0u32;
        for r in ranges {
            let field = |name: &str| {
                r[name]
                    .as_u64()
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or_else(|| bad(format!("{} range has no valid {name}", label(kc))))
            };
            let (from, to, decoys) = (field("from")?, field("to")?, field("decoys")?);
            if from != next || to < from {
                return Err(bad(format!(
                    "{} range {from}-{to} should start at {next}",
                    label(kc)
                )));
            }
            for index in from..=to {
                ledger.freeze((kc, index), decoys);
            }
            next = to
                .checked_add(1)
                .ok_or_else(|| bad("range runs past the last index"))?;
        }
    }
    if let Some(chain) = doc.get("chain") {
        let chain = chain
            .as_object()
            .ok_or_else(|| bad("chain is not an object"))?;
        for (name, entries) in chain {
            let kc = KEYCHAINS
                .into_iter()
                .find(|kc| label(*kc) == name.as_str())
                .ok_or_else(|| bad(format!("unknown keychain {name} in chain")))?;
            for e in entries
                .as_array()
                .ok_or_else(|| bad(format!("chain {name} is not a list")))?
            {
                let num = |f: &str| {
                    e[f].as_u64()
                        .and_then(|v| u32::try_from(v).ok())
                        .ok_or_else(|| bad(format!("chain {name} entry has no valid {f}")))
                };
                let (index, j) = (num("i")?, num("j")?);
                let script = e["script"]
                    .as_str()
                    .and_then(|h| Vec::<u8>::from_hex(h).ok())
                    .ok_or_else(|| bad(format!("chain {name} entry has no valid script")))?;
                if !ledger.set_chain_decoy((kc, index), j, script.into()) {
                    return Err(bad(format!(
                        "chain decoy {name}/{index}/{j} is outside the frozen positions or repeated"
                    )));
                }
            }
        }
    }
    Ok(ledger)
}

fn label(kc: Keychain) -> &'static str {
    std::str::from_utf8(kc.as_bytes()).expect("ascii label")
}

/// The ledger file at one path: loaded when the wallet starts, saved by the client before each
/// batch that carries newly frozen positions.
pub struct LedgerFile {
    path: PathBuf,
}

impl LedgerFile {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// `None` if there is no file yet, meaning a wallet that has never synced through Haystack.
    pub fn load(&self, key: &DecoyKey) -> Result<Option<Ledger>, LedgerFileError> {
        match fs::read_to_string(&self.path) {
            Ok(text) => import(&text, key).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self, ledger: &Ledger) -> Result<(), LedgerFileError> {
        write_atomically(&self.path, export(ledger).as_bytes())?;
        Ok(())
    }
}

/// Write a temporary file, flush it to disk, and rename it over `path`, so a crash leaves either
/// the old contents or the new ones, never a truncated file.
pub(crate) fn write_atomically(path: &Path, body: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut file = File::create(&tmp)?;
        file.write_all(body)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    sync_dir(path)
}

/// Make the rename itself durable: until the directory entry is on disk, a crash can bring back
/// the old file.
fn sync_dir(path: &Path) -> std::io::Result<()> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    File::open(dir)?.sync_all()
}

impl LedgerStore for LedgerFile {
    fn save(&self, ledger: &Ledger) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        LedgerFile::save(self, ledger).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_core::bitcoin::ScriptBuf;
    use std::collections::BTreeMap;

    fn key() -> DecoyKey {
        DecoyKey::for_tests(b"test-wallet")
    }

    fn ledger(ranges: &[(Keychain, u32, u32, u32)]) -> Ledger {
        let mut l = Ledger::new(&key());
        for &(kc, from, to, decoys) in ranges {
            for i in from..=to {
                l.freeze((kc, i), decoys);
            }
        }
        l
    }

    fn entries(l: &Ledger) -> Vec<((Keychain, u32), u32)> {
        l.confirmed().collect()
    }

    #[test]
    fn round_trips_as_ranges() {
        let l = ledger(&[
            (Keychain::External, 0, 49, 9),
            (Keychain::External, 50, 53, 19),
            (Keychain::Internal, 0, 51, 9),
        ]);
        let text = export(&l);
        let doc: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["keychains"]["external"].as_array().unwrap().len(), 2);
        assert_eq!(doc["keychains"]["internal"][0]["to"], 51);
        assert!(text.len() < 300, "{} bytes", text.len());
        assert_eq!(entries(&import(&text, &key()).unwrap()), entries(&l));
    }

    #[test]
    fn empty_ledger_round_trips() {
        let l = Ledger::new(&key());
        assert_eq!(entries(&import(&export(&l), &key()).unwrap()), vec![]);
    }

    #[test]
    fn refuses_another_key() {
        let text = export(&ledger(&[(Keychain::External, 0, 4, 9)]));
        let other = DecoyKey::for_tests(b"a different wallet");
        assert!(matches!(
            import(&text, &other),
            Err(LedgerFileError::KeyMismatch(_))
        ));
    }

    fn with_external(ranges: Value) -> String {
        json!({
            "format": FORMAT,
            "key_fingerprint": key().fingerprint().to_lower_hex_string(),
            "keychains": { "external": ranges },
        })
        .to_string()
    }

    #[test]
    fn refuses_ranges_that_do_not_describe_a_ledger() {
        for ranges in [
            json!([{"from": 1, "to": 4, "decoys": 9}]),
            json!([{"from": 0, "to": 4, "decoys": 9}, {"from": 6, "to": 9, "decoys": 9}]),
            json!([{"from": 0, "to": 4, "decoys": 9}, {"from": 3, "to": 9, "decoys": 9}]),
            json!([{"from": 0, "to": 4}]),
            json!([{"from": 5, "to": 4, "decoys": 9}]),
        ] {
            let result = import(&with_external(ranges.clone()), &key());
            assert!(
                matches!(result, Err(LedgerFileError::Format(_))),
                "{ranges}"
            );
        }
    }

    #[test]
    fn chain_decoys_round_trip_as_version_2() {
        let mut l = ledger(&[(Keychain::External, 0, 4, 9), (Keychain::Internal, 0, 1, 9)]);
        let a = ScriptBuf::from_bytes(vec![0x00, 0x14, 0xaa]);
        let b = ScriptBuf::from_bytes(vec![0x00, 0x14, 0xbb]);
        assert!(l.set_chain_decoy((Keychain::External, 3), 0, a.clone()));
        assert!(l.set_chain_decoy((Keychain::Internal, 1), 8, b.clone()));
        let text = export(&l);
        assert!(text.contains(FORMAT_CHAIN));
        let back = import(&text, &key()).unwrap();
        assert_eq!(entries(&back), entries(&l));
        assert_eq!(back.chain_decoys((Keychain::External, 3)), BTreeMap::from([(0, a)]));
        assert_eq!(back.chain_decoys((Keychain::Internal, 1)), BTreeMap::from([(8, b)]));
    }

    #[test]
    fn refuses_a_chain_decoy_outside_the_frozen_positions() {
        let mut l = ledger(&[(Keychain::External, 0, 4, 9)]);
        l.set_chain_decoy((Keychain::External, 1), 2, ScriptBuf::from_bytes(vec![0x00]));
        let text = export(&l).replace("\"i\":1", "\"i\":7");
        assert!(matches!(import(&text, &key()), Err(LedgerFileError::Format(_))));
    }

    #[test]
    fn refuses_another_format_or_keychain() {
        let text = export(&ledger(&[(Keychain::External, 0, 4, 9)]));
        let other_format = text.replace(FORMAT, "haystack-ledger/9");
        assert!(matches!(
            import(&other_format, &key()),
            Err(LedgerFileError::Format(_))
        ));
        let other_keychain = text.replace("\"external\"", "\"savings\"");
        assert!(matches!(
            import(&other_keychain, &key()),
            Err(LedgerFileError::Format(_))
        ));
    }

    #[test]
    fn file_saves_and_loads() {
        let dir = std::env::temp_dir().join(format!("haystack-ledger-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let file = LedgerFile::new(dir.join("ledger.json"));
        assert!(file.load(&key()).unwrap().is_none());
        let l = ledger(&[(Keychain::External, 0, 53, 9)]);
        file.save(&l).unwrap();
        assert_eq!(entries(&file.load(&key()).unwrap().unwrap()), entries(&l));
        assert!(!dir.join("ledger.tmp").exists());
        fs::remove_dir_all(&dir).unwrap();
    }
}
