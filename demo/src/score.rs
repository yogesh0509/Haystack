//! The live score: the repo's own attacker (`python3 -m attack score`) run on this wallet's session
//! log after every sync.
//!
//! The many-rounds attacker (T1) needs only the session log. The structural attacker (T2) also
//! needs a training set: labelled sessions of other wallets from `regtest/`'s generator, recorded
//! by the same client build at the same padding and chain share (`attack/a2_structural.py`). Only the
//! `train-*.jsonl` files are passed, because each folder's `demo.jsonl` has the same real addresses
//! as the demo's regtest wallet, which `fit` rightly refuses as training on the answer.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};

/// The repository root, where `python3 -m attack` runs.
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("demo/ sits in the repo root")
        .to_path_buf()
}

/// The training folder name `regtest/src/bin/sessions.rs` writes for a setting.
pub fn folder(padding: u32, share: f64) -> String {
    format!("p{padding}-c{}", (share * 100.0).round() as u32)
}

/// Every distinct (padding, chain share) the session log was recorded at.
pub fn settings(session: &Path) -> BTreeSet<(u32, u32)> {
    std::fs::read_to_string(session)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .map(|r| {
            (
                r["padding"].as_u64().unwrap_or(0) as u32,
                (r["chain_share"].as_f64().unwrap_or(0.0) * 100.0).round() as u32,
            )
        })
        .collect()
}

fn run(session: &Path, tier: &str, train: &[PathBuf]) -> Value {
    let mut cmd = Command::new("python3");
    cmd.current_dir(repo_root())
        .args([
            "-m",
            "attack",
            "score",
            "--last",
            "--json",
            "--tier",
            tier,
            "--session",
        ])
        .arg(session);
    if !train.is_empty() {
        cmd.arg("--train").args(train);
    }
    match cmd.output() {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            text.lines()
                .last()
                .and_then(|l| serde_json::from_str(l).ok())
                .unwrap_or_else(|| json!({ "unavailable": "the attacker printed no score" }))
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr);
            let reason = err
                .lines()
                .last()
                .unwrap_or("the attacker failed")
                .trim()
                .to_string();
            json!({ "unavailable": reason })
        }
        Err(e) => json!({ "unavailable": format!("couldn't run python3: {e}") }),
    }
}

/// T1 always; T2 when a matching training set exists.
pub fn score(session: &Path, train_root: &Path) -> Value {
    let t1 = run(session, "T1", &[]);
    let settings = settings(session);
    let t2 = match settings.iter().collect::<Vec<_>>().as_slice() {
        [(padding, share)] => {
            let dir = train_root.join(folder(*padding, *share as f64 / 100.0));
            let mut train: Vec<PathBuf> = std::fs::read_dir(&dir)
                .map(|it| {
                    it.flatten()
                        .map(|e| e.path())
                        .filter(|p| {
                            p.file_name()
                                .and_then(|n| n.to_str())
                                .is_some_and(|n| n.starts_with("train-") && n.ends_with(".jsonl"))
                        })
                        .collect()
                })
                .unwrap_or_default();
            train.sort();
            if train.is_empty() {
                json!({ "unavailable": format!(
                    "no training set at {}; generate one with `cargo run --release -p haystack-regtest --bin sessions -- --out {}`",
                    dir.display(), train_root.display()) })
            } else {
                run(session, "T2", &train)
            }
        }
        [] => json!({ "unavailable": "no session yet" }),
        _ => {
            json!({ "unavailable": "this session mixes dial settings, and the training set has one setting per folder" })
        }
    };
    json!({ "T1": t1, "T2": t2 })
}
