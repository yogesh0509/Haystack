//! Generates the labelled sessions behind Week 3's structural score and bandwidth curve
//! (`docs/04-roadmap.md`, option B), on a fresh regtest chain:
//!
//! - the demo wallet from `build_history`, which is the one scored;
//! - `--wallets` training wallets with random histories from `population.rs`'s assumed tables;
//! - every wallet synced through `HaystackElectrumClient` at every `--paddings` level and every
//!   `--chain-shares` level, twice, with one new payment between the two rounds, through a
//!   byte-counting relay. A chain share above 0 takes that share of each position's decoys from
//!   the chain, found through the same server (`haystack_electrum::chain`). Sessions land in
//!   `p<padding>-c<share as a percentage>/`, for example `p10-c30/`.
//!
//! This is also the reset (Week 3 safeguard 3): it deletes `--out` before writing, so one run
//! replaces the whole training set with sessions from the client as currently built.
//!
//! ```text
//! cargo run --release -p haystack-regtest --bin sessions -- --out regtest/sessions
//! python3 -m attack curve --dir regtest/sessions
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use bdk_wallet::Wallet;
use haystack_electrum::cache_file::SavedCache;
use haystack_electrum::chain::ChainDecoys;
use haystack_electrum::client::HaystackElectrumClient;
use haystack_electrum::ledger::Ledger;
use haystack_electrum::session::{JsonLinesFile, CLIENT_SOURCE, CLIENT_VERSION};
use haystack_regtest::population::{assumptions, next_unused_external, random_history};
use haystack_regtest::proxy::CountingProxy;
use haystack_regtest::{
    build_history, external, mine, pay, start, Error, RealWallet, DEMO_SEED, STOP_GAP,
};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde_json::json;

struct Args {
    out: PathBuf,
    wallets: usize,
    paddings: Vec<u32>,
    chain_shares: Vec<f64>,
    seed: u64,
}

/// Every (padding, chain share) pair to run. Padding 1 has no decoys, so it runs once.
fn configs(a: &Args) -> Vec<(u32, f64)> {
    let mut out = Vec::new();
    for &p in &a.paddings {
        for &c in &a.chain_shares {
            if p > 1 || c == 0.0 {
                out.push((p, c));
            }
        }
    }
    out
}

fn folder(padding: u32, share: f64) -> String {
    format!("p{padding}-c{}", (share * 100.0).round() as u32)
}

fn args() -> Result<Args, Error> {
    let mut a = Args {
        out: PathBuf::from("regtest/sessions"),
        wallets: 12,
        paddings: vec![1, 2, 5, 10, 20],
        chain_shares: vec![0.0, 0.1, 0.3],
        seed: 0,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let value = it.next().ok_or(format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--out" => a.out = value.into(),
            "--wallets" => a.wallets = value.parse()?,
            "--paddings" => {
                a.paddings = value.split(',').map(str::parse).collect::<Result<_, _>>()?
            }
            "--chain-shares" => {
                a.chain_shares = value.split(',').map(str::parse).collect::<Result<_, _>>()?
            }
            "--seed" => a.seed = value.parse()?,
            _ => return Err(format!("unknown flag {flag}").into()),
        }
    }
    Ok(a)
}

/// One wallet at one (padding, chain share) setting: its own wallet copy and ledger, carried between rounds.
struct Track {
    wallet: Wallet,
    ledger: Option<Ledger>,
    /// Carried between rounds like a restarted wallet's saved cache, so the second sync's bytes
    /// are the steady state: no transaction or proof is fetched twice.
    cache: SavedCache,
}

fn main() -> Result<(), Error> {
    let a = args()?;
    if a.out.exists() {
        fs::remove_dir_all(&a.out)?;
    }
    let configs = configs(&a);
    for &(p, c) in &configs {
        fs::create_dir_all(a.out.join(folder(p, c)))?;
    }

    let env = start()?;
    let mut wallets: Vec<(String, RealWallet)> =
        vec![("demo".into(), build_history(&env, DEMO_SEED)?)];
    // More mature coinbase outputs for the node, which pays everyone.
    mine(&env, 20)?;
    let mut rng = StdRng::seed_from_u64(a.seed);
    for i in 0..a.wallets {
        let name = format!("train-{i:02}");
        let rw = random_history(&env, &format!("haystack-train-{}-{i:02}", a.seed), &mut rng)?;
        eprintln!("{name}: {}", rw.story.join("; "));
        wallets.push((name, rw));
    }

    let proxy = CountingProxy::start(&env.electrsd.electrum_url)?;
    let mut tracks: BTreeMap<(usize, usize), Track> = BTreeMap::new();
    for (w, (_, rw)) in wallets.iter().enumerate() {
        for c in 0..configs.len() {
            tracks.insert(
                (w, c),
                Track {
                    wallet: rw.wallet(),
                    ledger: Some(Ledger::new(&rw.decoy_key())),
                    cache: SavedCache::default(),
                },
            );
        }
    }

    let mut bandwidth = Vec::new();
    for round in 0..2 {
        if round == 1 {
            for (w, (name, _)) in wallets.iter().enumerate() {
                let synced = &tracks[&(w, 0)].wallet;
                let index = next_unused_external(synced);
                pay(&env, &external(synced, index), 0.004)?;
                eprintln!("{name}: paid external {index} between rounds");
            }
            mine(&env, 1)?;
        }
        for (w, (name, rw)) in wallets.iter().enumerate() {
            let key = rw.decoy_key();
            for (c, &(p, share)) in configs.iter().enumerate() {
                let track = tracks.get_mut(&(w, c)).expect("created above");
                let log =
                    JsonLinesFile::new(a.out.join(format!("{}/{name}.jsonl", folder(p, share))));
                let client = HaystackElectrumClient::new(
                    electrum_client::Client::new(&proxy.url())?,
                    key.clone(),
                    p,
                )
                .with_chain_decoys(ChainDecoys::new(share))
                .with_ledger(track.ledger.take().expect("returned last round"))
                .map_err(|e| format!("{e:?}"))?
                .with_saved_cache(std::mem::take(&mut track.cache))
                .with_session_log(log);
                proxy.take();
                let update = client.full_scan(
                    track.wallet.start_full_scan(),
                    STOP_GAP,
                    5,
                    false,
                )?;
                let (sent, received) = proxy.take();
                track.wallet.apply_update(update)?;
                track.cache = client.saved_cache();
                track.ledger = Some(client.into_ledger());
                bandwidth.push(json!({
                    "wallet": name, "padding": p, "chain_share": share, "round": round,
                    "sent": sent, "received": received,
                }));
            }
        }
    }

    let manifest = json!({
        "format": "haystack-sessions/1",
        "client": {"name": "haystack-electrum", "version": CLIENT_VERSION, "source": CLIENT_SOURCE},
        "scored": "demo",
        "training": wallets.iter().skip(1).map(|(n, _)| n.clone()).collect::<Vec<_>>(),
        "configs": configs
            .iter()
            .map(|&(p, c)| json!({"padding": p, "chain_share": c, "dir": folder(p, c)}))
            .collect::<Vec<_>>(),
        "seed": a.seed,
        "stop_gap": STOP_GAP,
        "real_side": assumptions(),
        "decoy_side": "chain decoys are other regtest wallets' and the node's addresses, found through \
            the sync server; on this chain they come from the same assumed distribution as the real \
            side, so the structural score for them is optimistic by construction",
        "stories": wallets.iter().map(|(n, rw)| (n.clone(), rw.story.clone())).collect::<BTreeMap<_, _>>(),
    });
    fs::write(
        a.out.join("manifest.json"),
        serde_json::to_string_pretty(&manifest)?,
    )?;
    fs::write(
        a.out.join("bandwidth.json"),
        serde_json::to_string_pretty(&bandwidth)?,
    )?;
    eprintln!(
        "wrote {} sessions to {}",
        wallets.len() * configs.len(),
        a.out.display()
    );
    Ok(())
}
