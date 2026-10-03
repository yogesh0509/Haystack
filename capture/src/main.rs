//! Stock `bdk_wallet` + `bdk_electrum` full scans, one connection per round; writes what the wallet
//! itself queried. No Haystack code is linked: this is the unpadded baseline, recorded from the
//! wallet's side so it can be checked against what a server logged.

use std::str::FromStr;
use std::sync::{Arc, Mutex};

use bdk_electrum::{electrum_client, BdkElectrumClient};
use bdk_wallet::bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bdk_wallet::bitcoin::hashes::{sha256, Hash};
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::{Network, ScriptBuf};
use bdk_wallet::{KeychainKind, Wallet};
use serde_json::json;

type Error = Box<dyn std::error::Error>;

struct Args {
    url: String,
    stop_gap: usize,
    batch_size: usize,
    rounds: usize,
    seed: String,
    out: String,
}

fn parse_args() -> Result<Args, Error> {
    let mut a = Args {
        url: "tcp://127.0.0.1:50001".into(),
        stop_gap: 50,
        batch_size: 5,
        rounds: 1,
        seed: "haystack-capture-demo".into(),
        out: "capture-truth.json".into(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut val = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--url" => a.url = val()?,
            "--stop-gap" => a.stop_gap = val()?.parse()?,
            "--batch-size" => a.batch_size = val()?.parse()?,
            "--rounds" => a.rounds = val()?.parse()?,
            "--seed" => a.seed = val()?,
            "--out" => a.out = val()?,
            _ => return Err(format!("unknown flag {flag}").into()),
        }
    }
    Ok(a)
}

/// Watch-only BIP84 descriptors from a public demo seed; no private key reaches the wallet.
fn descriptors(seed: &str) -> Result<(String, String), Error> {
    let secp = Secp256k1::new();
    let seed = sha256::Hash::hash(seed.as_bytes());
    let master = Xpriv::new_master(Network::Bitcoin, seed.as_byte_array())?;
    let path = DerivationPath::from_str("m/84'/0'/0'")?;
    let account = Xpub::from_priv(&secp, &master.derive_priv(&secp, &path)?);
    let origin = format!("[{}/84'/0'/0']", master.fingerprint(&secp));
    Ok((
        format!("wpkh({origin}{account}/0/*)"),
        format!("wpkh({origin}{account}/1/*)"),
    ))
}

/// Electrum's lookup key: SHA-256 of the script pubkey, bytes reversed.
fn scripthash(spk: &ScriptBuf) -> String {
    let mut b = sha256::Hash::hash(spk.as_bytes()).to_byte_array();
    b.reverse();
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn keychain_name(k: KeychainKind) -> &'static str {
    match k {
        KeychainKind::External => "external",
        KeychainKind::Internal => "internal",
    }
}

fn main() -> Result<(), Error> {
    let args = parse_args()?;
    let (ext, int) = descriptors(&args.seed)?;
    let mut rounds = Vec::new();
    let mut public = None;

    for round in 0..args.rounds {
        // A fresh wallet each round, so every round is a full scan from nothing.
        let mut wallet = Wallet::create(ext.clone(), int.clone())
            .network(Network::Bitcoin)
            .create_wallet_no_persist()?;
        public.get_or_insert_with(|| {
            [KeychainKind::External, KeychainKind::Internal]
                .map(|k| wallet.public_descriptor(k).to_string())
        });

        let seen: Arc<Mutex<Vec<(KeychainKind, u32, ScriptBuf)>>> = Arc::default();
        let request = wallet.start_full_scan().inspect({
            let seen = Arc::clone(&seen);
            move |k, i, spk| seen.lock().unwrap().push((k, i, spk.to_owned()))
        });

        // Dropping the client closes its connection, so the next round is a new one.
        let client = BdkElectrumClient::new(electrum_client::Client::new(&args.url)?);
        let update = client.full_scan(request, args.stop_gap, args.batch_size, false)?;
        // The honeypot's fake chain may not connect; the queries were already sent.
        if let Err(e) = wallet.apply_update(update) {
            eprintln!("round {round}: apply_update rejected the fake chain ({e})");
        }

        let queried = seen.lock().unwrap();
        eprintln!("round {round}: wallet queried {} scriptPubKeys", queried.len());
        rounds.push(json!({
            "round": round,
            "queried": queried.iter().map(|(k, i, spk)| json!({
                "keychain": keychain_name(*k), "index": i, "scripthash": scripthash(spk),
            })).collect::<Vec<_>>(),
        }));
    }

    let [external, internal] = public.expect("at least one round");
    let out = json!({
        "format": "haystack-capture/1",
        "network": "bitcoin",
        "external_descriptor": external,
        "internal_descriptor": internal,
        "stop_gap": args.stop_gap,
        "batch_size": args.batch_size,
        "rounds": rounds,
    });
    std::fs::write(&args.out, serde_json::to_string(&out)? + "\n")?;
    eprintln!("ground truth written to {}", args.out);
    Ok(())
}
