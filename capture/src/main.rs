//! Real bdk_wallet full scans, one connection per round; writes what the wallet itself queried.
//!
//! `--padding 1` (the default) is a plain `bdk_electrum` scan. Above 1 the same scan goes through
//! `haystack-electrum`, with the decoy ledger carried from round to round as a wallet would keep it,
//! and each round also lists the decoy scripthashes the ledger says were sent.

use std::str::FromStr;
use std::sync::{Arc, Mutex};

use bdk_electrum::{electrum_client, BdkElectrumClient};
use bdk_wallet::bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bdk_wallet::bitcoin::hashes::{sha256, Hash};
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::{Network, ScriptBuf};
use bdk_wallet::{KeychainKind, Wallet};
use haystack_electrum::client::HaystackElectrumClient;
use haystack_electrum::decoy::decoys_for;
use haystack_electrum::key::DecoyKey;
use haystack_electrum::keychain::DecoyKeychain;
use haystack_electrum::ledger::Ledger;
use haystack_electrum::session::JsonLinesFile;

type Error = Box<dyn std::error::Error>;

struct Args {
    url: String,
    stop_gap: usize,
    batch_size: usize,
    rounds: usize,
    seed: String,
    out: String,
    padding: u32,
    session: Option<String>,
}

fn parse_args() -> Result<Args, Error> {
    let mut a = Args {
        url: "tcp://127.0.0.1:50001".into(),
        stop_gap: 50,
        batch_size: 5,
        rounds: 1,
        seed: "haystack-capture-demo".into(),
        out: "capture-truth.json".into(),
        padding: 1,
        session: None,
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
            "--padding" => a.padding = val()?.parse()?,
            "--session" => a.session = Some(val()?),
            _ => return Err(format!("unknown flag {flag}").into()),
        }
    }
    Ok(a)
}

/// Watch-only BIP84 descriptors from a public demo seed; no private key reaches the wallet.
fn descriptors(seed: &str) -> Result<(String, String, Xpub), Error> {
    let secp = Secp256k1::new();
    let seed = sha256::Hash::hash(seed.as_bytes());
    let master = Xpriv::new_master(Network::Bitcoin, seed.as_byte_array())?;
    let path = DerivationPath::from_str("m/84'/0'/0'")?;
    let account = Xpub::from_priv(&secp, &master.derive_priv(&secp, &path)?);
    let origin = format!("[{}/84'/0'/0']", master.fingerprint(&secp));
    Ok((
        format!("wpkh({origin}{account}/0/*)"),
        format!("wpkh({origin}{account}/1/*)"),
        account,
    ))
}

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
    // Reals' worth per write, bdk's 5 by default: 5 scripts when plain, 50 at padding 10.
    let batch_size = args.batch_size;
    let (ext, int, account) = descriptors(&args.seed)?;
    let key = DecoyKey::from_xpubs([account]).expect("one account xpub");
    let mut ledger = Some(Ledger::new(&key));
    let mut rounds = Vec::new();
    if let Some(path) = &args.session {
        if args.padding <= 1 {
            return Err(
                "--session needs --padding above 1: the plain path is upstream's client".into(),
            );
        }
        // The log appends one line per round, so start each run with an empty file.
        let _ = std::fs::remove_file(path);
    }

    for round in 0..args.rounds {
        let mut wallet = Wallet::create(ext.clone(), int.clone())
            .network(Network::Bitcoin)
            .create_wallet_no_persist()?;

        let seen: Arc<Mutex<Vec<(KeychainKind, u32, ScriptBuf)>>> = Arc::default();
        let request = wallet.start_full_scan().inspect({
            let seen = Arc::clone(&seen);
            move |k, i, spk| seen.lock().unwrap().push((k, i, spk.to_owned()))
        });

        // Dropping the client closes its connection, so the next round is a new one.
        let inner = electrum_client::Client::new(&args.url)?;
        let update = if args.padding <= 1 {
            BdkElectrumClient::new(inner).full_scan(request, args.stop_gap, batch_size, false)?
        } else {
            let mut client = HaystackElectrumClient::new(inner, key.clone(), args.padding)
                .with_ledger(ledger.take().expect("ledger returned last round"))
                .map_err(|e| format!("{e:?}"))?;
            if let Some(path) = &args.session {
                client = client.with_session_log(JsonLinesFile::new(path));
            }
            let update = client.full_scan(request, args.stop_gap, batch_size, false)?;
            ledger = Some(client.into_ledger());
            update
        };
        let queried = seen.lock().unwrap().clone();
        let ledger_now = ledger.as_ref().expect("ledger is back");
        let decoys: Vec<String> = queried
            .iter()
            .flat_map(|(k, i, spk)| {
                let count = ledger_now.get((k.keychain(), *i)).unwrap_or(0);
                decoys_for(&key, spk, k.keychain(), *i, count).expect("P2WPKH has a decoy shape")
            })
            .map(|d| format!(r#""{}""#, scripthash(&d)))
            .collect();

        // The honeypot's fake chain may not connect; the queries were already sent.
        if let Err(e) = wallet.apply_update(update) {
            eprintln!("round {round}: apply_update rejected the fake chain ({e})");
        }
        eprintln!(
            "round {round}: wallet queried {} scriptPubKeys",
            queried.len()
        );

        let entries: Vec<String> = queried
            .iter()
            .map(|(k, i, spk)| {
                format!(
                    r#"{{"keychain":"{}","index":{i},"scripthash":"{}"}}"#,
                    keychain_name(*k),
                    scripthash(spk)
                )
            })
            .collect();
        rounds.push(format!(
            r#"{{"round":{round},"queried":[{}],"decoys":[{}]}}"#,
            entries.join(","),
            decoys.join(",")
        ));
    }

    let ext_pub = Wallet::create(ext, int)
        .network(Network::Bitcoin)
        .create_wallet_no_persist()?;
    let json = format!(
        r#"{{"format":"haystack-capture/1","network":"bitcoin","external_descriptor":"{}","internal_descriptor":"{}","stop_gap":{},"batch_size":{},"padding":{},"rounds":[{}]}}"#,
        ext_pub.public_descriptor(KeychainKind::External),
        ext_pub.public_descriptor(KeychainKind::Internal),
        args.stop_gap,
        // Scripts per write as sent, the meaning the field had before batch sizes counted reals.
        batch_size * args.padding.max(1) as usize,
        args.padding,
        rounds.join(",")
    );
    std::fs::write(&args.out, json + "\n")?;
    eprintln!("ground truth written to {}", args.out);
    Ok(())
}
