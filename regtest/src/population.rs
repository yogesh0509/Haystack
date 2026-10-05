//! Training wallets for the structural attacker: other people's wallets, paid on the same regtest
//! chain, whose labelled Haystack sessions teach the attacker what real addresses and decoys look
//! like (`attack/README.md`, "The two attacks").
//!
//! **Every number in this file is an assumption, not a measurement.** These are the real side of
//! the agreed split: the history of personal wallets, which can't be measured on chain
//! without clustering and for which no verified published source has been found yet. The decoy side
//! needs no distribution while every decoy is HMAC-direct, because those never have history.
//! `docs/02-design.md`, "Where decoys come from", has the reasoning.

use rand::rngs::StdRng;
use rand::Rng;

use bdk_wallet::{KeychainKind, Wallet};

use crate::{external, mine, new_wallet, pay, spend, sync_plain, Error, RealWallet, TestEnv};

/// How many payments a wallet has received, as (value, weight).
pub const RECEIVES: &[(u32, f64)] = &[(2, 0.20), (4, 0.30), (8, 0.30), (15, 0.15), (30, 0.05)];
/// How many times it has spent, each spend sending change to the next internal address.
pub const SPENDS: &[(u32, f64)] = &[(0, 0.40), (1, 0.35), (2, 0.20), (3, 0.05)];
/// Chance that a payment reuses an address already paid.
pub const REUSE: f64 = 0.15;
/// Chance that the next new address is not the next index: 1 to 3 addresses were handed out and
/// never paid.
pub const SKIP: f64 = 0.20;
/// Chance that the last payment is still unconfirmed when the wallet is first synced.
pub const UNCONFIRMED_LAST: f64 = 0.30;

/// The assumptions above, for the session generator's manifest, so every score can say which
/// numbers were assumed.
pub fn assumptions() -> serde_json::Value {
    serde_json::json!({
        "source": "assumed, no verified source (regtest/src/population.rs)",
        "receives": RECEIVES,
        "spends": SPENDS,
        "reuse": REUSE,
        "skip": SKIP,
        "unconfirmed_last": UNCONFIRMED_LAST,
        "script_type": "p2wpkh only",
    })
}

fn pick(rng: &mut StdRng, table: &[(u32, f64)]) -> u32 {
    let total: f64 = table.iter().map(|(_, w)| w).sum();
    let mut x = rng.gen::<f64>() * total;
    for &(v, w) in table {
        if x < w {
            return v;
        }
        x -= w;
    }
    table.last().expect("non-empty table").0
}

/// Gives a fresh wallet from `seed` a random history drawn from the tables above.
pub fn random_history(env: &TestEnv, seed: &str, rng: &mut StdRng) -> Result<RealWallet, Error> {
    let mut rw = new_wallet(seed)?;
    let mut wallet = rw.wallet();
    let receives = pick(rng, RECEIVES);
    let spends = pick(rng, SPENDS);
    let leave_unconfirmed = rng.gen_bool(UNCONFIRMED_LAST);

    let mut paid: Vec<u32> = Vec::new();
    let mut next = 0u32;
    let mut reused = 0u32;
    for n in 0..receives {
        let index = if !paid.is_empty() && rng.gen_bool(REUSE) {
            reused += 1;
            paid[rng.gen_range(0..paid.len())]
        } else {
            if n > 0 && rng.gen_bool(SKIP) {
                next += rng.gen_range(1..=3);
            }
            let i = next;
            next += 1;
            paid.push(i);
            i
        };
        pay(env, &external(&wallet, index), rng.gen_range(0.001..0.2))?;
        let last = n + 1 == receives;
        // The node's own unconfirmed chains are limited, so confirm every few payments.
        if (n + 1) % 5 == 0 && !(last && leave_unconfirmed && spends == 0) {
            mine(env, 1)?;
        }
    }
    if !(leave_unconfirmed && spends == 0) {
        mine(env, 1)?;
    }

    let mut spent = 0u32;
    for s in 0..spends {
        sync_plain(env, &mut wallet)?;
        let balance = wallet.balance().trusted_spendable().to_btc();
        let amount = balance * rng.gen_range(0.1..0.5);
        if amount < 0.0005 {
            break;
        }
        // An exact match without change is refused before anything is broadcast; skip it.
        if spend(env, &mut wallet, (amount * 1e8).round() / 1e8).is_ok() {
            spent += 1;
        }
        if !(s + 1 == spends && leave_unconfirmed) {
            mine(env, 1)?;
        }
    }

    rw.story.push(format!(
        "{receives} payments to external {:?} ({reused} reusing an address), {spent} spends with \
         change, last transaction {}",
        paid,
        if leave_unconfirmed {
            "unconfirmed"
        } else {
            "confirmed"
        }
    ));
    Ok(rw)
}

/// The next external address after the last one used, for the payment between rounds: unused,
/// inside the queried tail, so the next sync sees it activate.
pub fn next_unused_external(wallet: &Wallet) -> u32 {
    wallet
        .derivation_index(KeychainKind::External)
        .map_or(0, |i| i + 1)
}
