//! The correctness gate on a real Electrum server: a padded scan and a plain `bdk_electrum` scan of
//! the same real wallet history must leave the wallet in the same state (`docs/04-roadmap.md`).
//!
//! Three rounds, each a full scan by both clients into their own copy of the wallet:
//! 1. the history `build_history` creates, with two transactions unconfirmed;
//! 2. after a block confirms them and a new payment lands on external 60, inside the frozen range,
//!    so Haystack needs a second stage;
//! 3. after a one-block reorganisation moves that block's transactions to a new block, so the
//!    chain-tip agreement and the merkle proofs run against changed history.
//!
//! The padded client carries its saved cache (`haystack_electrum::cache_file`) from round to round,
//! as a restarted wallet would, so round 3 also checks that proofs saved before the reorganisation
//! aren't served for the block that replaced theirs.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use bdk_wallet::bitcoin::{Amount, BlockHash, OutPoint, Txid};
use bdk_wallet::chain::ChainPosition;
use bdk_wallet::{Balance, KeychainKind, Wallet};
use haystack_electrum::cache_file::SavedCache;
use haystack_electrum::client::HaystackElectrumClient;
use haystack_electrum::key::DecoyKey;
use haystack_electrum::keychain::Keychain;
use haystack_electrum::ledger::Ledger;
use haystack_electrum::session::{SessionLog, SessionRound};
use haystack_regtest::{
    build_history, electrum, external, mine, pay, start, sync_plain, wait_for_tip, Error, TestEnv,
    DEMO_SEED, STOP_GAP,
};

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    balance: Balance,
    txs: BTreeSet<(Txid, Option<(u32, BlockHash)>)>,
    utxos: BTreeSet<(OutPoint, Amount)>,
    external: Option<u32>,
    internal: Option<u32>,
    tip: (u32, BlockHash),
}

fn snapshot(w: &Wallet) -> Snapshot {
    let tip = w.latest_checkpoint().block_id();
    Snapshot {
        balance: w.balance(),
        txs: w
            .transactions()
            .map(|t| {
                let at = match t.chain_position {
                    ChainPosition::Confirmed { anchor, .. } => {
                        Some((anchor.block_id.height, anchor.block_id.hash))
                    }
                    _ => None,
                };
                (t.tx_node.txid, at)
            })
            .collect(),
        utxos: w
            .list_unspent()
            .map(|u| (u.outpoint, u.txout.value))
            .collect(),
        external: w.derivation_index(KeychainKind::External),
        internal: w.derivation_index(KeychainKind::Internal),
        tip: (tip.height, tip.hash),
    }
}

#[derive(Clone, Default)]
struct MemoryLog(Arc<Mutex<Vec<SessionRound>>>);

impl SessionLog for MemoryLog {
    fn record(&self, round: &SessionRound) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.0.lock().unwrap().push(round.clone());
        Ok(())
    }
}

/// One padded round on a new connection, carrying the ledger over as a wallet would.
fn padded_round(
    env: &TestEnv,
    wallet: &mut Wallet,
    (ledger, cache): (Ledger, SavedCache),
    key: &DecoyKey,
    log: &MemoryLog,
) -> Result<(Ledger, SavedCache), Error> {
    let client = HaystackElectrumClient::new(electrum(env)?, key.clone(), 10)
        .with_ledger(ledger)
        .map_err(|e| format!("{e:?}"))?
        .with_saved_cache(cache)
        .with_session_log(log.clone());
    let update = client.full_scan(wallet.start_full_scan(), STOP_GAP, 5, false)?;
    wallet.apply_update(update)?;
    let cache = client.saved_cache();
    Ok((client.into_ledger(), cache))
}

fn reals_per_stage(round: &SessionRound) -> BTreeMap<u32, usize> {
    let mut n = BTreeMap::new();
    for q in round.queries.iter().filter(|q| q.decoy.is_none()) {
        *n.entry(q.stage).or_insert(0) += 1;
    }
    n
}

#[test]
fn padded_scans_leave_the_wallet_exactly_as_plain_scans_do() -> Result<(), Error> {
    let env = start()?;
    let rw = build_history(&env, DEMO_SEED)?;
    for line in &rw.story {
        eprintln!("history: {line}");
    }
    let key = rw.decoy_key();
    let (mut plain, mut padded) = (rw.wallet(), rw.wallet());
    let mut ledger = (Ledger::new(&key), SavedCache::default());
    let log = MemoryLog::default();

    // Round 1.
    sync_plain(&env, &mut plain)?;
    ledger = padded_round(&env, &mut padded, ledger, &key, &log)?;
    let s1 = snapshot(&plain);
    assert_eq!(snapshot(&padded), s1);
    assert!(!ledger.1.anchors.is_empty(), "round 1 saved its proofs");
    assert_eq!((s1.external, s1.internal), (Some(30), Some(1)));
    assert_eq!(s1.txs.len(), 8);
    assert_eq!(s1.txs.iter().filter(|(_, at)| at.is_none()).count(), 2);
    assert!(s1.balance.confirmed > Amount::ZERO && s1.balance.trusted_pending > Amount::ZERO);
    assert!(s1.balance.untrusted_pending > Amount::ZERO);

    // Round 2.
    mine(&env, 1)?;
    pay(&env, &external(&plain, 60), 0.03)?;
    sync_plain(&env, &mut plain)?;
    ledger = padded_round(&env, &mut padded, ledger, &key, &log)?;
    let s2 = snapshot(&plain);
    assert_eq!(snapshot(&padded), s2);
    assert_eq!(s2.external, Some(60));

    // Round 3.
    env.reorg(1)?;
    wait_for_tip(&env)?;
    sync_plain(&env, &mut plain)?;
    let _ = padded_round(&env, &mut padded, ledger, &key, &log)?;
    let s3 = snapshot(&plain);
    assert_eq!(snapshot(&padded), s3);
    assert_eq!(s3.tip.0, s2.tip.0);
    assert_ne!(s3.tip.1, s2.tip.1, "the reorg replaced the tip block");
    let in_old_tip: Vec<Txid> = s2
        .txs
        .iter()
        .filter(|(_, at)| *at == Some(s2.tip))
        .map(|(txid, _)| *txid)
        .collect();
    assert!(!in_old_tip.is_empty());
    for txid in in_old_tip {
        assert!(
            s3.txs.contains(&(txid, Some(s3.tip))),
            "{txid} moved to the new block"
        );
    }

    // What the session log says the server was asked, round by round.
    let rounds = log.0.lock().unwrap();
    assert_eq!(rounds.len(), 3);
    assert!(rounds.iter().all(|r| r.error.is_none()));
    // Round 1: positions 0-49 of each keychain, then the shortfalls the answers reveal — external
    // 30 used leaves 19 unused after it, so 31 more (50-80); internal 1 used leaves 48, so 2 more.
    assert_eq!(
        reals_per_stage(&rounds[0]),
        BTreeMap::from([(0, 100), (1, 31 + 2)])
    );
    // Round 2: those 133 again, then external 81-110 once 60 turned out to be used.
    assert_eq!(
        reals_per_stage(&rounds[1]),
        BTreeMap::from([(0, 133), (1, 30)])
    );
    assert_eq!(reals_per_stage(&rounds[2]), BTreeMap::from([(0, 163)]));
    let used = [
        (Keychain::External, [0, 1, 2, 5, 6, 30].as_slice()),
        (Keychain::Internal, [0, 1].as_slice()),
    ];
    for q in &rounds[0].queries {
        let is_used = used
            .iter()
            .any(|(k, idx)| *k == q.keychain && idx.contains(&q.index));
        match q.decoy {
            None => assert_eq!(q.tx_count.unwrap() > 0, is_used, "{q:?}"),
            Some(_) => assert_eq!(q.tx_count, Some(0), "a decoy with history: {q:?}"),
        }
        assert_eq!(q.script_type, "p2wpkh");
    }
    Ok(())
}
