//! A payment that leaves the mempool unconfirmed must leave the wallet's balance, through Haystack
//! as through upstream's `sync` (`docs/02-design.md`, "haystack-electrum").
//!
//! The node pays the wallet 0.02 BTC, unconfirmed, and every copy of the wallet sees it. Then the
//! node double-spends the same coins to its own address with a higher fee. The replacement never
//! touches the wallet's addresses, so only the list of expected transactions can say the payment
//! is gone.
//!
//! Three copies of the wallet:
//! - upstream `bdk_electrum`, a full scan and then the `sync` bdk's example uses;
//! - Haystack at padding 10 with `full_scan_expecting`, given the same expected transactions;
//! - Haystack with a plain `full_scan`, which can't know, to show the gap being closed.

use bdk_electrum::BdkElectrumClient;
use bdk_testenv::bitcoincore_rpc::RpcApi;
use bdk_wallet::bitcoin::{Amount, Sequence, Transaction, TxOut, Txid, Witness};
use bdk_wallet::{KeychainKind, Wallet};
use electrum_client::ElectrumApi;
use haystack_electrum::client::HaystackElectrumClient;
use haystack_electrum::key::DecoyKey;
use haystack_electrum::ledger::Ledger;
use haystack_regtest::{
    electrum, external, mine, new_wallet, wait_for_history, Error, TestEnv, STOP_GAP,
};

/// One Haystack scan on a new connection, carrying the ledger as a wallet would.
fn haystack(
    env: &TestEnv,
    wallet: &mut Wallet,
    key: &DecoyKey,
    ledger: Ledger,
    expecting: bool,
) -> Result<Ledger, Error> {
    let client = HaystackElectrumClient::new(electrum(env)?, key.clone(), 10)
        .with_ledger(ledger)
        .map_err(|e| format!("{e:?}"))?;
    let update = if expecting {
        client.full_scan_expecting(
            wallet.start_full_scan(),
            wallet.start_sync_with_revealed_spks(),
            STOP_GAP,
            5,
            false,
        )?
    } else {
        client.full_scan(wallet.start_full_scan(), STOP_GAP, 5, false)?
    };
    wallet.apply_update(update)?;
    Ok(client.into_ledger())
}

/// Replaces `txid` with a transaction spending the same coins to the node itself, 10,000 sat more
/// in fees, and waits until electrs no longer lists the original for `script`.
fn double_spend(
    env: &TestEnv,
    txid: Txid,
    script: &bdk_wallet::bitcoin::Script,
) -> Result<Txid, Error> {
    let rpc = &env.bitcoind.client;
    let original: Transaction = rpc.get_raw_transaction(&txid, None)?;
    let paid: Amount = original.output.iter().map(|o| o.value).sum();
    let to = rpc.get_new_address(None, None)?.assume_checked();
    let mut replacement = original.clone();
    for input in &mut replacement.input {
        input.script_sig = Default::default();
        input.witness = Witness::new();
        input.sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;
    }
    replacement.output = vec![TxOut {
        value: paid - Amount::from_sat(10_000),
        script_pubkey: to.script_pubkey(),
    }];
    let signed = rpc.sign_raw_transaction_with_wallet(&replacement, None, None)?;
    if !signed.complete {
        return Err("the node couldn't sign the replacement".into());
    }
    let replaced = rpc.send_raw_transaction(&signed.transaction()?)?;
    let client = electrum(env)?;
    for _ in 0..600 {
        env.electrsd.trigger()?;
        if !client
            .script_get_history(script)?
            .iter()
            .any(|h| h.tx_hash == txid)
        {
            return Ok(replaced);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err("electrs kept listing the replaced payment".into())
}

fn pending(w: &Wallet) -> Amount {
    let b = w.balance();
    b.trusted_pending + b.untrusted_pending
}

#[test]
fn a_payment_dropped_from_the_mempool_leaves_the_balance_as_after_upstreams_sync(
) -> Result<(), Error> {
    let env = haystack_regtest::start()?;
    mine(&env, 101)?;
    let rw = new_wallet("haystack-eviction-test")?;
    let key = rw.decoy_key();
    let (mut upstream, mut ours, mut blind) = (rw.wallet(), rw.wallet(), rw.wallet());

    // An unconfirmed payment that signals replaceability, as Bitcoin Core's wallet does by default.
    let address = external(&upstream, 0);
    let txid = env.bitcoind.client.send_to_address(
        &address,
        Amount::from_sat(2_000_000),
        None,
        None,
        None,
        Some(true),
        None,
        None,
    )?;
    wait_for_history(&env, &address.script_pubkey(), txid)?;

    // Everyone's first scan sees it.
    let update = BdkElectrumClient::new(electrum(&env)?).full_scan(
        upstream.start_full_scan(),
        STOP_GAP,
        5,
        false,
    )?;
    upstream.apply_update(update)?;
    let ledger = haystack(&env, &mut ours, &key, Ledger::new(&key), true)?;
    let blind_ledger = haystack(&env, &mut blind, &key, Ledger::new(&key), false)?;
    for w in [&upstream, &ours, &blind] {
        assert_eq!(pending(w), Amount::from_sat(2_000_000));
    }

    let replaced = double_spend(&env, txid, &address.script_pubkey())?;
    println!("payment {txid} replaced by {replaced}, which pays the node");

    // The example's sync, and Haystack's full scan given the same expected transactions.
    let update = BdkElectrumClient::new(electrum(&env)?).sync(
        upstream.start_sync_with_revealed_spks(),
        5,
        false,
    )?;
    upstream.apply_update(update)?;
    haystack(&env, &mut ours, &key, ledger, true)?;
    haystack(&env, &mut blind, &key, blind_ledger, false)?;

    assert_eq!(
        upstream.balance().total(),
        Amount::ZERO,
        "upstream's sync drops the payment"
    );
    assert_eq!(ours.balance(), upstream.balance());
    assert_eq!(ours.transactions().count(), upstream.transactions().count());
    assert_eq!(
        ours.derivation_index(KeychainKind::External),
        upstream.derivation_index(KeychainKind::External)
    );
    // Without the expected transactions the payment stays, which is the gap the expectations close.
    assert_eq!(pending(&blind), Amount::from_sat(2_000_000));
    Ok(())
}
