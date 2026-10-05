# haystack-electrum

A sibling crate to `bdk_electrum`: `HaystackElectrumClient` exposes the same `full_scan` surface,
but every batch it sends is padded with decoy scripthashes before it reaches the server. An app
that already drives `bdk_wallet` with `bdk_electrum` swaps the client and gets the same response
type back; the padding happens inside, at the batch level, not as a wrapper around the upstream
client (`docs/02-design.md`, "haystack-electrum: the padded sync client," explains why a wrapper
can't do this).

A decoy is a scripthash (`docs/00-problem.md` §1) for a script nobody holds a key for, built so the
server cannot tell it apart from a real one on the wire.

## What it does

Each sync is a full scan, so the client walks the wallet's two keychains — external (receive) and
internal (change) — from index 0 until it sees `stop_gap` unused positions in a row, exactly as
upstream does. For every real position it queries, it also sends some number of decoys of the same
script type, shuffled into the batch so the server sees one flat list of scripthashes with no way to
single out which are real.

| Module | What it owns |
|---|---|
| [`client.rs`](src/client.rs) | `HaystackElectrumClient`: drives the scan in stages, same caches and merkle-proof checks as `bdk_electrum` 0.23.2 |
| [`planner.rs`](src/planner.rs) | Round planning — which real positions to query, and in how many sequential stages |
| [`decoy.rs`](src/decoy.rs) | HMAC-direct decoys: a script built from `HMAC-SHA256(key, keychain ‖ index ‖ j)` |
| [`chain.rs`](src/chain.rs) | Chain-sourced decoys — real, previously-used scripts found by probing the sync server itself |
| [`ledger.rs`](src/ledger.rs) | In-memory record of how many decoys are frozen per position, and their chain-sourced scripts |
| [`ledger_file.rs`](src/ledger_file.rs) | The ledger on disk (`haystack-ledger/1` or `/2`) — also the wallet's Haystack backup |
| [`cache_file.rs`](src/cache_file.rs) | The saved transaction/proof cache (`haystack-cache/1`), filled only by what the client itself fetched |
| [`session.rs`](src/session.rs) | The session log (`haystack-session/1`) — what was sent, what came back, and which queries were real |
| [`schedule.rs`](src/schedule.rs) | When the next automatic sync fires: a memoryless exponential delay, so timing carries no signal |
| [`key.rs`](src/key.rs) | The decoy key, derived from the wallet's own xpubs so every device reaches the same decoys |
| [`keychain.rs`](src/keychain.rs) | Maps a request's keychain type (e.g. `bdk_wallet::KeychainKind`) onto the crate's own `Keychain` |

## The rule decoys follow

Decoys are **deterministic per wallet** and **append-only**: the first time a position is queried,
its decoy count is frozen in the ledger, and the same decoys are sent again on every later sync.
Moving the dial changes only positions frozen after the move, so decoys are added but never
withdrawn. Re-randomised decoys let a server intersect query sets across syncs and recover the
wallet in three rounds, and decoys rotated on any schedule collapse the moment a second epoch is
observed (`docs/00-problem.md` §6, checked by `tests/test_regression.py`; the design argument is in
`docs/02-design.md`).

## Adopting it in a `bdk_wallet` app

`HaystackElectrumClient::new(inner, decoy_key, padding)` stands in for `BdkElectrumClient::new(inner)`,
and `full_scan` keeps upstream's signature. An app makes five kinds of change. The crate has no
`sync` and no `transaction_broadcast`, so an app that misses one of them fails to compile instead of
silently sending an unpadded query. The demo wallet makes exactly these five and no others
(`demo/README.md` compares it line by line with `bdk_wallet`'s own Electrum example).

1. **Construct the client with the decoy key**, the padding dial, the ledger file and the saved
   cache file (the code sample below). The key comes from the wallet's own public keys, so every
   device reaches the same decoys, and the ledger file is the wallet's Haystack backup.
2. **Replace each `sync` with a full scan.** A sync of handed-out addresses only would drop the
   unused addresses and their decoys from the query, which exposes them.
3. **Broadcast through a different server** than the one the wallet syncs with, because
   broadcasting through the session's server would tie the transaction to it
   (`docs/01-threat-model.md`).
4. **Don't pre-fill the transaction cache from the wallet's own transactions.** There is no
   `populate_tx_cache`: a cache holding only real transactions makes a restarted client refetch
   every decoy transaction and no real one, which is exactly the signal the padding exists to hide
   (`cache_file.rs`).
5. **Pass the wallet's expected unconfirmed transactions to the scan**, as
   `full_scan_expecting(wallet.start_full_scan(), wallet.start_sync_with_revealed_spks(), …)`. A
   full scan alone can't tell when an unconfirmed transaction has left the mempool; this list, the
   one upstream's `sync` uses, can. It is checked locally and nothing extra is sent to the server.

## Use it

```toml
[dependencies]
haystack-electrum = { path = "../haystack-electrum" }
```

Where `bdk_electrum` takes only a connection, this client also takes the decoy key and the padding
dial, plus optional files for the ledger, the saved cache and the session log:

```rust
let key = DecoyKey::from_xpubs([account_xpub]).expect("one xpub");
let mut client = HaystackElectrumClient::new(electrum_client::Client::new(url)?, key.clone(), 10)
    .with_store(LedgerFile::new("ledger.json"))
    .with_saved_cache(CacheFile::new("cache.json").load()?)
    .with_cache_store(CacheFile::new("cache.json"));
if let Some(ledger) = LedgerFile::new("ledger.json").load(&key)? {
    // A ledger built from another wallet's key is refused rather than silently replacing every decoy.
    client = client.with_ledger(ledger).map_err(|e| anyhow::anyhow!("{e:?}"))?;
}
let update = client.full_scan(wallet.start_full_scan(), 50, 5, false)?;
wallet.apply_update(update)?;
```

`demo/src/wallet.rs` is this pattern in a real app, against a live regtest chain and with a padding
dial a user can turn. `tests/full_scan.rs` runs the client against an in-memory Electrum server next
to upstream's client and checks that both return the same wallet data:

```bash
cargo test -p haystack-electrum
```

## Known leak: chain-sourced decoys

Finding a chain-sourced decoy means probing the sync server for a random transaction's history,
which a real wallet never does, so a server that reads its own log can name every one. The leak is
accepted for now and recorded in the session log as `probes`, for an attack that isn't written yet
(`chain.rs`; `docs/02-design.md`, "Where decoys come from").

## Built on

[`bdk_core`](https://github.com/bitcoindevkit/bdk) for the wallet-facing types (`FullScanRequest`,
`TxUpdate`, …), [`electrum-client`](https://github.com/bitcoindevkit/rust-electrum-client) for the
wire protocol, and optionally `bdk_wallet` (default feature) so `full_scan` accepts
`bdk_wallet::KeychainKind` directly as its keychain type.

## License

GPL-3.0-only — see the repository [LICENSE](../LICENSE).
