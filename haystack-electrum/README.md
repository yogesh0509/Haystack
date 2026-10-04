# haystack-electrum

A sibling crate to `bdk_electrum`: `HaystackElectrumClient` exposes the same `full_scan` surface,
but every batch it sends is padded with decoy scripthashes before it reaches the server. An app
that already drives `bdk_wallet` with `bdk_electrum` swaps the client and gets the same response
type back; the padding happens inside, at the batch level, not as a wrapper around the upstream
client (`docs/02-design.md`, "haystack-electrum: the padded sync client," explains why a wrapper
can't do this).

A scripthash is the hashed form of an address that Electrum uses as its lookup key (SHA-256 of the
script pubkey, bytes reversed). A decoy is a scripthash for a script nobody holds a key for, built
so the server cannot tell it apart from a real one on the wire.

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
Moving the dial changes only positions frozen after the move, so new positions and decoys can be
added but none is ever withdrawn. Both properties come from the same finding in
`tests/test_regression.py`: independent, re-randomised decoys let a server intersect query sets
across syncs and recover the wallet in three rounds, and decoys rotated on any schedule collapse the
moment a second schedule epoch is observed. `docs/02-design.md` has the full argument.

## What it does not do

No `sync` and no `transaction_broadcast`. Every sync here is a full scan — a revealed-only sync
would drop the unused tail and its decoys, and broadcasting through this session's server would tie
a transaction to it (`docs/01-threat-model.md`). `full_scan_expecting` covers the one thing a plain
full scan can't: telling when an unconfirmed transaction has left the mempool. It takes the expected-
transaction list an app would otherwise pass to upstream's `sync` and checks it locally; nothing
extra is sent to the server for it.

No `populate_tx_cache`. A cache filled from the wallet's own stored transactions would hold reals
only, and after a restart the client would refetch every decoy and no real one — which is exactly
the signal the padding exists to hide. See `cache_file.rs`.

Chain-sourced decoys leak by construction: finding one means probing the sync server for a random
transaction's history, and a real wallet never makes that kind of lookup. The leak is accepted for
now and recorded in the session log as `probes`, for an attack that isn't written yet
(`chain.rs`, `docs/02-design.md` §"Where decoys come from").

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

## Built on

[`bdk_core`](https://github.com/bitcoindevkit/bdk) for the wallet-facing types (`FullScanRequest`,
`TxUpdate`, …), [`electrum-client`](https://github.com/bitcoindevkit/rust-electrum-client) for the
wire protocol, and optionally `bdk_wallet` (default feature) so `full_scan` accepts
`bdk_wallet::KeychainKind` directly as its keychain type.

## License

GPL-3.0-only — see the repository [LICENSE](../LICENSE).
