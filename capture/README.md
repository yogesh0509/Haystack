# capture/

A small Rust binary (`haystack-capture`) that runs real `bdk_wallet` full scans against an Electrum
endpoint and writes down exactly what the wallet itself asked for. It exists to produce **ground
truth** for `attack/`: a record, independent of anything a server logs, of which scripthashes are
actually the wallet's own.

**This tool does not pad anything.** It sends a plain, unmodified full scan — no decoys, no query
crafting. The decoy scheme that will eventually sit in front of a sync (`haystack-electrum`,
`docs/04-roadmap.md` Week 2) doesn't exist yet; `capture/` is a measurement tool, not a preview of it.

## What it produces

For each round, it creates a fresh, unsynced, in-memory wallet from a BIP84 (native segwit)
descriptor pair and calls `wallet.start_full_scan()`, with an `inspect` callback recording every
`(keychain, index, script pubkey)` the wallet queries — this is the wallet's own account of what it
sent, not a copy of what any server saw. Output is one JSON file:

```json
{
  "format": "haystack-capture/1",
  "network": "bitcoin",
  "external_descriptor": "wpkh([.../84'/0'/0']xpub.../0/*)",
  "internal_descriptor": "wpkh([.../84'/0'/0']xpub.../1/*)",
  "stop_gap": 50,
  "batch_size": 5,
  "rounds": [
    {"round": 0, "queried": [{"keychain": "external", "index": 0, "scripthash": "..."}, ...]}
  ]
}
```

Each round's `scripthash` is computed the same way `scripts/scripthash.py` computes it (SHA-256 of
the script pubkey, bytes reversed), so a query set here is directly comparable to a honeypot log
loaded by `attack/observe.py`'s `load_capture()`.

## Building and running

```bash
cargo build --release --manifest-path capture/Cargo.toml

# terminal 1: the fake server that logs every query it receives
python3 scripts/honeypot_electrum.py

# terminal 2: point the capture tool at it
./capture/target/release/haystack-capture --url tcp://127.0.0.1:50001 --rounds 6 \
    --out capture/capture-truth.json
```

| Flag | Default | Meaning |
|---|---|---|
| `--url` | `tcp://127.0.0.1:50001` | The Electrum endpoint to scan against — the honeypot by default. |
| `--stop-gap` | `50` | Consecutive unused positions before a keychain is considered exhausted. A never-paid wallet queries `2 × stop_gap` scripthashes per round. |
| `--batch-size` | `5` | Requests per socket write, matching `bdk_wallet`'s own example. |
| `--rounds` | `1` | How many independent full scans to run. Each round creates a brand-new wallet, so consecutive rounds are not a growing session — see the caveat below. |
| `--seed` | `haystack-capture-demo` | A public string, SHA-256'd into a BIP32 master key. Not a real wallet seed phrase — deliberately public, so anyone can reproduce the same descriptors and the same numbers. |
| `--out` | `capture-truth.json` | Where the ground-truth JSON is written. |

**Never send funds to the demo seed.** Because `--seed` is a plain public string, anyone can derive
its private key. It exists only to make this tool's output reproducible by a third party.

**Rounds are independent scans, not a growing session.** Each round starts a fresh `Wallet`, so
`--rounds 6` produces six copies of the same never-paid, 100-scripthash scan — useful for exercising
`attack/`'s many-rounds logic against something a real server actually sent, but it does not simulate
a wallet receiving payments over time (`attack/synth.py`'s `growing()` does that, synthetically).

## The committed fixture

`tests/fixtures/bdk-capture-truth.json` and `tests/fixtures/bdk-honeypot-log.json` are exactly the two
files this pipeline produces: `capture/` writes the first, `scripts/honeypot_electrum.py` writes the
second, from the same six rounds, at the same time. Both are committed so the tripwire test
(`tests/test_tripwire.py`) is reproducible without a live wallet — see `tests/README.md`.

## Which `bdk_wallet` version, and why

This crate targets `bdk_wallet` **2.1.0**, pinned in `Cargo.toml` and resolved in `Cargo.lock` (along
with `bdk_electrum` 0.23.2, `bdk_chain` 0.23.3, `bdk_core` 0.6.3, `electrum-client` 0.24.1) — the
published, stable release from crates.io, not the local `~/bdk_wallet` fork (version 3.1.0), which
exists only in that checkout. `docs/02-design.md`, "Which upstream version to copy," has the full
reasoning, including why the eventual `haystack-electrum` crate has to resolve the same `bdk_core`
minor version this one does.
