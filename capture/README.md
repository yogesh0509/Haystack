# capture

A small Rust binary (`haystack-capture`) that runs stock `bdk_wallet` 2.1.0 and `bdk_electrum` 0.23.2
full scans against an Electrum server and writes down which scripthashes the wallet itself says it
queried. It links no Haystack code. Its one job is the unpadded baseline: the answer key that shows
what a server really learns from an ordinary wallet, recorded from the wallet's side rather than the
server's.

A scripthash is the hashed form of an address that Electrum uses as its lookup key (SHA-256 of the
script pubkey, bytes reversed, the same as `scripts/scripthash.py`).

## What it records

Each round creates a fresh, in-memory wallet from a public BIP84 descriptor pair and runs
`wallet.start_full_scan()` on its own connection. An `inspect` callback, which bdk calls for every
address it is about to query, collects each `(keychain, index, scripthash)`. The output is one JSON
file:

```json
{"format": "haystack-capture/1", "network": "bitcoin",
 "external_descriptor": "wpkh([.../84'/0'/0']xpub.../0/*)#...",
 "internal_descriptor": "wpkh([.../84'/0'/0']xpub.../1/*)#...",
 "stop_gap": 50, "batch_size": 5,
 "rounds": [{"round": 0, "queried": [{"keychain": "external", "index": 0, "scripthash": "..."}]}]}
```

Pointed at `scripts/honeypot_electrum.py`, which logs what the server received, the two files can be
compared: `attack/observe.py`'s `check_plain()` requires the server's log to equal the wallet's own
record, and the attacker then reads 0.00 bits. `tests/test_plain_capture.py` does this on committed
fixtures, and running `capture/` again reproduces `tests/fixtures/bdk-capture-truth.json` exactly.

## Run it

```bash
cargo build --release -p haystack-capture          # from the repo root

python3 scripts/honeypot_electrum.py                # terminal 1; Ctrl-C when the scan is done
./target/release/haystack-capture --rounds 6 --out capture-truth.json   # terminal 2
python3 -m attack score --honeypot honeypot-log.json --capture capture-truth.json --tier T1
```

Start a fresh honeypot for each capture. It numbers connections from 1 and `attack` pairs the honeypot's
connection *n* with capture's round *n*, so a honeypot that already served an earlier run misaligns them.

| Flag | Default | Meaning |
|---|---|---|
| `--url` | `tcp://127.0.0.1:50001` | The Electrum server to scan against. |
| `--rounds` | `1` | How many scans to run. Each round starts a brand-new wallet, so six rounds are six copies of the same never-paid, 100-scripthash scan, not a wallet receiving payments over time. |
| `--stop-gap` | `50` | Consecutive unused positions before a keychain counts as exhausted. A never-paid wallet queries `2 × stop_gap` scripthashes per round. |
| `--batch-size` | `5` | Addresses per socket write, the value `bdk_wallet`'s own Electrum example uses. |
| `--seed` | `haystack-capture-demo` | A public string, SHA-256'd into a BIP32 master key. The demo wallet in `demo/` derives the same one, and a test there checks that the two agree. |
| `--out` | `capture-truth.json` | Where the JSON is written. |

**Never send funds to the demo seed.** Anyone can derive its private key.

## What it does not do

It does not run padded syncs. A padded sync's ground truth is the client's own session log
(`haystack-session/1`, written by `haystack-electrum` and by `demo/`), which `python3 -m attack
score --session … --honeypot …` checks against what the honeypot received. `docs/07-walkthrough.md`
case 3 shows it.
