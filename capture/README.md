# capture

A small Rust binary (`haystack-capture`) that runs stock `bdk_wallet` 2.1.0 and `bdk_electrum` 0.23.2
full scans against an Electrum server and writes down which scripthashes the wallet itself says it
queried. It links no Haystack code. Its one job is the unpadded baseline: the answer key that shows
what a server really learns from an ordinary wallet, recorded from the wallet's side rather than the
server's.

A scripthash is the hashed form of an address that Electrum uses as its lookup key (SHA-256 of the
script pubkey, bytes reversed, the same as `scripts/scripthash.py`).

## Why it exists

The project claims that plain Electrum hands the server every address the wallet owns. Proving that
takes two independent records of the same scan:

- **What the server saw.** This is the adversary's view. `scripts/honeypot_electrum.py` is a fake
  Electrum server that logs every scripthash it is asked about.
- **What the wallet really sent.** This is the answer key, called ground truth. Only the wallet can
  say which queries were its own. Capture records it.

`attack` then compares the two. If they match exactly, the claim is measured, not assumed.

## What it records

Each round creates a fresh, in-memory wallet from a public BIP84 descriptor pair (a descriptor is the
string that says how to derive every address of a wallet). It then runs a full scan on its own
connection. A full scan walks each of the wallet's two address chains, called keychains, from index 0
until it sees `stop_gap` (50) unused addresses in a row. The external keychain (`/0/*`) holds receive
addresses and the internal keychain (`/1/*`) holds change addresses. A never-paid wallet finds
nothing, so it queries 50 + 50 = 100 addresses per round.

These are real entries from round 0 of `tests/fixtures/bdk-capture-truth.json`, with the scripthash
cut to its first 16 hex characters:

| keychain | index | scripthash |
|---|---|---|
| external | 0 | `d179142620003677…` |
| external | 49 | `f4acbb38746c5da6…` |
| internal | 0 | `ad36d975aa6f471d…` |
| internal | 49 | `cef85a62d0333c2a…` |

The full round has 100 entries. The output is one JSON file:

```json
{"format": "haystack-capture/1", "network": "bitcoin",
 "external_descriptor": "wpkh([.../84'/0'/0']xpub.../0/*)#...",
 "internal_descriptor": "wpkh([.../84'/0'/0']xpub.../1/*)#...",
 "stop_gap": 50, "batch_size": 5,
 "rounds": [{"round": 0, "queried": [{"keychain": "external", "index": 0, "scripthash": "..."}]}]}
```

## How it fits with the honeypot and `attack`

The honeypot and capture record the same scan from two sides. In the committed fixtures the
honeypot's first logged query for connection 1 is `get_history d17914262000…`, and capture's round 0
starts with `external index 0 d17914262000…`. That is the same scripthash, the wallet's first receive
address: the honeypot saw it arrive, and capture recorded that the wallet sent it. The honeypot log
has 600 entries, which is 6 connections × 100 scripthashes.

`python3 -m attack score --honeypot … --capture … --tier T1` reads both files:

- `--honeypot` is the adversary's view. The honeypot tags each query with a connection number, and
  `attack` treats each connection as one round.
- `--capture` is the answer key: each round's `queried` list is the set of real scripthashes.
- `--tier T1` is how much the attacker may use: every round, through the many-rounds attack.

It does two things with them:

1. **A consistency check.** `check_plain()` in `attack/observe.py` compares what the server received
   with what the wallet sent. `unexpected` counts scripthashes the server got that the wallet didn't
   send, and `missing` counts the reverse. For a plain scan both must be 0 in every round, or the
   score is not trusted.
2. **The score.** The attacker guesses which scripthashes are real from the honeypot log alone, and
   the guesses are graded against capture's list. For plain Electrum every guess is right, so the
   table reads 0.00 bits and 100% precision.

`tests/test_plain_capture.py` does this on the committed fixtures. Those hold six rounds, and running
`capture/` with `--rounds 6` reproduces `tests/fixtures/bdk-capture-truth.json` exactly.

## Run it

Build it from the repo root:

```bash
cargo build --release -p haystack-capture
```

Terminal 1: start the fake server. It answers "nothing found" to every query, so the wallet walks
its whole gap limit, and it writes `honeypot-log.json` when you press Ctrl-C after the scan:

```bash
python3 scripts/honeypot_electrum.py
```

Terminal 2: run one real scan against it. The wallet's own record of what it sent goes to
`capture-truth.json`:

```bash
./target/release/haystack-capture --out capture-truth.json
```

Then, after pressing Ctrl-C in terminal 1, score the honeypot's log against the wallet's record:

```bash
python3 -m attack score --honeypot honeypot-log.json --capture capture-truth.json --tier T1
```

Start a fresh honeypot for each capture. It numbers connections from 1 and `attack` pairs the honeypot's
connection *n* with capture's round *n*, so a honeypot that already served an earlier run misaligns them.

**Never send funds to the demo seed.** Anyone can derive its private key.

## What it does not do

It does not run padded syncs. A padded sync's ground truth is the client's own session log
(`haystack-session/1`, written by `haystack-electrum` and by `demo/`), which `python3 -m attack
score --session … --honeypot …` checks against what the honeypot received. `docs/07-walkthrough.md`
case 3 shows it.
