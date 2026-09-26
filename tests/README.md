# tests/

25 unit tests covering `attack/`'s math and logic, the honeypot script's request handling, and the
end-of-week-1 tripwire against a real captured wallet. Standard-library `unittest`, no dependencies.

```bash
python3 -m unittest discover -s tests      # all 25, from the repo root
python3 -m unittest tests.test_posterior   # one file
```

## What each file checks

| File | What it checks |
|---|---|
| `test_posterior.py` | The exact-math shortcut in `attack/posterior.py` (elementary symmetric polynomials, avoiding enumerating every subset) against literally listing every subset by brute force, on 300 random small cases, plus a closed-form check at `n = 400, k = 40`. This is the test that justifies trusting the fast method at real scale. |
| `test_a1.py` | Persistence, withdrawal, and activation logic (`attack/a1.py`): a vanished scripthash is weighted out, a scripthash that goes from no history to some while watched is forced real, and a newly-added real address arriving without its own decoys is exposed (the delta corollary). |
| `test_a2.py` | The structural classifier (`attack/a2.py`) separates careless decoys from real addresses well, stays near chance against decoys generated from the same distribution as the real wallet (the oracle case), and that sending real addresses in a predictable position leaks even against otherwise perfect decoys. |
| `test_metrics.py` | The calibration anchors: plain Electrum reads `0.00` on every metric, a theoretically perfect scheme hits the exact analytically-computed ceiling, and an attack that does worse than random guessing is never credited as beating the defence. |
| `test_honeypot.py` | Starts the real honeypot server (`scripts/honeypot_electrum.py`), sends it two fake connections, and checks the log correctly tags each entry with its connection, batch, and position. |
| `test_regression.py` | Locks in that known-broken decoy schemes (fresh-random, and decoys rotated every few rounds) always score near zero privacy — a permanent guard so the metric can't quietly start rating a known-broken scheme well. |
| `test_tripwire.py` | Runs the full pipeline against the real captured honeypot rounds in `fixtures/` and checks it passes the end-of-week-1 bar (`docs/04-roadmap.md`). |

## `fixtures/`

Two files, produced together against the same six real scans and committed so the tests above don't
need a live wallet or a running honeypot to reproduce:

- `bdk-honeypot-log.json` — what the fake Electrum server (`scripts/honeypot_electrum.py`) recorded
  receiving: 600 entries (6 connections × 100 scripthashes), each tagged with its connection, batch,
  and position.
- `bdk-capture-truth.json` — what the wallet itself recorded sending, from `capture/` (see
  `capture/README.md`): the same six rounds, independently, as the wallet's own derivation.

`attack/observe.py`'s `check_plain()` diffs the two; the tripwire test requires them to match exactly
(0 unexpected, 0 missing scripthashes in every round) before it will even evaluate the rest of the
checks.

## What isn't covered here

Every test that touches decoys, activation, or the structural classifier runs on synthetic data from
`attack/synth.py`, because there is no real padded traffic yet — the query engine that would produce
it (`haystack-electrum`) is Week 2 work. `fixtures/`'s two files are the only real, captured traffic
in the repo, and they're both plain, unpadded scans.
