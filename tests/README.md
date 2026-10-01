# tests/

46 tests covering `attack/`'s math and logic, the honeypot script's request handling, the
end-of-week-1 tripwire against a real captured wallet, and the first real padded session. Standard-library `unittest`, no dependencies.

```bash
python3 -m unittest discover -s tests      # all 46, from the repo root
python3 -m unittest tests.test_posterior   # one file
```

## What each file checks

| File | What it checks |
|---|---|
| `test_posterior.py` | The exact-math shortcut in `attack/posterior.py` (elementary symmetric polynomials, avoiding enumerating every subset) against literally listing every subset by brute force, on 300 random small cases, plus a closed-form check at `n = 400, k = 40`. This is the test that justifies trusting the fast method at real scale. |
| `test_a1.py` | Persistence, withdrawal, and activation logic (`attack/a1.py`): a vanished scripthash is weighted out, a scripthash that goes from no history to some while watched is forced real, and a newly-added real address arriving without its own decoys is exposed (the delta corollary). |
| `test_a2.py` | The structural classifier (`attack/a2.py`) separates careless decoys from real addresses well, stays near chance against decoys generated from the same distribution as the real wallet (the oracle case), and that sending real addresses in a predictable position leaks even against otherwise perfect decoys. |
| `test_metrics.py` | The calibration anchors: plain Electrum reads `0.00` on every metric, a theoretically perfect scheme hits the exact analytically-computed ceiling, an attack that does worse than random guessing is never credited as beating the defence, and the funded-address column on the restored-wallet worked example: 100% with HMAC-direct decoys while the headline stays above 3 bits, chance with matched decoys. |
| `test_honeypot.py` | Starts the real honeypot server (`scripts/honeypot_electrum.py`), sends it two fake connections, and checks the log correctly tags each entry with its connection, batch, and position. |
| `test_regression.py` | Locks in that known-broken decoy schemes (fresh-random, and decoys rotated every few rounds) always score near zero privacy — a permanent guard so the metric can't quietly start rating a known-broken scheme well — and that `python3 -m attack strategies`, step 4 of the README's five-minute check, still reproduces `docs/00-problem.md` §6. |
| `test_tripwire.py` | Runs the full pipeline against the real captured honeypot rounds in `fixtures/` and checks it passes the end-of-week-1 bar (`docs/04-roadmap.md`). |
| `test_train.py` | Option B's safeguards (`attack/train.py`): a training session from a different client build, or with no provenance, is refused; so is one with any of the scored session's reals as its own reals, or recorded at another chain share; a scored real appearing as another wallet's decoy is allowed; and the scored session can't be its own training set. |
| `test_session.py` | Reading `haystack-session/1`: reals versus decoys, a script type hidden until its scripthash has history, an unanswered query observed but factless, and the check that catches a session log disagreeing with the server's order. |
| `test_padded_session.py` | Six real `haystack-electrum` scans at padding 10, against the honeypot: the server received exactly the wallet's reals plus the ledger's decoys, the same set every round, and the many-rounds attacker reads the 3.32-bit ceiling. |

## `fixtures/`

Two pairs of files, each produced together from six real scans and committed so the tests above don't
need a live wallet or a running honeypot to reproduce. The plain pair:

- `bdk-honeypot-log.json` — what the fake Electrum server (`scripts/honeypot_electrum.py`) recorded
  receiving: 600 entries (6 connections × 100 scripthashes), each tagged with its connection, batch,
  and position.
- `bdk-capture-truth.json` — what the wallet itself recorded sending, from `capture/` (see
  `capture/README.md`): the same six rounds, independently, as the wallet's own derivation.

`attack/observe.py`'s `check_plain()` diffs the two; the tripwire test requires them to match exactly
(0 unexpected, 0 missing scripthashes in every round) before it will even evaluate the rest of the
checks.

The padded set, three files from one run of `capture/ --padding 10 --batch-size 50 --session …`
against the same honeypot and demo wallet:

- `haystack-honeypot-log.json` — 6,000 entries (6 connections × 1,000 scripthashes).
- `haystack-capture-truth.json` — the wallet's 100 real scripthashes per round, plus the 900 decoys
  its ledger says it sent.
- `haystack-session.jsonl` — the client's session log: every query in send order, tagged real or
  decoy, with the server's answer.

## What isn't covered here

Every test that touches activation or the structural classifier runs on synthetic data from
`attack/synth.py`. The one real padded session in `fixtures/` came from the honeypot, which answers
"nothing found" to everything: the wallet is never paid, and the server's view carries no
transaction counts or script types. `haystack-electrum`'s own Rust tests
(`cargo test -p haystack-electrum`) cover its correctness against an in-memory server, and
`regtest/`'s gate (`cargo test -p haystack-regtest`) covers a paid wallet on a real regtest chain,
including confirmed transactions and a reorganisation — see `regtest/README.md`.
