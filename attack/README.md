# attack/

The adversary. Given a log of Electrum queries across one or more rounds, it computes a belief —
one probability per queried scripthash — that the scripthash belongs to the real wallet, then scores
that belief against the truth. This is what every privacy number in the project comes from. The
padding scheme itself lives in `haystack-electrum/`; this directory only attacks what it sends.
Standard-library Python 3 only — no dependencies.

Read `docs/03-metric.md` alongside this file for why the metrics are defined this way; this file is
the practical map of the code, not the argument for it. `docs/02-design.md`'s "A note on adversary
strength" (near the end) is the plain-language version of the `T0`/`T1`/`T2` levels below.

## Quick start

```bash
# from the repo root
python3 -m unittest discover -s tests

# why fresh random decoys collapse and fixed ones hold (docs/00-problem.md section 6)
python3 -m attack strategies

# the end-of-week-1 tripwire, against the committed real capture
python3 -m attack tripwire --honeypot tests/fixtures/bdk-honeypot-log.json \
                            --capture  tests/fixtures/bdk-capture-truth.json

# the full 13-row calibration suite (mixes the real capture with synthetic decoy rounds)
python3 -m attack calibrate --honeypot tests/fixtures/bdk-honeypot-log.json \
                             --capture  tests/fixtures/bdk-capture-truth.json

# score one real session round by round. A padded session is scored from haystack-electrum's
# session log, checked first against what the server itself received:
python3 -m attack score --session  tests/fixtures/haystack-session.jsonl \
                         --honeypot tests/fixtures/haystack-honeypot-log.json --tier T1
# a plain one from the honeypot's log and capture/'s record of what the wallet sent:
python3 -m attack score --honeypot tests/fixtures/bdk-honeypot-log.json \
                         --capture  tests/fixtures/bdk-capture-truth.json --tier T1

# the structural attacker (T2) on real sessions, trained on other wallets' sessions (Week 3,
# option B). The training and scored sessions come from regtest/'s session generator:
cargo run --release -p haystack-regtest --bin sessions -- --out regtest/sessions
python3 -m attack score --session regtest/sessions/p10/demo.jsonl --train regtest/sessions/p10 --tier T2
python3 -m attack curve --dir regtest/sessions     # bandwidth against score, every padding level
```

## What each file does

| File | Job |
|---|---|
| `observe.py` | The two input shapes. `Observation` is what the adversary sees: rounds of scripthashes in arrival order, plus a `Fact` (transaction count, script type) when the log carries one. `GroundTruth` is which scripthashes were real, kept in a separate type so an attack can't read the answer by accident. Loads the honeypot's log, `capture/`'s ground truth and `haystack-electrum`'s session log (`load_session`); `check_plain()` diffs a log against the truth, `check_session()` a session log against the honeypot's. |
| `a1.py` | `analyse()` walks the rounds and tracks each scripthash through three states: which round first queried it (its cohort), whether it later vanished (a wallet never stops watching its own addresses, so vanishing means decoy — weight 0), and whether it went from no transactions to some while being watched (a payment landed on it — certainly real, no decoy source can reproduce that). |
| `a2.py` | `StructuralModel`, a naive-Bayes classifier. Trained on labelled example rounds, it learns — separately for real and decoy scripthashes — how transaction-count bucket, script type, and position in the query are distributed, then turns an unlabelled scripthash's features into a likelihood ratio. Runs once per possible wallet script type and mixes the results, because the adversary isn't assumed to know the wallet's type in advance. |
| `posterior.py` | The exact math. `Block` takes a weight per scripthash and a count `k` ("exactly k of these are real") and computes every scripthash's exact marginal probability and the group's entropy, using elementary symmetric polynomials (`_esp_rows`) instead of enumerating subsets — `C(700, 70) ≈ 3.4 × 10^97` of them. `Posterior` composes independent groups (cohorts); `Mixture` composes the T2 per-script-type runs, weighted by how well each type fits. `Infeasible` is raised when the evidence is self-contradictory (e.g. a scripthash both ruled out and forced real) rather than silently producing a wrong number. |
| `harness.py` | Ties the above to an adversary level. `TIERS` names what each level may use: `T0` one round, no model; `T1` all rounds, using persistence/cohorts/activation; `T2` adds the structural classifier. `knowledge()` grants the attacker the count of real scripthashes newly seen in each round — a fixed padding ratio discloses this anyway (see `docs/03-metric.md`, open question 3). |
| `metrics.py` | Turns a `Posterior`/`Mixture` into a `Score`: `precision_bits` (the headline), `joint_bits`/`truth_bits` (calibration checks on the belief itself), `advantage` (secondary), and `candidates`, the count of scripthashes not yet ruled out. See the column table below. |
| `synth.py` | Generates synthetic wallets and decoys with assumed statistics, for the calibration suite and `strategies`. `pad()` applies decoy strategies (`plain`, `fresh`, `epoch`, `fixed`, `append`) to a sequence of real rounds; `synthetic_wallet()` builds a wallet with a gap-limit tail and optional payments; `world()` and `growing()` are used by the calibration suite. Every number derived from this file describes the attack code under assumed statistics, not Haystack's real traffic. |
| `train.py` | Option B. `fit()` builds a `StructuralModel` from labelled sessions of other wallets, after two safeguards: every training session must come from the same client build as the scored one (the session log's `client` record), and none may share a scripthash with it. Refusals raise `TrainingRefused`. The model is never saved. |
| `curve.py` | `curve()` — the bandwidth-versus-score table. At each padding level it scores every wallet with a model fit on the others (leave one out), and joins the bytes from `bandwidth.json`. |
| `calibrate.py` | `suite()` — the calibration table (13 configurations plus the analytic ceiling); `tripwire()` — the four pass/fail checks gating Week 1; `strategies()` — the decoy-strategy table of `docs/00-problem.md` §6; `run()`/`per_round()` — score one observation. |
| `__main__.py` | `python3 -m attack {strategies,tripwire,calibrate,score}`. |

## The belief, briefly

Every attack produces a weight per scripthash, not a score of its own: `0` rules it out (withdrawn —
must be a decoy), `1` is neutral, above `1` looks real, below `1` looks like a decoy, and "certainly
real" (paid while watched) is encoded as a forced member of its group rather than a weight. Within a
group of scripthashes first seen together, where exactly `k` are known to be real, the probability of
one particular subset of size `k` being the real one is proportional to the product of its members'
weights — this is Bayes' rule starting from a uniform prior over subsets. `docs/03-metric.md`'s
"How the adversary's belief over `Q` is built" walks the full worked example (a group of 5, weights
`{0, 3, 1, 1, 1}`) and the recursion that makes it computable at real sizes; this file just names
where each piece lives in code.

## Score columns

`attack/calibrate.py`'s own `LEGEND` is the source of truth (`python3 -m attack calibrate` prints it
at the end of its output); reproduced here for anyone reading the code without running it:

| Column | Meaning |
|---|---|
| `prec-b` | `-log2(max(precision, chance))` — the headline. `0.00` for plain Electrum, `log2(padding)` at the ceiling. |
| `prec%` | Expected share of real scripthashes among the adversary's top-`|R|` guesses. |
| `chance%` | `|R| / |Q|` — what a same-size random guess gets right, printed alongside precision for comparison. |
| `joint/R` | Entropy of the belief over which whole subset of `Q` is real, per real address — a calibration check, not a privacy number on its own (see `docs/03-metric.md` for why). |
| `truth/R` | `-log2 P(the true R)` per real address — whether the belief is actually correct, not just confident. |
| `adv` | `precision - chance` — kept as a secondary, easy-to-state number; can't tell a fully exposed wallet from a fully protected one on its own. |
| `fund-b`, `fund%` | Precision restricted to the scripthashes with history, against the funded reals: what the headline hides when the unused tail dominates it. `--` when no real has history. |

## Adversary levels

| Flag | What it may use | Built by |
|---|---|---|
| `T0` | The latest round only, no model of what a real wallet looks like. | `attack/harness.py` |
| `T1` | All rounds: which scripthashes persist, which vanish, which activate (`attack/a1.py`). This is the default, and the only level exercised against the real capture. | `attack/a1.py`, `attack/harness.py` |
| `T2` | Everything `T1` has, plus a `StructuralModel` trained on labelled rounds (`attack/a2.py`). Needs `model=` passed explicitly; `score --train` and `curve` fit it on real Haystack sessions of paid regtest wallets (`attack/train.py`). | `attack/a2.py` |
| `T3` (on-chain / co-spend) | Not implemented. `attack()` raises `ValueError` if asked for it. | — |

## What this does and doesn't cover

Real traffic comes in two committed sets in `tests/fixtures/`: six plain `bdk_wallet` full scans,
which the tripwire uses to confirm the plain-Electrum calibration point, and six `haystack-electrum`
scans at padding 10, which read the 3.32-bit ceiling at the single-round and many-rounds levels. Both
were sent to the honeypot, which answers "nothing found" to everything, so neither wallet was ever
paid. Every row involving activation or the structural classifier therefore still runs on synthetic
data from `synth.py` — those rows test this code, not Haystack, and the calibration suite's own
output says so under each table.
