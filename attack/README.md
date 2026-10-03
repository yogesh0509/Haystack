# attack/

This module is the attacker. It reads a log of the Electrum queries a wallet made, possibly across several rounds, and tries to guess which queries were for the wallet's real addresses and which were decoys. For each queried scripthash (the hashed form of an address that Electrum uses as its lookup key) it outputs a probability that the scripthash is real, then compares those guesses against the actual truth to see how good the attacker was. Every privacy number reported elsewhere in the project is computed from this comparison.

Read `docs/03-metric.md` alongside this file for why the score is defined this way.

## The two attacks

Haystack hides a wallet's real scripthashes among decoys. The attacker has two independent ways to
tell them apart, and each is one file.

**A1, the many-rounds attack** ([a1_many_rounds.py](a1_many_rounds.py)) compares syncs. It needs no
training, only the server's own log of what each sync asked for. It uses three facts about how a
wallet behaves:

- A wallet never stops asking about its own addresses. So a scripthash that was queried and then
  disappears from a later sync must be a decoy.
- Scripthashes first queried in the same sync form a group (a cohort). The attacker knows how many
  real addresses each group holds, because a fixed padding ratio reveals it: 1,000 new queries at
  padding 10 means 100 new real ones.
- A scripthash that goes from no transaction history to some, while the wallet is watching it, has
  just been paid. Nobody pays a decoy, so it must be real.

This is why decoys must be the same in every sync and never withdrawn: decoys redrawn every sync are
undone in about three syncs (`docs/00-problem.md` §6).

**A2, the structural attack** ([a2_structural.py](a2_structural.py)) looks at a single sync. It
learns what real scripthashes look like compared with decoys, using what the server sees about each
one: its transaction count, its script type, and its position in the query. It is a naive-Bayes
classifier. It is trained on labelled sessions of *other* wallets made by the same client build,
never on the wallet being scored. For example, if decoys have no history but some real addresses
do, A2 learns that "has history" means "real".

## How the evidence becomes a score

The two attacks never score anything themselves. Each turns what it found into a weight per
scripthash:

- A weight of `0` rules a scripthash out; a vanished scripthash gets this from A1.
- A weight of `1` means no information.
- A weight above `1` means it looks real, and below `1` means it looks like a decoy; A2 produces
  these.
- A scripthash that A1 saw being paid is marked as certainly real.

[posterior.py](posterior.py) turns the weights into a probability per scripthash. Within a cohort of
`n` scripthashes of which exactly `k` are real, every possible set of `k` real ones gets a
probability proportional to the product of its members' weights. That is Bayes' rule starting from
"every set is equally likely". Listing the sets is impossible at real sizes: choosing 70 of 700 has
about 3.4 × 10^97 possibilities. So the file computes each scripthash's probability exactly with a
running-total recursion instead. `docs/03-metric.md`, "How the adversary's belief over `Q` is built",
works through a five-scripthash example by hand.

[scoring.py](scoring.py) takes the attacker's top `|R|` guesses by probability (`|R|` is the number of
real scripthashes), counts how many are real, and reports that against what a random guess of the
same size would get. It also decides which evidence each attacker level may use:

| Level | What it may use |
|---|---|
| `T0` | The latest sync only, with no model of what a real wallet looks like. |
| `T1` | Every sync, through A1. This is the default. |
| `T2` | Everything `T1` has, plus A2. `score --train` and `curve` train it on real Haystack sessions of paid regtest wallets. |

## Quick start

Run every command below from the repo root.

Run the unit tests:

```bash
python3 -m unittest discover -s tests
```

Score a padded Haystack session round by round. The session log from `haystack-electrum` is first
checked against what the server itself received:

```bash
python3 -m attack score --session tests/fixtures/haystack-session.jsonl \
                        --honeypot tests/fixtures/haystack-honeypot-log.json --tier T1
```

Score a plain Electrum sync, from the honeypot's log and `capture/`'s record of what the wallet sent:

```bash
python3 -m attack score --honeypot tests/fixtures/bdk-honeypot-log.json \
                        --capture tests/fixtures/bdk-capture-truth.json --tier T1
```

Generate paid-wallet sessions on a local regtest chain, for the structural attacker (T2) to train on
and score (takes about 15 minutes):

```bash
cargo run --release -p haystack-regtest --bin sessions -- --out regtest/sessions
```

Score one of those sessions with the structural attacker, trained on the other wallets' sessions:

```bash
python3 -m attack score --session regtest/sessions/p10-c0/demo.jsonl --train regtest/sessions/p10-c0 --tier T2
```

Print privacy against bandwidth at every padding level:

```bash
python3 -m attack curve --dir regtest/sessions
```

## What each file does

The files are listed in the order the data flows through them.

| File | Job |
|---|---|
| `observe.py` | Reads the logs. `Observation` is what the server saw: each sync's scripthashes in arrival order, plus a `Fact` (transaction count, script type) when the log carries one. `GroundTruth` is which scripthashes were real, kept in a separate type so an attack can't read the answer by accident. `check_plain()` and `check_session()` confirm that the client's log and the server's log agree before anything is scored. |
| `a1_many_rounds.py` | A1. `analyse()` walks the syncs and returns, for every scripthash, the sync that first queried it, whether it later vanished, and whether it was paid while watched. |
| `a2_structural.py` | A2. `StructuralModel` learns, separately for real and decoy scripthashes, how transaction count, script type and query position are distributed, and turns a scripthash's features into a weight. It runs once per possible wallet script type and mixes the results, because the attacker isn't assumed to know the wallet's type. `fit()` trains it on other wallets' sessions and refuses (`TrainingRefused`) a session from another client build, at other settings, or containing any of the scored wallet's real scripthashes. The model is never saved. |
| `posterior.py` | Turns weights into probabilities. `Block` is one cohort ("exactly `k` of these are real"); `Posterior` combines independent cohorts; `Mixture` combines A2's per-script-type runs, weighted by how well each type fits. `Infeasible` is raised when the evidence contradicts itself, such as a scripthash both ruled out and certainly real, rather than producing a wrong number. |
| `scoring.py` | Runs an attacker level (`attack()`, `TIERS`) and scores it (`Score`, `run()`, `per_round()`). Prints the table below (`rounds_table()`). `ceiling()` is the best possible score, `log2(padding)`. |
| `curve.py` | The privacy-against-bandwidth table. At each padding level it scores every regtest wallet with an A2 model trained on the others, and adds the bytes each sync cost. |
| `__main__.py` | The command line: `python3 -m attack {score,curve}`. |

The synthetic wallets the tests use live in `tests/synthetic.py`, not here, because nothing in this
module needs them.

## Score columns

Every `score` table prints these columns, in this order (`COLUMNS` in `scoring.py`). The
names match the demo page; the notation in brackets is what `docs/03-metric.md` uses.

| Column | Meaning |
|---|---|
| `sync` | Which sync round of the session this row scores. |
| `real (\|R\|)` | How many real scripthashes the wallet queried in this sync. |
| `scripthashes (\|Q\|)` | How many scripthashes the server received in total, real plus decoys. `\|Q\| / \|R\|` is the padding. |
| `bits` (`-log2(max(precision, chance))`) | The headline. `0.00` means every guess was right, which is plain Electrum; `log2(padding)` means the guesses were no better than random, the ceiling. |
| `precision %` | The share of real scripthashes among the attacker's top-`\|R\|` guesses. |
| `chance %` (`\|R\| / \|Q\|`) | What a same-size random guess gets right, printed beside precision for comparison. |
| `funded bits`, `funded %` | The same two numbers, restricted to scripthashes with history: what the headline hides when the unused addresses outnumber the funded ones. `--` when no real address has history. |

## What this does and doesn't cover

Real traffic comes from three places. `tests/fixtures/` holds six plain `bdk_wallet` full scans,
which read 0.00 bits, and six `haystack-electrum` scans at padding 10, which read the 3.32-bit
ceiling. Both went to the honeypot, which answers "nothing found" to everything, so neither wallet
was ever paid. Paid wallets come from `regtest/`'s session generator: 13 wallets with real histories
on a local chain, whose sessions carry the server's real answers. A2 and A1's payment check run on
those (`python3 -m attack curve`). The tests' synthetic data, from `tests/synthetic.py`, checks this
code under assumed statistics, not Haystack.
