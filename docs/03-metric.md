# The deanonymisation score

**Status: implemented and calibrated.** Every metric below is computed by `attack/`: evidence from
each attack combines into one posterior belief (`attack/posterior.py`), scored against ground truth
(`attack/metrics.py`), and checked against a 13-configuration calibration suite plus a real-capture
tripwire (`attack/calibrate.py` — `python3 -m attack calibrate` / `tripwire`). All 25 unit tests pass.
What's still open is in the TODOs at the end: mainly, all of this has run only on synthetic decoy
traffic plus one real plain-Electrum capture, because the query engine that would send real padded
traffic (`haystack-electrum`, `docs/04-roadmap.md` Week 2) doesn't exist yet.

The problem statement asks for "a meaningful metric that reads 0 for an ordinary Electrum query."
This document defines that metric, explains how it's calibrated, and states clearly what the number
does and does not mean.

---

## Why 0 for plain Electrum

The orientation is worth stating explicitly, because "deanonymisation score" read naively would be
*high* for plain Electrum, not zero.

The metric measures **uncertainty added**, in bits. Plain Electrum sends exactly the real address
set: the adversary has no uncertainty to resolve, so zero bits were added. That gives a natural,
non-arbitrary calibration point — the baseline falls out of the definition rather than being a
convention we chose.

---

## Definition

### Notation

A quick reference, since the rest of this document leans on these symbols without redefining them
each time:

- `R` — the wallet's real scripthashes: the addresses it actually needs balances for.
- `D` — the decoy scripthashes the padding scheme adds, chosen so they aren't real but look
  plausible to an outside observer.
- `Q` — the query actually sent to the server: `Q = R ∪ D`, with `|Q| = padding × |R|`. `padding`
  is the user-facing dial; `padding = 1` means `Q = R` — no decoys, i.e. plain Electrum.
- `p(s)` — the adversary's belief, for one scripthash `s ∈ Q`, that `s` is real. "How a belief over
  `Q` is built," just below, is where this number actually comes from.
- `H` — Shannon entropy, in bits, of a probability distribution (see the primer below).

### How the adversary's belief over `Q` is built

Every attack in `attack/` — A1's persistence and activation checks, A2's structural classifier —
produces evidence about individual scripthashes, not a score of its own. The evidence is combined
into one belief about which subset of `Q` is the real set `R`, using Bayes' rule, and every metric in
this document is read off that single belief (`attack/posterior.py`).

**The mechanics.** Give each scripthash `s` a weight `w(s)`:

- `w(s) = 0` rules `s` out completely — it was withdrawn, so it must be a decoy.
- `w(s) = 1` means no information: as likely to be real as any other unweighted candidate.
- `w(s) > 1` means `s` looks real; `w(s) < 1` means it looks like a decoy.

A candidate subset `T` of the right size is scored by the product of its members' weights, and its
probability is that score divided by the total over every subset of that size. This is Bayes' rule,
starting from a uniform prior over subsets and multiplying in each piece of evidence as a likelihood
ratio. Summing the probability of every subset that contains `s` gives exactly `p(s)` from the
notation above.

**Worked example.** Five scripthashes, two of them really real: `a`, `b`, `c`, `d`, `e`.

- `e` vanished in a later round — a wallet never stops asking about its own addresses, so anything
  that vanishes must be a decoy. Weight 0.
- The structural model says `a`'s features (transaction count, script type) are three times as
  common among real addresses as among decoys, in its training data. Weight 3.
- `b`, `c`, `d` show nothing unusual. Weight 1 each.

Every pair not containing `e` gets a score (the product of its two weights), and dividing by the
total of all scores gives its probability:

| Pair | Score | Probability |
|---|---|---|
| {a,b}, {a,c}, {a,d} | 3 | 3/12 = 25.0% each |
| {b,c}, {b,d}, {c,d} | 1 | 1/12 = 8.3% each |
| any pair with `e` | 0 | 0% |

Summing the pairs that contain each address gives its marginal: `p(a) = 3 × 25.0% = 75.0%`,
`p(b) = p(c) = p(d) = 25.0% + 2 × 8.3% = 41.7%`, `p(e) = 0%`. These add to 2.0, the number of real
addresses, as they must.

If the true pair is `{a, b}`, the metrics below read: precision 66.7% against a chance rate of 40%
(the top guess `a` is right; the second guess is a three-way tie among `b`, `c`, `d`, right ⅓ of the
time — `1 + ⅓ = 1.33` correct out of 2); joint entropy 2.40 bits (with `e` merely ruled out and no
structural evidence at all, the four survivors would be uniform, `log2(C(4,2)) = 2.58` bits — the
extra weight on `a` brings it down slightly further); truth bits `-log2(25.0%) = 2.00`, the cost of
the actual answer under this belief.

**Why this stays computable at real sizes.** Listing every subset is impossible once `|Q|` and `|R|`
are realistic — `C(700, 70) ≈ 3.4 × 10^97`. Instead, the total is built up one address at a time,
keeping a running total for every subset size `j`. Adding an address of weight `w` either leaves it
out (keeping the old total for size `j`) or puts it in (adding `w` times the old total for size
`j−1`). Running the example through that rule, adding `a`, `b`, `c`, `d` in order and leaving `e` out
entirely (its weight is 0, so it can never be in a real subset):

```
start          [1, 0,  0]
add a (w=3)    [1, 3,  0]
add b (w=1)    [1, 4,  3]
add c (w=1)    [1, 5,  7]
add d (w=1)    [1, 6, 12]   <- 12, the total score of every pair
```

That takes `|Q| × |R|` steps — 1,000 × 100 = 100,000 for the largest calibration-suite rows
(`_esp_rows`, `attack/posterior.py`). Running the same table backwards gives each `p(s)`; a short
formula from the same table gives the entropy. `tests/test_posterior.py` checks this method against
brute-force enumeration on 300 random small cases, and against the closed form for the uniform case
at `n = 400, k = 40`.

### A primer on the entropy formula

Every formula below is one idea from Shannon (1948): define how "surprising" an outcome is by how
unlikely it was. Measured in bits, that surprise is `-log2(p(x))`. A certain outcome (`p = 1`) costs
0 bits — you already knew it was coming, so being told it happened tells you nothing new. A fair coin
flip (`p = 0.5`) costs exactly 1 bit — the everyday meaning of "a bit" you'd expect, since a coin flip
is the textbook example of something totally unpredictable. A rare outcome costs more the less likely
it was: an event with only a 1-in-1000 chance costs `-log2(1/1000) ≈ 10` bits if it happens.

Entropy is the *average* of that cost across every outcome the distribution can produce, weighted by
how often each outcome actually happens — so it answers "how surprised should I expect to be, on
average, once this is resolved":

```
H(p) = Σ p(x) · [-log2 p(x)]      (sum over every possible outcome x)
```

Two special cases worth having fixed in mind before the sections below use them:

- If every outcome is equally likely (`p(x) = 1/n` for `n` outcomes), the sum collapses to
  `H = log2(n)` — the familiar "how many yes/no questions to find 1-of-n" count. This is also the
  *maximum* entropy can reach for `n` possibilities: spreading belief unevenly across the same `n`
  outcomes always lowers it, never raises it.
- For a two-outcome variable — "is this scripthash real," our case — `H` is 0 at the extremes
  (`p = 0` or `p = 1`, no uncertainty left) and peaks at `p = 0.5`, a genuine coin flip. That
  non-monotonicity matters, and it's exactly what breaks the metric dropped further down.

---

## The metrics

### The set-size proxy

`scripts/intersection_sim.py`'s original metric, still computed as `proxy_bits`:

```
score = log2(|surviving candidates| / |R|)      , 0 when surviving <= |R|
```

In the language above, this is what the belief gives if every surviving candidate is left at weight
1 — the uniform special case, rather than the real per-address weights an attack actually produced.
It has one job now: it is what `docs/00-problem.md` §6 and the permanent regression tests
(`tests/test_regression.py`) are built on, so it stays in the table as a fixed point to check new
attacks against, alongside precision. It is not used for anything else, because whenever an attack
does produce uneven weights — which A2 always does — it silently reports the same number as if the
attack had learned nothing about which survivors look real. Row 10 of the calibration suite below
shows the gap directly: the proxy reads the same 3.32 bits whether or not the structural attack is
switched on, while precision moves from 10.00% to 79.85%.

### The headline: precision in bits

Rank every candidate in `Q` by `p(s)` and take the attacker's top `|R|` guesses — its best single
guess at the real set, exactly `|R|` addresses. Precision is the share of those guesses that are
actually real; ties are broken by giving each tied candidate a fractional share
(`expected_precision`), so the number doesn't jump around from an arbitrary tie-break. Chance is what
a same-size random guess gets right on average, `|R| / |Q|`. The headline number converts precision
into bits, capped so an attack that does worse than chance is credited as chance rather than as a
negative score for the defence:

```
precision_bits = -log2(max(precision, chance))
```

This reads 0 bits when precision is 100% — the attacker's top guesses are entirely correct, which is
plain Electrum — and `log2(padding)` bits when precision equals chance — the attacker's top guesses
are no better than random, the ceiling for that padding level.

**Worked example.** The delta-corollary case from `docs/02-design.md`: round 1 sends one real address
`r1` alongside 9 decoys; round 2 adds a second real address `r2` on its own.

- Left unpadded, `r2` arrives alone and so is certain, while `r1` is one of ten tied candidates from
  round 1. Precision is `(1 + 0.1)/2 = 55%` against a chance rate of `2/11 = 18.2%` —
  `precision_bits = -log2(0.55) = 0.86` bits.
- Padding the increment (9 fresh decoys alongside `r2`, the fix `docs/02-design.md` recommends)
  brings precision back down to the full `10%` chance rate — `precision_bits = -log2(0.10) = 3.32`
  bits, the ceiling.

**Why this is the headline, not adversary advantage.** Both are read off the same precision number,
but advantage (`precision - chance`) can't distinguish a well-protected wallet from a fully exposed
one: plain Electrum gives `100% - 100% = 0` and the ceiling gives `10% - 10% = 0` — the real capture's
own tripwire output reads `adv 0.00` on both rows. Precision in bits gives `0.00` and `3.32` for the
same two rows, which is the distinction a headline number needs to make. Advantage is kept as a
secondary column (below) because it is still the plainest way to state a specific attack's gain in
one sentence — "twice as good as guessing" needs no logarithm.

### The calibration check: joint entropy and truth bits

Precision only asks about the attacker's single best guess. Two more numbers, read off the same
belief, check whether that guess is backed by a trustworthy belief rather than a lucky ranking.

**Joint entropy** is the entropy of the belief over which *whole subset* of `Q` is real — not
per-address, over the joint question — reported per real address as `joint/R`. Its `2^H` form is the
"effective anonymity set": the number of equally-plausible whole answers, even when the true count is
far larger. At the uniform prior it equals `log2(C(|Q|,|R|)) / |R|`; `C(700, 70) ≈ 3.4 × 10^97`, more
candidate subsets than atoms in the observable universe, computed exactly by the running-total method
above rather than by listing them.

**Truth bits** is `-log2 P(the true R)`, capped at the same ceiling: how much probability the belief
assigned to the actual answer. If the belief is honest — statisticians call this *calibrated* — the
two should track each other closely over many independent draws, because that is what "the belief's
probabilities are trustworthy" means numerically. Rows 10 and 11 of the calibration suite agree to
within 0.01 bits per real address. Row 12 disagrees by 0.21 bits: there the model believes it learned
0.28 bits per address (`joint/R` 4.64 → 4.36 against the ceiling), yet its actual guesses land at
9.27% precision, *below* the 10% chance rate — a sign the model is fitting noise in its 30 training
worlds rather than a real signal, which precision alone wouldn't reveal.

**A known limitation, found by measurement rather than assumed:** joint entropy is sensitive to how
addresses are grouped into first-seen cohorts, in a way that doesn't track actual exposure. Take two
1,000-address queries, each with 100 real addresses, scored with no structural evidence at all:

| Query | Precision | Joint entropy per real address |
|---|---|---|
| All 100 real addresses first seen together, one cohort of 1,000 | 10.00% | 4.64 bits |
| Each real address first seen in its own round, with 9 fresh decoys — a wallet paying into new addresses over time | 10.00% | 3.32 bits |

Every address is equally exposed in both cases — 10% precision, exactly chance — but the joint number
reports the first as more private. It is counting the ways to name the *entire* 100-address set
exactly (there are more ways to choose 100 of 1,000 than to choose 1 from each of 100 separate groups
of 10), which is a real quantity, but not one that changes how safe any individual address is. Left
running over a long-lived wallet, whose real addresses do get revealed one at a time exactly like the
second row, this number would drift downward and look like a privacy loss that isn't actually
happening. That is why it is kept only as a check, next to truth bits, rather than reported as a
privacy number on its own — see "Open questions" below for where a corrected, whole-wallet version of
this metric belongs.

### Dropped: mean per-address entropy and its rescaled form

Both were implemented, measured, and removed. The numbers are kept here as the record of why, so
nobody re-adds them without re-discovering the same problem.

**Mean per-address entropy**, `H(p) = -p·log2(p) - (1-p)·log2(1-p)` averaged over every address in
`Q`, falls as padding rises rather than rising: at the uniform prior it equals `H(1/padding)`, which
is `1.00` bit at padding 2, `0.47` at padding 10, and `0.29` at padding 20. More privacy read as a
*lower* number, which is backwards for a metric meant to track a defence getting stronger.

**Its rescaled form** (the same sum, divided by `|R|` instead of `|Q|`, so it rises with padding
instead of falling) does rise correctly, but doesn't fix the actual problem: it is still a sum of
independent per-address terms `H(p(s))`, so it is blind to whether the remaining doubt is spread over
many addresses or concentrated into a group — the same blind spot as mean entropy, just rescaled to
trend the right way. Measured directly on the two-query example above (a real check, not a toy): both
queries read the rescaled sum at `4.69`, identical, even though joint entropy — the metric that does
see the difference — reads `4.64` and `3.32` for the two respectively.

Both were also tested on a smaller toy: 1 real address hidden among 9 decoys, then a structural
attack narrows the field to 5 tied survivors that still include the real one:

| Metric | Before | After | What moved |
|---|---|---|---|
| Mean per-address entropy | 0.469 bits | 0.361 bits | Fell by ~0.11 bits — about a tenth of the 1.00-bit loss that joint entropy (`log2(10) → log2(5)`) reports for the identical attack. |
| Its rescaled sum | 4.69 bits | 3.61 bits | The same ~1.08-bit fall — the number looks larger here only because dividing by `|R| = 1` in this toy doesn't shrink it the way dividing by 100 does in the two-query example above; it's the identical blind spot. |

### Reporting

Precision, in bits and as a percentage, next to the chance rate it's measured against, is the
headline: it's what a judge can check by hand, and no attack in the suite can make it look better
than reality without actually getting guesses right. Joint entropy and truth bits are reported
alongside it as a calibration check on the belief itself, not as a second privacy number — a gap
between them is a warning that the attack model is overconfident, as the case above shows. Adversary
advantage is kept as a secondary column, for the reason it used to be considered as the headline:
restating a specific gain as "twice as good as guessing" needs no logarithm. The set-size proxy is
kept for its regression-test role, pinned to the uniform-weight case `docs/00-problem.md` §6
established.

None of this is combined into one number. Averaging or weighting these together would mean choosing
weights, and that choice is itself a place a result could end up looking better than it is. Keeping
them separate means each checks the others: precision moving while the calibration check doesn't (or
the reverse) is itself a signal worth noticing.

---

## The calibration suite

The score is only as honest as the baselines it's checked against. `python3 -m attack calibrate` runs
every configuration below and prints all seven columns for each; `python3 -m attack tripwire` runs the
four pass/fail checks that gate Week 1 (`docs/04-roadmap.md`). Both are implemented and passing,
against 5 synthetic seeds per row plus the real captured wallet
(`tests/fixtures/bdk-capture-truth.json`, `tests/fixtures/bdk-honeypot-log.json`).

| Configuration | Expected result | What it checks |
|---|---|---|
| Plain Electrum, real honeypot capture | `0.00` bits, every round | The definitional zero, on real `bdk_wallet` traffic, not simulated. |
| Random decoys, fresh every round | `0.00` bits by round 3 | Reproduces the collapse in `docs/00-problem.md` §6. A metric that rates this well is wrong — a permanent regression check. |
| Random decoys, epoch/3 rotation | `0.00` bits once a second epoch is seen | Rotation is worse than none; also a permanent regression check. |
| Random decoys, fixed (deterministic) | ceiling | The many-rounds attack alone learns nothing once decoys stop changing. |
| Fixed decoys from a bundled public pool | `0.00` bits | An adversary who knows the pool subtracts it exactly — the subtractable-pool risk in `docs/02-design.md` open question 1, made concrete as a number. |
| Fixed decoys, wallet paid over 12 rounds, unpadded increments | below ceiling | The delta corollary: an unpadded new address is exposed. |
| Append-only with per-increment padding | near ceiling, aside from activation | The delta corollary's fix works, once activation is separately accounted for. |
| Careless chain-sourced / random-scripthash / oracle decoy wallets, structural attacker | ceiling only for the oracle | The structural attack (A2) separates careless decoys; only decoy groups shaped like the real wallet hold up. |
| Decoy wallets, reals sent first | below ceiling, at the structural level only | Query order leaks (A3) even with otherwise perfect decoys — see the mapping note under "Open questions" for where order is actually checked. |

The second and third rows matter most: **a metric that gives a good score to a known-broken scheme is
disqualifying**, and every run checks it automatically.

Every row's exact numbers depend on the random seeds and the assumed feature distributions in
`attack/synth.py` for the synthetic rows, so they are not pinned into this document — run the command
for the current numbers. The ceiling column is exact and analytic, not sampled.

### Ceilings, one per metric

Each column has its own ceiling — its value at the uniform prior, where the attacker has eliminated
nothing:

- **Precision and chance** both equal `1/padding` — e.g. `10%` at padding 10 — so **precision bits**
  reach `log2(padding)`, `3.32` bits at padding 10.
- **The set-size proxy** reaches the same `log2(padding)`, by construction.
- **Joint entropy and truth bits**, per real address, reach `log2(C(padding × |R|, |R|)) / |R|` —
  `4.64` bits per real address at padding 10, `|R| = 100`. This is a different number from the 3.32
  above measuring a different thing: precision cares about a single guess, joint entropy about naming
  the whole set. Row 4 of the calibration suite sits at both ceilings at once, since it has no
  structural evidence at all.
- **Adversary advantage** reaches `0` — a perfect scheme gives the adversary exactly the chance rate,
  no better.

All four are computed exactly (`ceiling()`, `attack/calibrate.py`), and every calibration row is
checked against them.

---

## What the score does not mean

Three caveats stated here rather than left implicit:

**It is a lower bound on the adversary's power, not an upper bound.** The number says "none of the
attacks we implemented recovered the set." An attack nobody wrote is invisible to it. This is the
central limitation, and it's surfaced in the demo UI directly, not only in this document.

**It is not a cryptographic guarantee.** There is no reduction, no hard problem, no negligible
function. Adversary advantage shrinks with padding; it does not vanish.

**It is specific to what the adversary knows.** A score that doesn't say what the adversary was
assumed to know when it was measured is meaningless — see the note on adversary strength at the end
of `docs/02-design.md`. Every reported score names that, and the on-chain case is expected to look
considerably worse than the multi-round case.

---

## Guarding against a flattering result

The failure mode is a weak attack suite producing a high score. Commitments made to avoid it:

1. **Attacks before defences.** The attack harness is Week 1, ahead of the query engine in Week 2 —
   see `docs/04-roadmap.md`. Whatever ships first is the attacker, not the padding scheme.
2. **Adversarial self-review.** For each attack, write down the attack that would beat it, then
   implement that too. Stop when out of ideas, and say so in the writeup.
3. **Regression the known-broken schemes.** Fresh-random and epoch-rotation decoy strategies stay in
   the suite permanently. If they ever score well, the metric regressed.
4. **Publish the attack suite prominently.** Credibility rests on the attacks being good, so they are
   as visible in the submission as the defence.

---

## TODOs

**Week 1 — the attacker: done.**

- [x] Attack harness: evidence from every attack combines into one posterior (`attack/harness.py`,
      `attack/posterior.py`); every metric is read off it.
- [x] A1 — persistence, cohort counts and activation, running against real captured query logs as
      well as synthetic ones (`attack/a1.py`, `tests/test_a1.py`, `tests/test_tripwire.py`).
- [x] A2 — structural classifier: transaction-count bucket, script type, and query-order position,
      mixed over the wallet's possible script type (`attack/a2.py`, `tests/test_a2.py`).
- [x] Metric implementation: precision in bits and percent plus the chance rate (headline), the
      set-size proxy (regression fixed point), joint entropy and truth bits (calibration check),
      adversary advantage (secondary) — `attack/metrics.py`, `attack/calibrate.py`. Mean per-address
      entropy and its rescaled form were implemented and dropped; see above.
- [x] Regression test: fresh-random and epoch-rotation strategies collapse to ≈0
      (`tests/test_regression.py`).
- [x] Tripwire passing on the real captured wallet (`python3 -m attack tripwire`,
      `tests/test_tripwire.py`).

**Before Week 2's first real score can use anything beyond the many-rounds attack:**

- [ ] **Session log and a loader for it.** The honeypot answers "nothing found" to everything, so it
      can check that the server received the right scripthashes, but it can't supply the transaction
      counts and script types the structural attack or activation need. `docs/02-design.md`'s
      proposed session log (tagging each query real/decoy, with the server's real answer) needs a
      loader alongside `load_honeypot` in `attack/observe.py` before a real padded sync can be scored
      on anything but the many-rounds level.
- [ ] **Label synthetic-feature scores as such wherever they're shown.** `attack/synth.py`'s
      script-type and transaction-count tables are declared assumptions, not chain measurements, in
      its own docstring; any structural-level score computed from them (the synthetic rows above, and
      any real session scored before Week 3's decoy work lands) should say so next to the number, not
      only in this document.
- [ ] **Reconsider decoy pool v1 for positions with no history yet.** The pool-aware row above
      measures exactly the risk `docs/04-roadmap.md` already accepts for Week 2's bundled
      chain-sourced pool: an adversary who knows the pool subtracts it, reading `0.00` bits. Sending
      the deterministic `HMAC-SHA256(key, keychain ‖ index ‖ j)` value directly as the scripthash for
      a position with no history yet — rather than using it to pick from a pool — has no chain
      history and no shared pool to subtract, so it should score at the ceiling instead; it doesn't
      help a position that already has history when first queried (a restored wallet), which stays
      Week 3's problem alongside the rest of decoy quality.

**Deferred, not urgent because nothing built yet depends on them:**

- [ ] A whole-wallet (group-level) version of the effective anonymity set — "how many candidate
      wallets are left," rather than "how many candidate addresses" — to pair with a future on-chain
      / co-spend attack. Not urgent because that attack isn't built (`docs/02-design.md`'s "on-chain"
      case).
- [ ] A per-address calibration check usable on a single real session: among addresses the belief
      rates near some probability `p`, check that roughly that share are actually real. The
      truth-bits-versus-joint-entropy check above only means something averaged over many independent
      sessions, which the synthetic suite has and a single real wallet doesn't.
- [ ] A count of real addresses the belief is at least, say, 90% confident about — considered this
      round and set aside for now, not dropped. Useful for making a single exposed paid address show
      up as a number rather than only as a shift in an averaged percentage.

**Week 2 onward, unchanged by this update — see `docs/04-roadmap.md`:**

- [ ] Run the attacker against the real query engine once it exists, dependent on the session log
      above. First non-simulated score.
- [ ] Iterate against the structural attack with real decoy quality work until synthetic groups stop
      being separable (Week 3), replacing the assumed feature distributions along the way.
- [ ] The bandwidth-versus-score curve across padding levels — the headline result.
- [ ] Live score, labelled with what the adversary was assumed to know, in the demo UI (Week 4).

---

## Open questions — resolved 2026-09-26

The four questions below shaped the metric's definition. All four are closed; kept here as the record
of what was open and why, in the style of `docs/02-design.md`'s resolved sync-integration questions.

1. **How does a hard-elimination attack produce a probability?** It doesn't need to, on its own. A
   hard elimination is a weight of 0, one piece of evidence among however many an attack level
   supplies; Bayes' rule combines all of them into per-address probabilities directly
   (`attack/posterior.py`, worked example above). Where the many-rounds attack is the only evidence
   available, this correctly reduces to "uniform over the survivors" — not a placeholder, the exact
   right answer given only that evidence.
2. **Is the effective anonymity set computable at realistic scale?** Yes, exactly, using the same
   running-total method as question 1 — an elementary-symmetric-polynomial recursion over `|Q|` items
   and `|R|` slots (`_esp_rows`, `attack/posterior.py`), checked against brute-force enumeration on
   300 random small cases (`tests/test_posterior.py`) and against the closed form for the uniform case
   at `n = 400, k = 40`. What wasn't anticipated: the metric is exact and cheap, but it turned out not
   to measure what it was meant to on its own — see the grouping limitation under "the calibration
   check," above. It stays, but only as a check next to truth bits, not as a privacy number by itself.
3. **Does the adversary know `|R|`?** Yes, and not only as a scoring convenience. `docs/01-threat-model.md`
   already grants the adversary the wallet software's behaviour, including the gap limit; every sync
   being a full scan (`docs/02-design.md`, "Sync integration," resolved 2026-09-25) means a never-paid
   wallet's real count is fixed by the gap limit alone, and the capture fixture confirms it: all 6 real
   rounds hold exactly 100 scripthashes. `attack/harness.py`'s `knowledge()` grants the attacker the
   real count per first-seen cohort, consistent with this.
4. **How does each adversary level map to a distinct `p(s)`-producing model?** There is one model, not
   one per level. A level just switches which evidence is available to it (`attack()`,
   `attack/harness.py`): the single-round level gets none, the many-rounds level gets persistence and
   activation, the structural level adds the classifier's weights on top. `docs/02-design.md`'s "A note
   on adversary strength" states the levels; this document and `attack/harness.py` state which evidence
   each one turns on. Two things this mapping made visible that weren't obvious before it was written
   down: query order is judged only at the structural level, even though the threat model grants order
   from the first round, so a good many-rounds score should not be read as meaning order is safe (the
   "reals sent first" row above is the direct check); and the many-rounds level's evidence is three
   things, not one — persistence, cohort counts, and activation — where the original open question and
   the design note both described it in looser terms.
