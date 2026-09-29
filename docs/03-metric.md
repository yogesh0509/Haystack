# The deanonymisation score

**Status: implemented and calibrated.** Every metric below is computed by `attack/`: evidence from
each attack combines into one posterior belief (`attack/posterior.py`), scored against ground truth
(`attack/metrics.py`), and checked against a 13-configuration calibration suite plus a real-capture
tripwire (`attack/calibrate.py` — `python3 -m attack calibrate` / `tripwire`). All 36 Python tests
pass. Real padded traffic now exists: six `haystack-electrum` scans at padding 10 against the honeypot
read 3.32 bits, the ceiling, in every round (`tests/test_padded_session.py`). What's still open is in
the TODOs at the end: mainly, the structural attack and activation have run only on synthetic
traffic, because the honeypot can't supply the server's real answers they need.

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

### Dropped: mean per-address entropy, its rescaled form, and the set-size proxy

Three metrics were implemented, measured, and removed. No code for them remains; the reasons stay so
nobody re-adds them without rediscovering the problem.

- **Mean per-address entropy**, `H(p) = -p·log2(p) - (1-p)·log2(1-p)` averaged over every address in
  `Q`, falls as padding rises: at the uniform prior it equals `H(1/padding)` — `1.00` bit at padding
  2, `0.47` at 10, `0.29` at 20. More privacy reads as a lower number, backwards for a metric meant to
  track a defence getting stronger.
- **Its rescaled form** (the same sum divided by `|R|` instead of `|Q|`) does rise with padding, but
  it is still a sum of independent per-address terms, so it can't see whether the remaining doubt is
  spread out or concentrated in a group. On the two queries in the table above it reads `4.69` for
  both, while joint entropy, which does see the difference, reads `4.64` and `3.32`.
- **The set-size proxy**, `log2(surviving candidates / |R|)`, Week 0's first metric, adds nothing
  precision in bits doesn't. When the only evidence is ruling candidates out, as in the intersection
  attack, precision among `S` equally likely survivors is `|R| / S`, so precision in bits is
  `log2(S / |R|)`: the same number (checked on `python3 -m attack strategies`'s setting, equal to
  within 1.6×10⁻¹⁶). When the evidence is uneven, the proxy ignores it: with the structural attack on
  careless chain decoys it still read the full 3.32 bits while precision was 79.85%. Removed
  2026-09-29.

### Reporting

Precision, in bits and as a percentage, next to the chance rate it's measured against, is the
headline: it's what a judge can check by hand, and no attack in the suite can make it look better
than reality without actually getting guesses right. Joint entropy and truth bits are reported
alongside it as a calibration check on the belief itself, not as a second privacy number — a gap
between them is a warning that the attack model is overconfident, as the case above shows. Adversary
advantage is kept as a secondary column, for the reason it used to be considered as the headline:
restating a specific gain as "twice as good as guessing" needs no logarithm.

None of this is combined into one number. Averaging or weighting these together would mean choosing
weights, and that choice is itself a place a result could end up looking better than it is. Keeping
them separate means each checks the others: precision moving while the calibration check doesn't (or
the reverse) is itself a signal worth noticing.

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
