# The deanonymisation score

**Status: implemented and calibrated.** Every metric below is computed by `attack/`: evidence from
each attack combines into one posterior belief (`attack/posterior.py`), scored against ground truth
(`attack/scoring.py`), and checked by the Python tests: plain Electrum reads 0.00 on synthetic data
and on a real captured wallet, a perfect scheme reads the analytic ceiling, and known-broken decoy
schemes read near zero (`tests/`). The metrics run on real traffic: padded sessions
against the honeypot, and paid regtest wallets whose sessions carry the server's real answers, scored by the structural
attacker trained on other wallets' sessions (`python3 -m attack curve`).

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

If the true pair is `{a, b}`, the headline below reads: precision 66.7% against a chance rate of
40%. The top guess `a` is right. The second guess is a three-way tie among `b`, `c` and `d`, right ⅓
of the time. So `1 + ⅓ = 1.33` of the 2 guesses are correct on average, and `1.33 / 2 = 66.7%`. In
bits that is `-log2(0.667) = 0.58`.

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

That takes `|Q| × |R|` steps — 1,000 × 100 = 100,000 for one round of the padded demo wallet
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

### Dropped metrics

Six metrics were implemented, measured, and removed. No code for them remains; the reasons stay so
nobody re-adds them without rediscovering the problem.

- **Adversary advantage**, `precision - chance`, can't tell a well-protected wallet from a fully
  exposed one. Plain Electrum gives `100% - 100% = 0`, and the ceiling at padding 10 gives
  `10% - 10% = 0`. Precision in bits gives `0.00` and `3.32` for the same two, which is the
  distinction a headline number needs to make. Its one strength, that "twice as good as guessing"
  needs no logarithm, is kept by printing precision and chance side by side.
- **Joint entropy** is the entropy of the belief over which *whole subset* of `Q` is real, reported
  per real address. At the uniform prior it equals `log2(C(|Q|,|R|)) / |R|`. It is sensitive to how
  addresses are grouped into first-seen cohorts, in a way that doesn't track actual exposure. Take
  two 1,000-address queries, each with 100 real addresses, scored with no structural evidence at all:

  | Query | Precision | Joint entropy per real address |
  |---|---|---|
  | All 100 real addresses first seen together, one cohort of 1,000 | 10.00% | 4.64 bits |
  | Each real address first seen in its own round, with 9 fresh decoys — a wallet paying into new addresses over time | 10.00% | 3.32 bits |

  Every address is equally exposed in both cases — 10% precision, exactly chance — but joint entropy
  reports the first as more private. It counts the ways to name the *entire* 100-address set exactly.
  There are more ways to choose 100 of 1,000 than to choose 1 from each of 100 separate groups of
  10. That is a real quantity, but not one that changes how safe any individual address is. Over a
  long-lived wallet, whose real addresses are revealed one at a time like the second row, it would
  drift downward and look like a privacy loss that isn't happening.
- **Truth bits**, `-log2 P(the true R)`, is how much probability the belief gave the actual answer.
  It was kept with joint entropy as a check that the attacker's belief is honest: the two should
  agree over many draws. On every session the repo can now score they agree exactly — 4.64 and 4.64
  on the padded session, 0.00 and 0.00 on the plain one — so the pair added columns without adding
  information about the wallet.
- **Mean per-address entropy**, `H(p) = -p·log2(p) - (1-p)·log2(1-p)` averaged over every address in
  `Q`, falls as padding rises: at the uniform prior it equals `H(1/padding)` — `1.00` bit at padding
  2, `0.47` at 10, `0.29` at 20. More privacy reads as a lower number, backwards for a metric meant to
  track a defence getting stronger.
- **Its rescaled form** (the same sum divided by `|R|` instead of `|Q|`) does rise with padding, but
  it is still a sum of independent per-address terms, so it can't see whether the remaining doubt is
  spread out or concentrated in a group. On the two queries in the joint-entropy table above it reads
  `4.69` for both.
- **The set-size proxy**, `log2(surviving candidates / |R|)`, the first metric tried, adds nothing
  precision in bits doesn't. When the only evidence is ruling candidates out, as in the intersection
  attack, precision among `S` equally likely survivors is `|R| / S`, so precision in bits is
  `log2(S / |R|)`: the same number. When the evidence is uneven, the proxy ignores it: the structural
  attack rules nothing out, so on careless chain decoys the proxy still reads the full 3.32 bits
  while precision is above 60% (`tests/test_a2.py`). Removed.

### Reporting

Precision, in bits and as a percentage, next to the chance rate it's measured against, is the
headline. A judge can check it by hand, and no attack can make it look better than reality without
actually getting guesses right.

**Precision among funded addresses** is the same precision, restricted to the scripthashes the server
reports history for. The attacker takes its top `|F|` guesses among them, where `F` is the funded
reals, and the chance rate is `|F|` divided by the number with history. It exists because the
headline averages over every real address, and the unused tail dominates. It is always printed
beside the headline, as `funded bits` and `funded %`.

The two are not combined into one number. Averaging or weighting them together would mean choosing
weights, and that choice is itself a place a result could end up looking better than it is.

---

## What the attacker is assumed to know

Two assumptions shape how the score is computed.

1. **The attacker knows how many real addresses there are, `|R|`.** `docs/01-threat-model.md` already
   grants the adversary the wallet software's behaviour, including the gap limit. Every sync being a
   full scan (`docs/02-design.md`, "haystack-electrum") means a never-paid wallet's real count is
   fixed by the gap limit alone, and the capture fixture confirms it: all 6 real rounds hold exactly
   100 scripthashes. `knowledge()` in `attack/scoring.py` grants the attacker the real count per
   first-seen cohort, consistent with this.
2. **There is one model, not one per adversary level.** A level only switches which evidence is
   available to it (`attack()`, `attack/scoring.py`): the single-round level gets none, the
   many-rounds level gets persistence, cohort counts and activation, and the structural level adds
   the classifier's weights on top. The levels themselves are in `docs/02-design.md`, "A note on
   adversary strength". Query order is judged only at the structural level, even though the threat
   model grants order from the first round, so a good many-rounds score should not be read as
   meaning order is safe (`tests/test_a2.py`'s reals-first test is the direct check).
