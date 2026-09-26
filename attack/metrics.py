"""Deanonymisation scores from an adversary posterior and the truth; plain Electrum reads 0 on all but `advantage`.

Mean per-address entropy and its rescaled form (`marg/R`) were implemented and dropped
(docs/03-metric.md): both are sums of independent per-address terms `H(p(s))`, so both fall as
padding rises rather than rising, and both are blind to whether the surviving doubt is spread out or
concentrated into a group -- see the two-wallets worked example in docs/03-metric.md. `joint_bits`
below is the metric that does see it."""
import math
from dataclasses import dataclass

from .posterior import LN2, NEG_INF, log_comb


@dataclass(frozen=True)
class Score:
    n_real: int
    n_query: int
    proxy_bits: float
    precision: float
    chance: float
    joint_bits: float
    joint_upper_bits: float
    truth_bits: float

    @property
    def precision_bits(self):
        # Capped at guessing: an attack worse than chance is abandoned, not credited to the defence.
        return max(0.0, -math.log2(max(self.precision, self.chance)))

    @property
    def advantage(self):
        return self.precision - self.chance

    def per_real(self, bits):
        return bits / self.n_real


def expected_precision(marginal, real, k, tol=1e-9):
    """Expected share of real among the top-k guesses, ties broken uniformly at random."""
    ranked = sorted(marginal.items(), key=lambda kv: -kv[1])
    hits, slots, i = 0.0, k, 0
    while slots > 0 and i < len(ranked):
        top = ranked[i][1]
        j = i
        while j < len(ranked) and top - ranked[j][1] <= tol * max(1.0, top):
            j += 1
        group = ranked[i:j]
        take = min(slots, len(group))
        hits += take * sum(1 for s, _ in group if s in real) / len(group)
        slots -= take
        i = j
    return hits / k


def score(post, latest_round, real):
    real = frozenset(real)
    k = len(real)
    n = len(latest_round.order)
    support = sum(1 for p in post.marginal.values() if p > 0.0)
    guessing = log_comb(n, k) / LN2
    lp = post.log2_prob(real)
    return Score(
        n_real=k,
        n_query=n,
        proxy_bits=math.log2(max(support, k) / k),
        precision=expected_precision(post.marginal, real, k),
        chance=k / len(latest_round.order),
        joint_bits=post.entropy_bits,
        joint_upper_bits=post.entropy_upper_bits,
        truth_bits=guessing if lp == NEG_INF else min(guessing, max(0.0, -lp)),
    )
