"""Deanonymisation scores from an adversary posterior and the truth; plain Electrum reads 0 on all but `advantage`.

Mean per-address entropy was implemented and dropped: it falls as padding rises (docs/03-metric.md)."""
import math
from dataclasses import dataclass
from typing import Optional

from .posterior import LN2, NEG_INF, log_comb


@dataclass(frozen=True)
class Score:
    n_real: int
    n_query: int
    # Scripthashes the attacker hasn't ruled out: a count to print, not a privacy metric.
    candidates: int
    precision: float
    chance: float
    joint_bits: float
    joint_upper_bits: float
    truth_bits: float
    # The same precision, restricted to scripthashes the server reports history for: the attacker's
    # top-|F| guesses among them, against the funded reals F. None when no real has history.
    funded: int = 0
    with_history: int = 0
    funded_precision: Optional[float] = None

    @property
    def funded_chance(self):
        return self.funded / self.with_history if self.funded else None

    @property
    def funded_bits(self):
        if not self.funded:
            return None
        return max(0.0, -math.log2(max(self.funded_precision, self.funded_chance)))

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
    # History is what the server sees, so the attacker can restrict its guesses to this class.
    history = {s for s in latest_round.order
               if (f := latest_round.facts.get(s)) is not None and f.tx_count > 0}
    funded = real & history
    return Score(
        n_real=k,
        n_query=n,
        candidates=support,
        precision=expected_precision(post.marginal, real, k),
        chance=k / len(latest_round.order),
        joint_bits=post.entropy_bits,
        joint_upper_bits=post.entropy_upper_bits,
        truth_bits=guessing if lp == NEG_INF else min(guessing, max(0.0, -lp)),
        funded=len(funded),
        with_history=len(history),
        funded_precision=expected_precision({s: post.marginal[s] for s in history}, funded, len(funded))
        if funded else None,
    )
