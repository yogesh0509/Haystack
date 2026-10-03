"""Run an attacker level on a session and score its guesses against the truth.

The pipeline is: A1 and A2 turn what the server saw into a weight per scripthash, `posterior.py` turns
the weights into a probability per scripthash, and this file ranks those probabilities into the
attacker's best guess and scores it (precision, and precision in bits, docs/03-metric.md).
"""
import math
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Optional

from .a1_many_rounds import analyse
from .observe import Observation
from .posterior import NEG_INF, Block, Mixture, Posterior


# Attacker levels (docs/02-design.md, "A note on adversary strength") and the evidence each may use.

TIERS = {
    "T0": "one round, no model of what wallets look like",
    "T1": "all rounds: persistence, cohorts, activation (A1)",
    "T2": "T1 plus a structural model of real vs decoy scripthashes (A2)",
}


@dataclass(frozen=True)
class Knowledge:
    """Everything granted beyond the query stream, so each strengthening assumption is explicit."""
    cohort_reals: dict
    model: object = None


def knowledge(obs, real, model=None):
    """Default grant: reals new per round (i.e. |R_t| every round), which fixed padding discloses anyway."""
    first, _, _ = analyse(obs)
    unseen = [s for s in real if s not in first]
    if unseen:
        raise ValueError(f"{len(unseen)} real scripthashes were never queried")
    return Knowledge(dict(Counter(first[s] for s in real)), model)


def attack(obs, know, tier="T1", activation=True):
    if tier not in TIERS:
        raise ValueError(f"unknown tier {tier}; T3 (co-spend) is not implemented yet")
    cohort_reals = know.cohort_reals
    if tier == "T0":
        obs = Observation([obs.rounds[-1]])
        cohort_reals = {0: sum(cohort_reals.values())}
    first, withdrawn, activated = analyse(obs)
    if tier == "T0" or not activation:
        activated = set()
    cohorts = defaultdict(list)
    for s, c in first.items():
        cohorts[c].append(s)
    latest = obs.rounds[-1]

    def posterior(wallet_type):
        struct = know.model.log_weights(latest, wallet_type) if tier == "T2" else {}
        blocks = []
        for c in sorted(cohorts):
            items = cohorts[c]
            lw = [NEG_INF if s in withdrawn else struct.get(s, 0.0) for s in items]
            blocks.append(Block(items, lw, cohort_reals.get(c, 0), activated.intersection(items)))
        return Posterior(blocks)

    if tier == "T2":
        if know.model is None:
            raise ValueError("T2 needs a structural model")
        return Mixture([(know.model.log_prior(h), posterior(h)) for h in know.model.wallet_types()])
    return posterior(None)


# The score: how many of the attacker's top guesses are real, against a random guess of the same size.

@dataclass(frozen=True)
class Score:
    n_real: int
    n_query: int
    precision: float
    chance: float
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
    # History is what the server sees, so the attacker can restrict its guesses to this class.
    history = {s for s in latest_round.order
               if (f := latest_round.facts.get(s)) is not None and f.tx_count > 0}
    funded = real & history
    return Score(
        n_real=k,
        n_query=n,
        precision=expected_precision(post.marginal, real, k),
        chance=k / n,
        funded=len(funded),
        with_history=len(history),
        funded_precision=expected_precision({s: post.marginal[s] for s in history}, funded, len(funded))
        if funded else None,
    )


def view(post, latest_round, real):
    """The server's-eye picture of one round, for the demo wallet's grid.

    One row per scripthash in the order the server received them: the attacker's probability that it
    is real, then 1/0 for whether it is, then 1/0 for whether the server reported history for it.
    """
    real = frozenset(real)
    rows = []
    for s in latest_round.order:
        f = latest_round.facts.get(s)
        rows.append([round(post.marginal[s], 3), int(s in real), int(f is not None and f.tx_count > 0)])
    return rows


# Running a level and scoring it, per round.

def run(obs, real, tier="T1", model=None, activation=True):
    real = frozenset(real)
    post = attack(obs, knowledge(obs, real, model), tier, activation)
    return score(post, obs.rounds[-1], real)


def per_round(obs, real_rounds, tier="T1", **kw):
    return [run(obs.upto(t), real_rounds[t], tier, **kw) for t in range(len(obs.rounds))]


def ceiling(n_real, padding):
    """Precision bits of a perfect scheme: the adversary is stuck at chance."""
    return math.log2(round(padding * n_real) / n_real)


COLUMNS = (
    ("bits", lambda s: s.precision_bits),
    ("precision %", lambda s: 100 * s.precision),
    ("chance %", lambda s: 100 * s.chance),
    ("funded bits", lambda s: s.funded_bits),
    ("funded %", lambda s: None if s.funded_precision is None else 100 * s.funded_precision),
)


def _fmt(v, width):
    if v is None:
        return f"{'--':>{width}}"
    return f"{'inf':>{width}}" if math.isinf(v) else f"{v:>{width}.2f}"


def rounds_table(title, scores):
    head = ("sync", "real (|R|)", "scripthashes (|Q|)") + tuple(c for c, _ in COLUMNS)
    widths = [len(h) for h in head]
    lines = [title, "  " + "  ".join(f"{h:>{w}}" for h, w in zip(head, widths))]
    for t, s in enumerate(scores, 1):
        cells = [f"{v:>{w}}" for v, w in zip((t, s.n_real, s.n_query), widths)]
        cells += [_fmt(f(s), w) for (_, f), w in zip(COLUMNS, widths[3:])]
        lines.append("  " + "  ".join(cells))
    return "\n".join(lines)
