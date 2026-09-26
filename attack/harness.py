"""Adversary levels (docs/02-design.md, "A note on adversary strength") mapped to the evidence each may use."""
from collections import Counter, defaultdict
from dataclasses import dataclass

from .a1 import analyse
from .observe import Observation
from .posterior import NEG_INF, Block, Mixture, Posterior

TIERS = {
    "T0": "one round, no model of what wallets look like",
    "T1": "all rounds: persistence, cohorts, activation (A1)",
    "T2": "T1 plus a structural model of real vs decoy scripthashes (A2)",
}


@dataclass(frozen=True)
class Knowledge:
    """Everything granted beyond the query stream, so each strengthening assumption is explicit."""
    cohort_reals: dict
    pool: frozenset = frozenset()
    model: object = None


def knowledge(obs, real, pool=(), model=None):
    """Default grant: reals new per round (i.e. |R_t| every round), which fixed padding discloses anyway."""
    first, _, _ = analyse(obs)
    unseen = [s for s in real if s not in first]
    if unseen:
        raise ValueError(f"{len(unseen)} real scripthashes were never queried")
    return Knowledge(dict(Counter(first[s] for s in real)), frozenset(pool), model)


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
            lw = [NEG_INF if s in withdrawn or s in know.pool else struct.get(s, 0.0) for s in items]
            blocks.append(Block(items, lw, cohort_reals.get(c, 0), activated.intersection(items)))
        return Posterior(blocks)

    if tier == "T2":
        if know.model is None:
            raise ValueError("T2 needs a structural model")
        return Mixture([(know.model.log_prior(h), posterior(h)) for h in know.model.wallet_types()])
    return posterior(None)
