"""A1, the many-rounds attack: what repetition across rounds reveals -- persistence, cohorts, and activation."""


def analyse(obs):
    """Return (first-seen round per scripthash, withdrawn set, activated set)."""
    first, withdrawn = {}, set()
    for t, rnd in enumerate(obs.rounds):
        for s in rnd.order:
            first.setdefault(s, t)
        # A wallet never stops watching its own addresses, so anything that vanishes is a decoy.
        withdrawn |= first.keys() - rnd.members

    # Unused while watched, then used: a payment landed on it, which no decoy source can reproduce.

    unused, activated = set(), set()
    for rnd in obs.rounds:
        for s in rnd.order:
            fact = rnd.facts.get(s)
            if fact is None:
                continue
            if fact.tx_count == 0:
                unused.add(s)
            elif s in unused:
                activated.add(s)
    return first, withdrawn, activated
