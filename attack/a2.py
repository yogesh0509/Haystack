"""A2: naive-Bayes likelihood ratio real:decoy from what a server sees about each scripthash."""
import math
from collections import Counter

ACTIVITY_EDGES = (0, 1, 2, 5, 20, 100)
POSITION_BINS = 10


def activity_bin(tx_count):
    for i, edge in enumerate(ACTIVITY_EDGES):
        if tx_count <= edge:
            return i
    return len(ACTIVITY_EDGES)


def position_bin(i, n):
    return min(POSITION_BINS - 1, i * POSITION_BINS // n)


def features(rnd):
    """(scripthash, activity bin, script type, position bin); derivation index is unobservable, so absent."""
    n = len(rnd.order)
    for i, s in enumerate(rnd.order):
        f = rnd.facts.get(s)
        act = activity_bin(f.tx_count) if f is not None else None
        stype = f.script_type if f is not None and f.tx_count > 0 else None
        yield s, act, stype, position_bin(i, n)


class StructuralModel:
    """Fit on labelled rounds; script-type uniformity is a mixture over the wallet's type, not a frequency."""

    def __init__(self, alpha=1.0, eps=0.01):
        self.alpha, self.eps = alpha, eps
        self.act = {True: Counter(), False: Counter()}
        self.pos = {True: Counter(), False: Counter()}
        self.decoy_types = Counter()
        self.wallet_type_counts = Counter()

    def fit(self, examples):
        for rnd, real in examples:
            own_types = Counter()
            for s, act, stype, pos in features(rnd):
                is_real = s in real
                if act is not None:
                    self.act[is_real][act] += 1
                self.pos[is_real][pos] += 1
                if stype is not None:
                    (own_types if is_real else self.decoy_types)[stype] += 1
            if own_types:
                self.wallet_type_counts[own_types.most_common(1)[0][0]] += 1
        return self

    def vocab(self):
        return sorted(set(self.wallet_type_counts) | set(self.decoy_types))

    def wallet_types(self):
        return self.vocab() or [None]

    def log_prior(self, wallet_type):
        if wallet_type is None:
            return 0.0
        total = sum(self.wallet_type_counts.values())
        return math.log((self.wallet_type_counts[wallet_type] + self.alpha)
                        / (total + self.alpha * len(self.vocab())))

    def _table(self, counts, bins):
        total = sum(counts.values())
        return lambda key: math.log((counts[key] + self.alpha) / (total + self.alpha * bins))

    def log_weights(self, rnd, wallet_type):
        vocab = self.vocab()
        n_act = len(ACTIVITY_EDGES) + 1
        act_r, act_d = self._table(self.act[True], n_act), self._table(self.act[False], n_act)
        pos_r, pos_d = self._table(self.pos[True], POSITION_BINS), self._table(self.pos[False], POSITION_BINS)
        type_d = self._table(self.decoy_types, max(1, len(vocab)))
        off_type = self.eps / max(1, len(vocab) - 1)
        lw = {}
        for s, act, stype, pos in features(rnd):
            w = pos_r(pos) - pos_d(pos)
            if act is not None:
                w += act_r(act) - act_d(act)
            if stype is not None and wallet_type is not None:
                w += math.log(1 - self.eps if stype == wallet_type else off_type) - type_d(stype)
            lw[s] = w
        return lw
