"""A2, the structural attack: a naive-Bayes likelihood ratio real:decoy from what a server sees about each
scripthash, trained on labelled sessions of other wallets. The training safeguards are in attack/README.md.

The model is fit fresh on every score and never saved. `fit()` refuses a training session from a different
client build, one that shares any real scripthash with the scored session (training on the answer), and one
recorded at a different padding or chain share. A scored real appearing as someone else's decoy is allowed:
chain-sourced decoys are other people's addresses, and on one shared chain that includes the scored wallet's.
"""
import json
import math
from collections import Counter
from pathlib import Path

from .observe import load_session

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


# Training on other wallets' sessions.

class TrainingRefused(ValueError):
    """The training set can't be used against this session."""


def session_clients(path):
    """Every distinct `client` record in a session log; sessions written before provenance give None."""
    clients = set()
    with open(path) as fh:
        for line in fh:
            if line.strip():
                c = json.loads(line).get("client")
                clients.add(None if c is None else (c.get("name"), c.get("version"), c.get("source")))
    return clients


def session_settings(path):
    """Every distinct (padding, chain share) in a session log; a log from before the chain dial reads 0."""
    settings = set()
    with open(path) as fh:
        for line in fh:
            if line.strip():
                r = json.loads(line)
                settings.add((r.get("padding"), float(r.get("chain_share", 0.0))))
    return settings


def session_paths(spec):
    """A directory means every *.jsonl in it; anything else is one file."""
    paths = []
    for item in spec:
        p = Path(item)
        paths.extend(sorted(p.glob("*.jsonl")) if p.is_dir() else [p])
    return paths


def fit(scored_path, train_paths):
    """Check both safeguards, then fit a StructuralModel on every round of every training session."""
    train_paths = [Path(p) for p in train_paths if Path(p).resolve() != Path(scored_path).resolve()]
    if not train_paths:
        raise TrainingRefused("no training sessions")
    scored_client = session_clients(scored_path)
    if None in scored_client or len(scored_client) != 1:
        raise TrainingRefused(f"{scored_path}: needs exactly one recorded client, has {scored_client}")
    scored_settings = session_settings(scored_path)
    _, scored_truth = load_session(scored_path)
    scored_reals = set().union(*(scored_truth.real(t) for t in range(len(scored_truth.rounds))))

    examples = []
    for path in train_paths:
        client = session_clients(path)
        if client != scored_client:
            raise TrainingRefused(f"{path} came from client {client}, the scored session from {scored_client}")
        settings = session_settings(path)
        if settings != scored_settings:
            raise TrainingRefused(f"{path} was recorded at {settings}, the scored session at {scored_settings}")
        obs, truth = load_session(path)
        shared = scored_reals & set().union(*(truth.real(t) for t in range(len(truth.rounds))))
        if shared:
            raise TrainingRefused(f"{path} has {len(shared)} of {scored_path}'s real scripthashes as reals")
        examples.extend((rnd, truth.real(t)) for t, rnd in enumerate(obs.rounds))
    return StructuralModel().fit(examples), len(train_paths)
