"""Option B: a structural model fit on labelled Haystack sessions of other wallets (docs/04-roadmap.md, Week 3).

The model is fit fresh on every score and never saved, so regenerating the training sessions is a complete
reset. Two of the three safeguards are enforced here, plus a settings check:

- a training session from a different client build than the scored session is refused;
- so is one in which any of the scored session's real scripthashes is also real, which is training on the
  answer. That catches the same wallet at another padding. A scored real appearing as someone else's
  decoy is allowed: chain-sourced decoys are other people's addresses, and on one shared chain that
  includes the scored wallet's;
- so is one recorded at a different padding or chain share, which would teach the model another
  configuration's fingerprint.
"""
import json
from pathlib import Path

from .a2 import StructuralModel
from .observe import load_session


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
