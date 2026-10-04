"""What the adversary observes, kept apart from the ground truth it is scored against."""
import json
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class Fact:
    """The server's own index entry for a scripthash at query time; type is unknowable while unused."""
    tx_count: int
    script_type: Optional[str] = None


@dataclass
class Round:
    """One sync: distinct scripthashes in first-arrival order."""
    order: list
    facts: dict = field(default_factory=dict)

    def __post_init__(self):
        self.order = list(dict.fromkeys(self.order))
        self.members = frozenset(self.order)


@dataclass
class Observation:
    rounds: list

    def upto(self, t):
        return Observation(self.rounds[: t + 1])


@dataclass
class GroundTruth:
    """The wallet's real scripthashes per round, in its own query order."""
    rounds: list

    def real(self, t):
        return frozenset(self.rounds[t])


def load_honeypot(path):
    """One round per client connection; logs without connection ids load as a single round."""
    with open(path) as fh:
        entries = json.load(fh)
    by_conn = {}
    for e in entries:
        if e.get("scripthash"):
            by_conn.setdefault(e.get("conn", 0), []).append(e["scripthash"])
    return Observation([Round(by_conn[c]) for c in sorted(by_conn)])


def load_capture(path):
    with open(path) as fh:
        cap = json.load(fh)
    if cap.get("format") != "haystack-capture/1":
        raise ValueError(f"{path}: not a haystack-capture/1 file")
    return GroundTruth([[q["scripthash"] for q in r["queried"]] for r in cap["rounds"]])


def check_plain(obs, truth):
    """Server-received versus wallet-sent, per round; equal for an unpadded sync."""
    report = []
    for t in range(max(len(obs.rounds), len(truth.rounds))):
        q = obs.rounds[t].members if t < len(obs.rounds) else frozenset()
        r = truth.real(t) if t < len(truth.rounds) else frozenset()
        report.append({"round": t, "server": len(q), "wallet": len(r),
                       "unexpected": len(q - r), "missing": len(r - q)})
    return report


def load_session(path):
    """haystack-session/1 from haystack-electrum: one round per line, the server's view and the truth.

    A scripthash's script type is on the chain only once it has history, so it is hidden for unused
    ones; a query whose answer never arrived (`tx` null) contributes no fact. A round that failed
    before sending any query (the client logs every failed round) reached the server with nothing,
    so it is skipped rather than scored as an empty round.
    """
    obs, truth = [], []
    with open(path) as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            r = json.loads(line)
            if r.get("format") != "haystack-session/1":
                raise ValueError(f"{path}:{n}: not a haystack-session/1 line")
            qs = r["queries"]
            if not qs:
                continue
            facts = {q["sh"]: Fact(q["tx"], q["type"] if q["tx"] else None)
                     for q in qs if q["tx"] is not None}
            obs.append(Round([q["sh"] for q in qs], facts))
            truth.append([q["sh"] for q in qs if q["j"] is None])
    return Observation(obs), GroundTruth(truth)


def check_session(session, server):
    """Per round: did the server receive exactly what the session log says was sent, in that order?"""
    report = []
    for t in range(max(len(session.rounds), len(server.rounds))):
        logged = session.rounds[t].order if t < len(session.rounds) else []
        received = server.rounds[t].order if t < len(server.rounds) else []
        report.append({"round": t, "logged": len(logged), "received": len(received),
                       "same_set": set(logged) == set(received), "same_order": logged == received})
    return report
