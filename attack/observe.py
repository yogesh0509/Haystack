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
