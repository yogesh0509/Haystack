"""Seeded synthetic rounds; the feature distributions are assumptions for exercising A2, not chain measurements."""
import random
from dataclasses import dataclass

from .observe import Fact, Observation, Round

STRATEGIES = ("plain", "fresh", "epoch", "fixed", "append")
DECOY_KINDS = ("chain", "random", "wallets")

WALLET_TYPES = (("p2wpkh", 0.60), ("p2tr", 0.20), ("p2sh", 0.12), ("p2pkh", 0.08))
CHAIN_TYPES = (("p2wpkh", 0.45), ("p2pkh", 0.22), ("p2sh", 0.20), ("p2tr", 0.13))
WALLET_TX = ((1, 0.55), (2, 0.25), (4, 0.12), (10, 0.06), (40, 0.02))
CHAIN_TX = ((1, 0.35), (2, 0.20), (4, 0.15), (10, 0.15), (50, 0.10), (300, 0.05))


def random_scripthash(rng):
    return rng.getrandbits(256).to_bytes(32, "big").hex()


def random_pool(n, seed=0):
    rng = random.Random(f"pool:{seed}")
    return [random_scripthash(rng) for _ in range(n)]


def pick(rng, table):
    values, weights = zip(*table)
    return rng.choices(values, weights)[0]


def pad(real_rounds, strategy, padding, pool, seed=0, epoch_len=3, order="shuffle"):
    """Each round's query: the wallet's reals plus (padding - 1) x |R_t| decoys chosen by `strategy`."""
    n = [round((padding - 1) * len(r)) for r in real_rounds]
    rounds = len(real_rounds)

    def draw(key, k):
        return random.Random(f"{seed}:{strategy}:{key}").sample(pool, k)

    if strategy == "plain":
        decoys = [[] for _ in range(rounds)]
    elif strategy == "fresh":
        decoys = [draw(t, n[t]) for t in range(rounds)]
    elif strategy == "epoch":
        decoys = []
        for t in range(rounds):
            e = t // epoch_len
            span = range(e * epoch_len, min(rounds, (e + 1) * epoch_len))
            decoys.append(draw(f"epoch{e}", max(n[u] for u in span))[: n[t]])
    elif strategy == "fixed":
        decoys = [draw("fixed", n[0])] * rounds
    elif strategy == "append":
        # Prefixes of one seeded stream: deterministic, never withdrawn, and growing with every new real.
        stream = draw("append", max(n))
        decoys = [stream[: n[t]] for t in range(rounds)]
    else:
        raise ValueError(f"unknown strategy {strategy}")

    queries = []
    for t in range(rounds):
        q = list(real_rounds[t]) + list(decoys[t])
        if order == "shuffle":
            random.Random(f"{seed}:order:{t}").shuffle(q)
        elif order != "reals-first":
            raise ValueError(f"unknown order {order}")
        queries.append(q)
    return queries


def observe(queries, facts=None):
    return Observation([
        Round(q, {s: facts[t][s] for s in q if s in facts[t]} if facts else {})
        for t, q in enumerate(queries)
    ])


def extend(real_rounds, n):
    """Repeat the last round: valid for a wallet whose server never reports a payment."""
    return list(real_rounds[:n]) + [real_rounds[-1]] * max(0, n - len(real_rounds))


@dataclass
class Wallet:
    rounds: list
    facts: list
    wallet_type: str


def synthetic_wallet(rng, n_rounds, stop_gap=20, pay_prob=0.0, wallet_type=None):
    """Used addresses plus a gap-limit tail per keychain; a payment uses the first unused address."""
    wtype = wallet_type or pick(rng, WALLET_TYPES)
    used_ext, used_int = int(rng.expovariate(1 / 8)), int(rng.expovariate(1 / 5))
    ext = [random_scripthash(rng) for _ in range(used_ext + stop_gap)]
    chg = [random_scripthash(rng) for _ in range(used_int + stop_gap)]
    tx = {s: pick(rng, WALLET_TX) for s in ext[:used_ext] + chg[:used_int]}
    rounds, facts = [], []
    for t in range(n_rounds):
        if t > 0 and rng.random() < pay_prob:
            tx[ext[used_ext]] = 1
            used_ext += 1
            ext.append(random_scripthash(rng))
        r = ext + chg
        rounds.append(r)
        facts.append({s: Fact(tx.get(s, 0), wtype if tx.get(s, 0) else None) for s in r})
    return Wallet(rounds, facts, wtype)


def chain_decoys(rng, n):
    """Careless chain-sourced decoys: all used, types and activity at chain-wide frequencies."""
    out = {}
    while len(out) < n:
        out[random_scripthash(rng)] = Fact(pick(rng, CHAIN_TX), pick(rng, CHAIN_TYPES))
    return out


def random_decoys(rng, n):
    return {random_scripthash(rng): Fact(0) for _ in range(n)}


def wallet_decoys(rng, n, wallet_type, stop_gap):
    """Whole synthetic wallets of the real wallet's type: the oracle-perfect decoy."""
    out = {}
    while len(out) < n:
        w = synthetic_wallet(rng, 1, stop_gap, wallet_type=wallet_type)
        for s in w.rounds[0][: n - len(out)]:
            out[s] = w.facts[0][s]
    return out


def world(seed, kind, padding, order="shuffle", stop_gap=20):
    """One static round: a synthetic wallet padded with fixed decoys of `kind`."""
    rng = random.Random(f"world:{seed}")
    w = synthetic_wallet(rng, 1, stop_gap)
    n = round((padding - 1) * len(w.rounds[0]))
    if kind == "chain":
        decoys = chain_decoys(rng, n)
    elif kind == "random":
        decoys = random_decoys(rng, n)
    elif kind == "wallets":
        decoys = wallet_decoys(rng, n, w.wallet_type, stop_gap)
    else:
        raise ValueError(f"unknown decoy kind {kind}")
    q = w.rounds[0] + list(decoys)
    if order == "shuffle":
        rng.shuffle(q)
    return Observation([Round(q, {**w.facts[0], **decoys})]), frozenset(w.rounds[0])


def growing(seed, strategy, padding, n_rounds=12, pay_prob=0.5, stop_gap=20, pool_size=100_000):
    """A wallet receiving payments over rounds, padded with random-scripthash decoys."""
    w = synthetic_wallet(random.Random(f"grow:{seed}"), n_rounds, stop_gap, pay_prob)
    queries = pad(w.rounds, strategy, padding, random_pool(pool_size, seed), seed)
    facts = [{**{s: Fact(0) for s in q}, **f} for f, q in zip(w.facts, queries)]
    return observe(queries, facts), w.rounds
