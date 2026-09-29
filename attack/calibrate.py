"""The calibration suite of docs/03-metric.md and the week-1 tripwire of docs/04-roadmap.md."""
import math
from dataclasses import dataclass

from . import synth
from .a2 import StructuralModel
from .harness import attack, knowledge
from .metrics import score
from .observe import check_plain, load_capture, load_honeypot
from .posterior import LN2, log_comb

COLUMNS = (
    ("prec-b", lambda s: s.precision_bits),
    ("prec%", lambda s: 100 * s.precision),
    ("chance%", lambda s: 100 * s.chance),
    ("joint/R", lambda s: s.per_real(s.joint_bits)),
    ("truth/R", lambda s: s.per_real(s.truth_bits)),
    ("adv", lambda s: s.advantage),
)

LEGEND = """\
prec-b   -log2(max(prec, chance)): 0 for plain Electrum, log2(padding) at the ceiling     [headline]
prec%    expected share of real among the adversary's top-|R| guesses                     [headline]
chance%  |R| / |Q|: what a same-size random guess gets right, for comparison              [headline]
joint/R  entropy of the posterior over the real subset, per real address        [calibration check]
truth/R  -log2 P_adversary(true R) per real: bits still missing, correctness-aware   [calibration check]
adv      prec - chance; reads 0 for plain Electrum AND for a perfect scheme, kept as a secondary view

Mean per-address entropy was implemented and dropped: it falls as padding rises -- see
docs/03-metric.md."""


@dataclass
class Row:
    name: str
    tier: str
    expect: str
    scores: list


def run(obs, real, tier="T1", pool=(), model=None, activation=True):
    real = frozenset(real)
    post = attack(obs, knowledge(obs, real, pool, model), tier, activation)
    return score(post, obs.rounds[-1], real)


def per_round(obs, real_rounds, tier="T1", **kw):
    return [run(obs.upto(t), real_rounds[t], tier, **kw) for t in range(len(obs.rounds))]


def ceiling(n_real, padding):
    """Analytic values for a perfect scheme: the adversary is stuck at the uniform prior."""
    q = round(padding * n_real)
    top = math.log2(q / n_real)
    joint = log_comb(q, n_real) / LN2 / n_real
    return [top, 100 * n_real / q, 100 * n_real / q, joint, joint, 0.0]


def _mean(xs):
    xs = list(xs)
    return math.inf if any(math.isinf(x) for x in xs) else math.fsum(xs) / len(xs)


def _fmt(v):
    return f"{'inf':>8}" if math.isinf(v) else f"{v:8.2f}"


def _table(rows, ceil_values, ceil_label):
    width = max(len(r.name) for r in rows) + 2
    head = f"{'':>3} {'':<{width}}{'tier':<7}" + "".join(f"{c:>8}" for c, _ in COLUMNS)
    out = [head, "-" * len(head)]
    for i, r in enumerate(rows, 1):
        vals = [_mean(f(s) for s in r.scores) for _, f in COLUMNS]
        out.append(f"{i:>3} {r.name:<{width}}{r.tier:<7}" + "".join(_fmt(v) for v in vals))
    out.append(f"{'':>3} {ceil_label:<{width}}{'--':<7}" + "".join(_fmt(v) for v in ceil_values))
    out.append("")
    out += [f"{i:>3}  expect: {r.expect}" for i, r in enumerate(rows, 1)]
    return "\n".join(out)


def suite(real_rounds=None, honeypot_obs=None, padding=10, seeds=5, rounds=9, pool_size=100_000):
    """Every row a reported score must sit next to; means over `seeds` decoy draws."""
    source = "captured BDK wallet"
    if real_rounds is None:
        real_rounds = [synth.random_pool(100, seed="stand-in")]
        source = "synthetic 100-address stand-in"
    real = synth.extend(real_rounds, rounds)
    pool = synth.random_pool(pool_size)
    rows = []

    if honeypot_obs is not None:
        n = len(honeypot_obs.rounds)
        plain = [run(honeypot_obs, real_rounds[n - 1])]
        rows.append(Row(f"plain Electrum, real honeypot log ({n} rounds)", "T1", "0.00 everywhere", plain))
    else:
        plain = [run(synth.observe(synth.pad(real, "plain", 1, pool)), real[-1])]
        rows.append(Row("plain Electrum", "T1", "0.00 everywhere", plain))

    for strategy, name, expect in (
        ("fresh", "random decoys, redrawn every round", "~0 after ~3 rounds: A1 recovers R"),
        ("epoch", "random decoys, epoch/3 rotation", "~0 once a second epoch is seen"),
        ("fixed", "random decoys, fixed (deterministic)", "ceiling on A1: intersection learns nothing"),
    ):
        scores = [run(synth.observe(synth.pad(real, strategy, padding, pool, seed)), real[-1])
                  for seed in range(seeds)]
        rows.append(Row(f"{name}, {rounds} rounds", "T1", expect, scores))

    rows.append(Row("fixed decoys from a public pool, pool-aware adversary", "T1+pool",
                    "0.00: a shared bundled pool is subtracted exactly",
                    [run(synth.observe(synth.pad(real, "fixed", padding, pool, seed)), real[-1], pool=pool)
                     for seed in range(seeds)]))

    for strategy, activation, name, expect in (
        ("fixed", False, "fixed decoys, wallet paid over 12 rounds",
         "below ceiling: each new real is unpadded (delta corollary)"),
        ("append", False, "append-only, per-increment padding, paid",
         "near ceiling: every cohort carries its own decoys"),
        ("append", True, "append-only, per-increment padding, paid",
         "below ceiling: every paid address is exposed on activation"),
    ):
        scores = []
        for seed in range(seeds):
            obs, wallet_rounds = synth.growing(seed, strategy, padding)
            scores.append(run(obs, wallet_rounds[-1], activation=activation))
        rows.append(Row(name, "T1" if activation else "T1-act", expect, scores))

    for kind, order, tiers, name, expect in (
        ("chain", "shuffle", ("T1", "T2"), "fixed careless chain decoys",
         "T1 ceiling, T2 far below: unused tail and script type give reals away"),
        ("random", "shuffle", ("T2",), "fixed random-scripthash decoys",
         "used reals exposed; unused reals hidden among random hashes"),
        ("wallets", "shuffle", ("T2",), "decoy wallets of the same shape (oracle)",
         "near ceiling: nothing structural to find"),
        ("wallets", "reals-first", ("T2",), "decoy wallets, reals sent first",
         "below ceiling: query order alone leaks (A3)"),
    ):
        model = StructuralModel().fit(
            (obs.rounds[0], r) for obs, r in (synth.world(10_000 + i, kind, padding, order) for i in range(30)))
        for tier in tiers:
            scores = [run(*synth.world(seed, kind, padding, order), tier=tier, model=model)
                      for seed in range(seeds)]
            rows.append(Row(f"{name} (synthetic)", tier, expect, scores))

    title = (f"Calibration suite -- padding {padding:g}x, {seeds} seeds per row, means shown\n"
             f"real set for rows 1-5: {source}, |R| = {len(real[-1])}\n")
    return title + "\n" + _table(rows, ceiling(len(real[-1]), padding),
                                 f"ceiling: perfect scheme, |R| = {len(real[-1])}") + \
        "\n\nT1-act = T1 with the activation attack switched off, to isolate the delta corollary.\n" + \
        "Synthetic rows use assumed feature distributions (attack/synth.py); they test the attack, not Haystack.\n\n" + \
        LEGEND


def _is_zero(s):
    return max(s.precision_bits, s.joint_bits, s.truth_bits) <= 1e-9


def rounds_table(title, scores):
    head = f"  {'round':>5} {'|R|':>5} {'|Q|':>6}" + "".join(f"{c:>8}" for c, _ in COLUMNS)
    lines = [title, head]
    for t, s in enumerate(scores, 1):
        lines.append(f"  {t:>5} {s.n_real:>5} {s.n_query:>6}" + "".join(_fmt(f(s)) for _, f in COLUMNS))
    return "\n".join(lines)


STRATEGIES = (("fresh", "fresh"), ("epoch", "epoch/3"), ("fixed", "fixed"))


def strategies(n_real=70, padding=10, rounds=6, pool_size=100_000, seed=0):
    """Why fresh random decoys collapse and deterministic ones hold, per docs/00-problem.md section 6.

    Each cell is the scripthashes the many-rounds attacker (T1) hasn't ruled out, and precision in
    bits. Decoys are otherwise indistinguishable from real addresses here, so these are an upper
    bound; the structural attack is what tests that assumption.
    """
    real = synth.extend([synth.random_pool(n_real, seed="strategies")], rounds)
    pool = synth.random_pool(pool_size)
    plain = per_round(synth.observe(synth.pad(real, "plain", 1, pool)), real)[-1]
    columns = [per_round(synth.observe(synth.pad(real, s, padding, pool, seed)), real)
               for s, _ in STRATEGIES]
    decoys = round((padding - 1) * n_real)
    lines = [
        f"real addresses : {n_real}",
        f"decoys / round : {decoys}  ({padding:g}x bandwidth)",
        f"decoy pool     : {pool_size}",
        f"baseline       : plain Electrum sends {n_real} scripthashes, {plain.precision_bits:.2f} bits",
        "each cell      : scripthashes not yet ruled out (precision in bits), many-rounds attacker",
        "",
        " round | " + " | ".join(f"{label:>18}" for _, label in STRATEGIES),
        "-" * (9 + 21 * len(STRATEGIES)),
    ]
    for t in range(rounds):
        cells = [f"{c[t].candidates:>5} ({c[t].precision_bits:4.2f} bits)" for c in columns]
        lines.append(f"{t + 1:>6} | " + " | ".join(f"{cell:>18}" for cell in cells))
    return "\n".join(lines)


def tripwire(honeypot_path, capture_path, padding=10, rounds=6, pool_size=100_000, tol=0.10):
    """Return (passed, report) for the end-of-week-1 tripwire."""
    obs, truth = load_honeypot(honeypot_path), load_capture(capture_path)
    report = check_plain(obs, truth)
    matches = all(r["unexpected"] == 0 and r["missing"] == 0 for r in report)
    plain = per_round(obs, [truth.real(t) for t in range(min(len(obs.rounds), len(truth.rounds)))]) \
        if matches else []
    real = synth.extend(truth.rounds, rounds)
    pool = synth.random_pool(pool_size)
    fresh = per_round(synth.observe(synth.pad(real, "fresh", padding, pool)), real)
    fixed = per_round(synth.observe(synth.pad(real, "fixed", padding, pool)), real)
    top = math.log2(round(padding * len(real[-1])) / len(real[-1]))

    checks = [
        ("server log equals the wallet's own derivation in every round", matches),
        ("plain Electrum reads 0.00 bits on every metric in every round",
         bool(plain) and all(_is_zero(s) for s in plain)),
        (f"fresh-random decoys read <= {tol:.2f} bits from round 3 on",
         len(fresh) >= 3 and all(s.precision_bits <= tol for s in fresh[2:])),
        ("the same metric reads log2(padding) for fixed decoys (guards a metric stuck at 0)",
         all(abs(s.precision_bits - top) < 1e-9 for s in fixed)),
    ]
    lines = [f"Tripwire: {honeypot_path} ({len(obs.rounds)} connections) + {capture_path} "
             f"({len(truth.rounds)} rounds)", ""]
    lines += [f"  round {r['round'] + 1}: server saw {r['server']}, wallet sent {r['wallet']}, "
              f"unexpected {r['unexpected']}, missing {r['missing']}" for r in report]
    lines.append("")
    if plain:
        lines += [rounds_table("plain Electrum -- the real honeypot rounds, T1", plain), ""]
    lines += [rounds_table(f"fresh random decoys, {padding:g}x, pool {pool_size}, T1", fresh), ""]
    lines += [rounds_table(f"fixed random decoys, {padding:g}x, T1", fixed), ""]
    lines += [f"  {'PASS' if ok else 'FAIL'}  {name}" for name, ok in checks]
    return all(ok for _, ok in checks), "\n".join(lines)
