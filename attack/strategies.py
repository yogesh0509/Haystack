"""Why fresh random decoys collapse and fixed ones hold (docs/00-problem.md, section 6)."""
from .scoring import attack, knowledge, score

STRATEGIES = (("fresh", "fresh"), ("epoch", "epoch/3"), ("fixed", "fixed"))


def strategies(n_real=100, padding=10, rounds=6, pool_size=100_000, seed=0):
    """One column per decoy strategy, one row per sync.

    Each cell is how many scripthashes the many-rounds attacker (T1) hasn't ruled out, and the
    precision in bits it scores. Decoys are otherwise indistinguishable from real addresses here,
    so these are an upper bound on what a strategy delivers; the structural attack (T2) tests that.
    """
    # The decoy generator is a test fixture, so it is imported only when this command runs.
    from tests import synthetic as synth

    real = synth.extend([synth.random_pool(n_real, seed="strategies")], rounds)
    pool = synth.random_pool(pool_size)

    def column(obs):
        out = []
        for t in range(rounds):
            seen = obs.upto(t)
            post = attack(seen, knowledge(seen, real[t]), "T1")
            candidates = sum(1 for p in post.marginal.values() if p > 0.0)
            out.append((candidates, score(post, seen.rounds[-1], real[t]).precision_bits))
        return out

    plain = column(synth.observe(real))[-1][1]
    columns = [column(synth.observe(synth.pad(real, s, padding, pool, seed))) for s, _ in STRATEGIES]
    decoys = round((padding - 1) * n_real)
    lines = [
        f"real addresses : {n_real}",
        f"decoys / round : {decoys}  ({padding:g}x bandwidth)",
        f"decoy pool     : {pool_size}",
        f"baseline       : plain Electrum sends {n_real} scripthashes, {plain:.2f} bits",
        "each cell      : scripthashes not yet ruled out (precision in bits), many-rounds attacker",
        "",
        " round | " + " | ".join(f"{label:>18}" for _, label in STRATEGIES),
        "-" * (9 + 21 * len(STRATEGIES)),
    ]
    for t in range(rounds):
        cells = [f"{c[t][0]:>5} ({c[t][1]:4.2f} bits)" for c in columns]
        lines.append(f"{t + 1:>6} | " + " | ".join(f"{cell:>18}" for cell in cells))
    return "\n".join(lines)
