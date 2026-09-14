#!/usr/bin/env python3
"""Why fresh random decoys collapse, and deterministic ones do not.

Padding a query with decoys buys privacy for exactly one round if the decoys
are re-randomised each time. A server that sees you sync repeatedly just
intersects the query sets: your real addresses appear in every round, and
independent decoys almost never do.

This simulates that attack against three decoy strategies and reports the
surviving candidate set after each round.

    python3 scripts/intersection_sim.py
    python3 scripts/intersection_sim.py --real 70 --decoys 630 --rounds 6

IMPORTANT SCOPE: this models the intersection attack ONLY. It assumes decoys
are otherwise indistinguishable from real addresses, which is exactly the
assumption that fails in practice (see docs/02-design.md). Treat these
numbers as an UPPER bound on the privacy a strategy can deliver.
"""
import argparse
import math
import random


def anonymity_bits(surviving, real_n):
    """log2 of the anonymity factor. 0 bits == fully deanonymised.

    With `surviving` indistinguishable candidates of which `real_n` are real,
    a uniform adversary's uncertainty about any given address scales with
    surviving/real_n. Plain Electrum sends exactly the real set, so
    surviving == real_n and this reads 0 -- the calibration point the
    problem statement asks for.
    """
    if surviving <= real_n:
        return 0.0
    return math.log2(surviving / real_n)


def run(strategy, real, universe, k, rounds, epoch_len, rng):
    """Return the surviving candidate-set size after each round."""
    real_set = set(rng.sample(sorted(universe), real))
    pool = sorted(universe - real_set)

    # Decoys the wallet commits to, for the strategies that reuse them.
    fixed = set(rng.sample(pool, k))

    surviving = None
    sizes = []
    for r in range(rounds):
        if strategy == "fresh":
            decoys = set(rng.sample(pool, k))
        elif strategy == "deterministic":
            decoys = fixed
        elif strategy == "epoch":
            # Re-derive once per epoch, deterministic within it.
            epoch_rng = random.Random(1000 + r // epoch_len)
            decoys = set(epoch_rng.sample(pool, k))
        elif strategy == "monotone":
            # Append-only: the round-0 decoys are never withdrawn, so the
            # intersection can never fall below them, while the set can still
            # grow to cover addresses the wallet reveals later.
            decoys = fixed | set(pool[k:k + r * (k // 10)])
        else:
            raise ValueError(strategy)

        query = real_set | decoys
        surviving = query if surviving is None else (surviving & query)
        sizes.append(len(surviving))
    return sizes, len(real_set)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--real", type=int, default=70,
                    help="addresses the wallet actually owns")
    ap.add_argument("--decoys", type=int, default=630,
                    help="decoys added per round (630 = 10x padding)")
    ap.add_argument("--universe", type=int, default=100_000,
                    help="plausible-decoy pool the wallet draws from")
    ap.add_argument("--rounds", type=int, default=6)
    ap.add_argument("--epoch-len", type=int, default=3)
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()

    universe = set(range(args.universe))
    print(f"real addresses : {args.real}")
    print(f"decoys / round : {args.decoys}  "
          f"({(args.real + args.decoys) / args.real:.1f}x bandwidth)")
    print(f"decoy pool     : {args.universe}")
    print(f"baseline       : plain Electrum sends {args.real} scripthashes, "
          f"0.00 bits\n")

    strategies = ("fresh", "deterministic", "epoch", "monotone")
    labels = ("fresh", "deterministic", f"epoch/{args.epoch_len}", "monotone")

    hdr = f"{'round':>6} | " + " | ".join(f"{l:>19}" for l in labels)
    print(hdr)
    print("-" * len(hdr))

    results = {}
    for strat in strategies:
        sizes, real_n = run(strat, args.real, universe, args.decoys,
                            args.rounds, args.epoch_len,
                            random.Random(args.seed))
        results[strat] = (sizes, real_n)

    for r in range(args.rounds):
        cells = []
        for strat in strategies:
            sizes, real_n = results[strat]
            s = sizes[r]
            cells.append(f"{s:>5} ({anonymity_bits(s, real_n):>5.2f} bits)")
        print(f"{r + 1:>6} | " + " | ".join(f"{c:>19}" for c in cells))

    fresh_final = results["fresh"][0][-1]
    det_final = results["deterministic"][0][-1]
    print(f"\nAfter {args.rounds} rounds:")
    print(f"  fresh decoys        -> {fresh_final} candidates "
          f"({anonymity_bits(fresh_final, args.real):.2f} bits). "
          f"{'The real set is fully exposed.' if fresh_final <= args.real else ''}")
    print(f"  deterministic decoys-> {det_final} candidates "
          f"({anonymity_bits(det_final, args.real):.2f} bits). Intersection "
          f"learns nothing.")
    print("\nExpected surviving decoys under 'fresh' after r rounds is")
    print("k^r / |U|^(r-1); with these parameters that is "
          f"{args.decoys ** 2 / args.universe:.2f} after round 2.")


if __name__ == "__main__":
    main()
