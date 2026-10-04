"""python3 -m attack {strategies,score,curve}"""
import argparse
import json
import sys

from .scoring import TIERS, attack, knowledge, per_round, rounds_table, score, view
from .curve import curve
from .a2_structural import TrainingRefused, fit, session_paths
from .observe import check_plain, check_session, load_capture, load_honeypot, load_session


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python3 -m attack")
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("strategies", help="why fresh random decoys collapse (docs/00-problem.md section 6)")
    d.add_argument("--real", type=int, default=100)
    d.add_argument("--padding", type=float, default=10)
    d.add_argument("--rounds", type=int, default=6)
    d.add_argument("--pool", type=int, default=100_000)
    d.add_argument("--seed", type=int, default=0)

    s = sub.add_parser("score", help="attack a logged session round by round")
    s.add_argument("--session", help="haystack-session/1 log from haystack-electrum")
    s.add_argument("--honeypot", help="the server's log; with --session, checked against it first")
    s.add_argument("--capture", help="ground truth from capture/, when scoring a honeypot log alone")
    s.add_argument("--tier", choices=sorted(TIERS), default="T1")
    s.add_argument("--train", nargs="+", help="labelled sessions of other wallets (files or directories); needed for T2")
    s.add_argument("--last", action="store_true", help="score only the last round")
    s.add_argument("--json", action="store_true", help="print one JSON object per scored round instead of a table")
    s.add_argument("--view", action="store_true",
                   help="with --last --json: add the attacker's probability per scripthash, in arrival order")

    v = sub.add_parser("curve", help="bandwidth against score, from regtest's session generator")
    v.add_argument("--dir", required=True, help="output of `cargo run -p haystack-regtest --bin sessions`")

    args = ap.parse_args(argv)
    if args.cmd == "strategies":
        from .strategies import strategies
        print(strategies(args.real, args.padding, args.rounds, args.pool, args.seed))
        return 0
    if args.cmd == "score" and args.view and not (args.last and args.json):
        ap.error("--view needs --last and --json")
    if args.cmd == "curve":
        try:
            print(curve(args.dir))
        except TrainingRefused as e:
            print(f"refused: {e}", file=sys.stderr)
            return 1
        return 0
    model = None
    if args.tier == "T2":
        if not (args.session and args.train):
            ap.error("T2 needs --session and --train")
        try:
            model, n_train = fit(args.session, session_paths(args.train))
        except TrainingRefused as e:
            print(f"refused: {e}", file=sys.stderr)
            return 1
        if not args.json:
            print(f"structural model fit on {n_train} training sessions")
    if args.session:
        obs, truth = load_session(args.session)
        if args.honeypot:
            for r in check_session(obs, load_honeypot(args.honeypot)):
                if not r["same_order"]:
                    print(f"round {r['round'] + 1}: the session log ({r['logged']} queries) doesn't match "
                          f"what the server received ({r['received']}), same set: {r['same_set']}",
                          file=sys.stderr)
                    return 1
        source = args.session
    elif args.honeypot and args.capture:
        obs, truth = load_honeypot(args.honeypot), load_capture(args.capture)
        source = args.honeypot
    else:
        ap.error("score needs --session, or both --honeypot and --capture")
    n = min(len(obs.rounds), len(truth.rounds))
    for r in check_plain(obs, truth)[:n]:
        if r["missing"]:
            print(f"round {r['round'] + 1}: {r['missing']} real scripthashes never reached the server",
                  file=sys.stderr)
            return 1
    views = None
    if args.last:
        last, real = obs.upto(n - 1), frozenset(truth.real(n - 1))
        post = attack(last, knowledge(last, real, model), args.tier)
        scores = [score(post, last.rounds[-1], real)]
        if args.view:
            views = [view(post, last.rounds[-1], real)]
        first = n
    else:
        scores = per_round(obs.upto(n - 1), [truth.real(t) for t in range(n)], args.tier, model=model)
        first = 1
    if args.json:
        for t, sc in enumerate(scores, first):
            line = {
                "round": t, "tier": args.tier, "n_real": sc.n_real, "n_query": sc.n_query,
                "precision_bits": sc.precision_bits, "precision": sc.precision, "chance": sc.chance,
                "funded": sc.funded, "with_history": sc.with_history,
                "funded_bits": sc.funded_bits, "funded_precision": sc.funded_precision,
                "funded_chance": sc.funded_chance,
            }
            if views:
                line["view"] = views[t - first]
            print(json.dumps(line))
        return 0
    print(rounds_table(f"{source}, tier {args.tier}", scores))
    return 0


if __name__ == "__main__":
    sys.exit(main())
