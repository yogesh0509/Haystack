"""python3 -m attack {tripwire,calibrate,score}"""
import argparse
import sys

from .calibrate import per_round, rounds_table, suite, tripwire
from .harness import TIERS
from .observe import check_plain, load_capture, load_honeypot


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python3 -m attack")
    sub = ap.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("tripwire", help="end-of-week-1 check against a real honeypot capture")
    t.add_argument("--honeypot", required=True, help="honeypot-log.json")
    t.add_argument("--capture", required=True, help="ground truth from capture/")
    t.add_argument("--padding", type=float, default=10)
    t.add_argument("--rounds", type=int, default=6)

    c = sub.add_parser("calibrate", help="the full calibration suite")
    c.add_argument("--honeypot")
    c.add_argument("--capture")
    c.add_argument("--padding", type=float, default=10)
    c.add_argument("--seeds", type=int, default=5)

    s = sub.add_parser("score", help="attack a logged session round by round")
    s.add_argument("--honeypot", required=True)
    s.add_argument("--capture", required=True)
    s.add_argument("--tier", choices=sorted(set(TIERS) - {"T2"}), default="T1")

    args = ap.parse_args(argv)
    if args.cmd == "tripwire":
        ok, report = tripwire(args.honeypot, args.capture, args.padding, args.rounds)
        print(report)
        return 0 if ok else 1
    if args.cmd == "calibrate":
        truth = load_capture(args.capture).rounds if args.capture else None
        obs = load_honeypot(args.honeypot) if args.honeypot else None
        print(suite(truth, obs, args.padding, args.seeds))
        return 0
    obs, truth = load_honeypot(args.honeypot), load_capture(args.capture)
    n = min(len(obs.rounds), len(truth.rounds))
    for r in check_plain(obs, truth)[:n]:
        if r["missing"]:
            print(f"round {r['round'] + 1}: {r['missing']} real scripthashes never reached the server",
                  file=sys.stderr)
            return 1
    print(rounds_table(f"{args.honeypot}, tier {args.tier}",
                       per_round(obs.upto(n - 1), [truth.real(t) for t in range(n)], args.tier)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
