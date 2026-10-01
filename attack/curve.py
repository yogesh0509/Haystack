"""Bandwidth against score: the Week 3 headline result (docs/04-roadmap.md), from regtest's session generator.

At each padding level and chain share every wallet is scored in turn, with the structural model fit on all the other
wallets' sessions (leave one out), so no wallet is ever scored by a model that saw it. The demo wallet's
row is printed on its own, and the mean over all wallets beside it.
"""
import json
import math
from pathlib import Path

from .calibrate import run
from .observe import load_session
from .train import fit


def _mean(xs):
    xs = [x for x in xs if x is not None]
    return math.fsum(xs) / len(xs) if xs else None


def _f(v, width=8, digits=2):
    return f"{'--':>{width}}" if v is None else f"{v:{width}.{digits}f}"


def score_wallet(directory, sub, wallet, wallets):
    folder = Path(directory) / sub
    scored = folder / f"{wallet}.jsonl"
    model, _ = fit(scored, [folder / f"{w}.jsonl" for w in wallets if w != wallet])
    obs, truth = load_session(scored)
    real = truth.real(len(obs.rounds) - 1)
    return run(obs, real, "T1"), run(obs, real, "T2", model=model)


def curve(directory):
    d = Path(directory)
    manifest = json.loads((d / "manifest.json").read_text())
    bandwidth = json.loads((d / "bandwidth.json").read_text())
    wallets = [manifest["scored"]] + manifest["training"]
    demo = manifest["scored"]

    def kib(padding, share, round_):
        rows = [b for b in bandwidth if b["wallet"] == demo and b["padding"] == padding
                and b.get("chain_share", 0.0) == share and b["round"] == round_]
        return (rows[0]["sent"] + rows[0]["received"]) / 1024 if rows else None

    head = (f"{'pad':>4} {'chain':>5} {'|Q|':>6} {'KiB r1':>8} {'KiB r2':>8} {'x plain':>8} |"
            f" {'T1 b':>6} {'T2 b':>6} {'T2 %':>6} {'fund b':>6} {'fund %':>6} |"
            f" {'mean T2 b':>9} {'mean fund %':>11}")
    lines = [
        f"Bandwidth against score -- {d}, last round of each session, scored wallet: {demo}",
        f"structural model: fit on the other {len(wallets) - 1} wallets' sessions at the same settings",
        "",
        head,
        "-" * len(head),
    ]
    base = kib(1, 0.0, 1)
    for cfg in manifest["configs"]:
        p, share = cfg["padding"], cfg["chain_share"]
        results = {w: score_wallet(d, cfg["dir"], w, wallets) for w in wallets}
        t1, t2 = results[demo]
        r2 = kib(p, share, 1)
        lines.append(
            f"{p:>4} {100 * share:>4.0f}% {t2.n_query:>6} {_f(kib(p, share, 0))} {_f(r2)} {_f(r2 / base if base else None)} |"
            f" {_f(t1.precision_bits, 6)} {_f(t2.precision_bits, 6)} {_f(100 * t2.precision, 6, 1)}"
            f" {_f(t2.funded_bits, 6)} {_f(None if t2.funded_precision is None else 100 * t2.funded_precision, 6, 1)} |"
            f" {_f(_mean(r[1].precision_bits for r in results.values()), 9)}"
            f" {_f(_mean(None if r[1].funded_precision is None else 100 * r[1].funded_precision for r in results.values()), 11, 1)}")
    real_side = manifest["real_side"]
    lines += [
        "",
        "KiB r1 / r2: bytes on the wire (both directions, no TLS) for the demo wallet's first and second sync;",
        "  x plain compares r2 with padding 1. T1 b, T2 b: precision in bits, the headline, many-rounds and",
        "  structural attackers. fund: the same precision among scripthashes with history (the funded reals).",
        "chain: share of decoys taken from the chain through the sync server. NOT MODELLED: that server's own",
        "  log of those lookups (the session's `probes`), which names every chain decoy; with it the chain",
        "  rows read like the 0% rows (docs/02-design.md, 'Where decoys come from').",
        f"real side: {real_side['source']}. decoy side: {manifest['decoy_side']}.",
        f"client: {manifest['client']['name']} {manifest['client']['version']} source {manifest['client']['source']}",
    ]
    return "\n".join(lines)
