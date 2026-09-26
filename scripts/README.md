# scripts/

Runnable demonstrations of the problem Haystack exists to solve. Standard-library Python 3 only —
no dependencies, no build, no virtualenv.

Read `../docs/00-problem.md` alongside these; it has the expected output and the interpretation.

| Script | What it demonstrates |
|---|---|
| `scripthash.py` | Address → Electrum scripthash. The transform is public, unkeyed and trivially invertible, so a scripthash is not a privacy measure. |
| `electrum_probe.py` | A live public server returns full balance and history for any scripthash, with no authentication. The leak is the question, not the answer. |
| `honeypot_electrum.py` | A fake server that logs every scripthash a wallet asks about. Answers "nothing found" to everything, so the wallet walks its entire gap limit and discloses its full address set. |
| `intersection_sim.py` | Why re-randomised decoys fail after ~3 sync rounds, why scheduled rotation is worse than none, and why append-only works. |

## Quick tour

```bash
python3 scripts/scripthash.py 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
python3 scripts/electrum_probe.py --address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
python3 scripts/intersection_sim.py

# two terminals for this one
python3 scripts/honeypot_electrum.py
```

## Notes

`electrum_probe.py` talks to `electrum.blockstream.info:50002` by default; override with
`--server host:port`. Certificate verification is deliberately disabled because Electrum servers
routinely use self-signed certificates — the protocol has no PKI story, which is a separate trust
problem worth noticing.

`honeypot_electrum.py` handles both single JSON-RPC requests and the batched arrays that
`electrum_client` sends during a full scan. It writes `honeypot-log.json` on shutdown via any of
Ctrl-C, SIGINT or SIGTERM. To point BDK at it, edit `ELECTRUM_URL` in
`~/bdk_wallet/examples/electrum.rs` to `tcp://127.0.0.1:50001`.

`intersection_sim.py` models the intersection attack **only**, assuming decoys are otherwise
indistinguishable from real addresses. That assumption is exactly what fails in practice, so treat
its numbers as an upper bound on achievable privacy rather than a measurement of it. See
`../docs/02-design.md` attack A2.

The attack is one line: `surviving = surviving & query` per round — no classifier, no belief
scoring, just "which scripthashes appeared in every observed query so far." Real addresses always
pass (`query = real_set | decoys` every round), so `surviving` floors at `|R|`. Decoys pass only if
the strategy happens to resend them:

- `fresh` redraws all decoys independently from the pool each round → near-zero overlap between
  rounds (expected survivors ≈ `k²/|U|`), collapses to `|R|` by round 3.
- `deterministic` resends the same fixed decoy set forever → never collapses.
- `epoch/N` holds decoys fixed within an epoch but redraws independently at each boundary →
  collapses like `fresh` every N rounds. Strictly worse than `deterministic`, not a middle ground.
- `monotone` (append-only) keeps the original fixed set forever and only ever unions in more
  addresses — a positional slice of the sorted pool (`pool[k:k+r*(k//10)]`), not re-randomized, so
  it can overlap `fixed` and isn't guaranteed to add exactly that many new addresses. Never
  collapses, and can grow to cover new real addresses without losing ground already won.
