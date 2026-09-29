# Haystack

**Private Electrum sync.** A light wallet has to ask a server about its addresses, and in doing so
hands over a perfectly labelled cluster: every address it owns, its full balance, its complete
history, and its change keychain — for free, in one burst, with no inference required.

Haystack hides a wallet's real address set inside a larger query padded with plausible decoys, and
then proves the hiding works by attacking it.

> Built for BOSS Battle — Cypherpunk track, *Private Electrum Sync* problem statement.

---
Bitcoin's privacy leaks are mostly not on the chain. You can coinjoin everything, never reuse an
address, and use silent payments — and your Electrum sync will still tell the server exactly which
addresses are yours. The fix that exists today is "run your own node," which excludes almost
everybody and is precisely the expert-only setting that keeps good privacy from being the default.
Haystack makes the private path a slider instead of a server rack: pay bandwidth, buy uncertainty,
and see the exchange rate you're getting.

## Three deliverables

1. **A query-crafting algorithm** — how decoys are chosen, scheduled, and grown, documented well
   enough to explain in a sentence and reimplement from the spec.
2. **An adversarial analysis tool** — attacks the scheme across multiple sync rounds and reports a
   deanonymisation score calibrated so an ordinary Electrum query reads `0.00 bits`.
3. **A demo wallet UI** — with a user-facing dial trading bandwidth against that score.

## Repo map

| Path | What it is |
|---|---|
| [docs/00-problem.md](docs/00-problem.md) | The leak, with commands you can run to verify every claim yourself |
| [docs/01-threat-model.md](docs/01-threat-model.md) | Who the adversary is, what they see, what is out of scope |
| [docs/02-design.md](docs/02-design.md) | Decoy construction, the three attacks that break naive designs, open questions |
| [docs/03-metric.md](docs/03-metric.md) | The deanonymisation score — definition, calibration, what it does not capture |
| [docs/04-roadmap.md](docs/04-roadmap.md) | Four-week plan, week-1 tripwire, cut lines |
| [docs/05-prior-art.md](docs/05-prior-art.md) | What already exists and how to position honestly against it |
| [docs/06-decision-log.md](docs/06-decision-log.md) | Why this project, and the alternatives considered and dropped |
| [scripts/](scripts/) | Runnable demonstrations of the problem — see below |

## Verify the problem in five minutes

No build required; these are stdlib Python only.

```bash
# 1. Address -> Electrum scripthash. A public, unkeyed, trivially invertible transform.
python3 scripts/scripthash.py 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

# 2. Ask a real public server about it. Note what you never had to prove.
python3 scripts/electrum_probe.py --address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

# 3. Become the server. Point any light wallet at this and watch it hand over
#    its entire address set, because every reply is "nothing found".
python3 scripts/honeypot_electrum.py

# 4. Why the obvious decoy scheme fails after two syncs, run by the project's own attacker.
python3 -m attack strategies
```

Full walkthrough with expected output in [docs/00-problem.md](docs/00-problem.md).

## Two results worth knowing up front

Both fall out of `python3 -m attack strategies`, and both are counterintuitive enough that a naive
implementation gets them backwards:

- **Re-randomising decoys every sync destroys privacy.** Your real addresses appear in every round;
  independent decoys almost never do. A server intersects the query sets and recovers your wallet
  exactly, in three rounds, at any padding factor. Decoys must be *deterministic per wallet*.
- **Rotating decoys on a schedule is worse than never rotating.** Epoch rotation collapses the
  moment a second epoch is observed. The workable invariant is **append-only**: decoys may be added,
  never withdrawn.

## Status

**Week 1 done:** the attack harness and metric suite are implemented and calibrated — `attack/`,
`python3 -m attack tripwire` and `calibrate`.

**Week 2 in progress:** `haystack-electrum`, the padded query engine, runs real `bdk_wallet` full
scans. Its tests include a correctness gate that runs upstream `bdk_electrum` beside it on the same
server and requires identical wallet data. The first score on real padded traffic — six scans of the
demo wallet at padding 10, sent over a real socket to the local honeypot — is 3.32 bits in every
round, the ceiling for padding 10 (`tests/test_padded_session.py`). That covers only the many-rounds
attacker. On a local regtest chain, a wallet with a real history — receives, a two-input spend
with change, unconfirmed transactions, a reorganisation — ends up identical whether scanned by
upstream `bdk_electrum` or by Haystack (`regtest/`). The client also writes a session log — every query, whether it was real, and the server's
answer — checked query for query against the honeypot's own log. But the honeypot answers "nothing
found" to everything, so the structural attack and activation have nothing real to work on until a
real server answers. See
[docs/04-roadmap.md](docs/04-roadmap.md) for what lands when.

## Built on

[`bdk_wallet`](https://github.com/bitcoindevkit/bdk_wallet) for descriptors, keychains and address
derivation; `bdk_electrum` for the sync path being replaced.

## License

MIT — see [LICENSE](LICENSE).
