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
| [docs/04-roadmap.md](docs/04-roadmap.md) | The four-week plan: what each week delivered, the evidence, known limitations, and what comes after the hackathon |
| [docs/07-walkthrough.md](docs/07-walkthrough.md) | Testing every case, step by step: the leak, new and restored wallets, chain decoys, restarts, the bandwidth curve |
| [scripts/](scripts/) | Runnable demonstrations of the problem — see below |
| [demo/](demo/) | The demo wallet: a local web page with the padding dial, the live score and the bytes each sync costs |

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

# 4. Why the obvious decoy scheme fails after two syncs, checked with the project's own attacker.
python3 -m unittest -v tests.test_regression

# 5. Haystack's answer: six real padded syncs of the demo wallet, scored by the same attacker.
python3 -m attack score --session tests/fixtures/haystack-session.jsonl \
    --honeypot tests/fixtures/haystack-honeypot-log.json --tier T1
```

Full walkthrough with expected output in [docs/00-problem.md](docs/00-problem.md). To test every
case Haystack handles, new and paid wallets included, follow [docs/07-walkthrough.md](docs/07-walkthrough.md).

## Run the demo wallet

Built and tested on WSL (Ubuntu 24.04) with Rust stable, Python 3, `libssl-dev` and `pkg-config`.
The first build downloads `bitcoind` and `electrs` for the local regtest chain.

```bash
# The structural attacker's training set, from the same client build: about 15 minutes.
cargo run --release -p haystack-regtest --bin sessions -- --out out/sessions
# A private regtest chain with a paid wallet; open http://127.0.0.1:7878
cargo run --release -p haystack-demo -- --regtest --mean-minutes 2
```

`--mean-minutes 2` runs the automatic sync at demo speed; the product default is 30 minutes.
[demo/README.md](demo/README.md) has the other servers, the flags, and the line-by-line comparison
with `bdk_wallet`'s own Electrum example.

## Two results worth knowing up front

Both are checked by `tests/test_regression.py`, and both are counterintuitive enough that a naive
implementation gets them backwards:

- **Re-randomising decoys every sync destroys privacy.** Your real addresses appear in every round;
  independent decoys almost never do. A server intersects the query sets and recovers your wallet
  exactly, in three rounds, at any padding factor. Decoys must be *deterministic per wallet*.
- **Rotating decoys on a schedule is worse than never rotating.** Epoch rotation collapses the
  moment a second epoch is observed. The workable invariant is **append-only**: decoys may be added,
  never withdrawn.

## Status

Weeks 0 to 3 are done, and Week 4, the demo wallet and the writeup, is in progress until the
submission deadline on 2026-10-05. [docs/04-roadmap.md](docs/04-roadmap.md) lists what each week
delivered, with the evidence, and the known limitations.

- **The attacker** (`attack/`) scores a sync session in bits, calibrated so plain Electrum reads
  `0.00`. It runs the many-rounds attack and a structural attack trained on labelled sessions of
  other wallets.
- **The padded client** (`haystack-electrum/`) is a sibling crate to `bdk_electrum` with the same
  `full_scan` signature. On a local regtest chain, a wallet with a real history ends up identical
  whether scanned by upstream `bdk_electrum` or by Haystack at padding 10 (`regtest/`).
- **The headline result**, at padding 10 averaged over 13 regtest wallets: the headline reads about
  2.7 bits, but every funded address of a restored wallet is exposed unless some decoys come from the
  chain, and those help only against a server that ignores its own lookup log
  (`python3 -m attack curve`, [docs/07-walkthrough.md](docs/07-walkthrough.md)).

## Built on

[`bdk_wallet`](https://github.com/bitcoindevkit/bdk_wallet) for descriptors, keychains and address
derivation; `bdk_electrum` for the sync path being replaced.

## License

GPL-3.0 — see [LICENSE](LICENSE).
