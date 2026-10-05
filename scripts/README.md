# scripts/

Runnable demonstrations of the problem Haystack exists to solve. Standard-library Python 3 only —
no dependencies, no build, no virtualenv.

Read `../docs/00-problem.md` alongside these; it has the expected output and the interpretation.

| Script | What it demonstrates |
|---|---|
| `scripthash.py` | Address → Electrum scripthash. The transform is public, unkeyed and trivially invertible, so a scripthash is not a privacy measure. |
| `electrum_probe.py` | A live public server returns full balance and history for any scripthash, with no authentication. The leak is the question, not the answer. |
| `honeypot_electrum.py` | A fake server that logs every scripthash a wallet asks about. Answers "nothing found" to everything, so the wallet walks its entire gap limit and discloses its full address set. |

## Quick tour

```bash
python3 scripts/scripthash.py 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
python3 scripts/electrum_probe.py --address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

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
Ctrl-C, SIGINT or SIGTERM. To point a stock `bdk_wallet` scan at it, run `capture/` (see
`../capture/README.md`), or the demo wallet with `haystack-demo --url tcp://127.0.0.1:50001`.
