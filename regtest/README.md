# regtest/

A real wallet history on a local regtest chain, for testing `haystack-electrum` against a real
Electrum server. The in-memory tests in `haystack-electrum/tests/` use a fake server, and the
honeypot answers "nothing found" to everything. Neither can show a paid wallet: confirmed
transactions with merkle proofs, change, spends, unconfirmed transactions, or a reorganisation of
the chain. This crate can.

```bash
cargo test -p haystack-regtest -- --nocapture   # about 20 seconds; prints the wallet's history
```

## What runs

`bdk_testenv` 0.13.1 starts `bitcoind` in regtest mode — a private chain where blocks are mined on
demand — and `electrs`, an Electrum indexer, connected to it. This is the setup upstream
`bdk_electrum` is tested against. Both processes are local and stop when the test ends.

Both binaries are downloaded the first time the crate is built, and each download is checked
against a SHA-256 hash pinned in the crate that fetches it. A mismatch stops the build.

| Binary | From | Checked against |
|---|---|---|
| Bitcoin Core 25.0 (`bitcoind`) | `bitcoincore.org/bin`, the official release tarball | the hash from Core's own `SHA256SUMS`, shipped in the `bitcoind` 0.36.1 crate |
| `electrs` (Blockstream's esplora build, commit `a33e97e1`) | the `electrsd` maintainer's GitHub releases | the hash pinned in the `electrsd` 0.28.0 crate |

The build script doesn't verify the GPG signature on Core's `SHA256SUMS`, and the `electrs` binary
is a third-party build. So we trust these crates as published — the same trust upstream `bdk`'s CI
places in them. That is acceptable here because nothing on a regtest chain has value and nothing
leaves the machine. To use binaries you built or verified yourself, set `BITCOIND_EXE` and
`ELECTRS_EXE` to their paths.

## The wallet

`build_history` (`src/lib.rs`) gives a BIP84 native-SegWit (P2WPKH) wallet at `m/84'/1'/0'` the
kind of history a real one has. The node's own wallet plays everyone else. Regtest coins are
worthless, so the wallet keeps private keys derived from a public seed string and signs its own
spends.

| Step | What happens | What it exercises |
|---|---|---|
| 1 | Someone pays external 0 (0.5) and external 1 (0.2); a block confirms them | ordinary receives |
| 2 | External 0 is paid again (0.1) | address reuse |
| 3 | One payout pays external 2 (0.3) and external 5 (0.05); two blocks | a transaction touching two of the wallet's addresses; 3 and 4 handed out, never paid |
| 4 | External 30 is paid (0.01) | a used address deep in the range: the scan must reach external 80 |
| 5 | The wallet spends 0.6, more than any one coin it holds; confirmed | two inputs spent together, change to internal 0 |
| 6 | The wallet spends 0.05; left unconfirmed | an unconfirmed outgoing transaction, change to internal 1 |
| 7 | Someone pays external 6 (0.02); left unconfirmed | an unconfirmed incoming payment |

The result: 8 transactions, 2 of them unconfirmed; external 0, 1, 2, 5, 6 and 30 used; internal 0
and 1 used.

## The correctness gate (`tests/gate.rs`)

`docs/04-roadmap.md`: a padded sync and a plain sync must produce the same wallet state. Three
rounds, each a full scan by upstream `bdk_electrum` and by `HaystackElectrumClient` at padding 10,
each into its own copy of the wallet:

1. The history above.
2. After a block confirms the two unconfirmed transactions and a new payment lands on external 60,
   inside the positions the ledger already froze. Haystack needs a second stage (external 81–110).
3. After a one-block reorganisation replaces the tip block, so its transactions confirm in a
   different block. This exercises the chain-tip agreement and the merkle-proof checks.

After every round the two wallets must match exactly. That covers the balance in all four
categories, every transaction with the block it confirmed in, every unspent coin, the derivation
index on each keychain, and the chain tip. The test also checks the session log. It expects the
stages the planner should take, a transaction count above zero for exactly the used real addresses,
and none for any decoy.

This is the only test of confirmed transactions. Making Haystack drop every confirmation anchor
leaves all 43 in-memory tests passing, and fails this one at round 1.
