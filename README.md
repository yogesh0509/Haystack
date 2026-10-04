# Haystack

**Private Electrum sync.** A light wallet has to ask a server about its addresses, and in doing so
hands over a perfectly labelled cluster: every address it owns, its full balance, its complete
history, and its change keychain, in one burst, with no inference required. Haystack hides the
wallet's real addresses among decoys, then measures how well the hiding works by attacking it.

> Built for BOSS Battle — Cypherpunk track, *Private Electrum Sync* problem statement.

**Demo video (3–5 minutes):** _link to be added_

---

## The problem

An Electrum server is asked about every address a wallet owns, including its change addresses and
the unused ones it will hand out next. The server sees them arrive together on one connection, so it
learns the whole wallet without any chain analysis. Coinjoins, fresh addresses and silent payments
don't help: the sync itself gives the wallet away. The fix available today is running your own
server, which most users never will. [docs/00-problem.md](docs/00-problem.md) shows the leak with
commands you can run, against a real public server and a fake one that logs every query.

## How Haystack works

- **Padding.** Each real address is sent together with `padding − 1` decoy addresses of the same
  type, shuffled together. At padding 10 the server receives 1,000 addresses for a 100-address
  wallet and answers all of them; the wallet keeps only its own answers. The user sets the padding
  on a dial and sees what each setting costs in bandwidth.
- **The same decoys every time, never withdrawn.** Decoys are derived from a keyed hash of the
  wallet's public keys, so every sync sends exactly the same set. Redrawing decoys each sync is
  undone after about three syncs, because the server intersects the sets and only the real addresses
  survive. Rotating them on a schedule is worse than never rotating. Both results are checked by
  `tests/test_regression.py`. New addresses get their own new decoys in the same sync.
- **A drop-in for `bdk_electrum`.** `haystack-electrum` is a sibling crate with the same `full_scan`
  signature, so a `bdk_wallet` app adopts it by changing a handful of lines (below). The server is
  unmodified.
- **Measured, not asserted.** `attack/` plays the server: it reads everything the server received and
  scores how well it can pick out the real addresses, in bits. Plain Electrum reads 0.00 bits; at
  padding 10, a perfect result reads 3.32 bits (log2 10). Beside it, the score among the addresses
  that have transaction history, which is where a restored wallet's money is.

The write-up of the design decisions and their trade-offs is at the top of
[docs/02-design.md](docs/02-design.md), and how this relates to earlier work (BIP37 bloom filters,
compact block filters, private information retrieval, decoy schemes in Monero and web search) is in
[docs/05-prior-art.md](docs/05-prior-art.md).

## What is finished and what isn't

**Finished and tested:**

- The padded client, which leaves the wallet exactly as plain `bdk_electrum` does: same balance,
  transactions, confirmations and chain tip, through confirmations, a reorganisation and a
  double-spent payment, on a real local Bitcoin chain (`cargo test -p haystack-regtest`).
- The attacker and its score, calibrated so plain Electrum reads 0.00 bits.
- The demo wallet, with the padding dial, the live score, the bytes each sync costs, automatic
  syncs on a random timer, certificate pinning for self-signed servers, and restore.
- The headline measurement: at padding 10 a sync costs about 8.4 times a plain one, and the
  attacker's score is about 2.6 to 2.7 bits averaged over 13 test wallets.

**Not finished:**

- **A restored wallet's funded addresses stay exposed** unless some decoys are real addresses taken
  from the chain. Haystack can take them, but it finds them by asking the same server, which could
  identify every one from its own log. A separate lookup server is the planned fix.
- **Some attacks aren't built**: linking addresses through shared transactions on chain, and
  analysing sync timing. The score covers only the attacks in this repo.
- **Tested against two public servers only** (`electrum.blockstream.info` and
  `fortress.qtornado.com`), once each.

Details, evidence and the post-hackathon plan are in [docs/04-roadmap.md](docs/04-roadmap.md).

## Setup

You need Git, Python 3.9 or newer (standard library only), Rust stable from
[rustup.rs](https://rustup.rs), a C compiler, and OpenSSL's development files. The first build needs
an internet connection: it downloads Rust crates, and `bitcoind` and `electrs` for the local test
chain, each checked against a pinned SHA-256 hash.

**Linux.** Debian or Ubuntu:

```bash
sudo apt install build-essential pkg-config libssl-dev python3 git
```

Fedora: `sudo dnf install gcc make pkgconf-pkg-config openssl-devel python3 git`. Then install Rust
with `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`.

**macOS.**

```bash
xcode-select --install           # C compiler, Git and Python 3
brew install openssl@3           # found automatically by the build
softwareupdate --install-rosetta --agree-to-license   # Apple Silicon only, see below
```

Then install Rust as on Linux. On Apple Silicon the test chain's `bitcoind` and `electrs` are Intel
builds, which run under Rosetta 2. The macOS build has not been tested yet.

**Windows.** The Python parts, including the five-minute check below, run natively: use `py`
wherever this README says `python3`. The Rust parts need WSL2 with any Linux distribution
(`wsl --install` in an administrator PowerShell), then the Linux steps above inside it. The local
test chain has no Windows build of `electrs`, so it can't run natively. The project was built and
tested in WSL2.

Then:

```bash
git clone https://github.com/yogesh0509/Haystack.git
cd Haystack
cargo build --release -p haystack-demo -p haystack-capture -p haystack-regtest
```

## Run it

### Five minutes, no build

Standard-library Python only:

```bash
# 1. Address -> Electrum scripthash: a public, unkeyed, trivially invertible transform.
python3 scripts/scripthash.py 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

# 2. Ask a real public server about it, without proving anything.
python3 scripts/electrum_probe.py --address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

# 3. Become the server: a fake one that logs every query a wallet sends it (Ctrl-C to stop).
python3 scripts/honeypot_electrum.py

# 4. Why redrawn decoys fail after a few syncs, by the project's own attacker
#    (docs/00-problem.md section 6 explains the table).
python3 -m attack strategies
python3 -m unittest -v tests.test_regression

# 5. Haystack's answer: six real padded syncs of the demo wallet, scored by the same attacker.
#    Every sync reads 3.32 bits, the most padding 10 can give.
python3 -m attack score --session tests/fixtures/haystack-session.jsonl \
    --honeypot tests/fixtures/haystack-honeypot-log.json --tier T1
```

### The demo wallet

```bash
cargo run --release -p haystack-demo -- --regtest --mean-minutes 2
```

This starts a private Bitcoin chain on your machine and gives a demo wallet a real history: payments
in, address reuse, spends with change, unconfirmed transactions. That takes about a minute and a
half. Then open <http://127.0.0.1:7878>. The page has two tabs: **Wallet**, as a user would see it,
and **Lab**, the evidence. `--mean-minutes 2` makes the automatic sync run every two minutes on
average, for a demonstration; the product default is 30.

The happy path:

1. **Wallet → Sync now.** The wallet syncs through Haystack at padding 10. Its balance appears, with
   what the attacker learned from the sync.
2. **Lab → Sync now on the plain copy.** The same wallet syncs as every Electrum wallet does today.
   Compare the two: plain Electrum reads 0.00 bits, every address identified; Haystack reads about
   3 bits, at about 8 times the bytes. The coin-history score shows the limitation above: this
   wallet's funded addresses are still exposed.
3. **Someone pays the wallet 0.004 BTC**, then wait for the next sync. The paid address goes from no
   history to some while the server watches, which no decoy ever does, so the score drops.
4. **Move the dial.** The confirmation explains that a new setting only applies to addresses queried
   after the change: decoys already sent are never withdrawn.
5. **Restore without the ledger.** The wallet is rebuilt from its descriptor alone, and the ledger
   file that records each address's decoy count is lost. At a lower padding, the withdrawn decoys
   mark themselves as decoys and the score falls.

The structural attacker (T2 on the page) also learns from other wallets' syncs. It needs a training
set generated by the same build, which takes about 15 minutes; until then the page shows it as
unavailable and scores with the many-rounds attacker (T1) alone:

```bash
cargo run --release -p haystack-regtest --bin sessions -- --out out/sessions
```

[demo/README.md](demo/README.md) has the other servers (the honeypot, a public server), every flag,
and the line-by-line comparison with `bdk_wallet`'s own Electrum example.

### Every case, step by step

[docs/07-walkthrough.md](docs/07-walkthrough.md) runs each case Haystack handles with its expected
output: the leak, a new wallet padded, the correctness tests, a restored wallet with and without
chain decoys, restarts, and the bandwidth-against-privacy curve.

## Using it in a `bdk_wallet` app

`HaystackElectrumClient` stands in for `BdkElectrumClient`. An app makes five kinds of change,
listed against `bdk_wallet`'s own Electrum example in [demo/README.md](demo/README.md):

1. construct `HaystackElectrumClient` with the decoy key, the padding, the ledger file and the saved
   cache file;
2. replace each `sync` with a full scan, so the unused addresses and their decoys are always sent;
3. broadcast through a different server than the one the wallet syncs with;
4. don't pre-fill the transaction cache from the wallet's own transactions;
5. pass the wallet's expected unconfirmed transactions to the scan
   (`full_scan_expecting(wallet.start_full_scan(), wallet.start_sync_with_revealed_spks(), …)`), so
   a payment that leaves the mempool leaves the balance.

The crate has no `sync` and no `transaction_broadcast`, so a missed change fails to compile instead
of silently sending an unpadded query.

## Known limitations and next steps

- **Privacy against a server that reads its own lookup log** needs an independent lookup server for
  chain decoys. Next step after the hackathon.
- **On-chain clustering and timing attacks** aren't built, so the score doesn't account for them.
- **The test wallets' histories are assumed**, not measured from real wallets, and scores on mainnet
  could differ.
- **Bandwidth and server limits.** Padding 10 costs about 8.4 times a plain sync, and a single
  padding-10 sync already exceeds ElectrumX's default per-session request budget, so busy public
  servers may throttle it. Not yet measured against one.
- **It is obfuscation, not cryptography.** Private information retrieval would let the server answer
  without learning anything, at a cost no Electrum server supports today.

The full list, and the plan for each, is in [docs/04-roadmap.md](docs/04-roadmap.md).

## Repo map

| Path | What it is |
|---|---|
| [docs/](docs/) | The problem, threat model, design and write-up, metric, roadmap, prior art, walkthrough, and UX |
| [haystack-electrum/](haystack-electrum/) | The padded Electrum client: decoy selector, ledger, cache, chain decoys and session log |
| [demo/](demo/) | The demo wallet: a local page with the padding dial, the live score and what the server sees |
| [attack/](attack/) | The attacker: reads what a server received and scores it in bits |
| [capture/](capture/) | Stock `bdk_wallet` scans that record what an unmodified wallet queries: the plain baseline |
| [regtest/](regtest/) | A private Bitcoin chain with paid wallets, the correctness tests and the training-set generator |
| [scripts/](scripts/) | The problem demonstrations, including the honeypot server |
| [tests/](tests/) | Python unit tests and the committed fixtures behind the headline numbers |

## Built on

[`bdk_wallet`](https://github.com/bitcoindevkit/bdk_wallet) for descriptors, keychains and address
derivation; `bdk_electrum` for the sync path being replaced.

## License

GPL-3.0 — see [LICENSE](LICENSE).
