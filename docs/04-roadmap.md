# Roadmap

This page is the plan Haystack was built to: what each part of the project set out to do, what was
delivered, where the evidence is, and what is still open. The reasoning behind each decision is in
`docs/02-design.md`; this page only points to it.

## Approach

Two rules shaped the plan.

- **Build the attacker before the defence.** Every privacy number in the project comes from the
  attack suite, so a weak attack would make every later number meaningless. The attacker is
  built first; the decoy scheme comes after.
- **Extend software that already runs.** Haystack is a query layer over `bdk_wallet` and unmodified
  public Electrum servers. It is not a new wallet and not a new server, and an existing `bdk_wallet`
  app adopts it by changing a few lines (`haystack-electrum/README.md`, "Adopting it in a
  `bdk_wallet` app").

## Week 0: the problem, verified

The goal was to show the leak with commands anyone can run, before building anything.

- `scripts/scripthash.py` shows that a scripthash is a public, unkeyed function of the address.
- `scripts/electrum_probe.py` asks a live public server about any address and gets an answer, with
  no proof of ownership.
- `scripts/honeypot_electrum.py` is a fake Electrum server that logs every query. A real
  `bdk_wallet` scan pointed at it hands over its whole address set, change addresses included, in
  under a second.
- The first design result came from simulation, not reasoning: redrawn and scheduled decoys fail,
  and the rule that survives is append-only (`docs/00-problem.md` §6, checked by
  `tests/test_regression.py`).

## Week 1: the attacker

The goal was an attacker strong enough that a good score means something, and a score that reads
exactly 0.00 for plain Electrum.

- [x] **One belief, many attacks.** Every attack adds evidence to a single Bayesian belief about
      which scripthashes are real, and every metric is read off that belief
      (`attack/scoring.py`, `attack/posterior.py`). `tests/test_posterior.py` checks the exact
      computation against brute force.
- [x] **The many-rounds attack** (`attack/a1_many_rounds.py`) compares syncs: a scripthash that
      vanishes was a decoy, and one that is paid while watched was real.
- [x] **The structural attack** (`attack/a2_structural.py`) learns how real and decoy scripthashes
      differ in transaction count, script type and position in the query, without needing repeated
      syncs.
- [x] **The metric** (`docs/03-metric.md`): precision in bits as the headline, with the same
      precision among funded addresses beside it. Six candidate metrics were measured and dropped,
      and the reasons are recorded there.
- [x] **Regression guard** (`tests/test_regression.py`): known-broken decoy schemes must always score
      near zero, so the metric cannot quietly start praising them.

**Check on the attacker, passing.** `tests/test_plain_capture.py` runs the attacker against real
captured honeypot sessions and reads 0.00 bits for plain Electrum; `tests/test_regression.py` reads
near zero for freshly redrawn decoys.

## Week 2: the padded sync client

The goal was a client that sends the padded query and leaves the wallet exactly as a plain sync
would.

- [x] **A sibling crate, not a fork.** `haystack-electrum` reimplements `bdk_electrum`'s full scan on
      the same public interfaces, targeting `bdk_wallet` 2.1.0, and its response plugs into
      `wallet.apply_update()` unchanged (`docs/02-design.md`, "haystack-electrum").
- [x] **Public API.** `HaystackElectrumClient::new(inner_client, decoy_key, padding)` stands in for
      `BdkElectrumClient::new(inner_client)`, and `full_scan` keeps upstream's signature. An app
      adopts it with five kinds of change, listed with their reasons in `haystack-electrum/README.md`;
      the demo wallet is held to exactly these.
- [x] **Deterministic decoys** (`haystack-electrum/src/decoy.rs`, `key.rs`): decoy `j` of an address
      is a same-type script filled from `HMAC-SHA256(key, keychain ‖ index ‖ j)`, with the key
      derived from the wallet's public keys, so every device produces the same decoys
      (`docs/02-design.md`, A1).
- [x] **Append-only, padded per increment** (`ledger.rs`). A position's decoy count is frozen the
      first time it is queried and recorded before anything is sent. A newly used address arrives
      with its own `padding − 1` new decoys in the same sync.
- [x] **The ledger file is the backup** (`ledger_file.rs`, format `haystack-ledger/1`). The key can
      be rebuilt from the wallet, but the frozen counts can't. The whole file is under 300 bytes
      for the demo wallet; what losing it costs is measured in `docs/07-walkthrough.md`, case 9.
- [x] **Session log** (`session.rs`, format `haystack-session/1`). The client records every query in
      send order, whether it was real, and the server's answer. `python3 -m attack score` checks it
      query for query against the server's own log before scoring.
- [x] **Order and batching.** Reals and decoys are shuffled together and sent in batches of five
      real addresses' worth, the ratio `bdk_wallet`'s own example uses. Timing is drawn from an
      exponential delay (`schedule.rs`, `docs/02-design.md`, "Sync scheduling").
- [x] **Correctness gate on a real chain** (`regtest/tests/gate.rs`, described in
      `regtest/README.md`). After every round, upstream `bdk_electrum` and Haystack at padding 10
      must leave the wallet with the same balance, transactions, confirmation blocks, unspent coins
      and chain tip, through receives, a spend, unconfirmed transactions and a one-block
      reorganisation. One difference is by design: Haystack can query a few more addresses than a
      plain scan, never fewer.
- [x] **A real public server.** The never-paid demo wallet, padded 10 times, synced against
      `electrum.blockstream.info`: every one of 1,000 answers arrived, and the session log matched
      the wallet's record. A padded sync took 9.3 s against 6.9 s for a plain one, about 1.35 times
      as long, with one sample per setting. A second server, `fortress.qtornado.com`, refused the
      connection because of its old certificate; that led to the certificate policy in
      `demo/README.md`.

## Week 3: decoys with history, and the headline curve

The goal was the hard part: a wallet whose own addresses already have history, as after a restore.
The first client's decoys never have history, so against them every address with history is exposed.

- [x] **The structural attacker on real sessions**, trained on labelled sessions of other wallets
      rather than on synthetic ones. `cargo run --release -p haystack-regtest --bin sessions` gives
      12 training wallets random histories on the regtest chain and syncs them, plus the demo
      wallet, at padding 1, 2, 5, 10 and 20. The training wallets' histories come from assumed
      tables, stated in one place (`regtest/src/population.rs`) and copied into every run.
- [x] **Three safeguards on the training data**: provenance, no training on the answer, and a
      reset (`attack/README.md`, "Training safeguards").
- [x] **Decoys taken from the chain** (`haystack-electrum/src/chain.rs`, off by default, stored in
      the ledger as `haystack-ledger/2`). A chosen share of each address's decoys are real
      addresses from past blocks, so they have history. The limits of finding them through the sync
      server are under "Known limitations".
- [x] **A saved cache shared by reals and decoys** (`cache_file.rs`), so a restarted client does
      not refetch decoy transactions only (`docs/02-design.md`, "haystack-electrum").
- [x] **Bandwidth, measured.** A byte-counting relay sits between the client and `electrs`
      (`regtest/src/proxy.rs`). The demo wallet's steady-state sync took 30.2 KiB plain and 253.5 KiB
      at padding 10, 8.4 times as much for 10 times the scripthashes.
- [x] **The bandwidth-versus-score curve** (`python3 -m attack curve`), the headline result. At
      padding 10, averaged over 13 wallets: the headline reads 2.75 bits, but precision among funded
      addresses is 100% when every decoy is HMAC-derived. With 10% of decoys from the chain, funded
      precision falls to 25.8%, against a server that ignores its own log. The shuffle is random
      each run, so a rerun reads 2.70 bits, 100% and 28.8%: the numbers move by a few points, and
      which funded addresses are exposed does not.
- [x] **The implementation's own fingerprint.** With history hidden, a model trained on order and
      batching alone stays within about 2.5 points of chance.

`docs/07-walkthrough.md` runs every one of these cases with real outputs.

## Week 4: demo and writeup

The goal is a demo wallet that shows the dial, the live score and the bandwidth it costs, built
with the same wallet code as `bdk_wallet`'s own Electrum example.

- [x] **Batch size counts real addresses.** `full_scan`'s `batch_size` means real addresses'
      worth per write, so the 5 that `bdk_wallet`'s example passes sends 50 scripts per write at
      padding 10 without the app changing. Counting scripts would have split a padded sync into 200
      writes instead of 20, which measured 64.1 s against 9.3 s on Blockstream's server, and fixing
      it in the app would have been one more kind of change.
- [x] **Automatic syncs on a random timer** (`haystack-electrum/src/schedule.rs`, driven by the
      demo's sync loop): an exponential delay, a missed sync skipped and redrawn rather than fired
      late, and a manual sync that never moves the timer. The product default mean is 30 minutes,
      about 11.9 MiB a day at padding 10. The demo runs with a 2-minute mean so that syncs happen
      during a presentation, and says so on screen. The reasoning and the arithmetic are in
      `docs/02-design.md`, "Sync scheduling".
- [x] **Demo wallet web page** (`demo/`; `demo/README.md` has the flags and the screens). Two copies
      of one wallet sync side by side against the same server, plain and Haystack at the dial, and
      the repo's attacker scores each copy's session log after every sync. On the paid regtest
      wallet's first sync, plain took 37.9 KiB and read 0.00 bits; padding 10 took 259.6 KiB and
      read 3.32 bits from the many-rounds attacker, with funded precision 100%, the restored-wallet
      exposure below.
- [x] **Mempool evictions detected, as by upstream's `sync`** (`full_scan_expecting`). A full scan
      can't tell when an unconfirmed transaction has left the mempool, so the app also passes the
      wallet's expected transactions; that is the fifth kind of change.
      `regtest/tests/eviction.rs` checks that Haystack at padding 10 ends with the balance
      upstream's `sync` gives (`docs/02-design.md`, "haystack-electrum").
- [x] **Demo wallet code held to the five kinds of change** over `bdk_wallet`'s
      `examples/electrum.rs` (`demo/src/wallet.rs`; `demo/README.md` lists every line of the example
      against the demo's).
- [x] **Server certificate policy** (`demo/src/transport.rs`): a self-signed certificate is trusted
      on first use and pinned, and a different one is refused afterwards. `demo/README.md`,
      "Certificate policy", has the survey of public servers behind it.
- [x] **A second public server.** The never-paid demo wallet at padding 10 against
      `fortress.qtornado.com:50002`, the server that refused the first connection: its version 1
      certificate was pinned on first use, and all 1,000 scripthashes were answered in 25.6 s,
      196.3 KiB on the wire with TLS included. One sample. This server, like other ElectrumX
      servers, refuses every request until the client sends Electrum's `server.version` greeting,
      which `electrum-client` never sends, so the demo sends it with an empty client name.
- [x] **Restore path.** The restore set is the descriptor plus the ledger file, both shown on the
      page. What a restore without the ledger costs is measured in `docs/02-design.md`, "What each
      user action does to the query".
- [x] **Every case reproducible** (`docs/07-walkthrough.md`): the leak, padded and plain syncs scored
      by the same attacker, the correctness tests, restored wallets with and without chain decoys,
      restarts and the bandwidth curve, each with its command and expected output.
- [x] **Write-up**: the design decisions and their trade-offs on one page at the top of
      `docs/02-design.md`, and the related work in `docs/05-prior-art.md`.
- [x] **README and a clean clone**: setup for Linux, macOS and Windows (through Docker or WSL2), the
      five-minute check, the demo's happy path and the known limitations, followed from a fresh
      clone.
- [x] **Demo video** (3–5 minutes), linked near the top of the README.
- [x] **A Docker image** (`Dockerfile`): `docker build -t haystack .` then `docker run -it --rm -p
      127.0.0.1:7878:7878 -v haystack-out:/haystack/out haystack` runs the regtest demo the same way
      on Linux, macOS and Windows.

## Known limitations

These are measured or stated, not hidden.

- **A restored wallet's funded addresses are exposed without chain decoys.** HMAC-derived decoys
  never have history, so every scripthash with history is real: precision among funded addresses
  reads 100%.
- **Chain decoys only help against a server that ignores its own log.** They are found through the
  sync server, which can match its lookups against later queries and remove every chain decoy
  (`docs/02-design.md`, "Where decoys come from"). That attack is described and deliberately not
  built.
- **A payment while the wallet is watched exposes the paid address.** An address that goes from no
  history to some must be real, since no decoy is ever paid (`docs/07-walkthrough.md`, case 7).
- **Evictions need the fifth change.** An app that calls plain `full_scan` instead of
  `full_scan_expecting` never learns that an unconfirmed payment left the mempool, as with
  upstream's own `full_scan`. An expected address the scan doesn't reach is left alone, too.
- **The training wallets' histories are assumed**, not measured from real wallets, and the
  regtest chain is small. Scores on mainnet could differ.
- **Only P2WPKH has been run end to end.** The engine builds same-type decoys for P2PKH, P2SH,
  P2WPKH, P2WSH and P2TR (`haystack-electrum/src/decoy.rs`, with a unit test for all five), but the
  demo wallet, `capture/` and every regtest wallet use `wpkh(...)` descriptors. A script outside
  those five types stops the sync with "no decoy shape" rather than being sent unpadded.
- **This is obfuscation, not cryptography.** The privacy bound is empirical: it holds against the
  attacks in this repo, and an attack nobody wrote doesn't show up in the score
  (`docs/01-threat-model.md`).

## After the hackathon

Planned once the items above are done and tested:

- **An independent lookup server for chain decoys**, so the sync server can't name them from its own
  log, together with the threat-model assumption it needs (`docs/02-design.md`, "Where decoys come
  from").
- **Decoy groups that look like real wallets on chain**, and the on-chain clustering attack they
  would be measured against.
- **Attacks on sync timing, batch pauses, the second stage and which transactions the client
  fetches**, to measure defences that exist and fill the rows marked "None" in the table under A3
  (`docs/02-design.md`).
- **bdk's full-scan-then-sync pattern, as a stretch goal.** Syncing only handed-out addresses between
  full scans saves bandwidth, but the attack harness must first learn to read an address's whole
  pattern of presence across syncs (`docs/02-design.md`, "bdk's full-scan-then-sync pattern,
  deferred").
- **Electrum's subscribe mechanism, as a stretch goal.** It changes how updates arrive, not what the
  server learns up front, and decoys never get notifications of their own (`docs/02-design.md`,
  "Sync scheduling").
- **Protocol compatibility.** Test against a server that offers only Electrum protocol 1.7, which
  replaces the scripthash lookup methods with scriptpubkey ones; `electrum-client` 0.24.1 still calls
  the old methods (`docs/05-prior-art.md`, "Earlier proposals in the Electrum and BDK ecosystem").
- **The cost of append-only growth.** Every new address adds `padding − 1` decoys that are never
  withdrawn, so a long-lived wallet's query only grows. Work out whether it needs a cap, and what
  the cap costs in privacy.
- **Padding and the stop gap.** The gap limit sets how many unused addresses get queried, and every
  one carries `padding − 1` decoys. Measure whether a smaller gap limit at high padding saves
  bandwidth without missing funds.
- **A longer-term PIR replacement**, once it covers address history and not only the UTXO set
  (`docs/05-prior-art.md`, "Private information retrieval").
- **Product patterns for a wallet built on Haystack**, from the Bitcoin Design Guide review: private
  by default before the first sync, since the first sync can't be taken back; an always-visible
  connection badge like Sparrow's; the dial under Settings → Network, matching where the guide puts
  other server choices; a private restore that ships the ledger file with the descriptor; and the
  receive and activity screens this demo leaves out.
- **Paths to wallets people use.** Any BDK wallet directly (`haystack-electrum` matches
  `bdk_electrum`'s `full_scan` signature); mobile through BDK's Kotlin/Swift bindings and example
  apps; an Electrum desktop plugin, which needs a Python port of decoy derivation and a subscription
  design.
