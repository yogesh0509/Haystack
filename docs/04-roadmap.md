# Roadmap

Haystack hides a light wallet's real addresses inside a larger query of decoys, then measures how
well the hiding works by attacking it. This page is the plan it was built to: what each week set out
to do, what was delivered, where the evidence is, and what is still open.

One person built it over four weeks, from 2026-09-08 to the submission deadline on 2026-10-05. Every
item below links to the code or document that backs it, and every number to the command or
measurement it came from.

## Terms used on this page

- A **scripthash** is the hash of an address that an Electrum server is asked about. It identifies
  the address as well as the address itself does (`docs/00-problem.md` §1).
- A **decoy** is a scripthash the wallet queries only to hide its real ones. **Padding** is the
  user's dial: the number of scripthashes sent per real one. Padding 10 sends 9 decoys with each
  real scripthash.
- A **full scan** walks each of the wallet's address chains until 50 unused addresses in a row. A
  **sync**, in `bdk_wallet`'s sense, re-checks only addresses the wallet has already handed out.
- **Precision** is the share of the attacker's best guesses that are really the wallet's.
  **Precision in bits**, the headline score, turns it into bits: 0.00 means every guess was right,
  which is what plain Electrum gives, and 3.32 at padding 10 means the guesses were no better than
  random. **Precision among funded addresses** is the same score restricted to the addresses that
  have transaction history, and it is always printed beside the headline (`docs/03-metric.md`).

## Approach

Two rules shaped the plan.

- **Build the attacker before the defence.** Every privacy number in the project comes from the
  attack suite, so a weak attack would make every later number meaningless. Week 1 is the attacker;
  the decoy scheme comes after.
- **Extend software that already runs.** Haystack is a query layer over `bdk_wallet` and unmodified
  public Electrum servers. It is not a new wallet and not a new server, and an existing `bdk_wallet`
  app adopts it by changing a few lines (Week 2, "Public API").

## Status at a glance

The table compares the five stages of the build; the last column is where to check the claim.

| Week | Goal | Status | Evidence |
|---|---|---|---|
| 0 | Show the leak on live infrastructure | Done | `docs/00-problem.md`, `scripts/` |
| 1 | An attacker and a score calibrated so plain Electrum reads 0.00 | Done | `attack/`, `tests/test_plain_capture.py` |
| 2 | The padded sync client, correct against a real chain | Done 2026-09-29 | `haystack-electrum/`, `regtest/tests/gate.rs` |
| 3 | Decoys with history, the structural attacker on real sessions, the bandwidth curve | Done 2026-10-01 | `python3 -m attack curve`, `docs/07-walkthrough.md` |
| 4 | Demo wallet, certificate policy, writeup | In progress | below |

---

## Week 0: the problem, verified

The goal was to show the leak with commands anyone can run, before building anything.

- `scripts/scripthash.py` shows that a scripthash is a public, unkeyed function of the address.
- `scripts/electrum_probe.py` asks a live public server about any address and gets an answer, with
  no proof of ownership.
- `scripts/honeypot_electrum.py` is a fake Electrum server that logs every query. A real
  `bdk_wallet` scan pointed at it hands over its whole address set, change addresses included, in
  under a second.
- The first design result came from simulation, not reasoning: redrawing decoys every sync is undone
  after about three syncs, and rotating them on a schedule is worse than never rotating. The rule
  that survives is append-only: decoys may be added, never withdrawn. `tests/test_regression.py`
  checks it with the project's own attacker (`docs/00-problem.md` §6).

## Week 1: the attacker

The goal was an attacker strong enough that a good score means something, and a score that reads
exactly 0.00 for plain Electrum.

- [x] **One belief, many attacks.** Every attack contributes evidence to a single Bayesian belief
      about which scripthashes are real, and every metric is read off that belief
      (`attack/scoring.py`, `attack/posterior.py`). The exact computation stays cheap at real sizes,
      and `tests/test_posterior.py` checks it against brute force on 300 random cases.
- [x] **The many-rounds attack** (`attack/a1_many_rounds.py`) compares syncs. A scripthash that disappears from a
      later sync must be a decoy, because a wallet never stops watching its own addresses. One that
      goes from no history to some while watched must be real, because nobody pays a decoy.
- [x] **The structural attack** (`attack/a2_structural.py`) learns how real and decoy scripthashes differ in
      transaction count, script type and position in the query, without needing repeated syncs.
- [x] **The metric** (`docs/03-metric.md`): precision in bits as the headline, with the same
      precision among funded addresses beside it. Six candidate metrics were measured and dropped,
      and the reasons are recorded there.
- [x] **Regression guard** (`tests/test_regression.py`): known-broken decoy schemes must always score
      near zero, so the metric cannot quietly start praising them.

**End-of-week-1 check, passing.** `tests/test_plain_capture.py` runs the attacker against real
captured honeypot sessions and reads 0.00 bits for plain Electrum; `tests/test_regression.py` reads
near zero for freshly redrawn decoys.

## Week 2: the padded sync client

The goal was a client that sends the padded query and leaves the wallet exactly as a plain sync
would.

- [x] **A sibling crate, not a fork.** `haystack-electrum` reimplements `bdk_electrum`'s full scan on
      the same public interfaces (`electrum_client::ElectrumApi`, `bdk_core::spk_client`), targeting
      `bdk_wallet` 2.1.0. Its response plugs into `wallet.apply_update()` unchanged
      (`docs/02-design.md`, "haystack-electrum").
- [x] **Public API.** `HaystackElectrumClient::new(inner_client, decoy_key, padding)` stands in for
      `BdkElectrumClient::new(inner_client)`, and `full_scan` keeps upstream's signature. An app
      adopting Haystack makes five kinds of change, and the demo wallet (Week 4) is held to exactly
      these. The first four were set in Week 2; Week 4 added the fifth:
      1. the client construction line, which also takes the decoy key, the dial, the ledger file
         and the saved cache file;
      2. each `sync` call becomes a full scan, because a sync of handed-out addresses only would
         drop the unused addresses and their decoys from the query, which exposes them;
      3. transactions are broadcast through a different server than the one the wallet syncs with,
         so the broadcast isn't tied to the sync session;
      4. the transaction cache is never pre-filled from the wallet's own transactions, because a
         cache holding only real transactions makes a restarted client refetch the decoys' alone;
      5. each scan also passes the wallet's expected unconfirmed transactions
         (`full_scan_expecting(wallet.start_full_scan(), wallet.start_sync_with_revealed_spks(), …)`),
         because a full scan alone can't tell when one has left the mempool (Week 4).

      The crate has no `sync` and no `transaction_broadcast`, so an app that still calls either
      fails to compile instead of silently sending an unpadded query.
- [x] **Deterministic decoys** (`haystack-electrum/src/decoy.rs`, `key.rs`). Decoy `j` of an address
      is a script of the same type, filled from `HMAC-SHA256(key, keychain ‖ index ‖ j)`, where the
      key is a tagged hash of the wallet's public keys. The same wallet always produces the same
      decoys, on any device, which is what defeats the many-rounds attack.
- [x] **Append-only, padded per increment** (`ledger.rs`). Each address's decoy count is frozen the
      first time it is queried and recorded before anything is sent. A newly used address arrives
      with its own `padding − 1` new decoys in the same sync.
- [x] **The ledger file is the backup** (`ledger_file.rs`, format `haystack-ledger/1`). The key can
      be rebuilt from the wallet, but the frozen counts can't. Without the file, a restore that
      lowers the dial from 10 to 5 withdraws 755 decoys in one sync on the test wallet; with it, the
      query is unchanged. The whole file is under 300 bytes for the demo wallet.
- [x] **Session log** (`session.rs`, format `haystack-session/1`). The client records every query in
      send order, whether it was real, and the server's answer. `python3 -m attack score` checks it
      query for query against the server's own log before scoring.
- [x] **Order and batching.** Reals and decoys are shuffled together and sent in batches of five
      real addresses' worth, the ratio `bdk_wallet`'s own example uses (Week 4 made the batch size
      count real addresses, so the dial scales it). Timing is drawn from an exponential delay
      (`schedule.rs`, `docs/02-design.md`, "Sync scheduling").
- [x] **Correctness gate on a real chain** (`regtest/tests/gate.rs`). `bitcoind` and `electrs` run on
      a private regtest chain, and a wallet gets a real history: receives, address reuse, a batched
      payout, a spend with change, unconfirmed transactions, and a one-block reorganisation. After
      every round, upstream `bdk_electrum` and Haystack at padding 10 must leave the wallet with the
      same balance, transactions, confirmation blocks, unspent coins and chain tip. One difference
      is by design: Haystack can query a few more addresses than a plain scan, never fewer.
- [x] **A real public server.** The never-paid demo wallet, padded 10 times, synced against
      `electrum.blockstream.info`: every one of 1,000 answers arrived, and the session log matched
      the wallet's record. A padded sync took 9.3 s against 6.9 s for a plain one, about 1.35 times
      as long, with one sample per setting. A second server, `fortress.qtornado.com`, refused the
      connection because of its old certificate; that led to Week 4's certificate policy.

## Week 3: decoys with history, and the headline curve

The goal was the hard part: a wallet whose own addresses already have history, as after a restore.
Week 2's decoys never have history, so against them every address with history is exposed.

- [x] **The structural attacker on real sessions** (option B: train on labelled sessions of other
      wallets, rather than on synthetic ones). `cargo run --release -p haystack-regtest --bin
      sessions` gives 12 training wallets random histories on the regtest chain and syncs them,
      plus the demo wallet, at padding 1, 2, 5, 10 and 20. The training wallets' histories come from
      assumed tables, stated in one place (`regtest/src/population.rs`) and copied into every run.
- [x] **Three safeguards on the training data.**
      1. **Provenance.** Every session line records the client build that wrote it, as a version
         and a hash of its source (`haystack-electrum/build.rs`). The attacker refuses to score a
         session with a model trained on another build's sessions.
      2. **No training on the answer.** A training session that shares any real address with the
         scored session is refused, and so is one recorded at another padding or chain share.
      3. **Reset.** The generator deletes its output before writing, so one command rebuilds the
         training set from the current client. The model is never saved.
- [x] **Decoys taken from the chain** (`haystack-electrum/src/chain.rs`, off by default). A chosen
      share of each address's decoys are real addresses from past blocks, so they have history.
      They are stored in the ledger (`haystack-ledger/2`), because the chain can't reproduce the
      choice. They are found through the sync server itself, which lets that server name every one
      of them from its own log of the lookups. That attack is written up in `docs/02-design.md`
      ("Where decoys come from") and deliberately not built, so every score with chain decoys is
      against a server that ignores its own log.
- [x] **A saved cache shared by reals and decoys** (`cache_file.rs`). Without it, a restarted client
      refetches decoy transactions only, which shows the server which addresses are real.
- [x] **Bandwidth, measured.** A byte-counting relay sits between the client and `electrs`
      (`regtest/src/proxy.rs`). The demo wallet's steady-state sync took 30.2 KiB plain and 253.5 KiB
      at padding 10, 8.4 times as much for 10 times the scripthashes.
- [x] **The bandwidth-versus-score curve** (`python3 -m attack curve`), the headline result. At
      padding 10, averaged over 13 wallets: the headline reads 2.75 bits, but precision among funded
      addresses is 100% when every decoy is HMAC-derived. With 10% of decoys from the chain, funded
      precision falls to 25.8%, against a server that ignores its own log. A rerun on 2026-10-02,
      after Week 4's client changes, read 2.70 bits, 100% and 28.8%: the shuffle is random each run,
      so these move by a few points, and which funded addresses are exposed does not.
- [x] **The implementation's own fingerprint.** With history hidden, a model trained on order and
      batching alone stays within about 2.5 points of chance.

`docs/07-walkthrough.md` runs every one of these cases with real outputs.

## Week 4: demo and writeup (in progress, 2026-10-02 to 2026-10-05)

The goal is a demo wallet that shows the dial, the live score and the bandwidth it costs, built
with the same wallet code as `bdk_wallet`'s own Electrum example.

- [x] **Batch size counts real addresses.** `full_scan`'s `batch_size` now means real addresses'
      worth per write, so the 5 that `bdk_wallet`'s example passes sends 5 scripts per write when
      plain and 50 at padding 10. Without this, the example's 5 would split a padded sync into 200
      writes instead of 20, which measured 64.1 s against 9.3 s on Blockstream's server in Week 2,
      and fixing it in the app would have been one more kind of change.
- [x] **Missed syncs are skipped, not fired late** (`haystack-electrum/src/schedule.rs`). A sync that
      came due while the app couldn't run is not fired when the app returns, because that would tie
      the sync to the moment the user looked. A fresh delay is drawn instead. Because the delay is
      memoryless, the next sync is as likely within 5 minutes of the app returning,
      1 − e^(−5/30) ≈ 15.4% at a 30-minute mean, as in any other 5-minute window.
- [x] **Sync timer defaults.** The product default mean is 30 minutes: 48 syncs a day, about 11.9
      MiB a day at padding 10 using Week 3's 253.5 KiB per sync, with a balance 30 minutes old on
      average and older than an hour 13.5% of the time. The demo runs with a 2-minute mean so that
      automatic syncs happen during a presentation, and says so on screen.
- [x] **Demo wallet web page** (`demo/`, `cargo run --release -p haystack-demo -- --regtest
      --mean-minutes 2`, then `http://127.0.0.1:7878`). Two copies of one wallet sync side by side
      against the same server: plain, allowed only against a local server, and Haystack at the
      dial. After every sync the repo's attacker scores each copy's session log, and the page shows
      precision in bits with the funded column beside it, the bytes the sync took, and the caveat
      about what the attacker is assumed to know. On the paid regtest wallet's first sync, plain
      took 37.9 KiB and read 0.00 bits; padding 10 took 259.6 KiB and read 3.32 bits from the
      many-rounds attacker, with funded precision 100%, the restored-wallet exposure below.
- [x] **Mempool evictions detected, as by upstream's `sync`.** A full scan, upstream's or Haystack's,
      can't tell when an unconfirmed transaction has left the mempool: only `sync` carries the
      wallet's list of expected transactions, and only that list can show a payment is gone when
      its replacement never touches the wallet. `full_scan_expecting` takes the same list, from
      `wallet.start_sync_with_revealed_spks()`, and marks an expected transaction missing from its
      address's history as evicted, with upstream's rule. Nothing extra is sent. The cost is the
      fifth kind of change above. `regtest/tests/eviction.rs` checks it on the regtest chain:
      the node pays the wallet 0.02 BTC unconfirmed, then double-spends the same coins to itself.
      Upstream's sync and Haystack at padding 10 both drop the 0.02 and end with the same balance,
      while a plain Haystack full scan keeps counting it.
- [x] **Demo wallet code held to the five kinds of change** over `bdk_wallet`'s
      `examples/electrum.rs`, the 3.1.0 release's copy, which compiles unchanged against the 2.1.0
      this project builds on (`demo/src/wallet.rs`; `demo/README.md` lists every line of the example
      against the demo's).
- [x] **The automatic sync loop**, on the timer above, plus a manual sync whose timing the page says
      is visible to the server. A due time that falls during a manual sync is skipped and redrawn.
- [x] **Server certificate policy** (`demo/src/transport.rs`): a self-signed certificate is trusted
      on first use and pinned, a different one is refused afterwards, and a server first seen with
      an authority-signed certificate that later presents a self-signed one is refused too. A
      survey of Electrum's public server list on 2026-10-02 found 37 servers reachable: 12 with
      authority-signed certificates, 18 self-signed with version 3 certificates, and 7 self-signed
      with old version 1 certificates. The connection uses OpenSSL, because rustls checks
      handshake signatures through webpki, which accepts only version 3.
- [x] **A second public server.** The never-paid demo wallet at padding 10 against
      `fortress.qtornado.com:50002`, the server that refused in Week 2: its version 1 certificate
      was pinned on first use, and all 1,000 scripthashes were answered in 25.6 s, 196.3 KiB on
      the wire with TLS included. One sample. This server, like other ElectrumX servers, refuses
      every request until the client sends Electrum's `server.version` greeting, which
      `electrum-client` never sends, so the demo sends it with an empty client name.
- [x] **Restore path.** The restore set is the descriptor plus the ledger file, both shown on the
      page. On regtest, a restore with the ledger sent the same query as before. A restore without
      it at padding 5, after syncs at 10 and 20, sent 670 scripthashes instead of 1,350, and the
      many-rounds attacker's headline fell to 2.23 bits, because every withdrawn decoy marks itself
      as a decoy. The page asks which dial the wallet used before restoring without the ledger.
- [ ] **Reproducible end-to-end demo**: plain and padded syncs with the attacker's output side by
      side, covering every case in `docs/07-walkthrough.md`.
- [ ] **Writeup**: the algorithm on one page, the attack suite, the curve, the limitations, and the
      prior work it builds on. Precision in bits is the headline, with precision among funded
      addresses beside it, and the first paragraph states the restored-wallet limitation below.
- [ ] **README and a clean clone**: the five-minute verification path and the demo work from a fresh
      clone on WSL (Ubuntu 24.04), the environment the project was built and tested on.

## Known limitations

These are measured or stated, not hidden.

- **A restored wallet's funded addresses are exposed without chain decoys.** HMAC-derived decoys
  never have history, so every scripthash with history is real: precision among funded addresses
  reads 100%.
- **Chain decoys only help against a server that ignores its own log.** They are found through the
  sync server, which can match its lookups against later queries and remove every chain decoy.
- **A payment while the wallet is watched exposes the paid address.** An address that goes from no
  history to some must be real, since no decoy is ever paid (`docs/07-walkthrough.md`, case 7).
- **Evictions need the fifth change.** An app that calls plain `full_scan` instead of
  `full_scan_expecting` never learns that an unconfirmed payment left the mempool, as with
  upstream's own `full_scan`. An expected address the scan doesn't reach is left alone, too.
- **Some attacks the server could run aren't built**: linking addresses through shared
  transactions on chain, sync timing, batch boundaries, and which transactions the client fetches
  (`docs/02-design.md`, "One sync on the wire").
- **The training wallets' histories are assumed**, not measured from real wallets, and the
  regtest chain is small. Scores on mainnet could differ.
- **This is obfuscation, not cryptography.** The privacy bound is empirical: it holds against the
  attacks in this repo, and an attack nobody wrote doesn't show up in the score
  (`docs/01-threat-model.md`).

## What this project chose not to build

- **Private information retrieval** answers this problem properly: the server never learns which
  record was asked for. It needs either heavy homomorphic encryption on one server, or several
  servers that don't collude, and neither fits a four-week build or today's Electrum servers.
- **Compact block filters** (BIP157/158) keep the address set off the server entirely, at the cost
  of downloading filters and matching blocks. Haystack instead targets wallets already built on
  Electrum servers, and needs no change on the server side.

## After the hackathon

Planned once all four weeks' items are done and tested:

- **An independent lookup server for chain decoys**, so the sync server can't name them from its own
  log, together with the threat-model assumption it needs (`docs/02-design.md`, "Where decoys come
  from").
- **Decoy groups that look like real wallets on chain**, and the on-chain clustering attack they
  would be measured against.
- **Attacks on sync timing and on which transactions the client fetches.**
- **bdk's full-scan-then-sync pattern, as a stretch goal.** Syncing only handed-out addresses between
  full scans saves bandwidth, but the attack harness must first learn to read an address's whole
  pattern of presence across syncs, or it scores that pattern wrongly (`docs/02-design.md`,
  "haystack-electrum").
- **Electrum's subscribe mechanism, as a stretch goal.** It changes how updates arrive, not what the
  server learns up front, and a decoy never gets a notification of its own, so the client would
  have to fake follow-up traffic per decoy (`docs/02-design.md`, "Sync scheduling").
- **Protocol compatibility.** Test against a server that offers only Electrum protocol 1.7, which
  replaces the scripthash lookup methods with scriptpubkey ones; `electrum-client` 0.24.1 still calls
  the old methods (`docs/05-prior-art.md`).
- **Attacks borrowed from decoy schemes that failed elsewhere** (`docs/05-prior-art.md`, "Lessons
  from decoy schemes that failed elsewhere"): a generic machine-learning classifier as a baseline
  attacker, a whole-wallet score over linked addresses and balance, an age/activity test for chain
  decoys, and a check for decoys that trip the server's error for an overly busy address.
- **Decoy sampling that matches real wallets, not just exists on chain.** Draw chain decoys from the
  age and activity distribution real wallets show, or bin them with a real position by block height,
  following Möser et al.'s fix for the same problem in Monero (`docs/05-prior-art.md`).
- **Server request limits as a bandwidth ceiling, not just a byte count.** ElectrumX prices each
  scripthash lookup at about 1.0 and throttles a session once its total cost passes 1,000 by default;
  one padding-10 sync of the demo wallet (1,330 lookups) already passes that point, and a padding-20
  sync of a 400-address wallet (8,000) approaches its 10,000 disconnect point. Fulcrum caps a
  JSON-RPC batch at 345 requests, above the demo's current 100. Needs measuring against a real
  server, not assumed.
- **A longer-term PIR replacement**, once it covers address history and not only the UTXO set
  (`docs/05-prior-art.md`, "The academically correct answer").
- **Product patterns for a wallet built on Haystack**, from the Bitcoin Design Guide review: private
  by default before the first sync, since the first sync can't be taken back; an always-visible
  connection badge like Sparrow's; the dial under Settings → Network, matching where the guide puts
  other server choices; a private restore that ships the ledger file with the descriptor; and the
  receive and activity screens this demo leaves out.
- **Paths to wallets people use.** Any BDK wallet directly (`haystack-electrum` matches
  `bdk_electrum`'s `full_scan` signature); mobile through BDK's Kotlin/Swift bindings and example
  apps; an Electrum desktop plugin, which needs a Python port of decoy derivation and a subscription
  design.
