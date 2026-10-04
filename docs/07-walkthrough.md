# Testing every case

This walks through every case Haystack handles, from the leak itself to a restored wallet whose
decoys come from the chain. Each case gives the command, what you should see, and what it means.
The outputs below are real, from actual runs.

Two kinds of wallet appear:

- **The never-paid demo wallet** has a public string as its seed (`capture/` and `haystack-demo`
  derive the same one), so anyone can reproduce it. Nobody may ever send it funds.
- **The paid regtest wallet** comes from `regtest/`. It lives on a private local chain (regtest),
  where blocks are mined on demand and coins are worthless. It receives, reuses an address, spends
  with change, and has unconfirmed transactions. Its first sync through Haystack is exactly a
  *restored* wallet: a fresh wallet whose addresses already have history.

The score in every table is the attacker's **precision**. The attacker guesses as many
scripthashes as the wallet really has, and precision is the share of those guesses that are right.
The `bits` column converts it: 0.00 means every guess was right, and `log2(padding)` (3.32 at padding
10) means the guesses were no better than random. `funded %` is the same precision restricted to the
scripthashes that have history, which are the funded addresses. `docs/03-metric.md` has the full
definitions.

## Before you start

- **The setup in `README.md`** ("Setup", for Linux, macOS or Windows through WSL2): Rust, Python 3,
  a C compiler and OpenSSL's development files. On Windows, `python3` is `py`.
- **An internet connection the first time** you build `regtest/`. The build downloads
  `bitcoind` and `electrs` and checks each against a pinned SHA-256 hash (`regtest/README.md`).
- Run everything from the repository root. Outputs go to `out/`, which git ignores:

```bash
mkdir -p out
cargo build --release -p haystack-capture -p haystack-demo -p haystack-regtest
```

## Case 1: plain Electrum gives the wallet away

**What it shows.** An unmodified `bdk_wallet` scan tells the server exactly which addresses are the
wallet's. The honeypot is a fake Electrum server that answers "nothing found" and logs every query.

```bash
# terminal 1
python3 scripts/honeypot_electrum.py --log out/plain-honeypot.json
# terminal 2
./target/release/haystack-capture --url tcp://127.0.0.1:50001 --out out/plain-truth.json
# terminal 1: press Ctrl-C to write the log, then:
python3 -m attack score --honeypot out/plain-honeypot.json --capture out/plain-truth.json --tier T1
```

**What you should see.** The honeypot receives 100 queries for 100 distinct scripthashes on one
connection. The score is 0.00 bits and 100% precision: every guess is right.

```
  sync  real (|R|)  scripthashes (|Q|)  bits  precision %  chance %  funded bits  funded %
     1         100                 100  0.00       100.00    100.00           --        --
```

**What it means.** The query *is* the wallet. `funded %` reads `--` because this wallet has no funded
addresses.

## Case 2: random decoys fail after a few syncs

**What it shows.** Padding each sync with freshly drawn random decoys is undone by comparing syncs.
Real addresses appear every time and fresh decoys don't.

```bash
python3 -m attack strategies
python3 -m unittest -v tests.test_regression
```

**What you should see.** First a table with one row per sync and one column per decoy strategy
(`fresh`, `epoch/3`, `fixed`) for a 100-address wallet padded 10×. The table and what each column
and cell means are in `docs/00-problem.md` §6. Then three tests, each ending in `ok`: freshly
redrawn decoys fall to at most 0.10 bits by round 3, and fixed decoys stay at 3.32 bits in every
round.

**What it means.** Decoys must be fixed per wallet and never withdrawn. `docs/00-problem.md` §6
explains why.

## Case 3: a new wallet, padded, is fully hidden

**What it shows.** The same never-paid wallet through Haystack at padding 10: nine decoys per real
address, the same decoys every sync.

```bash
# terminal 1
python3 scripts/honeypot_electrum.py --log out/padded-honeypot.json
# terminal 2: the demo wallet, pointed at the honeypot, keeping its files in out/padded-demo
./target/release/haystack-demo --url tcp://127.0.0.1:50001 --data out/padded-demo
# terminal 3, or the "Sync now" button at http://127.0.0.1:7878: three syncs of the Haystack wallet,
# once the demo is up
until curl -s http://127.0.0.1:7878/api/state | grep -q '"ready":true'; do sleep 1; done
for i in 1 2 3; do
  curl -s -X POST -H 'X-Haystack-Demo: 1' -d '{"profile":"haystack"}' http://127.0.0.1:7878/api/sync
  sleep 25
done
# terminal 1: Ctrl-C, then:
python3 -m attack score --session out/padded-demo/tcp___127.0.0.1_50001/haystack/session.jsonl \
    --honeypot out/padded-honeypot.json --tier T1
```

**What you should see.** The honeypot receives 3,000 queries for 1,000 distinct scripthashes. The
score sits at the 3.32-bit ceiling, 10% precision against 10% chance, in every round:

```
  sync  real (|R|)  scripthashes (|Q|)  bits  precision %  chance %  funded bits  funded %
     1         100                1000  3.32        10.00     10.00           --        --
```

`score` first checks the client's session log against the honeypot's own log and refuses if they
differ, so this number is about what the server really received.

**What it means.** A wallet with no history is as hidden as padding 10 allows. Nothing separates its
addresses from decoys, because neither has any transactions.

## Case 4: padding never changes the wallet

**What it shows.** Haystack hides the wallet by asking the server about extra decoy addresses. A
bug in that machinery could quietly change what the wallet believes: drop a transaction, show the
wrong balance, miss a used address, or reuse a stale proof after a reorganisation. A privacy tool
that sometimes shows the wrong balance is worse than none. So these tests run Haystack and plain
`bdk_electrum` against a real Electrum server (electrs) on regtest, and require the two wallets to
end up identical.

"Identical" means a *snapshot* match: the balance, every transaction with the block that confirmed
it, the unspent coins, the highest used address index on each keychain, and the chain tip.

```bash
cargo test -p haystack-regtest -- --nocapture
```

There are two tests.

### Test 1: padded and plain scans end in the same wallet

The paid wallet's history includes address reuse, a payment far out at external 30, spends with
change and two unconfirmed transactions. A plain copy and a Haystack copy (padding 10) of the wallet
each scan, and their snapshots must match after three rounds:

1. **The initial history.** Both reach external index 30 and internal index 1, with 8 transactions,
   2 of them unconfirmed.
2. **A new block and a payment.** The block confirms the two pending transactions, then 0.03 BTC
   arrives at external 60, past the range Haystack first scanned, so it needs a second stage.
3. **A one-block reorganisation.** The chain replaces its newest block, so the transactions in it
   move to the new block. The Haystack client keeps its saved cache of merkle proofs (proofs that a
   transaction is in a block) across rounds, so this also checks that proofs saved for the old block
   are not served for the new one.

The test also checks that every decoy returns no history, so server answers never leak into the
wallet.

### Test 2: a payment dropped from the mempool leaves the balance

An unconfirmed payment can vanish if someone double-spends the same coins with a higher fee
(replace-by-fee). The wallet still remembers it, and the replacement never touches the wallet's
addresses, so the wallet sees no conflict. Only a list of expected transactions reveals the payment
is gone. That is the list `full_scan_expecting` takes.

The node pays the wallet 0.02 BTC unconfirmed, then double-spends it to itself. Upstream's `sync`
and Haystack's `full_scan_expecting` must both drop the payment and agree on the balance. A plain
Haystack scan, which has no expected list, still shows 0.02 BTC pending. That is deliberate: it shows
the gap the list closes.

**What it means.** For these scenarios (fresh history, pending transactions that confirm, a
one-block reorganisation, a restart with saved cache, and a dropped payment), privacy costs
bandwidth, never correctness. The tests use one electrs and one-block reorganisations. They do not
cover deep reorganisations, very large wallets or a hostile server.

## Cases 5 to 8: a paid, restored wallet

These four cases share one set of sessions. The generator gives the paid regtest wallet and 12
other paid wallets a history, then syncs each one twice through Haystack, with a payment between
the two syncs. The 12 other wallets are the **training wallets**: the attacker learns from their
labelled sessions what real addresses and decoys look like, then attacks the demo wallet, which it
never saw. This quick version takes about 2½ minutes:

```bash
cargo run --release -p haystack-regtest --bin sessions -- \
    --out out/sessions --paddings 1,10 --chain-shares 0,0.1
```

It writes one folder per setting, named `p<padding>-c<percent>` (`p1-c0/`, `p10-c0/`, `p10-c10/`).
`regtest/README.md`, under "Training sessions and the bandwidth curve", says what the letters mean.
Running the generator again replaces the whole directory. That is the training set's reset.

**The scores move between runs.** The decoy shuffle is random each time, so the demo wallet's
headline at padding 10 varies by up to about half a bit. What doesn't move is which funded addresses
get exposed. The ranges below come from several runs.

### Case 5: plain sync of a paid wallet

```bash
python3 -m attack score --session out/sessions/p1-c0/demo.jsonl --train out/sessions/p1-c0 --tier T2
```

**What you should see.** 0.00 bits and 100% in both rounds, for all 133 real addresses and for the
funded ones.

**What it means.** This is the paid wallet's version of case 1: balance, history and change, all
handed over. It uses the stronger T2 attacker (case 1 used T1) so it matches cases 6 and 8, and only
the padding differs. With no decoys the attacker has nothing to separate, so T1 prints the same
table. Chance also reads 100%: every query is real, so even a random guess scores 100%.

### Case 6: a restored wallet with decoys that have no history

```bash
python3 -m attack score --session out/sessions/p10-c0/demo.jsonl --train out/sessions/p10-c0 --tier T2
```

**What you should see.** The headline reads about 2.4 to 3.1 bits, but `funded %` reads 100%:

```
  sync  real (|R|)  scripthashes (|Q|)  bits  precision %  chance %  funded bits  funded %
     1         133                1330  2.93        13.08     10.00         0.00    100.00
     2         134                1340  2.42        18.63     10.00         0.00    100.00
```

**What it means.** This is padding 10 on the same wallet as case 5 (`p10-c0`). The headline is good: guessing 133 of 1,330 scripthashes is right 10% of the
time by chance (133 / 1,330), the attacker gets 13.08%, and log2(1 / 0.1308) = 2.93 bits. But the
decoys here never have history, and the server sees every answer, so a scripthash with transactions
must be real. The 8 funded addresses, which hold the balance and the history, are therefore exposed
with certainty (`funded %` 100). The 125 unused addresses look like the decoys and stay hidden, and
they outnumber the funded ones, which is why the headline hides the leak. This is Haystack's main
limitation and the reason the funded column exists.

### Case 7: a payment while the wallet is watched

```bash
python3 -m attack score --session out/sessions/p10-c0/demo.jsonl --tier T1
```

**What you should see.** Round 1 reads 3.32 bits. Round 2, after a payment to the next unused
address, reads 3.24.

**What it means.** An address that goes from no history to some while being queried must be real,
since no decoy is ever paid. The many-rounds attacker marks it as certain. This is accepted as a
limitation (`docs/02-design.md`, A1).

### Case 8: a restored wallet with decoys from the chain

```bash
python3 -m attack score --session out/sessions/p10-c10/demo.jsonl --train out/sessions/p10-c10 --tier T2
```

**What you should see.** `funded %` falls from 100% to somewhere between about 6% and 28%,
depending on the run. Its chance rate is the funded addresses' share of every scripthash with
history: about 8 out of 120, or 7%, now that a tenth of the decoys have history too. One run:

```
  sync  real (|R|)  scripthashes (|Q|)  bits  precision %  chance %  funded bits  funded %
     1         133                1330  2.90        13.41     10.00         3.00     12.50
     2         134                1340  3.32         9.40     10.00         2.17     22.22
```

**What it means, and what it doesn't.** A tenth of the decoys are now real addresses from the chain
that have history, so funded addresses no longer stand out to this attacker. **But this holds only
against a server that ignores its own log.** The client found those decoys by asking the same
server for random transactions and their outputs' histories, which a real wallet never does. A
server that reads that log can cross off every chain decoy and is back at case 6. That attack is
described in `docs/02-design.md` ("Where the chain-sourced pool comes from") and deliberately not
built. You can see the evidence it would use in the session log's `probes`:

```bash
python3 -c "
import json
r = json.loads(open('out/sessions/p10-c10/demo.jsonl').readline())
kept = [p for p in r['probes'] if p['kind'] == 'history' and p['kept']]
chain = {q['sh'] for q in r['queries'] if q['src'] == 'chain'}
print(len(r['probes']), 'lookups;', len(kept), 'candidates kept;',
      len(chain & {p['sh'] for p in kept}), 'of', len(chain), 'chain decoys were looked up first')"
```

From the quick run this printed
`10034 lookups; 110 candidates kept; 110 of 110 chain decoys were looked up first`. Every chain decoy
appears in the lookups before it appears in the query. That match is the attack.
On regtest the result is also optimistic for a second reason: the chain decoys are the other regtest
wallets' addresses, whose histories come from the same assumed tables as the real wallet's.

## Case 9: restarts send exactly the same query

**What it shows.** After a restart, the ledger file reproduces every decoy, chain decoys included.
The saved cache stops the server from seeing refetches that would separate reals from decoys.

```bash
cargo test -p haystack-electrum --test full_scan -- \
    the_ledger_file_carries_every_decoy_across_a_restart \
    chain_decoys_are_frozen_like_any_other \
    a_restart_with_the_saved_cache_refetches_nothing_real_or_decoy
```

**What you should see.** `3 passed`. The first test also lowers the dial from 10 to 5 at the
restart. With the ledger file the set sent is unchanged. Without it, 755 decoys would be withdrawn
at once.

## Case 10: bandwidth against privacy

**What it shows.** What each padding level costs on the wire, next to what it buys. This is the
headline result.

```bash
python3 -m attack curve --dir out/sessions
```

**What you should see**, from the quick run above. The full sweep (`--out out/sessions` with the
default paddings 1, 2, 5, 10 and 20 and chain shares 0, 10% and 30%) takes about 15 minutes.

```
 pad chain    |Q|   KiB r1   KiB r2  x plain |   T1 b   T2 b   T2 % fund b fund % | mean T2 b mean fund %
   1    0%    134    38.24    30.14     1.00 |   0.00   0.00  100.0   0.00  100.0 |      0.00       100.0
  10    0%   1340   259.87   253.42     8.41 |   3.24   2.42   18.6   0.00  100.0 |      2.56       100.0
  10   10%   1340  2176.68   286.63     9.51 |   3.24   3.32    9.4   2.17   22.2 |      2.94        27.6
```

**How to read it.**
- **`KiB r2`** is the second sync, with the saved cache: the steady cost. Padding 10 costs 8.4 times
  a plain sync, and chain decoys 9.5 times.
- **`KiB r1`** is the first sync. With chain decoys it includes the search for them, inflated on
  regtest because most blocks hold only a coinbase, so most lookups miss.
- **The `mean` columns** score every one of the 13 wallets in turn, each with a model fit on the
  other 12. They are steadier than the demo wallet's own row.
- **Bytes** are counted between the client and electrs, without TLS. A public server adds well
  under 1% for TLS on writes this size.

## Optional: a real public server

**What it shows.** The never-paid wallet padded against a public server instead of the honeypot.
This sends the demo wallet's padded query to a third party, so it is opt-in. It was run against
`fortress.qtornado.com` on 2026-10-02 (`docs/04-roadmap.md`, Week 4). The demo pins a server's
certificate on first use, which a self-signed server such as `fortress.qtornado.com` needs. Press
Sync now on the Wallet tab of `http://127.0.0.1:7878`; the Lab tab shows the score and what the
server received.

```bash
cargo run --release -p haystack-demo -- --url ssl://fortress.qtornado.com:50002
python3 -m attack score --session out/demo/ssl___fortress.qtornado.com_50002/haystack/session.jsonl --tier T1
```

## What no case here covers

- **A server that reads its own lookup log** (case 8's caveat): described, not built.
- **On-chain clustering** (`T3`): linking addresses through shared transactions isn't built. Single
  chain decoys share no transactions, while a real wallet's addresses do.
- **Timing across syncs**: the automatic sync timer exists (`schedule.rs`), but no attack reads
  sync times yet.
