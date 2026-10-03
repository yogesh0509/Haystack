# The problem

Every claim below has a command next to it. Run them. The outputs in §1 and §2 were captured
against live infrastructure. The output in §4 was regenerated with `capture/`, which runs real scans
with the published `bdk_wallet` 2.1.0 the project builds against. The results in §6 are checked by
`tests/test_regression.py`, which runs the project's own attacker.

Each section states a claim and gives the command that verifies it, so nothing here needs to be taken
on faith. For how each script works, see `scripts/README.md`; the decoy strategies of §6 are `pad()`
in `tests/synthetic.py`.

---

## 0. What a light wallet is forced to do

A descriptor wallet derives addresses deterministically from an xpub — receiving addresses at
`.../0/*`, change at `.../1/*`. It has no idea which of those have been used until it asks somebody.

So on sync it derives addresses up to a **gap limit** (the number of consecutive unused addresses it
will tolerate before deciding it has found the end), converts each to a **scripthash**, and asks a
server for the history of each one.

That is the entire mechanism, and every leak below follows from it.

---

## 1. The scripthash transform is not privacy

Electrum servers do not receive addresses. They receive `sha256(scriptPubKey)`, byte-reversed. It is
easy to assume this hashing provides some protection. It provides none: the function is public,
unkeyed, and deterministic, so anyone can precompute scripthashes for every address they care about
and invert it by lookup.

```bash
python3 scripts/scripthash.py 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
```

```
input:        1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
scriptPubKey: 76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac
sha256:       6191c3b590bfcfa0475e877c302da1e323497acf3b42c08d8fa28e364edf018b
scripthash:   8b01df4e368ea28f8dc0423bcf7a4923e3a12d307c875e47a0cfbf90b5c39161
```

Works for segwit too — this input is the BIP173 test vector, so the `scriptPubKey` line is
independently checkable against the BIP:

```bash
python3 scripts/scripthash.py bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
```

```
scriptPubKey: 0014751e76e8199196d454941c45d1b3a323f1433bd6
scripthash:   9623df75239b5daa7f5f03042d325b51498c4bb7059c7748b17049bf96f73888
```

**Takeaway.** "The server only sees hashes" is not a mitigation. Treat a scripthash as an address.

---

## 2. A public server will answer anything, for anyone, with no questions

```bash
python3 scripts/electrum_probe.py --address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
```

```
server:     electrum.blockstream.info:50002  ['electrs-esplora 0.4.1', '1.4']
querying:   1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
scripthash: 8b01df4e368ea28f8dc0423bcf7a4923e3a12d307c875e47a0cfbf90b5c39161

balance:    5743396974 sat confirmed  (57.43396974 BTC)
            3672 sat unconfirmed
history:    65711 entries
              height    123723  3387418aaddb4927209c5032f515aa442a6587d6e54677f08a03b8fa7789e688
              height    127280  4574958d135e66a53abf9c61950aba340e9e140be50efeea9456aa9f92bf40b5
              ...
```

Try a quieter address to see a normal-looking response:

```bash
python3 scripts/electrum_probe.py --address bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
# history: 172 entries, utxos: 0
```

You can swap servers with `--server fortress.qtornado.com:50002` and get the same result from a
different operator. There is nothing special about Blockstream's instance. The probe switches
certificate checks off (`ssl.CERT_NONE`), because many Electrum servers use self-signed
certificates; the Rust client's certificate policy is in `docs/04-roadmap.md`, Week 4.

---

## 4. Acting as the server

`scripts/honeypot_electrum.py` is a fake Electrum server that answers "nothing found" to every query
and logs every scripthash it was asked about. Running it makes the disclosure directly observable.

Because it never reports a used address, the wallet never finds the end of its keychains, so it
walks the **entire** gap limit on both — and hands you its complete address set in one burst.

```bash
# terminal 1
python3 scripts/honeypot_electrum.py
```

```bash
# terminal 2 — a real bdk_wallet full scan of a public demo wallet, pointed at the honeypot
cargo build --release -p haystack-capture
./target/release/haystack-capture --url tcp://127.0.0.1:50001 --out capture-truth.json
```

Ctrl-C the honeypot for the summary. One scan of the demo wallet produces:

```
============================================================
scripthash queries received : 100
distinct scripthashes        : 100
connections (sync rounds)    : 1
elapsed across the burst     : 0.847s

Every one of those belongs to a single wallet, and they
arrived together on one connection. No inference required.

log written to honeypot-log.json
```

The full disclosure took under a second: one wallet, one connection, one burst, in derivation order.
A chain-analysis firm reconstructing the same cluster from public data alone has to run
probabilistic heuristics over the transaction graph, with a non-trivial error rate. The Electrum
sync produces the same result directly, with no inference required.

**Change is labelled too.** `bdk_electrum` scans the external keychain to its end before it starts
the internal one (`full_scan`'s loop over keychains, 0.23.2 `bdk_electrum_client.rs:132`), and the
internal keychain is where change goes. So the first 50 scripthashes the server received are receive
addresses 0–49, and the last 50 are change addresses 0–49 — labelled by order alone, where
chain analysis would normally have to guess which output of a transaction is the change.

To confirm the captured scripthashes are the wallet's own: `capture/` records what the wallet itself
sent, independently of any server, and `tests/test_plain_capture.py` checks the two against each
other on the committed copy of this scan (`tests/fixtures/`). They match exactly: the same 100
scripthashes in every round, none extra and none missing.

**Note on the lie.** The honeypot always answers empty so the scan runs to completion in one clean
burst — a measurement convenience, not the threat being modeled. A real server can't lie wholesale
without the user noticing a wrong balance (see `docs/01-threat-model.md`, "out of scope: a lying
server"). The leak this demo shows — full keychain disclosure, change labeling, future-address
prediction (§5) — is identical against a fully honest server that just logs and correlates what it's
asked.

---

## 5. Unused addresses leak too

The gap limit forces the wallet to ask about addresses that have **never received anything** — that
is the only way it can conclude there is nothing more to find. With `STOP_GAP = 50`, a wallet with
8 used addresses still queries dozens of empty ones.

The honeypot proves this directly: it returns empty for everything, and the wallet keeps asking
anyway.

This is not merely extra disclosure. The server learns **where you will be paid next, before you are
paid**: it holds your future receiving addresses and can watch for deposits to them in advance.
Derivation is sequential and now known, so the prediction extends indefinitely.

---

## 6. Why the obvious fix does not work

The intuitive countermeasure is to pad the query with random decoys and re-randomise each sync. That
is worse than useless, and this is the most important result in the repo.

Your real addresses appear in **every** round. Independently sampled decoys appear in one. So a
server that watches you sync a few times intersects the query sets and what survives is your wallet.

```bash
python3 -m unittest -v tests.test_regression
```

The test pads a 100-address wallet at 10× (900 decoys a round, drawn from a pool of 100,000) under
three decoy strategies and runs the many-rounds attacker (`attack/a1_many_rounds.py`), the same one every score
in this repo comes from. It scores each round in precision bits, the headline metric of
`docs/03-metric.md`: `log2(10) = 3.32` bits means the attacker does no better than chance, and `0.00`
means it has found the wallet. Over five random draws, it asserts:

- **`fresh`** redraws every decoy each round. It reads 3.32 bits in round 1 and at most 0.10 bits from
  round 3 on.
- **`epoch/3`** keeps decoys for three rounds, then redraws. It reads 3.32 bits through round 3 and
  at most 0.25 bits in round 4, the first round of the second epoch.
- **`fixed`** sends the same decoys forever. It reads 3.32 bits in every round.

Append-only — adding decoys for new addresses, never withdrawing one — is identical to `fixed` for a
wallet that isn't growing. For a wallet that is, `tests/test_a1.py` checks that a new address padded
with its own decoys stays at the 10% chance rate, and one added without them is exposed.

Ten-times padding with fresh decoys buys **three rounds**, then collapses to exactly the real set.
That matches the analytic prediction. A decoy survives round `r` only if it was drawn every time, so
the expected survivors after `r` rounds are `k^r / |U|^(r-1)` for `k` decoys a round from a pool of
`|U|`. After round two that is `900² / 100000 = 8.1` decoys left among the 100 reals, so precision is
about `100 / 108.1 = 92.5%`, or `-log2(0.925) = 0.11` bits. After round three it is
`900³ / 100000² = 0.07` decoys: almost always none, which is the 0.00 bits the test sees. These
numbers assume decoys are otherwise indistinguishable from real addresses, so they are an upper bound
on what a strategy can deliver, not a measurement of it.

Three conclusions shape the rest of the design, each the opposite of the naive instinct:

1. **Decoys must be deterministic per wallet.** Less randomness, more privacy.
2. **Scheduled rotation is actively harmful** — worse than never rotating at all, not a middle
   ground.
3. **The workable invariant is append-only.** Grow the decoy set to cover new addresses over time,
   but never withdraw one, so the intersection can never fall below the round-zero set.

Point 3 has a sharp corollary that shapes the whole design: an address first queried at round *t* is
absent from the intersection over rounds `1..t`, so intersection does not catch it — but the
adversary can instead examine each round's **delta**. Newly revealed real addresses are protected
only by the decoys added in the same delta. **Every increment needs its own padding ratio**, not
just the initial set.

---

## 7. What people do today, and why none of it is enough

**Run your own node.** The genuine fix. Also a machine, hundreds of gigabytes, and ongoing uptime —
which rules out essentially all mobile users. This is exactly the expert-only configuration the
Cypherpunk track is complaining about.

**Use Tor.** Hides your IP. The server still receives the complete labelled cluster; it just does
not know what city you are in. Necessary, nowhere near sufficient, and orthogonal to this project.

**Trust a no-logs server.** An unverifiable promise. The operator's stated policy is not a technical
constraint, and you cannot audit their retention.

**Compact block filters (BIP157/158).** The honest protocol-level answer: the server ships filters,
the client tests them locally and downloads only matching blocks. Much better privacy, but the
bandwidth is punishing on mobile, sync is slow, support is patchy, and the server still learns which
blocks you fetched.

The gap Haystack targets sits between "run a full node" (private, expensive, excludes everyone) and
"query Electrum" (cheap, zero privacy). Almost nothing lives there.

---

## 8. What an operator ends up holding

After a handful of syncs, a malicious or compromised server operator holds, for any wallet that used
it: the full address cluster labelled as one wallet, the accumulated balance and complete payment
history with timestamps, the change keychain, the next unused receiving addresses, and — absent
Tor — a source IP per session, which across multiple sync locations becomes a movement pattern.

That data has three realistic destinations: sale to an analytics firm and correlation against
exchange KYC on the next deposit, which attaches a legal identity to the cluster; exposure in a
breach; or direct use by anyone with server access who wants to know who holds how much, where, and
when they are online.

Physical attacks on bitcoin holders are a documented risk category. The sync protocol produces a
targeting list as a side effect of a wallet checking its own balance, without any on-chain analysis.
