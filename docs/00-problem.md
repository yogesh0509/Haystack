# The problem

Every claim below has a command next to it. Run them. The outputs shown were captured on
2026-09-08 against live infrastructure and a clean checkout of `bdk_wallet` v3.1.0 — the local fork
used for this one-off demonstration, not the version the project builds against. `capture/` and the
planned query engine target the published `bdk_wallet` 2.1.0 instead; see `docs/02-design.md`,
"Which upstream version to copy," for why.

Each section states a claim and gives the command that verifies it, so nothing here needs to be taken
on faith. For how a given script or decoy strategy is implemented mechanically, see
`scripts/README.md`; for the exact BDK code path behind §3, see `docs/bdk-code-path.md`.

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
different operator. There is nothing special about Blockstream's instance.

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
# terminal 2 — point BDK at it by editing examples/electrum.rs:
#   const ELECTRUM_URL: &str = "tcp://127.0.0.1:50001";
cd ~/bdk_wallet && cargo run --example electrum --features test-utils
```

Ctrl-C the honeypot for the summary. A simulated 50-address walk produces:

```
============================================================
scripthash queries received : 50
distinct scripthashes        : 50
elapsed across the burst     : 0.008s

Every one of those belongs to a single wallet, and they
arrived together on one connection. No inference required.

log written to honeypot-log.json
```

The full disclosure took 8ms: one wallet, one connection, one burst, in derivation order. A
chain-analysis firm reconstructing the same cluster from public data alone has to run probabilistic
heuristics over the transaction graph, with a non-trivial error rate. The Electrum sync produces the
same result directly, with no inference required.

To confirm the captured scripthashes are your own addresses, see `docs/bdk-code-path.md` for how to
dump your own derivation and diff it against `honeypot-log.json`.

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
python3 scripts/intersection_sim.py
```

```
real addresses : 70
decoys / round : 630  (10.0x bandwidth)
decoy pool     : 100000
baseline       : plain Electrum sends 70 scripthashes, 0.00 bits

 round |               fresh |       deterministic |             epoch/3 |            monotone
----------------------------------------------------------------------------------------------
     1 |    700 ( 3.32 bits) |    700 ( 3.32 bits) |    700 ( 3.32 bits) |    700 ( 3.32 bits)
     2 |     74 ( 0.08 bits) |    700 ( 3.32 bits) |    700 ( 3.32 bits) |    700 ( 3.32 bits)
     3 |     70 ( 0.00 bits) |    700 ( 3.32 bits) |    700 ( 3.32 bits) |    700 ( 3.32 bits)
     4 |     70 ( 0.00 bits) |    700 ( 3.32 bits) |     74 ( 0.08 bits) |    700 ( 3.32 bits)
     5 |     70 ( 0.00 bits) |    700 ( 3.32 bits) |     74 ( 0.08 bits) |    700 ( 3.32 bits)
     6 |     70 ( 0.00 bits) |    700 ( 3.32 bits) |     74 ( 0.08 bits) |    700 ( 3.32 bits)
```

Read the `fresh` column. Ten-times padding buys **three rounds**, then collapses to exactly the real
set — matching the analytic prediction that expected surviving decoys after `r` rounds is
`k^r / |U|^(r-1)` (`630² / 100000 = 3.97` after round two; observed 4). See `scripts/README.md` for
how each of the four strategies is implemented and why it behaves the way it does.

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
