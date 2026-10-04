# Prior art

Hiding a light client's addresses from the server it asks is an old problem. This document names
the earlier attempts, what they found, and where Haystack differs. Every source below was checked
against the original on 2026-10-03. What this work adds to the plan is in `docs/04-roadmap.md`,
"After the hackathon".

---

## BIP37 bloom filters: the closest precedent

BIP37 was Bitcoin's first attempt at the same goal. A light client sent a probabilistic bloom filter
instead of its address list, and the server returned matching transactions. Gervais, Karame, Gruber
and Capkun, ["On the Privacy Provisions of Bloom Filters in Lightweight Bitcoin Clients"](https://eprint.iacr.org/2014/763)
(ACSAC 2014), showed that a client with fewer than about 20 addresses risks revealing almost all of
them, and that a restart makes it worse: the client builds a fresh filter, and the observer
intersects the old and new ones. Their fix was to keep state rather than rebuild a filter that
overlaps the old one.

That is the failure `python3 -m attack strategies` reproduces with redrawn decoys
(`docs/00-problem.md` §6), and their fix has the same shape as Haystack's: the same decoys every
sync, never withdrawn. It is independent support for the idea, not only the same failure. Haystack
differs in sending real addresses among decoys, with the padding chosen by the user, and in
measuring the result with an attacker rather than reasoning about it.

---

## The deployed alternatives

- **Compact block filters** ([BIP157](https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki)
  and BIP158, also called Neutrino) keep the address set off the server entirely: the client tests
  per-block filters locally and downloads only matching blocks. The server still learns which blocks
  were fetched, so BIP157 says blocks "SHOULD be downloaded from outbound peers at random to mitigate
  privacy loss due to transaction intersection analysis". Wasabi Wallet works this way, and fetches
  each matching block from a random peer over Tor
  ([Wasabi FAQ](https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html)). The costs are filter and block
  downloads, and servers that serve filters. Haystack instead targets the many wallets already built
  on Electrum servers, and needs no change on the server. That is a deployment argument, not a claim
  to be more private.
- **Measuring this family.** Kotzer and Rottenstreich,
  ["Privacy Comparison for Bitcoin Light Client Implementations"](https://eprint.iacr.org/2024/1415)
  (AFT 2024), compare the privacy and bandwidth of SPV and Neutrino clients on real chain data, with
  a "detection ratio" and an entropy measure built to avoid over-crediting uncertainty spread across
  many unlikely addresses. Both could be reported beside Haystack's precision in bits as an outside
  cross-check.
- **Running your own Electrum server** (electrs, Fulcrum) removes the third party altogether, at the
  cost of a full node's hardware, storage and upkeep, which excludes most users and every phone.
- **Tor** hides the network address, not the query. It composes with Haystack and neither replaces
  the other.

---

## Private information retrieval

Private information retrieval lets a client fetch a record without the server learning which one.
Single-server versions need homomorphic encryption; multi-server versions need servers that don't
collude. It is the right long-term answer, and it is expensive:

- Qin, Hadass, Gervais and Reardon,
  ["Applying Private Information Retrieval to Lightweight Bitcoin Clients"](https://arxiv.org/abs/2008.11358)
  (2020), report about 33.5 MB and 4.8 minutes to fetch 100 transactions over a week, against
  12.85 MB for bloom filters on the same workload.
- [Bitcoin-PIR](https://github.com/Bitcoin-PIR/Bitcoin-PIR) covers the UTXO set, not full address
  history, with two-server, single-server and stateful backends. With verification on, it still
  leaks the approximate number of coins at an address it finds, so even working PIR isn't free of
  leaks in practice.
- Matetic et al.,
  ["BITE: Bitcoin Lightweight Client Privacy using Trusted Execution"](https://www.usenix.org/conference/usenixsecurity19/presentation/matetic)
  (USENIX Security 2019), answer from inside a trusted hardware enclave, with side-channel
  protections added because naive enclave processing still leaks.

None of these runs against today's Electrum servers. Haystack is obfuscation with a measured score,
not a cryptographic guarantee.

---

## Earlier proposals in the Electrum and BDK ecosystem

- [BDK issue #176, "More private sync using Electrum"](https://github.com/bitcoindevkit/bdk/issues/176)
  (opened in 2020, still open) asks for a choice between a fast, less private sync and a slower,
  more private one, because "the addresses are checked with the server sequentially, and the server
  could use that information". Haystack builds the private side, with its privacy measured.
- The Electrum protocol's [basics](https://electrum-protocol.readthedocs.io/en/latest/protocol-basics.html)
  say implementations "SHOULD pad messages to bucketed lengths". That pads message *length* against
  someone watching the network. Haystack pads the *set of addresses* against the server itself: a
  different observer and a different leak, and the two combine. The same page says a server "SHOULD
  send a JSON-RPC error with integer code 10001" for an address with too long a history; a chain
  decoy drawn from a busy address would trigger an error a real wallet almost never sees.
- [Electrum issue #5626](https://github.com/spesmilo/electrum/issues/5626) asks for an option not to
  watch old, empty addresses: cheaper, and it risks missing a late payment to one of them.
- Protocol version [1.7](https://electrum-protocol.readthedocs.io/en/latest/protocol-changes.html)
  replaces the scripthash lookup methods with scriptpubkey ones. `electrum-client` 0.24.1, which
  Haystack and `bdk_electrum` both use, still calls the old methods, so a server that offers only
  1.7 would refuse both.
- Silent payments ([BIP352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)) remove
  address reuse, but scanning for them still needs a full node or a server that learns something.
  The Bitcoin Design Guide notes that scanning "doesn't work well with electrum servers"
  ([Silent payments](https://bitcoin.design/guide/how-it-works/silent-payments/)). Sparrow's
  silent-payments server, [Frigate](https://github.com/sparrowwallet/frigate), scans on the server
  with keys held only in memory, so it must be trusted not to keep them: the same kind of problem
  Haystack addresses for ordinary lookups.

---

## Lessons from decoy schemes that failed elsewhere

- **Monero's decoys were told apart by age.** Möser et al.,
  ["An Empirical Analysis of Traceability in the Monero Blockchain"](https://arxiv.org/abs/1704.04299)
  (PoPETs 2018), found the real input is usually the newest one, which identifies it about 80% of the
  time. Their fix was to sample decoys from the real age distribution, or to group outputs from the
  same or neighbouring blocks. Haystack's decoys without history fail the same way for a restored
  wallet: they differ from the funded addresses in one visible property, history. Chain decoys have
  to match real wallets in age and activity, not merely exist on chain.
- **Generated web searches were caught by an ordinary classifier.** Peddinti and Saxena showed that
  TrackMeNot's decoy searches could be separated by off-the-shelf machine learning, with a reported
  48.88% average true-positive rate (PETS 2010, extended as "Web Search Query Privacy: Evaluating
  Query Obfuscation and Anonymizing Networks", *Journal of Computer Security* 2014). A scheme should
  be scored by an attacker that learns, which is why Haystack's structural attacker is trained, and
  a generic classifier as a second baseline is a planned addition.
- **Single queries and whole profiles both need defending.** Balsa, Troncoso and Díaz, "OB-PWS:
  Obfuscation-Based Private Web Search" (IEEE S&P 2012), separate analysis of one query (real or
  dummy?) from analysis of the whole reconstructed profile, and conclude both are needed. Haystack's
  attacks judge one address at a time; scoring the whole wallet, through its linked addresses and
  balance, is planned.
- **Intersection attacks fail only against consistent padding.** Mathewson and Dingledine,
  ["Practical Traffic Analysis: Extending and Resisting Statistical Disclosure"](https://www.freehaven.net/doc/e2e-traffic/e2e-traffic.pdf)
  (PET 2004), found the attack is slowed but still succeeds unless users "pad consistently". That is
  the rule `tests/test_regression.py` enforces.

---

## What is and isn't new

Padding a query with decoys is not new, and neither is knowing that Electrum sync leaks. What
Haystack adds:

- **A calibrated, many-sync score** for Electrum query privacy, with plain Electrum reading 0.00 bits
  by definition, and the attack suite that produces it.
- **The rule that decoys are never withdrawn, with new decoys for every new address**, derived and
  measured, including the result that rotating decoys on a schedule is worse than never rotating.
- **A drop-in client for existing `bdk_wallet` apps** against unmodified public servers, with the
  bandwidth cost of each padding level shown to the user.
