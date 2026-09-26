# Threat model

## The adversary

**A malicious or compromised Electrum/Esplora server operator**, who is also willing to correlate
across time and to use public chain data.

This is not a hypothetical. Running a public Electrum server is cheap, the client picks servers from
a list, and there is no reputation system, no attestation, and no way for a wallet to tell a hostile
server from an honest one.

### What the adversary sees, by assumption

- Every scripthash in every query, in arrival order.
- Which queries arrived on the same connection, and therefore belong to the same wallet.
- Timing: when each sync happened, how long the burst took, the interval between syncs.
- The source IP, unless the client is behind Tor.
- All public chain data, and unlimited compute to run standard clustering heuristics over it.
- The wallet software's behaviour, because clients are open source. The adversary knows the gap
  limit, the batch size, the derivation order, and the query cadence.

### What the adversary is assumed *not* to have

- The wallet's xpub or descriptor. (If they have it, no query scheme helps — they can derive
  everything and the game is over before it starts.)
- The ability to break sha256 or forge chain data.
- Control over the user's device.

A scheme can be fine against a weak version of this adversary and useless against a slightly
stronger one, so the analysis tool measures more than one strength of adversary rather than a
single number. What exactly gets varied, and why, is explained in `docs/02-design.md` — it's an
implementation detail of how the attack tool is built, not a separate part of the threat model.

---

## In scope

- Hiding *which* of the queried scripthashes belong to the querying wallet.
- Surviving repeated syncs by the same wallet against the same server.
- Making decoys structurally plausible enough to resist shape-based separation.
- Making the bandwidth cost explicit and adjustable, so a user can choose their point on the curve.
- Quantifying all of the above with a metric calibrated against unmodified Electrum.

## Out of scope

Stated up front rather than discovered by a judge:

- **Network-layer anonymity.** Haystack does not hide your IP. Use Tor; the two compose and neither
  substitutes for the other.
- **On-chain linkability.** If your transactions are linkable on the chain, they remain linkable.
  Haystack addresses the sync channel, not the ledger. Change selection is a separate leak and a
  separate project.
- **A lying server.** A hostile server can already omit transactions or report false balances to any
  client. Haystack neither fixes this nor makes it worse. Detecting it needs a different mechanism
  (multi-server cross-checking).
- **Transaction broadcast.** Broadcasting reveals interest in a transaction. Out of scope here;
  Tor plus broadcasting to a different server than you sync against is the standard mitigation.
- **Wallet fingerprinting by non-query behaviour.** TLS fingerprint, client version strings, timing
  jitter characteristic of a particular implementation. Real, but a different layer.
- **A global adversary.** One that watches many servers and many users at once, plus the network
  itself. Acknowledged as unaddressed.

---

## The security goal, stated precisely

> Given a query set `Q` containing a wallet's real scripthashes `R ⊆ Q`, and given observations of
> that wallet's queries over `n` rounds, an adversary who also knows what a real wallet's address
> set looks like should not be able to identify `R` within `Q` for certain, and its ability to do so
> should degrade gracefully — not catastrophically — as `n` grows.

Two things are deliberately *not* claimed:

**This is obfuscation, not cryptographic privacy.** There is no security reduction here, no hard
problem the adversary must solve. The adversary's advantage is a probability that shrinks with
padding, not a negligible function. Anyone expecting a PIR-style guarantee should read
`docs/05-prior-art.md` for why that path was not taken in a four-week build.

**The bound is empirical.** The score comes from running attacks, not from a proof. That makes the
attack suite the most important artifact in the repo — a weak attack suite produces a flattering,
meaningless score. See `docs/03-metric.md` for how that failure mode is guarded against.