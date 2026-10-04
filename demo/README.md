# demo/

The demo wallet: `bdk_wallet`'s own Electrum example with Haystack swapped in, behind a local web
page with two tabs. **Wallet** is the Haystack wallet as a user would see it: balance, a privacy
badge, what the attacker learned, the padding dial and what each setting costs. **Lab** is the
evidence: the plain and Haystack copies side by side, the attacker's scores, and a picture of what
the server received.

Two copies of one wallet sync against the same server. **Plain** sends exactly the wallet's
addresses, as every Electrum wallet does today, and runs only against a local server, because it is
the leak itself. **Haystack** hides them among decoys at the dial's setting. After every sync the
repository's own attacker (`python3 -m attack score`) reads that copy's session log and tries to
pick out the real addresses.

The page is served by the wallet process on `127.0.0.1` only. The Rust process holds the
descriptors, talks to the Electrum server and writes the ledger; the page only draws the screen.

## Running it

Set up as in the root `README.md`, "Setup" (Linux, macOS, or Windows through WSL2). The TLS code
links the system OpenSSL, which that setup installs.

```bash
# A private regtest chain with a paid wallet. --mean-minutes 2 is demo speed; see below.
cargo run --release -p haystack-demo -- --regtest --mean-minutes 2
# then open http://127.0.0.1:7878 (http://127.0.0.1:7878/#lab opens the Lab tab)

# Optional: the structural attacker (T2) needs a training set from the same client build, about
# 15 minutes. Until it exists, the page scores with the many-rounds attacker (T1) alone.
cargo run --release -p haystack-regtest --bin sessions -- --out out/sessions
```

For a recording, open the page as an app window, without tabs or an address bar. From WSL:
`cmd.exe /c start msedge --app=http://127.0.0.1:7878`. Chrome takes the same `--app=` flag.

Other servers:

```bash
# The never-paid public-seed wallet against the honeypot (run scripts/honeypot_electrum.py first).
cargo run --release -p haystack-demo -- --url tcp://127.0.0.1:50001
# The same wallet against a public server, padded only. Its certificate is pinned on first use.
cargo run --release -p haystack-demo -- --url ssl://fortress.qtornado.com:50002
```

| Flag | Default | Meaning |
|---|---|---|
| `--regtest` | off | Start `bitcoind` and `electrs` on a private chain, give the paid demo wallet its history, and give 12 other wallets theirs, the same population `regtest/`'s session generator builds, so chain decoys have candidates. |
| `--url` | none | Sync the never-paid demo wallet against `tcp://host:port` or `ssl://host:port` instead. |
| `--mean-minutes` | `30` | The automatic sync's mean delay. 30 minutes is the product default (`SyncTimer`'s `DEFAULT_MEAN`). |
| `--padding` | `10` | The dial's starting value: 2, 5, 10 or 20, the settings the structural attacker is trained at. |
| `--train` | `out/sessions` | Where the training set lives. |
| `--data` | `out/demo` | Wallet databases, ledgers, caches, session logs, and `pins.json`. The regtest folder is wiped at each start, because the chain is new. |
| `--port` | `7878` | The page's port on `127.0.0.1`. |

### The automatic sync's mean delay: 2 minutes for the demo, 30 in the product

The automatic sync waits an exponential delay with the configured mean, drawn the moment the last
sync finished. The product default is **30 minutes**: 48 syncs a day, about 11.9 MiB a day at
padding 10 using Week 3's measured 253.5 KiB per steady-state sync, with a balance that is 30
minutes old on average and older than an hour 13.5% of the time (`docs/02-design.md`, "Sync
scheduling"). A presentation runs with `--mean-minutes 2` so automatic syncs happen while people
watch, and the page says when it runs at demo speed. Leave the flag out to run at the default.

A sync that came due while the process couldn't run is skipped and redrawn from that moment, never
fired late. The same happens when it comes due during a manual sync.

## The wallet code and the five allowed changes

`src/wallet.rs` is the wallet-handling code. It keeps `examples/electrum.rs` from `bdk_wallet` 3.1.0,
which compiles unchanged against the 2.1.0 this repo builds on, except for the five kinds of change
the roadmap allows (`docs/04-roadmap.md`, Week 2, "Public API"). The table lists every line of the
example the demo uses, and how each one appears in `src/wallet.rs`.

| Example line | What it does | In the demo |
|---|---|---|
| 16–17 | `STOP_GAP = 50`, `BATCH_SIZE = 5` | Unchanged. `BATCH_SIZE` counts real addresses' worth per write, so at padding 10 a write carries 50 scripts. |
| 19–23 | Database path, network, descriptors, server URL | Given at run time, because the demo has two wallets and several servers. |
| 26–38 | `Connection::open`, `Wallet::load()…load_wallet`, else `Wallet::create(…).create_wallet` | Unchanged (`open`). |
| 40–41 | `next_unused_address`, `persist` | Unchanged (`next_address`), used when the regtest node pays the wallet. |
| 48 | `BdkElectrumClient::new(electrum_client::Client::new(URL)?)` | **Change 1**: `HaystackElectrumClient::new(inner, decoy_key, padding)` plus the chain-decoy share, the ledger file, the saved cache file and the session log. `inner` is this crate's connection, which pins TLS certificates and counts bytes (`src/transport.rs`). |
| 52, 116 | `client.populate_tx_cache(wallet.tx_graph()…)` | **Change 4**: removed. Haystack has no such method; its cache holds what it fetched, reals and decoys alike. |
| 54–66 | `start_full_scan().inspect(…)`, `full_scan(request, STOP_GAP, BATCH_SIZE, false)` | **Change 5**: `full_scan_expecting(request, wallet.start_sync_with_revealed_spks(), STOP_GAP, BATCH_SIZE, false)`. The second request carries the unconfirmed transactions the wallet counts, so one that left the mempool is marked evicted, as upstream's `sync` does. Without the progress printing in `inspect`. |
| 70–71 | `apply_update`, `persist` | Unchanged. |
| 86–96 | `build_tx`, `add_recipient`, `fee_rate`, `finish`, `sign`, `extract_tx` | Unchanged (`send`). |
| 97, 148 | `client.transaction_broadcast(&tx)` | **Change 3**: broadcast through a different server, here `bitcoind`'s RPC on regtest. |
| 104–120, 155–167 | `start_sync_with_revealed_spks`, `client.sync(…)`, `apply_update`, `persist` | **Change 2**: every sync is the full scan above. `start_sync_with_revealed_spks` survives inside change 5, as the source of the expected transactions. |
| 122–152 | Fee bump of the first transaction | Not used by the demo. |

## What the page shows

**Wallet tab**

- **Balance**, in BTC with all 8 decimals in thin-space groups, and a "Private sync on · padding N"
  badge.
- **What the attacker learned from the last sync**, in two words: one for all addresses and one for
  the addresses with coin history ("hidden", "partly hidden" or "exposed").
- **Sync now**, with "Syncing privately… 12 s (the last one took 25.6 s)" while a sync runs, and the
  automatic sync's next due time.
- **The padding dial.** A choice stays put until Apply, and the page says "Not applied yet". Under
  it is the cost of each setting: addresses and KiB per sync, scaled from the last sync, and per day
  at the product's 30-minute average.

**Lab tab**

- **Balance, transactions, last sync and data** for each copy. Balances must match: padding costs
  bandwidth, not correctness. Bytes are counted on the connection itself, with TLS included when the
  server uses it.
- **The score**, per attacker: the many-rounds attacker (T1), and the structural attacker (T2) when
  a training set matches the session's client build, padding and chain share. Each shows two numbers
  of the same size: precision in bits over all addresses, and how many of the addresses with coin
  history it finds. When T2 can't score, the page says why in plain words and gives the command
  that fixes it.
- **What the server sees**: one square per address in the order the server received them, shaded
  by the attacker's probability that it is the wallet's (`score --view`). Grey is a random guess,
  red is certain, pale is crossed off as a decoy; a dot marks coin history. A checkbox highlights
  the real addresses, which only the wallet knows.
- **The caveat** about what the attacker is assumed to know, and, once chain decoys are used, that
  they hold only against a server that ignores its own log of the lookups that found them.
- **The regtest chain**: pay, mine and send, each with its progress and result on the card.
- **Restore**: the descriptor and the ledger file, which together are the restore set, each with a
  Copy button. Restoring without the ledger takes the dial setting from a list of the four steps.
- **The certificate decision** for a TLS server: authority-signed, trusted on first use and pinned,
  or matching the pin. A different certificate from a pinned server is refused before any query
  is sent.

## Certificate policy

`src/transport.rs` trusts a self-signed certificate the first time and refuses a different one
afterwards, as Electrum's own client does. It uses OpenSSL rather than the `rustls` that
`electrum-client` ships with: rustls checks handshake signatures through `webpki`, which accepts
only version 3 certificates, and a survey of Electrum's public server list on 2026-10-02 found 7 of
the 37 reachable servers on version 1 certificates. The pins are kept in `out/demo/pins.json`.
