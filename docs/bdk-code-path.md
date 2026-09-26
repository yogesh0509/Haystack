# Where this leak lives in BDK

Reproducibility appendix for `docs/00-problem.md` §3: the exact code path in `bdk_wallet` that
discloses every scripthash queried during a full scan.

`~/bdk_wallet/examples/electrum.rs` is a working light-wallet sync. It already ships an inspection
hook that prints every scriptPubKey index sent to the server.

`examples/electrum.rs:16` sets the gap limit:

```rust
const STOP_GAP: usize = 50;
```

`examples/electrum.rs:54` builds the scan request and attaches a callback fired once per
scriptPubKey queried:

```rust
let request = wallet.start_full_scan().inspect({
    // ...
    move |k, spk_i, _| {
        if once.insert(k) { print!("\nScanning keychain [{k:?}]"); }
        print!(" {spk_i:<3}");            // <-- every index sent to the server
        stdout.flush().expect("must flush");
    }
});
let update = client.full_scan(request, STOP_GAP, BATCH_SIZE, false)?;
```

Run it and read the output as an inventory of what was disclosed:

```bash
cd ~/bdk_wallet
cargo run --example electrum --features test-utils
```

Every index printed is one scripthash the server received, tagged by keychain — and
`KeychainKind::Internal` is the **change** keychain (`src/types.rs:28`). Change identification is
usually inferred through chain-analysis heuristics; here it is labelled directly in the query stream.

## Derivation API

If you want to inspect derivation directly, in `~/bdk_wallet/src/wallet/mod.rs`:

| Symbol | Location |
|---|---|
| `Wallet::peek_address` | `src/wallet/mod.rs:605` |
| `Wallet::reveal_next_address` | `src/wallet/mod.rs:651` |
| `Wallet::reveal_addresses_to` | `src/wallet/mod.rs:679` |
| `Wallet::all_unbounded_spk_iters` | `src/wallet/mod.rs:852` |
| `Wallet::start_full_scan` | `src/wallet/mod.rs:2816` |

## Confirming the captured scripthashes are yours

To close the loop and prove the addresses logged by `scripts/honeypot_electrum.py`
(`docs/00-problem.md` §4) belong to your own wallet, dump your own derivation via `peek_address` and
hash each address:

```bash
python3 scripts/scripthash.py <address-from-peek_address>
```

Diff the result against `honeypot-log.json`.
