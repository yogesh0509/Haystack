#!/usr/bin/env python3
"""A fake Electrum server that answers "nothing found" to everything and
logs every scripthash it was asked about.

Because every reply is empty, a wallet pointed at this never finds a used
address, so it walks its entire gap limit on both keychains and hands over
its complete address set in one burst.

    Terminal 1:  python3 scripts/honeypot_electrum.py
    Terminal 2:  point a wallet at tcp://127.0.0.1:50001

For BDK, in bdk_wallet/examples/electrum.rs change:
    const ELECTRUM_URL: &str = "tcp://127.0.0.1:50001";
then:  cargo run --example electrum --features test-utils
or, without editing BDK:  cargo run --release --manifest-path capture/Cargo.toml

Ctrl-C for the summary. Full log written to honeypot-log.json, one entry per
query, tagged with its connection, batch and position -- the attack harness
treats each connection as one sync round.
"""
import argparse
import itertools
import json
import signal
import socketserver
import sys
import time

GENESIS_HEADER = (
    "01000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
    "29ab5f49" "ffff001d" "1dac2b7c"
)
FAKE_HEIGHT = 800_000

SCRIPTHASH_METHODS = {
    "blockchain.scripthash.get_history",
    "blockchain.scripthash.subscribe",
    "blockchain.scripthash.get_balance",
    "blockchain.scripthash.listunspent",
    "blockchain.scripthash.get_mempool",
}

# Every scripthash we were asked about, in arrival order.
CAPTURED = []
STARTED_AT = None
CONNECTIONS = itertools.count(1)


def dispatch(method, params, where):
    """Answer plausibly, and always answer 'empty' for anything wallet-shaped."""
    if method in SCRIPTHASH_METHODS:
        sh = params[0] if params else None
        CAPTURED.append({"t": round(time.time() - STARTED_AT, 4), **where,
                         "method": method, "scripthash": sh})
        n = len(CAPTURED)
        print(f"  [{n:>4}] conn {where['conn']}  {sh}", flush=True)
        if method == "blockchain.scripthash.get_balance":
            return {"confirmed": 0, "unconfirmed": 0}
        if method == "blockchain.scripthash.subscribe":
            return None
        return []

    if method == "server.version":
        return ["HaystackHoneypot 0.1", "1.4"]
    if method == "server.banner":
        return "Haystack honeypot - everything you send here is being logged."
    if method == "server.ping":
        return None
    if method == "server.features":
        return {
            "server_version": "HaystackHoneypot 0.1",
            "protocol_min": "1.4", "protocol_max": "1.4",
            "genesis_hash": "000000000019d6689c085ae165831e93"
                            "4ff763ae46a2a6c172b3f1b60a8ce26f",
            "hash_function": "sha256", "pruning": None,
        }
    if method == "blockchain.headers.subscribe":
        return {"height": FAKE_HEIGHT, "hex": GENESIS_HEADER}
    if method == "blockchain.block.header":
        return GENESIS_HEADER
    if method == "blockchain.block.headers":
        return {"count": 1, "hex": GENESIS_HEADER, "max": 2016}
    if method == "blockchain.relayfee":
        return 0.00001
    if method == "blockchain.estimatefee":
        return 0.00002
    if method == "mempool.get_fee_histogram":
        return []
    if method == "blockchain.transaction.get":
        raise LookupError("no such transaction")

    raise LookupError(f"unhandled method {method}")


def handle_one(req, where):
    rid = req.get("id")
    try:
        return {"jsonrpc": "2.0", "id": rid,
                "result": dispatch(req.get("method"), req.get("params") or [],
                                   where)}
    except Exception as e:
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32601, "message": str(e)}}


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        conn = next(CONNECTIONS)
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        print(f"\n--- client connected: {peer} (conn {conn}) ---", flush=True)
        for batch, line in enumerate(l for l in self.rfile if l.strip()):
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            # A batch arrives as a JSON array and must come back as one.
            if isinstance(msg, list):
                out = [handle_one(r, {"conn": conn, "peer": peer,
                                      "batch": batch, "pos": pos})
                       for pos, r in enumerate(msg)]
            else:
                out = handle_one(msg, {"conn": conn, "peer": peer,
                                       "batch": batch, "pos": 0})
            self.wfile.write((json.dumps(out) + "\n").encode())
            self.wfile.flush()
        print(f"--- client disconnected: {peer} (conn {conn}) ---", flush=True)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def summarise(path):
    uniq = {c["scripthash"] for c in CAPTURED if c["scripthash"]}
    print("\n" + "=" * 60)
    print(f"scripthash queries received : {len(CAPTURED)}")
    print(f"distinct scripthashes        : {len(uniq)}")
    print(f"connections (sync rounds)    : {len({c['conn'] for c in CAPTURED})}")
    if CAPTURED:
        span = CAPTURED[-1]["t"] - CAPTURED[0]["t"]
        print(f"elapsed across the burst     : {span:.3f}s")
        print("\nEvery one of those belongs to a single wallet, and they")
        print("arrived together on one connection. No inference required.")
    with open(path, "w") as fh:
        json.dump(CAPTURED, fh, indent=2)
    print(f"\nlog written to {path}")
    print("=" * 60)


def main():
    global STARTED_AT
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=50001)
    ap.add_argument("--log", default="honeypot-log.json")
    args = ap.parse_args()

    STARTED_AT = time.time()
    print(f"Haystack honeypot listening on tcp://{args.host}:{args.port}")
    print("Point a light wallet here. Ctrl-C for the summary.\n")
    srv = Server((args.host, args.port), Handler)

    done = {"already": False}

    def finish(*_):
        # Reachable via Ctrl-C, SIGTERM, or another shell's `kill -INT`.
        if done["already"]:
            return
        done["already"] = True
        summarise(args.log)
        sys.exit(0)

    signal.signal(signal.SIGINT, finish)
    signal.signal(signal.SIGTERM, finish)
    try:
        srv.serve_forever()
    finally:
        finish()


if __name__ == "__main__":
    sys.exit(main())
