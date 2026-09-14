#!/usr/bin/env python3
"""Query a public Electrum server directly, the way your wallet does.

This is the whole protocol. There is no authentication, no session, no
privacy layer -- you open a socket, send a scripthash, and the server
returns the complete history and balance for it.

Run it and note what you did NOT have to prove: that the address is yours,
that you have any right to the data, or who you are.

Usage:
    python3 scripts/electrum_probe.py <scripthash>
    python3 scripts/electrum_probe.py --address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
    python3 scripts/electrum_probe.py --address bc1q... --server fortress.qtornado.com:50002
"""
import argparse
import json
import socket
import ssl
import sys

from scripthash import scripthash, spk_from_address

DEFAULT_SERVER = "electrum.blockstream.info:50002"


class Electrum:
    def __init__(self, host, port, timeout=20):
        ctx = ssl.create_default_context()
        # Electrum servers routinely use self-signed certs; the protocol has no
        # PKI story. Worth noticing as its own trust problem.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((host, port), timeout=timeout)
        self.sock = ctx.wrap_socket(raw)
        self.f = self.sock.makefile("rw")
        self._id = 0

    def call(self, method, params):
        self._id += 1
        self.f.write(json.dumps({
            "jsonrpc": "2.0", "method": method,
            "params": params, "id": self._id,
        }) + "\n")
        self.f.flush()
        resp = json.loads(self.f.readline())
        if "error" in resp and resp["error"]:
            raise RuntimeError(resp["error"])
        return resp["result"]

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scripthash", nargs="?")
    ap.add_argument("--address")
    ap.add_argument("--server", default=DEFAULT_SERVER)
    args = ap.parse_args()

    if args.address:
        sh = scripthash(spk_from_address(args.address))
        label = args.address
    elif args.scripthash:
        sh = args.scripthash
        label = sh
    else:
        ap.error("give a scripthash or --address")

    host, port = args.server.rsplit(":", 1)
    cli = Electrum(host, int(port))
    try:
        ver = cli.call("server.version", ["haystack-probe", "1.4"])
        print(f"server:     {args.server}  {ver}")
        print(f"querying:   {label}")
        print(f"scripthash: {sh}\n")

        bal = cli.call("blockchain.scripthash.get_balance", [sh])
        conf, unconf = bal["confirmed"], bal["unconfirmed"]
        print(f"balance:    {conf} sat confirmed  ({conf / 1e8:.8f} BTC)")
        print(f"            {unconf} sat unconfirmed")

        hist = cli.call("blockchain.scripthash.get_history", [sh])
        print(f"history:    {len(hist)} entries")
        for e in hist[:5]:
            print(f"              height {e['height']:>9}  {e['tx_hash']}")
        if len(hist) > 5:
            print(f"              ... and {len(hist) - 5} more")

        try:
            utxos = cli.call("blockchain.scripthash.listunspent", [sh])
            print(f"utxos:      {len(utxos)}")
        except Exception as e:
            # Some servers cap response size or rate-limit heavy scripthashes.
            print(f"utxos:      (server declined: {type(e).__name__})")
    finally:
        cli.close()


if __name__ == "__main__":
    sys.exit(main())
