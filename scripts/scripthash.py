#!/usr/bin/env python3
"""address (or scriptPubKey hex) -> Electrum scripthash

The Electrum protocol never sees addresses directly, only sha256(scriptPubKey),
byte-reversed -- a fixed, public, unkeyed function anyone can invert by
precomputing scripthashes for the addresses they care about.

Usage:
    python3 scripts/scripthash.py 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
    python3 scripts/scripthash.py --spk 76a914...88ac
"""
import hashlib
import sys

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def b58decode_check(s):
    n = 0
    for ch in s:
        n = n * 58 + B58.index(ch)
    raw = n.to_bytes(25, "big")
    body, checksum = raw[:21], raw[21:]
    if hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] != checksum:
        raise ValueError("bad base58 checksum")
    return body


def bech32_decode(addr):
    addr = addr.lower()
    pos = addr.rfind("1")
    data = [BECH32.index(c) for c in addr[pos + 1:]]
    data = data[:-6]  # strip checksum
    witver, prog5 = data[0], data[1:]
    acc = bits = 0
    prog = bytearray()
    for v in prog5:
        acc = (acc << 5) | v
        bits += 5
        if bits >= 8:
            bits -= 8
            prog.append((acc >> bits) & 0xFF)
    return witver, bytes(prog)


def spk_from_address(addr):
    if addr.lower().startswith(("bc1", "tb1", "bcrt1")):
        witver, prog = bech32_decode(addr)
        op = 0x00 if witver == 0 else 0x50 + witver
        return bytes([op, len(prog)]) + prog
    body = b58decode_check(addr)
    ver, h160 = body[0], body[1:]
    if ver in (0x00, 0x6F):                      # P2PKH mainnet/testnet
        return b"\x76\xa9\x14" + h160 + b"\x88\xac"
    if ver in (0x05, 0xC4):                      # P2SH mainnet/testnet
        return b"\xa9\x14" + h160 + b"\x87"
    raise ValueError(f"unsupported base58 version byte {ver:#x}")


def scripthash(spk):
    return hashlib.sha256(spk).digest()[::-1].hex()


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(1)
    if args[0] == "--spk":
        spk = bytes.fromhex(args[1])
        label = "scriptPubKey"
    else:
        spk = spk_from_address(args[0])
        label = args[0]
    print(f"input:        {label}")
    print(f"scriptPubKey: {spk.hex()}")
    print(f"sha256:       {hashlib.sha256(spk).hexdigest()}")
    print(f"scripthash:   {scripthash(spk)}")
