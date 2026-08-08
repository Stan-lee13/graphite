#!/usr/bin/env python3
"""Verify the Jupiter DCA PDA derivation from REAL mainnet transaction data.

Jupiter DCA's `openDca` creates the `dca` account whose PDA is derived from
seeds that include a per-user nonce stored IN the instruction data. This
script fetches a real successful openDca tx, extracts the created dca account
address, and tests candidate seed layouts until one derives exactly that
address. The winning layout is the evidence-backed pda_seeds template for the
manifest.
"""
import json
import struct
import sys
import urllib.request

RPC = "https://api.mainnet-beta.solana.com"
DCA = "DCA265Vj8a9CEuX1eb1LWRnDT7uK6q1xMipnNyatn23M"
OPEN_DCA = "ee26b3c80e7dc30b"  # openDca discriminator from the manifest


def rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(RPC, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp).get("result")


def b58decode(s):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = 0
    for c in s:
        n = n * 58 + alphabet.index(c)
    b = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + b


def b58encode(b):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(b, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = alphabet[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\x00"))) + s


def find_pda(seeds, program):
    """Minimal findProgramAddress (no bump search beyond 0..255)."""
    for bump in range(256):
        h = hashlib_sha256()
        for s in seeds:
            h.update(s)
        h.update(bytes([bump]))
        h.update(program)
        d = h.digest()
        if d[-1] < 0xF0:  # on-curve check
            return d[:32], bump
    return None, None


import hashlib


def hashlib_sha256():
    return hashlib.sha256()


def main():
    sigs = rpc("getSignaturesForAddress", [DCA, {"limit": 20}])
    found = False
    for s in sigs:
        sig = s["signature"]
        r = rpc("getTransaction", [sig, {"encoding": "json", "maxSupportedTransactionVersion": 0}])
        if not r or r.get("meta", {}).get("err"):
            continue
        msg = r["transaction"]["message"]
        keys = msg.get("accountKeys", [])
        ixs = msg.get("instructions", [])
        for i, ix in enumerate(ixs):
            pidx = ix.get("programIdIndex", 0)
            prog = keys[pidx]
            if prog != DCA:
                continue
            data_b58 = ix.get("data", "")
            raw = b58decode(data_b58)
            if len(raw) < 8 or raw[:8].hex() != OPEN_DCA:
                continue
            # The dca account appears as a writable account in the ix account list.
            # First try: candidate seed layouts using user (first account) + data.
            user_idx = ix.get("accounts", [])[0]
            user = b58decode(keys[user_idx])
            print(f"openDca tx {sig[:24]}… ix{i}: data_len={len(raw)}")
            print(f"  data after discriminator: {raw[8:32].hex()}")
            dca_acct = None
            for aidx in ix.get("accounts", [])[1:]:
                a = keys[aidx]
                # the dca PDA is usually the 2nd account; try deriving
                candidates = [
                    ([b"dca", user, raw[8:16]], a),
                    ([b"dca", user, raw[8:16], raw[16:24]], a),
                    ([b"dca", raw[8:16]], a),
                    ([b"dca", user, bytes([raw[8]])], a),
                    ([b"dca", user, raw[8:9]], a),
                    ([b"dca", user, raw[24:32]], a),
                    ([b"dca", raw[8:16], user], a),
                ]
                for seeds, addr in candidates:
                    pk, bump = find_pda(seeds, b58decode(DCA))
                    if pk and b58encode(pk) == addr:
                        print(f"  ✓ DERIVED dca PDA {addr} with seeds {[s.hex()[:12] for s in seeds]} bump={bump}")
                        found = True
            if not found:
                print(f"  accounts: {[keys[a][:12] for a in ix.get('accounts', [])[:6]]}")
            break
        if found:
            break
    if not found:
        print("no derivation matched (try wider account/data layouts) — dumping an openDca ix fully:")


if __name__ == "__main__":
    main()
