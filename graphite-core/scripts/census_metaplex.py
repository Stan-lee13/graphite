#!/usr/bin/env python3
"""C25 — On-chain u8 discriminator census for Metaplex Token Metadata.

Fetches recent txs to the deployed program (metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s),
base58-decodes instruction data (getTransaction with encoding=json returns data as
base58), and tallies (first byte, account count) pairs. Account-count structure is
the disambiguator: e.g. SignMetadata = 3 accounts, VerifyCollection = 9 accounts,
UpdateMetadataAccountV2 = 2 accounts, CreateMetadataAccountV3 = 7 accounts.

Usage: python scripts/census_metaplex.py [max_txs]
"""
import json
import sys
import time
import urllib.request
from collections import Counter

import os

RPC = os.environ.get("RPC", "https://api.mainnet-beta.solana.com")
METAPLEX = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s"


def rpc(method, params, tries=4):
    for i in range(tries):
        try:
            req = urllib.request.Request(
                RPC,
                data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0 (census-research; graphite-verifier)",
                },
            )
            with urllib.request.urlopen(req, timeout=15) as r:
                return json.load(r).get("result")
        except Exception:
            time.sleep(1.0 * (i + 1))
    return None


def b58(b):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = 0
    for ch in b:
        n = n * 58 + alphabet.index(ch)
    return n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""


def main():
    max_txs = int(sys.argv[1]) if len(sys.argv) > 1 else 120
    sigs = []
    before = None
    while len(sigs) < max_txs and before != "":
        params = [METAPLEX, {"limit": 100, "before": before}]
        page = rpc("getSignaturesForAddress", params) or []
        if not page:
            break
        sigs.extend(s["signature"] for s in page)
        before = page[-1]["signature"]
        if len(page) < 100:
            break

    hist = Counter()      # (first_byte, account_count) -> n
    examples = {}         # (first_byte, account_count) -> signature
    n_tx = 0
    for sig in sigs[:max_txs]:
        tx = rpc("getTransaction", [sig, {"encoding": "json", "maxSupportedTransactionVersion": 0}])
        if not tx or not tx.get("meta") or tx.get("meta", {}).get("err"):
            continue
        msg = tx["transaction"]["message"]
        keys = msg.get("accountKeys", [])
        # accountKeys can be {pubkey, signer, writable} objects (ALT) or plain strings.
        key_list = [k if isinstance(k, str) else k.get("pubkey", "") for k in keys]
        try:
            meta_idx = key_list.index(METAPLEX)
        except ValueError:
            continue
        n_tx += 1
        all_ixs = list(msg.get("instructions", []))
        for inner in (tx.get("meta", {}).get("innerInstructions") or []):
            all_ixs.extend(inner.get("instructions", []))
        for ix in all_ixs:
            if ix.get("programIdIndex") != meta_idx:
                continue
            data_b58 = ix.get("data", "")
            try:
                data = b58(data_b58)
            except Exception:
                continue
            if not data:
                continue
            first = data[0]
            acct_count = len(ix.get("accounts", []))
            key = (first, acct_count)
            hist[key] += 1
            if key not in examples:
                examples[key] = sig

    print(f"scanned {n_tx} successful txs to metaplex")
    print(f"{'disc':<6} {'u8':<4} {'accts':<6} {'count':<6} example")
    for (first, acct_count), n in sorted(hist.items(), key=lambda kv: -kv[1]):
        print(f"0x{first:02x} {first:<4} {acct_count:<6} {n:<6} {examples[(first, acct_count)]}")


if __name__ == "__main__":
    main()
