#!/usr/bin/env python3
"""On-chain discriminator census for Orca Whirlpools.

Fetches recent Orca txs (paged back through history), base58-decodes every
instruction's data, and tallies observed 8-byte discriminators. Progress is
cached to a JSON file so an interrupted run resumes without re-fetching.

Usage: python scripts/census_orca.py [max_txs]
"""
import json
import sys
import time
import urllib.request
from collections import Counter

RPC = "https://api.mainnet-beta.solana.com"
ORCA = "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc"
CACHE = "scripts/.census_orca_cache.json"
MAX_TXS = int(sys.argv[1]) if len(sys.argv) > 1 else 300


def rpc(method, params, tries=4):
    for i in range(tries):
        try:
            req = urllib.request.Request(
                RPC,
                data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r).get("result")
        except Exception:
            time.sleep(1.5 * (i + 1))
    return None


def b58(b):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = 0
    for ch in b:
        n = n * 58 + alphabet.index(ch)
    return n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""


def main():
    try:
        cache = json.load(open(CACHE))
    except Exception:
        cache = {"counts": {}, "examples": {}, "fetched": []}

    counts = Counter(cache["counts"])
    examples = cache["examples"]
    fetched = set(cache["fetched"])

    # Collect signatures by paging back.
    before = None
    sigs_all = []
    pages = 0
    while pages < 40:
        params = [ORCA, {"limit": 100}]
        if before:
            params[1]["before"] = before
        sigs = rpc("getSignaturesForAddress", params)
        if not sigs or len(sigs) == 0:
            break
        sigs_all.extend(sigs)
        before = sigs[-1]["signature"]
        pages += 1
        if len(sigs) < 100:
            break
    print(f"collected {len(sigs_all)} signatures across {pages} pages", flush=True)

    for s in sigs_all:
        sig = s["signature"]
        if sig in fetched:
            continue
        if len(fetched) >= MAX_TXS:
            break
        tx = rpc("getTransaction", [sig, {"encoding": "json", "maxSupportedTransactionVersion": 0}])
        if not tx:
            continue
        fetched.add(sig)
        msg = tx["transaction"]["message"]
        keys = [k if isinstance(k, str) else k.get("pubkey", "") for k in msg.get("accountKeys", [])]
        loaded = ((tx.get("meta") or {}).get("loadedAddresses") or {})
        keys += loaded.get("writable", []) + loaded.get("readonly", [])
        meta = tx.get("meta", {})
        all_ix = list(msg.get("instructions", []))
        for ii in (meta.get("innerInstructions") or []):
            all_ix.extend(ii.get("instructions", []))
        for ix in all_ix:
            idx = ix.get("programIdIndex")
            if idx is None or idx >= len(keys) or keys[idx] != ORCA:
                continue
            data = ix.get("data", "")
            if data:
                raw = b58(data)
                if len(raw) >= 8:
                    d = raw[:8].hex()
                    counts[d] += 1
                    examples.setdefault(d, sig[:24])
        # Save progress every 25 txs.
        if len(fetched) % 25 == 0:
            json.dump(
                {"counts": dict(counts), "examples": examples, "fetched": sorted(fetched)},
                open(CACHE, "w"),
            )
            print(f"  ...{len(fetched)} txs, {len(counts)} distinct discriminators", flush=True)

    json.dump(
        {"counts": dict(counts), "examples": examples, "fetched": sorted(fetched)},
        open(CACHE, "w"),
    )
    print("=== ORCA observed ===", flush=True)
    for d, n in counts.most_common():
        print(f"  {d} x{n}  ex={examples[d]}...", flush=True)


if __name__ == "__main__":
    main()
