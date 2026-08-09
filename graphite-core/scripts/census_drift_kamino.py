#!/usr/bin/env python3
"""C27 — On-chain discriminator census for Drift + Kamino Lending.

Fetches recent txs for both programs (paged back through history), base58-
decodes every instruction's data, and tallies observed 8-byte discriminators.
Each observed discriminator is then matched against the DERIVED Anchor
convention (sha256("global:"+snake_case_name)[0..8]) from the official IDLs
(scripts/drift_idl.json, scripts/klend_idl.json), and matches/mismatches are
reported. This is the live ground-truth cross-check behind the C27 manifests.

Usage: python scripts/census_drift_kamino.py [max_txs_per_program]
"""
import hashlib
import json
import sys
import time
import urllib.request
from collections import Counter

RPC = "https://api.mainnet-beta.solana.com"
PROGRAMS = {
    "drift": "dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH",
    "klend": "KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD",
}
CACHE = "scripts/.census_dk_cache.json"
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


def snake(n):
    import re
    s = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", n)
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", s).lower()


def derived_map(prog):
    idl = json.load(open(f"scripts/{prog}_idl.json"))
    m = {}
    for i in idl["instructions"]:
        # Anchor's discriminator hashes the SNAKE_CASE Rust fn name:
        # sha256("global:" + fn_name)[0..8]. Verified live for Drift
        # (place_perp_order, place_orders, cancel_orders_by_ids) on C27.
        m[hashlib.sha256(("global:" + snake(i["name"])).encode()).hexdigest()[:16]] = i["name"]
    return m


def main():
    try:
        cache = json.load(open(CACHE))
    except Exception:
        cache = {"counts": {}, "fetched": []}

    counts = Counter(cache["counts"])
    fetched = set(cache["fetched"])
    derived = {p: derived_map(p) for p in PROGRAMS}

    for prog, pid in PROGRAMS.items():
        before = None
        sigs_all = []
        pages = 0
        while pages < 40:
            params = [pid, {"limit": 100}]
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
        print(f"[{prog}] {len(sigs_all)} signatures across {pages} pages", flush=True)

        prog_fetched = sum(1 for x in fetched if x.startswith(prog + ":"))
        for s in sigs_all:
            if prog_fetched >= MAX_TXS:
                break
            sig = s["signature"]
            if prog + ":" + sig in fetched:
                continue
            tx = rpc("getTransaction", [sig, {"encoding": "json", "maxSupportedTransactionVersion": 0}])
            if not tx:
                continue
            fetched.add(prog + ":" + sig)
            prog_fetched += 1
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
                if idx is None or idx >= len(keys) or keys[idx] != pid:
                    continue
                data = ix.get("data", "")
                if data:
                    raw = b58(data)
                    if len(raw) >= 8:
                        counts[prog + ":" + raw[:8].hex()] += 1
            if len(fetched) % 25 == 0:
                json.dump({"counts": dict(counts), "fetched": sorted(fetched)}, open(CACHE, "w"))
                print(f"  ...{len(fetched)} txs", flush=True)

    json.dump({"counts": dict(counts), "fetched": sorted(fetched)}, open(CACHE, "w"))

    print("=== OBSERVED vs DERIVED ===", flush=True)
    for prog in PROGRAMS:
        dm = derived[prog]
        print(f"--- {prog} ---", flush=True)
        match = mismatch = unknown = 0
        for key, n in counts.most_common():
            if not key.startswith(prog + ":"):
                continue
            disc = key.split(":", 1)[1]
            name = dm.get(disc)
            if name:
                match += 1
                print(f"  MATCH   {disc} x{n}  -> {name}", flush=True)
            else:
                mismatch += 1
                print(f"  UNKNOWN {disc} x{n}  -> (no derived match)", flush=True)
        print(f"  [{prog}] matched={match} unmatched={mismatch}", flush=True)


if __name__ == "__main__":
    main()
