#!/usr/bin/env python3
"""Rank the Solana program inventory by REAL mainnet usage.

Samples finalized blocks spread across a recent window and counts, per
program, the number of SUCCESSFUL transactions that invoke it (top-level or
via CPI). Nothing here is curated: the ranking is whatever the chain did.

Output: scripts/out/inventory_census.json

Read-only public RPC (getSlot / getBlock). No keys, no writes, no signing.
"""
import json
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

RPC = "https://api.mainnet-beta.solana.com"
OUT = Path(__file__).resolve().parent / "out" / "inventory_census.json"

N_BLOCKS = int(sys.argv[1]) if len(sys.argv) > 1 else 60
SPACING = int(sys.argv[2]) if len(sys.argv) > 2 else 400


def rpc(method, params, tries=8):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    delay = 1.0
    for attempt in range(tries):
        try:
            req = urllib.request.Request(RPC, data=body, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=180) as r:
                out = json.loads(r.read())
            if "error" in out:
                code = out["error"].get("code")
                # -32004/-32009/-32007: block not available (skipped slot) — do not retry
                if code in (-32004, -32007, -32009, -32014):
                    return None
                raise RuntimeError(out["error"])
            return out["result"]
        except RuntimeError:
            raise
        except Exception:
            # IncompleteRead, connection resets, gateway HTML, timeouts: a
            # 12 MB block over a public endpoint fails often enough that a
            # narrow except list silently ends the run.
            if attempt == tries - 1:
                return None
            time.sleep(delay)
            delay = min(delay * 2, 30)
    return None


def main():
    tip = rpc("getSlot", [{"commitment": "finalized"}])
    start = tip - 100
    tx_count = Counter()       # program -> successful txs invoking it
    top_level = Counter()      # program -> successful txs invoking it at top level
    blocks_seen = defaultdict(set)
    versions = Counter()
    total_tx = 0
    sampled = []
    # Per-transaction program SETS, so transaction-level manifest coverage can
    # be recomputed offline for any manifest set - the before and the after
    # then come from the same sample instead of two different hours of chain.
    combos = Counter()

    for i in range(N_BLOCKS):
        slot = start - i * SPACING
        blk = rpc(
            "getBlock",
            [slot, {"encoding": "jsonParsed", "transactionDetails": "full",
                    "rewards": False, "maxSupportedTransactionVersion": 1}],
        )
        if blk is None:
            continue
        sampled.append({"slot": slot, "block_time": blk.get("blockTime"), "txs": len(blk["transactions"])})
        for tx in blk["transactions"]:
            versions[str(tx.get("version"))] += 1
            if (tx.get("meta") or {}).get("err"):
                continue
            total_tx += 1
            msg = tx["transaction"]["message"]
            tops = {ix.get("programId") for ix in msg["instructions"] if ix.get("programId")}
            seen = set(tops)
            for inner in (tx["meta"].get("innerInstructions") or []):
                for ix in inner["instructions"]:
                    if ix.get("programId"):
                        seen.add(ix["programId"])
            for p in seen:
                tx_count[p] += 1
                blocks_seen[p].add(slot)
            for p in tops:
                top_level[p] += 1
            combos[("|".join(sorted(seen)), "|".join(sorted(tops)))] += 1
        print(f"[{i+1}/{N_BLOCKS}] slot {slot} txs={len(blk['transactions'])} programs={len(tx_count)}", flush=True)
        write_result(tip, sampled, versions, total_tx, tx_count, top_level, blocks_seen, N_BLOCKS, combos)

    result = write_result(tip, sampled, versions, total_tx, tx_count, top_level, blocks_seen, N_BLOCKS, combos)
    print(f"wrote {OUT} — {len(result['programs'])} distinct programs over {total_tx} successful txs")


def write_result(tip, sampled, versions, total_tx, tx_count, top_level, blocks_seen, n_blocks, combos):
    result = {
        "method": "getBlock(jsonParsed, full, maxSupportedTransactionVersion=1) over sampled finalized slots",
        "rpc": RPC,
        "sampled_at_unix": int(time.time()),
        "tip_slot": tip,
        "blocks_requested": n_blocks,
        "blocks_returned": len(sampled),
        "slot_spacing": SPACING,
        "successful_transactions": total_tx,
        "transaction_versions": dict(versions),
        "blocks": sampled,
        "programs": [
            {
                "program_id": p,
                "successful_txs": n,
                "top_level_txs": top_level[p],
                "blocks_seen": len(blocks_seen[p]),
            }
            for p, n in tx_count.most_common()
        ],
        "transaction_program_sets": [
            {"all": a, "top_level": t, "transactions": n} for (a, t), n in combos.most_common()
        ],
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=1), encoding="utf-8")
    return result


if __name__ == "__main__":
    main()
