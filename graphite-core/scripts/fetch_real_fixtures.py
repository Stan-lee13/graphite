#!/usr/bin/env python3
"""Fetch REAL mainnet transactions for pinned test fixtures.

Downloads a recent real transaction per target program (getSignaturesForAddress
-> getTransaction), trims it to the fields Graphite's live-corpus reader
actually consumes, and writes it to tests/fixtures/. The result is genuine
on-chain data — proof the parser handles real transaction shapes.
"""

# VERSION 0 ONLY (scripts/README.md, "Which tools see v1"): this one-off
# onboarding/census script asks the RPC for maxSupportedTransactionVersion 0
# and parses the `json` encoding's legacy/v0 shape, so every v1 transaction is
# left out of what it reads. Its output is for reviewing a manifest, never for
# measuring traffic; it says so on every run.
import sys as _v0_sys

print(
    "[graphite] version-0 tool: v1 transactions are excluded from this output; "
    "do not use it to measure traffic (scripts/README.md).",
    file=_v0_sys.stderr,
)
import json
import sys
import urllib.request

RPC = "https://api.mainnet-beta.solana.com"
OUT_DIR = "graphite-core/tests/fixtures"

TARGETS = [
    ("pump", "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"),  # pump.fun
    ("jup", "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"),  # Jupiter v6
    ("system", "11111111111111111111111111111111"),  # System transfer
]


def rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(RPC, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)["result"]


def main():
    for name, program in TARGETS:
        sigs = rpc("getSignaturesForAddress", [program, {"limit": 3}])
        if not sigs:
            print(f"{name}: NO SIGNATURES — skipping", file=sys.stderr)
            continue
        sig = sigs[0]["signature"]
        r = rpc(
            "getTransaction",
            [sig, {"encoding": "json", "maxSupportedTransactionVersion": 0}],
        )
        if not r:
            print(f"{name}: getTransaction returned null for {sig}", file=sys.stderr)
            continue
        # Keep the EXACT getBlock transaction-object shape the reader
        # consumes (transaction.message + transaction.signatures + meta), so
        # the pinned tests validate the parser against the true RPC contract.
        out = {
            "transaction": {
                "message": r["transaction"]["message"],
                "signatures": r["transaction"]["signatures"],
            },
            "slot": r.get("slot"),
            "blockTime": r.get("blockTime"),
            "meta": {
                "computeUnitsConsumed": r["meta"].get("computeUnitsConsumed", 0),
                "err": r["meta"].get("err"),
            },
        }
        path = f"{OUT_DIR}/real_mainnet_{name}.json"
        with open(path, "w") as f:
            json.dump(out, f, indent=1)
        msg = r["transaction"]["message"]
        first_ix = msg["instructions"][0]
        prog = msg["accountKeys"][first_ix["programIdIndex"]]
        print(f"{name}: saved {path} ({sig[:16]}…, slot {r.get('slot')}, first program {prog}, {len(msg['instructions'])} instructions)")


if __name__ == "__main__":
    main()
