#!/usr/bin/env python3
"""Fetch REAL, SUCCESSFUL mainnet transactions for pinned test fixtures.

For each target program: walk its recent signatures (getSignaturesForAddress),
skip every one whose `err` is not null, fetch the transaction, and keep the
first that (a) succeeded on chain (`meta.err == null`, checked again on the
transaction itself) and (b) invokes the target program in a TOP-LEVEL
instruction. Writes it to graphite-core/tests/fixtures/real_mainnet_<name>.json.

Round 29 (audit 2026-10-20, MED-5): this script used to take `sigs[0]` —
whatever was newest, failed or not — and the holdout corpus then described
two FAILED transactions (Custom 7002, Custom 6004) as successful; the "pump"
one did not even invoke pump.fun at top level. It also trimmed `meta` down to
`computeUnitsConsumed` and `err`, dropping `loadedAddresses`, without which a
v0 transaction's lookup-table accounts cannot be resolved. `meta` now keeps
every field the readers use.

A fixture written here is a real instruction SHAPE plus the fact that the
chain accepted it. Whether it is benign is a separate statement; the test
that scores it must say where that label comes from.
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
import argparse
import json
import sys
import urllib.request
from pathlib import Path

RPC = "https://api.mainnet-beta.solana.com"
OUT_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures"

TARGETS = [
    ("pump", "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"),  # pump.fun
    ("jup", "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"),  # Jupiter v6
    ("system", "11111111111111111111111111111111"),  # System transfer
]

# The `meta` fields the readers consume (live_corpus.rs, the corpus tests).
META_FIELDS = ("err", "computeUnitsConsumed", "fee", "loadedAddresses",
               "innerInstructions", "preBalances", "postBalances")


def rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(RPC, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        doc = json.load(resp)
    if "error" in doc:
        raise RuntimeError(f"{method}: {doc['error']}")
    return doc["result"]


def top_level_programs(message, meta):
    keys = list(message["accountKeys"])
    loaded = (meta or {}).get("loadedAddresses") or {}
    keys += loaded.get("writable", []) + loaded.get("readonly", [])
    out = []
    for ix in message["instructions"]:
        idx = ix["programIdIndex"]
        out.append(keys[idx] if idx < len(keys) else None)
    return out


def fetch_one(name, program, scan):
    sigs = rpc("getSignaturesForAddress", [program, {"limit": scan}]) or []
    for entry in sigs:
        if entry.get("err") is not None:
            continue
        sig = entry["signature"]
        r = rpc("getTransaction", [sig, {"encoding": "json", "maxSupportedTransactionVersion": 0}])
        if not r or (r.get("meta") or {}).get("err") is not None:
            continue
        if program not in top_level_programs(r["transaction"]["message"], r.get("meta")):
            continue
        meta = {k: r["meta"][k] for k in META_FIELDS if k in r["meta"]}
        return sig, {
            "transaction": {
                "message": r["transaction"]["message"],
                "signatures": r["transaction"]["signatures"],
            },
            "slot": r.get("slot"),
            "blockTime": r.get("blockTime"),
            "meta": meta,
        }
    return None, None


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("names", nargs="*", help="subset of: " + ", ".join(n for n, _ in TARGETS))
    ap.add_argument("--scan", type=int, default=50, help="signatures to examine per program")
    args = ap.parse_args()
    failed = 0
    for name, program in TARGETS:
        if args.names and name not in args.names:
            continue
        sig, out = fetch_one(name, program, args.scan)
        if out is None:
            print(f"{name}: no successful top-level invocation in the newest {args.scan} signatures",
                  file=sys.stderr)
            failed += 1
            continue
        path = OUT_DIR / f"real_mainnet_{name}.json"
        path.write_text(json.dumps(out, indent=1), encoding="utf-8")
        msg = out["transaction"]["message"]
        print(f"{name}: saved {path} ({sig[:16]}…, slot {out['slot']}, {len(msg['instructions'])} instructions, meta.err null)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
