"""Pull a sample of REAL, UNSEEN mainnet transactions for the Round 13 probe.

Read-only. One request at a time, a pause between blocks, backs off and stops
on a 429 — a public endpoint is somebody else's infrastructure, and the point
here is to read a handful of blocks, not to load it. No credentials: the
endpoint is the keyless public one the repo's own live tests default to, and
`GRAPHITE_RPC_URL` overrides it if the operator has their own.

Writes `mainnet_sample.json`: for every transaction, its slot, version, the
raw base64 transaction bytes, and the block's own metadata for it (whether it
failed, compute units, the addresses its lookup tables resolved to). Nothing is interpreted here;
interpretation is the Rust probe's job, so the sample can be re-run against
two builds of the engine and diffed.
"""
import http.client
import json
import os
import time
import urllib.error
import urllib.request

ENDPOINT = os.environ.get("GRAPHITE_RPC_URL") or "https://api.mainnet-beta.solana.com"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mainnet_sample.json")

# Blocks to sample, and how far apart. Spread out so the sample is not one
# moment of one leader's traffic.
BLOCKS = int(os.environ.get("PROBE_BLOCKS", "8"))
STRIDE = 400
PAUSE_S = 2.0


def rpc(method, params, timeout=120, attempts=4):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    for attempt in range(attempts):
        req = urllib.request.Request(
            ENDPOINT, data=body, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 429:
                print("  429 from the endpoint — stopping rather than retrying", flush=True)
                raise SystemExit(0)
            raise
        except (http.client.IncompleteRead, ConnectionError, TimeoutError) as e:
            # A whole mainnet block is 5-12 MB and the public endpoint drops
            # the tail often enough that a single truncated read used to end
            # the run. Retried — this is a short read of the SAME block, not
            # extra load: one more request, after a pause, and only a few
            # times.
            if attempt == attempts - 1:
                raise
            print(f"  short read ({type(e).__name__}) — retrying", flush=True)
            time.sleep(PAUSE_S * (attempt + 2))
    raise RuntimeError("unreachable")


def main():
    head = rpc("getSlot", [{"commitment": "finalized"}])["result"]
    print(f"finalized head {head}", flush=True)

    rows = []
    for i in range(BLOCKS):
        slot = head - 80 - i * STRIDE
        print(f"block {slot} ...", end=" ", flush=True)
        r = rpc(
            "getBlock",
            [
                slot,
                {
                    "encoding": "base64",
                    "transactionDetails": "full",
                    "rewards": False,
                    # Round 12 found a version-0 client is refused the WHOLE
                    # block once it holds one v1 transaction. Ask for them, and
                    # let the probe record what Graphite does with each.
                    "maxSupportedTransactionVersion": 1,
                    "commitment": "finalized",
                },
            ],
        )
        if "error" in r:
            print(f"skipped ({r['error'].get('message', '')[:60]})", flush=True)
            time.sleep(PAUSE_S)
            continue
        block = r["result"]
        txs = block.get("transactions", [])
        for t in txs:
            payload = t.get("transaction")
            if not isinstance(payload, list) or len(payload) < 2 or payload[1] != "base64":
                continue
            meta = t.get("meta") or {}
            loaded = meta.get("loadedAddresses") or {}
            rows.append(
                {
                    "slot": slot,
                    "version": str(t.get("version")),
                    "b64": payload[0],
                    "err": meta.get("err") is not None,
                    "cu": meta.get("computeUnitsConsumed") or 0,
                    "loaded_writable": loaded.get("writable") or [],
                    "loaded_readonly": loaded.get("readonly") or [],
                }
            )
        print(f"{len(txs)} txs", flush=True)
        time.sleep(PAUSE_S)

    with open(OUT, "w", encoding="utf-8") as f:
        json.dump({"endpoint_kind": "public mainnet", "count": len(rows), "rows": rows}, f)
    print(f"\nwrote {len(rows)} transactions to {OUT}", flush=True)
    by_version = {}
    for r in rows:
        by_version[r["version"]] = by_version.get(r["version"], 0) + 1
    print("versions:", by_version, flush=True)
    print("failed on chain:", sum(1 for r in rows if r["err"]), flush=True)


if __name__ == "__main__":
    main()
