"""Pull a sample of REAL, UNSEEN mainnet transactions for the Round 13 probe.

Read-only. One request at a time, a pause between blocks, and it stops — with
a failing status and no file written — on a 429 rather than retrying: a
public endpoint is somebody else's infrastructure, and the point here is to
read a handful of blocks, not to load it. No credentials: the endpoint is the
keyless public one the repo's own live tests default to, and
`GRAPHITE_RPC_URL` overrides it if the operator has their own (the sample
then records `endpoint_kind: "operator-supplied"`, never the URL, which may
carry a key).

Writes `mainnet_sample.json`: for every transaction, its slot, version, the
raw base64 transaction bytes, and the block's own metadata for it (whether it
failed, compute units, the addresses its lookup tables resolved to). Nothing is interpreted here;
interpretation is the Rust probe's job, so the sample can be re-run against
two builds of the engine and diffed.

Reproducible (W25, external review): `--slots 450453705,450454105,...` fetches
exactly those finalized blocks instead of blocks counted back from the head,
and every one of them must be fetched — a slot the endpoint cannot return
fails the run with no file written, because a sample missing a block it was
asked for is not the sample it claims to be (Round 29, audit 2026-10-20, M1:
the block was reported "skipped" and the file written anyway, exit 0). The
sample records the slots it holds, and the file's SHA-256 is printed. A
finalized block does not change, so the same slots give the same ROWS; the
file's bytes, and so its hash, also depend on the fetcher's own fields (this
version writes `slots`, which the recorded samples predate), so a refetch is
checked against a recorded sample row by row with `verify_sample.py`, not by
hash. The samples behind the published numbers are listed with their slots
and hashes in SAMPLES.md. `--out <path>` writes somewhere other than
mainnet_sample.json.
"""
import argparse
import hashlib
import http.client
import json
import os
import sys
import time
import urllib.error
import urllib.request

PUBLIC_ENDPOINT = "https://api.mainnet-beta.solana.com"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mainnet_sample.json")

# Blocks to sample, and how far apart. Spread out so the sample is not one
# moment of one leader's traffic.
BLOCKS = int(os.environ.get("PROBE_BLOCKS", "8"))
STRIDE = 400
PAUSE_S = 2.0


def endpoint(environ=None):
    env = os.environ if environ is None else environ
    return env.get("GRAPHITE_RPC_URL") or PUBLIC_ENDPOINT


def endpoint_kind(environ=None):
    """What the sample records about where it came from. Round 29 (M3): this
    was "public mainnet" even when GRAPHITE_RPC_URL pointed elsewhere. The URL
    itself is never recorded: a provider URL often carries an API key."""
    return "public mainnet" if endpoint(environ) == PUBLIC_ENDPOINT else "operator-supplied (GRAPHITE_RPC_URL)"


class FetchError(SystemExit):
    """A fetch that cannot produce the sample it was asked for. A SystemExit,
    so the process exits non-zero with the message and writes nothing."""


def rpc(method, params, timeout=120, attempts=4):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    url = endpoint()
    for attempt in range(attempts):
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 429:
                # Stop rather than retry a public endpoint that asked us to
                # slow down, and say so with a failing status: nothing has
                # been written, and a caller must not read exit 0 as a sample.
                raise FetchError(
                    "429 from the endpoint — stopped without writing a sample; retry later"
                ) from None
            raise FetchError(f"HTTP {e.code} from the endpoint — stopped without writing a sample") from None
        except (http.client.IncompleteRead, ConnectionError, TimeoutError, urllib.error.URLError) as e:
            # A whole mainnet block is 5-12 MB and the public endpoint drops
            # the tail often enough that a single truncated read used to end
            # the run. Retried — this is a short read of the SAME block, not
            # extra load: one more request, after a pause, and only a few
            # times. Round 29 (M3): URLError (DNS failure, refused
            # connection, a TLS error) escaped as a traceback; it is retried
            # the same way and then reported.
            if attempt == attempts - 1:
                raise FetchError(
                    f"no answer from the endpoint after {attempts} attempts "
                    f"({type(e).__name__}: {e}) — stopped without writing a sample"
                ) from None
            print(f"  {type(e).__name__} — retrying", flush=True)
            time.sleep(PAUSE_S * (attempt + 2))
    raise RuntimeError("unreachable")


def rows_from_block(slot, block):
    """The recorded fields of every base64 transaction in one block, in block
    order."""
    rows = []
    for t in block.get("transactions", []):
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
    return rows


def fetch(slots, require_all, pause=PAUSE_S):
    """Fetch `slots` in order -> (rows, fetched_slots).

    With `require_all` (an explicit slot list) a slot the endpoint does not
    return raises FetchError; without it (blocks counted back from the head,
    where a leader's skipped slot is ordinary) the slot is reported and left
    out."""
    rows = []
    fetched = []
    for slot in slots:
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
        if "error" in r or r.get("result") is None:
            why = (r.get("error") or {}).get("message", "no block returned")[:120]
            if require_all:
                raise FetchError(
                    f"slot {slot} was asked for and the endpoint did not return it ({why}) — "
                    "stopped without writing a sample"
                )
            print(f"skipped ({why[:60]})", flush=True)
            time.sleep(pause)
            continue
        block_rows = rows_from_block(slot, r["result"])
        rows.extend(block_rows)
        fetched.append(slot)
        print(f"{len(r['result'].get('transactions', []))} txs", flush=True)
        time.sleep(pause)
    return rows, fetched


def parse_slots(raw):
    try:
        slots = [int(s) for s in raw.split(",") if s.strip()]
    except ValueError:
        raise FetchError(f"--slots must be comma-separated integers, got {raw!r}") from None
    if not slots:
        raise FetchError("--slots names no slot")
    return slots


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--slots", help="comma-separated finalized slots to fetch, instead of counting back from the head")
    parser.add_argument("--out", default=OUT, help="where to write the sample (default: mainnet_sample.json here)")
    args = parser.parse_args(argv)

    if args.slots:
        slots = parse_slots(args.slots)
    else:
        head = rpc("getSlot", [{"commitment": "finalized"}])["result"]
        print(f"finalized head {head}", flush=True)
        slots = [head - 80 - i * STRIDE for i in range(BLOCKS)]

    rows, fetched = fetch(slots, require_all=bool(args.slots))

    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(
            {"endpoint_kind": endpoint_kind(), "slots": fetched, "count": len(rows), "rows": rows},
            f,
        )
    with open(args.out, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    print(f"\nwrote {len(rows)} transactions from {len(fetched)} blocks to {args.out}", flush=True)
    print(f"slots: {','.join(str(s) for s in fetched)}", flush=True)
    print(f"sha256: {digest}", flush=True)
    by_version = {}
    for r in rows:
        by_version[r["version"]] = by_version.get(r["version"], 0) + 1
    print("versions:", by_version, flush=True)
    print("failed on chain:", sum(1 for r in rows if r["err"]), flush=True)


if __name__ == "__main__":
    sys.exit(main())
