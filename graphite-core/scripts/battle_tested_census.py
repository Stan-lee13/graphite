#!/usr/bin/env python3
"""Measure, on mainnet, what "battle tested" is supposed to mean.

For every seed manifest (or the program ids given on the command line) this
records three independent measurements and nothing else:

  1. IDENTITY   - getAccountInfo: the account exists and is executable, and
                  under which loader.
  2. VOLUME     - getSignaturesForAddress, paged: how many SUCCESSFUL
                  transactions CARRY THE PROGRAM'S ADDRESS, and over what
                  wall-clock window. Paging stops at --target successes. Note
                  the wording: the address index returns every transaction
                  that mentions the address, which is not the same as every
                  transaction that invokes it - Drift's recent signatures are
                  mostly transactions that load its address through a lookup
                  table and then call something else. Volume alone therefore
                  cannot establish use; that is what DECODE is for, and why a
                  program must clear both.
  3. DECODE     - a sample of those successful transactions is re-read and
                  every instruction that targets the program is resolved
                  against the manifest by the SAME prefix rule the engine
                  uses. The output is the fraction of REAL on-chain
                  instructions the manifest can name.

Nothing is asserted. protocols/battle_tested_evidence.json is the record, and
tests/battle_tested_evidence.rs refuses any manifest that declares a tier this
file does not support.

Read-only public RPC. No keys, no signing, no writes to chain.
"""
import argparse
import json
import sys
import threading
import time
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from solana_keys import b58decode  # noqa: E402

HERE = Path(__file__).resolve().parent
PROTOCOLS = HERE.parent / "protocols"
OUT = PROTOCOLS / "battle_tested_evidence.json"
RPC = "https://api.mainnet-beta.solana.com"

# The thresholds a manifest must clear to DECLARE BattleTested. The volume bar
# mirrors semantic_graph_store::thresholds::BATTLE_TESTED_TX (1000) - the same
# number the runtime applies to earned evidence, applied to the shipped
# manifest.
MIN_SUCCESSFUL_TXS = 1000
MIN_DECODED_INSTRUCTIONS = 20
MIN_DECODE_RATE = 0.90

# An Anchor program emits an event by CPI-ing ITSELF with this discriminator
# (sha256("anchor:event")[0..8]). It appears in the trace as an instruction
# targeting the program, but no caller ever sends it and no IDL lists it among
# the program's instructions - it is the program talking to the log. Counting
# it as an instruction the manifest "failed to name" put Jupiter V6 at a 0.46
# decode rate when every instruction anyone actually sent it was named.
ANCHOR_EVENT_CPI = "e445a52e51cb9a1d"


# The public endpoint rate-limits hard enough that an unpaced loop silently
# loses most of its sample: the first run of this script drew 2 usable
# transactions out of 12 requested, which would have understated decode
# coverage as "no evidence".
# Deliberately gentle. This runs against somebody else's public endpoint, and
# the earlier, faster settings (0.10 s, 12 workers) drew enough throttling that
# a single `getAccountInfo` took over ten minutes to come back. A census is not
# worth degrading a shared resource for, and a throttled run is slower than a
# paced one anyway.
PACE_SECONDS = 0.35
_last_call = [0.0]
_pace_lock = threading.Lock()


def rpc(method, params, tries=6, timeout=90):
    # One global pace across all workers: the endpoint limits per IP, not per
    # thread, and an unpaced pool just converts throughput into 429s.
    with _pace_lock:
        wait = PACE_SECONDS - (time.time() - _last_call[0])
        if wait > 0:
            time.sleep(wait)
        _last_call[0] = time.time()
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    delay = 1.0
    for attempt in range(tries):
        try:
            req = urllib.request.Request(RPC, data=body, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                out = json.loads(r.read())
            if "error" in out:
                code = out["error"].get("code")
                if code in (-32004, -32007, -32009, -32014, -32602):
                    return None
                raise RuntimeError(out["error"])
            return out["result"]
        except RuntimeError:
            raise
        except Exception:
            if attempt == tries - 1:
                return None
            time.sleep(delay)
            delay = min(delay * 2, 20)
    return None


def identity(pid):
    # dataSlice of zero bytes. `executable` and `owner` are top-level fields;
    # the account DATA of a program is its whole ELF, and asking for it 131
    # times pulls hundreds of megabytes through the same connections the rest
    # of the census is queued behind. Slicing it away took this run from three
    # programs in twenty minutes to the whole set in minutes.
    v = rpc("getAccountInfo",
            [pid, {"encoding": "base64", "dataSlice": {"offset": 0, "length": 0}}])
    if not v or not v.get("value"):
        return {"exists": False}
    val = v["value"]
    return {
        "exists": True,
        "executable": bool(val["executable"]),
        "loader": val["owner"],
    }


def volume(pid, target, max_pages):
    """Page backwards until `target` successful txs are counted."""
    successes = 0
    scanned = 0
    pages = 0
    before = None
    newest = oldest = None
    newest_slot = oldest_slot = None
    sample_sigs = []
    answered = False
    while successes < target and pages < max_pages:
        params = {"limit": 1000}
        if before:
            params["before"] = before
        res = rpc("getSignaturesForAddress", [pid, params])
        if res is None:
            break
        answered = True
        if not res:
            break
        pages += 1
        scanned += len(res)
        for e in res:
            if newest_slot is None:
                newest_slot, newest = e["slot"], e.get("blockTime")
            oldest_slot, oldest = e["slot"], e.get("blockTime")
            if e.get("err") is None:
                successes += 1
                if len(sample_sigs) < 400:
                    sample_sigs.append(e["signature"])
        before = res[-1]["signature"]
        if len(res) < 1000:
            break
    return {
        "counts": "successful transactions whose account list carries the "
                  "program address (getSignaturesForAddress); invocation is "
                  "established by the decode sample, not by this number",
        "endpoint_answered": answered,
        "successful_transactions_counted": successes,
        "signatures_scanned": scanned,
        "pages": pages,
        "reached_target": successes >= target,
        "newest_slot": newest_slot,
        "oldest_slot": oldest_slot,
        "newest_block_time": newest,
        "oldest_block_time": oldest,
        "window_seconds": (newest - oldest) if (newest and oldest) else None,
    }, sample_sigs


def keys_of(tx):
    msg = tx["transaction"]["message"]
    keys = list(msg["accountKeys"])
    loaded = (tx.get("meta") or {}).get("loadedAddresses") or {}
    keys += list(loaded.get("writable") or [])
    keys += list(loaded.get("readonly") or [])
    return keys


def sweep_blocks(n_blocks, spacing, wanted):
    """Collect observed instruction bytes for every wanted program at once.

    One `getBlock` yields ~1,000 transactions and covers every program in
    them, so N blocks cost N requests instead of N-programs x M signatures.
    Measuring 131 manifests one signature at a time was on course for twenty
    hours against the public endpoint; this is the same evidence, read the
    cheap way, and it is drawn from whole blocks rather than from one
    program's own signature list.

    Returns {program_id: (Counter(leading_8_bytes), anchor_event_count,
             transactions_seen)}.
    """
    tip = rpc("getSlot", [{"commitment": "finalized"}])
    out = {p: [Counter(), 0, 0] for p in wanted}
    blocks = 0
    for i in range(n_blocks):
        slot = tip - 80 - i * spacing
        blk = rpc(
            "getBlock",
            [slot, {"encoding": "json", "transactionDetails": "full",
                    "rewards": False, "maxSupportedTransactionVersion": 1}],
            timeout=180,
        )
        if not blk:
            continue
        blocks += 1
        for tx in blk["transactions"]:
            meta = tx.get("meta") or {}
            if meta.get("err"):
                continue
            keys = keys_of(tx)
            ixs = list(tx["transaction"]["message"]["instructions"])
            for grp in (meta.get("innerInstructions") or []):
                ixs += grp["instructions"]
            hit = set()
            for ix in ixs:
                idx = ix.get("programIdIndex")
                if idx is None or idx >= len(keys):
                    continue
                pid = keys[idx]
                if pid not in out:
                    continue
                try:
                    data = b58decode(ix.get("data") or "")
                except Exception:
                    continue
                head = data[:8].hex()
                if head == ANCHOR_EVENT_CPI:
                    out[pid][1] += 1
                    continue
                out[pid][0][head] += 1
                hit.add(pid)
            for pid in hit:
                out[pid][2] += 1
        print(f"  block sweep {blocks}/{i+1} slot {slot} "
              f"({sum(1 for v in out.values() if sum(v[0].values()) >= MIN_DECODED_INSTRUCTIONS)}"
              f"/{len(out)} programs already at the sample floor)", flush=True)
    return out, blocks


def decode_census(pid, sigs, manifest, sample_size, prior=None):
    """Resolve real observed instructions against the manifest.

    `prior` is what the block sweep already saw for this program. The
    signature-by-signature fallback runs only when the sweep did not reach the
    sample floor, which is the case for programs too infrequent to show up in
    a few dozen blocks.
    """
    discs = [(i["name"], i["discriminator"].lower()) for i in manifest["instructions"]]
    # A manifest whose instructions carry no discriminator (the Memo family:
    # the entire data field IS the memo) cannot name anything by prefix, and
    # the engine does not pretend otherwise - `discriminator_matches` returns
    # false for an empty selector. Measuring it on this axis would report 0%
    # as though the manifest were wrong, so it is reported as not applicable.
    decodable = any(d for _, d in discs)
    observed = Counter()
    matched = Counter()
    unmatched = Counter()
    txs_used = 0
    requested = 0
    unavailable = 0
    events = 0
    from_blocks = 0
    if prior is not None:
        heads, events, txs_used = prior
        for head, n in heads.items():
            observed[head] += n
        from_blocks = sum(heads.values())
    needed = 0 if sum(observed.values()) >= MIN_DECODED_INSTRUCTIONS else sample_size
    for sig in sigs[:needed]:
        requested += 1
        tx = rpc(
            "getTransaction",
            [sig, {"encoding": "json", "maxSupportedTransactionVersion": 1}],
            tries=8,
        )
        if not tx:
            # A transaction the endpoint would not return is NOT evidence that
            # the program is idle. Counted separately so a rate-limited run
            # reads as "could not measure" instead of "nothing observed".
            unavailable += 1
            continue
        keys = keys_of(tx)
        ixs = list(tx["transaction"]["message"]["instructions"])
        for inner in ((tx.get("meta") or {}).get("innerInstructions") or []):
            ixs += inner["instructions"]
        hit = False
        for ix in ixs:
            idx = ix.get("programIdIndex")
            if idx is None or idx >= len(keys) or keys[idx] != pid:
                continue
            hit = True
            try:
                data = b58decode(ix.get("data") or "")
            except Exception:
                continue
            head = data[:8].hex()
            if head == ANCHOR_EVENT_CPI:
                events += 1
                continue
            observed[head] += 1
        if hit:
            txs_used += 1
    # Resolve ONCE, over everything observed from either source, so the two
    # paths cannot disagree about what the manifest can name.
    for head, n in observed.items():
        name = next((nm for nm, d in discs if d and head.startswith(d)), None)
        if name:
            matched[name] += n
        else:
            unmatched[head] += n
    total = sum(observed.values())
    return {
        "transactions_requested": requested,
        "transactions_unavailable": unavailable,
        "transactions_sampled": txs_used,
        "anchor_event_cpis_excluded": events,
        "instructions_from_block_sweep": from_blocks,
        "decode_applicable": decodable,
        "instructions_observed": total,
        "instructions_named_by_manifest": sum(matched.values()),
        "decode_rate": ((sum(matched.values()) / total) if total else None) if decodable else None,
        "instructions_by_name": dict(matched.most_common()),
        "unmatched_leading_bytes": dict(unmatched.most_common(12)),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("program_ids", nargs="*")
    ap.add_argument("--target", type=int, default=MIN_SUCCESSFUL_TXS)
    ap.add_argument("--max-pages", type=int, default=4)
    ap.add_argument("--sweep-cache", default=str(HERE / "out" / "block_sweep.json"),
                    help="where the block sweep is cached, so a restart does not re-read blocks")
    ap.add_argument("--sample", type=int, default=80)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--blocks", type=int, default=40,
                    help="finalized blocks to sweep for decode evidence before "
                         "falling back to per-program signature sampling")
    ap.add_argument("--block-spacing", type=int, default=250)
    ap.add_argument("--merge", action="store_true",
                    help="keep existing records for programs not measured in this run")
    args = ap.parse_args()

    manifests = {}
    for f in sorted(PROTOCOLS.glob("*.json")):
        if f.name in ("verified_program_ids.json", "battle_tested_evidence.json"):
            continue
        m = json.loads(f.read_text(encoding="utf-8"))
        manifests[m["protocol"]["program_id"]] = (f.name, m)

    targets = args.program_ids or list(manifests)
    block_obs = {}
    cache = Path(args.sweep_cache) if args.sweep_cache else None
    if args.blocks and cache and cache.exists():
        raw = json.loads(cache.read_text(encoding="utf-8"))
        block_obs = {p: [Counter(v[0]), v[1], v[2]] for p, v in raw["programs"].items()}
        print(f"reusing the block sweep cached in {cache} "
              f"({raw['blocks']} blocks, {len(block_obs)} programs)", flush=True)
    elif args.blocks:
        print(f"sweeping {args.blocks} finalized blocks for decode evidence", flush=True)
        block_obs, swept = sweep_blocks(args.blocks, args.block_spacing, set(targets))
        if cache:
            cache.write_text(json.dumps({
                "blocks": swept,
                "programs": {p: [dict(v[0]), v[1], v[2]] for p, v in block_obs.items()},
            }, indent=1), encoding="utf-8")
    if block_obs:
        ready = sum(1 for v in block_obs.values()
                    if sum(v[0].values()) >= MIN_DECODED_INSTRUCTIONS)
        print(f"{ready}/{len(targets)} programs reached the "
              f"{MIN_DECODED_INSTRUCTIONS}-instruction floor from blocks alone", flush=True)
    records = {}
    if args.merge and OUT.exists():
        prev = json.loads(OUT.read_text(encoding="utf-8"))
        records = {r["program_id"]: r for r in prev.get("programs", [])}

    lock = threading.Lock()
    done = [0]

    def write_out():
        OUT.write_text(json.dumps({
            "note": "Measured on mainnet, read-only. A manifest may declare BattleTested only "
                    "with a record here that meets every threshold below. Reproduce with "
                    "graphite-core/scripts/battle_tested_census.py.",
            "rpc": RPC,
            "thresholds": {
                "min_successful_transactions": MIN_SUCCESSFUL_TXS,
                "min_decoded_instructions": MIN_DECODED_INSTRUCTIONS,
                "min_decode_rate": MIN_DECODE_RATE,
            },
            "programs": [records[k] for k in sorted(records)],
        }, indent=1), encoding="utf-8")

    def measure(pid):
        if pid not in manifests:
            print(f"{pid}: no manifest - skipped", flush=True)
            return
        fname, manifest = manifests[pid]
        ident = identity(pid)
        vol, sigs = volume(pid, args.target, args.max_pages)
        prior = None
        if pid in block_obs:
            heads, ev, seen = block_obs[pid]
            prior = (heads, ev, seen)
        dec = decode_census(pid, sigs, manifest, args.sample, prior)
        rec = {
            "program_id": pid,
            "manifest": fname,
            "name": manifest["protocol"]["name"],
            "declared_trust_tier": manifest["trust_tier"],
            "measured_at_unix": int(time.time()),
            "identity": ident,
            "volume": vol,
            "decode": dec,
            "meets_battle_tested": bool(
                ident.get("executable")
                and vol["successful_transactions_counted"] >= MIN_SUCCESSFUL_TXS
                and (dec["instructions_observed"] or 0) >= MIN_DECODED_INSTRUCTIONS
                and (dec["decode_rate"] or 0) >= MIN_DECODE_RATE
            ),
        }
        with lock:
            records[pid] = rec
            done[0] += 1
            print(
                f"[{done[0]}/{len(targets)}] {fname}: "
                f"{vol['successful_transactions_counted']} ok txs "
                f"in {vol['window_seconds']}s, {dec['instructions_observed']} ix observed, "
                f"decode={dec['decode_rate']}, battle_tested={rec['meets_battle_tested']}",
                flush=True,
            )
            write_out()

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        list(pool.map(measure, targets))

    n = sum(1 for r in records.values() if r["meets_battle_tested"])
    print(f"\n{n}/{len(records)} programs meet the battle-tested bar - wrote {OUT}")


if __name__ == "__main__":
    main()
