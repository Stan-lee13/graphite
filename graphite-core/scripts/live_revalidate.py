#!/usr/bin/env python3
"""Live re-validation of all seed manifest program IDs AND the program-ID
registry on mainnet, plus the claimed SAK devnet signature.

Parses IDs from the manifests themselves and from
protocols/verified_program_ids.json (no hardcoding) so this stays correct as
the registry grows. Only files that carry a `protocol.program_id` are treated
as manifests — non-manifest JSON files (e.g. verified_program_ids.json) are
skipped, not crashed on.

Exit code is non-zero if any checked ID is missing/not executable, so this can
gate CI or a deploy step.
"""
import json
import os
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROTOCOLS = os.path.join(ROOT, "protocols")
REGISTRY_FILE = os.path.join(PROTOCOLS, "verified_program_ids.json")

MAINNET = "https://api.mainnet-beta.solana.com"
DEVNET = "https://api.devnet.solana.com"
SAK_SIG = "xHa4dyuFS6JmSaTsmhcMpEtwbWnPjBoUGwk3wNixD2uw2Wmeui6GhnSmmdzNVkv85zXSd6g7QYhHymAjciwP3jJ"


def rpc(url, method, params):
    req = urllib.request.Request(
        url,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)


def load_manifest_ids():
    """Map filename -> program_id for every file that is a protocol manifest
    (has a `protocol.program_id` key). Non-manifest JSON files are skipped."""
    ids = {}
    for f in sorted(os.listdir(PROTOCOLS)):
        if not f.endswith(".json"):
            continue
        path = os.path.join(PROTOCOLS, f)
        with open(path) as fh:
            data = json.load(fh)
        protocol = data.get("protocol")
        if not isinstance(protocol, dict) or not protocol.get("program_id"):
            print(f"  (skip non-manifest JSON: {f})")
            continue
        ids[f] = protocol["program_id"]
    return ids


def load_registry_ids():
    """Map program name -> program_id from verified_program_ids.json."""
    with open(REGISTRY_FILE) as fh:
        data = json.load(fh)
    return {p["name"]: p["program_id"] for p in data.get("programs", [])}


def check_ids(label, ids):
    """Check every ID in the dict on mainnet; returns list of failures."""
    failures = []
    for name, pid in sorted(ids.items()):
        try:
            res = rpc(MAINNET, "getAccountInfo", [pid, {"encoding": "jsonParsed"}])
            value = (res.get("result") or {}).get("value")
            executable = bool(value and value.get("executable"))
            if executable:
                print(f"  EXEC  {name:<40} {pid}")
            else:
                failures.append((name, pid, "account absent or not executable"))
                print(f"  ABSENT {name:<38} {pid}")
        except Exception as e:  # noqa: BLE001
            failures.append((name, pid, f"rpc error: {e}"))
            print(f"  ERROR {name:<38} {pid} ({e})")
    print(f"{label}: {len(ids) - len(failures)}/{len(ids)} executable, {len(failures)} failures")
    for name, pid, why in failures:
        print(f"  - {name}: {pid} -> {why}")
    return failures


def main():
    manifest_ids = load_manifest_ids()
    registry_ids = load_registry_ids()

    # Every manifest ID must appear in the registry (bidirectional consistency)
    # and every registry ID must be executable on mainnet. The registry is the
    # single source of truth; the manifest set is cross-checked against it.
    registry_set = set(registry_ids.values())
    orphan_manifests = {k: v for k, v in manifest_ids.items() if v not in registry_set}
    if orphan_manifests:
        print(f"ERROR: manifests not in registry: {orphan_manifests}")
        sys.exit(1)
    missing_manifests = {k: v for k, v in registry_ids.items() if v not in set(manifest_ids.values())}
    if missing_manifests:
        print(f"ERROR: registry programs missing from manifests: {missing_manifests}")
        sys.exit(1)

    print(f"checking {len(registry_ids)} registry IDs + {len(manifest_ids)} manifests on mainnet...")
    failures = check_ids("registry (single source of truth)", registry_ids)
    failures += check_ids("manifests (consistency)", manifest_ids)

    # SAK devnet signature re-validation
    print(f"\nSAK devnet signature: {SAK_SIG}")
    try:
        tx = rpc(DEVNET, "getTransaction", [SAK_SIG, {"encoding": "json", "maxSupportedTransactionVersion": 0}])
        result = tx.get("result")
        if result is None:
            print("  NOT FOUND — claim cannot be re-verified today")
        else:
            meta = result.get("meta") or {}
            err = meta.get("err")
            slot = result.get("slot")
            print(f"  status: {'Ok' if err is None else err}, slot {slot}, fee {meta.get('fee')}")
            msgs = result.get("transaction", {}).get("message", {})
            acct_keys = (msgs.get("accountKeys") or [])
            if isinstance(acct_keys, list) and acct_keys:
                print(f"  accounts[0]: {acct_keys[0] if isinstance(acct_keys[0], str) else acct_keys[0].get('pubkey')}")
    except Exception as e:  # noqa: BLE001
        print(f"  rpc error: {e}")

    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
