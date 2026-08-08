#!/usr/bin/env python3
"""Live re-validation of all seed manifest program IDs on mainnet, plus the
claimed SAK devnet signature. Parses IDs from the manifests themselves (no
hardcoding) so this stays correct as the registry grows."""
import json, os, sys, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROTOCOLS = os.path.join(ROOT, "protocols")

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


def main():
    ids = {}
    for f in sorted(os.listdir(PROTOCOLS)):
        if not f.endswith(".json"):
            continue
        with open(os.path.join(PROTOCOLS, f)) as fh:
            m = json.load(fh)
        pid = m["protocol"]["program_id"]
        ids[f] = pid

    print(f"checking {len(ids)} manifest IDs on mainnet...")
    exec_count, absent = 0, []
    for f, pid in sorted(ids.items()):
        try:
            res = rpc(MAINNET, "getAccountInfo", [pid, {"encoding": "jsonParsed"}])
            value = (res.get("result") or {}).get("value")
            executable = bool(value and value.get("executable"))
            if executable:
                exec_count += 1
                print(f"  EXEC  {f:<40} {pid}")
            else:
                absent.append((f, pid, "not executable"))
                print(f"  ABSENT {f:<38} {pid}")
        except Exception as e:  # noqa: BLE001
            absent.append((f, pid, f"rpc error: {e}"))
            print(f"  ERROR {f:<38} {pid} ({e})")

    print(f"\nmainnet: {exec_count}/{len(ids)} executable, {len(absent)} non-executable")
    for f, pid, why in absent:
        print(f"  - {f}: {pid} -> {why}")

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

    sys.exit(1 if absent else 0)


if __name__ == "__main__":
    main()
