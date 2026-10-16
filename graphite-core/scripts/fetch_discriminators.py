#!/usr/bin/env python3
"""Extract REAL instruction discriminators from live mainnet transactions (P16 evidence).

For each target program, fetch recent transactions, pull the raw instruction
bytes (base64), and report the first 8 bytes (Anchor discriminator) or first
byte (native variant) for instructions invoking the target program.
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
import base64
import json
import urllib.request


def b64dec(data):
    """Robust base64 decode handling string or [b64, enc] list shapes."""
    if isinstance(data, list):
        data = data[0]
    if not isinstance(data, str):
        return b""
    try:
        return base64.b64decode(data + "===" if len(data) % 4 else data)
    except Exception:
        try:
            return base64.b64decode(data)
        except Exception:
            return b""

RPC = "https://api.mainnet-beta.solana.com"

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + B58_ALPHABET.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw


def rpc(method: str, params: list) -> dict:
    req = urllib.request.Request(
        RPC,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=40) as resp:
        return json.loads(resp.read())


def fetch(program_id_b58: str, n: int = 6) -> None:
    sigs = rpc("getSignaturesForAddress", [program_id_b58, {"limit": n}])
    seen = set()
    print(f"=== {program_id_b58} ===")
    for s in sigs.get("result", []):
        sig = s["signature"]
        tx = rpc("getTransaction", [sig, {"encoding": "json", "maxSupportedTransactionVersion": 0}])
        val = tx.get("result")
        if not val:
            print(f"  {sig[:12]}: no result")
            continue
        msg = val["transaction"]["message"]
        # v0 or legacy: accountKeys at msg["accountKeys"]; instructions at msg["instructions"]
        keys = [k if isinstance(k, str) else k["pubkey"] for k in msg.get("accountKeys", [])]
        inner = val.get("meta", {}).get("innerInstructions", [])
        idx = 0
        for inst in msg.get("instructions", []):
            pid = keys[inst["programIdIndex"]]
            if pid == program_id_b58:
                data = b64dec(inst["data"])
                d = data[:8].hex() if len(data) >= 8 else data.hex()
                if d not in seen:
                    seen.add(d)
                    print(f"  outer[{idx}] {sig[:16]} data[:8]={d} len={len(data)}")
            idx += 1
        for ii in inner:
            for inst in ii.get("instructions", []):
                pid = keys[inst["programIdIndex"]]
                if pid == program_id_b58:
                    data = b64dec(inst["data"])
                    d = data[:8].hex() if len(data) >= 8 else data.hex()
                    if d not in seen:
                        seen.add(d)
                        print(f"  inner  {sig[:16]} data[:8]={d} len={len(data)}")
    print(f"  -> {len(seen)} distinct discriminators observed on-chain\n")


def main():
    targets = {
        "pump.fun": "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P",
        "jupiter-dca": "DCA265Vj8a9CEuX1eb1LWRnDT7uK6q1xMipnNyatn23M",
        "wormhole-core": "worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth",
    }
    for name, pid in targets.items():
        try:
            fetch(pid)
        except Exception as e:
            print(f"{name}: error {e}")


if __name__ == "__main__":
    main()
