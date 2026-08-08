#!/usr/bin/env python3
"""Fetch a REAL Squads V4 devnet transaction and analyze its instruction
data to ground the dynamic-PDA-seed work in on-chain reality."""
import base64
import json
import urllib.request

RPC = "https://api.devnet.solana.com"
SQUADS = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf"


def rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(RPC, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp).get("result")


def main():
    sigs = rpc("getSignaturesForAddress", [SQUADS, {"limit": 5}])
    if not sigs:
        print("no squads signatures")
        return
    for s in sigs:
        sig = s["signature"]
        r = rpc(
            "getTransaction",
            [sig, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}],
        )
        if not r or r.get("meta", {}).get("err"):
            continue
        msg = r["transaction"]["message"]
        ixs = msg.get("instructions", [])
        hits = []
        for i, ix in enumerate(ixs):
            prog = ix.get("programId")
            if isinstance(prog, dict):
                prog = prog.get("__programPubkey", "")
            if str(prog) == SQUADS:
                hits.append((i, ix))
        if not hits:
            continue
        print(f"tx {sig[:20]}… has {len(hits)} top-level Squads instruction(s)")
        for i, ix in hits:
            data_b58 = ix.get("data", "")
            print(f"  ix{i}: accounts={len(ix.get('accounts', []))} data_b58_len={len(data_b58)}")
            # base58 -> bytes head
            try:
                import base58
                raw = base58.b58decode(data_b58)
            except Exception:
                raw = b""
            print(f"    data hex head: {raw[:16].hex()}  ({len(raw)} bytes total)")
            # account list
            accs = ix.get("accounts", [])
            print(f"    account count: {len(accs)}; first 3: {[str(a)[:12] for a in accs[:3]]}")
        # Also dump any loaded addresses / created accounts
        meta = r.get("meta", {})
        print("    preTokenBalances:", len(meta.get("preTokenBalances", [])))
        return


if __name__ == "__main__":
    main()
