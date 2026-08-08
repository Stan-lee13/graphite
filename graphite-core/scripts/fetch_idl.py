#!/usr/bin/env python3
"""Fetch on-chain Anchor IDLs for verified Solana programs (P11 evidence).

IDLs live at PDA(seeds=[b"anchor:idl", program_id], program_id) and are
owned by the program itself. Uses only the public mainnet RPC.
"""
import base64
import hashlib
import json
import struct
import sys
import urllib.request

RPC = "https://api.mainnet-beta.solana.com"

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + B58_ALPHABET.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw


def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58_ALPHABET[r] + out
    pad = len(b) - len(b.lstrip(b"\x00"))
    return "1" * pad + out


def find_pda(seeds: list[bytes], program_id: bytes) -> tuple[bytes, int]:
    for bump in range(255, -1, -1):
        data = b"".join(seeds) + bytes([bump]) + program_id + b"ProgramDerivedAddress"
        h = hashlib.sha256(data).digest()
        # on-curve check: last byte < 0x80 means valid ed25519 point (approx; anchor uses this)
        if h[31] < 0x80:
            return h, bump
    raise RuntimeError("no bump found")


def rpc(method: str, params: list) -> dict:
    req = urllib.request.Request(
        RPC,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def fetch_idl(program_id_b58: str) -> dict | None:
    pid = b58decode(program_id_b58)
    if len(pid) != 32:
        print(f"  {program_id_b58}: INVALID pubkey ({len(pid)} bytes)")
        return None
    idl_addr, bump = find_pda([b"anchor:idl", pid], pid)
    idl_b58 = b58encode(idl_addr)
    r = rpc("getAccountInfo", [idl_b58, {"encoding": "base64"}])
    val = r.get("result", {}).get("value")
    if val is None:
        print(f"  {program_id_b58}: no on-chain IDL account at {idl_b58}")
        return None
    data = base64.b64decode(val["data"][0])
    # Anchor IDL account layout: 8-byte anchor discriminator + u32 LE len + JSON
    if len(data) < 12:
        print(f"  {program_id_b58}: IDL account too small ({len(data)} bytes)")
        return None
    disc = data[:8].hex()
    (dlen,) = struct.unpack("<I", data[8:12])
    body = data[12 : 12 + dlen]
    try:
        idl = json.loads(body.decode("utf-8"))
    except Exception as e:
        print(f"  {program_id_b58}: IDL decode failed ({e}) disc={disc}")
        return None
    return idl


def main():
    targets = {
        "pump.fun": "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P",
        "jupiter-dca": "DCA265Vj8a9CEuX1eb1LWRnDT7uK6q1xMipnNyatn23M",
        "metaplex-token-metadata": "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s",
    }
    out = {}
    for name, pid in targets.items():
        print(f"=== {name} ({pid}) ===")
        idl = fetch_idl(pid)
        if not idl:
            continue
        # Anchor v0.30+: instructions are under idl["instructions"] each with
        # a "discriminator" field; older: [8-byte sha256 prefix].
        instrs = idl.get("instructions", [])
        print(f"  {len(instrs)} instructions:")
        for ix in instrs:
            disc = ix.get("discriminator")
            if not disc:
                nm = ix["name"]
                h = hashlib.sha256(f"global:{nm}".encode()).digest()[:8]
                disc = h.hex()
            print(f"    {ix['name']}: {disc}")
        out[name] = {
            "program_id": pid,
            "instructions": [
                {"name": i["name"], "discriminator": i.get("discriminator") or hashlib.sha256(f"global:{i['name']}".encode()).digest()[:8].hex()}
                for i in instrs
            ],
        }
    with open("scripts/verified_idls.json", "w") as f:
        json.dump(out, f, indent=2)
    print("\nSaved scripts/verified_idls.json")


if __name__ == "__main__":
    main()
