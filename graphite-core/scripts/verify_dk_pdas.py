#!/usr/bin/env python3
"""C27 — Acceptance test: every PDA grounded in the Drift/Kamino manifests must
re-derive REAL on-chain accounts.

Fetches a sample of real txs once per program (from the census cache), parses
every ix with its account list + raw data, then for each grounded
(instruction, account) in the manifests: resolve the seed templates
({account_N}, {instruction_data:S:E}, ASCII) against the actual tx, derive the
PDA, and require the provided account to match. A mismatch means the manifest
would flag legitimate transactions — the C26 failure mode.
"""
import hashlib
import json
import time
import urllib.request

RPC = "https://api.mainnet-beta.solana.com"
CACHE = "scripts/.census_dk_cache.json"
MANIFESTS = {
    "drift": "protocols/drift.json",
    "klend": "protocols/kamino-lending.json",
}
PROG = {
    "drift": "dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH",
    "klend": "KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD",
}
SAMPLE = 40  # txs per program


def rpc(method, params, tries=4):
    for i in range(tries):
        try:
            req = urllib.request.Request(
                RPC,
                data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r).get("result")
        except Exception:
            time.sleep(1.5 * (i + 1))
    return None


B58A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58(b):
    """Decode base58 to raw bytes (variable length, no padding)."""
    n = 0
    for ch in b:
        n = n * 58 + B58A.index(ch)
    return n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""


def b58pk(b):
    """Decode a base58 pubkey to exactly 32 bytes (leading zeros significant,
    e.g. the System program placeholder in Option accounts decodes to 0)."""
    n = 0
    for ch in b:
        n = n * 58 + B58A.index(ch)
    return n.to_bytes((n.bit_length() + 7) // 8, "big").rjust(32, b"\x00") if n else b"\x00" * 32


def b58enc(b):
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58A[r] + out
    return "1" * (32 - len(out)) + out


P = 2 ** 255 - 19
D = (-121665 * pow(121666, P - 2, P)) % P


def off_curve(h):
    y = int.from_bytes(h, "little") & ((1 << 255) - 1)
    if y >= P:
        return False
    yy = (y * y) % P
    u = (yy - 1) % P
    v = (D * yy + 1) % P
    return pow(u * pow(v, P - 2, P), (P - 1) // 2, P) != 1


def find_pda(seeds, prog_id):
    prog = b58(prog_id)
    for bump in range(255, -1, -1):
        pre = b"".join(seeds) + bytes([bump]) + prog + b"ProgramDerivedAddress"
        h = hashlib.sha256(pre).digest()
        if off_curve(h):
            return b58enc(h), bump
    return None, None


def resolve_template(tmpl, accts, data, prog_id):
    if tmpl.startswith("{account_"):
        idx = int(tmpl[len("{account_"):-1])
        return b58pk(accts[idx]) if idx < len(accts) else None
    if tmpl.startswith("{instruction_data:"):
        parts = tmpl[len("{instruction_data:"):-1].split(":")
        s, e = int(parts[0]), int(parts[1])
        return data[s:e]
    if tmpl.startswith("0x"):
        return bytes.fromhex(tmpl[2:])
    return tmpl.encode()


def fetch_ixs(sig, program):
    """Return list of (accts, data_bytes) for program ixs in one tx."""
    tx = rpc("getTransaction", [sig, {"encoding": "json", "maxSupportedTransactionVersion": 0}])
    if not tx:
        return []
    msg = tx["transaction"]["message"]
    keys = [k if isinstance(k, str) else k.get("pubkey", "") for k in msg.get("accountKeys", [])]
    loaded = ((tx.get("meta") or {}).get("loadedAddresses") or {})
    keys += loaded.get("writable", []) + loaded.get("readonly", [])
    out = []
    for ix in msg.get("instructions", []):
        idx = ix.get("programIdIndex")
        if idx is not None and idx < len(keys) and keys[idx] == program:
            out.append(([keys[i] for i in ix.get("accounts", []) if i < len(keys)],
                        b58(ix.get("data", "")) if ix.get("data") else b""))
    for ii in ((tx.get("meta") or {}).get("innerInstructions") or []):
        for ix in ii.get("instructions", []):
            idx = ix.get("programIdIndex")
            if idx is not None and idx < len(keys) and keys[idx] == program:
                out.append(([keys[i] for i in ix.get("accounts", []) if i < len(keys)],
                            b58(ix.get("data", "")) if ix.get("data") else b""))
    return out


def main():
    cache = json.load(open(CACHE))
    sigs = {p: [s.split(":", 1)[1] for s in cache["fetched"] if s.startswith(p + ":")]
            for p in PROG}

    total_checks = 0
    mismatches = 0
    for prog, mpath in MANIFESTS.items():
        manifest = json.load(open(mpath))
        prog_id = PROG[prog]
        # Collect all observed ixs from the tx sample (top + inner).
        pool = []  # (ix_name, disc_hex, accts, data, sig)
        for sig in sigs.get(prog, [])[:SAMPLE]:
            for accts, data in fetch_ixs(sig, prog_id):
                pool.append((None, data[:8].hex(), accts, data, sig))
        by_disc = {}
        for ix in manifest["instructions"]:
            by_disc.setdefault(ix["discriminator"], []).append(ix)

        grounded = []
        for ix in manifest["instructions"]:
            for a in ix.get("accounts", []):
                if a.get("pda_seeds"):
                    grounded.append((ix["name"], ix["discriminator"], a["name"],
                                     a["pda_seeds"], [x["name"] for x in ix["accounts"]]))
        print(f"=== {prog}: {len(grounded)} grounded PDAs, {len(pool)} observed ixs ===", flush=True)

        checked = set()
        for gname, gdisc, aname, tmpls, acc_names in grounded:
            if (gname, aname) in checked:
                continue
            checked.add((gname, aname))
            matched = False
            for _, disc, accts, data, sig in pool:
                if disc != gdisc:
                    continue
                seeds = []
                ok = True
                for t in tmpls:
                    r = resolve_template(t, accts, data, prog_id)
                    if r is None:
                        ok = False
                        break
                    seeds.append(r)
                if not ok:
                    continue
                try:
                    idx = acc_names.index(aname)
                except ValueError:
                    continue
                if idx >= len(accts):
                    continue
                real = accts[idx]
                pda, bump = find_pda(seeds, prog_id)
                status = "MATCH" if pda == real else "MISMATCH"
                if pda != real:
                    mismatches += 1
                total_checks += 1
                print(f"  {gname}.{aname}: {status} (bump {bump}) tx {sig[:20]}", flush=True)
                matched = True
                break
            if not matched:
                print(f"  {gname}.{aname}: NO LIVE TX OBSERVED (source-derived; not census-proven)", flush=True)
    print(f"\nTOTAL checked: {total_checks}, MISMATCHES: {mismatches}", flush=True)
    if mismatches:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
