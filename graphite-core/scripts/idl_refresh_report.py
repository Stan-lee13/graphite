#!/usr/bin/env python3
"""What the `idl-refresh` workflow prints (Round 41). Read-only.

  compare OLD NEW       the difference between a committed on-chain IDL and
                        the one just fetched: its instructions, and every
                        variant of its Swap / CandidateSwap enums (the Core
                        reads a Jupiter route's steps by these, by position)
  txs PROGRAM SIG...    each executed transaction's top-level instructions to
                        PROGRAM, with their data in hex, from the public RPC
  deployments INDEX ID... each program's last deployment slot and upgrade
                        authority, from fetch_onchain_idls.py's idl_index.json

Nothing is signed or sent; the RPC is the one fetch_onchain_idls.py reads.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fetch_onchain_idls import rpc  # noqa: E402
from solana_keys import b58decode  # noqa: E402

ENUMS = ("Swap", "CandidateSwap")


def variants(idl, name):
    for t in idl.get("types") or []:
        if t.get("name") == name and (t.get("type") or {}).get("kind") == "enum":
            return [(v["name"], json.dumps(v.get("fields") or [], sort_keys=True))
                    for v in t["type"]["variants"]]
    return None


def compare(old_path, new_path):
    old = json.loads(Path(old_path).read_text(encoding="utf-8"))
    new = json.loads(Path(new_path).read_text(encoding="utf-8"))
    changed = False
    old_ix = {i["name"]: json.dumps(i, sort_keys=True) for i in old.get("instructions") or []}
    new_ix = {i["name"]: json.dumps(i, sort_keys=True) for i in new.get("instructions") or []}
    print(f"instructions: {len(old_ix)} committed, {len(new_ix)} deployed")
    for n in sorted(set(new_ix) - set(old_ix)):
        changed = True
        print(f"  added: {n}")
    for n in sorted(set(old_ix) - set(new_ix)):
        changed = True
        print(f"  removed: {n}")
    for n in sorted(set(old_ix) & set(new_ix)):
        if old_ix[n] != new_ix[n]:
            changed = True
            print(f"  changed: {n}")
    for enum in ENUMS:
        a, b = variants(old, enum), variants(new, enum)
        if a is None and b is None:
            continue
        a, b = a or [], b or []
        print(f"{enum}: {len(a)} variants committed, {len(b)} deployed")
        for i in range(max(len(a), len(b))):
            was = a[i] if i < len(a) else None
            now = b[i] if i < len(b) else None
            if was == now:
                continue
            changed = True
            if was is None:
                print(f"  {i} added: {now[0]} {now[1]}")
            elif now is None:
                print(f"  {i} removed: {was[0]} {was[1]}")
            else:
                print(f"  {i} changed: {was[0]} {was[1]} -> {now[0]} {now[1]}")
    print("the deployed IDL differs from the committed one" if changed
          else "the deployed IDL is the committed one")


def txs(program, sigs):
    for sig in sigs:
        try:
            tx = rpc("getTransaction", [sig, {"encoding": "json", "maxSupportedTransactionVersion": 0,
                                              "commitment": "finalized"}])
        except Exception as e:  # one unreadable transaction is reported, not fatal
            print(f"{sig}: not read ({e})")
            continue
        if tx is None:
            print(f"{sig}: not found")
            continue
        msg = tx["transaction"]["message"]
        loaded = (tx.get("meta") or {}).get("loadedAddresses") or {}
        keys = msg["accountKeys"] + loaded.get("writable", []) + loaded.get("readonly", [])
        print(f"{sig}: slot {tx['slot']}, {len(msg['instructions'])} top-level instructions")
        for n, ix in enumerate(msg["instructions"]):
            if keys[ix["programIdIndex"]] != program:
                continue
            data = b58decode(ix["data"])
            print(f"  ix {n}: {len(data)} bytes {data.hex()}")


def deployments(index_path, ids):
    """Each program's identity as fetch_onchain_idls.py read it: its last
    deployment slot and upgrade authority."""
    index = {p["program_id"]: p for p in json.loads(Path(index_path).read_text(encoding="utf-8"))["programs"]}
    for pid in ids:
        p = index.get(pid)
        if p is None:
            print(f"{pid}: not read")
            continue
        print(f"{pid}: last deployed at slot {p.get('last_deployed_slot')}, upgrade authority "
              f"{p.get('upgrade_authority') or ('none (immutable)' if p.get('immutable') else 'not read')}")


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "compare":
        compare(sys.argv[2], sys.argv[3])
    elif len(sys.argv) >= 3 and sys.argv[1] == "deployments":
        deployments(sys.argv[2], sys.argv[3:])
    elif len(sys.argv) >= 3 and sys.argv[1] == "txs":
        txs(sys.argv[2], sys.argv[3:])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
