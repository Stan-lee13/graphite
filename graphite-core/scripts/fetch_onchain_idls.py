#!/usr/bin/env python3
"""Fetch each program's on-chain identity and its own published Anchor IDL.

For every program id given (or the top N of scripts/out/inventory_census.json):

  * getAccountInfo(program)          -> executable, owner (loader), size
  * the upgradeable loader's program-data account -> upgrade authority, slot
  * Anchor IDL account               -> the program's OWN published interface

The IDL address is `create_with_seed(find_program_address([], pid), "anchor:idl",
pid)` and the account is owned by the program itself, so a fetched IDL is the
deployed program's own statement about its instruction surface — not a
third-party copy that could have drifted.

Output: scripts/out/onchain_idls/<program_id>.json + out/idl_index.json
"""
import base64
import json
import struct
import sys
import time
import urllib.error
import urllib.request
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from solana_keys import anchor_idl_address, b58encode, b58decode  # noqa: E402

RPC = "https://api.mainnet-beta.solana.com"
HERE = Path(__file__).resolve().parent
OUTDIR = HERE / "out" / "onchain_idls"
UPGRADEABLE_LOADER = "BPFLoaderUpgradeab1e11111111111111111111111"


PACE_SECONDS = 0.22
_last = [0.0]


def rpc(method, params, tries=6):
    wait = PACE_SECONDS - (time.time() - _last[0])
    if wait > 0:
        time.sleep(wait)
    _last[0] = time.time()
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    delay = 1.0
    for attempt in range(tries):
        try:
            req = urllib.request.Request(RPC, data=body, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=90) as r:
                out = json.loads(r.read())
            if "error" in out:
                raise RuntimeError(out["error"])
            return out["result"]
        except Exception:
            if attempt == tries - 1:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 20)


def account(pubkey, slice_len=None):
    """Fetch an account.

    `slice_len` matters: a program account carries its whole ELF, so an
    unsliced read of 200 programs pulls hundreds of megabytes over a public
    endpoint and turns a two-minute job into a two-hour one. Only the header
    is needed to learn the loader and the program-data pointer.
    """
    cfg = {"encoding": "base64"}
    if slice_len is not None:
        cfg["dataSlice"] = {"offset": 0, "length": slice_len}
    return rpc("getAccountInfo", [pubkey, cfg])["value"]


def program_identity(pid):
    v = account(pid, slice_len=36)
    if v is None:
        return {"program_id": pid, "exists": False}
    info = {
        "program_id": pid,
        "exists": True,
        "executable": bool(v["executable"]),
        "owner": v["owner"],
        "lamports": v["lamports"],
        "data_len": v.get("space"),
    }
    if v["owner"] == UPGRADEABLE_LOADER:
        raw = base64.b64decode(v["data"][0])
        # UpgradeableLoaderState::Program { programdata_address } = u32 tag + pubkey
        if len(raw) >= 36 and struct.unpack("<I", raw[:4])[0] == 2:
            pda = b58encode(raw[4:36])
            info["program_data_account"] = pda
            pv = account(pda, slice_len=45)
            if pv:
                praw = base64.b64decode(pv["data"][0])
                # ProgramData { slot: u64, upgrade_authority: Option<Pubkey> }
                if len(praw) >= 45:
                    info["last_deployed_slot"] = struct.unpack("<Q", praw[4:12])[0]
                    info["upgrade_authority"] = (
                        b58encode(praw[13:45]) if praw[12] == 1 else None
                    )
                    info["immutable"] = praw[12] == 0
    return info


def fetch_idl(pid):
    addr = anchor_idl_address(pid)
    v = account(addr)
    if v is None:
        return None, addr, "no IDL account"
    raw = base64.b64decode(v["data"][0])
    if v["owner"] != pid:
        return None, addr, f"IDL account owned by {v['owner']}, not the program"
    if len(raw) < 44:
        return None, addr, f"IDL account too small ({len(raw)} bytes)"
    (dlen,) = struct.unpack("<I", raw[40:44])
    body = raw[44 : 44 + dlen]
    try:
        return json.loads(zlib.decompress(body).decode("utf-8")), addr, None
    except Exception:
        try:
            return json.loads(body.decode("utf-8")), addr, None
        except Exception as e:
            return None, addr, f"IDL decode failed: {e}"


def main():
    args = sys.argv[1:]
    if args and not args[0].isdigit():
        pids = args
    else:
        top = int(args[0]) if args else 120
        census = json.loads((HERE / "out" / "inventory_census.json").read_text(encoding="utf-8"))
        pids = [p["program_id"] for p in census["programs"][:top]]

    OUTDIR.mkdir(parents=True, exist_ok=True)
    # Merge with whatever a previous run recorded: the inventory is walked in
    # chunks (the top 250 first, then the tail), and a fresh file would drop
    # everything the earlier chunk learned.
    index = []
    prev = HERE / "out" / "idl_index.json"
    if prev.exists():
        index = [p for p in json.loads(prev.read_text(encoding="utf-8"))["programs"]
                 if p["program_id"] not in set(pids)]
    for i, pid in enumerate(pids):
        try:
            ident = program_identity(pid)
        except Exception as e:
            print(f"[{i+1}/{len(pids)}] {pid}: identity failed: {e}", flush=True)
            continue
        if not ident.get("executable"):
            ident["idl"] = None
            ident["idl_error"] = "not an executable program account"
            index.append(ident)
            print(f"[{i+1}/{len(pids)}] {pid}: not executable — skipped", flush=True)
            continue
        try:
            idl, addr, err = fetch_idl(pid)
        except Exception as e:
            idl, addr, err = None, None, str(e)
        ident["idl_account"] = addr
        if idl is None:
            ident["idl"] = None
            ident["idl_error"] = err
            print(f"[{i+1}/{len(pids)}] {pid}: {err}", flush=True)
        else:
            meta = idl.get("metadata") or {}
            name = idl.get("name") or meta.get("name") or ""
            ver = idl.get("version") or meta.get("version") or ""
            ixs = idl.get("instructions") or []
            ident["idl"] = {
                "name": name,
                "version": ver,
                "instruction_count": len(ixs),
                "has_explicit_discriminators": bool(ixs and ixs[0].get("discriminator")),
                "spec": "new" if (ixs and ixs[0].get("discriminator")) else "old",
            }
            (OUTDIR / f"{pid}.json").write_text(json.dumps(idl, indent=1), encoding="utf-8")
            print(f"[{i+1}/{len(pids)}] {pid}: {name} v{ver} — {len(ixs)} ix "
                  f"({ident['idl']['spec']} spec)", flush=True)
        index.append(ident)

    (HERE / "out" / "idl_index.json").write_text(
        json.dumps({"fetched_at_unix": int(time.time()), "rpc": RPC, "programs": index}, indent=1),
        encoding="utf-8",
    )
    ok = sum(1 for p in index if p.get("idl"))
    print(f"\n{ok}/{len(index)} programs published an on-chain IDL")


if __name__ == "__main__":
    main()
