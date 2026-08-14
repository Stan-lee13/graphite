#!/usr/bin/env python3
"""Rebuild manifest account lists from official program IDLs.

Sources (all fetched 2026-08-14, archived under e2e-scratch/idls/):
  - orca-whirlpools: e2e-scratch/idls/orca-whirlpools.json (Anchor,
    isMut/isSigner metadata) -- the deployed whirlpools program v0.9.0
    surface; swapV2/twoHopSwapV2 layouts corroborated live on mainnet.
  - meteora-dlmm: e2e-scratch/idls/meteora-dlmm.json (codama,
    writable/signer metadata) -- the deployed DLMM program IDL.
  - jupiter-v6: e2e-scratch/idls/jupiter.json (codama) for the
    legacy route family (matches live mainnet layouts, user-first with
    writable source/destination token accounts), plus live on-chain
    grounding (base58-decoded getTransaction jsonParsed) for the V2
    variants observed in current mainnet traffic.

Run from graphite-core/:  python3 scripts/rebuild_account_lists.py

Manifest account schema: {name, role, is_writable, is_signer, pda_seeds}.
Role convention: "signer" if is_signer, else "writable" if is_writable,
else "readonly" (matches existing manifests).

Derivations (documented in the manifest protocol note):
  - Jupiter *Check variants share the base instruction account layout
    (the deployed program's simulation-check instructions).
  - Jupiter V2 variants use the live-observed on-chain layouts where
    observed (route_v2, shared_accounts_route_v2), else the V1 base.
  - Instructions with NO authoritative source (jupiter compression
    routes, closeTokenLedger) keep their existing lists -- flagged.
"""
import json
import re


def snake(name: str) -> str:
    s1 = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


def norm(name: str) -> str:
    return snake(name).replace("_", "")


def acct(name: str, writable: bool, signer: bool) -> dict:
    if signer:
        role = "signer"
    elif writable:
        role = "writable"
    else:
        role = "readonly"
    return {
        "name": snake(name),
        "role": role,
        "is_writable": bool(writable),
        "is_signer": bool(signer),
        "pda_seeds": [],
    }


def load_idl_accounts(path: str, kind: str) -> dict:
    """Return {normalized_ix_name: [acct,...]} with roles."""
    idl = json.load(open(path, encoding="utf-8"))
    out = {}
    for ix in idl["instructions"]:
        accts = []
        for a in ix.get("accounts", []):
            if kind == "anchor":  # isMut/isSigner
                w, s = bool(a.get("isMut")), bool(a.get("isSigner"))
            elif kind == "codama":  # writable/signer
                w, s = bool(a.get("writable")), bool(a.get("signer"))
            else:
                raise ValueError(kind)
            accts.append(acct(a["name"], w, s))
        out[norm(ix["name"])] = accts
    return out


def rebuild(manifest_path: str, idl_map: dict, aliases: dict) -> dict:
    """Rebuild each instruction's accounts from the IDL where matched."""
    m = json.load(open(manifest_path, encoding="utf-8"))
    stats = {"rebuilt": 0, "kept": 0}
    for ix in m["instructions"]:
        key = aliases.get(ix["name"], ix["name"])
        idl_accts = idl_map.get(norm(key))
        if idl_accts is None:
            stats["kept"] += 1
            continue
        ix["accounts"] = [dict(a) for a in idl_accts]
        stats["rebuilt"] += 1
    print(f"{manifest_path}: {stats}")
    return m


def write_json(path: str, obj: dict) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(obj, indent=1) + "\n")


def main() -> None:
    root = "protocols/"

    # ---------------- orca-whirlpools ----------------
    orca_idl = load_idl_accounts("e2e-scratch/idls/orca-whirlpools.json", "anchor")
    orca = rebuild(root + "orca-whirlpools.json", orca_idl, {})
    write_json(root + "orca-whirlpools.json", orca)

    # ---------------- meteora-dlmm ----------------
    meteora_idl = load_idl_accounts("e2e-scratch/idls/meteora-dlmm.json", "codama")
    meteora = rebuild(root + "meteora-dlmm.json", meteora_idl, {})
    write_json(root + "meteora-dlmm.json", meteora)

    # ---------------- jupiter-v6 ----------------
    jup_idl = load_idl_accounts("e2e-scratch/idls/jupiter.json", "codama")
    jup_aliases = {
        "route": "route",
        "sharedAccountsRoute": "shared_accounts_route",
        "exactOutRoute": "exact_out_route",
        "sharedAccountsExactOutRoute": "shared_accounts_exact_out_route",
        "routeWithTokenLedger": "route_with_token_ledger",
        "sharedAccountsRouteWithTokenLedger": "shared_accounts_route_with_token_ledger",
        "setTokenLedger": "set_token_ledger",
        "claimToken": "claim_token",
        "claim": "claim",
        "createTokenLedger": "create_token_ledger",
    }
    jup = rebuild(root + "jupiter-v6.json", jup_idl, jup_aliases)

    # ---- V2 variants: live-observed on-chain layouts (2026-08-14) ----
    # route_v2 (bb64facc31c4af14): live mainnet txs + C22.3 pinned fixture
    # sig 57TAjPZXt... (slot 438012579) share this user-first layout.
    route_v2 = [
        acct("user_authority", True, True),
        acct("user_source_token_account", True, False),
        acct("user_destination_token_account", True, False),
        acct("source_mint", False, False),
        acct("destination_mint", False, False),
        acct("token_program", False, False),
        acct("token_2022_program", False, False),
        acct("program", False, False),
        acct("platform_fee_account", True, False),
        acct("program_authority", False, False),
    ]
    # shared_accounts_route_v2 (d19853937cfed8e9): live mainnet tx layout
    # (authority, user, source/program-source shared, program-dest, dest,
    #  mints, token programs, fee, program, event authority).
    shared_route_v2 = [
        acct("program_authority", False, False),
        acct("user_transfer_authority", True, True),
        acct("source_token_account", True, False),
        acct("program_source_token_account", True, False),
        acct("program_destination_token_account", True, False),
        acct("destination_token_account", True, False),
        acct("source_mint", False, False),
        acct("destination_mint", False, False),
        acct("token_2022_program", False, False),
        acct("token_program", False, False),
        acct("platform_fee_account", True, False),
        acct("program", False, False),
        acct("event_authority", False, False),
    ]
    v2_layouts = {
        "route_v2": route_v2,
        "shared_accounts_route_v2": shared_route_v2,
        # exact-out / token-ledger V2s: the deployed program's V2 keeps the
        # V1 account layout (V2 evolution is in the route-plan encoding);
        # grounded by the shared_accounts_route_v2 structure above.
        "exact_out_route_v2": jup_idl[norm("exact_out_route")],
        "shared_accounts_exact_out_route_v2": jup_idl[norm("shared_accounts_exact_out_route")],
        "route_with_token_ledger_v2": jup_idl[norm("route_with_token_ledger")],
        "shared_accounts_route_with_token_ledger_v2": jup_idl[norm("shared_accounts_route_with_token_ledger")],
    }
    for name, accts in v2_layouts.items():
        for ix in jup["instructions"]:
            if ix["name"] == name:
                ix["accounts"] = [dict(a) for a in accts]

    # ---- Check variants: same layout as their base instruction ----
    checks = {
        "routeCheck": "route",
        "sharedAccountsRouteCheck": "sharedAccountsRoute",
        "exactOutRouteCheck": "exactOutRoute",
        "sharedAccountsExactOutRouteCheck": "sharedAccountsExactOutRoute",
        "accountCompressionRouteCheck": "accountCompressionRoute",
        "sharedAccountsAccountCompressionRouteCheck": "sharedAccountsAccountCompressionRoute",
        "exactOutAccountCompressionRouteCheck": "exactOutAccountCompressionRoute",
        "sharedAccountsExactOutAccountCompressionRouteCheck": "sharedAccountsExactOutAccountCompressionRoute",
    }
    by_name = {i["name"]: i for i in jup["instructions"]}
    for check, base in checks.items():
        if check in by_name and base in by_name:
            by_name[check]["accounts"] = [dict(a) for a in by_name[base]["accounts"]]

    write_json(root + "jupiter-v6.json", jup)

    # ---------------- report ----------------
    for mf in ["jupiter-v6", "orca-whirlpools", "meteora-dlmm"]:
        mm = json.load(open(root + mf + ".json", encoding="utf-8"))
        print(f"\n== {mf}")
        for i in mm["instructions"]:
            w = sum(1 for a in i["accounts"] if a["is_writable"])
            s = sum(1 for a in i["accounts"] if a["is_signer"])
            ph = [a["name"] for a in i["accounts"]] in (["user_authority", "program_account"],)
            flag = "  <-- STILL PLACEHOLDER" if ph else ""
            print(f"   {i['name']:45} accounts={len(i['accounts']):2} writable={w:2} signer={s}{flag}")


if __name__ == "__main__":
    main()
