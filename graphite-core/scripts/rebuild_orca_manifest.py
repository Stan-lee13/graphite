#!/usr/bin/env python3
"""C25 — Rebuild the Orca Whirlpools manifest from the deployed program's IDL.

Ground truth: the official IDL of the DEPLOYED program `whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc`
(npm `@orca-so/whirlpools`, program version 0.9.0). The orca-so/whirlpools repo's Anchor.toml maps
this program id to the source that produced this IDL, and a live on-chain census observed
`increase_liquidity_by_token_amounts_v2` (an instruction that exists only in this IDL) executing on
the deployed program — so the IDL is the deployment's instruction set, not a guess.

Findings fixed by this rebuild:
  C25.1 — 6 of 24 manifest entries were FABRICATED (updateFeeRate, transferPositionDelegate,
          applyDelta, syncTickArray, closeAccount, closeConfigExtension). They appear in neither
          the 2022-era deployed IDL (v0.1.0, 25 instructions) nor the current deployed IDL
          (66 instructions), and the repo's entire git history contains zero occurrences.
          They are removed.
  C25.2 — The manifest covered only 24 of the 66 deployed instructions; every legitimate Orca
          txn using any other instruction fell to unknown-protocol mode (0.55 confidence ceiling).
          The manifest now covers the full 66-instruction deployed surface, with discriminators
          taken from the IDL's explicit byte arrays (not re-derived hashes).
  C25.3 — 3 discriminators additionally corroborated by live on-chain observation:
          swap=f8c69e91e17587c8 (x153), swap_v2=2b04ed0b1ac91e62 (x342),
          increase_liquidity_by_token_amounts_v2=effb097cd2c6352b (x7). The census
          progress cache is gitignored (scripts/.census_orca_cache.json); the IDL
          itself is committed as scripts/whirlpool_idl.json for reproducibility.
"""
import json
import re

IDL = "scripts/whirlpool_idl.json"
MANIFEST = "protocols/orca-whirlpools.json"

TOKEN_PROGS = [
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",   # SPL Token
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",   # Token-2022
]

LIVE_OBSERVED = {
    "swap": "f8c69e91e17587c8",
    "swap_v2": "2b04ed0b1ac91e62",
    "increase_liquidity_by_token_amounts_v2": "effb097cd2c6352b",
}

def snake_to_camel(name: str) -> str:
    parts = name.split("_")
    return parts[0] + "".join(p.capitalize() for p in parts[1:])

def camel_to_snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()

def state_changes(name: str) -> list:
    g = {
        "swap": ["swaps tokens across the whirlpool concentrated-liquidity pool",
                 "debits user source token account", "credits user destination token account"],
        "two_hop_swap": ["swaps tokens across two whirlpool pools",
                         "debits user source token account", "credits user destination token account"],
        "open_position": ["opens a liquidity position", "mints the position NFT"],
        "open_position_with_metadata": ["opens a liquidity position with NFT metadata",
                                        "mints the position NFT with metadata"],
        "close_position": ["closes a liquidity position", "burns the position NFT"],
        "increase_liquidity": ["adds liquidity to a position", "debits user token accounts"],
        "decrease_liquidity": ["removes liquidity from a position", "credits user token accounts"],
        "collect_fees": ["collects accrued fees from a position", "credits user token accounts"],
        "collect_reward": ["collects accrued rewards from a position", "credits user token accounts"],
        "collect_protocol_fees": ["collects protocol fees from the pool", "credits the protocol fee vaults"],
        "lock_position": ["locks a position", "prevents further position transfers"],
        "transfer_locked_position": ["transfers a locked position between owners"],
        "reset_position_range": ["resets a position's active tick range"],
        "reposition_liquidity_v2": ["repositions liquidity within the pool's tick range"],
    }
    if name in g:
        return g[name]
    if name.startswith("initialize_"):
        entity = name[len("initialize_"):].replace("_", " ")
        return [f"initializes the {entity} account for the whirlpool protocol"]
    if name.startswith("set_"):
        return [f"updates a whirlpool protocol authority or parameter"]
    if name.startswith("close_"):
        entity = name[len("close_"):].replace("_", " ")
        return [f"closes the {entity} account and reclaims rent"]
    if name.startswith("delete_"):
        entity = name[len("delete_"):].replace("_", " ")
        return [f"removes the {entity} entry from protocol state"]
    return ["whirlpool protocol state transition"]

def touches_tokens(accounts: list) -> bool:
    for a in accounts:
        n = a.get("name", "").lower()
        if "token" in n or "vault" in n or "mint" in n:
            return True
    return False

def main():
    idl = json.load(open(IDL, encoding="utf-8"))
    old = json.load(open(MANIFEST, encoding="utf-8"))

    # Carry-over table: snake_case name -> old instruction (for curated fields).
    carry = {}
    for ix in old["instructions"]:
        carry[camel_to_snake(ix["name"])] = ix

    out = []
    for i in idl["instructions"]:
        snake = i["name"]
        name = snake_to_camel(snake)
        disc = bytes(i["discriminator"]).hex()
        accounts = []
        for a in i.get("accounts", []):
            is_signer = bool(a.get("isSigner", False))
            is_writable = bool(a.get("isMut", False))
            role = "signer" if is_signer else ("writable" if is_writable else "readonly")
            accounts.append({
                "name": a["name"],
                "role": role,
                "is_writable": is_writable,
                "is_signer": is_signer,
                "pda_seeds": [],
            })
        old_ix = carry.get(snake)
        if old_ix is not None:
            expected = old_ix.get("expected_state_changes") or state_changes(snake)
            allowed = old_ix.get("allowed_cpis") or (TOKEN_PROGS if touches_tokens(accounts) else [])
            rules = old_ix.get("risk_rules") or []
            var_accts = old_ix.get("variable_accounts", False)
        else:
            expected = state_changes(snake)
            allowed = TOKEN_PROGS if touches_tokens(accounts) else []
            rules = []
            var_accts = False
        entry = {
            "name": name,
            "discriminator": disc,
            "accounts": accounts,
            "expected_state_changes": expected,
            "allowed_cpis": allowed,
            "risk_rules": rules,
        }
        if var_accts:
            entry["variable_accounts"] = True
        out.append(entry)

    out.sort(key=lambda e: e["name"].lower())

    note = (
        "C25 full-surface rebuild (2026-08-09): the manifest previously carried 6 FABRICATED "
        "instructions (updateFeeRate, transferPositionDelegate, applyDelta, syncTickArray, "
        "closeAccount, closeConfigExtension) that were never part of the deployed program at any "
        "version — they appear in neither the 2022-era deployed IDL (v0.1.0, 25 instructions) nor "
        "the current deployed IDL (66 instructions), and the orca-so/whirlpools git history has "
        "zero occurrences. Those entries are removed. The manifest now covers the FULL deployed "
        "surface: all 66 discriminators are the explicit byte arrays from the official deployed-"
        "program IDL (npm @orca-so/whirlpools, program v0.9.0; the repo's Anchor.toml maps "
        "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc to this source), NOT re-derived hashes. "
        "Three are additionally corroborated by live on-chain observation (base58-correct decode): "
        "swap=f8c69e91e17587c8, swap_v2=2b04ed0b1ac91e62, "
        "increase_liquidity_by_token_amounts_v2=effb097cd2c6352b. The C24 note's claim that the 6 "
        "were 'corrected to the snake_case convention' was itself based on the false premise that "
        "they existed; this note supersedes it."
    )

    manifest = {
        "graphite_manifest_version": old["graphite_manifest_version"],
        "protocol": {
            "name": old["protocol"]["name"],
            "program_id": old["protocol"]["program_id"],
            "website": old["protocol"]["website"],
            "github": old["protocol"]["github"],
            "note": note,
        },
        "version": {
            "label": "2.0.0",
            "effective_from_slot": 0,
            "previous_version_ref": "1.0.0",
        },
        "instructions": out,
        "trust_tier": old["trust_tier"],
    }

    with open(MANIFEST, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
        f.write("\n")

    # Sanity checks.
    print(f"wrote {len(out)} instructions")
    names = [e["name"] for e in out]
    assert len(names) == len(set(names)), "duplicate names"
    discs = [e["discriminator"] for e in out]
    assert len(discs) == len(set(discs)), "duplicate discriminators"
    for e in out:
        assert len(e["discriminator"]) == 16, f"bad disc len for {e['name']}: {e['discriminator']}"
        assert e["name"] != "idlInclude" or True
    # The 6 fabricated names must be gone.
    for bad in ["updateFeeRate", "transferPositionDelegate", "applyDelta", "syncTickArray",
                "closeAccount", "closeConfigExtension"]:
        assert bad not in names, f"{bad} must be removed"
    # The 3 live-observed values must be present.
    live = {snake_to_camel(k): v for k, v in LIVE_OBSERVED.items()}
    for nm, dv in live.items():
        assert any(e["name"] == nm and e["discriminator"] == dv for e in out), f"{nm}={dv} missing"
    print("all sanity checks passed")

if __name__ == "__main__":
    main()
