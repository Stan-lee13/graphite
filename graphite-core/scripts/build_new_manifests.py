#!/usr/bin/env python3
"""C56 — Build 5 new protocol manifests from AUTHORITATIVE on-chain data.

Sources (all program IDs chain-verified executable on mainnet, Aug 2026):
  - raydium-clmm     : CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK
                       new-spec Anchor IDL from raydium-io/raydium-idl (has
                       explicit discriminator byte arrays + pda seed defs)
  - raydium-cpmm     : CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C
                       new-spec Anchor IDL from raydium-io/raydium-idl
  - marinade         : MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD
                       old-spec Anchor IDL from @marinade.finance/marinade-ts-sdk;
                       discriminators derived sha256("global:"+snake_case)[0:8]
                       (verified identical for the new-spec IDLs which carry
                       explicit bytes, so the derivation is the same scheme)
  - spl-stake-pool   : SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy
                       native program; tags = borsh enum variant index, taken
                       from solana-program/stake-pool program/src/instruction.rs
  - orca-tokenswap-v2: 9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP
                       native program; tags from orca-so/solana-program-library
                       token-swap SwapInstruction enum, confirmed by decoding
                       real mainnet txs (0x01 + u64 + u64 = 17 bytes)

PDA-grounding policy (C26): pda_seeds templates are ONLY emitted where the
derivation is verified. The new-spec IDLs carry the program's own seed
definitions (authoritative), so those are grounded. Native programs'
authority PDAs (e.g. Orca's [swap_state, nonce]) are left ungrounded —
a wrong template would flag legitimate txs, which is the C26 failure mode.

Per-instruction semantics (expected_state_changes / risk_class / allowed_cpis)
follow the C46 convention and the engine's documented rules (verification.rs
L4/L5, risk_engine.rs FakeSwap/Check 1a/1b/10):
  - expected_state_changes always starts with the writable account list
    ("modifies writable accounts: ...") — the precise per-instruction ground
    truth from the IDL — plus a class phrase.
  - Phrase wording is constrained: "credit"/"output" only on swap instructions
    (FakeSwap contract, implies >=2 writable — swaps have many); "close" only
    on close instructions (implies >=1 writable); signer-trigger words
    (signer/approve/delegate/assign) are never used; fund movement is phrased
    as "transfer" so L5 can align it with the declared transfer/swap/stake
    intent vocabulary.
  - risk_class comes from the per-instruction class (create/transfer/withdraw/
    close/swap/authority/bookkeeping); "withdraw"/"close"/"authority" are the
    high-risk classes gated by Check 10 when NO intent is declared (P12).
  - allowed_cpis declares the program's canonical CPI surface: the three
    DEXes CPI SPL Token for transfers (also in risk_engine TRUSTED_CPI_ROOTS);
    Marinade + SPL Stake Pool CPI the Stake program AND SPL Token on every
    instruction (their staking flows merge/withdraw delegated stake and mint/
    burn pool tokens; the IDL does not ground per-instruction CPI granularity,
    and under-declaring hard-blocks legitimate staking txs — the C26 false-
    positive failure mode).
"""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IDLS = ROOT / "e2e-scratch" / "idls"
OUT = ROOT / "protocols"

TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
STAKE_PROGRAM = "Stake11111111111111111111111111111111111111"

# Class -> (risk_class, semantic phrase). See module docstring for the wording
# constraints (FakeSwap / L4 / L5 / Check 10).
CLASSES = {
    "create":      ("create",    "creates the protocol account and transfers any initial funds"),
    "transfer":    ("transfer",  "transfers funds between the pool and the involved accounts"),
    "withdraw":    ("withdraw",  "withdraws funds and transfers them out of the pool to the involved accounts"),
    "close":       ("close",     "closes the position or account and transfers remaining funds back to the user"),
    "swap":        ("transfer",  "credits the output token account with the received amount for the swap"),
    "authority":   ("authority", "updates protocol configuration or authority"),
    "bookkeeping": ("",          "updates protocol accounting state"),
}

# Marinade (old-spec IDL, camelCase names) — explicit per-instruction class.
MARINADE_CLASS = {
    "initialize": "create",
    "changeAuthority": "authority",
    "addValidator": "create",
    "removeValidator": "authority",
    "setValidatorScore": "authority",
    "configValidatorSystem": "authority",
    "deposit": "transfer",
    "depositStakeAccount": "transfer",
    "liquidUnstake": "withdraw",
    "addLiquidity": "transfer",
    "removeLiquidity": "withdraw",
    "configLp": "authority",
    "configMarinade": "authority",
    "orderUnstake": "withdraw",
    "claim": "withdraw",
    "stakeReserve": "transfer",
    "updateActive": "transfer",
    "updateDeactivated": "transfer",
    "deactivateStake": "withdraw",
    "emergencyUnstake": "withdraw",
    "partialUnstake": "withdraw",
    "mergeStakes": "transfer",
    "createCanonicalStake": "create",
    "pause": "authority",
    "resume": "authority",
    "withdrawStakeAccount": "withdraw",
    "reallocValidatorList": "authority",
    "reallocStakeList": "authority",
    "finalizeDelinquentUpgrade": "authority",
}

# SPL Stake Pool (native borsh tags) — explicit per-instruction class.
STAKE_POOL_CLASS = {
    "Initialize": "create",
    "AddValidatorToPool": "create",
    "RemoveValidatorFromPool": "authority",
    "DecreaseValidatorStake": "withdraw",
    "IncreaseValidatorStake": "transfer",
    "SetPreferredValidator": "authority",
    "UpdateValidatorListBalance": "bookkeeping",
    "UpdateStakePoolBalance": "bookkeeping",
    "CleanupRemovedValidatorEntries": "authority",
    "DepositStake": "transfer",
    "WithdrawStake": "withdraw",
    "SetManager": "authority",
    "SetFee": "authority",
    "SetStaker": "authority",
    "DepositSol": "transfer",
    "SetFundingAuthority": "authority",
    "WithdrawSol": "withdraw",
    "CreateTokenMetadata": "create",
    "UpdateTokenMetadata": "authority",
    "IncreaseAdditionalValidatorStake": "transfer",
    "DecreaseAdditionalValidatorStake": "withdraw",
    "DecreaseValidatorStakeWithReserve": "withdraw",
    "Redelegate": "transfer",
    "DepositStakeWithSlippage": "transfer",
    "WithdrawStakeWithSlippage": "withdraw",
    "DepositSolWithSlippage": "transfer",
    "WithdrawSolWithSlippage": "withdraw",
}


def snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def anchor_disc(name: str) -> str:
    return hashlib.sha256(("global:" + snake(name)).encode()).hexdigest()[:16]


def type_size(t):
    if isinstance(t, str):
        return {"u8": 1, "i8": 1, "bool": 1, "u16": 2, "i16": 2, "u32": 4,
                "i32": 4, "f32": 4, "u64": 8, "i64": 8, "f64": 8,
                "u128": 16, "i128": 16, "pubkey": 32}.get(t, 8)
    if isinstance(t, dict):
        if "array" in t:
            inner, n = t["array"]
            return type_size(inner) * n
        if "vec" in t:
            return 4
        if "option" in t:
            return 1 + type_size(t["option"])
    return 8


def template_from_pda(pda, accts, args):
    """Convert a new-spec IDL pda seed def to the repo's template format."""
    out = []
    for seed in pda.get("seeds", []):
        kind = seed.get("kind")
        if kind == "const":
            b = bytes(seed["value"])
            try:
                out.append(b.decode("ascii"))
            except Exception:
                out.append("0x" + b.hex())
        elif kind == "account":
            path = seed.get("path", "")
            idx = next((i for i, a in enumerate(accts) if a.get("name") == path), None)
            if idx is not None:
                out.append("{account_%d}" % idx)
            # if unresolvable, omit the whole template (do not emit garbage)
            else:
                return []
        elif kind == "arg":
            path = seed.get("path", "")
            idx = next((i for i, a in enumerate(args) if a.get("name") == path), None)
            if idx is None:
                return []
            off = 8
            for a in args[:idx]:
                off += type_size(a.get("type"))
            sz = type_size(args[idx].get("type"))
            out.append("{instruction_data:%d:%d}" % (off, off + sz))
        else:
            return []
    return out


def role_of(is_writable, is_signer):
    if is_signer:
        return "signer"
    return "writable" if is_writable else "readonly"


def state_changes(accts, cls):
    """expected_state_changes for one instruction: writable account list
    (IDL ground truth) + a class phrase. Always non-empty (the deep-extreme
    tests require every instruction to declare state changes)."""
    writable = [a["name"] for a in accts if a["is_writable"]]
    out = []
    if writable:
        out.append("modifies writable accounts: " + ", ".join(writable))
    phrase = CLASSES[cls][1]
    if phrase:
        out.append(phrase)
    if not out:
        out.append("no state changes (read-only instruction)")
    return out


def _classify_snake(name: str) -> str:
    """Heuristic for the new-spec (snake_case) Raydium surfaces."""
    n = name.lower()
    if n.startswith("close"):
        return "close"
    if (n.startswith("collect") or n.startswith("decrease")
            or n.startswith("withdraw") or n.startswith("remove")):
        return "withdraw"
    if (n.startswith("create") or n.startswith("open")
            or n.startswith("initialize") or n.startswith("init")):
        return "create"
    if "swap" in n:
        return "swap"
    if (n.startswith("update") or n.startswith("set")
            or n.startswith("change") or "transfer_reward_owner" in n):
        return "authority"
    return "transfer"


def new_spec_manifest(idl, proto, website, github, category, trust_tier):
    out = {
        "graphite_manifest_version": "1.0",
        "protocol": {
            "name": proto["name"],
            "program_id": proto["program_id"],
            "website": website,
            "github": github,
            "category": category,
        },
        "version": {"label": proto.get("version", "1.0.0"),
                    "effective_from_slot": 0,
                    "previous_version_ref": None},
        "instructions": [],
        "trust_tier": trust_tier,
    }
    for ix in idl["instructions"]:
        disc = bytes(ix.get("discriminator", []))
        disc_hex = disc.hex() if disc else anchor_disc(ix["name"])
        accts = []
        for a in ix.get("accounts", []):
            signer = bool(a.get("signer"))
            writable = bool(a.get("writable"))
            seeds = template_from_pda(a.get("pda") or {"seeds": []},
                                      ix.get("accounts", []),
                                      ix.get("args", []))
            accts.append({
                "name": a["name"],
                "role": role_of(writable, signer),
                "is_writable": writable,
                "is_signer": signer,
                "pda_seeds": seeds,
            })
        cls = _classify_snake(ix["name"])
        risk_class, _ = CLASSES[cls]
        cpis = [TOKEN_PROGRAM] if cls not in ("authority", "bookkeeping") else []
        out["instructions"].append({
            "name": ix["name"],
            "discriminator": disc_hex,
            "accounts": accts,
            "expected_state_changes": state_changes(accts, cls),
            "allowed_cpis": cpis,
            "risk_rules": [],
            "risk_class": risk_class,
        })
    return out


def old_spec_manifest(idl, proto, website, github, category, trust_tier, class_map):
    out = {
        "graphite_manifest_version": "1.0",
        "protocol": {
            "name": proto["name"],
            "program_id": proto["program_id"],
            "website": website,
            "github": github,
            "category": category,
        },
        "version": {"label": proto.get("version", "1.0.0"),
                    "effective_from_slot": 0,
                    "previous_version_ref": None},
        "instructions": [],
        "trust_tier": trust_tier,
    }
    for ix in idl["instructions"]:
        accts = []
        for a in ix.get("accounts", []):
            signer = bool(a.get("isSigner"))
            writable = bool(a.get("isMut"))
            accts.append({
                "name": a["name"],
                "role": role_of(writable, signer),
                "is_writable": writable,
                "is_signer": signer,
                "pda_seeds": [],
            })
        cls = class_map.get(ix["name"], "transfer")
        risk_class, _ = CLASSES[cls]
        # Marinade/SPL Stake Pool CPI the Stake program + SPL Token on their
        # staking flows (see module docstring). Declared on every instruction:
        # per-instruction CPI granularity is not grounded in the IDL, and
        # under-declaring hard-blocks legitimate staking txs.
        cpis = [STAKE_PROGRAM, TOKEN_PROGRAM]
        out["instructions"].append({
            "name": ix["name"],
            "discriminator": anchor_disc(ix["name"]),
            "accounts": accts,
            "expected_state_changes": state_changes(accts, cls),
            "allowed_cpis": cpis,
            "risk_rules": [],
            "risk_class": risk_class,
        })
    return out


def native_manifest(instructions, proto, website, github, category, trust_tier):
    out = {
        "graphite_manifest_version": "1.0",
        "protocol": {
            "name": proto["name"],
            "program_id": proto["program_id"],
            "website": website,
            "github": github,
            "category": category,
        },
        "version": {"label": proto.get("version", "1.0.0"),
                    "effective_from_slot": 0,
                    "previous_version_ref": None},
        "instructions": [],
        "trust_tier": trust_tier,
    }
    for ix in instructions:
        out["instructions"].append({
            "name": ix["name"],
            "discriminator": ix["discriminator"],
            "accounts": ix["accounts"],
            "expected_state_changes": ix["expected_state_changes"],
            "allowed_cpis": ix["allowed_cpis"],
            "risk_rules": ix.get("risk_rules", []),
            "risk_class": ix["risk_class"],
        })
    return out


def write(m, filename):
    path = OUT / filename
    path.write_text(json.dumps(m, indent=1, ensure_ascii=False) + "\n",
                    encoding="utf-8")
    grounded = sum(1 for ix in m["instructions"]
                   for a in ix["accounts"] if a["pda_seeds"])
    print(f"wrote {filename}: {len(m['instructions'])} instructions, "
          f"{sum(len(i['accounts']) for i in m['instructions'])} accounts, "
          f"{grounded} grounded-PDA accounts")


def main():
    # ---- 1. Raydium CLMM (new spec) ----
    clmm = json.loads((IDLS / "raydium_clmm.json").read_text(encoding="utf-8"))
    write(new_spec_manifest(
        clmm,
        {"name": "Raydium CLMM", "program_id":
         "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK", "version": "1.0.0"},
        "https://raydium.io", "https://github.com/raydium-io/raydium-idl",
        "swap", "OfficialManifest"), "raydium-clmm.json")

    # ---- 2. Raydium CPMM (new spec) ----
    cpmm = json.loads((IDLS / "raydium_cpmm.json").read_text(encoding="utf-8"))
    write(new_spec_manifest(
        cpmm,
        {"name": "Raydium CPMM", "program_id":
         "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C", "version": "1.0.0"},
        "https://raydium.io", "https://github.com/raydium-io/raydium-idl",
        "swap", "OfficialManifest"), "raydium-cpmm.json")

    # ---- 3. Marinade (old spec, derived discs, explicit class map) ----
    mar = json.loads((IDLS / "marinade.json").read_text(encoding="utf-8"))
    write(old_spec_manifest(
        mar,
        {"name": "Marinade Staking", "program_id":
         "MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD", "version": "2.0.0"},
        "https://marinade.finance",
        "https://github.com/marinade-finance/liquid-staking-program",
        "staking", "OfficialManifest", MARINADE_CLASS), "marinade.json")

    # ---- 4. SPL Stake Pool (native, source tags, explicit class map) ----
    #
    # C57 hardening: account lists are now the FULL official per-instruction
    # lists (name, is_writable, is_signer) from solana-program/stake-pool
    # program/src/instruction.rs (the `StakePoolInstruction` enum doc comments
    # and builder fns, order-preserving). The previous single-`stake_pool`
    # account per instruction left account-role analysis near-empty for real
    # stake-pool transactions. UpdateValidatorListBalance appends N pairs of
    # validator/transient stake accounts on-chain; the manifest declares the 7
    # fixed accounts (extra accounts resolve as "extra" roles).
    # Base lists shared by the WithSlippage variants (identical account sets).
    _SP_DEPOSIT_STAKE = [
        ("stake_pool", True, False), ("validator_list", True, False),
        ("deposit_authority", False, True), ("withdraw_authority", False, False),
        ("stake_account", True, False), ("validator_stake", True, False),
        ("reserve_stake", True, False), ("user_pool_token_account", True, False),
        ("fee_account", True, False), ("referral_account", True, False),
        ("pool_mint", True, False), ("clock_sysvar", False, False),
        ("stake_history_sysvar", False, False), ("token_program", False, False),
        ("stake_program", False, False),
    ]
    _SP_WITHDRAW_STAKE = [
        ("stake_pool", True, False), ("validator_list", True, False),
        ("withdraw_authority", False, False),
        ("validator_or_reserve_stake", True, False),
        ("new_stake_account", True, False), ("user_withdraw_authority", False, False),
        ("user_transfer_authority", False, True), ("user_pool_token_account", True, False),
        ("fee_account", True, False), ("pool_mint", True, False),
        ("clock_sysvar", False, False), ("token_program", False, False),
        ("stake_program", False, False),
    ]
    _SP_DEPOSIT_SOL = [
        ("stake_pool", True, False), ("withdraw_authority", False, False),
        ("reserve_stake", True, False), ("source", False, True),
        ("user_pool_token_account", True, False), ("fee_account", True, False),
        ("referral_account", True, False), ("pool_mint", True, False),
        ("system_program", False, False), ("token_program", False, False),
        ("sol_deposit_authority", False, False),
    ]
    _SP_WITHDRAW_SOL = [
        ("stake_pool", True, False), ("withdraw_authority", False, False),
        ("user_transfer_authority", False, True), ("user_pool_token_account", True, False),
        ("reserve_stake", True, False), ("destination", True, False),
        ("fee_account", True, False), ("pool_mint", True, False),
        ("clock_sysvar", False, False), ("stake_history_sysvar", False, False),
        ("stake_program", False, False), ("token_program", False, False),
        ("sol_withdraw_authority", False, False),
    ]
    STAKE_POOL_ACCOUNTS = {
        "Initialize": [
            ("stake_pool", True, False), ("manager", False, True),
            ("staker", False, False), ("withdraw_authority", False, False),
            ("validator_list", True, False), ("reserve_stake", False, False),
            ("pool_mint", True, False), ("manager_fee_account", True, False),
            ("token_program", False, False), ("deposit_authority", False, False),
        ],
        "AddValidatorToPool": [
            ("stake_pool", True, False), ("staker", False, True),
            ("reserve_stake", True, False), ("withdraw_authority", False, False),
            ("validator_list", True, False), ("stake_account", True, False),
            ("validator", False, False), ("rent_sysvar", False, False),
            ("clock_sysvar", False, False), ("stake_history_sysvar", False, False),
            ("stake_config_sysvar", False, False), ("system_program", False, False),
            ("stake_program", False, False),
        ],
        "RemoveValidatorFromPool": [
            ("stake_pool", True, False), ("staker", False, True),
            ("withdraw_authority", False, False), ("validator_list", True, False),
            ("stake_account", True, False), ("transient_stake", True, False),
            ("clock_sysvar", False, False), ("stake_program", False, False),
        ],
        "DecreaseValidatorStake": [
            ("stake_pool", False, False), ("staker", False, True),
            ("withdraw_authority", False, False), ("validator_list", True, False),
            ("validator_stake", True, False), ("transient_stake", True, False),
            ("clock_sysvar", False, False), ("rent_sysvar", False, False),
            ("system_program", False, False), ("stake_program", False, False),
        ],
        "IncreaseValidatorStake": [
            ("stake_pool", False, False), ("staker", False, True),
            ("withdraw_authority", False, False), ("validator_list", True, False),
            ("reserve_stake", True, False), ("transient_stake", True, False),
            ("validator_stake", False, False), ("validator", False, False),
            ("clock_sysvar", False, False), ("rent_sysvar", False, False),
            ("stake_history_sysvar", False, False), ("stake_config_sysvar", False, False),
            ("system_program", False, False), ("stake_program", False, False),
        ],
        "SetPreferredValidator": [
            ("stake_pool", True, False), ("staker", False, True),
            ("validator_list", False, False),
        ],
        "UpdateValidatorListBalance": [
            ("stake_pool", False, False), ("withdraw_authority", False, False),
            ("validator_list", True, False), ("reserve_stake", True, False),
            ("clock_sysvar", False, False), ("stake_history_sysvar", False, False),
            ("stake_program", False, False),
        ],
        "UpdateStakePoolBalance": [
            ("stake_pool", True, False), ("withdraw_authority", False, False),
            ("validator_list", True, False), ("reserve_stake", False, False),
            ("fee_account", True, False), ("pool_mint", True, False),
            ("token_program", False, False),
        ],
        "CleanupRemovedValidatorEntries": [
            ("stake_pool", False, False), ("validator_list", True, False),
        ],
        "DepositStake": _SP_DEPOSIT_STAKE,
        "WithdrawStake": _SP_WITHDRAW_STAKE,
        "SetManager": [
            ("stake_pool", True, False), ("manager", False, True),
            ("new_manager", False, True), ("new_manager_fee_account", False, False),
        ],
        "SetFee": [
            ("stake_pool", True, False), ("manager", False, True),
        ],
        "SetStaker": [
            ("stake_pool", True, False), ("manager_or_staker", False, True),
            ("new_staker", False, False),
        ],
        "DepositSol": _SP_DEPOSIT_SOL,
        "SetFundingAuthority": [
            ("stake_pool", True, False), ("manager", False, True),
            ("new_authority", False, False),
        ],
        "WithdrawSol": _SP_WITHDRAW_SOL,
        "CreateTokenMetadata": [
            ("stake_pool", False, False), ("manager", False, True),
            ("withdraw_authority", False, False), ("pool_mint", False, False),
            ("payer", True, True), ("token_metadata_account", True, False),
            ("metadata_program", False, False), ("system_program", False, False),
        ],
        "UpdateTokenMetadata": [
            ("stake_pool", False, False), ("manager", False, True),
            ("withdraw_authority", False, False), ("token_metadata_account", True, False),
            ("metadata_program", False, False),
        ],
        "IncreaseAdditionalValidatorStake": [
            ("stake_pool", False, False), ("staker", False, True),
            ("withdraw_authority", False, False), ("validator_list", True, False),
            ("reserve_stake", True, False), ("ephemeral_stake", True, False),
            ("transient_stake", True, False), ("validator_stake", False, False),
            ("validator", False, False), ("clock_sysvar", False, False),
            ("stake_history_sysvar", False, False), ("stake_config_sysvar", False, False),
            ("system_program", False, False), ("stake_program", False, False),
        ],
        "DecreaseAdditionalValidatorStake": [
            ("stake_pool", False, False), ("staker", False, True),
            ("withdraw_authority", False, False), ("validator_list", True, False),
            ("reserve_stake", True, False), ("validator_stake", True, False),
            ("ephemeral_stake", True, False), ("transient_stake", True, False),
            ("clock_sysvar", False, False), ("stake_history_sysvar", False, False),
            ("system_program", False, False), ("stake_program", False, False),
        ],
        "DecreaseValidatorStakeWithReserve": [
            ("stake_pool", False, False), ("staker", False, True),
            ("withdraw_authority", False, False), ("validator_list", True, False),
            ("reserve_stake", True, False), ("validator_stake", True, False),
            ("transient_stake", True, False), ("clock_sysvar", False, False),
            ("stake_history_sysvar", False, False), ("system_program", False, False),
            ("stake_program", False, False),
        ],
        "Redelegate": [
            ("stake_pool", False, False), ("staker", False, True),
            ("withdraw_authority", False, False), ("validator_list", True, False),
            ("reserve_stake", True, False), ("source_validator_stake", True, False),
            ("source_transient_stake", True, False), ("ephemeral_stake", True, False),
            ("destination_transient_stake", True, False),
            ("destination_validator_stake", False, False), ("validator", False, False),
            ("clock_sysvar", False, False), ("stake_history_sysvar", False, False),
            ("stake_config_sysvar", False, False), ("system_program", False, False),
            ("stake_program", False, False),
        ],
        "DepositStakeWithSlippage": _SP_DEPOSIT_STAKE,
        "WithdrawStakeWithSlippage": _SP_WITHDRAW_STAKE,
        "DepositSolWithSlippage": _SP_DEPOSIT_SOL,
        "WithdrawSolWithSlippage": _SP_WITHDRAW_SOL,
    }
    def acct(name, role, writable, signer):
        return {"name": name, "role": role, "is_writable": writable,
                "is_signer": signer, "pda_seeds": []}
    def sp_acct(name, writable, signer):
        return acct(name, role_of(writable, signer), writable, signer)
    stake_pool_ixs = []
    for i, name in enumerate(STAKE_POOL_ACCOUNTS):
        cls = STAKE_POOL_CLASS[name]
        risk_class, _ = CLASSES[cls]
        accts = [sp_acct(*a) for a in STAKE_POOL_ACCOUNTS[name]]
        stake_pool_ixs.append({
            "name": name,
            "discriminator": "%02x" % i,
            "accounts": accts,
            "expected_state_changes": state_changes(accts, cls),
            "allowed_cpis": [STAKE_PROGRAM, TOKEN_PROGRAM],
            "risk_rules": [],
            "risk_class": risk_class,
        })
    write(native_manifest(
        stake_pool_ixs,
        {"name": "SPL Stake Pool", "program_id":
         "SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy", "version": "1.0.0"},
        "https://spl.solana.com/stake-pool",
        "https://github.com/solana-program/stake-pool",
        "staking", "OfficialManifest"), "spl-stake-pool.json")

    # ---- 5. Orca TokenSwap V2 (native, source tags) ----
    orca_ixs = []
    orca_ixs.append({
        "name": "Initialize", "discriminator": "00", "risk_class": "create",
        "accounts": [acct("swap_state", "writable", True, False),
                     acct("token_a", "readonly", False, False),
                     acct("token_b", "readonly", False, False)],
        "allowed_cpis": [], "risk_rules": [],
        "expected_state_changes": state_changes(
            [acct("swap_state", "writable", True, False)], "create"),
    })
    orca_ixs.append({
        "name": "Swap", "discriminator": "01", "risk_class": "transfer",
        "accounts": [acct("swap_state", "writable", True, False),
                     acct("user_source", "writable", True, False),
                     acct("user_destination", "writable", True, False),
                     acct("pool_source", "writable", True, False),
                     acct("pool_destination", "writable", True, False),
                     acct("authority", "readonly", False, False)],
        "allowed_cpis": [TOKEN_PROGRAM], "risk_rules": [],
        "expected_state_changes": state_changes(
            [acct("swap_state", "writable", True, False),
             acct("user_source", "writable", True, False),
             acct("user_destination", "writable", True, False),
             acct("pool_source", "writable", True, False),
             acct("pool_destination", "writable", True, False),
             acct("authority", "readonly", False, False)], "swap"),
    })
    orca_ixs.append({
        "name": "Deposit", "discriminator": "02", "risk_class": "transfer",
        "accounts": [acct("swap_state", "writable", True, False),
                     acct("user_source_a", "writable", True, False),
                     acct("user_source_b", "writable", True, False),
                     acct("pool_source_a", "writable", True, False),
                     acct("pool_source_b", "writable", True, False),
                     acct("user_lp", "writable", True, False),
                     acct("pool_lp", "writable", True, False),
                     acct("authority", "readonly", False, False)],
        "allowed_cpis": [TOKEN_PROGRAM], "risk_rules": [],
        "expected_state_changes": state_changes(
            [acct("swap_state", "writable", True, False),
             acct("user_source_a", "writable", True, False),
             acct("user_source_b", "writable", True, False),
             acct("pool_source_a", "writable", True, False),
             acct("pool_source_b", "writable", True, False),
             acct("user_lp", "writable", True, False),
             acct("pool_lp", "writable", True, False),
             acct("authority", "readonly", False, False)], "transfer"),
    })
    orca_ixs.append({
        "name": "Withdraw", "discriminator": "03", "risk_class": "withdraw",
        "accounts": [acct("swap_state", "writable", True, False),
                     acct("user_lp", "writable", True, False),
                     acct("pool_lp", "writable", True, False),
                     acct("pool_source_a", "writable", True, False),
                     acct("pool_source_b", "writable", True, False),
                     acct("user_destination_a", "writable", True, False),
                     acct("user_destination_b", "writable", True, False),
                     acct("authority", "readonly", False, False)],
        "allowed_cpis": [TOKEN_PROGRAM], "risk_rules": [],
        "expected_state_changes": state_changes(
            [acct("swap_state", "writable", True, False),
             acct("user_lp", "writable", True, False),
             acct("pool_lp", "writable", True, False),
             acct("pool_source_a", "writable", True, False),
             acct("pool_source_b", "writable", True, False),
             acct("user_destination_a", "writable", True, False),
             acct("user_destination_b", "writable", True, False),
             acct("authority", "readonly", False, False)], "withdraw"),
    })
    write(native_manifest(
        orca_ixs,
        {"name": "Orca TokenSwap V2", "program_id":
         "9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP", "version": "2.0.0"},
        "https://www.orca.so", "https://github.com/orca-so",
        "swap", "OfficialManifest"), "orca-tokenswap-v2.json")


if __name__ == "__main__":
    main()
