#!/usr/bin/env python3
"""C27 — Build the Drift + Kamino Lending manifests from the official IDLs.

Ground truth:
  - Drift:   scripts/drift_idl.json from velocity-exchange/protocol-v2
             (sdk/src/idl/drift.json, the moved drift-labs/protocol-v2), program
             dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH (SDK DRIFT_PROGRAM_ID,
             confirmed as an executable account on mainnet).
  - Kamino:  scripts/klend_idl.json from Kamino-Finance/klend-sdk
             (src/idl/klend.json), program
             KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD (codegen PROGRAM_ID,
             confirmed as an executable account on mainnet).

Discriminators: Anchor derives them as sha256("global:" + SNAKE_CASE rust fn
name)[0..8]. The IDLs carry no discriminator bytes, so every value here is
DERIVED, then verified LIVE: an on-chain census (scripts/census_drift_kamino.py,
base58-correct decode) observed 3 Drift instructions (placePerpOrder x128,
cancelOrdersByIds x41, placeOrders x41) and 11 Kamino instructions
(flashBorrowReserveLiquidity x136, flashRepayReserveLiquidity x136,
refreshReserve x19, refreshReservesBatch x13, refreshObligation x8,
depositReserveLiquidityAndObligationCollateralV2 x5,
borrowObligationLiquidityV2 x3, redeemReserveCollateral x3,
depositReserveLiquidity x2, initUserMetadata x1, initObligation x1) — all
matched the derived values, zero unmatched. The remaining instructions follow
the same proven convention on the same deployed binaries.

PDA seeds: only accounts whose seed construction is VERIFIED from the deployed
program source (velocity-exchange/protocol-v2 programs/drift/src/instructions/
user.rs; Kamino-Finance/klend libs/klend-interface/src/pda.rs +
programs/klend/src/handlers/*) or the official SDKs are grounded. Accounts the
program does NOT seed-constrain are left with empty pda_seeds — grounding them
with guessed seeds would flag legitimate transactions (C26 principle).
"""
import hashlib
import json
import re

TOKEN_PROGS = [
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",  # SPL Token
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",  # Token-2022
]

PROGRAMS = {
    "drift": {
        "idl": "scripts/drift_idl.json",
        "manifest": "protocols/drift.json",
        "name": "Drift Perpetuals Exchange",
        "program_id": "dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH",
        "website": "https://www.drift.trade",
        "github": "https://github.com/velocity-exchange/protocol-v2",
        "version": "2.0.0",
        "prev": "1.0.0",
        "tier": "BattleTested",
        "live_observed": {
            "placePerpOrder": "45a15dca787e4cb9",
            "cancelOrdersByIds": "861390a55ef0d25e",
            "placeOrders": "3c3f327b0cc53cbe",
        },
    },
    "klend": {
        "idl": "scripts/klend_idl.json",
        "manifest": "protocols/kamino-lending.json",
        "name": "Kamino Lending",
        "program_id": "KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD",
        "website": "https://kamino.finance",
        "github": "https://github.com/Kamino-Finance/klend",
        "version": "2.0.0",
        "prev": "1.0.0",
        "tier": "BattleTested",
        "live_observed": {
            "flashBorrowReserveLiquidity": "87e734a70734d4c1",
            "flashRepayReserveLiquidity": "b97500cb60f5b4ba",
            "refreshReserve": "02da8aeb4fc91966",
            "refreshReservesBatch": "906e1a67a2ccfc93",
            "refreshObligation": "218493e497c04859",
            "depositReserveLiquidityAndObligationCollateralV2": "d8e0bf1bcc9766af",
            "borrowObligationLiquidityV2": "a1808ff5abc7c206",
            "redeemReserveCollateral": "ea75b57db98edc1d",
            "depositReserveLiquidity": "a9c91e7e06cd6644",
            "initUserMetadata": "75a9b045c5170fa2",
            "initObligation": "fb0ae74c1b0b9f60",
        },
    },
}

# ---------------------------------------------------------------------------
# PDA grounding — VERIFIED from program source / official SDKs.
# ---------------------------------------------------------------------------
# Value templates: "{account_N}" = pubkey bytes of account index N in the
# instruction's account list; "{instruction_data:S:E}" = byte slice of the raw
# instruction data (post-discriminator offset included, i.e. S=8 skips the
# 8-byte discriminator); "0x.." = literal hex bytes; anything else = ASCII.

def pda_rules(prog):
    """(instruction_snake, account_name) -> seed template builder.

    Only seed constructions VERIFIED from the deployed program source or the
    official SDK are grounded (C26 principle: a wrong seed spec would flag
    legitimate transactions).
    """
    rules = {}
    if prog == "drift":
        # user = [b"user", authority, sub_account_id.to_le_bytes()]
        # (programs/drift/src/instructions/user.rs:4477) — sub_account_id is a
        # u16 LE arg at instruction-data bytes 8:10.
        rules[("initialize_user", "user")] = lambda acc, ix: [
            "user", "{account_%d}" % acc.index("authority"), "{instruction_data:8:10}",
        ]
        # user_stats = [b"user_stats", authority] — seed-constrained ONLY in
        # initialize_user_stats (user.rs:4502). In every other instruction the
        # program checks `has_one = authority` / `is_stats_for_user` (consistency,
        # NOT a PDA derivation), so grounding the PDA there would flag legitimate
        # txs that pass a valid-but-non-PDA user_stats — C26 principle.
        rules[("initialize_user_stats", "user_stats")] = lambda acc, ix: [
            "user_stats", "{account_%d}" % acc.index("authority"),
        ]
        # spot_market_vault = [b"spot_market_vault", market_index.to_le_bytes()]
        # (user.rs:4706) — market_index is args[0] (u16 LE) -> bytes 8:10.
        for ix_name in ("deposit", "withdraw", "transfer_deposit"):
            rules[(ix_name, "spot_market_vault")] = lambda acc, ix: [
                "spot_market_vault", "{instruction_data:8:10}",
            ]
        # drift_signer = [b"drift_signer"] (SDK pda.ts) — withdraw's vault signer.
        rules[("withdraw", "drift_signer")] = lambda acc, ix: ["drift_signer"]
    return rules


# Kamino: account-name -> seed templates (constants from pda.rs, seed-
# constraining accounts in the handlers). CRITICAL SCOPE RULE (C26): only
# ground accounts where the DEPLOYED program's account struct seed-constrains
# them. Runtime instructions (deposit/withdraw/borrow/repay/flashBorrow/etc.)
# carry vaults as plain token accounts constrained by `address = reserve.state.
# vault` — NOT as PDAs — so grounding [const, reserve] there would flag
# legitimate transactions. Verified on the deployed source: only initReserve
# PDA-creates the vaults; only initUserMetadata PDA-creates user_metadata;
# lending_market_authority ([lma, market]) is seed-constrained in EVERY
# instruction that carries it (it is the program's signing authority).
def kamino_rule(account_name, acc, ix, sn):
    # Ground only when the seed's referenced sibling account is present in the
    # instruction (a missing sibling means a different derivation — do not guess).
    def ref(nm):
        return "{account_%d}" % acc.index(nm) if nm in acc else None

    if account_name == "lending_market_authority":
        # seeds = [b"lma", lending_market.key()]  — constrained in every handler
        r = ref("lending_market")
        return ["lma", r] if r else None
    if sn == "init_reserve" and account_name in (
        "reserve_liquidity_supply", "fee_receiver",
        "reserve_collateral_mint", "reserve_collateral_supply",
    ):
        # seeds = [const, reserve.key()]  (handler_init_reserve.rs:148-161) —
        # ONLY here; runtime handlers do not seed-constrain these accounts.
        const = {
            "reserve_liquidity_supply": "reserve_liq_supply",
            "fee_receiver": "fee_receiver",
            "reserve_collateral_mint": "reserve_coll_mint",
            "reserve_collateral_supply": "reserve_coll_supply",
        }[account_name]
        r = ref("reserve")
        return [const, r] if r else None
    if sn == "init_user_metadata" and account_name == "user_metadata":
        # seeds = [b"user_meta", owner.key()]  (handler_init_user_metadata.rs)
        r = ref("owner")
        return ["user_meta", r] if r else None
    return None


def kamino_obligation_rule(acc, ix):
    # seeds = [&[tag], &[id], owner, lending_market, seed1, seed2]
    # (handler_init_obligation.rs) — tag/id are InitObligationArgs u8 fields,
    # serialized at instruction-data bytes 8 and 9.
    return [
        "{instruction_data:8:9}",
        "{instruction_data:9:10}",
        "{account_%d}" % acc.index("obligation_owner"),
        "{account_%d}" % acc.index("lending_market"),
        "{account_%d}" % acc.index("seed1_account"),
        "{account_%d}" % acc.index("seed2_account"),
    ]


# ---------------------------------------------------------------------------
# Curated behavior (state changes / CPIs / risk rules) for security-relevant
# instructions; pattern fallbacks cover the rest.
# ---------------------------------------------------------------------------
def snake(n):
    s = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", n)
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", s).lower()


DRIFT_STATE = {
    "initialize_user": ["initializes the user account and user_stats PDA for the authority"],
    "initialize_user_stats": ["initializes the user_stats PDA for the authority"],
    "deposit": ["debits the user's spot token account into the spot market vault",
                "credits the user's spot balance"],
    "withdraw": ["debits the user's spot balance",
                 "credits the user's spot token account from the spot market vault"],
    "transfer_deposit": ["transfers spot balance between the user's sub-accounts"],
    "place_order": ["places a perp/spot order in the orderbook"],
    "place_orders": ["places multiple perp/spot orders in the orderbook"],
    "place_perp_order": ["places a perp order in the orderbook"],
    "place_spot_order": ["places a spot order in the orderbook"],
    "cancel_order": ["cancels a user order"],
    "cancel_orders": ["cancels multiple user orders"],
    "cancel_orders_by_ids": ["cancels multiple user orders by id"],
    "settle_pnl": ["settles the user's unrealized perp pnl into their spot balance"],
    "settle_pnl_to_revenue_pool": ["settles the user's negative pnl to the revenue pool"],
    "liquidate_borrow": ["liquidates a user's spot borrow"],
    "liquidate_perp": ["liquidates a user's perp position"],
    "liquidate_spot": ["liquidates a user's spot position"],
    "liquidate_perp_pnl_for_deposit": ["liquidates a user's perp pnl for spot deposit"],
    "liquidate_insurance_fund_stake": ["liquidates an insurance fund stake"],
    "add_perp_lp_shares": ["adds perp market LP shares"],
    "remove_perp_lp_shares": ["removes perp market LP shares"],
    "delete_user": ["closes the user account and reclaims rent"],
    "update_user": ["updates the user account's margin mode or name"],
    "update_user_margin_trading_enabled": ["toggles the user's margin trading flag"],
    "deposit_into_spot_market_revenue_pool": ["deposits into the spot market revenue pool"],
    "withdraw_from_spot_market_vault": ["withdraws from the spot market vault"],
    "claim_referrer_rewards": ["claims referrer rewards to the referrer's token account"],
    "initialize_referrer_name": ["initializes a referrer name account"],
    "initialize_insurance_fund_stake": ["initializes an insurance fund stake"],
    "add_insurance_fund_stake": ["adds insurance fund stake"],
    "request_remove_insurance_fund_stake": ["requests insurance fund stake removal"],
    "cancel_request_remove_insurance_fund_stake": ["cancels a stake removal request"],
    "remove_insurance_fund_stake": ["removes insurance fund stake"],
    "resolve_perp_pnl_deficit": ["resolves a perp pnl deficit"],
    "resolve_bankruptcy": ["resolves a user's bankruptcy"],
    "force_cancel_orders": ["force-cancels a user's orders"],
    "trigger_order": ["triggers a user's trigger order"],
    "place_and_take": ["places and immediately takes against an order"],
    "place_and_make": ["places and makes an order"],
    "fill_perp_order": ["fills a perp order"],
    "fill_spot_order": ["fills a spot order"],
    "update_amm": ["updates the AMM curve"],
    "update_spot_market": ["updates spot market parameters"],
    "update_perp_market": ["updates perp market parameters"],
    "initialize_state": ["initializes the drift protocol state"],
    "initialize_spot_market": ["initializes a spot market"],
    "initialize_perp_market": ["initializes a perp market"],
    "initialize_prediction_market": ["initializes a prediction market"],
    "update_funding_rate": ["updates the funding rate"],
    "settle_funding": ["settles funding payments"],
    "settle_revenue_pool": ["settles revenue pool funds to the insurance fund"],
    "update_keeper_apr": ["updates keeper apr parameters"],
    "initialize_user_signed_msg_orders": ["initializes a signed-msg orders account"],
    "resize_signed_msg_user_orders": ["resizes the signed-msg orders account"],
    "initialize_signed_msg_ws_delegates": ["initializes signed-msg ws delegates"],
    "update_signed_msg_user_orders": ["updates signed-msg orders"],
    "update_signed_msg_ws_delegate": ["updates a signed-msg ws delegate"],
    "delete_signed_msg_user_orders": ["deletes the signed-msg orders account"],
    "update_amms": ["updates AMM curves for multiple markets"],
    "admin_fix_spot_market_fee": ["admin fixes spot market fees"],
    "admin_fix_perp_market_fee": ["admin fixes perp market fees"],
    "update_insurance_fund_unstaking_period": ["updates the insurance fund unstaking period"],
    "revenue_pool_deposit": ["deposits into the revenue pool"],
    "settle_bankruptcy": ["settles a bankrupt user"],
    "settle_borrow": ["settles a user's borrow interest"],
    "settle_spot_borrow": ["settles spot borrow interest"],
    "update_user_quote_asset_insurance_stake": ["updates the user's quote asset insurance stake"],
    "delete_user_signed_msg_orders": ["deletes the signed-msg orders account"],
    "update_spot_market_oracle": ["updates a spot market's oracle"],
    "update_perp_market_oracle": ["updates a perp market's oracle"],
    "update_spot_market_expiry": ["updates a spot market's expiry"],
    "update_perp_market_expiry": ["updates a perp market's expiry"],
    "update_whitelist": ["updates the whitelist"],
    "update_quote_asset_insurance_fund": ["updates quote asset insurance fund parameters"],
}

DRIFT_RISK = {
    "withdraw": ["withdraw must match the declared transfer intent and the authority must sign"],
    "transfer_deposit": ["transfer must be between the signer's own sub-accounts"],
    "liquidate_borrow": ["liquidation must target a delinquent user's borrow"],
    "liquidate_perp": ["liquidation must target a delinquent user's perp position"],
    "liquidate_spot": ["liquidation must target a delinquent user's spot position"],
    "delete_user": ["deleting a user account with nonzero balance must be blocked"],
    "force_cancel_orders": ["force-cancel must be authorized by the keeper"],
    "resolve_bankruptcy": ["bankruptcy resolution must be authorized"],
}

KLEND_STATE = {
    "init_lending_market": ["initializes a lending market"],
    "init_reserve": ["initializes a reserve with its vault PDAs"],
    "init_obligation": ["initializes an obligation account for the owner"],
    "init_user_metadata": ["initializes user metadata for the owner"],
    "deposit_reserve_liquidity": ["debits user_source_liquidity", "credits user_destination_collateral"],
    "deposit_reserve_liquidity_and_obligation_collateral": ["debits user source liquidity", "credits obligation collateral"],
    "deposit_reserve_liquidity_and_obligation_collateral_v2": ["debits user source liquidity", "credits obligation collateral"],
    "withdraw_obligation_collateral": ["debits reserve collateral supply", "credits user destination collateral"],
    "withdraw_obligation_collateral_and_redeem_reserve_collateral": ["redeems reserve collateral for liquidity"],
    "borrow_obligation_liquidity": ["debits reserve liquidity supply", "credits user destination liquidity", "increases obligation borrows"],
    "borrow_obligation_liquidity_v2": ["debits reserve liquidity supply", "credits user destination liquidity", "increases obligation borrows"],
    "repay_obligation_liquidity": ["debits user source liquidity", "credits reserve liquidity supply", "decreases obligation borrows"],
    "repay_obligation_liquidity_v2": ["debits user source liquidity", "credits reserve liquidity supply", "decreases obligation borrows"],
    "liquidate_obligation": ["repays the delinquent obligation's debt", "seizes the obligation's collateral"],
    "liquidate_obligation_and_redeem_reserve_collateral": ["liquidates the obligation and redeems seized collateral"],
    "redeem_reserve_collateral": ["burns reserve collateral", "credits the user reserve liquidity"],
    "refresh_reserve": ["updates reserve state from current oracle prices"],
    "refresh_reserves_batch": ["updates multiple reserves from oracle prices"],
    "refresh_obligation": ["updates obligation state from current reserve prices"],
    "refresh_obligations_batch": ["updates multiple obligations from reserve prices"],
    "flash_borrow_reserve_liquidity": ["temporarily borrows reserve liquidity", "the flash loan must be repaid in the same transaction"],
    "flash_repay_reserve_liquidity": ["repays the flash borrow plus fee"],
    "init_farms_for_reserve": ["initializes farms for a reserve"],
    "init_obligation_farms_for_reserve": ["initializes obligation farms for a reserve"],
    "withdraw_protocol_fee": ["withdraws protocol fees to the market owner"],
    "redeem_fees": ["redeems fees from reserves"],
    "update_reserve_config": ["updates reserve configuration"],
    "update_lending_market": ["updates lending market configuration"],
    "update_lending_market_owner": ["updates the lending market owner"],
    "update_global_config": ["updates the global configuration"],
    "update_global_config_admin": ["updates the global config admin"],
    "update_obligation_config": ["updates the obligation configuration"],
    "update_obligation_farms_config": ["updates obligation farms configuration"],
    "update_farms_config": ["updates farms configuration"],
    "update_obligation_tag": ["updates the obligation tag"],
    "deposit_borrow": ["deposits collateral and borrows in one instruction"],
    "deposit_borrow_v2": ["deposits collateral and borrows in one instruction"],
    "withdraw_borrow": ["withdraws collateral and borrows"],
    "withdraw_borrow_v2": ["withdraws collateral and borrows"],
    "repay_withdraw": ["repays and withdraws in one instruction"],
    "repay_withdraw_v2": ["repays and withdraws in one instruction"],
    "seed_deposit_on_init_reserve": ["seeds the initial reserve liquidity"],
    "seed_deposit": ["seeds reserve liquidity"],
    "seed_withdraw": ["withdraws seeded liquidity"],
    "seed_borrow": ["seeds a borrow"],
    "seed_repay": ["repays a seeded borrow"],
    "seed_borrow_slim": ["seeds a borrow (slim)"],
    "seed_repay_slim": ["repays a seeded borrow (slim)"],
}

KLEND_RISK = {
    "withdraw_obligation_collateral": ["withdrawal must match the declared intent and the owner must sign"],
    "borrow_obligation_liquidity": ["borrow must match the declared intent and the owner must sign"],
    "borrow_obligation_liquidity_v2": ["borrow must match the declared intent and the owner must sign"],
    "liquidate_obligation": ["liquidation must target a delinquent obligation"],
    "liquidate_obligation_and_redeem_reserve_collateral": ["liquidation must target a delinquent obligation"],
    "flash_borrow_reserve_liquidity": ["a flash borrow must be repaid in the same transaction"],
    "flash_repay_reserve_liquidity": ["flash repay must settle a prior flash borrow"],
    "update_lending_market_owner": ["changing the market owner must match the declared intent"],
}


def state_changes(prog, name):
    table = DRIFT_STATE if prog == "drift" else KLEND_STATE
    if name in table:
        return table[name]
    if name.startswith("initialize_") or name.startswith("init_"):
        entity = name.split("_", 1)[1].replace("_", " ")
        return [f"initializes the {entity} account for the protocol"]
    if name.startswith("update_"):
        return ["updates a protocol parameter"]
    if name.startswith("delete_"):
        return [f"closes the {name.split('_',1)[1]} account and reclaims rent"]
    return ["protocol state transition"]


def allowed_cpis(prog, name, accounts):
    names = " ".join(snake(a["name"]) for a in accounts)
    if "token_program" in names or "liquidity_token_program" in names or \
       "collateral_token_program" in names or "token_interface" in names or \
       "token_account" in names or "token_vault" in names:
        return list(TOKEN_PROGS)
    return []


def risk_rules(prog, name):
    table = DRIFT_RISK if prog == "drift" else KLEND_RISK
    return list(table.get(name, []))


def main():
    for prog, meta in PROGRAMS.items():
        idl = json.load(open(meta["idl"], encoding="utf-8"))
        # Old manifest, if present, carries curated fields to carry over.
        try:
            old = json.load(open(meta["manifest"], encoding="utf-8"))
        except Exception:
            old = None
        old_map = {}
        if old:
            for ix in old["instructions"]:
                old_map[snake(ix["name"])] = ix

        out = []
        for i in idl["instructions"]:
            nm = i["name"]
            sn = snake(nm)
            disc = hashlib.sha256(("global:" + sn).encode()).hexdigest()[:16]
            acc_names = [a["name"] for a in i.get("accounts", [])]
            acc_snakes = [snake(n) for n in acc_names]
            accounts = []
            for a in i.get("accounts", []):
                is_signer = bool(a.get("isSigner", False))
                is_writable = bool(a.get("isMut", False))
                role = "signer" if is_signer else ("writable" if is_writable else "readonly")
                an = snake(a["name"])
                seeds = []
                if prog == "drift":
                    # user_stats is PDA-constrained ONLY in initialize_user_stats;
                    # elsewhere the program checks has_one/is_stats_for_user
                    # (consistency, not derivation) — see pda_rules().
                    rule = pda_rules("drift").get((sn, an))
                    if rule:
                        seeds = rule(acc_snakes, i)
                else:
                    if sn == "init_obligation" and an == "obligation":
                        seeds = kamino_obligation_rule(acc_snakes, i)
                    else:
                        r = kamino_rule(an, acc_snakes, i, sn)
                        if r:
                            seeds = r
                accounts.append({
                    "name": a["name"],
                    "role": role,
                    "is_writable": is_writable,
                    "is_signer": is_signer,
                    "pda_seeds": seeds,
                })
            old_ix = old_map.get(sn) if old_map else None
            entry = {
                "name": nm,
                "discriminator": disc,
                "accounts": accounts,
                "expected_state_changes": (old_ix.get("expected_state_changes")
                                           if old_ix and old_ix.get("expected_state_changes")
                                           else state_changes(prog, sn)),
                "allowed_cpis": (old_ix.get("allowed_cpis")
                                 if old_ix and old_ix.get("allowed_cpis")
                                 else allowed_cpis(prog, sn, i.get("accounts", []))),
                "risk_rules": (old_ix.get("risk_rules")
                               if old_ix and old_ix.get("risk_rules")
                               else risk_rules(prog, sn)),
            }
            if old_ix and old_ix.get("variable_accounts"):
                entry["variable_accounts"] = True
            if prog == "klend" and sn == "refresh_reserves_batch":
                # Deployed program reads reserve/lending_market pairs from
                # remaining_accounts (handler_refresh_reserves_batch.rs) — the
                # IDL declares zero accounts; mark it variable so the drainer
                # heuristics don't false-flag legitimate batch refreshes.
                entry["variable_accounts"] = True
            out.append(entry)

        out.sort(key=lambda e: e["name"].lower())

        live = meta["live_observed"]
        note = (
            f"C27 build (2026-08-09) from the official deployed-program IDL "
            f"(scripts/{prog}_idl.json, committed for reproducibility). All "
            f"{len(out)} discriminators are DERIVED as "
            f'sha256("global:"+snake_case_name)[0..8] (the IDLs carry no byte '
            f"arrays) and VERIFIED LIVE by on-chain census "
            f"(scripts/census_drift_kamino.py, base58-correct decode): "
            + ", ".join(f"{k}={v}" for k, v in live.items())
            + " all matched the derived value with zero unmatched — the "
            f"convention is proven on the deployed binary. PDA seeds are "
            f"grounded ONLY where the deployed program's account struct seed-"
            f"constrains the derivation (C26: a wrong seed spec would flag "
            f"legitimate txs): Drift initialize_user user="
            f"[user,authority,sub_account_id], initialize_user_stats user_stats="
            f"[user_stats,authority], deposit/withdraw/transfer_deposit "
            f"spot_market_vault=[spot_market_vault,market_index], withdraw "
            f"drift_signer=[drift_signer]; Kamino lending_market_authority="
            f"[lma,market] (every ix carrying it), init_reserve vaults="
            f"[reserve_liq_supply|fee_receiver|reserve_coll_mint|reserve_coll_"
            f"supply, reserve] (ONLY init_reserve — runtime ixs constrain vaults "
            f"by address-from-state, not PDA), init_user_metadata user_metadata="
            f"[user_meta,owner], init_obligation obligation="
            f"[tag,id,owner,market,seed1,seed2]."
        )
        manifest = {
            "graphite_manifest_version": "1.0",
            "protocol": {
                "name": meta["name"],
                "program_id": meta["program_id"],
                "website": meta["website"],
                "github": meta["github"],
                "note": note,
            },
            "version": {
                "label": meta["version"],
                "effective_from_slot": 0,
                "previous_version_ref": meta["prev"],
            },
            "instructions": out,
            "trust_tier": meta["tier"],
        }
        with open(meta["manifest"], "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)
            f.write("\n")

        # Sanity checks.
        names = [e["name"] for e in out]
        discs = [e["discriminator"] for e in out]
        assert len(names) == len(set(names)), "duplicate names"
        assert len(discs) == len(set(discs)), "duplicate discriminators"
        for e in out:
            assert len(e["discriminator"]) == 16, f"bad disc {e['name']}"
        for nm, dv in live.items():
            assert any(e["name"] == nm and e["discriminator"] == dv for e in out), \
                f"{nm}={dv} missing"
        # Every grounded PDA template must reference a real account index.
        for e in out:
            for a in e["accounts"]:
                for s in a["pda_seeds"]:
                    if s.startswith("{account_"):
                        idx = int(s.split("_")[1].rstrip("}"))
                        assert idx < len(a and e["accounts"]), \
                            f"{e['name']}.{a['name']} bad seed {s}"
        print(f"[{prog}] wrote {len(out)} instructions; "
              f"grounded PDAs: {sum(1 for e in out for a in e['accounts'] if a['pda_seeds'])}")

    print("all sanity checks passed")


if __name__ == "__main__":
    main()
