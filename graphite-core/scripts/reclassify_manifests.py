#!/usr/bin/env python3
"""Re-apply the risk-class rules to the shipped manifests, in place.

Round 29 (audit 2026-10-20). Two findings, one deterministic rule set:

  MED-3  `idl_to_manifest.classify()` tested the swap words (which match
         anywhere in a name) before the authority prefixes, so administrators'
         setters shipped as swaps — class `transfer` with the swap credit
         phrase — and names with an authority word but no prefix
         (`pool_config_update`, `shutdown`, `panic_unpause_permissionless`) as
         plain transfers. `classify()` is fixed; this script re-applies it to
         every instruction the generator wrote (recognised by its template
         phrase), but only where the corrected class is STRICTER than the
         shipped one. A class a reviewer already raised by hand (Marinade's
         and SPL Stake Pool's explicit maps, a hand `authority`) is never
         lowered by a name heuristic.

  LOW-1  562 instructions carried no class at all — every Drift instruction,
         most of Kamino, Orca, Squads and the Jupiter routes. An unclassed
         instruction is declarable only by a swap or a revoke intent and is
         refused as a sibling, so they were unusable under most intents and
         undescribed under the rest. Each gets the class the same rules give
         it (name family + account roles), or the one in `OVERRIDES` below
         where a reviewer read the program and the name misleads. Two kinds
         stay unclassed on purpose, because the empty class is the one an
         intent declares (`manifest::INTENT_DECLARES`):
           * `Revoke` (SPL Token, Token-2022, and Metaplex Token Metadata's,
             added in the same round): the revoke intent declares exactly the
             empty class, so a class would make revoking a delegate
             unverifiable;
           * a swap on a swap-category program (Jupiter routes, Meteora,
             Orca, Raydium AMM v4 and pump.fun swaps, DCA/limit fills,
             OpenBook refill): the swap intent declares the empty class, under
             FakeSwap and Check 9; `transfer` — which the generator gives
             swaps — would let a TRANSFER intent declare a swap as well.

Only `risk_class` and, for generated instructions whose class changes, the
generator's own class phrase in `expected_state_changes` are edited; every
other field and the file layout are preserved (`manifest_json`). Run it twice
and the second run changes nothing.

    python3 graphite-core/scripts/reclassify_manifests.py          # apply
    python3 graphite-core/scripts/reclassify_manifests.py --check  # exit 1 if anything would change
"""
import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import idl_to_manifest as gen  # noqa: E402
import manifest_json  # noqa: E402

PROTOCOLS = HERE.parent / "protocols"
NOT_MANIFESTS = ("battle_tested_evidence.json", "verified_program_ids.json")

# How much an instruction of each class is held back: a corrected class is
# applied to a generated instruction only when it ranks higher.
RANK = {"": 0, "inert": 0, "transfer": 1, "create": 1, "withdraw": 2, "close": 2,
        "mint": 2, "stake": 2, "authority": 3, "drain": 3}

# The generator's class phrases, old wording included (`build_new_manifests.py`
# says "the pool" where `idl_to_manifest.py` says "the protocol").
PHRASES = {phrase: family for family, (_, phrase) in gen.CLASSES.items()}
PHRASES["transfers funds between the pool and the involved accounts"] = "transfer"
PHRASES["withdraws funds and transfers them out of the pool to the involved accounts"] = "withdraw"

# Manifests whose classes come from an explicit, reviewed per-instruction map
# rather than the name heuristic (`build_new_manifests.py` MARINADE_CLASS and
# STAKE_POOL_CLASS). The MED-3 pass leaves them alone; their unclassed
# instructions are in OVERRIDES.
EXPLICIT_MAPS = ("marinade.json", "spl-stake-pool.json")

# Instructions left unclassed on purpose (see the module docstring).
UNCLASSED_BY_DESIGN = {
    ("spl-token.json", "Revoke"),
    ("token-2022.json", "Revoke"),
    ("metaplex-token-metadata.json", "Revoke"),
}

# (manifest, instruction) -> (class, why). Classed by hand: the rules above
# give a different answer and the program says otherwise. Reported in full by
# `--list-overrides`.
OVERRIDES = {
    # Program deployment (BPF loaders): writing and finalizing program bytes is
    # part of creating a program account; only the create intent declares it.
    ("bpf-loader-upgradeable.json", "Write"): ("create", "writes program bytes into a buffer the caller is creating"),
    ("bpf-loader-upgradeable.json", "DeployWithMaxDataLen"): ("create", "creates the program and program-data accounts"),
    ("bpf-loader.json", "Write"): ("create", "writes program bytes into the account being created"),
    ("bpf-loader.json", "Finalize"): ("create", "marks the account being created executable"),
    # Drift.
    ("drift.json", "addInsuranceFundStake"): ("transfer", "deposits the user's tokens into the insurance fund vault"),
    ("drift.json", "beginInsuranceFundSwap"): ("authority", "insurance-fund rebalance; signer must be the admin or the IF rebalance authority"),
    ("drift.json", "endInsuranceFundSwap"): ("authority", "insurance-fund rebalance; signer must be the admin or the IF rebalance authority"),
    ("drift.json", "transferProtocolIfSharesToRevenuePool"): ("authority", "moves protocol-owned insurance-fund shares; admin signer"),
    # Jupiter v6.
    ("jupiter-v6.json", "setTokenLedger"): ("inert", "records a token account's balance in the caller's ledger; no signer, moves nothing"),
    # Kamino Lending.
    ("kamino-lending.json", "idlMissingTypes"): ("authority", "IDL type-export stub, not a user operation; fail closed"),
    ("kamino-lending.json", "initReserve"): ("authority", "adds a reserve to a market; lending-market owner only"),
    ("kamino-lending.json", "initFarmsForReserve"): ("authority", "attaches farms to a reserve; lending-market owner only"),
    ("kamino-lending.json", "markObligationForDeleveraging"): ("authority", "lending-market owner only"),
    ("kamino-lending.json", "socializeLoss"): ("authority", "risk council only"),
    ("kamino-lending.json", "socializeLossV2"): ("authority", "risk council only"),
    ("kamino-lending.json", "requestElevationGroup"): ("authority", "changes the obligation's elevation group (its borrow limits); a setting, not a transfer"),
    ("kamino-lending.json", "fillBorrowOrder"): ("withdraw", "pays borrowed liquidity out of the reserve to the destination"),
    # Meteora DLMM: placeholder account lists for instructions that change a
    # pool's fee; fail closed.
    ("meteora-dlmm.json", "add_pool_fee"): ("authority", "changes a pool's fee"),
    ("meteora-dlmm.json", "remove_pool_fee"): ("authority", "changes a pool's fee"),
    # Memo v1 (the other two memo manifests are already inert).
    ("memo-program.json", "Memo"): ("inert", "a memo moves nothing"),
    # Orca Whirlpools: operations reserved to a config, fee, reward or
    # token-badge authority.
    ("orca-whirlpools.json", "collectProtocolFeesV2"): ("authority", "collect-protocol-fees authority only"),
    ("orca-whirlpools.json", "initializeAdaptiveFeeTier"): ("authority", "fee authority only"),
    ("orca-whirlpools.json", "initializeFeeTier"): ("authority", "fee authority only"),
    ("orca-whirlpools.json", "initializeReward"): ("authority", "pool reward authority only"),
    ("orca-whirlpools.json", "initializeRewardV2"): ("authority", "pool reward authority only"),
    ("orca-whirlpools.json", "initializeTokenBadge"): ("authority", "token-badge authority only"),
    ("orca-whirlpools.json", "deleteTokenBadge"): ("authority", "token-badge authority only"),
    ("orca-whirlpools.json", "lockPosition"): ("authority", "locks a position permanently: a change of control, not a transfer"),
    ("orca-whirlpools.json", "idlInclude"): ("inert", "IDL type-include stub; the program's handler does nothing"),
    # Phoenix: market-authority operations and seat requests.
    ("phoenix.json", "RequestSeat"): ("create", "creates the trader's seat account"),
    ("phoenix.json", "NameSuccessor"): ("authority", "names the market authority's successor"),
    ("phoenix.json", "RequestSeatAuthorized"): ("authority", "market authority only"),
    ("phoenix.json", "EvictSeat"): ("authority", "market authority only"),
    ("phoenix.json", "ForceCancelOrders"): ("authority", "market authority only"),
    ("phoenix.json", "CollectFees"): ("authority", "the market's designated sweeper only"),
    # SPL Stake Pool: permissionless balance cranks that move lamports between
    # the pool's own stake accounts and mint the manager's fee.
    ("spl-stake-pool.json", "UpdateValidatorListBalance"): ("transfer", "merges transient stake into the pool's reserve"),
    ("spl-stake-pool.json", "UpdateStakePoolBalance"): ("transfer", "updates the pool total and pays the manager fee"),
    # Squads v4: membership, limits and votes change who controls the vault.
    ("squads-v4.json", "multisigCreate"): ("create", "creates a multisig"),
    ("squads-v4.json", "multisigCreateV2"): ("create", "creates a multisig"),
    ("squads-v4.json", "multisigAddMember"): ("authority", "changes the multisig's members"),
    ("squads-v4.json", "multisigRemoveMember"): ("authority", "changes the multisig's members"),
    ("squads-v4.json", "multisigSetTimeLock"): ("authority", "changes the multisig's time lock"),
    ("squads-v4.json", "multisigAddSpendingLimit"): ("authority", "grants a spending limit"),
    ("squads-v4.json", "multisigRemoveSpendingLimit"): ("authority", "revokes a spending limit"),
    ("squads-v4.json", "multisigSetRentCollector"): ("authority", "changes who collects the multisig's rent"),
    ("squads-v4.json", "configTransactionAccountsClose"): ("close", "closes an executed config transaction's accounts"),
    ("squads-v4.json", "transactionBufferCreate"): ("create", "creates a transaction buffer"),
    ("squads-v4.json", "transactionBufferExtend"): ("create", "extends a transaction buffer"),
    ("squads-v4.json", "batchCreate"): ("create", "creates a batch"),
    ("squads-v4.json", "batchAddTransaction"): ("create", "creates a batch transaction account"),
    ("squads-v4.json", "proposalCreate"): ("create", "creates a proposal"),
    ("squads-v4.json", "proposalActivate"): ("authority", "a member's governance action over the vault"),
    ("squads-v4.json", "proposalApprove"): ("authority", "a member's vote authorising the vault's transaction"),
    ("squads-v4.json", "proposalReject"): ("authority", "a member's governance vote"),
    ("squads-v4.json", "proposalCancel"): ("authority", "a member's governance vote"),
    ("squads-v4.json", "proposalCancelV2"): ("authority", "a member's governance vote"),
    # Stake program.
    ("stake-program.json", "DeactivateDelinquent"): ("stake", "deactivates stake delegated to a delinquent validator"),
    # Switchboard v2: aggregator, job and VRF-pool configuration.
    ("switchboard-v2.json", "aggregator_add_job"): ("authority", "aggregator authority only"),
    ("switchboard-v2.json", "aggregator_remove_job"): ("authority", "aggregator authority only"),
    ("switchboard-v2.json", "aggregator_lock"): ("authority", "aggregator authority only"),
    ("switchboard-v2.json", "aggregator_set_resolution_mode"): ("authority", "aggregator authority only"),
    ("switchboard-v2.json", "aggregator_set_history_buffer"): ("authority", "aggregator authority only"),
    ("switchboard-v2.json", "aggregator_set_queue"): ("authority", "aggregator authority only"),
    ("switchboard-v2.json", "job_set_data"): ("authority", "job authority only"),
    ("switchboard-v2.json", "vrf_pool_add"): ("authority", "VRF pool authority only"),
    ("switchboard-v2.json", "vrf_pool_remove"): ("authority", "VRF pool authority only"),
    ("switchboard-v2.json", "vrf_set_callback"): ("authority", "VRF authority only"),
    # Wormhole core.
    ("wormhole-core.json", "Initialize"): ("authority", "initialises the bridge's guardian set and fee"),
    ("wormhole-core.json", "PostVAA"): ("create", "creates the posted-VAA account"),
    ("wormhole-core.json", "VerifySignatures"): ("create", "creates or fills the signature-set account"),
    # Zeta: the event-queue crank settles fills between margin accounts.
    ("zeta-zetaxs.json", "crankEventQueue"): ("transfer", "settles fills between margin accounts"),
    # Generated instructions where the corrected rule would over-restrict a
    # permissionless or user operation: kept as shipped.
    ("mango-v4-4mango.json", "tokenUpdateIndexAndRate"): ("transfer", "permissionless index crank; no signer"),
    ("mango-v4-4mango.json", "tokenUpdateIndexAndRateResilient"): ("transfer", "permissionless index crank; no signer"),
    ("zap-zapvx9.json", "update_ledger_balance_after_swap"): ("transfer", "a step of the user's own zap"),
    ("perpetuals-perphj.json", "updateDecreasePositionRequest2"): ("withdraw", "the position owner's own close request"),
    # LOW-2.
    ("order-book-mzloyn.json", "idl_instruction"): ("inert", "Anchor's IDL-management instruction surface, declared with no accounts"),
    ("marginfi-v2.json", "lending_account_repay"): ("transfer", "moves the user's tokens into the bank's liquidity vault, like lending_account_deposit"),
}


def rule_class(ix):
    family = gen.refine(gen.classify(ix["name"]), ix["accounts"])
    return family, gen.CLASSES[family][0]


def generated_family(ix):
    for change in ix["expected_state_changes"]:
        if change in PHRASES:
            return PHRASES[change]
    return None


def set_phrase(ix, family):
    """Replace the generator's class phrase with `family`'s."""
    new_phrase = gen.CLASSES[family][1]
    out = []
    for change in ix["expected_state_changes"]:
        out.append(new_phrase if change in PHRASES else change)
    ix["expected_state_changes"] = out


def reclassify(path):
    try:
        data, layout = manifest_json.load(path)
    except ValueError:
        # Hand-formatted; fine as long as nothing in it needs to change.
        import json

        data, layout = json.loads(path.read_text(encoding="utf-8")), None
    name = path.name
    changes = []
    for ix in data["instructions"]:
        key = (name, ix["name"])
        current = ix.get("risk_class", "")
        old_family = generated_family(ix)
        if key in UNCLASSED_BY_DESIGN:
            continue
        if key in OVERRIDES:
            new_class = OVERRIDES[key][0]
            family = None
            if old_family is not None:
                family = next(f for f, (c, _) in gen.CLASSES.items() if c == new_class and f != "swap")
                if new_class == current and old_family is not None:
                    family = None  # kept as shipped: phrase untouched
            why = "override"
        elif current == "":
            family, new_class = rule_class(ix)
            why = "unclassed"
            if family == "swap" and data["protocol"].get("category") == "swap":
                # A swap on a swap program stays unclassed: the empty class is
                # the one the SWAP intent declares (with FakeSwap and Check 9
                # holding it to a swap program that credits an output), and
                # `transfer` would let a TRANSFER intent declare a swap too.
                continue
            if old_family is None:
                family = None  # hand-written prose stays
        elif old_family is not None and name not in EXPLICIT_MAPS:
            family, new_class = rule_class(ix)
            why = "generated"
            stricter = RANK[new_class] > RANK[current]
            # The one change applied at the same class: dropping the swap
            # credit phrase from an instruction that is not a swap (the phrase
            # is what lets a swap intent through FakeSwap).
            drops_swap_phrase = old_family == "swap" and family != "swap" and new_class == current
            if not (stricter or drops_swap_phrase):
                continue
        else:
            continue
        if new_class == current and (family is None or family == old_family):
            continue
        ix["risk_class"] = new_class
        if family is not None and family != old_family:
            set_phrase(ix, family)
        changes.append((ix["name"], current, new_class, why))
    return data, layout, changes


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true", help="change nothing; exit 1 if anything would change")
    ap.add_argument("--list-overrides", action="store_true", help="print the hand-classed instructions")
    args = ap.parse_args()
    if args.list_overrides:
        for (f, n), (c, why) in sorted(OVERRIDES.items()):
            print(f"{f:40} {n:45} {c:10} {why}")
        return 0
    total = 0
    for path in sorted(PROTOCOLS.glob("*.json")):
        if path.name in NOT_MANIFESTS:
            continue
        data, layout, changes = reclassify(path)
        if not changes:
            continue
        total += len(changes)
        for n, old, new, why in changes:
            print(f"{path.name}: {n}: {old or '(none)'} -> {new} [{why}]")
        if not args.check:
            if layout is None:
                raise SystemExit(f"{path.name}: hand-formatted, edit it by hand: {changes}")
            manifest_json.dump(path, data, layout)
    print(f"{total} instruction(s) {'would change' if args.check else 'changed'}")
    return 1 if (args.check and total) else 0


if __name__ == "__main__":
    sys.exit(main())
