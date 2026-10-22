//! R30 (§4.5): how every shipped instruction's declaration parses, pinned.
//!
//! L4 judges an observed diff against `expected_state_changes`. The census
//! below is what the R30 rule for unreadable declarations was measured on:
//! how many declarations are silent, unreadable, mixed (a readable line beside
//! an unreadable one — judged strictly), and how many unreadable ones state a
//! class that moves no value, so that a signer's loss under them blocks even
//! when the operator relaxes the rule. A change to the manifests that moves
//! these numbers fails here, so the rule is re-measured rather than silently
//! re-scoped.
//!
//! Round 32 (R30-F-1 residual): by default a signer's loss under ANY
//! unreadable declaration blocks; the last column counts the unreadable
//! declarations whose class moves value, where the operator's
//! `GRAPHITE_ALLOW_UNREADABLE_VALUE_DECLARATIONS` restores the R30 warning.
//! Measured at `bdc9dab`: 382 unreadable, 227 strict, 155 relaxable. The 16
//! declarations [`REWRITTEN`] names were rewritten from the program's IDL, so
//! 366 remain unreadable (227 strict, 139 relaxable).
use graphite_core::manifest::load_seed_manifests;
use graphite_core::state_diff::{security_class_line, DeclaredEffects};

#[test]
fn every_shipped_declaration_is_classified_as_measured() {
    let reg = load_seed_manifests();
    let (mut total, mut silent, mut unreadable, mut mixed, mut strict, mut relaxable) =
        (0, 0, 0, 0, 0, 0);
    for m in reg.list() {
        for ix in &m.instructions {
            total += 1;
            let mut with_class = ix.expected_state_changes.clone();
            with_class.push(security_class_line(ix.security_class()));
            let e = DeclaredEffects::parse(&with_class);
            if e.is_silent() {
                silent += 1;
            }
            if e.unrecognised {
                unreadable += 1;
                if e.class_moves_value() {
                    relaxable += 1;
                } else {
                    strict += 1;
                }
            }
            let some_line_unread = ix
                .expected_state_changes
                .iter()
                .any(|l| DeclaredEffects::parse(std::slice::from_ref(l)).unrecognised);
            if !e.unrecognised && some_line_unread {
                mixed += 1;
                assert!(e.is_interpretable(), "{}::{}", m.protocol.name, ix.name);
            }
        }
    }
    assert_eq!(
        (total, silent, unreadable, mixed, strict, relaxable),
        (3541, 0, 366, 38, 227, 139),
        "(instructions, silent, unreadable, mixed, unreadable-and-strict-even-when-relaxed, unreadable-and-relaxable)"
    );
}

/// Round 32: the declarations rewritten from the program's IDL (program,
/// instruction, the IDL file the accounts were checked against).
const REWRITTEN: &[(&str, &str, &str)] = &[
    (
        "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc",
        "increaseLiquidityV2",
        ORCA_IDL,
    ),
    (
        "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc",
        "increaseLiquidityByTokenAmountsV2",
        ORCA_IDL,
    ),
    (
        "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc",
        "decreaseLiquidity",
        ORCA_IDL,
    ),
    (
        "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc",
        "decreaseLiquidityV2",
        ORCA_IDL,
    ),
    (
        "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc",
        "collectFees",
        ORCA_IDL,
    ),
    (
        "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc",
        "collectFeesV2",
        ORCA_IDL,
    ),
    (
        "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc",
        "collectRewardV2",
        ORCA_IDL,
    ),
    (
        "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo",
        "add_liquidity_by_strategy",
        DLMM_IDL,
    ),
    (
        "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo",
        "add_liquidity_by_strategy_one_side",
        DLMM_IDL,
    ),
    (
        "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo",
        "remove_liquidity",
        DLMM_IDL,
    ),
    (
        "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo",
        "remove_liquidity_by_range",
        DLMM_IDL,
    ),
    (
        "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo",
        "claim_fee",
        DLMM_IDL,
    ),
    (
        "KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD",
        "depositObligationCollateral",
        KLEND_IDL,
    ),
    (
        "KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD",
        "depositObligationCollateralV2",
        KLEND_IDL,
    ),
    (
        "KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD",
        "withdrawObligationCollateralV2",
        KLEND_IDL,
    ),
    (
        "MFv2hWf31Z9kbCa1snEPYctwafyhdvnV7FZnsebVacA",
        "lending_account_borrow",
        MARGINFI_IDL,
    ),
];
const ORCA_IDL: &str = "scripts/out/onchain_idls/whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc.json";
const DLMM_IDL: &str = "scripts/idls/meteora-dlmm.json";
const KLEND_IDL: &str = "scripts/out/onchain_idls/KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD.json";
const MARGINFI_IDL: &str =
    "scripts/out/onchain_idls/MFv2hWf31Z9kbCa1snEPYctwafyhdvnV7FZnsebVacA.json";

/// The IDL's accounts for `name` (nested account groups flattened), each with
/// whether it is writable and whether it signs.
fn idl_accounts(file: &str, name: &str) -> Vec<(String, bool, bool)> {
    let norm = |s: &str| {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_lowercase()
    };
    let path = format!("{}/{file}", env!("CARGO_MANIFEST_DIR"));
    let idl: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let ix = idl["instructions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| norm(i["name"].as_str().unwrap()) == norm(name))
        .unwrap_or_else(|| panic!("{file} has no {name}"));
    fn walk(accs: &serde_json::Value, out: &mut Vec<(String, bool, bool)>) {
        for a in accs.as_array().unwrap() {
            if a.get("accounts").is_some() {
                walk(&a["accounts"], out);
            } else {
                let flag = |k: &str, legacy: &str| {
                    a.get(k)
                        .or_else(|| a.get(legacy))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                };
                out.push((
                    a["name"].as_str().unwrap().to_string(),
                    flag("writable", "isMut"),
                    flag("signer", "isSigner"),
                ));
            }
        }
    }
    let mut out = Vec::new();
    walk(&ix["accounts"], &mut out);
    out.into_iter().map(|(n, w, s)| (norm(&n), w, s)).collect()
}

/// Every rewritten declaration is read in full (no unread line), names only
/// accounts of its own layout, and every account it moves tokens out of or
/// into is one the IDL marks writable and not a signer — the declaration says
/// what the IDL's accounts say and nothing it invented.
#[test]
fn the_idl_rewritten_declarations_are_read_and_name_only_the_idls_accounts() {
    let reg = load_seed_manifests();
    for (program, name, idl) in REWRITTEN {
        let m = reg.get(program).unwrap();
        let ix = m
            .instructions
            .iter()
            .find(|i| i.name == *name)
            .unwrap_or_else(|| panic!("{name}"));
        let mut with_class = ix.expected_state_changes.clone();
        with_class.push(security_class_line(ix.security_class()));
        let e = DeclaredEffects::parse(&with_class);
        assert!(
            e.is_interpretable(),
            "{name}: {:?}",
            ix.expected_state_changes
        );
        assert!(e.debit && e.credit, "{name}");
        for line in &ix.expected_state_changes {
            assert!(
                !DeclaredEffects::parse(std::slice::from_ref(line)).unrecognised,
                "{name}: {line}"
            );
        }
        let accounts = idl_accounts(idl, name);
        let layout: Vec<String> = ix
            .accounts
            .iter()
            .map(|a| {
                a.name
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric())
                    .collect::<String>()
                    .to_lowercase()
            })
            .collect();
        for (k, slot) in layout.iter().enumerate() {
            assert_eq!(&accounts[k].0, slot, "{name}: slot {k}");
        }
        let mut named = 0;
        for line in &ix.expected_state_changes {
            for (i, _) in line.match_indices("accounts.") {
                let reference: String = line[i + 9..]
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                let slot = ix
                    .accounts
                    .iter()
                    .position(|a| a.name == reference)
                    .unwrap_or_else(|| panic!("{name}: `{reference}` is not in the layout"));
                let (_, writable, signer) = &accounts[slot];
                assert!(*writable && !*signer, "{name}: `{reference}`");
                named += 1;
            }
        }
        assert!(named >= 2, "{name}: names its source and its destination");
    }
}

/// Round 34 (K-7): every seed instruction whose program has a committed
/// on-chain IDL (`scripts/out/onchain_idls/<program>.json`) carries, in one of
/// its layouts, as many account slots as the IDL names (nested groups
/// flattened). Orca's `increaseLiquidityByTokenAmountsV2` had 15 where the
/// IDL has 16 (a trailing `whirlpool_program`), so the slot the program reads
/// was outside every layout.
///
/// The mismatches below are measured and pinned, not fixed: in each the
/// on-chain IDL appends one account the manifest's layout lacks — Kamino's
/// `instructionSysvarAccount` on ten administrative instructions, and Orca's
/// `whirlpool_program` on every other instruction. Neither is unambiguous:
/// the Orca manifest's `swapV2` layout was checked position-for-position
/// against an executed mainnet transaction with 15 accounts and a tick-array
/// tail, so whether the trailing program account is required (a newer program
/// version) or rides in the remaining accounts cannot be read from the IDL
/// alone, and the committed mainnet sample has no top-level Orca instruction
/// to settle it. A new mismatch fails here, and so does fixing a pinned one
/// (remove it from the list).
#[test]
fn every_instruction_with_an_onchain_idl_has_the_idls_slot_count() {
    const ORCA: &str = "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc";
    const KLEND: &str = "KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD";
    const KNOWN: &[(&str, &str)] = &[
        (KLEND, "idlMissingTypes"),
        (KLEND, "initFarmsForReserve"),
        (KLEND, "initGlobalConfig"),
        (KLEND, "initLendingMarket"),
        (KLEND, "initReserve"),
        (KLEND, "updateGlobalConfig"),
        (KLEND, "updateGlobalConfigAdmin"),
        (KLEND, "updateLendingMarketOwner"),
        (KLEND, "updateReserveConfig"),
        (KLEND, "withdrawProtocolFee"),
        (ORCA, "closeBundledPosition"),
        (ORCA, "closePosition"),
        (ORCA, "closePositionWithTokenExtensions"),
        (ORCA, "collectFees"),
        (ORCA, "collectFeesV2"),
        (ORCA, "collectProtocolFees"),
        (ORCA, "collectProtocolFeesV2"),
        (ORCA, "collectReward"),
        (ORCA, "collectRewardV2"),
        (ORCA, "decreaseLiquidity"),
        (ORCA, "decreaseLiquidityV2"),
        (ORCA, "deletePositionBundle"),
        (ORCA, "deleteTokenBadge"),
        (ORCA, "idlInclude"),
        (ORCA, "increaseLiquidity"),
        (ORCA, "increaseLiquidityV2"),
        (ORCA, "initializeAdaptiveFeeTier"),
        (ORCA, "initializeConfig"),
        (ORCA, "initializeConfigExtension"),
        (ORCA, "initializeDynamicTickArray"),
        (ORCA, "initializeFeeTier"),
        (ORCA, "initializePool"),
        (ORCA, "initializePoolV2"),
        (ORCA, "initializePoolWithAdaptiveFee"),
        (ORCA, "initializePositionBundle"),
        (ORCA, "initializePositionBundleWithMetadata"),
        (ORCA, "initializeReward"),
        (ORCA, "initializeRewardV2"),
        (ORCA, "initializeTickArray"),
        (ORCA, "initializeTokenBadge"),
        (ORCA, "lockPosition"),
        (ORCA, "migrateRepurposeRewardAuthoritySpace"),
        (ORCA, "openBundledPosition"),
        (ORCA, "openPosition"),
        (ORCA, "openPositionWithMetadata"),
        (ORCA, "openPositionWithTokenExtensions"),
        (ORCA, "repositionLiquidityV2"),
        (ORCA, "resetPositionRange"),
        (ORCA, "setAdaptiveFeeConstants"),
        (ORCA, "setCollectProtocolFeesAuthority"),
        (ORCA, "setConfigExtensionAuthority"),
        (ORCA, "setConfigFeatureFlag"),
        (ORCA, "setDefaultBaseFeeRate"),
        (ORCA, "setDefaultFeeRate"),
        (ORCA, "setDefaultProtocolFeeRate"),
        (ORCA, "setDelegatedFeeAuthority"),
        (ORCA, "setFeeAuthority"),
        (ORCA, "setFeeRate"),
        (ORCA, "setFeeRateByDelegatedFeeAuthority"),
        (ORCA, "setInitializePoolAuthority"),
        (ORCA, "setPresetAdaptiveFeeConstants"),
        (ORCA, "setProtocolFeeRate"),
        (ORCA, "setRewardAuthority"),
        (ORCA, "setRewardAuthorityBySuperAuthority"),
        (ORCA, "setRewardEmissions"),
        (ORCA, "setRewardEmissionsSuperAuthority"),
        (ORCA, "setRewardEmissionsV2"),
        (ORCA, "setTokenBadgeAttribute"),
        (ORCA, "setTokenBadgeAuthority"),
        (ORCA, "swap"),
        (ORCA, "swapV2"),
        (ORCA, "transferLockedPosition"),
        (ORCA, "twoHopSwap"),
        (ORCA, "twoHopSwapV2"),
        (ORCA, "updateFeesAndRewards"),
    ];
    let norm = |s: &str| {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_lowercase()
    };
    fn count(accs: &serde_json::Value) -> usize {
        accs.as_array()
            .map(|a| {
                a.iter()
                    .map(|x| {
                        if x.get("accounts").is_some() {
                            count(&x["accounts"])
                        } else {
                            1
                        }
                    })
                    .sum()
            })
            .unwrap_or(0)
    }
    let reg = load_seed_manifests();
    let (mut compared, mut found) = (0usize, Vec::new());
    for m in reg.list() {
        let path = format!(
            "{}/scripts/out/onchain_idls/{}.json",
            env!("CARGO_MANIFEST_DIR"),
            m.protocol.program_id
        );
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let idl: serde_json::Value = serde_json::from_str(&text).unwrap();
        let Some(ixs) = idl["instructions"].as_array() else {
            continue;
        };
        for ix in &m.instructions {
            let Some(on_chain) = ixs
                .iter()
                .find(|i| i["name"].as_str().is_some_and(|n| norm(n) == norm(&ix.name)))
            else {
                continue;
            };
            compared += 1;
            let slots = count(&on_chain["accounts"]);
            if !ix.all_layouts().any(|l| l.len() == slots) {
                found.push((m.protocol.program_id.clone(), ix.name.clone()));
            }
        }
    }
    found.sort();
    let mut known: Vec<(String, String)> = KNOWN
        .iter()
        .map(|(p, n)| (p.to_string(), n.to_string()))
        .collect();
    known.sort();
    assert!(compared > 2_800, "{compared} instructions compared");
    assert_eq!(
        found, known,
        "the manifests whose slot count differs from their on-chain IDL changed"
    );
}

/// Every `accounts.<name>` a shipped declaration references names an account
/// of one of the instruction's layouts. A reference to no slot scopes its
/// effect to nothing: Pump.fun's `buy_v2`/`sell_v2` named `associated_user`,
/// the v1 slot the v2 layout calls `associated_base_user`, so the user's base
/// token debit on a sell was outside every declared scope (Round 32).
#[test]
fn every_declared_account_reference_names_a_layout_account() {
    let reg = load_seed_manifests();
    let mut refs = 0;
    for m in reg.list() {
        for ix in &m.instructions {
            for line in &ix.expected_state_changes {
                for (i, _) in line.match_indices("accounts.") {
                    // `accounts.` inside a longer word is not a reference.
                    if line[..i]
                        .chars()
                        .last()
                        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
                    {
                        continue;
                    }
                    let reference: String = line[i + 9..]
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect();
                    refs += 1;
                    assert!(
                        ix.all_layouts()
                            .any(|l| l.iter().any(|a| a.name == reference)),
                        "{}::{}: `accounts.{reference}` names no account of its layouts",
                        m.protocol.name,
                        ix.name
                    );
                }
            }
        }
    }
    assert!(refs > 200, "{refs}");
}
