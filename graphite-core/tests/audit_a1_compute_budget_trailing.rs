//! A1-02 (2026-09-29 audit): Compute Budget instructions with trailing data
//! bytes are read the way the runtime reads them.
//!
//! agave decodes Compute Budget data with `try_from_slice_unchecked`
//! (`compute_budget_instruction_details.rs`), which reads the tag and the
//! fixed-width value and ignores whatever follows: `[3, price u64 LE, extra]`
//! sets the price and `[2, limit u32 LE, extra]` sets the limit.
//! `tx_artifact::compute_budget_request` required exact lengths and skipped
//! any other data as "of the wrong length", a disclosure nothing refused on.
//! A trailing byte on the price made Graphite read a fee of zero; one on the
//! limit made it apply the default (200,000 CU per non-budget instruction)
//! where the runtime applied 1,400,000. Either way the Round 21
//! `ExcessivePriorityFee` bound judged a fee far below what the payer is
//! charged.
//!
//! The fix refuses only data too short to decode. Trailing bytes are accepted
//! and the value before them is the value judged; duplicate detection counts
//! the trailing-byte forms too. `round21_open_list.rs` was updated for the
//! corrected rule.
//!
//! These tests pin that a price and a limit behind a trailing byte are read,
//! and that through the pipeline an implausible priority fee hidden that way
//! is still refused. The control reads the canonical encoding.

use graphite_core::tx_artifact::{compute_budget_request, parse_transaction};

const CB: &str = "ComputeBudget111111111111111111111111111111";

/// keys [payer, recipient, system, compute budget]; the budget instructions
/// first, then one System transfer — the same shape as
/// `round21_open_list::compute_budget::legacy`.
fn legacy(budget: &[Vec<u8>]) -> Vec<u8> {
    let cb: [u8; 32] = bs58::decode(CB).into_vec().unwrap().try_into().unwrap();
    let keys = [[1u8; 32], [2u8; 32], [0u8; 32], cb];
    let mut out = vec![1u8];
    out.extend_from_slice(&[0u8; 64]);
    out.extend_from_slice(&[1, 0, 2]);
    out.push(keys.len() as u8);
    for k in &keys {
        out.extend_from_slice(k);
    }
    out.extend_from_slice(&[9u8; 32]);
    out.push((budget.len() + 1) as u8);
    for data in budget {
        out.extend_from_slice(&[3, 0, data.len() as u8]);
        out.extend_from_slice(data);
    }
    let mut transfer = vec![2u8, 0, 0, 0];
    transfer.extend_from_slice(&1u64.to_le_bytes());
    out.extend_from_slice(&[2, 2, 0, 1, transfer.len() as u8]);
    out.extend_from_slice(&transfer);
    out
}

fn limit(n: u32) -> Vec<u8> {
    let mut d = vec![2u8];
    d.extend_from_slice(&n.to_le_bytes());
    d
}
fn price(n: u64) -> Vec<u8> {
    let mut d = vec![3u8];
    d.extend_from_slice(&n.to_le_bytes());
    d
}
fn with_trailing_byte(mut d: Vec<u8>) -> Vec<u8> {
    d.push(0);
    d
}

fn budget(frame: &[u8]) -> graphite_core::tx_artifact::ComputeBudgetRequest {
    compute_budget_request(&parse_transaction(frame).expect("parses"))
}

/// Control: the canonical encoding is read.
#[test]
fn control_canonical_price_and_limit_are_read() {
    let b = budget(&legacy(&[limit(1_400_000), price(1_000_000_000)]));
    assert_eq!(b.compute_unit_price_micro_lamports, Some(1_000_000_000));
    assert_eq!(b.priority_fee_lamports, 1_400_000_000);
}

/// (a) The price behind a trailing byte is read, not dropped as the wrong length.
#[test]
fn a_price_with_a_trailing_byte_is_the_price_the_runtime_charges() {
    let b = budget(&legacy(&[
        limit(1_400_000),
        with_trailing_byte(price(1_000_000_000)),
    ]));
    assert_eq!(
        b.compute_unit_price_micro_lamports,
        Some(1_000_000_000),
        "agave's try_from_slice_unchecked reads this price; problems: {:?}",
        b.problems
    );
    assert_eq!(b.priority_fee_lamports, 1_400_000_000);
}

/// (b) The limit behind a trailing byte is read, not replaced by the default.
#[test]
fn a_limit_with_a_trailing_byte_is_the_limit_the_runtime_applies() {
    let b = budget(&legacy(&[
        with_trailing_byte(limit(1_400_000)),
        price(500_000_000),
    ]));
    assert_eq!(
        b.compute_unit_limit,
        Some(1_400_000),
        "problems: {:?}",
        b.problems
    );
    // 500,000,000 micro-lamports x 1,400,000 CU / 1e6 = 0.7 SOL, not the
    // 0.1 SOL the default 200,000 CU limit implies.
    assert_eq!(b.priority_fee_lamports, 700_000_000);
}

/// Through the pipeline: the gate that exists to refuse this fee fires when
/// the price carries a trailing byte.
#[cfg(any(feature = "rpc", feature = "cli"))]
#[test]
fn an_implausible_priority_fee_behind_a_trailing_byte_is_still_refused() {
    use graphite_core::manifest::load_seed_manifests;
    use graphite_core::policy_engine::WalletProfile;
    use graphite_core::semantic_graph_store::BehaviorEvidence;
    use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};

    let core = GraphiteCore::with_registry(load_seed_manifests());
    let run = |frame: Vec<u8>| {
        let mut data = vec![2u8, 0, 0, 0];
        data.extend_from_slice(&1u64.to_le_bytes());
        core.verify(&VerificationInput {
            proposed_intent: ProposedIntent {
                intent_type: "transfer".to_string(),
                raw_natural_language: "send 1 lamport".to_string(),
                confidence_of_parse: 0.9,
                extracted_parameters: None,
            },
            program_id: "11111111111111111111111111111111".to_string(),
            protocol_version: "1.0.0".to_string(),
            instruction_discriminator: "02000000".to_string(),
            account_addresses: vec![
                bs58::encode([1u8; 32]).into_string(),
                bs58::encode([2u8; 32]).into_string(),
            ],
            instruction_data: Some(data),
            cpi_targets: vec![],
            wallet_profile: WalletProfile::Gaming,
            behavior_evidence: BehaviorEvidence::default(),
            compute_units: 0,
            account_writes: 0,
            cpi_hops: 0,
            signed_transaction: Some(frame),
            transaction_instructions: vec![],
            cpi_trace: None,
            uses_versioned_transaction: false,
            lookup_table_count: 0,
            real_account_metas: vec![],
            state_diff: None,
        })
        .expect("verified")
    };
    let has_fee_finding = |r: &graphite_core::verification::VerificationResult| {
        r.risk_verdict
            .findings
            .iter()
            .any(|f| f.pattern == "ExcessivePriorityFee")
    };
    // Control: canonical encoding, 1.4 SOL priority fee.
    let r = run(legacy(&[limit(1_400_000), price(1_000_000_000)]));
    assert!(has_fee_finding(&r), "{:?}", r.risk_verdict);
    // The same fee, one trailing byte on the price.
    let r = run(legacy(&[
        limit(1_400_000),
        with_trailing_byte(price(1_000_000_000)),
    ]));
    assert!(
        has_fee_finding(&r),
        "a 1.4 SOL priority fee the runtime charges was read as 0: {:?}",
        r.risk_verdict
    );
}
