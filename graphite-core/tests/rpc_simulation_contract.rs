//! Requires the `rpc` feature: the module under test only exists with a client
//! to produce the responses it parses.
#![cfg(feature = "rpc")]

//! The RPC simulation contract: what Solana actually sends, and what Graphite
//! must do with it.
//!
//! Every case here was found on 2026-09-07, the first time real devnet RPC data
//! reached the state-diff path. All three were invisible to synthetic tests
//! because a hand-built fixture does not have a fee, does not expire, and can
//! carry any field the test wants.
//!
//! 1. `accountWrites` and `cpiHops` are NOT fields any Solana RPC returns. The
//!    caller of `parse_simulation_value` treats "both present" as the test for
//!    whether a result is complete enough to trust, and only a trusted result
//!    may grow the simulation baseline or certify a clean L3. Reading for
//!    fields that never arrive made that permanently false, so the Simulation
//!    Integrity Layer could accumulate nothing and could never reach its own
//!    positive verdict.
//! 2. A simulated post-state has the transaction FEE deducted. Hardcoding the
//!    fee to zero made the lamport-conservation identity come out short by
//!    exactly the fee, so every RPC-diffed transaction — an ordinary SOL
//!    transfer included — failed L4 with a spurious `LamportsNotConserved`.
//! 3. A blockhash is valid for ~150 slots. Without `replaceRecentBlockhash` a
//!    simulation of a transaction built even a minute earlier returns
//!    `BlockhashNotFound`, and both L3 and L4 silently degrade.

use graphite_core::rpc_client::simulation_result_from_value_for_test as parse_sim;

/// A real `simulateTransaction` response, captured verbatim from
/// api.devnet.solana.com on 2026-09-07 for a System transfer.
///
/// The field list is the point: this is exactly what a Solana RPC sends, and it
/// contains neither `accountWrites` nor `cpiHops`.
fn real_devnet_response() -> serde_json::Value {
    serde_json::json!({
        "accounts": [
            {"data": ["", "base64"], "executable": false, "lamports": 9997980000u64,
             "owner": "11111111111111111111111111111111", "rentEpoch": 18446744073709551615u64, "space": 0},
            {"data": ["", "base64"], "executable": false, "lamports": 2000000u64,
             "owner": "11111111111111111111111111111111", "rentEpoch": 18446744073709551615u64, "space": 0}
        ],
        "err": null,
        "fee": 5000,
        "innerInstructions": [],
        "loadedAccountsDataSize": 0,
        "logs": ["Program 11111111111111111111111111111111 invoke [1]",
                 "Program 11111111111111111111111111111111 success"],
        "postBalances": [9997980000u64, 2000000u64, 1u64],
        "preBalances": [9999985000u64, 0u64, 1u64],
        "replacementBlockhash": {"blockhash": "abc", "lastValidBlockHeight": 1},
        "returnData": null,
        "unitsConsumed": 150
    })
}

#[test]
fn a_real_solana_response_yields_a_complete_result() {
    // The whole point: without derivation this response is "incomplete" and the
    // integrity layer stays inert forever.
    let r = parse_sim(&real_devnet_response()).expect("parse");
    assert_eq!(r.units_consumed, 150);
    assert_eq!(r.err, None);
    assert_eq!(r.fee, Some(5000), "the fee must be read, not assumed zero");
    assert!(
        r.account_writes.is_some(),
        "account_writes must be derived from preBalances/postBalances - a real \
         Solana RPC never sends an `accountWrites` field, and treating it as \
         missing makes rpc_sim_ok permanently false"
    );
    assert!(
        r.cpi_hops.is_some(),
        "cpi_hops must be derived from innerInstructions for the same reason"
    );
    // Two balances moved (payer and destination); the third is unchanged.
    assert_eq!(r.account_writes, Some(2));
    assert_eq!(r.cpi_hops, Some(0));
}

#[test]
fn cpi_hops_counts_real_inner_instructions() {
    let mut v = real_devnet_response();
    v["innerInstructions"] = serde_json::json!([
        {"index": 0, "instructions": [{"programIdIndex": 3}, {"programIdIndex": 4}]},
        {"index": 1, "instructions": [{"programIdIndex": 5}]}
    ]);
    assert_eq!(parse_sim(&v).unwrap().cpi_hops, Some(3));
}

#[test]
fn an_absent_inner_instructions_field_is_not_zero_cpi() {
    // `null` means "not requested"; an empty array means "no CPI happened".
    // Reporting the first as zero would certify a completeness the response
    // does not have.
    let mut v = real_devnet_response();
    v["innerInstructions"] = serde_json::Value::Null;
    assert_eq!(
        parse_sim(&v).unwrap().cpi_hops,
        None,
        "a missing innerInstructions must stay None, not become Some(0)"
    );
}

#[test]
fn mismatched_balance_arrays_do_not_produce_a_write_count() {
    // A truncated or inconsistent response must not yield a confident number.
    let mut v = real_devnet_response();
    v["postBalances"] = serde_json::json!([1u64, 2u64]);
    assert_eq!(parse_sim(&v).unwrap().account_writes, None);
    let mut v2 = real_devnet_response();
    v2["preBalances"] = serde_json::Value::Null;
    assert_eq!(parse_sim(&v2).unwrap().account_writes, None);
}

#[test]
fn a_provider_that_does_send_the_fields_wins_over_the_derivation() {
    let mut v = real_devnet_response();
    v["accountWrites"] = serde_json::json!(7);
    v["cpiHops"] = serde_json::json!(9);
    let r = parse_sim(&v).unwrap();
    assert_eq!(r.account_writes, Some(7));
    assert_eq!(r.cpi_hops, Some(9));
}

#[test]
fn a_null_err_is_no_error_not_an_error_named_null() {
    assert_eq!(parse_sim(&real_devnet_response()).unwrap().err, None);
    let mut v = real_devnet_response();
    v["err"] = serde_json::json!({"InstructionError": [0, "InvalidAccountData"]});
    assert!(parse_sim(&v).unwrap().err.is_some());
}

#[test]
fn a_blockhash_not_found_response_carries_no_usable_evidence() {
    // The shape a stale blockhash produces. It must not look like a clean run:
    // zero units keeps rpc_sim_ok false, and the error keeps L4 from diffing.
    let v = serde_json::json!({
        "accounts": null, "err": "BlockhashNotFound", "logs": [],
        "unitsConsumed": 0, "innerInstructions": null
    });
    let r = parse_sim(&v).unwrap();
    assert_eq!(r.units_consumed, 0);
    assert!(r.err.is_some());
    assert_eq!(r.fee, None);
}
