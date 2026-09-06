//! The audit trail must not be storage an attacker chooses the size of.
//!
//! `/data/audit.jsonl` is a Constitution P9 guarantee: the append-only record
//! of every verdict and every rejected probe. Found 2026-09-06 against the
//! running container - a `program_id` of 100,000 characters was echoed verbatim
//! into that file, so anyone able to reach the port could write close to a
//! megabyte of chosen bytes per request onto the operator's volume. Probing
//! alone grew it to 3.6 MB.
//!
//! It is not an approval bypass; nothing malformed was ever approved. It
//! degrades the audit trail, which is the thing that answers "why was this
//! approved last Tuesday", and it exhausts the volume the server refuses to
//! boot without.
//!
//! Two independent defences, tested separately so neither can quietly become
//! the only one: the entry point refuses over-long identifiers before they
//! reach any formatter, and the record itself bounds every caller-influenced
//! field no matter what reaches it.

use graphite_core::durable::{AuditErrorRecord, AuditLog};
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};
use graphite_core::WalletProfile;

const SYSTEM: &str = "11111111111111111111111111111111";
const ALICE: &str = "7vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";
const BOB: &str = "6bSsP4p6wXqFJdD2TkYgNcVmLzHfWq7pRyA8tCzE5nBj";

fn input() -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: "x".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: SYSTEM.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: "02000000".to_string(),
        account_addresses: vec![ALICE.to_string(), BOB.to_string()],
        instruction_data: None,
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        real_account_metas: vec![],
        state_diff: None,
    }
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "graphite-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Defence 1: refuse over-long identifiers at the entry point, and report the
/// LENGTH rather than the value - a rejection that echoes the payload is the
/// amplification vector wearing a different hat.
#[test]
fn oversized_identifiers_are_refused_without_echoing_them() {
    let core = GraphiteCore::new();
    let mut cases: Vec<(&str, VerificationInput)> = Vec::new();

    let mut a = input();
    a.program_id = "A".repeat(100_000);
    cases.push(("program_id", a));

    let mut b = input();
    b.instruction_discriminator = "0".repeat(100_000);
    cases.push(("instruction_discriminator", b));

    let mut c = input();
    c.account_addresses[1] = "B".repeat(100_000);
    cases.push(("account_addresses[1]", c));

    for (field, i) in cases {
        let err = core
            .verify(&i)
            .expect_err("a 100k-character identifier must be refused");
        let msg = err.to_string();
        assert!(
            msg.len() < 400,
            "{field}: the rejection is {} chars - it is echoing the payload back, \
             which is the flooding vector with extra steps",
            msg.len()
        );
        assert!(
            !msg.contains(&"A".repeat(64)) && !msg.contains(&"B".repeat(64)),
            "{field}: the rejection carries the caller's padding: {msg}"
        );
    }
}

/// The identifier caps must not reject anything legitimate: a real base58
/// pubkey is 43-44 characters and has to keep working.
#[test]
fn real_pubkeys_are_comfortably_under_the_cap() {
    let core = GraphiteCore::new();
    for addr in [
        SYSTEM,
        ALICE,
        BOB,
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
    ] {
        assert!(addr.len() <= 44, "{addr} is {} chars", addr.len());
    }
    core.verify(&input())
        .expect("an ordinary transfer must still verify");
}

/// Defence 2: whatever reaches the record, the bytes on disk stay bounded.
#[test]
fn a_single_error_record_cannot_be_made_arbitrarily_large() {
    let dir = temp_dir("audit-flood");
    let path = dir.join("audit.jsonl");
    let log = AuditLog::open(&path).expect("open audit log");

    // A megabyte in every caller-influenced field, as if every upstream guard
    // had been bypassed.
    log.append_error(&AuditErrorRecord {
        timestamp: "2026-09-06T00:00:00Z".to_string(),
        program_id: "A".repeat(1_000_000),
        instruction_name: "B".repeat(1_000_000),
        error: "C".repeat(1_000_000),
        error_type: "D".repeat(1_000_000),
        status: 400,
    });

    let written = std::fs::metadata(&path).expect("audit file").len();
    assert!(
        written < 4_000,
        "one error record wrote {written} bytes to the audit trail - a caller \
         choosing that number is disk exhaustion and a buried trail"
    );

    // Truncation must be visible: a silently shortened field would make an
    // investigator believe they had the whole value.
    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(
        contents.contains("truncated"),
        "the record must say it was truncated: {}",
        &contents[..contents.len().min(300)]
    );
    // And it must still be one parseable JSON line, or the trail is unreadable.
    let line = contents.lines().next().expect("one line");
    let parsed: serde_json::Value = serde_json::from_str(line).expect("record stays valid JSON");
    assert_eq!(parsed["status"], 400);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A short, genuine error must survive intact - the bound cannot cost the
/// diagnostic value the trail exists for.
#[test]
fn an_ordinary_error_record_is_stored_verbatim() {
    let dir = temp_dir("audit-ok");
    let path = dir.join("audit.jsonl");
    let log = AuditLog::open(&path).expect("open audit log");
    log.append_error(&AuditErrorRecord {
        timestamp: "2026-09-06T00:00:00Z".to_string(),
        program_id: SYSTEM.to_string(),
        instruction_name: "02000000".to_string(),
        error: "Invalid address: not-base58".to_string(),
        error_type: "AccountResolution".to_string(),
        status: 400,
    });
    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(contents.contains(SYSTEM), "{contents}");
    assert!(
        contents.contains("Invalid address: not-base58"),
        "{contents}"
    );
    assert!(!contents.contains("truncated"), "{contents}");
    let _ = std::fs::remove_dir_all(&dir);
}
