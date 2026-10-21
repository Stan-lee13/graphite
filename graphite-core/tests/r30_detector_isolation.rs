//! R30 (§8, the Round 29 deliberate-break gap): every Risk Engine check was
//! disabled in turn and the whole suite run. Three checks were caught by
//! almost nothing:
//!
//! - Check 6b (System account creation under a non-`create` intent): no test
//!   failed. Check 9b refuses the same inputs whenever the manifest classes
//!   the instruction `create`, so 6b's own rule was never exercised.
//! - Check 6a (a self-refunding CloseAccount declared as something else): only
//!   the mainnet conformance pin failed.
//! - Check 9 (an intent the program does not serve): one registry unit test.
//!
//! Each is driven here on its own — with no security class, so Check 9b
//! cannot answer for it — with the cause asserted and a control beside it.

use graphite_core::risk_engine::{assess, RiskAssessmentInput, RiskPattern, RiskVerdict};

const SYSTEM: &str = "11111111111111111111111111111111";
const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const A: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const B: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
const C: &str = "9wDJULnQ6to8Z8kYqxJy9hrrwX8G4WmNy8G6pqm5m6X7";

fn input(program: &str, disc: &str, accounts: &[&str], intent: &str) -> RiskAssessmentInput {
    RiskAssessmentInput {
        program_id: program.to_string(),
        accounts: accounts.iter().map(|s| s.to_string()).collect(),
        cpi_targets: vec![],
        expected_state_changes: vec!["debits accounts.from by amount".to_string()],
        allowed_cpis: vec![],
        instruction_discriminator: disc.to_string(),
        expected_account_count: Some(accounts.len()),
        variable_accounts: false,
        proposed_intent_type: intent.to_string(),
        extracted_output_token: None,
        manifest_risk_class: String::new(),
        verified_self_refund_close: false,
        writable_extra_accounts: None,
    }
}

fn blocked_by(v: &RiskVerdict, pattern: RiskPattern, says: &str) -> bool {
    matches!(v, RiskVerdict::Blocked { pattern: p, reason } if *p == pattern && reason.contains(says))
}

#[test]
fn check_6b_refuses_account_creation_under_a_transfer_intent() {
    for disc in ["00000000", "03000000", "08000000", "09000000"] {
        let v = assess(&input(SYSTEM, disc, &[A, B], "transfer")).unwrap();
        assert!(
            blocked_by(
                &v,
                RiskPattern::MaliciousAccountChange,
                "Account allocation/creation detected"
            ),
            "{disc}: {v:?}"
        );
    }
    // Control: the same instruction declared as a creation.
    let v = assess(&input(SYSTEM, "00000000", &[A, B], "create")).unwrap();
    assert!(
        !blocked_by(
            &v,
            RiskPattern::MaliciousAccountChange,
            "Account allocation/creation detected"
        ),
        "{v:?}"
    );
}

#[test]
fn check_6a_refuses_a_self_refunding_close_declared_as_a_transfer() {
    let mut close = input(TOKEN, "09", &[A, B, B], "transfer");
    close.verified_self_refund_close = true;
    let v = assess(&close).unwrap();
    assert!(
        blocked_by(
            &v,
            RiskPattern::MaliciousAccountChange,
            "CloseAccount instruction detected"
        ),
        "{v:?}"
    );
    // Control: declared as the close it is.
    close.proposed_intent_type = "close".to_string();
    let v = assess(&close).unwrap();
    assert!(
        !blocked_by(
            &v,
            RiskPattern::MaliciousAccountChange,
            "CloseAccount instruction detected"
        ),
        "{v:?}"
    );
}

#[test]
fn check_9_refuses_an_intent_the_program_does_not_serve() {
    let v = assess(&input(SYSTEM, "02000000", &[A, C], "swap")).unwrap();
    assert!(
        blocked_by(
            &v,
            RiskPattern::PermissionEscalation,
            "Intent-Program mismatch"
        ),
        "{v:?}"
    );
    // Control: the intent the program serves.
    let v = assess(&input(SYSTEM, "02000000", &[A, C], "transfer")).unwrap();
    assert!(
        !blocked_by(
            &v,
            RiskPattern::PermissionEscalation,
            "Intent-Program mismatch"
        ),
        "{v:?}"
    );
}
