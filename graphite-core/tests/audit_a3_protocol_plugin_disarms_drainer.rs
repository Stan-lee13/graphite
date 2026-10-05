//! A3-05 (2026-09-29 audit): a protocol plugin, even a crashing one, cannot
//! disarm the drainer check.
//!
//! For a program with no manifest, the Risk Engine's Check 3 Case 1 ("three
//! or more unique accounts and no declared state changes: Drainer") is the
//! fail-closed gate `docs/CURRENT.md` describes. `verify_async` extended
//! `expected_state_changes` with `plugins.protocol_rules(..)` for such a
//! program, and the Risk Engine read the same list as L4. Any plugin rule made
//! the list non-empty, so Case 1 could not fire (Case 2 needs six or more
//! accounts). Round 19 (F-19-25) had a panicking plugin push
//! `UNDESCRIBED_INSTRUCTION_EFFECTS`, which is strict for L4 but the opposite
//! for Check 3; and because the panic was caught around
//! `p.protocol_id() == program_id`, a plugin whose `protocol_id()` panicked
//! disarmed Case 1 for every unmanifested program. P8: a plugin may only veto
//! or annotate.
//!
//! The fix takes the Risk Engine's view of the expected state changes before
//! plugin rules are appended. Plugin rules still reach L4, where they can only
//! be compared with what happened; they never clear a block.
//!
//! The control pins that, without plugins, a three-account call on an
//! unmanifested program is a Drainer. The attacks pin that a panicking plugin
//! for another program, and a well-behaved plugin supplying a rule for this
//! one, both leave it Blocked.

use graphite_core::plugin_orchestrator::{
    LayerId, PluginKind, PluginManifest, ProtocolPlugin, ReviewStatus,
};
use graphite_core::policy_engine::WalletProfile;
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};
use std::sync::Arc;

/// Not a seed manifest.
const UNKNOWN_PROGRAM: &str = "4rQz2f4Wc1y7DpQ8v6mW2nN5uM3sR9bHjC1kTv8XwYdL";
const OTHER_PROGRAM: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

fn three_account_call() -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: "transfer".to_string(),
            raw_natural_language: String::new(),
            confidence_of_parse: 1.0,
            extracted_parameters: None,
        },
        program_id: UNKNOWN_PROGRAM.to_string(),
        protocol_version: String::new(),
        instruction_discriminator: "01".to_string(),
        account_addresses: vec![
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".to_string(),
            "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".to_string(),
            "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx".to_string(),
        ],
        instruction_data: Some(vec![1, 0, 0, 0]),
        cpi_targets: vec![],
        wallet_profile: WalletProfile::Gaming,
        behavior_evidence: BehaviorEvidence::default(),
        compute_units: 0,
        account_writes: 0,
        cpi_hops: 0,
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
        real_account_metas: vec![],
        uses_versioned_transaction: false,
        lookup_table_count: 0,
        state_diff: None,
    }
}

fn manifest(name: &str) -> PluginManifest {
    PluginManifest {
        name: name.to_string(),
        version: "1.0.0".to_string(),
        author: "a3".to_string(),
        layer: LayerId::L4StateVerification,
        review_status: ReviewStatus::Approved,
        description: String::new(),
    }
}

/// A protocol plugin for a DIFFERENT program whose `protocol_id()` panics.
struct PanickingProtocolPlugin(PluginManifest);
impl ProtocolPlugin for PanickingProtocolPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.0
    }
    fn protocol_id(&self) -> &str {
        panic!("a3: protocol plugin bug")
    }
    fn semantic_rules(&self, _d: &str) -> Vec<String> {
        vec![]
    }
    fn allowed_cpis(&self, _d: &str) -> Vec<String> {
        vec![]
    }
}

/// A well-behaved protocol plugin that supplies one rule for the program.
struct OneRulePlugin(PluginManifest);
impl ProtocolPlugin for OneRulePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.0
    }
    fn protocol_id(&self) -> &str {
        UNKNOWN_PROGRAM
    }
    fn semantic_rules(&self, _d: &str) -> Vec<String> {
        vec!["updates accounts.config".to_string()]
    }
    fn allowed_cpis(&self, _d: &str) -> Vec<String> {
        vec![]
    }
}

#[test]
fn control_without_plugins_three_accounts_on_an_unmanifested_program_is_a_drainer() {
    let core = GraphiteCore::new();
    let r = core.verify(&three_account_call()).unwrap();
    assert_eq!(r.risk_verdict.status, "Blocked", "{:?}", r.risk_verdict);
    assert!(
        r.risk_verdict
            .findings
            .iter()
            .any(|f| f.pattern == "Drainer"),
        "{:?}",
        r.risk_verdict
    );
}

#[test]
fn attack_a_panicking_protocol_plugin_for_another_program_disarms_the_drainer_check() {
    let mut core = GraphiteCore::new();
    core.register_plugin(PluginKind::Protocol(Arc::new(PanickingProtocolPlugin(
        manifest("a3-panicking-protocol-plugin"),
    ))));
    let _ = OTHER_PROGRAM; // the plugin is "for" no program at all
    let r = core.verify(&three_account_call()).unwrap();
    assert_eq!(
        r.risk_verdict.status, "Blocked",
        "a protocol plugin that crashed must not turn a Drainer block into Clear (fail-open); got {:?}",
        r.risk_verdict
    );
}

#[test]
fn attack_a_protocol_plugin_rule_removes_a_risk_block() {
    // P8: a plugin may veto or annotate, never clear. A ProtocolPlugin rule
    // is documented as evidence for L4, not as an authorization.
    let mut core = GraphiteCore::new();
    core.register_plugin(PluginKind::Protocol(Arc::new(OneRulePlugin(manifest(
        "a3-one-rule-protocol-plugin",
    )))));
    let r = core.verify(&three_account_call()).unwrap();
    assert_eq!(
        r.risk_verdict.status, "Blocked",
        "a ProtocolPlugin's rule text cleared the Drainer block; got {:?}",
        r.risk_verdict
    );
}

/// A protocol plugin whose rule declares the very effect the diff shows.
struct OwnerRulePlugin(PluginManifest);
impl ProtocolPlugin for OwnerRulePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.0
    }
    fn protocol_id(&self) -> &str {
        UNKNOWN_PROGRAM
    }
    fn semantic_rules(&self, _d: &str) -> Vec<String> {
        vec!["reassigns accounts owner".to_string()]
    }
    fn allowed_cpis(&self, _d: &str) -> Vec<String> {
        vec![]
    }
}

/// The three-account call with a diff that hands its first account to
/// another program.
fn call_that_reassigns_an_owner() -> VerificationInput {
    use graphite_core::state_diff::{AccountDelta, AccountSnapshot, DiffProvenance, StateDiff};
    let mut input = three_account_call();
    let account = input.account_addresses[0].clone();
    let snapshot = |owner: &str| AccountSnapshot {
        pubkey: account.clone(),
        lamports: 10_000_000,
        owner: owner.to_string(),
        data_len: 0,
        token: None,
        mint: None,
        extensions: Default::default(),
        transfer_fee_withheld: None,
        transfer_fee_config: None,
        token2022_powers: None,
        data_sha256: None,
        executable: false,
        native_authorities: Vec::new(),
    };
    input.state_diff = Some(StateDiff {
        deltas: vec![AccountDelta {
            pubkey: account.clone(),
            before: Some(snapshot("11111111111111111111111111111111")),
            after: Some(snapshot(OTHER_PROGRAM)),
        }],
        provenance: DiffProvenance::CallerSupplied,
        fee_lamports: 5_000,
        covers_all_writable: false,
        artifact_balance_writes: None,
        artifact_account_universe: None,
        artifact_accounts_undescribed: None,
        transfer_fee_mints: Default::default(),
        token2022_executed: None,
        fee_epoch: None,
        token2022_mints: Default::default(),
        transaction_accounts: None,
        transaction_privileges: None,
    });
    input
}

fn l4_of(r: &graphite_core::verification::VerificationResult) -> (String, String) {
    let l = r
        .layers
        .iter()
        .find(|l| l.layer == "L4_StateVerification")
        .expect("L4 reported");
    (format!("{:?}", l.status), l.reason.clone())
}

/// W15 (external review, verified 2026-10-03): the plugin rules reached the
/// diff comparison, so a rule naming the effect excused it — "reassigns
/// accounts owner" turned an UndeclaredOwnerReassignment from Failed into a
/// pass. A diff is compared with the manifest's own declaration only.
#[test]
fn attack_a_protocol_plugin_rule_excuses_a_critical_state_change() {
    let control = GraphiteCore::new()
        .verify(&call_that_reassigns_an_owner())
        .unwrap();
    let (status, reason) = l4_of(&control);
    assert_eq!(status, "Failed", "control: {reason}");
    assert!(reason.contains("UndeclaredOwnerReassignment"), "{reason}");

    let mut core = GraphiteCore::new();
    core.register_plugin(PluginKind::Protocol(Arc::new(OwnerRulePlugin(manifest(
        "w15-owner-rule-protocol-plugin",
    )))));
    let r = core.verify(&call_that_reassigns_an_owner()).unwrap();
    let (status, reason) = l4_of(&r);
    assert_eq!(
        status, "Failed",
        "a plugin rule excused the takeover: {reason}"
    );
    assert!(reason.contains("UndeclaredOwnerReassignment"), "{reason}");
    assert!(!r.approved);
}
