//! The "fake rewards" drainer RiskPlugin (L7).
//!
//! Detects the semantic inversion behind reward/airdrop scams: a transaction
//! that *claims* to deliver rewards, airdrops, or bonuses — an intent whose
//! legitimate shape only ever CREDITS the user — but whose expected state
//! changes DEBIT the user's account. A genuine claim credits; a debit inside a
//! rewards-shaped claim is the signature of a drainer.
//!
//! This is deliberately additive to the core Risk Engine: the engine's built-in
//! patterns key off structural signals (account counts, known discriminators,
//! compositional drains). This plugin keys off the intent/state-change
//! INVERSION — a shape the engine's pattern list does not cover.
//!
//! The block is a real hard-block: the orchestrator converts a `Block` verdict
//! into a risk finding on L7, which fails the transaction regardless of
//! confidence (risk findings are binary-and-blocking by design).

use crate::plugin_orchestrator::{
    LayerId, PluginContext, PluginManifest, PluginVerdict, ReviewStatus, RiskPlugin,
};

/// First-party plugin name (discovery key for manifest-driven activation).
pub const NAME: &str = "fake-rewards-drainer";

/// Intent shapes that a genuine rewards claim may have (checked against the
/// structured intent type).
const REWARDS_INTENT_KEYWORDS: [&str; 5] = ["claim", "airdrop", "reward", "bonus", "mint"];

/// Reward-claim words checked against the RAW natural language too. This is
/// the real scam vector: the AI parser normalizes "claim airdrop rewards" to
/// a `transfer` intent (the underlying instruction IS a transfer), so the
/// structured intent alone would miss it. These words are scam-vector-strong
/// ("claim" / "airdrop") — deliberately NOT "bonus", "reward", or "mint",
/// which appear legitimately in everyday text ("send my bonus to…") and would
/// false-positive a hard, policy-non-overridable block.
const REWARDS_NL_KEYWORDS: [&str; 2] = ["claim", "airdrop"];

/// State-change signals that money is moving OUT of the user's account.
/// "withdraw" is deliberately EXCLUDED: staking withdrawals are legitimate
/// rewards-shaped transactions, while a genuine claim never debits.
const OUTBOUND_KEYWORDS: [&str; 2] = ["debit", "deduct"];

/// The risk finding pattern label (surfaced in `RiskVerdictSummary.findings`).
pub const PATTERN: &str = "FakeRewardsDrainer";

/// Deterministic, stateless L7 risk plugin. Implements exactly ONE plugin
/// trait (P8 review rule). `Send + Sync` — safe to share across server clones
/// and concurrent verifications.
#[derive(Debug)]
pub struct FakeRewardsDrainerRiskPlugin {
    manifest: PluginManifest,
}

impl FakeRewardsDrainerRiskPlugin {
    pub fn new() -> Self {
        Self {
            manifest: PluginManifest {
                name: NAME.to_string(),
                version: "1.0.0".to_string(),
                author: "graphite-core".to_string(),
                layer: LayerId::L7RiskVerification,
                review_status: ReviewStatus::Approved,
                description: "Blocks reward/airdrop-shaped claims whose state changes debit the user's account (FakeRewardsDrainer)".to_string(),
            },
        }
    }
}

impl Default for FakeRewardsDrainerRiskPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl RiskPlugin for FakeRewardsDrainerRiskPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn assess_risk(&self, ctx: &PluginContext) -> PluginVerdict {
        let intent = ctx.proposed_intent.intent_type.to_lowercase();
        let raw_nl = ctx.proposed_intent.raw_natural_language.to_lowercase();
        // Rewards-shaped = the structured intent claims rewards, OR the raw
        // natural language asks to claim/airdrop/bonus (which the parser may
        // have normalized into a transfer intent).
        let rewards_shaped = REWARDS_INTENT_KEYWORDS.iter().any(|k| intent.contains(k))
            || REWARDS_NL_KEYWORDS.iter().any(|k| raw_nl.contains(k));
        if !rewards_shaped {
            return PluginVerdict::NoFinding;
        }

        let outbound = ctx.expected_state_changes.iter().any(|s| {
            let s = s.to_lowercase();
            OUTBOUND_KEYWORDS.iter().any(|k| s.contains(k))
        });
        if !outbound {
            return PluginVerdict::NoFinding;
        }

        PluginVerdict::Block {
            pattern: PATTERN.to_string(),
            reason: format!(
                "reward-shaped request ('{}') but the transaction moves value OUT of the user's account ({} state change(s) debit/deduct) — a genuine claim credits, never debits",
                if ctx.proposed_intent.raw_natural_language.trim().is_empty() {
                    &ctx.proposed_intent.intent_type
                } else {
                    &ctx.proposed_intent.raw_natural_language
                },
                ctx.expected_state_changes.len()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin_orchestrator::PluginContext;
    use crate::verification::ProposedIntent;

    /// Build a `'static` context by leaking the owned test data (tests only).
    fn ctx_with(intent: &str, state_changes: &[&str]) -> PluginContext<'static> {
        ctx_with_raw(intent, "", state_changes)
    }

    fn ctx_with_raw(intent: &str, raw_nl: &str, state_changes: &[&str]) -> PluginContext<'static> {
        let changes: Vec<String> = state_changes.iter().map(|s| s.to_string()).collect();
        let changes: &'static Vec<String> = Box::leak(Box::new(changes));
        let intent_owned = ProposedIntent {
            intent_type: intent.to_string(),
            raw_natural_language: raw_nl.to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        };
        let intent_owned: &'static ProposedIntent = Box::leak(Box::new(intent_owned));
        PluginContext {
            program_id: "11111111111111111111111111111111",
            protocol_name: "x",
            instruction_discriminator: "01",
            instruction_name: "y",
            proposed_intent: intent_owned,
            account_addresses: &[],
            cpi_targets: &[],
            expected_state_changes: changes,
            allowed_cpis: &[],
            manifest_found: true,
            compute_units: 0,
            account_writes: 0,
            cpi_hops: 0,
        }
    }

    #[test]
    fn test_manifest_is_l7_and_approved() {
        let p = FakeRewardsDrainerRiskPlugin::new();
        assert_eq!(p.manifest().layer, LayerId::L7RiskVerification);
        assert_eq!(p.manifest().review_status, ReviewStatus::Approved);
    }

    #[test]
    fn test_blocks_claim_with_debit() {
        let p = FakeRewardsDrainerRiskPlugin::new();
        let v = p.assess_risk(&ctx_with(
            "claim",
            &["debits accounts.0 by data.amount lamports"],
        ));
        assert!(matches!(v, PluginVerdict::Block { .. }));
    }

    #[test]
    fn test_blocks_airdrop_with_deduct() {
        let p = FakeRewardsDrainerRiskPlugin::new();
        let v = p.assess_risk(&ctx_with("airdrop", &["deducts 100 lamports"]));
        assert!(matches!(v, PluginVerdict::Block { .. }));
    }

    #[test]
    fn test_claim_without_debit_is_no_finding() {
        // A genuine claim only credits — no false positive.
        let p = FakeRewardsDrainerRiskPlugin::new();
        let v = p.assess_risk(&ctx_with(
            "claim",
            &["credits accounts.1 by data.amount lamports"],
        ));
        assert_eq!(v, PluginVerdict::NoFinding);
    }

    #[test]
    fn test_non_rewards_intent_with_debit_is_no_finding() {
        // A swap legitimately debits — the plugin must not fire outside the
        // rewards-shaped intent class.
        let p = FakeRewardsDrainerRiskPlugin::new();
        let v = p.assess_risk(&ctx_with(
            "swap",
            &["debits accounts.0 by data.amount lamports"],
        ));
        assert_eq!(v, PluginVerdict::NoFinding);
    }

    #[test]
    fn test_staking_withdraw_is_not_blocked() {
        // "withdraw" is deliberately excluded — staking withdrawals are
        // legitimate rewards-shaped transactions.
        let p = FakeRewardsDrainerRiskPlugin::new();
        let v = p.assess_risk(&ctx_with("withdraw", &["withdraws stake account"]));
        assert_eq!(v, PluginVerdict::NoFinding);
    }

    #[test]
    fn test_case_insensitive() {
        let p = FakeRewardsDrainerRiskPlugin::new();
        let v = p.assess_risk(&ctx_with("ClaimRewards", &["Debits accounts.0 by 100"]));
        assert!(matches!(v, PluginVerdict::Block { .. }));
    }

    #[test]
    fn test_blocks_transfer_intent_with_claim_natural_language() {
        // The real scam vector: the parser normalizes "Claim airdrop rewards"
        // into a `transfer` intent (the underlying instruction IS a transfer),
        // so the structured intent alone misses it. The raw NL catches it.
        let p = FakeRewardsDrainerRiskPlugin::new();
        let v = p.assess_risk(&ctx_with_raw(
            "transfer",
            "Claim airdrop rewards now",
            &["debits accounts.from by data.amount lamports"],
        ));
        assert!(matches!(v, PluginVerdict::Block { .. }));
    }

    #[test]
    fn test_plain_transfer_with_reward_mention_is_no_finding() {
        // The standalone words "reward" and "bonus" in everyday text must not
        // fire (only claim/airdrop in raw NL, or a rewards-shaped intent
        // type). "Send my bonus to Alice" is a legit transfer.
        let p = FakeRewardsDrainerRiskPlugin::new();
        for raw in [
            "Send my reward money to Alice",
            "Send the bonus to my friend",
        ] {
            let v = p.assess_risk(&ctx_with_raw(
                "transfer",
                raw,
                &["debits accounts.from by data.amount lamports"],
            ));
            assert_eq!(v, PluginVerdict::NoFinding, "raw NL '{}'", raw);
        }
    }

    #[test]
    fn test_deterministic() {
        let p = FakeRewardsDrainerRiskPlugin::new();
        let c = ctx_with("claim", &["debits accounts.0 by data.amount lamports"]);
        for _ in 0..100 {
            assert_eq!(p.assess_risk(&c), p.assess_risk(&c));
        }
    }
}
