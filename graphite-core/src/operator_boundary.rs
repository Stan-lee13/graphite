//! What the server applies at its trust boundary from its environment, in
//! one place for the server and for `graphite verify`/`explain`.
//!
//! Audit 2026-10-20 (L11): the CLI answered "what would the gate decide about
//! this?" with a different gate. It ignored `GRAPHITE_WALLET_PROFILE`, the
//! clamp the server applies to a weak caller-supplied `Custom` profile (and
//! its `GRAPHITE_ALLOW_PERMISSIVE_PROFILES` opt-out), the plugins in
//! `GRAPHITE_PLUGINS_DIR` and `GRAPHITE_ALLOW_DURABLE_NONCE` /
//! `GRAPHITE_QUARANTINE_ON_UPGRADE`, so an operator could read APPROVED here
//! for a request the server refused, or the reverse. The rules now live here
//! and both read them; nothing is restated.
//!
//! It is its own module, gated by no feature, so the server and the CLI
//! can both use it without one feature having to enable the other.

use crate::confidence_engine::TrustTier;
use crate::policy_engine::{
    WalletProfile, WEAKEST_BUILTIN_MIN_CONFIDENCE, WEAKEST_BUILTIN_MIN_TRUST_TIER,
};
use crate::verification::GraphiteCore;
use std::path::PathBuf;

/// A boolean switch from the environment, read strictly: unset, empty,
/// `0` or `false` is off; `1` or `true` is on (case and surrounding
/// whitespace ignored); anything else is a configuration error, so a
/// typo is never a silent "off" (audit 2026-10-20: several switches read
/// anything but `1`/`true` as off, one of them without trimming).
pub fn env_flag(name: &str, value: Option<&str>) -> Result<bool, String> {
    match value.map(str::trim) {
        None | Some("") | Some("0") => Ok(false),
        Some("1") => Ok(true),
        Some(v) if v.eq_ignore_ascii_case("true") => Ok(true),
        Some(v) if v.eq_ignore_ascii_case("false") => Ok(false),
        Some(v) => Err(format!(
            "{name}={v:?} is not 1, true, 0 or false. REFUSING TO START."
        )),
    }
}

/// A non-negative integer from the environment: unset or empty is
/// `default`; anything that does not parse, or that `valid` refuses, is
/// a configuration error naming the variable and what it accepts (audit
/// 2026-10-20: these fell back to their defaults silently, so a typo'd
/// limit ran with a value nobody chose).
pub fn env_number<T: std::str::FromStr + Copy>(
    name: &str,
    value: Option<&str>,
    default: T,
    accepts: &str,
    valid: impl Fn(T) -> bool,
) -> Result<T, String> {
    match value.map(str::trim) {
        None | Some("") => Ok(default),
        Some(v) => match v.parse::<T>() {
            Ok(n) if valid(n) => Ok(n),
            _ => Err(format!(
                "invalid {name} {v:?}: must be {accepts}. REFUSING TO START."
            )),
        },
    }
}

/// Every `GRAPHITE_*` variable the Core reads (Round 36, F-020). Kept
/// complete by `tests/round36_env_names.rs`, which reads the source.
pub const CORE_ENV_NAMES: &[&str] = &[
    "GRAPHITE_ADMIN_API_KEY",
    "GRAPHITE_ALLOW_DURABLE_NONCE",
    "GRAPHITE_ALLOW_PERMISSIVE_PROFILES",
    "GRAPHITE_ALLOW_SIGNER_LAMPORTS_OUTSIDE_DECLARED_DEBIT",
    "GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS",
    "GRAPHITE_ALLOW_UNREADABLE_VALUE_DECLARATIONS",
    "GRAPHITE_API_KEY",
    "GRAPHITE_AUDIT_ANCHOR_DIR",
    "GRAPHITE_AUDIT_KEY_FILE",
    "GRAPHITE_AUDIT_MAX_ARCHIVES",
    "GRAPHITE_AUDIT_PREVIOUS_KEY_FILE",
    "GRAPHITE_AUDIT_ROTATE_BYTES",
    "GRAPHITE_CONNECTION_LIFETIME_SECS",
    "GRAPHITE_CORS_ORIGINS",
    "GRAPHITE_DATA_DIR",
    "GRAPHITE_DEV_MODE",
    "GRAPHITE_GRAPH_STATE",
    "GRAPHITE_L8_HIGH_ASSURANCE",
    "GRAPHITE_LEARN_FROM_POLICY_REFUSALS",
    "GRAPHITE_LOG_FORMAT",
    "GRAPHITE_MAX_CONCURRENT",
    "GRAPHITE_MAX_CONNECTIONS",
    "GRAPHITE_MAX_CONNECTIONS_PER_IP",
    "GRAPHITE_PLUGINS_DIR",
    "GRAPHITE_PLUGIN_EVENTS_FILE",
    "GRAPHITE_QUARANTINE_ON_UPGRADE",
    "GRAPHITE_RATE_LIMIT",
    "GRAPHITE_READ_API_KEY",
    "GRAPHITE_REGISTRY_STATE",
    "GRAPHITE_RPC_PROVIDER",
    "GRAPHITE_RPC_URL",
    "GRAPHITE_RPC_WITNESS_PROVIDER",
    "GRAPHITE_RPC_WITNESS_URL",
    "GRAPHITE_SIGNER_KEY_FILE",
    "GRAPHITE_TRUST_PROXY",
    "GRAPHITE_WALLET_PROFILE",
];

/// `GRAPHITE_*` names other Graphite components read (the agent guard and
/// its adapters, the dashboard, the deploy kit, CI and the measurement
/// tools). The AI layer's are [`AI_LAYER_ENV_PREFIX`]: the Core names none
/// of them (`tests/ai_layer_isolation.rs`, P1). Never a misspelling of a Core name, even when one is
/// a letter away from one. Kept complete by `tests/round36_env_names.rs`.
pub const COMPONENT_ENV_NAMES: &[&str] = &[
    "GRAPHITE_ACCEPT_UNOBSERVED",
    "GRAPHITE_ALLOWED_DESTINATIONS",
    "GRAPHITE_ALLOW_UNCAPPED",
    "GRAPHITE_BIN",
    "GRAPHITE_BINARY",
    "GRAPHITE_CONTRACT_GATE_REQUIRED",
    "GRAPHITE_CORE_URL",
    "GRAPHITE_DASHBOARD_SOURCEMAP",
    "GRAPHITE_DEVNET_RPC_URL",
    "GRAPHITE_GUARD_ALLOW_SHARED_WALLET",
    "GRAPHITE_GUARD_LOCK_DIR",
    "GRAPHITE_GUARD_STATE_FILE",
    "GRAPHITE_HEALTH_URL",
    "GRAPHITE_IMAGE",
    "GRAPHITE_IMAGE_DIGEST",
    "GRAPHITE_LIVE_RPC_URL",
    "GRAPHITE_MAINNET_HONEST_INTENT",
    "GRAPHITE_MAINNET_LIVE_LIMIT",
    "GRAPHITE_MAINNET_REASONS",
    "GRAPHITE_MAINNET_REQUESTS",
    "GRAPHITE_MAINNET_RPC_URL",
    "GRAPHITE_MAINNET_SAMPLE",
    "GRAPHITE_MAINNET_SHOW_DRAINER",
    "GRAPHITE_MAINNET_SHOW_L2",
    "GRAPHITE_MAINNET_SHOW_RISK",
    "GRAPHITE_MAINNET_VERDICTS",
    "GRAPHITE_MAX_TOTAL_LAMPORTS",
    "GRAPHITE_MAX_TRANSFER_LAMPORTS",
    "GRAPHITE_MAX_VERDICT_AGE_MS",
    "GRAPHITE_MCP_CONFIRMATION",
    "GRAPHITE_RESEAL_HOLDOUT",
    "GRAPHITE_RPC_TIMEOUT_MS",
    "GRAPHITE_SERVER_URL",
    "GRAPHITE_SITE",
    "GRAPHITE_SPEND_WINDOW_SECONDS",
    "GRAPHITE_SWAP_ALLOW_UNPRICED",
    "GRAPHITE_SWAP_ALLOW_UNVERIFIED_EXECUTION",
    "GRAPHITE_SWAP_COMPUTE_UNIT_LIMIT",
    "GRAPHITE_SWAP_COMPUTE_UNIT_PRICE",
    "GRAPHITE_SWAP_CREATE_OUTPUT_ATA",
    "GRAPHITE_SWAP_MAX_SLIPPAGE_BPS",
    "GRAPHITE_SWAP_MIN_RATES",
    "GRAPHITE_SWAP_STRICT",
    "GRAPHITE_TOOL_APPROVAL",
    "GRAPHITE_TRANSACTION_VERSION",
    "GRAPHITE_UPSTREAM",
    "GRAPHITE_URL",
];

/// The prefix of every variable the AI layer reads, and only it.
pub const AI_LAYER_ENV_PREFIX: &str = "GRAPHITE_AI_";

/// Levenshtein distance, bounded: anything over `max` is `max + 1`.
fn edit_distance(a: &str, b: &str, max: usize) -> usize {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len().abs_diff(b.len()) > max {
        return max + 1;
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, x) in a.iter().enumerate() {
        let mut cur = vec![i + 1; b.len() + 1];
        for (j, y) in b.iter().enumerate() {
            cur[j + 1] = (prev[j] + usize::from(x != y))
                .min(prev[j + 1] + 1)
                .min(cur[j] + 1);
        }
        prev = cur;
    }
    prev[b.len()].min(max + 1)
}

/// What the environment names that no Graphite component reads (Round 36,
/// F-020): `(name, Some(core_name))` for a near-miss of a Core variable —
/// within two edits, or the same letters in another case — and
/// `(name, None)` for any other unknown `GRAPHITE_*` name. A switch spelled
/// one letter short of `GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS` was simply
/// never read: the operator believed a decision was configured that the
/// Core never saw.
///
/// Round 38 (R37-15): a name outside the `GRAPHITE_` prefix is a near-miss
/// too when it is within two edits of a Core name — `GRAPHTIE_AUDIT_KEY_FILE`
/// was not even logged.
pub fn unknown_env_names<'a>(
    names: impl IntoIterator<Item = &'a str>,
) -> Vec<(String, Option<&'static str>)> {
    let mut out = Vec::new();
    for name in names {
        let upper = name.to_ascii_uppercase();
        if name.starts_with(AI_LAYER_ENV_PREFIX)
            || CORE_ENV_NAMES.contains(&name)
            || COMPONENT_ENV_NAMES.contains(&name)
        {
            continue;
        }
        let near = CORE_ENV_NAMES
            .iter()
            .copied()
            .find(|core| *core == upper || edit_distance(&upper, core, 2) <= 2);
        if upper.starts_with("GRAPHITE_") || near.is_some() {
            out.push((name.to_string(), near));
        }
    }
    out.sort();
    out
}

/// Refuse to start over any name [`unknown_env_names`] reports.
/// The server and the CLI call this before they read anything else.
///
/// Round 38 (R37-15): only a near-miss within two edits refused; every other
/// unknown `GRAPHITE_*` name was logged and the server started without it.
/// The protective switches are the ones a misspelling hurts —
/// `GRAPHITE_L8_HIGH_ASSURANCE` without its `L8_` (no witness requirement),
/// `GRAPHITE_AUDIT_KEY_FILE` without its `_FILE` (no MACs),
/// `GRAPHITE_RPC_WITNESS_URL` without its `RPC_` — and each is more than two
/// edits away (`tests/round36_env_names.rs` spells them out). Every Graphite component's names are listed
/// (`tests/round36_env_names.rs` keeps the lists complete), so a name no
/// component reads is a mistake, whatever it is a mistake for.
pub fn check_env_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Result<(), String> {
    let unknown = unknown_env_names(names);
    if unknown.is_empty() {
        return Ok(());
    }
    let listed: Vec<String> = unknown
        .iter()
        .map(|(name, near)| match near {
            Some(core) => format!("{name} (did you mean {core}?)"),
            None => name.clone(),
        })
        .collect();
    Err(format!(
        "{} set, and no Graphite component reads {}: {}. The Core would have run as if {} unset; remove {} or correct {}. REFUSING TO START.",
        if listed.len() == 1 { "a variable is" } else { "variables are" },
        if listed.len() == 1 { "it" } else { "them" },
        listed.join(", "),
        if listed.len() == 1 { "it were" } else { "they were" },
        if listed.len() == 1 { "it" } else { "them" },
        if listed.len() == 1 { "its name" } else { "their names" },
    ))
}

/// Parse `GRAPHITE_WALLET_PROFILE`. Accepts the four built-in names, or
/// `custom:<min_confidence>:<TrustTier>`. An unparseable value is a
/// configuration error the operator must see, so it is reported rather
/// than silently ignored.
pub fn parse_pinned_profile(raw: &str) -> Result<WalletProfile, String> {
    let v = raw.trim();
    match v.to_ascii_lowercase().as_str() {
        "treasury" => return Ok(WalletProfile::Treasury),
        "trading" | "tradingbot" => return Ok(WalletProfile::TradingBot),
        "gaming" => return Ok(WalletProfile::Gaming),
        "enterprise" => return Ok(WalletProfile::Enterprise),
        _ => {}
    }
    let parts: Vec<&str> = v.split(':').collect();
    if parts.len() == 3 && parts[0].eq_ignore_ascii_case("custom") {
        let min_confidence: f64 = parts[1]
            .parse()
            .map_err(|_| format!("invalid min_confidence {:?}", parts[1]))?;
        if !min_confidence.is_finite() || !(0.0..=1.0).contains(&min_confidence) {
            return Err(format!(
                "min_confidence {min_confidence} must be within [0.0, 1.0]"
            ));
        }
        let min_trust_tier = match parts[2] {
            "Unknown" => TrustTier::Unknown,
            "HeuristicInferred" => TrustTier::HeuristicInferred,
            "OfficialManifest" => TrustTier::OfficialManifest,
            "SimulationValidated" => TrustTier::SimulationValidated,
            "CommunityVerified" => TrustTier::CommunityVerified,
            "BattleTested" => TrustTier::BattleTested,
            other => return Err(format!("unknown trust tier {other:?}")),
        };
        return Ok(WalletProfile::Custom {
            min_confidence,
            min_trust_tier,
        });
    }
    Err(format!(
        "unrecognized profile {v:?} (expected treasury|trading|gaming|enterprise|custom:<min_confidence>:<TrustTier>)"
    ))
}

/// Enforce the wallet policy profile at the network trust boundary.
///
/// CRITICAL (2026-09-05 red-team, verified end-to-end against a live
/// server): `wallet_profile` arrives in the SAME request body, over the
/// SAME connection, as `proposed_intent`, `program_id` and every other
/// field the (possibly prompt-injected) agent supplies. Graphite has no
/// way to tell an operator's deliberate policy from an attacker's chosen
/// one. Sending `{"Custom":{"min_confidence":0.0,"min_trust_tier":"Unknown"}}`
/// therefore approved a transaction to a completely unmanifested program
/// at confidence 0.0 — P6's ceiling still computed correctly, it just no
/// longer gated anything, because the threshold it was compared against
/// was attacker-chosen.
///
/// Two layers, both applied at the boundary rather than in the core (a
/// library embedder IS its own operator and may legitimately choose any
/// profile; an HTTP caller is not):
///
/// 1. `GRAPHITE_WALLET_PROFILE` pins the profile server-side. When set,
///    the request body's profile is ignored entirely — the operator's
///    policy is configuration, not something the caller can negotiate.
/// 2. Otherwise a caller-supplied `Custom` profile is CLAMPED so it can
///    never be weaker than the weakest built-in profile. Named profiles
///    pass through untouched (all four are sane postures).
///    `GRAPHITE_ALLOW_PERMISSIVE_PROFILES=1` opts out for the genuinely
///    trusted single-tenant case.
///
/// Returns the effective profile and, when it differs from what was asked
/// for, a disclosure string so the override is visible in the response and
/// audit trail rather than silently applied (P3).
pub fn enforce_wallet_profile(
    requested: WalletProfile,
    pinned: Option<WalletProfile>,
    allow_permissive: bool,
) -> Result<(WalletProfile, Option<String>), String> {
    // Round 17 (F-16-08): a confidence bar above 1.0 can never be met and
    // is not a policy; it used to travel through the whole pipeline and
    // come back as a 500 from the policy engine. Malformed input is a
    // 400, and it is refused before anything is simulated or recorded.
    //
    // Round 19 (F-19-27): the same for a bar BELOW 0.0, NaN or infinite.
    // They were clamped up to the weakest built-in by default — safe —
    // but passed straight through under GRAPHITE_ALLOW_PERMISSIVE_PROFILES,
    // carrying a NaN into the policy comparison. The operator's own
    // `custom:<x>:<tier>` pin already refused all of them; the request
    // path now agrees with it in every mode.
    if let WalletProfile::Custom { min_confidence, .. } = requested {
        if !(0.0..=1.0).contains(&min_confidence) {
            return Err(format!(
                "wallet_profile.Custom.min_confidence must be within [0.0, 1.0], got {min_confidence}"
            ));
        }
    }

    if let Some(p) = pinned {
        if p != requested {
            return Ok((
                p,
                Some(
                    "wallet profile is pinned server-side (GRAPHITE_WALLET_PROFILE); the \
                     profile supplied in the request was ignored"
                        .to_string(),
                ),
            ));
        }
        return Ok((p, None));
    }
    if allow_permissive {
        return Ok((requested, None));
    }
    match requested {
        WalletProfile::Custom {
            min_confidence,
            min_trust_tier,
        } if !min_confidence.is_finite()
            || min_confidence < WEAKEST_BUILTIN_MIN_CONFIDENCE
            || min_trust_tier < WEAKEST_BUILTIN_MIN_TRUST_TIER =>
        {
            // Both axes (F-15-07): the confidence floor AND the tier floor
            // of the weakest built-in profile. Each override is disclosed.
            let confidence_raised =
                !min_confidence.is_finite() || min_confidence < WEAKEST_BUILTIN_MIN_CONFIDENCE;
            let tier_raised = min_trust_tier < WEAKEST_BUILTIN_MIN_TRUST_TIER;
            let mut notes = Vec::new();
            if confidence_raised {
                notes.push(format!(
                    "min_confidence ({min_confidence}) was raised to {WEAKEST_BUILTIN_MIN_CONFIDENCE}"
                ));
            }
            if tier_raised {
                notes.push(format!(
                    "min_trust_tier ({min_trust_tier:?}) was raised to {WEAKEST_BUILTIN_MIN_TRUST_TIER:?}"
                ));
            }
            Ok((
                WalletProfile::Custom {
                    min_confidence: if confidence_raised {
                        WEAKEST_BUILTIN_MIN_CONFIDENCE
                    } else {
                        min_confidence
                    },
                    min_trust_tier: if tier_raised {
                        WEAKEST_BUILTIN_MIN_TRUST_TIER
                    } else {
                        min_trust_tier
                    },
                },
                Some(format!(
                    "requested custom profile is weaker than any built-in profile: {} — a \
                     caller-supplied threshold cannot disable the confidence/trust-tier gate (set \
                     GRAPHITE_ALLOW_PERMISSIVE_PROFILES=1 to allow, or pin the profile with \
                     GRAPHITE_WALLET_PROFILE)",
                    notes.join("; ")
                )),
            ))
        }
        other => Ok((other, None)),
    }
}

/// The variable that let threshold-only refusals train evidence (Round 29),
/// refused since Round 30 (G-02).
pub const RETIRED_LEARN_FROM_POLICY_REFUSALS: &str = "GRAPHITE_LEARN_FROM_POLICY_REFUSALS";

/// The operator's policy settings, read once from the environment.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct OperatorPolicy {
    /// `GRAPHITE_WALLET_PROFILE`: overrides every request's profile.
    pub pinned_profile: Option<WalletProfile>,
    /// `GRAPHITE_ALLOW_PERMISSIVE_PROFILES`: no clamp on a weak `Custom`.
    pub allow_permissive_profiles: bool,
    /// `GRAPHITE_ALLOW_DURABLE_NONCE`.
    pub allow_durable_nonce: bool,
    /// `GRAPHITE_QUARANTINE_ON_UPGRADE`.
    pub quarantine_on_upgrade: bool,
    /// `GRAPHITE_PLUGINS_DIR`, when set and non-empty.
    pub plugins_dir: Option<PathBuf>,
    /// `GRAPHITE_ALLOW_UNREADABLE_VALUE_DECLARATIONS` (Round 32): a signer's
    /// loss under a declaration Graphite cannot read warns, instead of being
    /// refused, when the instruction's class moves value.
    pub allow_unreadable_value_declarations: bool,
    /// `GRAPHITE_ALLOW_SIGNER_LAMPORTS_OUTSIDE_DECLARED_DEBIT` (Round 32,
    /// W19): a signer's lamports leaving under a debit declared for other
    /// accounts only warn.
    pub allow_signer_lamports_outside_declared_debit: bool,
    /// `GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS` (Round 32, R30-G-1): a granted
    /// withdrawal whose every minimum output is zero keeps its grant.
    pub allow_unbounded_withdrawals: bool,
}

impl OperatorPolicy {
    /// Read from the process environment.
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Read through `get` (the environment, or a test's map). Every
    /// value that does not parse is an error; none falls back.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let pinned_profile = match get("GRAPHITE_WALLET_PROFILE") {
            Some(v) if !v.trim().is_empty() => Some(
                parse_pinned_profile(&v)
                    .map_err(|e| format!("invalid GRAPHITE_WALLET_PROFILE: {e}"))?,
            ),
            _ => None,
        };
        // Round 30 (G-02): retired. With it on, anyone holding the verify
        // key could raise a program's confidence for every caller of the
        // node; no request-driven path may train evidence below the built-in
        // floor now (`verification::ObservationPolicy`). An operator who set
        // it is told rather than silently ignored.
        if get(RETIRED_LEARN_FROM_POLICY_REFUSALS).is_some_and(|v| !v.trim().is_empty()) {
            return Err(format!(
                "{RETIRED_LEARN_FROM_POLICY_REFUSALS} was removed in Round 30: a verify request can no longer train evidence for a program no built-in profile admits. Stand a program up with `graphite evidence seed` or `graphite evidence baseline` (operator-asserted, recorded on the trail), and unset the variable"
            ));
        }
        let flag = |name: &str| env_flag(name, get(name).as_deref());
        Ok(Self {
            pinned_profile,
            allow_permissive_profiles: flag("GRAPHITE_ALLOW_PERMISSIVE_PROFILES")?,
            allow_durable_nonce: flag("GRAPHITE_ALLOW_DURABLE_NONCE")?,
            quarantine_on_upgrade: flag("GRAPHITE_QUARANTINE_ON_UPGRADE")?,
            plugins_dir: get("GRAPHITE_PLUGINS_DIR")
                .filter(|d| !d.trim().is_empty())
                .map(PathBuf::from),
            allow_unreadable_value_declarations: flag(
                "GRAPHITE_ALLOW_UNREADABLE_VALUE_DECLARATIONS",
            )?,
            allow_signer_lamports_outside_declared_debit: flag(
                "GRAPHITE_ALLOW_SIGNER_LAMPORTS_OUTSIDE_DECLARED_DEBIT",
            )?,
            allow_unbounded_withdrawals: flag("GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS")?,
        })
    }

    /// Apply the settings that live in the core: durable nonces, the
    /// upgrade quarantine, L4's and the grants' relaxations (Round 32) and
    /// the plugins directory. Returns the plugin
    /// registration summary when a directory is configured. A directory
    /// that does not load is an error: an operator who configured
    /// plugins expects them to be running (Round 17, F-16-07).
    pub fn apply_to_core(
        &self,
        core: &mut GraphiteCore,
    ) -> Result<Option<crate::plugin_orchestrator::RegistrationSummary>, String> {
        core.set_allow_durable_nonce(self.allow_durable_nonce);
        core.set_quarantine_on_upgrade(self.quarantine_on_upgrade);
        core.set_l4_relaxations(crate::state_diff::L4Relaxations {
            unreadable_value_declarations: self.allow_unreadable_value_declarations,
            signer_lamports_outside_declared_debit: self
                .allow_signer_lamports_outside_declared_debit,
        });
        core.set_allow_unbounded_withdrawals(self.allow_unbounded_withdrawals);
        match &self.plugins_dir {
            Some(dir) => core.attach_plugins_dir(dir).map(Some).map_err(|e| {
                format!(
                    "plugins: FAILED to load {} (GRAPHITE_PLUGINS_DIR): {e} — refusing to run without the plugins the operator configured",
                    dir.display()
                )
            }),
            None => Ok(None),
        }
    }
}
