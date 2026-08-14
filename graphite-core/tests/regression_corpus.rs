//! Phase 2 certification regression corpus (mandate items 3/4/5).
//!
//! Builds a diverse, HONESTLY-LABELED corpus and splits it into three sets:
//!
//!   - **holdout (real)** — 35 real mainnet exploit signatures (SolPhishHunter
//!     arXiv:2505.04094 provenance), labeled `block` independently of
//!     Graphite, plus 3 real mainnet successful transactions labeled by the
//!     documented policy verdict for the instruction the reader selects.
//!     NEVER used for tuning; evaluated last.
//!   - **dev (synthetic)**  — manifest-driven canonical + structural variants
//!     for every instruction of every seed manifest. Expected outcomes are
//!     derived from DOCUMENTED rules (risk-engine gates, manifest resolution,
//!     FakeSwap credit rule, P12 confidence ceiling). Used for implementation.
//!   - **regression (synthetic attack shapes)** — re-pins every fixed attack
//!     class (P0-1..P0-4, Phase 2 multi-instruction + CPI trace, risk-class
//!     gates, ordering) so a regression fails loudly.
//!
//! Labeling rules (each is a documented Graphite behavior, not a Graphite
//! result):
//!   - Discriminator in the RISKY_PATTERNS policy set → block (unconditional).
//!   - Swap intent on a swap program whose manifest state changes cannot
//!     establish output credit → block (FakeSwap).
//!   - High-risk manifest class (drain/authority/withdraw/mint/close) with
//!     empty intent → block (Check 10, P12 fail-closed).
//!   - Intent the program does not support → block (Check 9).
//!   - Unique account count > manifest expected + 2 on a non-DEX,
//!     non-variable instruction → block (Check 3b STMT drainer).
//!   - Unknown instruction on a known protocol → NOT approved end-to-end
//!     (P12 Response 2 confidence ceiling — pinned by
//!     `attack_p0_1_unknown_selector_full_pipeline_not_approved`).
//!   - Unknown program → fail-closed block (P12).
//!   - Everything else → approve (established account, matching intent).

use graphite_core::manifest::ProtocolManifest;
use graphite_core::policy_engine::WalletProfile;
use graphite_core::regression_engine::{replay_corpus, RegressionCorpus, RegressionFixture};
use graphite_core::risk_engine::is_swap_program;
use graphite_core::semantic_graph_store::BehaviorEvidence;
use graphite_core::tx_pattern_analysis::{CpiTraceNode, TransactionInstruction};
use graphite_core::verification::{GraphiteCore, ProposedIntent, VerificationInput};
use serde::Deserialize;
use std::path::Path;

// ───────────────────────── deterministic addresses ─────────────────────────

const B58_ALPHA: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn b58_encode(input: &[u8]) -> String {
    let mut digits: Vec<u8> = vec![0];
    for &byte in input {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let zeros = input.iter().take_while(|&&b| b == 0).count();
    let mut out = String::new();
    for _ in 0..zeros {
        out.push('1');
    }
    for d in digits.iter().rev() {
        out.push(B58_ALPHA[*d as usize] as char);
    }
    out
}

/// Deterministic 32-byte base58 "address" from a seed (splitmix64 expansion).
fn gen_addr(seed: u64) -> String {
    let mut s = seed.wrapping_add(0x9E3779B97F4A7C15);
    let mut b = [0u8; 32];
    for chunk in b.chunks_mut(8) {
        s = s.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = s;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^= z >> 31;
        chunk.copy_from_slice(&z.to_le_bytes());
    }
    b58_encode(&b)
}

// ──────────────────── documented policy constants ─────────────────────────

const SYSTEM: &str = "11111111111111111111111111111111";
const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const JUPITER: &str = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
const JUPITER_DCA: &str = "DCA265Vj8a9CEuX1eb1LWRnDT7uK6q1xMipnNyatn23M";
const STAKE_PROGRAM: &str = "Stake11111111111111111111111111111111111111";
const COMPUTE_BUDGET: &str = "ComputeBudget111111111111111111111111111111";
const ATA: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const MEMO: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

/// Programs a "create" intent is valid for (mirrors risk_engine's
/// program_supports_intent create branch).
const CREATE_PROGRAMS: &[&str] = &[
    "11111111111111111111111111111111",
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
    "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s",
    "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P",
];

/// Programs that legitimately CPI to SPL Token (trusted roots) — the
/// risk-engine whitelist (mirrors risk_engine TRUSTED_CPI_ROOTS/DEX_PROGRAMS;
/// C46 added Phoenix/OpenBook V2/Jupiter Limit, C56 added Raydium CLMM/CPMM
/// and Orca TokenSwap V2).
const TRUSTED_ROOTS: &[&str] = &[
    "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
    "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc",
    "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo",
    "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8",
    "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf",
    "DCA265Vj8a9CEuX1eb1LWRnDT7uK6q1xMipnNyatn23M",
    "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P",
    "PhoeNiXZ8ByJGLkxNfZRnkUfjvmuYqLR89jjFHGqdXY",
    "opnb2LAfJYbRMAHHvqjCwQxanZn7ReEHp1k81EohpZb",
    "jupoNjAxXgZ4rjzxzPMP4oxduvQsQtZzyknqvzYNrNu",
    "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK",
    "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C",
    "9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP",
];

/// Programs exempt from the drainer/hidden-transfer account heuristics.
const DEX_PROGRAMS: &[&str] = TRUSTED_ROOTS;

/// RISKY_PATTERNS policy set from risk_engine.rs (documented): these
/// discriminators block unconditionally regardless of intent.
fn risky_policy_block(program: &str, disc: &str) -> bool {
    let token = program == TOKEN || program == TOKEN_2022;
    if token && (disc.starts_with("06") || disc.starts_with("09") || disc.starts_with("04")) {
        return true;
    }
    program == SYSTEM && disc.starts_with("01000000")
}

// ─────────────────────────── input builders ───────────────────────────────

fn good_evidence() -> BehaviorEvidence {
    BehaviorEvidence {
        has_signed_manifest: false,
        community_verified_count: 5,
        battle_tested_tx_count: 50000,
        simulation_match_count: 100,
    }
}

fn input(
    program: &str,
    disc: &str,
    accounts: Vec<String>,
    cpis: Vec<String>,
    intent: &str,
    evidence: BehaviorEvidence,
) -> VerificationInput {
    VerificationInput {
        proposed_intent: ProposedIntent {
            intent_type: intent.to_string(),
            raw_natural_language: "certification corpus fixture".to_string(),
            confidence_of_parse: 0.9,
            extracted_parameters: None,
        },
        program_id: program.to_string(),
        protocol_version: "1.0.0".to_string(),
        instruction_discriminator: disc.to_string(),
        account_addresses: accounts,
        instruction_data: None,
        cpi_targets: cpis,
        // Same profile convention as the benchmark's benign cases: a
        // documented operator threshold (0.40 / OfficialManifest), NOT the
        // Treasury profile — a fresh-node cold-start ceiling (P7) keeps
        // confidence at 0.44, which Treasury would reject for every benign
        // transaction on an empty graph. The corpus records the steady-state
        // contract: risk-clear + confidence above an operator's documented
        // floor ⇒ approve.
        wallet_profile: WalletProfile::Custom {
            min_confidence: 0.40,
            min_trust_tier: graphite_core::semantic_graph_store::TrustTier::OfficialManifest,
        },
        behavior_evidence: evidence,
        compute_units: 150,
        account_writes: 1,
        cpi_hops: 0,
        signed_transaction: None,
        transaction_instructions: vec![],
        cpi_trace: None,
    }
}

fn txi(program: &str, disc: &str, accounts: Vec<String>) -> TransactionInstruction {
    TransactionInstruction {
        program_id: program.to_string(),
        instruction_discriminator: disc.to_string(),
        account_addresses: accounts,
        cpi_targets: vec![],
    }
}

/// Per-instruction instruction-data buffer: the discriminator bytes first
/// (L2 requires instruction data to START with the discriminator), padded to
/// 8 bytes, then a deterministic tail whose bytes 8-9 carry a fixed market
/// index for PDA templates that slice `{instruction_data:N:M}` (Drift
/// spot_market_vault 8:10, Kamino obligation 8:9/9:10). Both sides of the
/// PDA derivation (this builder and account_resolution) receive the SAME
/// buffer, so the derived addresses agree.
fn instruction_data_for(disc: &str) -> Vec<u8> {
    let mut data = hex::decode(disc.trim_start_matches("0x")).unwrap_or_default();
    while data.len() < 8 {
        data.push(0);
    }
    data.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    data
}

fn parse_slice(data: &[u8], spec: &str) -> Vec<u8> {
    let parts: Vec<&str> = spec.split(':').collect();
    match parts.as_slice() {
        [s, e] => {
            if let (Ok(s), Ok(e)) = (s.parse::<usize>(), e.parse::<usize>()) {
                return data.get(s..e).unwrap_or_default().to_vec();
            }
            data.to_vec()
        }
        [s] => {
            if let Ok(s) = s.parse::<usize>() {
                return data.get(s..).unwrap_or_default().to_vec();
            }
            data.to_vec()
        }
        _ => data.to_vec(),
    }
}

/// Resolve one PDA seed template component, mirroring the production
/// `account_resolution::resolve_pda_seed_template` semantics exactly so the
/// derived address matches what the pipeline re-derives (no mismatch flag).
fn resolve_pda_seed(
    seed: &str,
    program_pk: &graphite_core::solana_types::Pubkey,
    addrs: &[Option<graphite_core::solana_types::Pubkey>],
    instruction_data: &[u8],
) -> Vec<u8> {
    if seed == "{program_id}" {
        program_pk.as_bytes().to_vec()
    } else if seed == "{instruction_data}" {
        instruction_data.to_vec()
    } else if let Some(spec) = seed
        .strip_prefix("{instruction_data:")
        .and_then(|s| s.strip_suffix('}'))
    {
        parse_slice(instruction_data, spec)
    } else if let Some(spec) = seed
        .strip_prefix("{account_")
        .and_then(|s| s.strip_suffix('}'))
    {
        if let Some((idx_s, range)) = spec.split_once(':') {
            if let Ok(i) = idx_s.parse::<usize>() {
                if let Some(Some(pk)) = addrs.get(i) {
                    return parse_slice(pk.as_bytes(), range);
                }
            }
        } else if let Ok(i) = spec.parse::<usize>() {
            if let Some(Some(pk)) = addrs.get(i) {
                return pk.as_bytes().to_vec();
            }
        }
        seed.as_bytes().to_vec()
    } else if let Some(h) = seed.strip_prefix("0x") {
        hex::decode(h).unwrap_or_else(|_| seed.as_bytes().to_vec())
    } else {
        seed.as_bytes().to_vec()
    }
}

/// Build a canonical account list for a manifest instruction: non-PDA roles
/// get deterministic addresses; PDA roles are DERIVED from the manifest's
/// seed templates (find_program_address) so the pipeline's own re-derivation
/// matches — a random address on a PDA role would legitimately trip the
/// PDA-mismatch detection (a real security signal, not a fixture).
fn instruction_accounts(
    program: &str,
    ins: &graphite_core::manifest::InstructionDef,
    seed_base: u64,
    instruction_data: &[u8],
) -> Vec<String> {
    use graphite_core::solana_types::{find_program_address, Pubkey};
    let program_pk = Pubkey::from_base58(program).expect("manifest program id must be base58");
    let n = ins.accounts.len();
    let mut addrs: Vec<Option<Pubkey>> = vec![None; n];
    // Pass 1: non-PDA roles.
    for (i, a) in ins.accounts.iter().enumerate() {
        if a.pda_seeds.is_empty() {
            addrs[i] =
                Some(Pubkey::from_base58(&gen_addr(seed_base + i as u64)).expect("valid addr"));
        }
    }
    // Pass 2: iteratively derive PDAs (a PDA may reference another account).
    let mut changed = true;
    while changed {
        changed = false;
        for (i, a) in ins.accounts.iter().enumerate() {
            if !a.pda_seeds.is_empty() && addrs[i].is_none() {
                let seeds: Vec<Vec<u8>> = a
                    .pda_seeds
                    .iter()
                    .map(|s| resolve_pda_seed(s, &program_pk, &addrs, instruction_data))
                    .collect();
                let refs: Vec<&[u8]> = seeds.iter().map(|s| s.as_slice()).collect();
                if let Ok((pk, _bump)) = find_program_address(&refs, &program_pk) {
                    addrs[i] = Some(pk);
                    changed = true;
                }
            }
        }
    }
    // Fallback: any PDA that could not be derived gets a deterministic
    // address (identical fallback semantics to the production resolver, so
    // the pipeline derives the same value and no mismatch fires).
    for (i, slot) in addrs.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(
                Pubkey::from_base58(&gen_addr(seed_base + 1000 + i as u64)).expect("valid addr"),
            );
        }
    }
    addrs
        .iter()
        .map(|a| a.expect("filled").to_base58())
        .collect()
}

fn trace_node(program: &str, depth: u32, children: Vec<CpiTraceNode>) -> CpiTraceNode {
    CpiTraceNode {
        program_id: program.to_string(),
        instruction_discriminator: String::new(),
        depth,
        account_addresses: vec![],
        children,
    }
}

// ─────────────────────────── intent + label rules ─────────────────────────

/// Map an instruction name + program to the intent an honest agent would
/// declare, constrained to intents the program supports (Check 9) AND the
/// L5 vocabulary (so the semantic layer can confirm alignment).
fn intent_for(name: &str, program: &str) -> &'static str {
    let n = name.to_lowercase();
    let swap_like = n.contains("route")
        || n.contains("swap")
        || n.contains("exchange")
        || n.contains("buy")
        || n.contains("sell");
    let create_like = n.contains("create")
        || n.contains("init")
        || n.contains("allocate")
        || n.contains("assign");
    if swap_like && is_swap_program(program) {
        "swap"
    } else if program == STAKE_PROGRAM
        && (n.contains("stake")
            || n.contains("delegate")
            || n.contains("withdraw")
            || n.contains("deactivate"))
    {
        "stake"
    } else if create_like && CREATE_PROGRAMS.contains(&program) {
        "create"
    } else if n.contains("revoke") && (program == TOKEN || program == TOKEN_2022) {
        "revoke"
    } else if n.contains("approve") && (program == TOKEN || program == TOKEN_2022) {
        "approve"
    } else if n.contains("close")
        && (program == TOKEN || program == TOKEN_2022 || program == JUPITER_DCA)
    {
        "close"
    } else {
        // "transfer" is universally supported (Check 9); L5 alignment then
        // decides whether the instruction's semantics match it.
        "transfer"
    }
}

/// L5 semantic-layer keyword table (verification.rs `verify_semantic`): the
/// declared intent's keywords must appear in the instruction name OR the
/// manifest's expected state changes for the layer to pass.
fn l5_keywords(intent: &str) -> &'static [&'static str] {
    match intent {
        "swap" | "trade" | "exchange" => &["swap", "route", "trade", "token", "credit", "debit"],
        "transfer" | "send" => &["transfer", "send", "debit", "credit", "move"],
        "stake" | "delegate" => &["stake", "delegate", "withdraw", "deactivate", "reward"],
        "close" | "close_account" => &["close", "closure", "shutdown"],
        "create" | "create_account" => &["create", "allocate", "assign", "initialize"],
        "approve" | "revoke" => &["approve", "revoke", "delegate"],
        _ => &[],
    }
}

/// L4 state-verification outcome modeled from `verify_state`'s documented
/// rules: debit/credit in state changes ⇒ ≥2 writable accounts; signer/
/// approve/delegate/assign ⇒ ≥1 signer; close/closure ⇒ ≥1 writable.
/// Several manifests carry stub entries (all-readonly role lists with
/// fund-moving state text, e.g. Kamino V2); L4 correctly flags those as
/// inconsistent, so the corpus labels them NOT-approved with a documented
/// defect note rather than pretending the manifest is correct.
fn l4_passes(
    state_changes: &[String],
    accounts: &[graphite_core::manifest::AccountRoleDef],
) -> bool {
    let lower: Vec<String> = state_changes.iter().map(|c| c.to_lowercase()).collect();
    let writable = accounts.iter().filter(|a| a.is_writable).count();
    let signers = accounts.iter().filter(|a| a.is_signer).count();
    let needs_writable = lower
        .iter()
        .any(|c| c.contains("debit") || c.contains("credit"));
    if needs_writable && writable < 2 {
        return false;
    }
    let needs_signer = lower.iter().any(|c| {
        c.contains("signer")
            || c.contains("approve")
            || c.contains("delegate")
            || c.contains("assign")
    });
    if needs_signer && signers == 0 {
        return false;
    }
    let needs_close = lower
        .iter()
        .any(|c| c.contains("close") || c.contains("closure"));
    if needs_close && writable == 0 {
        return false;
    }
    true
}

fn l5_matches(intent: &str, name: &str, state_changes: &[String]) -> bool {
    let kws = l5_keywords(intent);
    if kws.is_empty() {
        return false; // unknown intent type → L5 fail-closed
    }
    let n = name.to_lowercase();
    let changes: Vec<String> = state_changes.iter().map(|c| c.to_lowercase()).collect();
    let ix_matches = kws.iter().any(|kw| n.contains(kw));
    let changes_match = changes.iter().any(|c| kws.iter().any(|kw| c.contains(kw)));
    ix_matches || changes_match
}

/// Expected approval for a canonical manifest instruction, from documented
/// rules only:
///   - RISKY_PATTERNS policy set → block (unconditional);
///   - swap intent whose state changes cannot establish output credit →
///     block (FakeSwap);
///   - L5 semantic misalignment → NOT approved (intent-alignment signal 0.3,
///     capped manifest tier 0.7 ⇒ confidence 0.37 − penalties < the 0.40
///     operator floor used by the corpus — this is the fresh-core P7
///     cold-start contract, identical to the benchmark's benign cases);
///   - otherwise → approve (confidence 0.44 ≥ floor).
fn canonical_expected(
    program: &str,
    disc: &str,
    name: &str,
    state_changes: &[String],
    intent: &str,
    manifest_accounts: &[graphite_core::manifest::AccountRoleDef],
) -> bool {
    if risky_policy_block(program, disc) {
        return false;
    }
    if intent == "swap" && is_swap_program(program) {
        let has_credit = state_changes
            .iter()
            .any(|c| c.to_lowercase().contains("credit") || c.to_lowercase().contains("output"));
        if !has_credit && !state_changes.is_empty() {
            return false; // FakeSwap: output unverifiable
        }
    }
    l5_matches(intent, name, state_changes) && l4_passes(state_changes, manifest_accounts)
}

// ────────────────────────────── fixture notes ─────────────────────────────

#[derive(Clone, Debug, serde::Serialize)]
struct Note {
    hash: String,
    split: &'static str,
    class: &'static str,
    provenance: String,
    note: String,
}

// Test-only fixture builder: the label fields (split/class/provenance/note)
// are deliberately kept flat so each fixture's documentation is explicit;
// bundling them into a struct would obscure the per-fixture labels.
#[allow(clippy::too_many_arguments)]
fn push(
    corpus: &mut RegressionCorpus,
    notes: &mut Vec<Note>,
    input: VerificationInput,
    expected: bool,
    split: &'static str,
    class: &'static str,
    provenance: impl Into<String>,
    note: impl Into<String>,
) {
    let provenance = provenance.into();
    let fixture = RegressionFixture::new(input, expected, &provenance);
    notes.push(Note {
        hash: fixture.content_hash.clone(),
        split,
        class,
        provenance,
        note: note.into(),
    });
    corpus.add_fixture(fixture);
}

// ──────────────────────────── dev corpus ──────────────────────────────────

fn build_dev(manifests: &[&ProtocolManifest]) -> (RegressionCorpus, Vec<Note>) {
    let mut corpus = RegressionCorpus::new();
    let mut notes = Vec::new();
    for (mi, m) in manifests.iter().enumerate() {
        let program = &m.protocol.program_id;
        let is_dex = DEX_PROGRAMS.contains(&program.as_str());
        for (ii, ins) in m.instructions.iter().enumerate() {
            let disc = ins.discriminator.clone();
            let seed_base = (mi as u64) << 32 | (ii as u64) << 8;
            // Instruction-data buffer: discriminator prefix (L2 requires it)
            // + deterministic market-index tail for {instruction_data:N:M}
            // PDA seed templates.
            let instruction_data = instruction_data_for(&disc);
            let accounts = instruction_accounts(program, ins, seed_base, &instruction_data);
            let cpis = ins.allowed_cpis.clone();
            let intent = intent_for(&ins.name, program);
            // Empty-discriminator manifests (Memo family) resolve as
            // unknown_instruction on the pipeline → P12 soft path → approved
            // under the 0.40 floor. The label follows the actual resolution.
            let expected = if disc.trim().is_empty() {
                true
            } else {
                canonical_expected(
                    program,
                    &disc,
                    &ins.name,
                    &ins.expected_state_changes,
                    intent,
                    &ins.accounts,
                )
            };
            let instruction_data = Some(instruction_data);

            // canonical benign (or policy-blocked) shape
            let mut canonical = input(
                program,
                &disc,
                accounts.clone(),
                cpis.clone(),
                intent,
                good_evidence(),
            );
            canonical.instruction_data = instruction_data.clone();
            push(
                &mut corpus,
                &mut notes,
                canonical,
                expected,
                "dev",
                "canonical",
                "synthetic-manifest",
                format!("{}::{} intent={}", m.protocol.name, ins.name, intent),
            );

            // no-intent variant — NOT approved in every case: high-risk
            // classes are blocked by Check 10 (P12), and low-risk classes
            // collapse confidence to 0.04 (IntentAlignment 0.0) which the
            // 0.40 operator floor rejects. Both are documented behavior.
            let expected_no_intent = false;
            let mut no_intent = input(
                program,
                &disc,
                accounts.clone(),
                cpis.clone(),
                "",
                good_evidence(),
            );
            no_intent.instruction_data = instruction_data.clone();
            push(
                &mut corpus,
                &mut notes,
                no_intent,
                expected_no_intent,
                "dev",
                "no-intent",
                "synthetic-manifest",
                format!(
                    "{}::{} empty intent — Check 10 gate",
                    m.protocol.name, ins.name
                ),
            );

            // mismatch-intent variant — Check 9 gate (non-swap programs only)
            if !is_swap_program(program) {
                let mut mismatch = input(
                    program,
                    &disc,
                    accounts.clone(),
                    cpis.clone(),
                    "swap",
                    good_evidence(),
                );
                mismatch.instruction_data = instruction_data.clone();
                push(
                    &mut corpus,
                    &mut notes,
                    mismatch,
                    false,
                    "dev",
                    "intent-mismatch",
                    "synthetic-manifest",
                    format!(
                        "{}::{} swap intent on non-swap program — Check 9",
                        m.protocol.name, ins.name
                    ),
                );
            }

            // account-overflow variant — Check 3b STMT drainer gate
            if !is_dex && !ins.variable_accounts {
                let mut overflow = accounts.clone();
                for k in 0..8 {
                    // NOTE: bitwise-OR with 0xFFFF swallowed k here once
                    // (0xFFFF | k == 0xFFFF for k < 16), producing duplicate
                    // addresses that silently defeated the STMT drainer
                    // check. Seeds must be distinct per slot.
                    overflow.push(gen_addr(
                        ((mi as u64) << 32) | ((ii as u64) << 8) | (0xFFFFu64 << 8) | k as u64,
                    ));
                }
                let mut ov = input(
                    program,
                    &disc,
                    overflow,
                    cpis.clone(),
                    intent,
                    good_evidence(),
                );
                ov.instruction_data = instruction_data.clone();
                push(
                    &mut corpus,
                    &mut notes,
                    ov,
                    false,
                    "dev",
                    "account-overflow",
                    "synthetic-manifest",
                    format!(
                        "{}::{} +8 accounts — STMT drainer",
                        m.protocol.name, ins.name
                    ),
                );
            }

            // width variants — P0-1 prefix-matching semantics (zero-pad to 8
            // bytes; a space-padded discriminator is not hex and fails closed).
            if !disc.trim().is_empty() && disc.len() < 16 {
                // Zero-pad to 8 bytes. Skip when padding is a no-op (disc
                // already 8 bytes) — the "variant" would be byte-identical
                // to the canonical fixture and duplicate its content hash.
                let padded = format!("{:0<8}", disc);
                if padded != disc {
                    let mut p = input(
                        program,
                        &padded,
                        accounts.clone(),
                        cpis.clone(),
                        intent,
                        good_evidence(),
                    );
                    // L2 requires instruction data to start with the input
                    // discriminator — the variant's own bytes, not the
                    // canonical disc's.
                    p.instruction_data = Some(instruction_data_for(&padded));
                    push(
                        &mut corpus,
                        &mut notes,
                        p,
                        expected,
                        "dev",
                        "padded-width",
                        "synthetic-manifest",
                        format!(
                            "{}::{} zero-padded discriminator",
                            m.protocol.name, ins.name
                        ),
                    );
                }
                let near = format!("{}ff00", disc);
                let mut np = input(
                    program,
                    &near,
                    accounts.clone(),
                    cpis.clone(),
                    intent,
                    good_evidence(),
                );
                np.instruction_data = Some(instruction_data_for(&near));
                push(
                    &mut corpus,
                    &mut notes,
                    np,
                    expected,
                    "dev",
                    "near-prefix",
                    "synthetic-manifest",
                    format!(
                        "{}::{} near-prefix discriminator",
                        m.protocol.name, ins.name
                    ),
                );
            }

            // unknown-instruction variant — P12 Response-2 (one per program).
            // L5 is Inconclusive for a low-risk intent (not a failure, by
            // design GAP-2026-08-06-3), so confidence stays 0.44 and the
            // 0.40 operator floor APPROVES. The strict case (Treasury floor)
            // is pinned in the regression split and in
            // attack_p0_1_unknown_selector_full_pipeline_not_approved.
            if ii == 0 {
                // Small fixed account list: an unknown instruction has no
                // manifest account layout, so a large list would trip the
                // drainer heuristic; two accounts exercise the P12 soft path
                // cleanly.
                let unknown_input = input(
                    program,
                    "deadbeefdeadbeef",
                    vec![gen_addr(1), gen_addr(2)],
                    vec![],
                    "transfer",
                    good_evidence(),
                );
                push(
                    &mut corpus,
                    &mut notes,
                    unknown_input,
                    true,
                    "dev",
                    "unknown-instruction",
                    "synthetic-manifest",
                    format!(
                        "{} unknown discriminator — P12 Response 2 (approved under 0.40 floor)",
                        m.protocol.name
                    ),
                );
            }
        }
    }
    (corpus, notes)
}

// ────────────────────────── regression corpus ─────────────────────────────

fn build_regression() -> (RegressionCorpus, Vec<Note>) {
    let mut corpus = RegressionCorpus::new();
    let mut notes = Vec::new();
    let mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string();
    let mk = |src: &str, dst: &str| -> TransactionInstruction {
        txi(
            TOKEN,
            "0c",
            vec![
                src.to_string(),
                mint.clone(),
                dst.to_string(),
                "owner".to_string(),
            ],
        )
    };

    // P0-1: discriminator width on policy-blocked instructions
    for disc in [
        "06",
        "0600000000000000",
        "06ff",
        "0x06",
        "09",
        "09000000",
        "04",
        "04000000",
    ] {
        push(
            &mut corpus,
            &mut notes,
            input(
                TOKEN,
                disc,
                vec![gen_addr(1), gen_addr(2)],
                vec![],
                "transfer",
                good_evidence(),
            ),
            false,
            "regression",
            "p0-1-width",
            "synthetic-attack",
            format!("SPL Token disc={disc} — policy block"),
        );
    }
    push(
        &mut corpus,
        &mut notes,
        input(
            SYSTEM,
            "01000000",
            vec![gen_addr(1)],
            vec![],
            "create",
            good_evidence(),
        ),
        false,
        "regression",
        "p0-1-width",
        "synthetic-attack",
        "System Assign padded — policy block",
    );
    push(
        &mut corpus,
        &mut notes,
        input(
            TOKEN,
            "03",
            vec![gen_addr(1), gen_addr(2), gen_addr(3)],
            vec![],
            "transfer",
            good_evidence(),
        ),
        true,
        "regression",
        "p0-1-benign-control",
        "synthetic-benign",
        "plain SPL Transfer must approve",
    );

    // P12 Response-2 strict path: an unknown instruction on a known protocol
    // is NOT approved under the Treasury floor (mirrors
    // attack_p0_1_unknown_selector_full_pipeline_not_approved). The dev
    // split's 0.40-floor variant approves — both are documented.
    let mut strict_unknown = input(
        TOKEN,
        "deadbeefdeadbeef",
        vec![gen_addr(1), gen_addr(2)],
        vec![],
        "transfer",
        good_evidence(),
    );
    strict_unknown.wallet_profile = WalletProfile::Treasury;
    push(
        &mut corpus,
        &mut notes,
        strict_unknown,
        false,
        "regression",
        "p12-unknown-instruction",
        "synthetic-attack",
        "unknown instruction on known protocol under Treasury floor — must not approve",
    );

    // P0-2: TransferChecked shared-mint sweeps (destination is accounts[2])
    for n in 3..=6 {
        let mut txs = Vec::new();
        for k in 0..n {
            txs.push(mk(&format!("s{k}"), &format!("d{k}")));
        }
        let mut v = input(
            TOKEN,
            "0c",
            vec![
                gen_addr(10),
                mint.clone(),
                gen_addr(11),
                "owner".to_string(),
            ],
            vec![],
            "transfer",
            good_evidence(),
        );
        v.transaction_instructions = txs;
        push(
            &mut corpus,
            &mut notes,
            v,
            false,
            "regression",
            "p0-2-sweep",
            "synthetic-attack",
            format!("{n}-destination shared-mint TransferChecked sweep"),
        );
    }
    // mixed SPL + Token-2022 sweep
    let mut txs = vec![mk("a1", "b1"), mk("a2", "b2")];
    txs.push(txi(
        TOKEN_2022,
        "0c",
        vec![
            "a3".to_string(),
            mint.clone(),
            "b3".to_string(),
            "owner".to_string(),
        ],
    ));
    let mut v = input(
        TOKEN,
        "0c",
        vec![
            gen_addr(10),
            mint.clone(),
            gen_addr(11),
            "owner".to_string(),
        ],
        vec![],
        "transfer",
        good_evidence(),
    );
    v.transaction_instructions = txs;
    push(
        &mut corpus,
        &mut notes,
        v,
        false,
        "regression",
        "p0-2-sweep",
        "synthetic-attack",
        "mixed SPL/Token-2022 sweep",
    );

    // P0-3: CPI path traversal semantics. Jupiter route declares 5 accounts
    // in its manifest (variable_accounts) — the fixture must carry ≥5 for
    // account resolution.
    // A→A→A (root + 2 children of SPL Token): 3 Token visits → block
    let mut v = input(
        JUPITER,
        "e517cb977ae3ad2a",
        vec![
            gen_addr(1),
            gen_addr(2),
            gen_addr(3),
            gen_addr(4),
            gen_addr(5),
        ],
        vec![],
        "swap",
        good_evidence(),
    );
    v.cpi_trace = Some(trace_node(
        JUPITER,
        0,
        vec![trace_node(
            TOKEN,
            1,
            vec![trace_node(TOKEN, 2, vec![trace_node(TOKEN, 3, vec![])])],
        )],
    ));
    push(
        &mut corpus,
        &mut notes,
        v,
        false,
        "regression",
        "p0-3-traversal",
        "synthetic-attack",
        "root self-chain Token→Token→Token — 3 visits",
    );
    // A→B→A→A
    let mut v = input(
        JUPITER,
        "e517cb977ae3ad2a",
        vec![
            gen_addr(1),
            gen_addr(2),
            gen_addr(3),
            gen_addr(4),
            gen_addr(5),
        ],
        vec![],
        "swap",
        good_evidence(),
    );
    v.cpi_trace = Some(trace_node(
        JUPITER,
        0,
        vec![trace_node(
            TOKEN,
            1,
            vec![trace_node(
                SYSTEM,
                2,
                vec![trace_node(TOKEN, 3, vec![trace_node(TOKEN, 4, vec![])])],
            )],
        )],
    ));
    push(
        &mut corpus,
        &mut notes,
        v,
        false,
        "regression",
        "p0-3-traversal",
        "synthetic-attack",
        "Token→System→Token→Token — 3 Token visits",
    );
    // benign control: single-level [Token] child → approve
    let mut v = input(
        JUPITER,
        "e517cb977ae3ad2a",
        vec![
            gen_addr(1),
            gen_addr(2),
            gen_addr(3),
            gen_addr(4),
            gen_addr(5),
        ],
        vec![],
        "swap",
        good_evidence(),
    );
    v.cpi_trace = Some(trace_node(JUPITER, 0, vec![trace_node(TOKEN, 1, vec![])]));
    push(
        &mut corpus,
        &mut notes,
        v,
        true,
        "regression",
        "p0-3-benign-control",
        "synthetic-benign",
        "single Token child — no re-entry",
    );

    // P0-4: compositional drain — infra repetition benign, custom repeats blocked
    let v = input(
        JUPITER,
        "e517cb977ae3ad2a",
        vec![
            gen_addr(1),
            gen_addr(2),
            gen_addr(3),
            gen_addr(4),
            gen_addr(5),
        ],
        vec![TOKEN.to_string(), TOKEN.to_string(), TOKEN.to_string()],
        "swap",
        good_evidence(),
    );
    push(
        &mut corpus,
        &mut notes,
        v,
        true,
        "regression",
        "p0-4-infra-repeats",
        "synthetic-benign",
        "repeated SPL Token CPI from trusted root — must approve",
    );
    let mut v = input(
        JUPITER,
        "e517cb977ae3ad2a",
        vec![
            gen_addr(1),
            gen_addr(2),
            gen_addr(3),
            gen_addr(4),
            gen_addr(5),
        ],
        vec![
            "custom_drainer".to_string(),
            "custom_drainer".to_string(),
            "custom_drainer".to_string(),
        ],
        "swap",
        good_evidence(),
    );
    v.cpi_targets[0] = "custom_drainer_9x".to_string();
    push(
        &mut corpus,
        &mut notes,
        v,
        false,
        "regression",
        "p0-4-custom-repeats",
        "synthetic-attack",
        "repeated custom-program CPI behind trusted root — must block",
    );

    // Phase 2 multi-instruction rules
    // AAT: Approve then Transfer on the same token account
    let approve = txi(TOKEN, "04", vec![gen_addr(1), gen_addr(2), gen_addr(3)]);
    let transfer = txi(TOKEN, "03", vec![gen_addr(1), gen_addr(4), gen_addr(5)]);
    let mut v = input(
        TOKEN,
        "04",
        vec![gen_addr(1), gen_addr(2), gen_addr(3)],
        vec![],
        "transfer",
        good_evidence(),
    );
    v.transaction_instructions = vec![transfer.clone()];
    push(
        &mut corpus,
        &mut notes,
        v,
        false,
        "regression",
        "multi-instruction",
        "synthetic-attack",
        "AAT approve-then-transfer on same account",
    );
    // ordering control: Transfer then Approve → NOT an AAT → approve
    let mut v = input(
        TOKEN,
        "03",
        vec![gen_addr(1), gen_addr(4), gen_addr(5)],
        vec![],
        "transfer",
        good_evidence(),
    );
    v.transaction_instructions = vec![approve.clone()];
    push(
        &mut corpus,
        &mut notes,
        v,
        true,
        "regression",
        "multi-instruction-control",
        "synthetic-benign",
        "transfer-then-approve ordering — must NOT be AAT",
    );
    // close-and-sweep: CloseAccount + Transfer
    let mut v = input(
        TOKEN,
        "09",
        vec![gen_addr(1), gen_addr(2)],
        vec![],
        "transfer",
        good_evidence(),
    );
    v.transaction_instructions = vec![transfer.clone()];
    push(
        &mut corpus,
        &mut notes,
        v,
        false,
        "regression",
        "multi-instruction",
        "synthetic-attack",
        "close-and-sweep (CloseAccount + Transfer)",
    );
    // ownership-theft: Approve + System Assign
    let mut v = input(
        TOKEN,
        "04",
        vec![gen_addr(1), gen_addr(2), gen_addr(3)],
        vec![],
        "transfer",
        good_evidence(),
    );
    v.transaction_instructions = vec![txi(SYSTEM, "01000000", vec![gen_addr(1)])];
    push(
        &mut corpus,
        &mut notes,
        v,
        false,
        "regression",
        "multi-instruction",
        "synthetic-attack",
        "ownership-theft (Approve + System assign)",
    );

    // Risk-class gates: high-risk + no intent → block; with intent → proceed
    push(
        &mut corpus,
        &mut notes,
        input(
            "Stake11111111111111111111111111111111111111",
            "04000000",
            vec![
                gen_addr(1),
                gen_addr(2),
                gen_addr(3),
                gen_addr(4),
                gen_addr(5),
            ],
            vec![],
            "",
            good_evidence(),
        ),
        false,
        "regression",
        "risk-class",
        "synthetic-attack",
        "Stake Withdraw no intent — Check 10",
    );
    push(
        &mut corpus,
        &mut notes,
        input(
            "Stake11111111111111111111111111111111111111",
            "04000000",
            vec![
                gen_addr(1),
                gen_addr(2),
                gen_addr(3),
                gen_addr(4),
                gen_addr(5),
            ],
            vec![],
            "transfer",
            good_evidence(),
        ),
        true,
        "regression",
        "risk-class",
        "synthetic-benign",
        "Stake Withdraw with transfer intent — proceeds",
    );
    push(
        &mut corpus,
        &mut notes,
        input(
            TOKEN,
            "07",
            vec![gen_addr(1), gen_addr(2), gen_addr(3)],
            vec![],
            "",
            good_evidence(),
        ),
        false,
        "regression",
        "risk-class",
        "synthetic-attack",
        "Token MintTo no intent — Check 10",
    );
    push(
        &mut corpus,
        &mut notes,
        input(
            TOKEN,
            "07",
            vec![gen_addr(1), gen_addr(2), gen_addr(3)],
            vec![],
            "transfer",
            good_evidence(),
        ),
        true,
        "regression",
        "risk-class",
        "synthetic-benign",
        "Token MintTo with intent — proceeds",
    );

    // CPI trace rules (C29)
    // unknown program in trace → block
    let mut v = input(
        JUPITER,
        "e517cb977ae3ad2a",
        vec![
            gen_addr(1),
            gen_addr(2),
            gen_addr(3),
            gen_addr(4),
            gen_addr(5),
        ],
        vec![],
        "swap",
        good_evidence(),
    );
    v.cpi_trace = Some(trace_node(
        JUPITER,
        0,
        vec![trace_node("attacker_prog_9x", 1, vec![])],
    ));
    push(
        &mut corpus,
        &mut notes,
        v,
        false,
        "regression",
        "cpi-trace",
        "synthetic-attack",
        "unknown program in CPI trace",
    );
    // depth ≥6 → warning only (not a hard block) — approve. The chain uses
    // SIX DISTINCT known programs (token → token-2022 → system → compute
    // budget → ATA → memo) so only the depth warning fires: a repeated
    // program (6× Token) would correctly trip the re-entry gate instead,
    // which is a different rule with a different verdict.
    let mut v = input(
        JUPITER,
        "e517cb977ae3ad2a",
        vec![
            gen_addr(1),
            gen_addr(2),
            gen_addr(3),
            gen_addr(4),
            gen_addr(5),
        ],
        vec![],
        "swap",
        good_evidence(),
    );
    let mut child = trace_node(
        COMPUTE_BUDGET,
        4,
        vec![trace_node(ATA, 5, vec![trace_node(MEMO, 6, vec![])])],
    );
    child = trace_node(SYSTEM, 3, vec![child]);
    child = trace_node(TOKEN_2022, 2, vec![child]);
    child = trace_node(TOKEN, 1, vec![child]);
    v.cpi_trace = Some(trace_node(JUPITER, 0, vec![child]));
    push(
        &mut corpus,
        &mut notes,
        v,
        true,
        "regression",
        "cpi-trace-depth",
        "synthetic-benign",
        "deep chain (6 distinct known programs) — depth warning only, not a block",
    );

    (corpus, notes)
}

// ─────────────────────────── real holdout corpus ──────────────────────────

#[derive(Deserialize)]
struct ExploitCorpus {
    count: usize,
    entries: Vec<ExploitEntry>,
}

#[derive(Deserialize)]
struct ExploitEntry {
    signature: String,
    source: String,
    attack_type: String,
    program_id: String,
    instruction_discriminator: String,
    account_addresses: Vec<String>,
    cpi_targets: Vec<String>,
}

const EXPLOIT_CORPUS_JSON: &str = include_str!("fixtures/exploit_corpus.json");
const JUP_MAINNET_JSON: &str = include_str!("fixtures/real_mainnet_jup.json");
const PUMP_MAINNET_JSON: &str = include_str!("fixtures/real_mainnet_pump.json");
const SYSTEM_MAINNET_JSON: &str = include_str!("fixtures/real_mainnet_system.json");

fn build_holdout() -> (RegressionCorpus, Vec<Note>) {
    let mut corpus = RegressionCorpus::new();
    let mut notes = Vec::new();

    // 35 real mainnet exploit signatures — expected=block from provenance
    // (SolPhishHunter arXiv:2505.04094 + on-chain reality), NOT from Graphite.
    let exploits: ExploitCorpus =
        serde_json::from_str(EXPLOIT_CORPUS_JSON).expect("exploit corpus parses");
    assert_eq!(
        exploits.count,
        exploits.entries.len(),
        "corpus count must match entries"
    );
    for e in &exploits.entries {
        let v = VerificationInput {
            proposed_intent: ProposedIntent {
                intent_type: "transfer".to_string(),
                raw_natural_language: "certification holdout".to_string(),
                confidence_of_parse: 0.9,
                extracted_parameters: None,
            },
            program_id: e.program_id.clone(),
            protocol_version: "1.0.0".to_string(),
            instruction_discriminator: e.instruction_discriminator.clone(),
            account_addresses: e.account_addresses.clone(),
            instruction_data: None,
            cpi_targets: e.cpi_targets.clone(),
            wallet_profile: WalletProfile::Custom {
                min_confidence: 0.40,
                min_trust_tier: graphite_core::semantic_graph_store::TrustTier::OfficialManifest,
            },
            behavior_evidence: good_evidence(),
            compute_units: 150,
            account_writes: 1,
            cpi_hops: 0,
            signed_transaction: None,
            transaction_instructions: vec![],
            cpi_trace: None,
        };
        // The signature is the fixture identity: two distinct real
        // transactions with byte-identical instruction shapes are DIFFERENT
        // fixtures (the provenance feeds the content hash), so no real
        // signature is ever deduped away.
        push(
            &mut corpus,
            &mut notes,
            v,
            false,
            "holdout",
            "real-exploit",
            format!("real-mainnet-exploit:{}", e.signature),
            format!("{} ({}) attack={}", e.signature, e.source, e.attack_type),
        );
    }

    // 3 real mainnet SUCCESSFUL transactions (meta.err == null). The label is
    // the DOCUMENTED policy verdict for the instruction the reader selects:
    //   - Jupiter swap → approve (known protocol, matching intent).
    //   - pump/system fixtures select an UNKNOWN top-level program via the
    //     max-accounts fallback → fail-closed block (P12 unknown protocol).
    // This is the honest statement of Graphite's contract, not "benign ⇒
    // approve".
    for (json, prefer, label) in [
        (
            JUP_MAINNET_JSON,
            "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
            "real-mainnet-jupiter",
        ),
        (
            PUMP_MAINNET_JSON,
            "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P",
            "real-mainnet-pump",
        ),
        (SYSTEM_MAINNET_JSON, "", "real-mainnet-system"),
    ] {
        let tx: serde_json::Value = serde_json::from_str(json).expect("mainnet fixture parses");
        let prefer: Vec<&str> = if prefer.is_empty() {
            vec![]
        } else {
            vec![prefer]
        };
        match graphite_core::live_corpus::tx_to_input(&tx, &prefer) {
            Some(v) => {
                // Documented policy: unknown program ⇒ fail-closed block.
                let is_manifested = {
                    let core = GraphiteCore::new();
                    core.list_manifests()
                        .iter()
                        .any(|m| m.protocol.program_id == v.program_id)
                };
                let expected = is_manifested;
                let short_prog = v.program_id[..8.min(v.program_id.len())].to_string();
                push(
                    &mut corpus,
                    &mut notes,
                    v,
                    expected,
                    "holdout",
                    "real-mainnet-benign",
                    "real-mainnet-tx",
                    format!("{label}: selected program {short_prog} (manifested={is_manifested})"),
                );
            }
            None => {
                panic!("{label}: real mainnet fixture did not convert to an input");
            }
        }
    }

    (corpus, notes)
}

// ──────────────────────────── replay helpers ──────────────────────────────

struct Diagnostic {
    program: String,
    disc: String,
    intent: String,
    expected: bool,
    got: bool,
    note: String,
    confidence: f64,
    risk: String,
    instruction: String,
    layers: Vec<String>,
}

/// Replay with rich diagnostics (per-fixture context for triage).
fn replay_with_diagnostics(
    core: &GraphiteCore,
    corpus: &RegressionCorpus,
    notes: &[Note],
) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    for f in corpus.all() {
        let note = notes
            .iter()
            .find(|n| n.hash == f.content_hash)
            .map(|n| n.note.clone())
            .unwrap_or_default();
        let got = match core.verify(&f.input) {
            Ok(r) => r.approved,
            Err(_) => false,
        };
        if got != f.expected_approved {
            let (confidence, risk, instruction, layers) = match core.verify(&f.input) {
                Ok(r) => {
                    let reason = r
                        .risk_verdict
                        .findings
                        .first()
                        .map(|x| format!("{}: {}", x.pattern, x.reason))
                        .unwrap_or_default();
                    let l: Vec<String> = r
                        .layers
                        .iter()
                        .map(|x| {
                            let st = format!("{:?}", x.status);
                            if st == "Failed" {
                                format!("{}:{}:{}", x.layer, st, x.reason)
                            } else {
                                format!("{}:{st}", x.layer)
                            }
                        })
                        .collect();
                    (r.confidence, reason, r.instruction_name.clone(), l)
                }
                Err(_) => (0.0, "verify-error".to_string(), String::new(), vec![]),
            };
            out.push(Diagnostic {
                program: f.program_id.clone(),
                disc: f.input.instruction_discriminator.clone(),
                intent: f.input.proposed_intent.intent_type.clone(),
                expected: f.expected_approved,
                got,
                note,
                confidence,
                risk,
                instruction,
                layers,
            });
        }
    }
    out
}

fn write_corpus_manifest(dir: &Path, notes: &[Note]) {
    std::fs::create_dir_all(dir).expect("corpus dir");
    // A plain sequence (hashes are unique — the in-memory corpus dedupes)
    // so the documentation file reads naturally and can never be mistaken
    // for a per-program fixture list.
    let json = serde_json::to_string_pretty(&notes).expect("notes serialize");
    std::fs::write(dir.join("corpus_manifest.json"), json).expect("write manifest");
}

// ───────────────────────────────── tests ──────────────────────────────────

fn build_all() -> (RegressionCorpus, Vec<Note>) {
    let core = GraphiteCore::new();
    let manifests: Vec<&ProtocolManifest> = core.list_manifests();
    assert!(
        manifests.len() >= 20,
        "expected the seed manifest set, got {}",
        manifests.len()
    );
    let (dev, dev_notes) = build_dev(&manifests);
    let (reg, reg_notes) = build_regression();
    let (hold, hold_notes) = build_holdout();
    let mut all = RegressionCorpus::new();
    let mut notes = Vec::new();
    for (c, n) in [(dev, dev_notes), (reg, reg_notes), (hold, hold_notes)] {
        for f in c.all().to_vec() {
            all.add_fixture(f);
        }
        notes.extend(n);
    }
    (all, notes)
}

#[test]
fn corpus_is_large_diverse_and_honestly_split() {
    let (corpus, notes) = build_all();
    let total = corpus.len();
    assert!(
        total >= 1000,
        "corpus must exceed 1000 meaningful fixtures, got {total}"
    );

    let by_split = |s: &str| notes.iter().filter(|n| n.split == s).count();
    let dev = by_split("dev");
    let reg = by_split("regression");
    let hold = by_split("holdout");
    assert!(dev >= 700, "dev split too small: {dev}");
    assert!(reg >= 30, "regression split too small: {reg}");
    assert!(hold >= 35, "holdout split too small: {hold}");

    // provenance honesty: holdout must be real; dev/regression must be labeled synthetic
    assert!(notes
        .iter()
        .filter(|n| n.split == "holdout")
        .all(|n| n.provenance.starts_with("real-")));
    assert!(notes
        .iter()
        .filter(|n| n.split != "holdout")
        .all(|n| n.provenance.starts_with("synthetic-")));

    // content-hash uniqueness (append-only corpus never duplicates)
    let mut hashes: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for n in &notes {
        assert!(hashes.insert(&n.hash), "duplicate content hash {}", n.hash);
    }
    assert_eq!(hashes.len(), total, "corpus len must equal unique fixtures");

    // protocol diversity
    let mut programs: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for f in corpus.all() {
        programs.insert(f.program_id.as_str());
    }
    assert!(
        programs.len() >= 20,
        "expected 20+ distinct programs, got {}",
        programs.len()
    );

    eprintln!(
        "\n[corpus] total={total} dev={dev} regression={reg} holdout={hold} programs={}",
        programs.len()
    );
}

#[test]
fn dev_corpus_replays_with_high_pass_rate() {
    let core = GraphiteCore::new();
    let (all, notes) = build_all();
    let dev_notes: Vec<Note> = notes.iter().filter(|n| n.split == "dev").cloned().collect();
    let dev_fixtures: Vec<RegressionFixture> = all
        .all()
        .iter()
        .filter(|f| dev_notes.iter().any(|n| n.hash == f.content_hash))
        .cloned()
        .collect();
    let mut dev_corpus = RegressionCorpus::new();
    for f in dev_fixtures {
        dev_corpus.add_fixture(f);
    }
    let failures = replay_with_diagnostics(&core, &dev_corpus, &dev_notes);
    let total = dev_corpus.len();
    let passed = total - failures.len();
    let rate = if total == 0 {
        0.0
    } else {
        passed as f64 / total as f64
    };
    eprintln!("\n[dev] {passed}/{total} pass ({:.3})", rate);
    for d in failures.iter() {
        eprintln!(
            "  FAIL exp={} got={} conf={:.3} risk={} ix={} layers={:?} prog={} disc={} intent={} | {}",
            d.expected, d.got, d.confidence, &d.risk[..d.risk.len().min(90)], d.instruction, d.layers,
            &d.program[..8.min(d.program.len())], d.disc, d.intent, d.note
        );
    }
    // Dev corpus is the implementation set — genuine divergences here are
    // either mislabeled fixtures or detector FPs; both must be resolved
    // before certification. Threshold 99.5% (P10 convention).
    assert!(
        rate >= 0.995,
        "dev corpus pass rate {rate:.3} below 0.995 — {} divergences to triage",
        failures.len()
    );
}

#[test]
fn regression_corpus_replays_perfect() {
    let core = GraphiteCore::new();
    let (all, notes) = build_all();
    let reg_notes: Vec<Note> = notes
        .iter()
        .filter(|n| n.split == "regression")
        .cloned()
        .collect();
    let reg_fixtures: Vec<RegressionFixture> = all
        .all()
        .iter()
        .filter(|f| reg_notes.iter().any(|n| n.hash == f.content_hash))
        .cloned()
        .collect();
    let mut reg_corpus = RegressionCorpus::new();
    for f in reg_fixtures {
        reg_corpus.add_fixture(f);
    }
    let failures = replay_with_diagnostics(&core, &reg_corpus, &reg_notes);
    eprintln!(
        "\n[regression] {}/{} pass",
        reg_corpus.len() - failures.len(),
        reg_corpus.len()
    );
    for d in &failures {
        eprintln!(
            "  REGRESSION exp={} got={} conf={:.3} risk={} ix={} layers={:?} prog={} disc={} | {}",
            d.expected,
            d.got,
            d.confidence,
            &d.risk[..d.risk.len().min(90)],
            d.instruction,
            d.layers,
            &d.program[..8.min(d.program.len())],
            d.disc,
            d.note
        );
    }
    // The regression split re-pins fixed issues: every fixture must pass.
    assert!(
        failures.is_empty(),
        "regression corpus has {} divergences — a fixed issue regressed",
        failures.len()
    );
}

#[test]
fn real_holdout_evaluation_independent_labels() {
    let core = GraphiteCore::new();
    let (all, notes) = build_all();
    let hold_notes: Vec<Note> = notes
        .iter()
        .filter(|n| n.split == "holdout")
        .cloned()
        .collect();
    let hold_fixtures: Vec<RegressionFixture> = all
        .all()
        .iter()
        .filter(|f| hold_notes.iter().any(|n| n.hash == f.content_hash))
        .cloned()
        .collect();
    let mut hold_corpus = RegressionCorpus::new();
    for f in hold_fixtures {
        hold_corpus.add_fixture(f);
    }

    // Independent-label evaluation: expected comes from provenance/policy,
    // never from Graphite. Report full confusion-matrix metrics.
    let mut tp = 0usize; // malicious, blocked
    let mut fn_c = 0usize; // malicious, approved  ← the security-critical number
    let mut fp = 0usize; // benign, blocked
    let mut tn = 0usize; // benign, approved
    let mut fn_details = Vec::new();
    let mut fp_details = Vec::new();
    for f in hold_corpus.all() {
        let got = match core.verify(&f.input) {
            Ok(r) => r.approved,
            Err(_) => false,
        };
        let malicious = !f.expected_approved;
        match (malicious, got) {
            (true, false) => tp += 1,
            (true, true) => {
                fn_c += 1;
                fn_details.push((f.program_id.clone(), f.content_hash.clone()));
            }
            (false, true) => tn += 1,
            (false, false) => {
                fp += 1;
                fp_details.push((f.program_id.clone(), f.content_hash.clone()));
            }
        }
    }
    let precision = if tp + fp == 0 {
        0.0
    } else {
        tp as f64 / (tp + fp) as f64
    };
    let recall = if tp + fn_c == 0 {
        0.0
    } else {
        tp as f64 / (tp + fn_c) as f64
    };
    let f1 = if precision + recall == 0.0 {
        0.0
    } else {
        2.0 * precision * recall / (precision + recall)
    };
    eprintln!(
        "\n[holdout] n={} TP={tp} TN={tn} FP={fp} FN={fn_c}\n  precision={precision:.3} recall={recall:.3} F1={f1:.3}",
        hold_corpus.len()
    );
    for (p, h) in &fn_details {
        eprintln!("  FALSE NEGATIVE (malicious approved): program {p} hash {h}");
    }
    for (p, h) in &fp_details {
        eprintln!("  FALSE POSITIVE (benign blocked): program {p} hash {h}");
    }

    // Security property: a documented real exploit must NEVER be approved.
    // (FP on a real benign tx is a finding to report, not a hard failure —
    // those are the policy-labeled unknowns documented in build_holdout.)
    assert!(
        fn_c == 0,
        "{} documented real exploit(s) were APPROVED — security regression",
        fn_c
    );
}

#[test]
fn corpus_persists_and_reloads_identically() {
    let (all, notes) = build_all();
    let dir = Path::new("fixtures/corpus");
    all.save_to_dir(dir).expect("save corpus");
    let loaded = RegressionCorpus::load_from_dir(dir).expect("load corpus");
    assert_eq!(
        loaded.len(),
        all.len(),
        "save/load roundtrip must preserve the corpus"
    );
    // The manifest documents splits/provenance; it must NOT live inside the
    // corpus dir (load_from_dir parses every .json there as a fixture list).
    write_corpus_manifest(Path::new("fixtures/corpus/meta"), &notes);
}

#[test]
fn p10_promotion_gate_passes_over_full_corpus() {
    // P10 gate (regression_engine): ≥99.5% of non-deprecated fixtures must
    // pass for promotion. The certification corpus is the engine's own
    // replay — using the production `replay_corpus`/`decide_promotion`, not
    // the test-local diagnostic loop.
    let core = GraphiteCore::new();
    let (all, _notes) = build_all();
    let run = replay_corpus(&core, &all);
    eprintln!(
        "\n[P10] {} passed / {} total ({:.3})",
        run.passed, run.total, run.pass_rate
    );
    for f in run.failures.iter().take(20) {
        eprintln!(
            "  P10-FAIL exp={} got={} prog={} hash={}",
            f.expected,
            f.got,
            &f.program_id[..8.min(f.program_id.len())],
            &f.content_hash[..12]
        );
    }
    assert!(
        matches!(
            graphite_core::regression_engine::decide_promotion(&run),
            graphite_core::regression_engine::PromotionDecision::Promote
        ),
        "P10 promotion gate blocked: {} failures",
        run.failures.len()
    );
}
