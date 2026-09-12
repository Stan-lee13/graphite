// Graphite Verification SDK — TypeScript types

// Must stay aligned with the Rust Core's semantic-layer vocabulary
// (verification.rs L5). Anything outside this set fails closed as
// "unknown intent type". `lend` is intentionally absent: the Core has no
// lending semantic class, so labeling an intent `lend` would fail closed.
export type IntentType =
  | "swap" | "trade" | "exchange"
  | "transfer" | "send"
  | "stake" | "delegate"
  | "close" | "close_account"
  | "create" | "create_account"
  | "approve" | "revoke"
  | "unknown";

export interface ExtractedParameters {
  input_token?: string;
  output_token?: string;
  amount?: string;
  destination?: string;
  slippage_bps?: number;
}

export interface ProposedIntent {
  intent_type: IntentType;
  raw_natural_language: string;
  confidence_of_parse: number;
  extracted_parameters?: ExtractedParameters;
}

/**
 * Wallet profile. The four built-in names map to fixed thresholds; Custom uses
 * the externally-tagged serde shape the Rust Core expects:
 * `{ "Custom": { "min_confidence": 0.40, "min_trust_tier": "OfficialManifest" } }`.
 */
export type WalletProfile =
  | "Treasury"
  | "TradingBot"
  | "Gaming"
  | "Enterprise"
  | { Custom: CustomProfile };
export interface CustomProfile {
  min_confidence: number;
  min_trust_tier: TrustTier;
}

export interface BehaviorEvidence {
  has_signed_manifest: boolean;
  community_verified_count: number;
  battle_tested_tx_count: number;
  simulation_match_count: number;
}

export interface VerificationInput {
  proposed_intent: ProposedIntent;
  program_id: string;
  protocol_version?: string;
  instruction_discriminator: string;
  account_addresses: string[];
  instruction_data?: number[];
  cpi_targets?: string[];
  wallet_profile?: WalletProfile;
  behavior_evidence?: BehaviorEvidence;
  compute_units?: number;
  account_writes?: number;
  cpi_hops?: number;
  /** Optional fully-signed transaction blob (binary). When provided, the
   *  Core's RPC client simulates this exact blob (most accurate L3 result).
   *  Serialized as a JSON array of bytes, NOT base64 (serde Vec<u8>). */
  signed_transaction?: number[];
  /** Phase 2: the COMPLETE list of instructions in the transaction, including
   *  the primary instruction. When 2+, the multi-instruction pattern analysis
   *  layer detects coordinated mass-drain patterns across them. */
  transaction_instructions?: TransactionInstruction[];
  /** Phase 2: the hierarchical CPI trace tree of the primary instruction. */
  cpi_trace?: CpiTraceNode;
  /** P1 (2026-09-05): declare that the underlying transaction is a
   *  versioned (v0) message resolving one or more accounts through Address
   *  Lookup Tables. Graphite cannot detect this itself (it only ever sees
   *  the flat account_addresses list) — when true, this surfaces a
   *  non-blocking warning that ALT-resolved accounts were not
   *  independently verified. Never reduces confidence or blocks (ALT usage
   *  is normal for legitimate complex swaps/routes). */
  uses_versioned_transaction?: boolean;
  /** Number of distinct Address Lookup Tables referenced, if known. Purely
   *  informational; included in the warning text when non-zero. */
  lookup_table_count?: number;
  /** P1 (2026-09-05): the REAL per-account signer/writable bits from the
   *  actual transaction, in the same order as `account_addresses`, when the
   *  caller has them (e.g. an SDK/bridge holding a real `AccountMeta[]`
   *  before calling Graphite). Cross-checked against the manifest's
   *  declared expectations — see `ResolvedAccount.privilege_mismatch`.
   *  Omitted/empty (the common case) means "not supplied": nothing is
   *  flagged, never silently assumed to match. A length mismatch against
   *  `account_addresses` is treated the same way (fail-safe). */
  real_account_metas?: RealAccountMeta[];
  /** Phase 1.5 simulation baselines are TRUSTED SERVER STATE (earned via
   *  RPC-verified usage or seeded by the operator) — never sent from the
   *  client. See GRAPHITE_RPC_URL and GraphiteCore::seed_simulation_baseline. */
}

/** The real per-account signer/writable bits from an actual transaction.
 *  Mirrors graphite-core/src/account_resolution.rs RealAccountMeta. */
export interface RealAccountMeta {
  is_signer: boolean;
  is_writable: boolean;
}

/** A single compiled instruction inside a Solana transaction message
 *  (Phase 2 multi-instruction analysis). Mirrors
 *  graphite-core/src/tx_pattern_analysis.rs TransactionInstruction. */
export interface TransactionInstruction {
  program_id: string;
  instruction_discriminator?: string;
  account_addresses?: string[];
  cpi_targets?: string[];
}

/** A node in the hierarchical CPI trace tree (depth 0 = root). Mirrors
 *  graphite-core/src/tx_pattern_analysis.rs CpiTraceNode. */
export interface CpiTraceNode {
  program_id: string;
  instruction_discriminator?: string;
  depth: number;
  account_addresses?: string[];
  children?: CpiTraceNode[];
}

export type TrustTier =
  | "Unknown"
  | "HeuristicInferred"
  | "OfficialManifest"
  | "SimulationValidated"
  | "CommunityVerified"
  | "BattleTested";

export interface VerificationBreakdownItem {
  kind: string;
  raw_value: number;
  weight: number;
  contribution: number;
}

export interface RiskFinding {
  pattern: string;
  reason: string;
}

export interface RiskVerdictSummary {
  status: "Clear" | "Blocked";
  findings: RiskFinding[];
}

export interface BuiltAccountMeta {
  address: string;
  is_signer: boolean;
  is_writable: boolean;
}

export interface BuiltTransaction {
  program_id: string;
  protocol_version: string;
  instruction_name: string;
  instruction_discriminator: string;
  instruction_count: number;
  account_count: number;
  signer_count: number;
  writable_count: number;
  compute_budget_units: number;
  accounts: BuiltAccountMeta[];
  data_hex: string;
  data_len: number;
}

/** How an account's identity is verified. `Pda` = re-derived from the
 *  manifest's seed template; `Constant` = matched against a manifest-declared
 *  fixed address (e.g. the SPL Token program); `Unverified` = genuinely
 *  externally-determined (no PDA formula, no fixed constant) — honestly
 *  disclosed rather than silently assumed safe. Mirrors
 *  graphite-core/src/account_resolution.rs AccountIdentity. */
export type AccountIdentity = "Pda" | "Constant" | "Unverified";

export interface ResolvedAccount {
  address: string;
  role: string;
  is_pda: boolean;
  is_signer: boolean;
  is_writable: boolean;
  pda_seeds: string[];
  identity: AccountIdentity;
  /** True if the derived PDA does not match the provided address.
   *  This is a security signal — a PDA mismatch means the transaction
   *  is sending accounts that don't match the protocol's expected PDA. */
  pda_mismatch?: boolean;
  /** True if a manifest-declared `expected_address` constant (e.g. the SPL
   *  Token program) does not match the provided address — an attacker
   *  substituting a lookalike program for a fixed-constant slot. */
  expected_address_mismatch?: boolean;
  /** P1 (2026-09-05): true if a caller-supplied `real_account_metas` entry
   *  for this position DISAGREES with the manifest's declared expectation
   *  in a security-relevant direction — a required signer that the real
   *  transaction did not sign, or a manifest-readonly slot the real
   *  transaction marks writable (privilege escalation). The reverse
   *  (more-restrictive) directions are never flagged, and absence of
   *  `real_account_metas` leaves this honestly `false` ("not checked"). */
  privilege_mismatch?: boolean;
}

export interface VerificationResult {
  approved: boolean;
  confidence: number;
  breakdown: VerificationBreakdownItem[];
  trust_tier: TrustTier;
  risk_verdict: RiskVerdictSummary;
  policy_verdict: string;
  audit_trail_id: string;
  content_hash: string;
  transaction: BuiltTransaction;
  resolved_accounts: ResolvedAccount[];
  protocol_name: string;
  instruction_name: string;
  manifest_found: boolean;
  unknown_protocol: boolean;
  /** Version label of the protocol manifest this result was checked against
   *  (null/absent for unknown protocols). Constitution G7 — lets a consumer
   *  confirm which manifest version produced the verification. */
  manifest_version?: string | null;
  summary: string;
  /** Phase 1.5: Simulation integrity result (null if not checked) */
  simulation_flagged?: boolean | null;
  simulation_divergence?: number | null;
  /** 8-layer pipeline results (L1-L8) */
  layers?: PipelineLayerResult[];
  /**
   * What this verdict is BOUND to, and what it did not observe.
   *
   * This is the field that makes Graphite's central promise checkable instead
   * of assumed: the thing it approved is the thing that gets signed, and every
   * security-relevant property of that thing was either independently verified
   * or explicitly identified as unverified.
   *
   * `approved` alone does not tell you which half applies. A verdict that
   * merely describes caller-supplied metadata and one bound to real signed
   * bytes are otherwise the same shape — which is exactly how an integration
   * can end up executing an instruction nothing examined.
   *
   * Optional for compatibility with servers older than 2026-09-08. Absent is
   * NOT the same as `descriptive`: it means the server did not say, and a gate
   * that requires artifact binding should treat it as unknown rather than
   * assume either answer.
   */
  scope?: VerificationScope;
}

/**
 * A machine-readable name for one entry of `scope.unobserved`.
 *
 * `unobserved_codes[i]` names `unobserved[i]`: same length, same order. The
 * prose is for people; a consumer that has to DECIDE whether a residual is
 * acceptable needs a stable identifier, and this is it. Mirrors
 * `UnobservedCode` in `graphite-core/src/verification.rs` and the enum in
 * `schemas/verification-result-v1.json`.
 *
 * `program_semantics` and `inner_instructions` are inherent to every
 * artifact-bound verdict (see `INHERENT_UNOBSERVED`). Every other code names
 * an observation that was possible and did not happen. An execution-capable
 * integration must not execute on a verdict carrying one it has not
 * explicitly accepted.
 */
export type UnobservedCode =
  | "not_simulated"
  | "no_state_diff"
  | "privileges_from_caller"
  | "privileges_absent"
  | "lookup_tables_unresolved"
  | "program_semantics"
  | "inner_instructions"
  | "artifact_unparsed"
  | "account_identity_unparsed"
  | "instruction_not_located"
  | "no_artifact"
  | "other_instructions"
  | "fee_payer_blockhash_signers"
  | "no_real_effects";

/** Every code, in the core's declaration order. */
export const UNOBSERVED_CODES: readonly UnobservedCode[] = [
  "not_simulated",
  "no_state_diff",
  "privileges_from_caller",
  "privileges_absent",
  "lookup_tables_unresolved",
  "program_semantics",
  "inner_instructions",
  "artifact_unparsed",
  "account_identity_unparsed",
  "instruction_not_located",
  "no_artifact",
  "other_instructions",
  "fee_payer_blockhash_signers",
  "no_real_effects",
] as const;

/**
 * The residuals every artifact-bound verdict carries by construction. A
 * policy that accepts only these accepts nothing the pipeline could have
 * observed and did not.
 */
export const INHERENT_UNOBSERVED: ReadonlySet<UnobservedCode> = new Set<UnobservedCode>([
  "program_semantics",
  "inner_instructions",
]);

/** `scope.kind === "artifact_bound"`: the verdict is tied to concrete bytes. */
export interface ArtifactBoundScope {
  kind: "artifact_bound";
  /**
   * SHA-256 of the exact transaction bytes that were supplied. A caller can
   * recompute this over what they are about to submit and refuse if it differs
   * — a stronger binding than `content_hash`, which covers a projection of one
   * instruction and cannot see the fee payer, the blockhash, the signer set, or
   * any sibling instruction.
   */
  transaction_sha256: string;
  transaction_bytes: number;
  /** Whether a simulator actually executed those bytes. */
  simulated: boolean;
  /** Security-relevant properties still not independently observed. */
  unobserved: string[];
  /**
   * `unobserved_codes[i]` names `unobserved[i]`. Optional only for servers
   * older than Round 9 (2026-09-12); a gate that decides on codes must treat
   * its absence as unknown, not as empty.
   */
  unobserved_codes?: UnobservedCode[];
}

/** `scope.kind === "descriptive"`: nothing here constrains what gets signed. */
export interface DescriptiveScope {
  kind: "descriptive";
  unobserved: string[];
  unobserved_codes?: UnobservedCode[];
}

export type VerificationScope = ArtifactBoundScope | DescriptiveScope;

/**
 * True only when the verdict is tied to concrete transaction bytes.
 *
 * An execution gate that can actually move funds should require this rather
 * than gating on `approved` alone. Returns false for an absent scope: an older
 * server that did not say has not said yes.
 */
export function isArtifactBound(
  result: Pick<VerificationResult, "scope">,
): result is Pick<VerificationResult, "scope"> & { scope: ArtifactBoundScope } {
  return result.scope?.kind === "artifact_bound";
}

/**
 * Everything Graphite did not independently observe, in either mode.
 * Empty when the server did not report a scope at all — which is itself
 * unknown rather than nothing.
 */
export function unobserved(result: Pick<VerificationResult, "scope">): string[] {
  return result.scope?.unobserved ?? [];
}

/**
 * The codes naming each entry of `unobserved`, or `undefined` when the server
 * did not report them (pre-Round-9). Never an empty array for a missing
 * field: "no codes reported" and "nothing unobserved" are different answers,
 * and the second is never true.
 */
export function unobservedCodes(
  result: Pick<VerificationResult, "scope">,
): UnobservedCode[] | undefined {
  return result.scope?.unobserved_codes;
}

/**
 * A caller-reported lifecycle stage. Graphite performs construction,
 * simulation and verification itself and records those; signing,
 * submission, confirmation and finalization happen in the caller, and only
 * the caller can put them on the trail (`POST /audit/event`).
 */
export type CallerLifecycleEvent = "signing" | "submission" | "confirmation" | "finalization";

export interface LifecycleEventInput {
  event_type: CallerLifecycleEvent;
  /** The verification's `content_hash`: 16 lowercase hex characters. */
  content_hash: string;
  audit_trail_id?: string;
  /** Base58 signature, once one exists (submission onward). */
  transaction_signature?: string;
  /** Who is reporting — an operator-meaningful name, never a credential. */
  reported_by?: string;
  /** Free-form, at most 1024 characters. */
  detail?: string;
}

/**
 * What the trail held for the event's `content_hash` when the event was
 * recorded — established by Graphite, not reported by the caller. `blocked`
 * means the caller just reported acting on a transaction Graphite refused.
 */
export type VerdictOnRecord = "approved" | "blocked" | "not_found";

export interface LifecycleEventReceipt {
  recorded: true;
  event_type: CallerLifecycleEvent;
  content_hash: string;
  verdict_on_record: VerdictOnRecord;
}

/** Body of `POST /verify/execution` (L8). */
export interface ExecutionCheckInput {
  /** The on-chain signature to confirm. */
  signature: string;
  /** The verification this execution corresponds to. */
  content_hash?: string;
  reported_by?: string;
}

/**
 * L8's answer: what the chain says about the signature, reconciled against
 * the verdict on record. `reconciliation` is the server's tagged enum,
 * carried as-is; `BlockedButExecuted` is the one to page on.
 */
export interface ExecutionCheckResult {
  signature: string;
  /** The server's `ExecutionVerification` for the signature, as-is. */
  chain_status: unknown;
  /** The verdict on record for the content_hash, when one exists. */
  recorded_approved: boolean | null;
  recorded_audit_trail_id: string | null;
  /**
   * The server's `ExecutionReconciliation`: a string for unit variants
   * (`"ApprovedAndExecuted"`, `"BlockedButExecuted"`, `"NotFound"`,
   * `"NoVerificationOnRecord"`, ...) or a one-key object for variants that
   * carry data. Read `discrepancy` for the decision.
   */
  reconciliation: unknown;
  /** True for `BlockedButExecuted`: Graphite's decision did not govern. */
  discrepancy: boolean;
  /** Whether this reconciliation row reached the trail. */
  audit_recorded: boolean;
}

export interface PipelineLayerResult {
  layer: string;
  passed: boolean;
  /**
   * Tri-state layer outcome (GAP-2026-08-06-3). `passed` is derived from
   * this: only 'passed' yields `passed: true`. Inconclusive = skipped or
   * not yet verified — never a pass.
   */
  status?: 'passed' | 'failed' | 'inconclusive';
  reason: string;
}

export interface ProtocolManifest {
  graphite_manifest_version: string;
  protocol: {
    name: string;
    program_id: string;
    website?: string;
    github?: string;
    /** Functional classification ("swap", "lending", "bridge", "nft", ...). */
    category?: string;
  };
  version: {
    label: string;
    effective_from_slot?: number;
    previous_version_ref?: string | null;
  };
  instructions: Array<{
    name: string;
    discriminator: string;
    accounts: Array<{
      name: string;
      role: string;
      is_writable: boolean;
      is_signer: boolean;
      pda_seeds?: string[];
    }>;
    expected_state_changes: string[];
    allowed_cpis: string[];
    risk_rules: string[];
  }>;
  trust_tier?: string;
}
