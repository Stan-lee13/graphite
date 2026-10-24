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
  // Round 30: these describe only the instructions a grounded grant names
  // (graphite-core/src/intent_grants.rs), when the transaction's accounts
  // show the operation is the signer's own; anything else is refused.
  | "withdraw" | "redeem" | "remove_liquidity" | "decrease_liquidity"
  | "claim" | "claim_fees" | "claim_rewards" | "collect_fees" | "harvest"
  | "burn"
  | "configure" | "update_config"
  | "unknown";

/** Every `IntentType`, in the order of `schemas/proposed-intent-v1.json`. */
export const INTENT_TYPES: readonly IntentType[] = [
  "swap", "trade", "exchange", "transfer", "send", "stake", "delegate",
  "close", "close_account", "create", "create_account", "approve", "revoke",
  "withdraw", "redeem", "remove_liquidity", "decrease_liquidity",
  "claim", "claim_fees", "claim_rewards", "collect_fees", "harvest",
  "burn", "configure", "update_config", "unknown",
];

export interface ExtractedParameters {
  input_token?: string;
  output_token?: string;
  amount?: string;
  destination?: string;
  account_type?: string;
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
  /** The serialized transaction artifact, UNSIGNED: every signature slot must
   *  be 64 zero bytes. Despite the field's name it is not a signed blob —
   *  Graphite verifies before signing, and since Round 17 (F-16-01) the Core
   *  answers 400 to an artifact with a filled slot, because signed bytes mean
   *  the signing already happened (Round 19, F-19-C3 corrected this doc). When
   *  provided the verdict is `artifact_bound`, the Core's RPC client simulates
   *  these exact bytes, and `scope.transaction_sha256` is their digest — check
   *  it with `verifyTransactionDigest` before signing or submitting.
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

/**
 * The verdict's `transaction` field: a SUMMARY of the one described
 * instruction (Rust `InstructionSummary`), not a transaction and not wire
 * bytes. `compute_budget_units` is a heuristic estimate, never a
 * measurement. The bytes a verdict binds to are identified by
 * `scope.transaction_sha256`.
 */
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

/** How an account's identity is verified. `pda` = re-derived from the
 *  manifest's seed template; `constant` = matched against a manifest-declared
 *  fixed address (e.g. the SPL Token program); `unverified` = genuinely
 *  externally-determined (no PDA formula, no fixed constant) — honestly
 *  disclosed rather than silently assumed safe. Mirrors
 *  graphite-core/src/account_resolution.rs AccountIdentity, which serializes
 *  snake_case. A5-03 (2026-09-29 audit): this was `"Pda" | "Constant" |
 *  "Unverified"`, which no real verdict ever carries. */
export type AccountIdentity = "pda" | "constant" | "unverified";

/** Every identity value, as the Core puts it on the wire. */
export const ACCOUNT_IDENTITIES: readonly AccountIdentity[] = ["pda", "constant", "unverified"] as const;

export interface ResolvedAccount {
  address: string;
  role: string;
  /** The slot's name in the manifest (`source`, `authority`, ...). Omitted
   *  by the Core when empty: an account past the manifest's declared list,
   *  or of an unknown program. */
  name?: string;
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

/** The same type under the name that says what it is (Round 30). */
export type InstructionSummary = BuiltTransaction;

/**
 * What a verdict permits (Round 30, G-01). Only `executable_approved`
 * permits signing; see `isExecutable`. Mirrors `ExecutionDecision` in
 * `graphite-core/src/verification.rs` and the schema's enum.
 */
export type ExecutionDecision = "executable_approved" | "analysis_only" | "inconclusive" | "blocked";

/** Every decision, in the Core's declaration order. */
export const EXECUTION_DECISIONS: readonly ExecutionDecision[] = [
  "executable_approved",
  "analysis_only",
  "inconclusive",
  "blocked",
] as const;

export interface VerificationResult {
  /**
   * Whether the pipeline refused the transaction. NOT permission to sign:
   * an approval from a node without an RPC was never simulated, and a
   * descriptive approval binds to no bytes. Gate signing on `isExecutable`.
   */
  approved: boolean;
  /**
   * What this verdict permits (Round 30). Only `executable_approved` permits
   * signing. Absent from servers older than Round 30; `GraphiteClient.verify`
   * requires a known value when present, and `isExecutable` recomputes it.
   */
  decision?: ExecutionDecision;
  /** `decision === "executable_approved"` (Round 30). */
  executable?: boolean;
  confidence: number;
  breakdown: VerificationBreakdownItem[];
  trust_tier: TrustTier;
  risk_verdict: RiskVerdictSummary;
  policy_verdict: string;
  audit_trail_id: string;
  /**
   * @deprecated Round 30 (R-M10): read `instruction_bind_key` (or
   * `instructionBindKey(result)`), which carries the same value. A 64-bit
   * key for the described INSTRUCTION, not the transaction's identity —
   * that is `scope.transaction_sha256`.
   */
  content_hash: string;
  /**
   * The same value as `content_hash`, named for what it is: the key binding
   * audit and lifecycle records to the described instruction (Round 30).
   * Absent from servers older than Round 30.
   */
  instruction_bind_key?: string;
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
  /** 8-layer pipeline results (L1-L8). Always emitted by the Core and
   *  required by `GraphiteClient.verify`; optional here for hand-built results. */
  layers?: PipelineLayerResult[];
  /**
   * Roadmap R-M1: programs this transaction invokes that were redeployed, or
   * handed to a new upgrade authority, since Graphite last saw them. Absent
   * when none were (or no RPC is attached, or the server predates it).
   */
  program_upgrades?: ProgramUpgrade[];
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
   * Optional in this type only so that code constructing a result by hand
   * (test fakes, older fixtures) still compiles. `GraphiteClient.verify`
   * refuses a response without it (audit 2026-10-20: the Core has emitted it
   * on every verdict since 2026-09-08 and the schema now requires it). Absent
   * is NOT the same as `descriptive`: it means nothing said, and a gate that
   * requires artifact binding treats it as unknown rather than assume either
   * answer.
   */
  scope?: VerificationScope;
}

/** `GET /health`. Open by design (no API key); `status` stays "ok" while the
 *  node serves traffic, and `degraded` is the operator signal. */
export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  degraded?: boolean;
  degraded_reasons?: string[];
  /** Round 30: `analysis_only` when the Core has no RPC (every verdict is then
   *  not executable), `executable` otherwise. Absent from older servers. */
  verification_mode?: "executable" | "analysis_only";
  [key: string]: unknown;
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
  | "simulation_failed"
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
  | "no_real_effects"
  | "intent_parameters"
  | "program_deployments";

/** Every code, in the core's declaration order. */
export const UNOBSERVED_CODES: readonly UnobservedCode[] = [
  "not_simulated",
  "no_state_diff",
  "simulation_failed",
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
  "intent_parameters",
  "program_deployments",
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

/** A program whose deployment changed since Graphite last saw it (roadmap R-M1). */
export interface ProgramUpgrade {
  program_id: string;
  previous_deploy_slot: number;
  deploy_slot: number;
  previous_upgrade_authority: string | null;
  upgrade_authority: string | null;
  /** Whether the operator's GRAPHITE_QUARANTINE_ON_UPGRADE withdrew it from trust. */
  quarantined: boolean;
}

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
   * `unobserved_codes[i]` names `unobserved[i]`. Optional in this type for
   * hand-built results; `GraphiteClient.verify` requires it, as the schema
   * does (audit 2026-10-20). A gate that decides on codes must treat its
   * absence as unknown, not as empty.
   */
  unobserved_codes?: UnobservedCode[];
  /**
   * What the transaction asks of the compute budget, read from its bytes
   * (Round 21): the v1 header, or Compute Budget instructions for legacy/v0.
   * Absent from servers older than Round 21 and when the bytes did not parse.
   */
  compute_budget?: ComputeBudgetRequest;
  /**
   * The message version the bytes carry, read from them (Round 24). Absent
   * when they did not parse, and from servers older than Round 24.
   */
  message_version?: "legacy" | "v0" | "v1";
}

/** A transaction's compute-budget request (Round 21). */
export interface ComputeBudgetRequest {
  source: "v1_header" | "compute_budget_instructions";
  compute_unit_limit?: number | null;
  /** The limit the runtime applies (the set one capped at 1.4M, else the default's upper bound). */
  effective_compute_unit_limit: number;
  compute_unit_price_micro_lamports?: number | null;
  /** The priority fee in lamports (at most this when no limit is set). */
  priority_fee_lamports: number;
  heap_bytes?: number | null;
  loaded_accounts_data_size_limit?: number | null;
  /** What the runtime would refuse. */
  problems?: string[];
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
 * server that did not say has not said yes. Returns false, too, for a scope
 * that claims `artifact_bound` without a 64-lowercase-hex digest of what it
 * bound (audit 2026-10-20, parity with Go's `IsArtifactBound`): a binding
 * without its digest binds nothing.
 */
export function isArtifactBound(
  result: Pick<VerificationResult, "scope">,
): result is Pick<VerificationResult, "scope"> & { scope: ArtifactBoundScope } {
  const scope = result.scope;
  return (
    scope?.kind === "artifact_bound" &&
    typeof scope.transaction_sha256 === "string" &&
    /^[0-9a-f]{64}$/.test(scope.transaction_sha256)
  );
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

/** The fields the execution decision is computed from. */
export type DecisionInputs = Pick<
  VerificationResult,
  "approved" | "risk_verdict" | "policy_verdict" | "scope" | "layers"
>;

/**
 * The Core's execution-decision rule, recomputed from a verdict's own
 * fields (Round 30, G-01; `execution_decision` in
 * `graphite-core/src/verification.rs`). Executable only when ALL hold:
 * approved; risk Clear; policy "Approved"; scope `artifact_bound` with a
 * digest and `simulated: true`; `unobserved_codes` present, naming every
 * `unobserved` entry, and all inherent; layers reported and none `failed`.
 * Otherwise an approval is `analysis_only`; a refusal whose risk findings
 * are all `VerificationIncomplete` is `inconclusive`; every other refusal is
 * `blocked`. Missing fields never make a verdict executable.
 */
export function computeExecutionDecision(result: DecisionInputs): ExecutionDecision {
  if (result.approved !== true) {
    const findings = result.risk_verdict?.findings ?? [];
    return findings.length > 0 && findings.every((f) => f.pattern === "VerificationIncomplete")
      ? "inconclusive"
      : "blocked";
  }
  const scope = result.scope;
  const codes = scope?.unobserved_codes;
  const executable =
    result.risk_verdict?.status === "Clear" &&
    result.policy_verdict === "Approved" &&
    isArtifactBound(result) &&
    scope?.kind === "artifact_bound" &&
    scope.simulated === true &&
    Array.isArray(codes) &&
    Array.isArray(scope.unobserved) &&
    codes.length === scope.unobserved.length &&
    codes.every((c) => INHERENT_UNOBSERVED.has(c)) &&
    Array.isArray(result.layers) &&
    !result.layers.some((l) => l.status === "failed");
  return executable ? "executable_approved" : "analysis_only";
}

/**
 * Whether this verdict permits signing — the ONE gate an execution path
 * should use (Round 30, G-01). Not `approved`: without an RPC nothing is
 * simulated and an approval carries `not_simulated`.
 *
 * Recomputes the Core's rule locally and requires the server to agree:
 * - a server that sent `decision` must say `executable_approved` with
 *   `executable: true`, AND the local recomputation must agree;
 * - a decision this SDK does not know is not executable;
 * - a response without `decision` (a server older than Round 30) is judged
 *   by the local recomputation alone, which is never looser than the
 *   server's rule.
 */
export function isExecutable(result: DecisionInputs & Pick<VerificationResult, "decision" | "executable">): boolean {
  const local = computeExecutionDecision(result);
  if (result.decision === undefined && result.executable === undefined) {
    return local === "executable_approved";
  }
  if (!(EXECUTION_DECISIONS as readonly unknown[]).includes(result.decision)) return false;
  return result.decision === "executable_approved" && result.executable === true && local === "executable_approved";
}

/**
 * The key binding audit and lifecycle records to the described instruction
 * (Round 30, R-M10): `instruction_bind_key`, or the deprecated
 * `content_hash` from an older server.
 */
export function instructionBindKey(result: Pick<VerificationResult, "content_hash" | "instruction_bind_key">): string {
  return result.instruction_bind_key ?? result.content_hash;
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
  /**
   * The verification's `instruction_bind_key`: 16 lowercase hex characters.
   * An instruction-level key — every transaction carrying that instruction
   * shares it — so send `audit_trail_id` (and `transaction_sha256`) with it.
   * This or `content_hash` is required (Round 32, R-M10); the client sends
   * the key under both names, which every Core accepts.
   */
  instruction_bind_key?: string;
  /**
   * @deprecated Round 32 (R-M10): send `instruction_bind_key`. The same key
   * under its first name; when both are given they must be equal.
   */
  content_hash?: string;
  /** The exact verification. The most exact key; resolves first. */
  audit_trail_id?: string;
  /** The exact transaction (`scope.transaction_sha256`, 64 lowercase hex). */
  transaction_sha256?: string;
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

/**
 * Which key `verdict_on_record` was resolved by. `content_hash` means the
 * answer is about *a* transaction carrying that instruction, not necessarily
 * the one the event is about.
 */
export type VerificationKeyKind = "audit_trail_id" | "transaction_sha256" | "content_hash";

export interface LifecycleEventReceipt {
  recorded: true;
  event_type: CallerLifecycleEvent;
  content_hash: string;
  verdict_on_record: VerdictOnRecord;
  verdict_on_record_key: VerificationKeyKind;
  /**
   * How this report sits against the rows already on record for the same
   * transaction (Round 12): `duplicate: …` (a retry — harmless), `out of
   * order: …`, `unpreceded: …`, or `signature conflict: …` (a different
   * signature is already attached to this transaction; one of the two
   * reports is not about it). Empty when the report is in order. Servers
   * before Round 12 omit the field.
   */
  sequence_anomalies?: string[];
  /** How many lifecycle rows were already on record for this transaction. */
  prior_events_on_record?: number;
}

/**
 * How far the cluster stands behind an inclusion, from
 * `getSignatureStatuses`. `processed` is one node's view and can still be
 * discarded; L8 draws no positive conclusion from it.
 */
export type InclusionCommitment = "processed" | "confirmed" | "finalized";

/** See `ExecutionCheckResult.inclusion_assurance` (Round 30). */
export type InclusionAssurance =
  | "single_provider"
  | "witnessed"
  | "witnessed_not_independent"
  | "witness_disputed"
  | "witness_unavailable";

/** Every `InclusionAssurance`, for runtime checks. */
export const INCLUSION_ASSURANCES: readonly InclusionAssurance[] = [
  "single_provider",
  "witnessed",
  "witnessed_not_independent",
  "witness_disputed",
  "witness_unavailable",
];

/**
 * A second RPC's account of the signature, held against the primary's
 * (Round 12). Present when the server has `GRAPHITE_RPC_WITNESS_URL`.
 */
export interface InclusionWitness {
  /** Both have no record, or both place it in the same slot with the same outcome. */
  agrees: boolean;
  /** Whether the witness has any record; `null` when it could not be reached. */
  seen: boolean | null;
  commitment?: InclusionCommitment | null;
  detail: string;
}

/** Body of `POST /verify/execution` (L8). */
export interface ExecutionCheckInput {
  /** The on-chain signature to confirm. */
  signature: string;
  /** The verification this execution corresponds to (instruction-level key). */
  instruction_bind_key?: string;
  /**
   * @deprecated Round 32 (R-M10): send `instruction_bind_key`. When both are
   * given they must be equal.
   */
  content_hash?: string;
  /** The exact transaction (`scope.transaction_sha256`). */
  transaction_sha256?: string;
  /** The exact verification. */
  audit_trail_id?: string;
  reported_by?: string;
}

/**
 * How L8 joined the execution to a verification. `chain` is the answer
 * independent of anything the caller said: the bytes behind the signature,
 * signature slots zeroed, digest to the verification of those bytes. The
 * others are caller-supplied keys used only when the chain's bytes could not
 * be fetched; `content_hash` alone may name a different transaction carrying
 * the same instruction.
 */
export type ExecutionAttribution =
  | "chain"
  | "audit_trail_id"
  | "transaction_sha256"
  | "content_hash"
  | "none";

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
  recorded_transaction_sha256: string | null;
  attribution: ExecutionAttribution;
  /** The artifact digest recomputed from the chain's bytes, when fetched. */
  chain_transaction_sha256: string | null;
  /**
   * Caller-supplied keys that named a different verification from the one
   * the execution resolves to. Non-empty means the caller's attestation was
   * wrong; the reconciliation is against the resolved record.
   */
  caller_keys_disagree: string[];
  /**
   * Present when the RPC returned transaction bytes for the signature that
   * are not bound to it — the first slot does not hold the signature, or the
   * signature does not verify over the message under the fee payer's key.
   * Those bytes were not used and the caller's keys were NOT consulted in
   * their place; `reconciliation` is `Unavailable` with this reason. An RPC
   * that does this is faulty or hostile.
   */
  chain_bytes_rejected?: string | null;
  /**
   * Why the chain's bytes were not available although the status said the
   * signature landed (the fetch failed, or the RPC answered `null`), so an
   * attribution by caller keys is visibly not the chain's (Round 12).
   */
  chain_bytes_unavailable?: string | null;
  /**
   * The RPC contradicted itself about this signature — slot or outcome
   * differ between `getSignatureStatuses` and `getTransaction`. No positive
   * conclusion is drawn; `BlockedButExecuted` still fires (Round 12).
   */
  chain_inconsistent?: string | null;
  /** The inclusion witness's account, when one is attached; `null` otherwise. */
  inclusion_witness?: InclusionWitness | null;
  /**
   * What this reconciliation's account of inclusion rests on (Round 30): one
   * provider's word, an independent witness that agrees, a witness that is
   * not an independent provider, one that disagrees, or one that could not
   * be reached. L8 asks RPC providers; it checks no light-client proof.
   * Absent from servers older than Round 30.
   */
  inclusion_assurance?: InclusionAssurance;
  /**
   * Every verdict the trail holds for the key the execution resolved by, as
   * counts (Round 17, F-16-11): `refused > 0` beside an approval means the
   * artifact was refused and then re-verified under a looser profile. `null`
   * when nothing was resolved. The server has always sent it; the type
   * lacked it until the 2026-10-20 audit.
   */
  recorded_verdicts?: { approved: number; refused: number } | null;
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
