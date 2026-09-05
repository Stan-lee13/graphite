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
  /** Phase 1.5 simulation baselines are TRUSTED SERVER STATE (earned via
   *  RPC-verified usage or seeded by the operator) — never sent from the
   *  client. See GRAPHITE_RPC_URL and GraphiteCore::seed_simulation_baseline. */
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

export interface ResolvedAccount {
  address: string;
  role: string;
  is_pda: boolean;
  is_signer: boolean;
  is_writable: boolean;
  pda_seeds: string[];
  /** True if the derived PDA does not match the provided address.
   *  This is a security signal — a PDA mismatch means the transaction
   *  is sending accounts that don't match the protocol's expected PDA. */
  pda_mismatch?: boolean;
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
