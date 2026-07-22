// Graphite Verification SDK — TypeScript types

export type IntentType = "swap" | "transfer" | "stake" | "lend" | "unknown";

export interface ExtractedParameters {
  input_token?: string;
  output_token?: string;
  amount?: string;
  slippage_bps?: number;
}

export interface ProposedIntent {
  intent_type: IntentType;
  raw_natural_language: string;
  confidence_of_parse: number;
  extracted_parameters?: ExtractedParameters;
}

export type WalletProfile = "Conservative" | "Standard" | "Permissive" | "Enterprise";

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
}

export interface VerificationResult {
  approved: boolean;
  confidence: number;
  breakdown: VerificationBreakdownItem[];
  trust_tier: TrustTier;
  risk_verdict: RiskVerdictSummary;
  policy_verdict: string;
  audit_trail_id: string;
  transaction: BuiltTransaction;
  resolved_accounts: ResolvedAccount[];
  protocol_name: string;
  instruction_name: string;
  manifest_found: boolean;
  unknown_protocol: boolean;
  summary: string;
}

export interface ProtocolManifest {
  graphite_manifest_version: string;
  protocol: {
    name: string;
    program_id: string;
    website?: string;
    github?: string;
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
