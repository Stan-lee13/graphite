/**
 * Graphite × Solana Agent Kit — Integration Adapter
 *
 * Exports the core adapter that wraps Graphite verification around
 * Solana Agent Kit execution. Any agent using SAK can gate transactions
 * through Graphite with a single import.
 *
 * Constitution P1: Graphite Core (Rust) makes all security decisions.
 * This adapter only forwards data and enforces the verdict — it never
 * overrides a BLOCKED result.
 *
 * @example
 * ```ts
 * import { GraphiteVerifiedAgent } from "@graphite/solana-agent-kit-integration";
 *
 * const agent = new GraphiteVerifiedAgent({ coreUrl: "http://localhost:7331" });
 * const result = await agent.verify({
 *   intent: "Swap 0.5 SOL for USDC",
 *   programId: "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
 *   accounts: [...],
 *   cpiTargets: [...],
 * });
 * if (result.approved) {
 *   // Safe to execute via SAK
 * } else {
 *   // Agent REFUSES — Graphite blocked this transaction
 * }
 * ```
 */

// ─── Types (mirrored from Graphite TypeScript SDK) ───────────────

export interface ProposedIntent {
  intent_type: string;
  raw_natural_language: string;
  confidence_of_parse: number;
  extracted_parameters?: {
    input_token?: string;
    output_token?: string;
    amount?: string;
    slippage_bps?: number;
  };
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
  protocol_version: string;
  instruction_discriminator: string;
  account_addresses: string[];
  instruction_data?: number[];
  cpi_targets: string[];
  wallet_profile: string;
  behavior_evidence: BehaviorEvidence;
  compute_units: number;
  account_writes: number;
  cpi_hops: number;
}

export interface RiskFinding {
  pattern: string;
  reason: string;
}

export interface VerificationResult {
  approved: boolean;
  confidence: number;
  breakdown: Array<{ kind: string; raw_value: number; weight: number; contribution: number }>;
  trust_tier: string;
  risk_verdict: { status: string; findings: RiskFinding[] };
  policy_verdict: string;
  audit_trail_id: string;
  protocol_name: string;
  instruction_name: string;
  manifest_found: boolean;
  unknown_protocol: boolean;
  summary: string;
  simulation_flagged?: boolean | null;
}

// ─── Adapter ─────────────────────────────────────────────────────

export interface GraphiteConfig {
  coreUrl?: string;
  aiLayerUrl?: string;
  walletProfile?: string;
  defaultBehaviorEvidence?: Partial<BehaviorEvidence>;
}

export class GraphiteVerifiedAgent {
  private coreUrl: string;
  private aiLayerUrl: string;
  private walletProfile: string;
  private defaultEvidence: BehaviorEvidence;

  constructor(config: GraphiteConfig = {}) {
    this.coreUrl = config.coreUrl || process.env.GRAPHITE_CORE_URL || "http://localhost:7331";
    this.aiLayerUrl = config.aiLayerUrl || process.env.GRAPHITE_AI_URL || "http://localhost:8081";
    this.walletProfile = config.walletProfile || "Standard";
    this.defaultEvidence = {
      has_signed_manifest: false,
      community_verified_count: 0,
      battle_tested_tx_count: 0,
      simulation_match_count: 0,
      ...config.defaultBehaviorEvidence,
    };
  }

  /** Parse natural language intent via the AI Layer (advisory only, P1). */
  async parseIntent(text: string): Promise<ProposedIntent & { suggested_program_id: string; suggested_discriminator: string }> {
    const res = await fetch(`${this.aiLayerUrl}/parse`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text }),
    });
    if (!res.ok) throw new Error(`AI Layer error ${res.status}: ${await res.text()}`);
    return res.json() as Promise<ProposedIntent & { suggested_program_id: string; suggested_discriminator: string }>;
  }

  /** Verify a transaction against Graphite Core. Returns the verdict — never throws on BLOCKED. */
  async verify(input: VerificationInput): Promise<VerificationResult> {
    const res = await fetch(`${this.coreUrl}/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(input),
    });
    if (!res.ok) {
      const err = (await res.json().catch(() => ({ error: "unknown" }))) as { error?: string };
      // Fail-closed: return a blocked result on HTTP error
      return {
        approved: false,
        confidence: 0,
        breakdown: [],
        trust_tier: "Unknown",
        risk_verdict: { status: "Blocked", findings: [{ pattern: "VerificationError", reason: err.error || `HTTP ${res.status}` }] },
        policy_verdict: "Blocked",
        audit_trail_id: "",
        protocol_name: "",
        instruction_name: "",
        manifest_found: false,
        unknown_protocol: true,
        summary: "Graphite Core returned an error — transaction blocked (fail-closed, P12).",
      };
    }
    return res.json() as Promise<VerificationResult>;
  }

  /** Check if the Graphite Core server is healthy. */
  async healthCheck(): Promise<boolean> {
    try {
      const res = await fetch(`${this.coreUrl}/health`);
      return res.ok;
    } catch {
      return false;
    }
  }

  /** Get available protocol manifests from Graphite Core. */
  async listManifests(): Promise<unknown[]> {
    const res = await fetch(`${this.coreUrl}/manifests`);
    if (!res.ok) throw new Error(`Failed to fetch manifests: ${res.status}`);
    return res.json() as Promise<unknown[]>;
  }
}

// ─── Convenience: build verification input ─────────────────────────

export function buildVerificationInput(
  intent: ProposedIntent & { suggested_program_id: string; suggested_discriminator: string },
  accounts: string[],
  cpiTargets: string[],
  options?: {
    walletProfile?: string;
    behaviorEvidence?: Partial<BehaviorEvidence>;
    computeUnits?: number;
    accountWrites?: number;
  }
): VerificationInput {
  return {
    proposed_intent: intent,
    program_id: intent.suggested_program_id,
    protocol_version: "1.0.0",
    instruction_discriminator: intent.suggested_discriminator,
    account_addresses: accounts,
    cpi_targets: cpiTargets,
    wallet_profile: options?.walletProfile || "Standard",
    behavior_evidence: {
      has_signed_manifest: false,
      community_verified_count: 5,
      battle_tested_tx_count: 50000,
      simulation_match_count: 100,
      ...options?.behaviorEvidence,
    },
    compute_units: options?.computeUnits || 200000,
    account_writes: options?.accountWrites || 3,
    cpi_hops: cpiTargets.length,
  };
}

// ─── Known program IDs (convenience export) ───────────────────────

export const PROGRAMS = {
  SYSTEM: "11111111111111111111111111111111",
  SPL_TOKEN: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
  JUPITER_V6: "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
  RAYDIUM_V4: "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8",
  STAKE: "Stake11111111111111111111111111111111111111",
} as const;
