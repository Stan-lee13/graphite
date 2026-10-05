/**
 * What a fund-moving tool reports back to the model that called it — shared
 * by every framework adapter (Vercel AI SDK tools, MCP server), so the same
 * outcome reads the same way whichever framework the agent runs in.
 *
 * Structured, never an exception the model has to interpret: a refusal says
 * who refused (the operator's spend policy, the grounding of the request in
 * its own words, a person who declined, or Graphite) and why.
 */
import type { ExecutionOutcome } from "./guard.js";
import { IntentGroundingError } from "./intent-grounding.js";
import { ResidualPolicyRefusal } from "./residual-policy.js";
import { SpendPolicyRefusal } from "./spend-policy.js";

export interface GraphiteToolResult {
  executed: boolean;
  /** Who stopped it, when it did not execute. */
  refusedBy?: "spend-policy" | "request-grounding" | "residual-policy" | "person" | "graphite" | "error";
  reason?: string;
  /** The transaction id, when it executed. */
  signature?: string;
  /** Whether the RPC confirmed it inside its blockhash window. */
  confirmed?: boolean;
  /** What Graphite did not observe that this deployment accepted, when it executed. */
  acceptedUnobserved?: string[];
  /** Graphite's verdict, when the Core was asked. */
  verdict?: {
    approved: boolean;
    risk: string;
    findings: { pattern: string; reason: string }[];
    auditTrailId: string;
    /**
     * `artifact_bound`: the verdict is about these exact bytes, whose digest is
     * `transactionSha256`; `descriptive`: it is about what the request said.
     * W22 (external review): the tool result used to leave this out.
     */
    scope: "artifact_bound" | "descriptive" | "unscoped";
    transactionSha256?: string;
    /** What Graphite did not observe (codes), as the verdict reports it. */
    unobservedCodes: string[];
    /** The manifest version the verdict was judged against, when one was. */
    manifestVersion?: string;
  };
}

/** The outcome of a guard execution, as a tool result. */
export function toolResultOf(outcome: ExecutionOutcome): GraphiteToolResult {
  const v = outcome.verification;
  const scope = v.scope;
  const verdict: NonNullable<GraphiteToolResult["verdict"]> = {
    approved: v.approved,
    risk: v.risk_verdict.status,
    findings: v.risk_verdict.findings.map((f) => ({ pattern: f.pattern, reason: f.reason })),
    auditTrailId: v.audit_trail_id,
    scope: scope?.kind ?? "unscoped",
    ...(scope?.kind === "artifact_bound" ? { transactionSha256: scope.transaction_sha256 } : {}),
    unobservedCodes: [...(scope?.unobserved_codes ?? [])],
    ...(v.manifest_version ? { manifestVersion: v.manifest_version } : {}),
  };
  if (!outcome.verifiedExecution) {
    return { executed: false, refusedBy: "graphite", reason: v.summary, verdict };
  }
  return {
    executed: true,
    signature: outcome.signature,
    confirmed: outcome.lifecycle?.confirmed,
    acceptedUnobserved: [...(outcome.lifecycle?.acceptedUnobserved ?? [])],
    verdict,
  };
}

/** A refusal raised before or instead of an execution, as a tool result. */
export function toolRefusalOf(e: unknown): GraphiteToolResult {
  const reason = e instanceof Error ? e.message : String(e);
  if (e instanceof SpendPolicyRefusal) return { executed: false, refusedBy: "spend-policy", reason };
  if (e instanceof IntentGroundingError) return { executed: false, refusedBy: "request-grounding", reason };
  if (e instanceof ResidualPolicyRefusal) return { executed: false, refusedBy: "residual-policy", reason };
  return { executed: false, refusedBy: "error", reason };
}
