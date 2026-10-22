/**
 * What a fund-moving tool reports back to the model that called it — shared
 * by every framework adapter (Vercel AI SDK tools, MCP server), so the same
 * outcome reads the same way whichever framework the agent runs in.
 *
 * Structured, never an exception the model has to interpret: a refusal says
 * who refused (the operator's spend policy, the grounding of the request in
 * its own words, a person who declined, or Graphite) and why.
 */
import { PriorSubmissionUnresolved, RequestInFlight, type ExecutionOutcome } from "./guard.js";
import { UnsupportedCapability, type UnsupportedCapabilityCode } from "./capabilities.js";
import { ConfirmationDeclined, SubmissionOutcomeUnknown } from "./execution-lifecycle.js";
import { IntentGroundingError } from "./intent-grounding.js";
import { ResidualPolicyRefusal } from "./residual-policy.js";
import { SpendPolicyRefusal } from "./spend-policy.js";
import { SwapRouteRefusal } from "./swap-instructions.js";

export interface GraphiteToolResult {
  executed: boolean;
  /**
   * Who stopped it, when it did not execute. `swap-route`: the route's own
   * data (exact-out, unreadable, or a minimum output below what was
   * simulated, the slippage allowed or the price floor — Round 29, H2).
   * `submission-unknown`: signed and handed to the RPC, outcome unknown —
   * `signature` is set and must be checked before any retry (Round 29, L2).
   */
  refusedBy?:
    | "spend-policy"
    | "request-grounding"
    | "swap-route"
    | "residual-policy"
    | "person"
    | "graphite"
    | "submission-unknown"
    | "duplicate-request"
    | "unsupported"
    | "error";
  /**
   * Round 30: for `unsupported`, which capability (`GUARD_CAPABILITIES`
   * lists every one the guard does not have).
   */
  unsupported?: UnsupportedCapabilityCode;
  /**
   * Round 30: the execution decision the guard acted on, when it executed:
   * `executable_approved`, or `analysis_only` under residuals the operator
   * accepted by name.
   */
  decision?: "executable_approved" | "analysis_only";
  /** Round 30: anomalies seen on the way, e.g. an RPC that named another transaction id. */
  anomalies?: string[];
  reason?: string;
  /** The transaction id, when it executed — or when its submission's outcome is unknown. */
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
  const lc = outcome.lifecycle;
  const anomalies: string[] = [];
  if (lc?.rpcReportedSignature) {
    anomalies.push(`the RPC answered the submission with ${lc.rpcReportedSignature}; the signed bytes carry ${outcome.signature}`);
  }
  if (lc?.reconciliation?.discrepancy) anomalies.push("L8 reported a discrepancy: Graphite's decision did not govern");
  return {
    executed: true,
    signature: outcome.signature,
    confirmed: lc?.confirmed,
    acceptedUnobserved: [...(lc?.acceptedUnobserved ?? [])],
    ...(lc ? { decision: lc.decision } : {}),
    ...(anomalies.length > 0 ? { anomalies } : {}),
    verdict,
  };
}

/** The most of a refusal's text a tool result carries. */
export const MAX_REASON_CHARS = 600;

/**
 * A refusal's text as the model may see it (audit 2026-10-20, Info). The
 * guard's own refusals say which form is accepted and why this request was
 * not — that is meant for the model and the person. But an `error` can carry
 * text from anywhere (a fetch failure naming an RPC URL with its `api-key`,
 * a header echoed by a proxy), and the model reading it is the party a
 * secret must not reach. URLs lose their userinfo, path and query, bearer
 * tokens and key-like assignments are masked, and the length is bounded.
 */
export function redactReason(text: string): string {
  const out = text
    .replace(/\b([a-z][a-z0-9+.-]*):\/\/[^\s"'<>)]+/gi, (m) => {
      try {
        const u = new URL(m);
        return `${u.protocol}//${u.host}`;
      } catch {
        return "<url>";
      }
    })
    .replace(/\b(bearer)\s+[A-Za-z0-9._~+/=-]+/gi, "$1 <redacted>")
    .replace(/\b(api[-_]?key|apikey|token|secret|password|private[-_]?key|authorization)\b(\s*[:=]\s*)("?)[^\s"',;&]+/gi, "$1$2$3<redacted>");
  return out.length > MAX_REASON_CHARS ? `${out.slice(0, MAX_REASON_CHARS)}…` : out;
}

/** A refusal raised before or instead of an execution, as a tool result. */
export function toolRefusalOf(e: unknown): GraphiteToolResult {
  const reason = redactReason(e instanceof Error ? e.message : String(e));
  if (e instanceof SpendPolicyRefusal) return { executed: false, refusedBy: "spend-policy", reason };
  if (e instanceof IntentGroundingError) return { executed: false, refusedBy: "request-grounding", reason };
  if (e instanceof SwapRouteRefusal) return { executed: false, refusedBy: "swap-route", reason };
  if (e instanceof ResidualPolicyRefusal) return { executed: false, refusedBy: "residual-policy", reason };
  if (e instanceof ConfirmationDeclined) return { executed: false, refusedBy: "person", reason };
  if (e instanceof SubmissionOutcomeUnknown) {
    return { executed: false, refusedBy: "submission-unknown", reason, signature: e.signature };
  }
  // Round 30: a repeat refused because an earlier submission of the same
  // request may still land names that submission's signature, like the
  // ambiguous send itself did (it used to be reported as a generic error).
  if (e instanceof PriorSubmissionUnresolved) {
    return { executed: false, refusedBy: "submission-unknown", reason, signature: e.signature };
  }
  if (e instanceof RequestInFlight) return { executed: false, refusedBy: "duplicate-request", reason };
  if (e instanceof UnsupportedCapability) return { executed: false, refusedBy: "unsupported", unsupported: e.code, reason };
  return { executed: false, refusedBy: "error", reason };
}
