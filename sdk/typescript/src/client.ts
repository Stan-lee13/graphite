import type {
  ExecutionCheckInput,
  ExecutionCheckResult,
  LifecycleEventInput,
  LifecycleEventReceipt,
  ProtocolManifest,
  VerificationInput,
  VerificationResult,
} from "./types.js";
import { UNOBSERVED_CODES } from "./types.js";

export interface GraphiteClientOptions {
  baseUrl: string;
  /**
   * Bearer API key for a secured Core server (GRAPHITE_API_KEY). When set,
   * every authenticated request sends `Authorization: Bearer <apiKey>`. The
   * `/health` endpoint stays open by design. Optional — a keyless dev Core
   * works without it.
   */
  apiKey?: string;
  /**
   * Request timeout in milliseconds (default 30000).
   *
   * A hung Core — a stalled TLS proxy, a slow disk on the audit-write path,
   * an overloaded RPC provider on the L3 path — would otherwise leave
   * `verify()` pending forever. That is not itself fail-open, but it pushes
   * callers into hand-rolling `Promise.race([verify(), timeout()])`, and the
   * timeout branch of such a race is very easy to resolve as "proceed"
   * instead of "abort".
   *
   * A timeout means VERIFICATION DID NOT HAPPEN. Treat it as a hard stop —
   * never as an implicit pass. Set to 0 to disable (not recommended).
   */
  timeoutMs?: number;
}

const TRUST_TIERS: ReadonlySet<string> = new Set([
  "Unknown",
  "HeuristicInferred",
  "OfficialManifest",
  "SimulationValidated",
  "CommunityVerified",
  "BattleTested",
]);

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((s) => typeof s === "string");
}

/**
 * The scope's shape, as `schemas/verification-result-v1.json` states it: the
 * field an execution gate decides on (artifact_bound or not, and what was not
 * observed). A scope that claims `artifact_bound` without the digest of what
 * it bound is not a binding.
 */
function scopeViolation(scope: unknown): string | null {
  if (typeof scope !== "object" || scope === null || Array.isArray(scope)) {
    return "`scope` must be an object";
  }
  const s = scope as Record<string, unknown>;
  if (s.kind !== "artifact_bound" && s.kind !== "descriptive") {
    return "`scope.kind` must be \"artifact_bound\" or \"descriptive\"";
  }
  if (!isStringArray(s.unobserved) || s.unobserved.length === 0) {
    return "`scope.unobserved` must be a non-empty array of strings";
  }
  if (s.unobserved_codes !== undefined) {
    if (!isStringArray(s.unobserved_codes)) return "`scope.unobserved_codes` must be an array of strings";
    const unknown = s.unobserved_codes.find((c) => !(UNOBSERVED_CODES as readonly string[]).includes(c));
    if (unknown !== undefined) return `\`scope.unobserved_codes\` has an unknown code ${JSON.stringify(unknown)}`;
    if (s.unobserved_codes.length !== s.unobserved.length) {
      return "`scope.unobserved_codes` must name each entry of `scope.unobserved`";
    }
  }
  if (s.kind === "artifact_bound") {
    if (typeof s.transaction_sha256 !== "string" || !/^[0-9a-f]{64}$/.test(s.transaction_sha256)) {
      return "`scope.transaction_sha256` must be 64 lowercase hex characters";
    }
    if (!Number.isSafeInteger(s.transaction_bytes) || (s.transaction_bytes as number) < 1) {
      return "`scope.transaction_bytes` must be a positive integer";
    }
    if (typeof s.simulated !== "boolean") return "`scope.simulated` must be a boolean";
  }
  return null;
}

/**
 * Runtime shape guard for a VerificationResult (GAP-2026-08-06-8; deepened in
 * Round 24, W22).
 *
 * The wire format is the only untrusted input the SDK consumes — a truncated,
 * hostile, or mis-shaped payload must fail loudly here instead of flowing
 * through typed as a `VerificationResult`. Every field a caller decides on is
 * checked against `schemas/verification-result-v1.json`: the verdict, its
 * confidence, its risk verdict and findings, its trust tier, its layers, and
 * its scope (what the approval is bound to and what was not observed). A
 * verdict that contradicts itself — approved while the risk verdict is
 * Blocked — is refused. This is defense-in-depth, not a substitute for TLS:
 * transport-level integrity still belongs to the deployment (see README
 * trust-boundary notes).
 *
 * Returns a description of the first violation, or null when the shape is
 * valid.
 */
export function validateVerificationResult(value: unknown): string | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return "verification result must be a JSON object";
  }
  const v = value as Record<string, unknown>;
  if (typeof v.approved !== "boolean") return "`approved` must be a boolean";
  if (typeof v.confidence !== "number" || !Number.isFinite(v.confidence) || v.confidence < 0 || v.confidence > 1) {
    return "`confidence` must be a finite number in [0, 1]";
  }
  if (typeof v.audit_trail_id !== "string" || v.audit_trail_id.length === 0) {
    return "`audit_trail_id` must be a non-empty string";
  }
  if (typeof v.content_hash !== "string" || v.content_hash.length === 0) {
    return "`content_hash` must be a non-empty string";
  }
  const riskVerdict = v.risk_verdict;
  if (typeof riskVerdict !== "object" || riskVerdict === null || Array.isArray(riskVerdict)) {
    return "`risk_verdict` must be an object";
  }
  const risk = riskVerdict as Record<string, unknown>;
  if (risk.status !== "Clear" && risk.status !== "Blocked") {
    return "`risk_verdict.status` must be \"Clear\" or \"Blocked\"";
  }
  if (
    !Array.isArray(risk.findings) ||
    !risk.findings.every(
      (f) => typeof f === "object" && f !== null && typeof f.pattern === "string" && typeof f.reason === "string",
    )
  ) {
    return "`risk_verdict.findings` must be an array of { pattern, reason } strings";
  }
  if (v.approved && risk.status !== "Clear") {
    return "an approved verdict must have a Clear risk verdict";
  }
  if (v.trust_tier !== undefined && (typeof v.trust_tier !== "string" || !TRUST_TIERS.has(v.trust_tier))) {
    return "`trust_tier` must be one of the schema's tiers";
  }
  if (v.layers !== undefined) {
    if (!Array.isArray(v.layers)) return "`layers` must be an array";
    for (const layer of v.layers) {
      if (typeof layer?.layer !== "string" || typeof layer?.passed !== "boolean" || typeof layer?.reason !== "string") {
        return "each layer must carry `layer` (string), `passed` (boolean) and `reason` (string)";
      }
    }
  }
  if (v.scope !== undefined) {
    const violation = scopeViolation(v.scope);
    if (violation !== null) return violation;
  }
  return null;
}

/**
 * Whether a URL hostname is the local machine: `localhost`, 127.0.0.0/8, or
 * `::1`. The WHATWG URL parser has already canonicalised the host (`127.1`
 * and `0x7f.0.0.1` both arrive as `127.0.0.1`; IPv6 arrives bracketed), so
 * this compares canonical forms only.
 */
export function isLoopbackHost(hostname: string): boolean {
  const h = hostname.toLowerCase();
  if (h === "localhost" || h === "[::1]" || h === "::1") return true;
  const m = /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  return m !== null && m.slice(1).every((o) => Number(o) <= 255);
}

/**
 * Refuse a Core base URL that would carry the API key, or a verdict, in
 * cleartext across a network.
 *
 * Round 19 (F-19-C6): the client accepted any `http://` URL and sent
 * `Authorization: Bearer <key>` to it. On anything but the local machine that
 * puts the operator key on the wire in the clear — and lets anyone on the path
 * rewrite `approved: false` into `approved: true`, which no amount of
 * client-side shape checking can detect. `https://` is always accepted;
 * `http://` only for a loopback host (a local dev Core, a test harness).
 * Throws with the reason; returns the URL without a trailing slash.
 */
export function assertSecureBaseUrl(baseUrl: string): string {
  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch {
    throw new Error(`Graphite base URL ${JSON.stringify(baseUrl)} is not a valid URL`);
  }
  if (url.protocol === "https:") return baseUrl.replace(/\/$/, "");
  if (url.protocol === "http:") {
    if (isLoopbackHost(url.hostname)) return baseUrl.replace(/\/$/, "");
    throw new Error(
      `Graphite base URL ${url.origin} is plain http:// to a non-loopback host. The API key ` +
        "and every verdict would cross the network unencrypted, where a verdict can be rewritten " +
        "in flight. Use https://, or http:// only to localhost / 127.0.0.0/8 / [::1] " +
        "(Round 19, F-19-C6).",
    );
  }
  throw new Error(`Graphite base URL must be https:// (or http:// to loopback), got ${url.protocol}`);
}

export class GraphiteClient {
  private baseUrl: string;
  private apiKey?: string;
  private timeoutMs: number;

  constructor(options: GraphiteClientOptions) {
    // Refused at construction, before any request can carry the key.
    this.baseUrl = assertSecureBaseUrl(options.baseUrl);
    this.apiKey = options.apiKey?.trim() || undefined;
    this.timeoutMs = options.timeoutMs ?? 30_000;
  }

  /** AbortSignal enforcing the configured timeout (undefined when disabled). */
  private signal(): AbortSignal | undefined {
    return this.timeoutMs > 0 ? AbortSignal.timeout(this.timeoutMs) : undefined;
  }

  /**
   * Every request goes through here: the configured timeout, and no redirects.
   *
   * A5-04 (2026-09-29 audit): `fetch` follows redirects by default, and
   * `assertSecureBaseUrl` checks only the configured base URL. A Core or a
   * proxy answering 307 to an http:// URL took the request — body included —
   * to a location the transport rule never saw, and the verdict that came
   * back from it was accepted. `redirect: "error"` makes any redirect a failed
   * request; the target is never contacted.
   */
  private async send(path: string, init: RequestInit = {}): Promise<Response> {
    try {
      return await fetch(`${this.baseUrl}${path}`, { ...init, redirect: "error", signal: this.signal() });
    } catch (e) {
      const cause = (e as { cause?: { message?: unknown } }).cause;
      if (typeof cause?.message === "string" && /redirect/i.test(cause.message)) {
        throw new Error(
          `Graphite ${path} answered with a redirect; redirects are refused, because the new ` +
            "location has not passed the base-URL transport check (A5-04)",
        );
      }
      throw e;
    }
  }

  private headers(extra?: Record<string, string>): Record<string, string> {
    const headers: Record<string, string> = { ...extra };
    if (this.apiKey) {
      headers["authorization"] = `Bearer ${this.apiKey}`;
    }
    return headers;
  }

  async verify(input: VerificationInput): Promise<VerificationResult> {
    const response = await this.send("/verify", {
      method: "POST",
      headers: this.headers({ "content-type": "application/json" }),
      body: JSON.stringify(input),
    });

    if (!response.ok) {
      const errorBody = (await response.json().catch(() => ({}))) as { error?: string };
      throw new Error(
        `Graphite verification failed: ${response.status} ${response.statusText} — ${errorBody.error ?? ""}`
      );
    }

    const raw: unknown = await response.json();
    const violation = validateVerificationResult(raw);
    if (violation !== null) {
      throw new Error(
        `Graphite returned a structurally invalid verification result: ${violation}`
      );
    }
    return raw as VerificationResult;
  }

  /**
   * Put a caller-performed lifecycle stage on Graphite's append-only trail
   * (`POST /audit/event`, Constitution P9).
   *
   * Resolves only when the server says `recorded: true`: a 503 means the
   * event was NOT recorded and is thrown, never swallowed, so a caller that
   * is about to submit knows the signing it just performed is not on the
   * trail. The receipt carries `verdict_on_record` — what Graphite's own
   * trail says about the hash — and a caller reporting a signing against a
   * `blocked` verdict has just told Graphite the gate was bypassed.
   */
  async recordLifecycleEvent(event: LifecycleEventInput): Promise<LifecycleEventReceipt> {
    const response = await this.send("/audit/event", {
      method: "POST",
      headers: this.headers({ "content-type": "application/json" }),
      body: JSON.stringify(event),
    });
    const raw = (await response.json().catch(() => ({}))) as Record<string, unknown>;
    if (!response.ok || raw.recorded !== true) {
      throw new Error(
        `Graphite did not record the ${event.event_type} event: ${response.status} ${response.statusText} — ${
          typeof raw.error === "string" ? raw.error : "no detail"
        }`,
      );
    }
    return raw as unknown as LifecycleEventReceipt;
  }

  /**
   * L8: confirm a submitted signature on-chain and reconcile it against the
   * verdict Graphite recorded (`POST /verify/execution`).
   *
   * A 503 (`AuditUnavailable`) still carries the reconciliation in
   * `outcome`; it is thrown here with that detail in the message, because a
   * reconciliation that was not recorded is not one the trail can be
   * audited against.
   */
  async verifyExecution(input: ExecutionCheckInput): Promise<ExecutionCheckResult> {
    const response = await this.send("/verify/execution", {
      method: "POST",
      headers: this.headers({ "content-type": "application/json" }),
      body: JSON.stringify(input),
    });
    const raw = (await response.json().catch(() => ({}))) as Record<string, unknown>;
    if (!response.ok) {
      throw new Error(
        `Graphite execution check failed: ${response.status} ${response.statusText} — ${
          typeof raw.error === "string" ? raw.error : "no detail"
        }${raw.outcome ? ` (outcome: ${JSON.stringify(raw.outcome)})` : ""}`,
      );
    }
    return raw as unknown as ExecutionCheckResult;
  }

  async health(): Promise<{ status: string; service: string; version: string }> {
    const response = await this.send("/health");
    if (!response.ok) throw new Error(`Health check failed: ${response.status}`);
    return (await response.json()) as { status: string; service: string; version: string };
  }

  async listManifests(): Promise<ProtocolManifest[]> {
    const response = await this.send("/manifests", { headers: this.headers() });
    if (!response.ok) throw new Error(`Failed to list manifests: ${response.status}`);
    return (await response.json()) as ProtocolManifest[];
  }
}
