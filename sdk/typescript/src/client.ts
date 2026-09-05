import type { VerificationInput, VerificationResult, ProtocolManifest } from "./types.js";

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

/**
 * Minimal runtime shape guard for a VerificationResult (GAP-2026-08-06-8).
 *
 * The wire format is the only untrusted input the SDK consumes — a truncated,
 * hostile, or mis-shaped payload must fail loudly here instead of flowing
 * through typed as a `VerificationResult` (which would let e.g. a flipped
 * `approved` or a missing `audit_trail_id` reach caller logic silently). This
 * is defense-in-depth, not a substitute for TLS: transport-level integrity
 * still belongs to the deployment (see README trust-boundary notes).
 *
 * Returns a description of the first violation, or null when the shape is
 * structurally valid.
 */
export function validateVerificationResult(value: unknown): string | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return "verification result must be a JSON object";
  }
  const v = value as Record<string, unknown>;
  if (typeof v.approved !== "boolean") return "`approved` must be a boolean";
  if (typeof v.confidence !== "number" || !Number.isFinite(v.confidence)) {
    return "`confidence` must be a finite number";
  }
  if (typeof v.audit_trail_id !== "string" || v.audit_trail_id.length === 0) {
    return "`audit_trail_id` must be a non-empty string";
  }
  if (typeof v.content_hash !== "string" || v.content_hash.length === 0) {
    return "`content_hash` must be a non-empty string";
  }
  const riskVerdict = v.risk_verdict;
  if (
    typeof riskVerdict !== "object" ||
    riskVerdict === null ||
    typeof (riskVerdict as { status?: unknown }).status !== "string"
  ) {
    return "`risk_verdict.status` must be a string";
  }
  if (v.layers !== undefined) {
    if (!Array.isArray(v.layers)) return "`layers` must be an array";
    for (const layer of v.layers) {
      if (typeof layer?.layer !== "string" || typeof layer?.passed !== "boolean") {
        return "each layer must carry `layer` (string) and `passed` (boolean)";
      }
    }
  }
  return null;
}

export class GraphiteClient {
  private baseUrl: string;
  private apiKey?: string;
  private timeoutMs: number;

  constructor(options: GraphiteClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.apiKey = options.apiKey?.trim() || undefined;
    this.timeoutMs = options.timeoutMs ?? 30_000;
  }

  /** AbortSignal enforcing the configured timeout (undefined when disabled). */
  private signal(): AbortSignal | undefined {
    return this.timeoutMs > 0 ? AbortSignal.timeout(this.timeoutMs) : undefined;
  }

  private headers(extra?: Record<string, string>): Record<string, string> {
    const headers: Record<string, string> = { ...extra };
    if (this.apiKey) {
      headers["authorization"] = `Bearer ${this.apiKey}`;
    }
    return headers;
  }

  async verify(input: VerificationInput): Promise<VerificationResult> {
    const response = await fetch(`${this.baseUrl}/verify`, {
      method: "POST",
      headers: this.headers({ "content-type": "application/json" }),
      body: JSON.stringify(input),
      signal: this.signal(),
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

  async health(): Promise<{ status: string; service: string; version: string }> {
    const response = await fetch(`${this.baseUrl}/health`, { signal: this.signal() });
    if (!response.ok) throw new Error(`Health check failed: ${response.status}`);
    return (await response.json()) as { status: string; service: string; version: string };
  }

  async listManifests(): Promise<ProtocolManifest[]> {
    const response = await fetch(`${this.baseUrl}/manifests`, {
      headers: this.headers(),
      signal: this.signal(),
    });
    if (!response.ok) throw new Error(`Failed to list manifests: ${response.status}`);
    return (await response.json()) as ProtocolManifest[];
  }
}
