import type { VerificationInput, VerificationResult, ProtocolManifest } from "./types.js";

export interface GraphiteClientOptions {
  baseUrl: string;
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

  constructor(options: GraphiteClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
  }

  async verify(input: VerificationInput): Promise<VerificationResult> {
    const response = await fetch(`${this.baseUrl}/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
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

  async health(): Promise<{ status: string; service: string; version: string }> {
    const response = await fetch(`${this.baseUrl}/health`);
    if (!response.ok) throw new Error(`Health check failed: ${response.status}`);
    return (await response.json()) as { status: string; service: string; version: string };
  }

  async listManifests(): Promise<ProtocolManifest[]> {
    const response = await fetch(`${this.baseUrl}/manifests`);
    if (!response.ok) throw new Error(`Failed to list manifests: ${response.status}`);
    return (await response.json()) as ProtocolManifest[];
  }
}
