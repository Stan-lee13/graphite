// Typed client for the Graphite Core read-only dashboard API (Constitution
// P4 — these endpoints never mutate server state).

export interface GraphNode {
  program_id: string;
  name: string;
  manifest_version: string | null;
  trust_tier: string;
  instruction_count: number;
  baseline_samples: number | null;
  battle_tested_tx_count: number;
  community_verified_count: number;
  quarantined: boolean;
  quarantine_reason: string | null;
  cpi_targets: string[];
}

export interface GraphEdge {
  from: string;
  to: string;
}

export interface GraphSnapshot {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface ConfidencePoint {
  timestamp: string;
  confidence: number;
  approved: boolean;
  program_id: string;
  audit_trail_id: string;
}

export interface ConfidenceHistory {
  series: ConfidencePoint[];
  count: number;
}

export interface PolicyViolation {
  timestamp: string;
  program_id: string;
  protocol_name: string;
  instruction_name: string;
  confidence: number;
  policy_verdict: string;
  risk_status: string;
  audit_trail_id: string;
}

export interface ErrorViolation {
  timestamp: string;
  program_id: string;
  instruction_name: string;
  error: string;
  error_type: string;
  status: number;
}

export interface PolicyViolations {
  violations: PolicyViolation[];
  error_violations: ErrorViolation[];
  count: number;
}

export interface TopProtocol {
  program_id: string;
  name: string;
  trust_tier: string;
  battle_tested_tx_count: number;
  observed_verifications: number;
  quarantined: boolean;
}

export interface TopProtocols {
  top: TopProtocol[];
}

export interface RegistryRecord {
  program_id: string;
  version_label: string;
  previous_version_ref: string | null;
  content_hash: string;
  trust_tier: string;
  source: string;
}

export interface RegistryReviewer {
  pubkey: string;
  reputation_score: number;
}

export interface RegistryState {
  records: RegistryRecord[];
  reviewers: RegistryReviewer[];
  record_count: number;
}

/** Base URL for the Core API. Defaults to same-origin /api; override with
 *  VITE_GRAPHITE_API (e.g. "http://localhost:7331/api"). */
const API_BASE: string =
  (import.meta.env.VITE_GRAPHITE_API as string | undefined)?.replace(/\/$/, "") ??
  "/api";

/**
 * Bearer API key for a secured Core (GRAPHITE_API_KEY). All /api/* routes
 * require it when the server runs with a key. Stored in localStorage so the
 * operator enters it once; never logged. An empty key (dev Core) sends no
 * Authorization header.
 */
const KEY_STORAGE = "graphite_api_key";
let apiKey: string = localStorage.getItem(KEY_STORAGE) ?? "";

/** Update the Bearer key used for subsequent requests (persisted). */
export function setApiKey(key: string): void {
  apiKey = key.trim();
  if (apiKey) localStorage.setItem(KEY_STORAGE, apiKey);
  else localStorage.removeItem(KEY_STORAGE);
}

async function get<T>(path: string): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (apiKey) headers["Authorization"] = `Bearer ${apiKey}`;
  const resp = await fetch(`${API_BASE}${path}`, { headers });
  if (!resp.ok) {
    throw new Error(`GET ${path} failed: HTTP ${resp.status} ${resp.statusText}`);
  }
  return (await resp.json()) as T;
}

export const api = {
  graph: () => get<GraphSnapshot>("/graph"),
  confidenceHistory: () => get<ConfidenceHistory>("/confidence-history"),
  policyViolations: () => get<PolicyViolations>("/policy-violations"),
  topProtocols: () => get<TopProtocols>("/protocols/top"),
  registry: () => get<RegistryState>("/registry"),
};
