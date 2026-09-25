// Typed client for the Graphite Core's read-only surface (Constitution P4:
// nothing here mutates server state).
//
// Where the Core lives and which key unlocks it are decided at runtime, not at
// build time: the console is a static bundle that any operator can point at
// their own Core from the Connect screen. Both settings live in this
// browser's localStorage and nowhere else — never in a URL, never in a log.

import { insecureBaseReason } from "./transport";

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

export interface ManifestAccount {
  name: string;
  role: "signer" | "writable" | "readonly" | "pda" | string;
  is_writable: boolean;
  is_signer: boolean;
  pda_seeds: unknown[];
  expected_address: string[];
}

export interface ManifestInstruction {
  name: string;
  discriminator: string;
  accounts: ManifestAccount[];
  expected_state_changes: string[];
  allowed_cpis: string[];
  risk_rules: string[];
  variable_accounts: boolean;
  risk_class: string;
}

export interface Manifest {
  graphite_manifest_version: string;
  protocol: {
    name: string;
    program_id: string;
    website: string;
    github: string;
    category: string;
  };
  version: {
    label: string;
    effective_from_slot: number;
    previous_version_ref: string | null;
  };
  trust_tier: string;
  instructions: ManifestInstruction[];
}

export interface Health {
  status: string;
  service: string;
  version: string;
  degraded?: boolean;
  degraded_reasons?: string[];
  inclusion_witness?: boolean;
  audit?: {
    enabled: boolean;
    writes_ok?: number;
    writes_failed?: number;
    active_bytes?: number;
    archive_count?: number;
    rotations_ok?: number;
    rotations_failed?: number;
  };
  graph_persistence?: {
    enabled: boolean;
    snapshots_ok?: number;
    snapshots_failed?: number;
    last_error?: string | null;
  };
}

/** Prometheus counters and gauges, by metric name. */
export type Metrics = Map<string, number>;

// ---------------------------------------------------------------------------
// Connection settings

export interface Connection {
  /** Origin of the Core, e.g. `http://127.0.0.1:7331`. Empty means same
   *  origin (the dev proxy, or a Core serving the built console itself). */
  base: string;
  /** The operator key (`GRAPHITE_API_KEY`). Empty for a dev-mode Core. */
  key: string;
}

const BASE_STORAGE = "graphite.core";
const KEY_STORAGE = "graphite.key";

/** The shortest key the Core will start with; mirrors `MIN_API_KEY_CHARS`. */
export const MIN_KEY_CHARS = 32;

const buildDefault = (import.meta.env.VITE_GRAPHITE_API as string | undefined) ?? "";

function read(k: string): string | null {
  try {
    return localStorage.getItem(k);
  } catch {
    return null;
  }
}
function write(k: string, v: string): void {
  try {
    if (v) localStorage.setItem(k, v);
    else localStorage.removeItem(k);
  } catch {
    /* private mode or blocked storage: the setting lives for this page only */
  }
}

let connection: Connection = {
  base: normaliseBase(read(BASE_STORAGE) ?? buildDefault),
  key: read(KEY_STORAGE) ?? "",
};

const listeners = new Set<() => void>();

export function getConnection(): Connection {
  return connection;
}

export function setConnection(next: Connection): void {
  connection = { base: normaliseBase(next.base), key: next.key.trim() };
  write(BASE_STORAGE, connection.base);
  write(KEY_STORAGE, connection.key);
  for (const l of listeners) l();
}

export function onConnectionChange(l: () => void): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}

/** Trim, drop a trailing slash and a trailing `/api` so either form works. */
export function normaliseBase(raw: string): string {
  let b = raw.trim().replace(/\/+$/, "");
  if (b.endsWith("/api")) b = b.slice(0, -4);
  return b;
}

// ---------------------------------------------------------------------------
// Errors that the interface can act on

export type ApiErrorKind =
  | "unauthorized" // 401: no key, or the wrong key
  | "ratelimited" // 429
  | "unavailable" // 503: the Core is shedding load
  | "server" // any other non-2xx from the Core
  | "network" // no response at all: down, wrong URL, or CORS refused
  | "insecure"; // refused before sending: plain http:// to a non-loopback host

export class ApiError extends Error {
  constructor(
    public readonly kind: ApiErrorKind,
    public readonly path: string,
    public readonly status?: number,
    detail?: string,
  ) {
    super(detail ?? describe(kind, path, status));
    this.name = "ApiError";
  }
}

function describe(kind: ApiErrorKind, path: string, status?: number): string {
  switch (kind) {
    case "unauthorized":
      return "The Core rejected the API key.";
    case "ratelimited":
      return "The Core is rate limiting this browser.";
    case "unavailable":
      return "The Core is at its in-flight limit and shed the request.";
    case "server":
      return `The Core answered ${status ?? "an error"} for ${path}.`;
    case "network":
      return "No response from the Core.";
    case "insecure":
      return "The console refused to send the key over plain http:// to another machine.";
  }
}

export function toApiError(e: unknown, path: string): ApiError {
  if (e instanceof ApiError) return e;
  return new ApiError("network", path);
}

function authHeaders(key: string): Record<string, string> {
  const h: Record<string, string> = { Accept: "application/json" };
  if (key) h["Authorization"] = `Bearer ${key}`;
  return h;
}

async function request(path: string, conn: Connection = connection): Promise<Response> {
  // Round 19 (F-19-C6): checked on every request, before `fetch`, so the key
  // never leaves over cleartext to another machine — see transport.ts.
  const insecure = insecureBaseReason(conn.base, window.location.origin);
  if (insecure !== null) throw new ApiError("insecure", path, undefined, insecure);
  let resp: Response;
  try {
    resp = await fetch(`${conn.base}${path}`, { headers: authHeaders(conn.key) });
  } catch {
    throw new ApiError("network", path);
  }
  if (resp.ok) return resp;
  if (resp.status === 401) throw new ApiError("unauthorized", path, 401);
  if (resp.status === 429) throw new ApiError("ratelimited", path, 429);
  if (resp.status === 503) throw new ApiError("unavailable", path, 503);
  throw new ApiError("server", path, resp.status);
}

async function getJson<T>(path: string): Promise<T> {
  const resp = await request(path);
  return (await resp.json()) as T;
}

/** Parse the Prometheus text exposition into name → value. */
export function parseMetrics(text: string): Metrics {
  const out: Metrics = new Map();
  for (const line of text.split("\n")) {
    if (!line || line.startsWith("#")) continue;
    const sp = line.lastIndexOf(" ");
    if (sp < 0) continue;
    const name = line.slice(0, sp).replace(/\{.*\}$/, "");
    const v = Number(line.slice(sp + 1));
    if (Number.isFinite(v)) out.set(name, (out.get(name) ?? 0) + v);
  }
  return out;
}

/** Oldest first, ties broken by audit ID so the order is total and stable.
 *  The Core returns the trail newest-first; every view here reads it as a
 *  timeline, so the client settles the order once. */
function chronological(h: ConfidenceHistory): ConfidenceHistory {
  const series = [...h.series].sort(
    (a, b) => a.timestamp.localeCompare(b.timestamp) || a.audit_trail_id.localeCompare(b.audit_trail_id),
  );
  return { ...h, series };
}

export const api = {
  health: () => getJson<Health>("/health"),
  graph: () => getJson<GraphSnapshot>("/api/graph"),
  confidenceHistory: () => getJson<ConfidenceHistory>("/api/confidence-history").then(chronological),
  policyViolations: () => getJson<PolicyViolations>("/api/policy-violations"),
  topProtocols: () => getJson<TopProtocols>("/api/protocols/top"),
  registry: () => getJson<RegistryState>("/api/registry"),
  manifests: () => getJson<Manifest[]>("/manifests"),
  metrics: async () => parseMetrics(await (await request("/metrics")).text()),
};

// ---------------------------------------------------------------------------
// Connection test, for the Connect screen

export interface ConnectionReport {
  /** `/health` answered (it needs no key). */
  reachable: boolean;
  version?: string;
  degraded?: boolean;
  /** An authenticated route answered 200 with the given key. */
  authorized: boolean;
  /** What went wrong, per step, in words the operator can act on. */
  reachError?: ApiError;
  authError?: ApiError;
}

/**
 * Two probes, in order. `/health` proves the URL is a Core and that the
 * browser is allowed to talk to it (CORS). `/api/protocols/top` is the
 * cheapest key-guarded route, so its status is the verdict on the key.
 */
export async function testConnection(conn: Connection): Promise<ConnectionReport> {
  const c = { base: normaliseBase(conn.base), key: conn.key.trim() };
  const report: ConnectionReport = { reachable: false, authorized: false };
  try {
    const h = (await (await request("/health", { ...c, key: "" })).json()) as Health;
    report.reachable = true;
    report.version = h.version;
    report.degraded = h.degraded === true;
  } catch (e) {
    report.reachError = toApiError(e, "/health");
    return report;
  }
  try {
    await request("/api/protocols/top", c);
    report.authorized = true;
  } catch (e) {
    report.authError = toApiError(e, "/api/protocols/top");
  }
  return report;
}
