// Typed client for the Graphite Core's read-only surface (Constitution P4:
// nothing here mutates server state).
//
// Where the Core lives and which key unlocks it are decided at runtime, not at
// build time: the console is a static bundle that any operator can point at
// their own Core from the Connect screen. Both settings live in this
// browser and nowhere else — never in a URL, never in a log; the key is kept
// for this tab only unless the operator asks for it to be remembered
// (connection.ts).

import { createConnectionStore, normaliseBase, type Connection } from "./connection";
import { originOf } from "./csp";
import {
  ShapeError,
  checkGraph,
  checkHealth,
  checkHistory,
  checkManifests,
  checkRegistry,
  checkTop,
  checkViolations,
} from "./shape";
import { fetchFromCore, insecureBaseReason, ResponseTooLarge, type CoreResponse } from "./transport";

export { normaliseBase, storageGet, storageSet, type Connection } from "./connection";

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
  /**
   * The digest of the bytes the verdict is bound to; null for a descriptive
   * verdict, which is about what the request said (W22, external review: the
   * dashboard showed "approved" either way). Absent from older servers.
   */
  transaction_sha256?: string | null;
  /** The manifest version the verdict was judged against. */
  manifest_version?: string | null;
  /**
   * The Core's execution decision (Round 30 shared contract):
   * "executable_approved" | "analysis_only" | "inconclusive" | "blocked".
   * Only "executable_approved" with `executable: true` permits signing; any
   * other approval is drawn as not executable. Absent from Cores before the
   * contract.
   */
  decision?: string | null;
  executable?: boolean | null;
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
  /** Every refused verification on the trail plus the rejected requests
   *  returned in `error_violations` (server.rs policy_violations_handler). */
  count: number;
  /** Whole-trail totals, when a Core reports them separately. */
  violation_count?: number;
  error_count?: number;
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
  /** How many programs the Core has in all (absent from older Cores). */
  program_count?: number;
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
  /** The account may be omitted (Round 39: drawn as such). */
  optional?: boolean;
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
  /**
   * Whether the Core has an RPC to simulate against; without one every
   * approval is analysis only. Absent from Cores that do not report it, and
   * then drawn as "not reported", never as either answer.
   */
  rpc_attached?: boolean;
  /** Trusted baselines that have refused clean executions (Round 17). */
  frozen_baseline_count?: number;
  /** Programs found redeployed since last seen (R-M1). */
  program_upgrades?: { detected?: number; quarantine_on_upgrade?: boolean };
  audit?: {
    enabled: boolean;
    writes_ok?: number;
    writes_failed?: number;
    active_bytes?: number;
    archive_count?: number;
    rotations_ok?: number;
    rotations_failed?: number;
    /** Round 30 (G-07): what the trail's integrity rests on. */
    integrity?: "tamper_evident" | "corruption_evident";
    chain_head_seq?: number | null;
    anchors_failed?: number;
  };
  /** Round 30 (G-08): whether the witness is another provider, and whether
   *  every L8 conclusion needs it. */
  l8_assurance?: { witness_independent?: boolean | null; high_assurance?: boolean };
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

/** The shortest key the Core will start with; mirrors `MIN_API_KEY_CHARS`. */
export const MIN_KEY_CHARS = 32;

/** The build-time default Core's origin, which the CSP names (csp.ts). */
const BUILD_ORIGIN = originOf(import.meta.env.VITE_GRAPHITE_API as string | undefined);

const store = createConnectionStore({
  local: () => window.localStorage,
  session: () => window.sessionStorage,
  buildDefault: (import.meta.env.VITE_GRAPHITE_API as string | undefined) ?? "",
});

export const getConnection = (): Connection => store.get();

/**
 * Why the console would refuse to use `base`, or null. The Connect screen
 * asks before saving (Round 39, R39-DASH-7): an address the console will
 * never send to is not stored, so a key pasted into the address field is not
 * kept in localStorage or drawn in the sidebar.
 */
export const baseProblem = (base: string): string | null =>
  insecureBaseReason(normaliseBase(base), window.location.origin, BUILD_ORIGIN);
export const setConnection = (next: Connection): void => store.set(next);
export const forgetKey = (): void => store.forgetKey();
export const onConnectionChange = (l: () => void): (() => void) => store.onChange(l);

// ---------------------------------------------------------------------------
// Errors that the interface can act on

export type ApiErrorKind =
  | "unauthorized" // 401: no key, or the wrong key
  | "ratelimited" // 429
  | "unavailable" // 503: the Core is shedding load
  | "server" // any other non-2xx from the Core
  | "network" // no response at all: down, wrong URL, or CORS refused
  | "malformed" // an answer, but not the shape this console reads
  | "insecure";// refused before sending: plain http:// to a non-loopback host

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
    case "malformed":
      return `The Core answered ${path} with something this console cannot read.`;
    case "insecure":
      return "The console refused to send the key over plain http:// to another machine.";
  }
}

export function toApiError(e: unknown, path: string): ApiError {
  if (e instanceof ApiError) return e;
  // Round 30: `request` already turns a failed fetch into "network". Anything
  // else thrown while handling an answer is the answer being unreadable, and
  // used to be reported as "No response from the Core".
  return new ApiError(
    "malformed",
    path,
    undefined,
    `The answer to ${path} could not be read: ${e instanceof Error ? e.message : String(e)}.`,
  );
}

function authHeaders(key: string): Record<string, string> {
  const h: Record<string, string> = { Accept: "application/json" };
  if (key) h["Authorization"] = `Bearer ${key}`;
  return h;
}

async function request(path: string, conn: Connection = getConnection()): Promise<CoreResponse> {
  // Round 19 (F-19-C6): checked on every request, before `fetch`, so the key
  // never leaves over cleartext to another machine — see transport.ts.
  const insecure = insecureBaseReason(conn.base, window.location.origin, BUILD_ORIGIN);
  if (insecure !== null) throw new ApiError("insecure", path, undefined, insecure);
  let resp: CoreResponse;
  try {
    // A5-04: a redirect rejects here and is reported as no response; so does
    // a request that outlives its deadline (Round 29, D3).
    resp = await fetchFromCore(`${conn.base}${path}`, authHeaders(conn.key));
  } catch (e) {
    // Round 38 (G2-6): an answer over the size bound came, and is not read.
    if (e instanceof ResponseTooLarge) throw new ApiError("malformed", path, undefined, e.message);
    throw new ApiError("network", path);
  }
  if (resp.ok) return resp;
  if (resp.status === 401) throw new ApiError("unauthorized", path, 401);
  if (resp.status === 429) throw new ApiError("ratelimited", path, 429);
  if (resp.status === 503) throw new ApiError("unavailable", path, 503);
  throw new ApiError("server", path, resp.status);
}

/**
 * GET `path`, parse it, and check it has what the views read (shape.ts).
 * Round 30: an answer that is not JSON, or JSON without those fields, is a
 * "malformed" failure naming what is wrong — not a crash in the view, and
 * not "No response" (it used to be either, depending on where it broke).
 */
async function getJson<T>(path: string, check: (v: unknown) => void): Promise<T> {
  const resp = await request(path);
  let value: unknown;
  try {
    value = JSON.parse(resp.text);
  } catch {
    throw new ApiError("malformed", path, resp.status, `The Core answered ${path} with something that is not JSON.`);
  }
  try {
    check(value);
  } catch (e) {
    const why = e instanceof ShapeError ? e.message : String(e);
    throw new ApiError("malformed", path, resp.status, `The Core's answer to ${path} is not what this console reads: ${why}.`);
  }
  return value as T;
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

/**
 * Round 30: every program's count, not the default five rows. The Core caps
 * `?limit=` at 500 (server.rs MAX_TOP_PROTOCOLS); a program beyond the rows
 * returned is still "not reported", never zero.
 */
export const TOP_PROTOCOLS_LIMIT = 500;

export const api = {
  health: () => getJson<Health>("/health", checkHealth),
  graph: () => getJson<GraphSnapshot>("/api/graph", checkGraph),
  confidenceHistory: () => getJson<ConfidenceHistory>("/api/confidence-history", checkHistory).then(chronological),
  policyViolations: () => getJson<PolicyViolations>("/api/policy-violations", checkViolations),
  topProtocols: () => getJson<TopProtocols>(`/api/protocols/top?limit=${TOP_PROTOCOLS_LIMIT}`, checkTop),
  registry: () => getJson<RegistryState>("/api/registry", checkRegistry),
  manifests: () => getJson<Manifest[]>("/manifests", checkManifests),
  metrics: async () => parseMetrics((await request("/metrics")).text),
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
 * cheapest key-guarded route, so its status is the verdict on the key — on
 * that one route; the report says so rather than vouching for every route.
 */
export async function testConnection(conn: Connection): Promise<ConnectionReport> {
  const c = { base: normaliseBase(conn.base), key: conn.key.trim(), remember: conn.remember };
  const report: ConnectionReport = { reachable: false, authorized: false };
  try {
    const resp = await request("/health", { ...c, key: "" });
    let h: Health;
    try {
      const v: unknown = JSON.parse(resp.text);
      checkHealth(v);
      h = v as Health;
    } catch {
      // Something answered, but not a Core (a proxy's page, another service
      // on that port): not "reached" in the sense this report means.
      throw new ApiError(
        "malformed",
        "/health",
        resp.status,
        "Something answered /health, but not with a Graphite Core's health report.",
      );
    }
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
