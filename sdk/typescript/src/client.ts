import type {
  ExecutionCheckInput,
  ExecutionCheckResult,
  HealthResponse,
  LifecycleEventInput,
  LifecycleEventReceipt,
  ProtocolManifest,
  VerificationInput,
  VerificationResult,
} from "./types.js";
import { ACCOUNT_IDENTITIES, UNOBSERVED_CODES } from "./types.js";

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
   * never as an implicit pass. Set to 0 to disable (not recommended). Any
   * other value must be a whole number of milliseconds from 1 to
   * 2147483647; anything else (negative, NaN, fractional, Infinity) is
   * refused at construction rather than silently disabling the timeout
   * (audit 2026-10-20, T2).
   */
  timeoutMs?: number;
}

/** The largest delay a Node timer honours; above it the timer fires at once. */
export const MAX_TIMEOUT_MS = 2_147_483_647;

/**
 * The configured timeout, or a thrown error for one that is not a timeout.
 *
 * Audit 2026-10-20 (T2): `timeoutMs > 0 ? AbortSignal.timeout(...) :
 * undefined` read a negative number, `NaN` and `-Infinity` as "disabled",
 * so a typo or an unparsed environment variable (`Number("30s")` is NaN)
 * turned the timeout off without a word. Only the documented 0 disables it.
 */
export function resolveTimeoutMs(timeoutMs: number | undefined): number {
  if (timeoutMs === undefined) return 30_000;
  if (
    typeof timeoutMs !== "number" ||
    !Number.isInteger(timeoutMs) ||
    timeoutMs < 0 ||
    timeoutMs > MAX_TIMEOUT_MS
  ) {
    throw new Error(
      `Graphite timeoutMs must be 0 (disabled) or a whole number of milliseconds from 1 to ` +
        `${MAX_TIMEOUT_MS}, got ${String(timeoutMs)}`,
    );
  }
  return timeoutMs;
}

const TRUST_TIERS: ReadonlySet<string> = new Set([
  "Unknown",
  "HeuristicInferred",
  "OfficialManifest",
  "SimulationValidated",
  "CommunityVerified",
  "BattleTested",
]);

const LOWER_HEX_64 = /^[0-9a-f]{64}$/;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((s) => typeof s === "string");
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function isCount(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function isNullable<T>(value: unknown, test: (v: unknown) => v is T): boolean {
  return value === null || test(value);
}

function isString(value: unknown): value is string {
  return typeof value === "string";
}

function isBoolean(value: unknown): value is boolean {
  return typeof value === "boolean";
}

/** The fields an artifact binding carries, which a descriptive scope must not. */
const ARTIFACT_FIELDS = ["transaction_sha256", "transaction_bytes", "simulated", "compute_budget", "message_version"];

function computeBudgetViolation(value: unknown): string | null {
  if (!isObject(value)) return "`scope.compute_budget` must be an object";
  if (value.source !== "v1_header" && value.source !== "compute_budget_instructions") {
    return "`scope.compute_budget.source` must be \"v1_header\" or \"compute_budget_instructions\"";
  }
  if (!isCount(value.effective_compute_unit_limit) || !isCount(value.priority_fee_lamports)) {
    return "`scope.compute_budget` must carry non-negative integer `effective_compute_unit_limit` and `priority_fee_lamports`";
  }
  for (const k of [
    "compute_unit_limit",
    "compute_unit_price_micro_lamports",
    "heap_bytes",
    "loaded_accounts_data_size_limit",
  ]) {
    if (value[k] !== undefined && !isNullable(value[k], isCount)) {
      return `\`scope.compute_budget.${k}\` must be a non-negative integer or null`;
    }
  }
  if (value.problems !== undefined && !isStringArray(value.problems)) {
    return "`scope.compute_budget.problems` must be an array of strings";
  }
  return null;
}

/**
 * The scope's shape, as `schemas/verification-result-v1.json` states it: the
 * field an execution gate decides on (artifact_bound or not, and what was not
 * observed). A scope that claims `artifact_bound` without the digest of what
 * it bound is not a binding; a `descriptive` scope carrying artifact fields
 * advertises a binding that does not exist (audit 2026-10-20: the validator
 * accepted both that and a scope without `unobserved_codes`, which the
 * schema requires and the Core always emits).
 */
function scopeViolation(scope: unknown): string | null {
  if (!isObject(scope)) return "`scope` must be an object";
  const s = scope;
  if (s.kind !== "artifact_bound" && s.kind !== "descriptive") {
    return "`scope.kind` must be \"artifact_bound\" or \"descriptive\"";
  }
  if (!isStringArray(s.unobserved) || s.unobserved.length === 0) {
    return "`scope.unobserved` must be a non-empty array of strings";
  }
  if (!isStringArray(s.unobserved_codes)) return "`scope.unobserved_codes` must be an array of strings";
  const unknown = s.unobserved_codes.find((c) => !(UNOBSERVED_CODES as readonly string[]).includes(c));
  if (unknown !== undefined) return `\`scope.unobserved_codes\` has an unknown code ${JSON.stringify(unknown)}`;
  if (s.unobserved_codes.length !== s.unobserved.length) {
    return "`scope.unobserved_codes` must name each entry of `scope.unobserved`";
  }
  if (s.kind === "descriptive") {
    const field = ARTIFACT_FIELDS.find((f) => s[f] !== undefined);
    if (field !== undefined) {
      return `a descriptive \`scope\` must not carry \`${field}\`: nothing was bound`;
    }
    return null;
  }
  if (typeof s.transaction_sha256 !== "string" || !LOWER_HEX_64.test(s.transaction_sha256)) {
    return "`scope.transaction_sha256` must be 64 lowercase hex characters";
  }
  if (!Number.isSafeInteger(s.transaction_bytes) || (s.transaction_bytes as number) < 1) {
    return "`scope.transaction_bytes` must be a positive integer";
  }
  if (typeof s.simulated !== "boolean") return "`scope.simulated` must be a boolean";
  if (s.message_version !== undefined && !["legacy", "v0", "v1"].includes(s.message_version as string)) {
    return "`scope.message_version` must be \"legacy\", \"v0\" or \"v1\"";
  }
  if (s.compute_budget !== undefined) return computeBudgetViolation(s.compute_budget);
  return null;
}

function transactionViolation(value: unknown): string | null {
  if (!isObject(value)) return "`transaction` must be an object";
  for (const k of ["program_id", "protocol_version", "instruction_name", "instruction_discriminator", "data_hex"]) {
    if (!isString(value[k])) return `\`transaction.${k}\` must be a string`;
  }
  for (const k of [
    "instruction_count",
    "account_count",
    "signer_count",
    "writable_count",
    "compute_budget_units",
    "data_len",
  ]) {
    if (!isCount(value[k])) return `\`transaction.${k}\` must be a non-negative integer`;
  }
  if (
    !Array.isArray(value.accounts) ||
    !value.accounts.every((a) => isObject(a) && isString(a.address) && isBoolean(a.is_signer) && isBoolean(a.is_writable))
  ) {
    return "`transaction.accounts` must be an array of { address, is_signer, is_writable }";
  }
  return null;
}

function resolvedAccountViolation(value: unknown, i: number): string | null {
  const at = `\`resolved_accounts[${i}]\``;
  if (!isObject(value)) return `${at} must be an object`;
  if (!isString(value.address) || !isString(value.role)) return `${at} must carry string \`address\` and \`role\``;
  if (value.name !== undefined && !isString(value.name)) return `${at}.name must be a string`;
  if (!isStringArray(value.pda_seeds)) return `${at}.pda_seeds must be an array of strings`;
  for (const k of ["is_pda", "is_signer", "is_writable", "pda_mismatch", "expected_address_mismatch", "privilege_mismatch"]) {
    // The three mismatch flags are security signals the Core always emits;
    // an absent one is not "no mismatch".
    if (!isBoolean(value[k])) return `${at}.${k} must be a boolean`;
  }
  if (!(ACCOUNT_IDENTITIES as readonly unknown[]).includes(value.identity)) {
    return `${at}.identity must be one of ${ACCOUNT_IDENTITIES.join(", ")}`;
  }
  return null;
}

function layerViolation(value: unknown): string | null {
  if (!isObject(value) || !isString(value.layer) || !isBoolean(value.passed) || !isString(value.reason)) {
    return "each layer must carry `layer` (string), `passed` (boolean) and `reason` (string)";
  }
  if (value.status !== "passed" && value.status !== "failed" && value.status !== "inconclusive") {
    return "each layer's `status` must be \"passed\", \"failed\" or \"inconclusive\"";
  }
  if (value.passed !== (value.status === "passed")) {
    // `passed` is derived from `status` at construction in the Core
    // (GAP-2026-08-06-3); a layer where they disagree did not come from it.
    return `layer ${value.layer}: \`passed\` must be true exactly when \`status\` is "passed"`;
  }
  return null;
}

function programUpgradeViolation(value: unknown): string | null {
  if (
    !isObject(value) ||
    !isString(value.program_id) ||
    !isCount(value.previous_deploy_slot) ||
    !isCount(value.deploy_slot) ||
    !isNullable(value.previous_upgrade_authority, isString) ||
    !isNullable(value.upgrade_authority, isString) ||
    !isBoolean(value.quarantined)
  ) {
    return "each `program_upgrades` entry must match the schema's ProgramUpgrade";
  }
  return null;
}

/**
 * Runtime shape guard for a VerificationResult (GAP-2026-08-06-8; deepened in
 * Round 24, W22; aligned with the tightened schema in the 2026-10-20 audit).
 *
 * The wire format is the only untrusted input the SDK consumes — a truncated,
 * hostile, or mis-shaped payload must fail loudly here instead of flowing
 * through typed as a `VerificationResult`. Every field the Core always emits
 * is required, as `schemas/verification-result-v1.json` requires it: the
 * verdict, its confidence and breakdown, its risk verdict and findings, its
 * trust tier and policy verdict, the transaction, the resolved accounts and
 * their identity, its layers, and its scope (what the approval is bound to
 * and what was not observed). A verdict that contradicts itself — approved
 * while the risk verdict is Blocked or the policy verdict is not
 * "Approved", or a layer whose `passed` disagrees with its `status` — is
 * refused.
 *
 * One deliberate difference from the schema: a top-level field this SDK does
 * not know is ignored rather than refused, so a newer Core that adds an
 * optional field does not break every deployed client. Everything a caller
 * decides on is checked.
 *
 * This is defense-in-depth, not a substitute for TLS: transport-level
 * integrity still belongs to the deployment (see README trust-boundary
 * notes).
 *
 * Returns a description of the first violation, or null when the shape is
 * valid.
 */
export function validateVerificationResult(value: unknown): string | null {
  if (!isObject(value)) return "verification result must be a JSON object";
  const v = value;
  if (typeof v.approved !== "boolean") return "`approved` must be a boolean";
  if (!isFiniteNumber(v.confidence) || v.confidence < 0 || v.confidence > 1) {
    return "`confidence` must be a finite number in [0, 1]";
  }
  if (
    !Array.isArray(v.breakdown) ||
    v.breakdown.length === 0 ||
    !v.breakdown.every(
      (b) =>
        isObject(b) &&
        isString(b.kind) &&
        isFiniteNumber(b.raw_value) &&
        isFiniteNumber(b.weight) &&
        isFiniteNumber(b.contribution),
    )
  ) {
    return "`breakdown` must be a non-empty array of { kind, raw_value, weight, contribution }";
  }
  if (typeof v.trust_tier !== "string" || !TRUST_TIERS.has(v.trust_tier)) {
    return "`trust_tier` must be one of the schema's tiers";
  }
  if (!isObject(v.risk_verdict)) return "`risk_verdict` must be an object";
  const risk = v.risk_verdict;
  if (risk.status !== "Clear" && risk.status !== "Blocked") {
    return "`risk_verdict.status` must be \"Clear\" or \"Blocked\"";
  }
  if (
    !Array.isArray(risk.findings) ||
    !risk.findings.every((f) => isObject(f) && isString(f.pattern) && isString(f.reason))
  ) {
    return "`risk_verdict.findings` must be an array of { pattern, reason } strings";
  }
  if (v.policy_verdict !== "Approved" && v.policy_verdict !== "Rejected") {
    return "`policy_verdict` must be \"Approved\" or \"Rejected\"";
  }
  if (v.approved && risk.status !== "Clear") {
    return "an approved verdict must have a Clear risk verdict";
  }
  if (v.approved !== (v.policy_verdict === "Approved")) {
    return "`policy_verdict` must be \"Approved\" exactly when `approved` is true";
  }
  if (typeof v.audit_trail_id !== "string" || v.audit_trail_id.length === 0) {
    return "`audit_trail_id` must be a non-empty string";
  }
  if (typeof v.content_hash !== "string" || v.content_hash.length === 0) {
    return "`content_hash` must be a non-empty string";
  }
  const tx = transactionViolation(v.transaction);
  if (tx !== null) return tx;
  if (!Array.isArray(v.resolved_accounts)) return "`resolved_accounts` must be an array";
  for (const [i, a] of v.resolved_accounts.entries()) {
    const violation = resolvedAccountViolation(a, i);
    if (violation !== null) return violation;
  }
  for (const k of ["protocol_name", "instruction_name", "summary"]) {
    if (!isString(v[k])) return `\`${k}\` must be a string`;
  }
  for (const k of ["manifest_found", "unknown_protocol"]) {
    if (!isBoolean(v[k])) return `\`${k}\` must be a boolean`;
  }
  // Always emitted, possibly null: absent is not the same answer as null.
  if (!("manifest_version" in v) || !isNullable(v.manifest_version, isString)) {
    return "`manifest_version` must be a string or null";
  }
  if (!("simulation_flagged" in v) || !isNullable(v.simulation_flagged, isBoolean)) {
    return "`simulation_flagged` must be a boolean or null";
  }
  if (!("simulation_divergence" in v) || !isNullable(v.simulation_divergence, isFiniteNumber)) {
    return "`simulation_divergence` must be a number or null";
  }
  if (!Array.isArray(v.layers)) return "`layers` must be an array";
  for (const layer of v.layers) {
    const violation = layerViolation(layer);
    if (violation !== null) return violation;
  }
  if (v.program_upgrades !== undefined) {
    if (!Array.isArray(v.program_upgrades)) return "`program_upgrades` must be an array";
    for (const u of v.program_upgrades) {
      const violation = programUpgradeViolation(u);
      if (violation !== null) return violation;
    }
  }
  if (v.scope === undefined) {
    return "`scope` is missing: the verdict does not say what it is bound to";
  }
  return scopeViolation(v.scope);
}

const CALLER_LIFECYCLE_EVENTS: readonly string[] = ["signing", "submission", "confirmation", "finalization"];

/**
 * Shape guard for `POST /audit/event`'s receipt (audit 2026-10-20, T1). The
 * receipt is what a caller decides on before submitting — `verdict_on_record`
 * above all — so it is checked like a verdict. When `sent` is given, the
 * receipt must be about that event: the same `event_type`, and the
 * `content_hash` the server trims and echoes.
 */
export function validateLifecycleEventReceipt(value: unknown, sent?: LifecycleEventInput): string | null {
  if (!isObject(value)) return "lifecycle receipt must be a JSON object";
  if (value.recorded !== true) return "`recorded` must be true";
  if (!CALLER_LIFECYCLE_EVENTS.includes(value.event_type as string)) {
    return "`event_type` must be a caller-reported lifecycle stage";
  }
  if (!isString(value.content_hash)) return "`content_hash` must be a string";
  if (!["approved", "blocked", "not_found"].includes(value.verdict_on_record as string)) {
    return "`verdict_on_record` must be \"approved\", \"blocked\" or \"not_found\"";
  }
  if (!["audit_trail_id", "transaction_sha256", "content_hash"].includes(value.verdict_on_record_key as string)) {
    return "`verdict_on_record_key` must be \"audit_trail_id\", \"transaction_sha256\" or \"content_hash\"";
  }
  if (value.sequence_anomalies !== undefined && !isStringArray(value.sequence_anomalies)) {
    return "`sequence_anomalies` must be an array of strings";
  }
  if (value.prior_events_on_record !== undefined && !isCount(value.prior_events_on_record)) {
    return "`prior_events_on_record` must be a non-negative integer";
  }
  if (sent !== undefined) {
    if (value.event_type !== sent.event_type) {
      return `the receipt is for ${JSON.stringify(value.event_type)}, not the ${sent.event_type} event sent`;
    }
    if (typeof sent.content_hash === "string" && value.content_hash !== sent.content_hash.trim()) {
      return "the receipt names a different `content_hash` from the one sent";
    }
  }
  return null;
}

const RECONCILIATION_UNIT = [
  "ApprovedAndExecuted",
  "BlockedButExecuted",
  "BlockedAndNotExecuted",
  "NotFound",
  "NoVerificationOnRecord",
];
const RECONCILIATION_DATA = ["ApprovedButFailedOnChain", "RecordedForDifferentBytes", "Unavailable"];
const CHAIN_STATUS = ["Confirmed", "UnknownSignature", "Unavailable"];

/** A serde externally-tagged enum value: a unit name, or a one-key object. */
function variantOf(value: unknown, units: readonly string[], data: readonly string[]): string | null {
  if (typeof value === "string") return units.includes(value) ? value : null;
  if (!isObject(value)) return null;
  const keys = Object.keys(value);
  return keys.length === 1 && data.includes(keys[0]) ? keys[0] : null;
}

/**
 * Shape guard for `POST /verify/execution`'s answer (audit 2026-10-20, T1:
 * the method used to resolve `{}` for a 200 whose body was not JSON, which a
 * caller read as "no discrepancy"). `discrepancy` must agree with the
 * reconciliation the server computed it from — `BlockedButExecuted`, or
 * `RecordedForDifferentBytes` of a refusal — so a body that drops the alarm
 * while keeping the outcome is refused. When `sent` is given, the answer must
 * be about that signature.
 */
export function validateExecutionCheckResult(value: unknown, sent?: ExecutionCheckInput): string | null {
  if (!isObject(value)) return "execution check result must be a JSON object";
  if (!isString(value.signature)) return "`signature` must be a string";
  if (variantOf(value.chain_status, [], CHAIN_STATUS) === null) {
    return "`chain_status` must be one of Confirmed, UnknownSignature or Unavailable";
  }
  const reconciliation = variantOf(value.reconciliation, RECONCILIATION_UNIT, RECONCILIATION_DATA);
  if (reconciliation === null) return "`reconciliation` is not an ExecutionReconciliation";
  if (!isBoolean(value.discrepancy)) return "`discrepancy` must be a boolean";
  const differentBytes = isObject(value.reconciliation) ? value.reconciliation.RecordedForDifferentBytes : undefined;
  const expected =
    reconciliation === "BlockedButExecuted" ||
    (reconciliation === "RecordedForDifferentBytes" && isObject(differentBytes) && differentBytes.recorded_approved === false);
  if (value.discrepancy !== expected) {
    return `\`discrepancy\` must be ${expected} for a ${reconciliation} reconciliation`;
  }
  if (!isNullable(value.recorded_approved, isBoolean)) return "`recorded_approved` must be a boolean or null";
  for (const k of ["recorded_audit_trail_id", "recorded_transaction_sha256", "chain_transaction_sha256"]) {
    if (!isNullable(value[k], isString)) return `\`${k}\` must be a string or null`;
  }
  if (!["chain", "audit_trail_id", "transaction_sha256", "content_hash", "none"].includes(value.attribution as string)) {
    return "`attribution` must be chain, audit_trail_id, transaction_sha256, content_hash or none";
  }
  if (!isStringArray(value.caller_keys_disagree)) return "`caller_keys_disagree` must be an array of strings";
  for (const k of ["chain_bytes_rejected", "chain_bytes_unavailable", "chain_inconsistent"]) {
    if (value[k] !== undefined && !isNullable(value[k], isString)) return `\`${k}\` must be a string or null`;
  }
  const w = value.inclusion_witness;
  if (w !== undefined && w !== null) {
    if (!isObject(w) || !isBoolean(w.agrees) || !isNullable(w.seen, isBoolean) || !isString(w.detail)) {
      return "`inclusion_witness` must be { agrees, seen, detail } or null";
    }
  }
  const rv = value.recorded_verdicts;
  if (rv !== undefined && rv !== null && !(isObject(rv) && isCount(rv.approved) && isCount(rv.refused))) {
    return "`recorded_verdicts` must be { approved, refused } counts or null";
  }
  if (!isBoolean(value.audit_recorded)) return "`audit_recorded` must be a boolean";
  if (sent !== undefined && typeof sent.signature === "string" && value.signature !== sent.signature.trim()) {
    return "the result is about a different signature from the one sent";
  }
  return null;
}

/** Shape guard for `GET /health` (audit 2026-10-20, T1). */
export function validateHealthResponse(value: unknown): string | null {
  if (!isObject(value)) return "health response must be a JSON object";
  for (const k of ["status", "service", "version"]) {
    if (!isString(value[k])) return `\`${k}\` must be a string`;
  }
  if (value.degraded !== undefined && !isBoolean(value.degraded)) return "`degraded` must be a boolean";
  if (value.degraded_reasons !== undefined && !isStringArray(value.degraded_reasons)) {
    return "`degraded_reasons` must be an array of strings";
  }
  return null;
}

/** Shape guard for `GET /manifests` (audit 2026-10-20, T1). */
export function validateManifestList(value: unknown): string | null {
  if (!Array.isArray(value)) return "manifest list must be a JSON array";
  for (const [i, m] of value.entries()) {
    const at = `manifest ${i}`;
    if (!isObject(m) || !isString(m.graphite_manifest_version)) {
      return `${at}: must be an object with a string \`graphite_manifest_version\``;
    }
    if (!isObject(m.protocol) || !isString(m.protocol.name) || !isString(m.protocol.program_id)) {
      return `${at}: \`protocol\` must carry string \`name\` and \`program_id\``;
    }
    if (!isObject(m.version) || !isString(m.version.label)) {
      return `${at}: \`version\` must carry a string \`label\``;
    }
    if (m.trust_tier !== undefined && !isString(m.trust_tier)) return `${at}: \`trust_tier\` must be a string`;
    if (!Array.isArray(m.instructions)) return `${at}: \`instructions\` must be an array`;
    for (const ix of m.instructions) {
      if (
        !isObject(ix) ||
        !isString(ix.name) ||
        !isString(ix.discriminator) ||
        !isStringArray(ix.expected_state_changes) ||
        !isStringArray(ix.allowed_cpis) ||
        !isStringArray(ix.risk_rules) ||
        !Array.isArray(ix.accounts) ||
        !ix.accounts.every(
          (a) =>
            isObject(a) && isString(a.name) && isString(a.role) && isBoolean(a.is_writable) && isBoolean(a.is_signer),
        )
      ) {
        return `${at}: every instruction must match the manifest schema`;
      }
    }
  }
  return null;
}

/**
 * Whether a URL hostname is the local machine: `localhost`, 127.0.0.0/8,
 * `::1`, or 127.0.0.0/8 written as an IPv4-mapped IPv6 address
 * (`::ffff:127.0.0.1`, which the URL parser canonicalises to
 * `[::ffff:7f00:1]`). The WHATWG URL parser has already canonicalised the
 * host (`127.1` and `0x7f.0.0.1` both arrive as `127.0.0.1`; IPv6 arrives
 * bracketed and compressed), so this compares canonical forms only.
 *
 * Audit 2026-10-20: Go's CheckBaseURL accepted `http://[::ffff:127.0.0.1]`
 * and this refused it. An IPv4-mapped address is the IPv4 address — a
 * connection to it is a connection to 127.0.0.1 — so both SDKs now accept
 * the mapped form of 127.0.0.0/8 and nothing else mapped. The deprecated
 * IPv4-compatible form (`::127.0.0.1`) stays refused in both.
 */
export function isLoopbackHost(hostname: string): boolean {
  const h = hostname.toLowerCase();
  if (h === "localhost" || h === "[::1]" || h === "::1") return true;
  const m = /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (m !== null) return m.slice(1).every((o) => Number(o) <= 255);
  const mapped = /^\[?::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})\]?$/.exec(h);
  return mapped !== null && parseInt(mapped[1], 16) >> 8 === 127;
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
  /**
   * An ES private field, not a TypeScript `private` one (audit 2026-10-20):
   * `private` is erased at compile time, so `client["apiKey"]`, a debugger's
   * object view or a `JSON.stringify(client)` in a log line read the operator
   * key. `#apiKey` is not a property of the object at all.
   */
  readonly #apiKey?: string;
  private timeoutMs: number;

  constructor(options: GraphiteClientOptions) {
    // Refused at construction, before any request can carry the key.
    this.baseUrl = assertSecureBaseUrl(options.baseUrl);
    this.#apiKey = options.apiKey?.trim() || undefined;
    this.timeoutMs = resolveTimeoutMs(options.timeoutMs);
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
    if (this.#apiKey) {
      headers["authorization"] = `Bearer ${this.#apiKey}`;
    }
    return headers;
  }

  /**
   * Read a 2xx body as JSON and check its shape. A body that is not JSON, or
   * not the shape the route answers with, is thrown — never returned typed
   * as the answer (audit 2026-10-20, T1).
   */
  private async accept<T>(response: Response, what: string, check: (v: unknown) => string | null): Promise<T> {
    let raw: unknown;
    try {
      raw = await response.json();
    } catch {
      throw new Error(`Graphite ${what} returned ${response.status} with a body that is not JSON`);
    }
    const violation = check(raw);
    if (violation !== null) {
      throw new Error(`Graphite returned a structurally invalid ${what}: ${violation}`);
    }
    return raw as T;
  }

  async verify(input: VerificationInput): Promise<VerificationResult> {
    const response = await this.send("/verify", {
      method: "POST",
      headers: this.headers({ "content-type": "application/json" }),
      body: JSON.stringify(input),
    });

    if (!response.ok) {
      const errorBody = (await response.json().catch(() => ({}))) as { error?: unknown };
      throw new Error(
        `Graphite verification failed: ${response.status} ${response.statusText} — ${
          typeof errorBody?.error === "string" ? errorBody.error : ""
        }`,
      );
    }
    return this.accept<VerificationResult>(response, "verification result", validateVerificationResult);
  }

  /**
   * Put a caller-performed lifecycle stage on Graphite's append-only trail
   * (`POST /audit/event`, Constitution P9).
   *
   * Resolves only when the server says `recorded: true` in a receipt about
   * this event: a 503 means the event was NOT recorded and is thrown, never
   * swallowed, so a caller that is about to submit knows the signing it just
   * performed is not on the trail. The receipt carries `verdict_on_record` —
   * what Graphite's own trail says about the hash — and a caller reporting a
   * signing against a `blocked` verdict has just told Graphite the gate was
   * bypassed.
   */
  async recordLifecycleEvent(event: LifecycleEventInput): Promise<LifecycleEventReceipt> {
    const response = await this.send("/audit/event", {
      method: "POST",
      headers: this.headers({ "content-type": "application/json" }),
      body: JSON.stringify(event),
    });
    if (!response.ok) {
      const raw = (await response.json().catch(() => ({}))) as Record<string, unknown>;
      throw new Error(
        `Graphite did not record the ${event.event_type} event: ${response.status} ${response.statusText} — ${
          typeof raw?.error === "string" ? raw.error : "no detail"
        }`,
      );
    }
    return this.accept<LifecycleEventReceipt>(response, "lifecycle receipt", (v) =>
      validateLifecycleEventReceipt(v, event),
    );
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
    if (!response.ok) {
      const raw = (await response.json().catch(() => ({}))) as Record<string, unknown>;
      throw new Error(
        `Graphite execution check failed: ${response.status} ${response.statusText} — ${
          typeof raw?.error === "string" ? raw.error : "no detail"
        }${raw?.outcome ? ` (outcome: ${JSON.stringify(raw.outcome)})` : ""}`,
      );
    }
    return this.accept<ExecutionCheckResult>(response, "execution check result", (v) =>
      validateExecutionCheckResult(v, input),
    );
  }

  async health(): Promise<HealthResponse> {
    const response = await this.send("/health");
    if (!response.ok) throw new Error(`Health check failed: ${response.status}`);
    return this.accept<HealthResponse>(response, "health response", validateHealthResponse);
  }

  async listManifests(): Promise<ProtocolManifest[]> {
    const response = await this.send("/manifests", { headers: this.headers() });
    if (!response.ok) throw new Error(`Failed to list manifests: ${response.status}`);
    return this.accept<ProtocolManifest[]>(response, "manifest list", validateManifestList);
  }
}
