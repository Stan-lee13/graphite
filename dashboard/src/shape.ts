// What the console accepts from the Core, checked before any view reads it.
// No imports, so it runs under Node for its tests (shape.test.ts).
//
// Round 30: every payload was `JSON.parse(text) as T`. A Core of another
// version, a proxy's login page, or a payload with `null` where a list was
// expected reached the views unchecked: a missing `count` drew "NaN", a
// `nodes: null` crashed the view into its error boundary, and a payload that
// failed inside `.then()` was reported as "No response from the Core" — a
// network fault — when the Core had answered. Each response is now checked
// for the fields the views read, and a response that does not have them is
// its own failure ("malformed"), with the field named.
//
// Only what the console reads is checked; fields it does not read pass
// through untouched, so a newer Core's additions do not break an older
// console.

export class ShapeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ShapeError";
  }
}

type Obj = Record<string, unknown>;

function obj(v: unknown, where: string): Obj {
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new ShapeError(`${where} is not an object`);
  return v as Obj;
}

function arr(v: unknown, where: string): unknown[] {
  if (!Array.isArray(v)) throw new ShapeError(`${where} is not a list`);
  return v;
}

function count(v: unknown, where: string): number {
  if (typeof v !== "number" || !Number.isFinite(v) || v < 0 || !Number.isInteger(v)) {
    throw new ShapeError(`${where} is not a whole, non-negative number`);
  }
  return v;
}

function num(v: unknown, where: string): number {
  if (typeof v !== "number" || !Number.isFinite(v)) throw new ShapeError(`${where} is not a finite number`);
  return v;
}

function str(v: unknown, where: string): string {
  if (typeof v !== "string") throw new ShapeError(`${where} is not text`);
  return v;
}

function bool(v: unknown, where: string): boolean {
  if (typeof v !== "boolean") throw new ShapeError(`${where} is not true or false`);
  return v;
}

function optCount(v: unknown, where: string): void {
  if (v !== undefined && v !== null) count(v, where);
}

function optStr(v: unknown, where: string): void {
  if (v !== undefined && v !== null) str(v, where);
}

/** `/api/graph` */
export function checkGraph(v: unknown): void {
  const g = obj(v, "the graph");
  arr(g.nodes, "`nodes`").forEach((n, i) => {
    const o = obj(n, `node ${i}`);
    str(o.program_id, `node ${i} \`program_id\``);
    str(o.name, `node ${i} \`name\``);
    str(o.trust_tier, `node ${i} \`trust_tier\``);
    count(o.instruction_count, `node ${i} \`instruction_count\``);
    count(o.battle_tested_tx_count, `node ${i} \`battle_tested_tx_count\``);
    optCount(o.baseline_samples, `node ${i} \`baseline_samples\``);
    // Round 39: drawn too, as a number and as text; a missing count was
    // drawn "NaN", a non-text CPI target crashed the detail pane.
    optCount(o.community_verified_count, `node ${i} \`community_verified_count\``);
    optStr(o.manifest_version, `node ${i} \`manifest_version\``);
    optStr(o.quarantine_reason, `node ${i} \`quarantine_reason\``);
    bool(o.quarantined, `node ${i} \`quarantined\``);
    arr(o.cpi_targets, `node ${i} \`cpi_targets\``).forEach((t, j) => str(t, `node ${i} \`cpi_targets[${j}]\``));
  });
  arr(g.edges, "`edges`").forEach((e, i) => {
    const o = obj(e, `edge ${i}`);
    str(o.from, `edge ${i} \`from\``);
    str(o.to, `edge ${i} \`to\``);
  });
}

/** The execution decisions a Core may report (the shared contract). */
export const DECISIONS = ["executable_approved", "analysis_only", "inconclusive", "blocked"] as const;

/** `/api/confidence-history` */
export function checkHistory(v: unknown): void {
  const h = obj(v, "the confidence history");
  count(h.count, "`count`");
  arr(h.series, "`series`").forEach((p, i) => {
    const o = obj(p, `point ${i}`);
    str(o.timestamp, `point ${i} \`timestamp\``);
    num(o.confidence, `point ${i} \`confidence\``);
    bool(o.approved, `point ${i} \`approved\``);
    str(o.program_id, `point ${i} \`program_id\``);
    str(o.audit_trail_id, `point ${i} \`audit_trail_id\``);
    optStr(o.transaction_sha256, `point ${i} \`transaction_sha256\``);
    // An unknown decision string is not refused here: it is drawn as "not
    // executable" (figures.ts), which is the fail-closed reading. A
    // decision that is not text at all is malformed.
    optStr(o.decision, `point ${i} \`decision\``);
    if (o.executable !== undefined && o.executable !== null) bool(o.executable, `point ${i} \`executable\``);
  });
}

/** `/api/policy-violations` */
export function checkViolations(v: unknown): void {
  const p = obj(v, "the policy violations");
  count(p.count, "`count`");
  optCount(p.violation_count, "`violation_count`");
  optCount(p.error_count, "`error_count`");
  arr(p.violations, "`violations`").forEach((x, i) => {
    const o = obj(x, `violation ${i}`);
    str(o.timestamp, `violation ${i} \`timestamp\``);
    str(o.program_id, `violation ${i} \`program_id\``);
    str(o.audit_trail_id, `violation ${i} \`audit_trail_id\``);
    num(o.confidence, `violation ${i} \`confidence\``);
    str(o.risk_status, `violation ${i} \`risk_status\``);
    str(o.policy_verdict, `violation ${i} \`policy_verdict\``);
  });
  arr(p.error_violations, "`error_violations`").forEach((x, i) => {
    const o = obj(x, `rejected request ${i}`);
    str(o.timestamp, `rejected request ${i} \`timestamp\``);
    str(o.error, `rejected request ${i} \`error\``);
  });
}

/** `/api/protocols/top` */
export function checkTop(v: unknown): void {
  const t = obj(v, "the protocol list");
  optCount(t.program_count, "`program_count`");
  arr(t.top, "`top`").forEach((x, i) => {
    const o = obj(x, `row ${i}`);
    str(o.program_id, `row ${i} \`program_id\``);
    count(o.observed_verifications, `row ${i} \`observed_verifications\``);
  });
}

/** `/api/registry` */
export function checkRegistry(v: unknown): void {
  const r = obj(v, "the registry");
  count(r.record_count, "`record_count`");
  arr(r.records, "`records`").forEach((x, i) => {
    const o = obj(x, `record ${i}`);
    str(o.program_id, `record ${i} \`program_id\``);
    str(o.version_label, `record ${i} \`version_label\``);
    str(o.content_hash, `record ${i} \`content_hash\``);
  });
  arr(r.reviewers, "`reviewers`").forEach((x, i) => {
    const o = obj(x, `reviewer ${i}`);
    str(o.pubkey, `reviewer ${i} \`pubkey\``);
    num(o.reputation_score, `reviewer ${i} \`reputation_score\``);
  });
}

/** `/manifests` */
export function checkManifests(v: unknown): void {
  arr(v, "the manifest list").forEach((m, i) => {
    const o = obj(m, `manifest ${i}`);
    str(obj(o.protocol, `manifest ${i} \`protocol\``).program_id, `manifest ${i} \`protocol.program_id\``);
    // Round 39 (R39-DASH-12): every list the instruction list draws. Only
    // the instruction array was checked, so a manifest whose instruction
    // had no `accounts` reached the view and crashed it into its error
    // boundary when a program was opened — the answer half-drawn rather
    // than refused as unreadable.
    arr(o.instructions, `manifest ${i} \`instructions\``).forEach((x, j) => {
      const where = `manifest ${i} instruction ${j}`;
      const ix = obj(x, where);
      str(ix.name, `${where} \`name\``);
      str(ix.discriminator, `${where} \`discriminator\``);
      arr(ix.accounts, `${where} \`accounts\``).forEach((a, k) => {
        const acc = obj(a, `${where} account ${k}`);
        bool(acc.is_writable, `${where} account ${k} \`is_writable\``);
        bool(acc.is_signer, `${where} account ${k} \`is_signer\``);
      });
      for (const list of ["expected_state_changes", "allowed_cpis", "risk_rules"] as const) {
        arr(ix[list], `${where} \`${list}\``).forEach((t, k) => str(t, `${where} \`${list}[${k}]\``));
      }
      optStr(ix.risk_class, `${where} \`risk_class\``);
    });
  });
}

/** `/health` */
export function checkHealth(v: unknown): void {
  const h = obj(v, "the health report");
  str(h.status, "`status`");
  str(h.version, "`version`");
  if (h.degraded !== undefined) bool(h.degraded, "`degraded`");
  // Round 39: each reason is drawn as a list item; one that is not text
  // crashed the System view.
  if (h.degraded_reasons !== undefined) arr(h.degraded_reasons, "`degraded_reasons`").forEach((r, i) => str(r, `\`degraded_reasons[${i}]\``));
}
