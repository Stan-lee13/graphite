// Round 40 (assurance): the shared conformance corpus,
// `examples/decisions/conformance.json`, through the function that decides
// whether the console draws a verdict green ("executable").
//
// The console is never handed a verdict. It reads `/api/confidence-history`,
// whose rows the server writes from the Core's own result
// (graphite-core/src/server.rs, `verify_handler`'s AuditRecord and
// `confidence_history_handler`): `approved`, `decision`, `executable` and
// `transaction_sha256` (the scope's digest when artifact-bound, else null).
// Those four fields are all `verdictKind` reads. So each corpus verdict goes
// through the row the server writes for it, then the console's own path:
// `checkHistory` (api.ts runs it on every `/api/confidence-history` response
// before a view reads it; a row it refuses is drawn as a malformed response,
// never as a verdict), `verdictKind` and `verdictTone` — the narrowest code
// that decides green.
//
// What this holds: green is exactly "approved, bound to bytes, decision
// executable_approved, executable true"; every verdict the corpus marks
// executable is green; and every verdict drawn green that the corpus does NOT
// mark executable carries, in those four fields, exactly the row of the
// committed executable verdict — what takes its permission away (a residual,
// a failed layer, a policy refusal, a malformed field) is not on the row.
// That such a verdict never reaches a row is the server's half:
// graphite-core/tests/round40_surface_conformance.rs runs the real server for
// each corpus base and checks the row's `executable` is the Core's rule.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { verdictKind, verdictTone } from "./figures.ts";
import { checkHistory } from "./shape.ts";
import type { ConfidencePoint } from "./api";

type Outcome = "executable" | "not_executable" | "unreadable";
type Edit = { op: "set" | "delete" | "push"; path: (string | number)[]; value?: unknown };
interface Vector {
  name: string;
  base: string;
  raw_replace?: [string, string][];
  edits?: Edit[];
  expect: { rust: Outcome; ts: Outcome; go: Outcome };
}

const DIR = new URL("../../examples/decisions/", import.meta.url);
const corpus = JSON.parse(readFileSync(new URL("conformance.json", DIR), "utf8")) as { version: number; verdicts: Vector[] };

/** The vector's text: its base with the exact replacements applied. */
function vectorText(v: Vector): string {
  let text = readFileSync(new URL(`${v.base}.json`, DIR), "utf8");
  for (const [from, to] of v.raw_replace ?? []) {
    const at = text.indexOf(from);
    assert.ok(at >= 0 && text.indexOf(from, at + 1) < 0, `${v.name}: ${JSON.stringify(from)} must occur exactly once`);
    text = text.slice(0, at) + to + text.slice(at + from.length);
  }
  return text;
}

function applyEdits(value: unknown, edits: Edit[]): void {
  for (const e of edits) {
    let at = value as Record<string | number, unknown>;
    for (const k of e.path.slice(0, -1)) at = at[k] as Record<string | number, unknown>;
    const last = e.path[e.path.length - 1];
    if (e.op === "set") at[last] = structuredClone(e.value);
    else if (e.op === "delete") delete at[last];
    else (at[last] as unknown[]).push(structuredClone(e.value));
  }
}

/** The verdict as JSON, or null when it is not JSON at all. */
function verdict(v: Vector): Record<string, unknown> | null {
  const text = vectorText(v);
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    return null;
  }
  applyEdits(doc, v.edits ?? []);
  return doc !== null && typeof doc === "object" && !Array.isArray(doc) ? (doc as Record<string, unknown>) : null;
}

/** The `/api/confidence-history` row the server writes for this verdict: the
 *  fields the console decides on, copied as `verify_handler` copies them. */
function rowFor(r: Record<string, unknown>): ConfidencePoint {
  const scope = r.scope as Record<string, unknown> | undefined;
  return {
    timestamp: "2026-10-25T00:00:00Z",
    confidence: typeof r.confidence === "number" ? r.confidence : 0,
    approved: r.approved as boolean,
    program_id: "11111111111111111111111111111111",
    audit_trail_id: String(r.audit_trail_id ?? ""),
    decision: r.decision as string | null | undefined,
    executable: r.executable as boolean | null | undefined,
    transaction_sha256: scope && scope.kind === "artifact_bound" ? (scope.transaction_sha256 as string | null | undefined) : null,
  };
}

/** Drawn green by the console: the response passes its shape check, and the
 *  row's kind is the green one. */
const green = (p: ConfidencePoint): boolean => {
  try {
    checkHistory({ series: [p], count: 1 });
  } catch {
    return false;
  }
  return verdictTone(verdictKind(p)) === "pass";
};
const decided = (p: ConfidencePoint) => ({
  approved: p.approved,
  decision: p.decision,
  executable: p.executable,
  bound: typeof p.transaction_sha256 === "string" && p.transaction_sha256.length > 0,
});

test("the console draws green exactly the rows that say executable, over every corpus verdict", () => {
  assert.equal(corpus.version, 1);
  assert.ok(corpus.verdicts.length >= 90, `${corpus.verdicts.length} verdict vectors`);
  const executableRow = decided(rowFor(verdict(corpus.verdicts.find((v) => v.base === "executable_approved" && !v.edits && !v.raw_replace)!)!));
  assert.deepEqual(executableRow, { approved: true, decision: "executable_approved", executable: true, bound: true });

  const wrong: string[] = [];
  let corpusExecutable = 0;
  let greenNotExecutable = 0;
  let notJson = 0;
  for (const v of corpus.verdicts) {
    const r = verdict(v);
    if (r === null) {
      notJson++;
      assert.notEqual(v.expect.rust, "executable", `${v.name}: not JSON, yet executable to the Core`);
      continue;
    }
    const row = rowFor(r);
    const isGreen = green(row);
    // The console's whole rule: green iff the row says executable.
    const says = row.approved === true && decided(row).bound && row.decision === "executable_approved" && row.executable === true;
    if (isGreen !== says) wrong.push(`${v.name}: green=${isGreen}, the row says executable=${says}`);
    if (v.expect.rust === "executable") {
      corpusExecutable++;
      if (!isGreen) wrong.push(`${v.name}: executable to the Core, not drawn green`);
    } else if (isGreen) {
      greenNotExecutable++;
      // Drawn green although not executable: only because the row carries
      // exactly what the executable verdict's row carries.
      if (JSON.stringify(decided(row)) !== JSON.stringify(executableRow)) {
        wrong.push(`${v.name}: green with a row that differs from the executable one: ${JSON.stringify(decided(row))}`);
      }
    }
  }
  assert.deepEqual(wrong, []);
  // Every executable vector of the corpus was seen (21 at Round 40).
  assert.equal(corpusExecutable, corpus.verdicts.filter((v) => v.expect.rust === "executable").length);
  assert.ok(corpusExecutable >= 7, `${corpusExecutable} executable vectors`);
  // Every vector is JSON to the console's parser (JSON.parse keeps the last
  // of two duplicate keys; the Core refuses them), so each one reached a row.
  assert.equal(notJson, 0, "a vector the console could not parse at all");
  // Reported, not hidden: verdicts whose permission is taken away by a field
  // the row does not carry (41 at Round 40). The server never writes their
  // row from a verdict it built (the Rust half); a row edited on the trail
  // is the trail's integrity (the audit MAC), not the console's.
  assert.ok(greenNotExecutable > 0, "the corpus still has verdicts whose row alone looks executable");
});

test("each committed base's row is drawn as the Core decided it", () => {
  const want: Record<string, string> = {
    executable_approved: "executable",
    analysis_only: "analysis",
    inconclusive: "inconclusive",
    blocked: "refused",
  };
  for (const [base, kind] of Object.entries(want)) {
    const v = corpus.verdicts.find((x) => x.base === base && !x.edits && !x.raw_replace)!;
    const row = rowFor(verdict(v)!);
    assert.equal(verdictKind(row), kind, base);
    assert.equal(green(row), v.expect.rust === "executable", base);
  }
});

test("a row that disagrees with itself, or a decision the console does not know, is never green", () => {
  const exec = rowFor(verdict(corpus.verdicts.find((v) => v.base === "executable_approved" && !v.edits && !v.raw_replace)!)!);
  assert.equal(green(exec), true, "control");
  for (const [what, p] of [
    ["executable false", { ...exec, executable: false }],
    ["executable absent", { ...exec, executable: undefined }],
    ["executable null", { ...exec, executable: null }],
    ["decision analysis_only", { ...exec, decision: "analysis_only" }],
    ["decision absent (an older Core)", { ...exec, decision: undefined }],
    ["decision in another case", { ...exec, decision: "Executable_Approved" }],
    ["not approved", { ...exec, approved: false }],
    ["not bound to bytes", { ...exec, transaction_sha256: null }],
    ["an empty digest", { ...exec, transaction_sha256: "" }],
    ["approved as the number 1", { ...exec, approved: 1 as unknown as boolean }],
    ["executable as the text \"true\"", { ...exec, executable: "true" as unknown as boolean }],
  ] as [string, ConfidencePoint][]) {
    assert.equal(green(p), false, what);
  }
  // `verdictKind` alone reads `approved` by truthiness; the shape check in
  // front of it is what refuses a row whose `approved` is not a boolean.
  assert.throws(() => checkHistory({ series: [{ ...exec, approved: 1 }], count: 1 }), /approved/);
});
