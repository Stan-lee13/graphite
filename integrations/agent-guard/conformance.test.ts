/**
 * Round 39 (campaign 14): the cross-language conformance corpus,
 * `examples/decisions/conformance.json`, through the agent guard's signing
 * decision. Each vector is read the way the guard reads a Core answer —
 * the SDK's `parseJsonStrict` and `validateVerificationResult` (inside
 * `GraphiteClient.verify`), then `ResidualPolicy.assertExecutableVerdict`
 * (inside `executeBoundTransaction`) — once under the default policy and once
 * accepting every code a deployment may accept, and held to the corpus's
 * `guard` and `guard_accepting_all` outcomes.
 *
 * Over the whole corpus: under the default policy the guard signs exactly
 * what the SDK's `isExecutable` calls executable, so neither is looser than
 * the other or than the Core's rule; and no residual waiver lets it sign a
 * verdict the Core's rule refuses to read, a descriptive one, or one carrying
 * `intent_parameters`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseJsonStrict, validateVerificationResult } from "../../sdk/typescript/src/client.js";
import { isExecutable, UNOBSERVED_CODES, type VerificationResult } from "../../sdk/typescript/src/types.js";
import { NEVER_ACCEPTABLE, ResidualPolicy, ResidualPolicyRefusal } from "./residual-policy.js";

type Edit = { op: "set" | "delete" | "push"; path: (string | number)[]; value?: unknown };
interface Vector {
  name: string;
  base: string;
  raw_replace?: [string, string][];
  edits?: Edit[];
  expect: { rust: string; ts: string; go: string; guard: "signs" | "refuses"; guard_accepting_all: "signs" | "refuses" };
}

const DIR = new URL("../../examples/decisions/", import.meta.url);
const corpus = JSON.parse(readFileSync(new URL("conformance.json", DIR), "utf8")) as { version: number; verdicts: Vector[] };

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

/** The verdict as `GraphiteClient.verify` would hand it to the guard, or null when it refuses it. */
function asTheGuardReadsIt(v: Vector): VerificationResult | null {
  const text = vectorText(v);
  let parsed: unknown;
  try {
    parsed = parseJsonStrict(text);
  } catch {
    return null;
  }
  applyEdits(parsed, v.edits ?? []);
  return validateVerificationResult(parsed) === null ? (parsed as VerificationResult) : null;
}

function guardOutcome(policy: ResidualPolicy, verdict: VerificationResult | null): "signs" | "refuses" {
  if (verdict === null) return "refuses";
  try {
    policy.assertExecutableVerdict(verdict, "conformance");
    return "signs";
  } catch (e) {
    assert.ok(e instanceof ResidualPolicyRefusal, `a refusal, not a crash: ${String(e)}`);
    return "refuses";
  }
}

const EVERY_ACCEPTABLE = UNOBSERVED_CODES.filter((c) => !NEVER_ACCEPTABLE.has(c));

test("Round 39 corpus: the guard signs, under both policies, exactly as the corpus says", () => {
  assert.equal(corpus.version, 1);
  const strict = new ResidualPolicy();
  const waived = new ResidualPolicy(EVERY_ACCEPTABLE);
  const wrong: string[] = [];
  for (const v of corpus.verdicts) {
    const verdict = asTheGuardReadsIt(v);
    const a = guardOutcome(strict, verdict);
    const b = guardOutcome(waived, verdict);
    if (a !== v.expect.guard) wrong.push(`${v.name}: default policy ${a}, corpus ${v.expect.guard}`);
    if (b !== v.expect.guard_accepting_all) wrong.push(`${v.name}: accepting all ${b}, corpus ${v.expect.guard_accepting_all}`);
  }
  assert.deepEqual(wrong, []);
});

test("Round 39 corpus: under the default policy the guard signs exactly what isExecutable calls executable", () => {
  const strict = new ResidualPolicy();
  for (const v of corpus.verdicts) {
    const verdict = asTheGuardReadsIt(v);
    const sdk = verdict !== null && isExecutable(verdict);
    assert.equal(guardOutcome(strict, verdict) === "signs", sdk, v.name);
    if (sdk) assert.equal(v.expect.rust, "executable", `${v.name}: signed where the Core's rule does not execute`);
  }
});

test("Round 39 corpus: no waiver signs what the Core cannot read, a descriptive verdict, or intent_parameters", () => {
  const waived = new ResidualPolicy(EVERY_ACCEPTABLE);
  for (const v of corpus.verdicts) {
    const verdict = asTheGuardReadsIt(v);
    if (guardOutcome(waived, verdict) !== "signs") continue;
    assert.notEqual(v.expect.rust, "unreadable", `${v.name}: signed a verdict the Core's type refuses`);
    assert.equal(verdict?.scope?.kind, "artifact_bound", v.name);
    assert.ok(!verdict?.scope?.unobserved_codes?.includes("intent_parameters"), v.name);
    assert.equal(verdict?.approved, true, v.name);
  }
});
