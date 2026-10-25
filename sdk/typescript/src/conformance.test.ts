/**
 * Round 39 (campaign 14): the cross-language conformance corpus,
 * `examples/decisions/conformance.json`, read the way this SDK reads a
 * server's answer — `parseJsonStrict`, `validateVerificationResult`, then
 * `isExecutable` — and held to the outcome the corpus names for TypeScript.
 * The Rust Core (`graphite-core/tests/round39_conformance_corpus.rs`), the Go
 * SDK (`sdk/go/conformance_test.go`) and the agent guard
 * (`integrations/agent-guard/conformance.test.ts`) read the same file.
 *
 * Besides each vector's own outcome, two rules hold over the whole corpus:
 * nothing this SDK calls executable is not executable to the Core's own rule
 * (`expect.rust`), and every vector executable in one language and not in
 * another says why in its `note`.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseJsonStrict, validateVerificationResult } from "./client.js";
import { computeContentHash } from "./auditbind.js";
import { transactionDigest } from "./transaction-digest.js";
import { isExecutable, type VerificationResult } from "./types.js";

type Outcome = "executable" | "not_executable" | "unreadable";
type Edit = { op: "set" | "delete" | "push"; path: (string | number)[]; value?: unknown };
interface Vector {
  name: string;
  base: string;
  raw_replace?: [string, string][];
  edits?: Edit[];
  expect: { rust: Outcome; ts: Outcome; go: Outcome; guard: string; guard_accepting_all: string };
  note?: string;
}
interface Corpus {
  version: number;
  verdicts: Vector[];
  content_hash: {
    name: string;
    program_id: string;
    discriminator: string;
    accounts: string[];
    data: number[] | null;
    cpi_targets: string[];
    expect: string | null;
    differs_from?: string;
  }[];
  transaction_digest: { name: string; hex: string; expect: { rust: string; ts: string; go: string } }[];
}

const DIR = new URL("../../../examples/decisions/", import.meta.url);
export const corpus = JSON.parse(readFileSync(new URL("conformance.json", DIR), "utf8")) as Corpus;

/** The committed verdict text a vector starts from, with its exact text replacements applied. */
export function vectorText(v: Vector): string {
  let text = readFileSync(new URL(`${v.base}.json`, DIR), "utf8");
  for (const [from, to] of v.raw_replace ?? []) {
    const at = text.indexOf(from);
    assert.ok(at >= 0 && text.indexOf(from, at + 1) < 0, `${v.name}: ${JSON.stringify(from)} must occur exactly once`);
    text = text.slice(0, at) + to + text.slice(at + from.length);
  }
  return text;
}

/** Apply the vector's JSON edits to a parsed verdict (in place). */
export function applyEdits(value: unknown, edits: Edit[]): void {
  for (const e of edits) {
    let at = value as Record<string | number, unknown>;
    for (const k of e.path.slice(0, -1)) at = at[k] as Record<string | number, unknown>;
    const last = e.path[e.path.length - 1];
    if (e.op === "set") at[last] = structuredClone(e.value);
    else if (e.op === "delete") delete at[last];
    else (at[last] as unknown[]).push(structuredClone(e.value));
  }
}

function tsOutcome(v: Vector): Outcome {
  assert.ok(!(v.raw_replace && v.edits), `${v.name}: a vector is either raw text or edits, not both`);
  // Outside the try: a corpus whose replacement does not apply is a broken
  // corpus, never an "unreadable" verdict.
  const text = vectorText(v);
  let parsed: unknown;
  try {
    parsed = parseJsonStrict(text);
  } catch {
    return "unreadable";
  }
  applyEdits(parsed, v.edits ?? []);
  if (validateVerificationResult(parsed) !== null) return "unreadable";
  return isExecutable(parsed as VerificationResult) ? "executable" : "not_executable";
}

test("Round 39 corpus: every verdict vector reads in TypeScript as the corpus says", () => {
  assert.equal(corpus.version, 1);
  assert.ok(corpus.verdicts.length >= 90, `the corpus holds ${corpus.verdicts.length} verdict vectors`);
  const wrong: string[] = [];
  for (const v of corpus.verdicts) {
    const got = tsOutcome(v);
    if (got !== v.expect.ts) wrong.push(`${v.name}: expected ${v.expect.ts}, got ${got}`);
  }
  assert.deepEqual(wrong, []);
});

test("Round 39 corpus: TypeScript is never looser than the Core's rule, and every difference is explained", () => {
  for (const v of corpus.verdicts) {
    if (v.expect.ts === "executable") {
      assert.equal(v.expect.rust, "executable", `${v.name}: TS executable where the Core's rule is not`);
    }
    // Unreadable and not executable are both a refusal; a vector on which the
    // languages disagree about EXECUTABLE must say why.
    const executable = [v.expect.rust, v.expect.ts, v.expect.go].map((o) => o === "executable");
    if (executable.some((e) => e !== executable[0])) {
      assert.ok(v.note, `${v.name}: executable in one language and not another, without a note saying why`);
    }
  }
});

test("Round 39 corpus: the corpus covers every decision, every residual code and the hash versions", () => {
  const names = corpus.verdicts.map((v) => v.name).join("\n");
  for (const d of ["executable_approved", "analysis_only", "inconclusive", "blocked"]) {
    assert.ok(corpus.verdicts.some((v) => v.base === d && !v.edits && !v.raw_replace), `the unedited ${d} verdict`);
  }
  for (const code of [
    "not_simulated", "no_state_diff", "simulation_failed", "privileges_from_caller", "privileges_absent",
    "lookup_tables_unresolved", "artifact_unparsed", "account_identity_unparsed", "instruction_not_located",
    "no_artifact", "other_instructions", "fee_payer_blockhash_signers", "no_real_effects", "intent_parameters",
    "program_deployments",
  ]) {
    assert.match(names, new RegExp(`residual: ${code}, the verdict still claiming executable`));
    assert.match(names, new RegExp(`residual: ${code}, an honest analysis_only`));
  }
  assert.ok(corpus.content_hash.length >= 5 && corpus.transaction_digest.some((d) => d.hex.startsWith("81")));
});

test("Round 39 corpus: the framed v2 content hash, as the corpus pins it", () => {
  const got = new Map<string, string>();
  for (const c of corpus.content_hash) {
    let hash: string;
    try {
      hash = computeContentHash({
        programId: c.program_id,
        instructionDiscriminator: c.discriminator,
        accountAddresses: c.accounts,
        ...(c.data === null ? {} : { instructionData: c.data }),
        cpiTargets: c.cpi_targets,
      });
    } catch {
      hash = "error";
    }
    got.set(c.name, hash);
    if (c.expect !== null) assert.equal(hash, c.expect, c.name);
    else assert.match(hash, /^[0-9a-f]{16}$/, c.name);
  }
  for (const c of corpus.content_hash) {
    if (c.differs_from) assert.notEqual(got.get(c.name), got.get(c.differs_from), `${c.name} vs ${c.differs_from}`);
  }
});

test("Round 39 corpus: transaction digests (signature slots zeroed), as the corpus pins them for TypeScript", () => {
  for (const d of corpus.transaction_digest) {
    let digest: string;
    try {
      digest = transactionDigest(Uint8Array.from(Buffer.from(d.hex, "hex")));
    } catch {
      digest = "error";
    }
    assert.equal(digest, d.expect.ts, d.name);
    // Where the Core computes a digest, the SDK computes the same one or refuses.
    if (d.expect.rust !== "error") assert.ok(digest === d.expect.rust || digest === "error", `${d.name}: differs from the Core`);
  }
});
