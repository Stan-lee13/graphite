/**
 * Round 29 (audit 2026-10-20, M6 / S1): `.env.example` said it listed every
 * variable the adapter reads and left out GRAPHITE_MAX_TRANSFER_LAMPORTS,
 * GRAPHITE_ALLOWED_DESTINATIONS and GRAPHITE_TRANSACTION_VERSION. This reads
 * every environment name the adapter and the guard's modules mention and
 * requires each in the example, so a new variable cannot be added silently.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";

const GUARD = new URL("../agent-guard/", import.meta.url);
const NAME = /\b(?:GRAPHITE|SOLANA|OPENAI)_[A-Z0-9_]+\b/g;
/** Names that are refused rather than read (env-names.ts), and test-only names. */
const NOT_READ = new Set(["GRAPHITE_SERVER_URL", "GRAPHITE_URL", "GRAPHITE_TOOL_APPROVAL"]);

test("M6: .env.example lists every variable the adapter and the guard read", () => {
  const sources = [
    readFileSync(new URL("./graphite-sak-bridge.ts", import.meta.url), "utf8"),
    ...readdirSync(GUARD)
      .filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts") && !/^(emit-|mainnet-|devnet-|build_)/.test(f))
      .map((f) => readFileSync(new URL(f, GUARD), "utf8")),
  ];
  const read = new Set<string>();
  for (const s of sources) {
    for (const m of s.matchAll(/(?:process\.)?env\.([A-Z0-9_]+)|"((?:GRAPHITE|SOLANA)_[A-Z0-9_]+)"/g)) {
      const name = m[1] ?? m[2];
      if (name && NAME.test(name) && !NOT_READ.has(name)) read.add(name);
      NAME.lastIndex = 0;
    }
  }
  const example = readFileSync(new URL("./.env.example", import.meta.url), "utf8");
  const listed = new Set(
    example
      .split("\n")
      .map((l) => /^#?\s*([A-Z0-9_]+)=/.exec(l)?.[1])
      .filter((n): n is string => n !== undefined),
  );
  for (const name of ["GRAPHITE_MAX_TRANSFER_LAMPORTS", "GRAPHITE_ALLOWED_DESTINATIONS", "GRAPHITE_TRANSACTION_VERSION"]) {
    assert.ok(read.has(name), `the scan finds ${name}`);
  }
  const missing = [...read].filter((n) => !listed.has(n)).sort();
  assert.deepEqual(missing, [], "read by the code, missing from .env.example");
});
