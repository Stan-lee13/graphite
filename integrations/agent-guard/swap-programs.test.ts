/**
 * A5-01: `SWAP_PROGRAM_IDS` is the Core's swap set, which the Core derives
 * from the seed manifests tagged `"category": "swap"`. This reads the same
 * manifests (read-only) and fails in either direction when the tag and the
 * constant drift apart — the TypeScript twin of the Core's
 * `manifest_category_aligns_with_swap_set`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { SWAP_PROGRAM_IDS } from "./swap-programs.js";

const PROTOCOLS = new URL("../../graphite-core/protocols/", import.meta.url);
/** Not manifests (see the Core's seed-list test): skipped the same way. */
const NOT_MANIFESTS = new Set(["verified_program_ids.json", "battle_tested_evidence.json"]);

test("A5-01: SWAP_PROGRAM_IDS is exactly the seed manifests tagged as swap", () => {
  const tagged = new Set<string>();
  for (const name of readdirSync(PROTOCOLS)) {
    if (!name.endsWith(".json") || NOT_MANIFESTS.has(name)) continue;
    const manifest = JSON.parse(readFileSync(new URL(name, PROTOCOLS), "utf8")) as {
      protocol?: { program_id?: string; category?: string };
    };
    if (manifest.protocol?.category === "swap" && manifest.protocol.program_id) {
      tagged.add(manifest.protocol.program_id);
    }
  }
  assert.ok(tagged.size > 0, "expected at least one swap-tagged manifest");
  const missing = [...tagged].filter((id) => !SWAP_PROGRAM_IDS.has(id));
  const extra = [...SWAP_PROGRAM_IDS].filter((id) => !tagged.has(id));
  assert.deepEqual(missing, [], "tagged swap in a manifest, missing from SWAP_PROGRAM_IDS");
  assert.deepEqual(extra, [], "in SWAP_PROGRAM_IDS, but no seed manifest tags it as swap");
});
