/**
 * Round 29 (audit 2026-10-20, L3): `SWAP_PROGRAM_IDS` is the set of programs
 * whose swap instruction the guard decodes, and it must be a SUBSET of the
 * Core's swap set — the seed manifests tagged `"category": "swap"`, which the
 * Core's `risk_engine::is_swap_program` reads. A program the guard would
 * build a swap for but the Core does not count as swapping could never be
 * approved. The converse used to be asserted too (the guard's list WAS the
 * Core's set); it is not any more, by design: the Core's set includes
 * programs that do not swap at all, and their categories are being corrected
 * separately.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { SWAP_PROGRAM_IDS } from "./swap-programs.js";

const PROTOCOLS = new URL("../../graphite-core/protocols/", import.meta.url);
/** Not manifests (see the Core's seed-list test): skipped the same way. */
const NOT_MANIFESTS = new Set(["verified_program_ids.json", "battle_tested_evidence.json"]);

function coreSwapSet(): Set<string> {
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
  return tagged;
}

test("L3: every program the guard builds a swap for is in the Core's swap set", () => {
  const tagged = coreSwapSet();
  assert.ok(tagged.size > 0, "expected at least one swap-tagged manifest");
  const outside = [...SWAP_PROGRAM_IDS].filter((id) => !tagged.has(id));
  assert.deepEqual(outside, [], "in SWAP_PROGRAM_IDS, but no seed manifest tags it as swap");
});

test("L3: the guard's swap set is exactly the decoded programs, and none of the non-swaps", () => {
  assert.deepEqual([...SWAP_PROGRAM_IDS].sort(), [
    "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8", // Raydium AMM v4
    "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK", // Raydium CLMM
    "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C", // Raydium CPMM
    "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4", // Jupiter v6
    "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo", // Meteora DLMM
    "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc", // Orca Whirlpools
  ]);
  // The audit's examples of what the old list held: DCA, limit orders, perps,
  // a bridge, a liquidity locker, Arcium, Helium sub-DAOs, futarchy, GMX store,
  // a launchpad.
  for (const id of [
    "DCA265Vj8a9CEuX1eb1LWRnDT7uK6q1xMipnNyatn23M",
    "jupoNjAxXgZ4rjzxzPMP4oxduvQsQtZzyknqvzYNrNu",
    "PERPHjGBqRHArX4DySjwM6UJHiR3sWAatqfdBS2qQJu",
    "FCW1uBM3pZ7fQWvEL9sxTe4fNiH41bu9DWX4ErTZ6aMq",
    "LockrWmn6K5twhz3y9w1dQERbmgSaRkfnTeTKbpofwE",
    "Arcj82pX7HxYKLR92qvgZUAd7vGS1k4hQvAFcPATFdEQ",
    "hdaoVTCqhfHHo75XdAMxBKdUqvq1i5bF23sisBqVgGR",
    "FUTARELBfJfQ8RDGhg1wdhddq1odMAJUePHFuBYfUxKq",
    "Gmso1uvJnLbawvw7yezdfCDcPydwW2s2iqG3w6MDucLo",
    "LanMV9sAd7wArD4vJFi2qDdfnVhFxYSUg6eADduJ3uj",
  ]) {
    assert.equal(SWAP_PROGRAM_IDS.has(id), false, id);
  }
});
