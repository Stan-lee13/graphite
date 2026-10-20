/**
 * Round 29 (audit 2026-10-20, L5): the exploit-corpus builder's discriminators
 * are each program's own, at the program's own width — the ones the guard
 * sends and the seed manifests name.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parsedDiscriminator, rawSelector, SPL_TOKEN_PROGRAM, SYSTEM_PROGRAM } from "./parsed-discriminators.js";

test("L5: SPL Token transfer is 03 (not InitializeMultisig's 02); System allocate is 08000000 (not 3)", () => {
  assert.equal(parsedDiscriminator(SPL_TOKEN_PROGRAM, "transfer"), "03");
  assert.equal(parsedDiscriminator(SYSTEM_PROGRAM, "transfer"), "02000000");
  assert.equal(parsedDiscriminator(SYSTEM_PROGRAM, "allocate"), "08000000");
  assert.equal(parsedDiscriminator(SYSTEM_PROGRAM, "transferWithSeed"), "0b000000");
  assert.equal(parsedDiscriminator(SPL_TOKEN_PROGRAM, "closeAccount"), "09");
  // An unknown type is unknown, never a fabricated "00…".
  assert.equal(parsedDiscriminator(SYSTEM_PROGRAM, "somethingNew"), undefined);
  assert.equal(parsedDiscriminator(SPL_TOKEN_PROGRAM, "toString"), undefined);
  assert.equal(parsedDiscriminator("Other111111111111111111111111111111111111", "transfer"), undefined);
});

test("L5: raw selectors are cut at the program's width (System 4, SPL Token 1, Anchor 8)", () => {
  const data = Uint8Array.from([2, 0, 0, 0, 0x40, 0x42, 0x0f, 0, 0, 0, 0, 0]);
  assert.equal(rawSelector(SYSTEM_PROGRAM, data), "02000000", "not the amount's first bytes");
  assert.equal(rawSelector(SPL_TOKEN_PROGRAM, Uint8Array.from([3, 1, 2])), "03");
  assert.equal(rawSelector("Anchor1111111111111111111111111111111111111", Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8, 9])), "0102030405060708");
});

test("L5: every mapped discriminator is one the seed manifests name for that program", () => {
  const manifests = {
    [SYSTEM_PROGRAM]: "system-program.json",
    [SPL_TOKEN_PROGRAM]: "spl-token.json",
  };
  for (const [program, file] of Object.entries(manifests)) {
    const m = JSON.parse(readFileSync(new URL(`../../graphite-core/protocols/${file}`, import.meta.url), "utf8")) as {
      instructions: { discriminator: string }[];
    };
    const named = new Set(m.instructions.map((i) => i.discriminator.toLowerCase()));
    for (const type of ["transfer", "approve", "allocate", "assign", "createAccount", "closeAccount", "burn", "mintTo"]) {
      const d = parsedDiscriminator(program, type);
      if (d !== undefined) assert.ok(named.has(d), `${file} names ${type} = ${d}`);
    }
  }
});
