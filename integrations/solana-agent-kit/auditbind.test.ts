/**
 * AuditBind content_hash cross-language regression tests.
 *
 * The TS computeHash MUST reproduce the Rust Core's deterministic content_hash
 * byte-for-byte (graphite-core/src/verification.rs::generate_audit_id):
 *   SHA-256(programId || discriminator || accounts... || data bytes || cpis...)
 *   truncated to 16 hex chars.
 *
 * The pinned vectors below were generated from the Rust algorithm itself
 * (computed independently, e.g. `node .freebuff/compute_hash.mjs`). If the Rust
 * side ever changes the field set or ordering, BOTH sides must change together
 * and these vectors must be regenerated — a mismatch here is the TOCTOU check
 * silently failing closed (or worse, passing wrongly).
 *
 * Run: npx tsx --test auditbind.test.ts
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { AuditBind } from "./auditbind.ts";

const SYSTEM_PROGRAM = "11111111111111111111111111111111";
const TRANSFER_DISCRIMINATOR = "02000000";
const FROM = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const TO = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";

test("content_hash matches Rust reference vector (no data, no CPI)", () => {
  const hash = AuditBind.computeHash({
    programId: SYSTEM_PROGRAM,
    instructionDiscriminator: TRANSFER_DISCRIMINATOR,
    accountAddresses: [FROM, TO],
  });
  // Pinned from the Rust algorithm: sha256(program||disc||from||to)[0..16]
  assert.equal(hash, "afb61d8865b4cb68");
});

test("content_hash matches Rust reference vector (with data and CPI)", () => {
  const hash = AuditBind.computeHash({
    programId: SYSTEM_PROGRAM,
    instructionDiscriminator: TRANSFER_DISCRIMINATOR,
    accountAddresses: [FROM],
    instructionData: [1, 2, 3],
    cpiTargets: ["cpiA"],
  });
  // Pinned from the Rust algorithm: sha256(program||disc||from||bytes(1,2,3)||"cpiA")[0..16]
  assert.equal(hash, "87751f34a0f8a590");
});

test("verify() accepts a matching content_hash", () => {
  const hash = AuditBind.computeHash({
    programId: SYSTEM_PROGRAM,
    instructionDiscriminator: TRANSFER_DISCRIMINATOR,
    accountAddresses: [FROM, TO],
  });
  // Must not throw.
  AuditBind.verify({
    transaction: {
      programId: SYSTEM_PROGRAM,
      instructionDiscriminator: TRANSFER_DISCRIMINATOR,
      accountAddresses: [FROM, TO],
    },
    contentHash: hash,
  });
});

test("verify() aborts when the transaction was mutated (TOCTOU)", () => {
  const hash = AuditBind.computeHash({
    programId: SYSTEM_PROGRAM,
    instructionDiscriminator: TRANSFER_DISCRIMINATOR,
    accountAddresses: [FROM, TO],
  });
  assert.throws(
    () =>
      AuditBind.verify({
        transaction: {
          programId: SYSTEM_PROGRAM,
          instructionDiscriminator: TRANSFER_DISCRIMINATOR,
          // Destination swapped — a mutation between verification and execution.
          accountAddresses: [FROM, "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR".replace("CVfeR", "CVfeQ")],
        },
        contentHash: hash,
      }),
    /AuditBind FAILED: hash mismatch/
  );
});

test("verify() fail-closed when given audit_trail_id instead of content_hash", () => {
  assert.throws(
    () =>
      AuditBind.verify({
        transaction: {
          programId: SYSTEM_PROGRAM,
          instructionDiscriminator: TRANSFER_DISCRIMINATOR,
          accountAddresses: [FROM],
        },
        contentHash: "gr-abc12345-00000001",
      }),
    /content_hash not available/
  );
});
