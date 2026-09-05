/**
 * Cross-language parity + misuse tests for the SDK's AuditBind.
 *
 * The whole mechanism is worthless unless this TypeScript implementation
 * reproduces the Rust core's `content_hash` byte for byte. That is not
 * hypothetical: an earlier implementation used a `"|"`-joined encoding that
 * never matched the Rust byte stream, so the TOCTOU check could never pass
 * and always aborted. The vectors below are pinned against the Rust algorithm
 * (graphite-core/src/verification.rs::generate_audit_id) and are the same
 * values asserted by the SolanaAgentKit integration's own suite — if the two
 * implementations ever drift, one of these fails.
 *
 * Run: npx tsx --test src/auditbind.test.ts
 */
import test from "node:test";
import assert from "node:assert/strict";
import {
  AuditBindError,
  computeContentHash,
  projectionFromInstruction,
  verifyContentHash,
  verifyInstruction,
} from "./auditbind.js";

const SYSTEM_PROGRAM = "11111111111111111111111111111111";
const TRANSFER_DISCRIMINATOR = "02000000";
const FROM = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const TO = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";

test("content_hash matches the Rust reference vector (no data, no CPI)", () => {
  const hash = computeContentHash({
    programId: SYSTEM_PROGRAM,
    instructionDiscriminator: TRANSFER_DISCRIMINATOR,
    accountAddresses: [FROM, TO],
  });
  // sha256(program || disc || from || to)[0..16]
  assert.equal(hash, "afb61d8865b4cb68");
});

test("content_hash matches the Rust reference vector (with data and CPI)", () => {
  const hash = computeContentHash({
    programId: SYSTEM_PROGRAM,
    instructionDiscriminator: TRANSFER_DISCRIMINATOR,
    accountAddresses: [FROM],
    instructionData: [1, 2, 3],
    cpiTargets: ["cpiA"],
  });
  // sha256(program || disc || from || bytes(1,2,3) || "cpiA")[0..16]
  assert.equal(hash, "87751f34a0f8a590");
});

test("verifyContentHash accepts the exact verified transaction", () => {
  const tx = {
    programId: SYSTEM_PROGRAM,
    instructionDiscriminator: TRANSFER_DISCRIMINATOR,
    accountAddresses: [FROM, TO],
  };
  verifyContentHash(tx, computeContentHash(tx));
});

// ── The attacks this exists to stop ────────────────────────────────────────

test("a swapped destination account is caught", () => {
  const verified = {
    programId: SYSTEM_PROGRAM,
    instructionDiscriminator: TRANSFER_DISCRIMINATOR,
    accountAddresses: [FROM, TO],
  };
  const approved = computeContentHash(verified);
  const attacker = "9wDJULnQ6to8Z8kYqxJy9hrrwX8G4WmNy8G6pqm5m6X7";
  assert.throws(
    () => verifyContentHash({ ...verified, accountAddresses: [FROM, attacker] }, approved),
    AuditBindError,
    "redirecting funds to an attacker address must abort",
  );
});

test("a mutated amount (instruction data) is caught", () => {
  const verified = {
    programId: SYSTEM_PROGRAM,
    instructionDiscriminator: TRANSFER_DISCRIMINATOR,
    accountAddresses: [FROM, TO],
    instructionData: [2, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0],
  };
  const approved = computeContentHash(verified);
  const inflated = { ...verified, instructionData: [2, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0] };
  assert.throws(
    () => verifyContentHash(inflated, approved),
    AuditBindError,
    "changing the transfer amount must abort",
  );
});

test("account REORDERING is caught (hash is order-sensitive)", () => {
  const verified = {
    programId: SYSTEM_PROGRAM,
    instructionDiscriminator: TRANSFER_DISCRIMINATOR,
    accountAddresses: [FROM, TO],
  };
  const approved = computeContentHash(verified);
  assert.throws(
    () => verifyContentHash({ ...verified, accountAddresses: [TO, FROM] }, approved),
    AuditBindError,
    "swapping source and destination must abort",
  );
});

test("a substituted program id is caught", () => {
  const verified = {
    programId: SYSTEM_PROGRAM,
    instructionDiscriminator: TRANSFER_DISCRIMINATOR,
    accountAddresses: [FROM, TO],
  };
  const approved = computeContentHash(verified);
  assert.throws(
    () =>
      verifyContentHash(
        { ...verified, programId: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" },
        approved,
      ),
    AuditBindError,
  );
});

test("an injected CPI target is caught", () => {
  const verified = {
    programId: SYSTEM_PROGRAM,
    instructionDiscriminator: TRANSFER_DISCRIMINATOR,
    accountAddresses: [FROM],
  };
  const approved = computeContentHash(verified);
  assert.throws(
    () => verifyContentHash({ ...verified, cpiTargets: ["evilProgram"] }, approved),
    AuditBindError,
  );
});

// ── Misuse must fail closed, never silently pass ───────────────────────────

test("passing audit_trail_id instead of content_hash aborts rather than no-oping", () => {
  const tx = {
    programId: SYSTEM_PROGRAM,
    instructionDiscriminator: TRANSFER_DISCRIMINATOR,
    accountAddresses: [FROM, TO],
  };
  assert.throws(
    () => verifyContentHash(tx, "gr-622ce548dab9f32d-00000000"),
    AuditBindError,
    "audit_trail_id is not client-reproducible — accepting it would mean never detecting a mutation",
  );
});

test("an empty content_hash aborts", () => {
  const tx = {
    programId: SYSTEM_PROGRAM,
    instructionDiscriminator: TRANSFER_DISCRIMINATOR,
    accountAddresses: [FROM, TO],
  };
  assert.throws(() => verifyContentHash(tx, ""), AuditBindError);
});

// ── Instruction-level binding ──────────────────────────────────────────────

test("projectionFromInstruction derives the discriminator from real data bytes", () => {
  const data = new Uint8Array([2, 0, 0, 0, 232, 118, 72, 23]);
  const proj = projectionFromInstruction({
    programId: SYSTEM_PROGRAM,
    data,
    accounts: [FROM, TO],
  });
  assert.equal(proj.programId, SYSTEM_PROGRAM);
  assert.equal(proj.instructionDiscriminator, "02000000e8764817");
  assert.deepEqual(proj.accountAddresses, [FROM, TO]);
});

test("verifyInstruction binds the exact submitted instruction", () => {
  const ix = {
    programId: SYSTEM_PROGRAM,
    data: new Uint8Array([2, 0, 0, 0, 232, 118, 72, 23]),
    accounts: [FROM, TO],
  };
  const approved = computeContentHash(projectionFromInstruction(ix));
  verifyInstruction(ix, approved);

  const tampered = { ...ix, accounts: [FROM, "9wDJULnQ6to8Z8kYqxJy9hrrwX8G4WmNy8G6pqm5m6X7"] };
  assert.throws(() => verifyInstruction(tampered, approved), AuditBindError);
});

test("an instruction with no data still hashes consistently", () => {
  const ix = { programId: SYSTEM_PROGRAM, data: new Uint8Array(0), accounts: [FROM] };
  const approved = computeContentHash(projectionFromInstruction(ix));
  verifyInstruction(ix, approved);
});
