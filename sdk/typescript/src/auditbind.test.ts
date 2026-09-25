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
  // framed v2: domain || len-prefixed program, disc, [from, to], empty data, no CPI
  assert.equal(hash, "48c65c638aceb5de");
});

test("content_hash matches the Rust reference vector (with data and CPI)", () => {
  const hash = computeContentHash({
    programId: SYSTEM_PROGRAM,
    instructionDiscriminator: TRANSFER_DISCRIMINATOR,
    accountAddresses: [FROM],
    instructionData: [1, 2, 3],
    cpiTargets: ["cpiA"],
  });
  // framed v2: domain || len-prefixed program, disc, [from], bytes(1,2,3), ["cpiA"]
  assert.equal(hash, "dd8569c46af7e6c0");
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

// ── Native programs: an explicit discriminator (Round 19, F-19-C4) ─────────

/** A real System transfer of 1_000_000 lamports: u32 LE 2, then u64 LE amount. */
const TRANSFER_1M = new Uint8Array([2, 0, 0, 0, 0x40, 0x42, 0x0f, 0, 0, 0, 0, 0]);

test("the 6d302e018b2b91ce vector: a native transfer projected with its 4-byte discriminator", () => {
  // The third cross-language vector. Pinned in the SolanaAgentKit suite
  // (toctou-signing-boundary.test.ts) and the Go SDK (auditbind_test.go) as
  // the hash graphite-core computes for this System transfer, framed v2.
  const projected = projectionFromInstruction({
    programId: SYSTEM_PROGRAM,
    data: TRANSFER_1M,
    accounts: [FROM, TO],
    discriminator: TRANSFER_DISCRIMINATOR,
  });
  assert.equal(projected.instructionDiscriminator, TRANSFER_DISCRIMINATOR);
  assert.equal(computeContentHash(projected), "6d302e018b2b91ce");
  verifyInstruction(
    { programId: SYSTEM_PROGRAM, data: TRANSFER_1M, accounts: [FROM, TO], discriminator: TRANSFER_DISCRIMINATOR },
    "6d302e018b2b91ce",
  );
  // Without it the Anchor 8-byte guess reads half the amount into the
  // discriminator and can never reproduce the Core's hash.
  const guessed = projectionFromInstruction({ programId: SYSTEM_PROGRAM, data: TRANSFER_1M, accounts: [FROM, TO] });
  assert.equal(guessed.instructionDiscriminator, "0200000040420f00");
  assert.notEqual(computeContentHash(guessed), "6d302e018b2b91ce");
});

test("an SPL Token 1-byte discriminator binds its instruction", () => {
  const SPL_TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
  // TransferChecked: tag 12, u64 amount, u8 decimals.
  const data = new Uint8Array([12, 0x10, 0x27, 0, 0, 0, 0, 0, 0, 6]);
  const ix = { programId: SPL_TOKEN, data, accounts: [FROM, TO], discriminator: "0c" };
  const approved = computeContentHash({
    programId: SPL_TOKEN,
    instructionDiscriminator: "0c",
    accountAddresses: [FROM, TO],
    instructionData: Array.from(data),
  });
  verifyInstruction(ix, approved);
  assert.throws(() => verifyInstruction({ ...ix, discriminator: undefined }, approved), AuditBindError);
});

test("GFX-001: an explicit discriminator that is not a prefix of the data is refused", () => {
  const SPL_TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
  const setAuthority = new Uint8Array([0x06, 0x02, 0x01, ...new Array(32).fill(0xaa)]);
  assert.throws(
    () => projectionFromInstruction({ programId: SPL_TOKEN, data: setAuthority, accounts: [FROM, TO], discriminator: "ff" }),
    /not a prefix of this instruction/,
  );
  assert.throws(
    () => verifyInstruction({ programId: SYSTEM_PROGRAM, data: TRANSFER_1M, accounts: [FROM, TO], discriminator: "03000000" }, "6d302e018b2b91ce"),
    AuditBindError,
  );
  // Case and a 0x prefix are normalised for the comparison; the projection
  // keeps the string as sent, because it must reproduce what Graphite hashed.
  const ok = projectionFromInstruction({ programId: SPL_TOKEN, data: setAuthority, accounts: [FROM, TO], discriminator: "0x06" });
  assert.equal(ok.instructionDiscriminator, "0x06");
  // A discriminator longer than the data cannot be its prefix.
  assert.throws(
    () => projectionFromInstruction({ programId: SYSTEM_PROGRAM, data: new Uint8Array([2]), accounts: [FROM], discriminator: "02000000" }),
    /not a prefix/,
  );
});
