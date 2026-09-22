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
  assert.equal(hash, "48c65c638aceb5de");
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
  assert.equal(hash, "dd8569c46af7e6c0");
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

test("projectionFromInstruction extracts discriminator from real data bytes", () => {
  // A real System transfer: discriminator 0x02 + 4-byte padding + lamports.
  const data = new Uint8Array([2, 0, 0, 0, 0xe8, 0x76, 0x48, 0x17, 0x00, 0x00, 0x00, 0x00]);
  const proj = AuditBind.projectionFromInstruction({
    programId: SYSTEM_PROGRAM,
    data,
    accounts: [FROM, TO],
  });
  assert.equal(proj.programId, SYSTEM_PROGRAM);
  assert.equal(proj.instructionDiscriminator, "02000000e8764817");
  assert.deepEqual(proj.instructionData, Array.from(data));
  assert.deepEqual(proj.accountAddresses, [FROM, TO]);
});

test("an explicit discriminator that is not a prefix of the data is refused", () => {
  // GFX-001 (2026-09-17 forensic audit). The Core used to judge the caller's
  // LABEL for an instruction rather than the instruction: declaring an unknown
  // discriminator over a real SetAuthority payload took the unknown-instruction
  // soft pass and the known-risky table never fired. This path was shielded
  // from that, but only by accident — `executeSwap` passes no discriminator,
  // so the projection was rebuilt from the bytes and the recomputed hash
  // diverged. A caller that DID pass a mismatched discriminator got a
  // projection built around the label.
  const SPL_TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
  const setAuthority = new Uint8Array([0x06, 0x02, 0x01, ...new Array(32).fill(0xaa)]);
  assert.throws(
    () =>
      AuditBind.projectionFromInstruction({
        programId: SPL_TOKEN,
        data: setAuthority,
        accounts: [FROM, TO],
        discriminator: "ff",
      }),
    /not a prefix of this instruction/,
  );
  // Case and an 0x prefix are normalised, not a reason to refuse.
  const ok = AuditBind.projectionFromInstruction({
    programId: SPL_TOKEN,
    data: setAuthority,
    accounts: [FROM, TO],
    discriminator: "0x06",
  });
  assert.equal(ok.instructionDiscriminator, "0x06");
  // And the honest System-transfer case the doc comment describes still works:
  // a 4-byte discriminator over 12 bytes of data is a prefix, so it passes.
  const transfer = new Uint8Array([2, 0, 0, 0, 0xe8, 0x76, 0x48, 0x17, 0, 0, 0, 0]);
  const sys = AuditBind.projectionFromInstruction({
    programId: SYSTEM_PROGRAM,
    data: transfer,
    accounts: [FROM, TO],
    discriminator: "02000000",
  });
  assert.equal(sys.instructionDiscriminator, "02000000");
});

test("verifyInstruction binds the exact instruction payload (swap TOCTOU closure)", () => {
  const data = new Uint8Array([2, 0, 0, 0, 0xe8, 0x76, 0x48, 0x17, 0x00, 0x00, 0x00, 0x00]);
  const hash = AuditBind.computeHash(
    AuditBind.projectionFromInstruction({
      programId: SYSTEM_PROGRAM,
      data,
      accounts: [FROM, TO],
    }),
  );
  // Identical payload → passes (no throw).
  AuditBind.verifyInstruction(
    { programId: SYSTEM_PROGRAM, data, accounts: [FROM, TO] },
    hash,
  );
  // Mutated accounts → ABORTS.
  assert.throws(
    () =>
      AuditBind.verifyInstruction(
        { programId: SYSTEM_PROGRAM, data, accounts: [FROM, TO.replace("CVfeR", "CVfeQ")] },
        hash,
      ),
    /AuditBind FAILED: hash mismatch/,
  );
  // Mutated instruction data → ABORTS.
  const mutated = new Uint8Array(data);
  mutated[4] = 0xff;
  assert.throws(
    () =>
      AuditBind.verifyInstruction(
        { programId: SYSTEM_PROGRAM, data: mutated, accounts: [FROM, TO] },
        hash,
      ),
    /AuditBind FAILED: hash mismatch/,
  );
});

test("C22 transfer binding: amount is bound via instructionData (4-byte discriminator shape)", () => {
  // The exact shape the bridge's executeTransfer now verifies and binds:
  //   programId + 4-byte discriminator ("02000000") + accounts + raw data.
  // System transfer data = 0x02 || 3 pad bytes || u64 LE lamports.
  const lamportsLE = (n: number) => {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
    return Array.from(b);
  };
  const makeData = (amount: number) => [2, 0, 0, 0, ...lamportsLE(amount)];
  const hash = AuditBind.computeHash({
    programId: SYSTEM_PROGRAM,
    instructionDiscriminator: "02000000",
    accountAddresses: [FROM, TO],
    instructionData: makeData(1_000_000_000),
  });
  // Same everything, only the amount changed (1 SOL -> 100 SOL) → hash differs.
  const mutated = AuditBind.computeHash({
    programId: SYSTEM_PROGRAM,
    instructionDiscriminator: "02000000",
    accountAddresses: [FROM, TO],
    instructionData: makeData(100_000_000_000),
  });
  assert.notEqual(mutated, hash, "amount mutation must change the content hash");
  // The pre-C22 projection (no instructionData) also must NOT equal the
  // bound hash — proving the amount was previously unbound.
  const oldProjection = AuditBind.computeHash({
    programId: SYSTEM_PROGRAM,
    instructionDiscriminator: "02000000",
    accountAddresses: [FROM, TO],
  });
  assert.notEqual(oldProjection, hash, "the old projection did not bind the amount");
  // And the bound projection verifies cleanly against its own hash.
  AuditBind.verify({
    transaction: {
      programId: SYSTEM_PROGRAM,
      instructionDiscriminator: "02000000",
      accountAddresses: [FROM, TO],
      instructionData: makeData(1_000_000_000),
    },
    contentHash: hash,
  });
});

test("verifyInstruction with no data hashes as empty instructionData (parity with Rust)", () => {
  const proj = AuditBind.projectionFromInstruction({
    programId: SYSTEM_PROGRAM,
    data: new Uint8Array(0),
    accounts: [FROM, TO],
  });
  assert.equal(proj.instructionDiscriminator, "");
  assert.equal(proj.instructionData, undefined);
  // Matches the no-data computeHash reference contract exactly.
  const hash = AuditBind.computeHash(proj);
  assert.equal(hash, AuditBind.computeHash({ programId: SYSTEM_PROGRAM, instructionDiscriminator: "", accountAddresses: [FROM, TO] }));
});
