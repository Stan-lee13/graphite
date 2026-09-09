/**
 * Does AuditBind protect the artifact that gets SIGNED, or a copy of it?
 *
 * The claim the integration makes is precise: "a transaction verified by
 * Graphite is the exact transaction that reaches the signing boundary, and it
 * cannot be modified after verification without detection."
 *
 * `AuditBind.verify()` takes a reconstructed projection — a program-id string,
 * a discriminator string, an array of address strings, an array of data bytes.
 * `sendAndConfirmTransaction` signs a `Transaction` built from a
 * `TransactionInstruction` OBJECT. Those are two different things, and a check
 * that hashes the first while the second is signed protects nothing: the
 * projection is a snapshot taken before the window it is supposed to cover.
 *
 * The module already has the right primitive — `verifyInstruction`, which
 * projects FROM the live instruction — so this is about which one the
 * production path calls.
 *
 * These tests mutate the instruction the way an attacker with any foothold in
 * the process would: after approval, before signing, on the object itself.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { PublicKey, SystemProgram, Transaction } from "@solana/web3.js";
import { AuditBind } from "./auditbind.js";

const WALLET = new PublicKey("7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU");
const VICTIM_DEST = new PublicKey("8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR");
const ATTACKER_DEST = new PublicKey("6bSsP4p6wXqFJdD2TkYgNcVmLzHfWq7pRyA8tCzE5nBj");

const SYSTEM_PROGRAM = "11111111111111111111111111111111";
const TRANSFER_DISCRIMINATOR = "02000000";

/** The instruction the agent builds and intends to sign. */
function buildTransfer(to: PublicKey, lamports: number) {
  return SystemProgram.transfer({
    fromPubkey: WALLET,
    toPubkey: to,
    lamports,
  });
}

/**
 * The projection the bridge reconstructs from its own local variables — the
 * shape passed to `AuditBind.verify()` on the production path.
 */
function reconstructedProjection(destination: string, data: Buffer) {
  return {
    programId: SYSTEM_PROGRAM,
    instructionDiscriminator: TRANSFER_DISCRIMINATOR,
    accountAddresses: [WALLET.toBase58(), destination],
    instructionData: Array.from(data),
  };
}

test("a snapshot projection cannot see the signed instruction being rewritten (why the bridge no longer uses one)", () => {
  const ix = buildTransfer(VICTIM_DEST, 1_000_000);

  // Verification happens here. The bridge snapshots the data bytes and the
  // destination STRING at this moment.
  const snapshotData = Buffer.from(ix.data);
  const snapshotDest = VICTIM_DEST.toBase58();
  const approvedHash = AuditBind.computeHash(
    reconstructedProjection(snapshotDest, snapshotData),
  );

  // The attack window: the approved instruction object is redirected and the
  // amount raised. Nothing else in the process changes.
  ix.keys[1].pubkey = ATTACKER_DEST;
  const drained = Buffer.alloc(12);
  drained.writeUInt32LE(2, 0);
  drained.writeBigUInt64LE(999_000_000_000n, 4);
  ix.data = drained;

  // What the production path checks: the snapshot against the approved hash.
  // It passes, because the snapshot was never touched.
  assert.doesNotThrow(
    () =>
      AuditBind.verify({
        transaction: reconstructedProjection(snapshotDest, snapshotData),
        contentHash: approvedHash,
      }),
    "the reconstructed projection is a snapshot and cannot see the mutation — this is the gap",
  );

  // And the mutated instruction is what a Transaction would carry to signing.
  const tx = new Transaction().add(ix);
  const signed = tx.instructions[0];
  assert.equal(
    signed.keys[1].pubkey.toBase58(),
    ATTACKER_DEST.toBase58(),
    "the object heading for the signer is the attacker's, while the check passed",
  );
});

test("verifyInstruction, applied to the live instruction, catches the same mutation", () => {
  const ix = buildTransfer(VICTIM_DEST, 1_000_000);

  // Bind the ACTUAL instruction at approval time.
  const approvedHash = AuditBind.computeHash(
    AuditBind.projectionFromInstruction({
      programId: ix.programId.toBase58(),
      data: ix.data,
      accounts: ix.keys.map((k) => k.pubkey.toBase58()),
    }),
  );

  ix.keys[1].pubkey = ATTACKER_DEST;

  assert.throws(
    () =>
      AuditBind.verifyInstruction(
        {
          programId: ix.programId.toBase58(),
          data: ix.data,
          accounts: ix.keys.map((k) => k.pubkey.toBase58()),
        },
        approvedHash,
      ),
    /AuditBind FAILED/,
    "binding the live instruction must detect a redirected destination",
  );
});

test("the amount alone, rewritten in place, is caught when the live instruction is bound", () => {
  const ix = buildTransfer(VICTIM_DEST, 1_000_000);
  const project = () => ({
    programId: ix.programId.toBase58(),
    data: ix.data,
    accounts: ix.keys.map((k) => k.pubkey.toBase58()),
  });
  const approvedHash = AuditBind.computeHash(
    AuditBind.projectionFromInstruction(project()),
  );

  // Same destination, same accounts, 999,000 SOL instead of 0.001.
  ix.data.writeBigUInt64LE(999_000_000_000_000n, 4);

  assert.throws(
    () => AuditBind.verifyInstruction(project(), approvedHash),
    /AuditBind FAILED/,
    "an in-place amount rewrite must be detected",
  );
});

test("an extra instruction appended after approval is detected", () => {
  // The attack Graphite's own L4 work exists for, moved to the signing
  // boundary: the approved instruction is untouched, and a second one rides
  // along. A per-instruction hash cannot see this on its own — the binding has
  // to cover the transaction's whole instruction list.
  const approved = buildTransfer(VICTIM_DEST, 1_000_000);
  const bindTransaction = (tx: Transaction) =>
    tx.instructions
      .map((ix) =>
        AuditBind.computeHash(
          AuditBind.projectionFromInstruction({
            programId: ix.programId.toBase58(),
            data: ix.data,
            accounts: ix.keys.map((k) => k.pubkey.toBase58()),
          }),
        ),
      )
      .join(":");

  const tx = new Transaction().add(approved);
  const approvedBinding = bindTransaction(tx);

  // Attacker appends a drain to the same transaction.
  tx.add(buildTransfer(ATTACKER_DEST, 999_000_000_000));

  assert.notEqual(
    bindTransaction(tx),
    approvedBinding,
    "appending an instruction after approval must change the binding",
  );
});


test("the live-instruction projection reproduces the Rust core's content_hash", () => {
  // The pinned cross-language vector. `projectionFromInstruction` used to
  // derive the discriminator from the first 8 bytes of the data, which for a
  // System transfer is `0200000040420f00` — the 4-byte discriminator plus half
  // the lamport amount — hashing to 030424ed4db245eb instead of the core's
  // 42bd6f2a33492dc2. The check could therefore never pass for a native
  // program, which is why the bridge reconstructed literals and opened the
  // window above. The discriminator is now passed explicitly.
  const ix = buildTransfer(VICTIM_DEST, 1_000_000);
  const projected = AuditBind.projectionFromInstruction({
    programId: ix.programId.toBase58(),
    data: ix.data,
    accounts: ix.keys.map((k) => k.pubkey.toBase58()),
    discriminator: TRANSFER_DISCRIMINATOR,
  });
  assert.equal(
    projected.instructionDiscriminator,
    TRANSFER_DISCRIMINATOR,
    "an explicit discriminator must win over the 8-byte Anchor guess",
  );
  assert.equal(
    AuditBind.computeHash(projected),
    "42bd6f2a33492dc2",
    "the live-instruction projection must reproduce the hash graphite-core computes for this " +
      "transfer — verified against the running server on 2026-09-08",
  );

  // And without it, the old behaviour is still visible: a different hash, so a
  // check against the core's value would abort rather than silently pass.
  const guessed = AuditBind.projectionFromInstruction({
    programId: ix.programId.toBase58(),
    data: ix.data,
    accounts: ix.keys.map((k) => k.pubkey.toBase58()),
  });
  assert.notEqual(
    AuditBind.computeHash(guessed),
    "42bd6f2a33492dc2",
    "the 8-byte guess is wrong for native programs; if this ever matches, the fallback has " +
      "silently changed meaning",
  );
});

test("transactionBinding covers additions, removals and reordering", () => {
  const project = (ix: ReturnType<typeof buildTransfer>) => ({
    programId: ix.programId.toBase58(),
    data: ix.data,
    accounts: ix.keys.map((k) => k.pubkey.toBase58()),
    discriminator: TRANSFER_DISCRIMINATOR,
  });
  const a = buildTransfer(VICTIM_DEST, 1_000_000);
  const b = buildTransfer(ATTACKER_DEST, 2_000_000);

  const one = AuditBind.transactionBinding([project(a)]);
  const appended = AuditBind.transactionBinding([project(a), project(b)]);
  const reordered = AuditBind.transactionBinding([project(b), project(a)]);

  assert.notEqual(one, appended, "an appended instruction must change the binding");
  assert.notEqual(appended, reordered, "reordering must change the binding");

  assert.throws(
    () => AuditBind.verifyTransactionUnchanged([project(a), project(b)], one),
    /instruction set changed after approval/,
    "verifyTransactionUnchanged must abort when an instruction is appended",
  );
  assert.doesNotThrow(
    () => AuditBind.verifyTransactionUnchanged([project(a)], one),
    "an unchanged transaction must still verify",
  );
});

// ── The execution binding covers privilege flags, at full length ─────────────
//
// From an independent review, 2026-09-09. `content_hash` covers programId,
// discriminator, accounts, data and CPI targets — matching the Rust core byte
// for byte — and does NOT cover isSigner/isWritable. But
// `buildInstructionFromPayload` uses those flags to build the instruction that
// executes, and Graphite checks them via `real_account_metas`. A binding that
// omitted them was checking less than the Core did.
//
// It was also 128 bits (a truncated digest). `content_hash` is 64, which is
// right for a cross-language pinned identifier and wrong for the thing standing
// between "Graphite approved this" and "the wallet signed this" — NIST SP
// 800-107 §5.1 puts a λ-bit truncated digest at λ/2 collision strength. The
// execution binding is now the full 256 bits.

test("the execution binding is a full-length digest, not a truncated one", () => {
  const ix = buildTransfer(VICTIM_DEST, 1_000_000);
  const binding = AuditBind.transactionBinding([
    {
      programId: ix.programId.toBase58(),
      data: ix.data,
      accounts: ix.keys.map((k) => k.pubkey.toBase58()),
      discriminator: TRANSFER_DISCRIMINATOR,
      accountMetas: ix.keys.map((k) => ({ isSigner: k.isSigner, isWritable: k.isWritable })),
    },
  ]);
  assert.equal(
    binding.length,
    64,
    "the execution binding must be a full 256-bit SHA-256 (64 hex chars); a truncated digest " +
      "halves collision resistance and this is the value that gates signing",
  );
  // content_hash stays 64 bits on purpose: it is the cross-language identifier
  // pinned byte-for-byte against the Rust core, not the execution binding.
  assert.equal(
    AuditBind.computeHash({
      programId: ix.programId.toBase58(),
      instructionDiscriminator: TRANSFER_DISCRIMINATOR,
      accountAddresses: ix.keys.map((k) => k.pubkey.toBase58()),
      instructionData: Array.from(ix.data),
    }).length,
    16,
    "content_hash must stay 16 hex chars or cross-language parity with the Rust core breaks",
  );
});

test("flipping a writable bit changes the execution binding", () => {
  const ix = buildTransfer(VICTIM_DEST, 1_000_000);
  const project = (metas: { isSigner: boolean; isWritable: boolean }[]) => ({
    programId: ix.programId.toBase58(),
    data: ix.data,
    accounts: ix.keys.map((k) => k.pubkey.toBase58()),
    discriminator: TRANSFER_DISCRIMINATOR,
    accountMetas: metas,
  });
  const honest = ix.keys.map((k) => ({ isSigner: k.isSigner, isWritable: k.isWritable }));
  const escalated = honest.map((m, i) => (i === 1 ? { ...m, isWritable: !m.isWritable } : m));

  const approved = AuditBind.transactionBinding([project(honest)]);
  assert.notEqual(
    AuditBind.transactionBinding([project(escalated)]),
    approved,
    "a read-only account becoming writable changes what the instruction can do and must " +
      "change the binding",
  );
  assert.throws(
    () => AuditBind.verifyTransactionUnchanged([project(escalated)], approved),
    /instruction set changed after approval/,
  );
});

test("flipping a signer bit changes the execution binding", () => {
  const ix = buildTransfer(VICTIM_DEST, 1_000_000);
  const project = (metas: { isSigner: boolean; isWritable: boolean }[]) => ({
    programId: ix.programId.toBase58(),
    data: ix.data,
    accounts: ix.keys.map((k) => k.pubkey.toBase58()),
    discriminator: TRANSFER_DISCRIMINATOR,
    accountMetas: metas,
  });
  const honest = ix.keys.map((k) => ({ isSigner: k.isSigner, isWritable: k.isWritable }));
  const forged = honest.map((m, i) => (i === 1 ? { ...m, isSigner: !m.isSigner } : m));
  assert.notEqual(
    AuditBind.transactionBinding([project(forged)]),
    AuditBind.transactionBinding([project(honest)]),
    "a non-signer becoming a signer must change the binding",
  );
});

test("absent metas and all-false metas are different bindings", () => {
  // Otherwise an integration that simply stopped supplying the flags would
  // silently produce the same digest as one asserting every account is
  // read-only and unsigned — a downgrade that looks like no change at all.
  const ix = buildTransfer(VICTIM_DEST, 1_000_000);
  const base = {
    programId: ix.programId.toBase58(),
    data: ix.data,
    accounts: ix.keys.map((k) => k.pubkey.toBase58()),
    discriminator: TRANSFER_DISCRIMINATOR,
  };
  const absent = AuditBind.transactionBinding([base]);
  const allFalse = AuditBind.transactionBinding([
    { ...base, accountMetas: ix.keys.map(() => ({ isSigner: false, isWritable: false })) },
  ]);
  assert.notEqual(
    absent,
    allFalse,
    "dropping the privilege flags must not be indistinguishable from asserting they are all off",
  );
});
