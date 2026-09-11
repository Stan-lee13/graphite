/**
 * Round 6: attack the boundary rather than demonstrate it.
 *
 * Three campaigns, each answering a question the previous tests did not.
 *
 * 1. `messageOf` is a SECOND implementation of Solana's compact-u16, in a second
 *    language. Two parsers of one wire format must accept the same language or
 *    the format has forked. The Rust core's ShortU16 reader accepted values up
 *    to 2,097,151 until a review caught it; this asserts the TypeScript side
 *    does not repeat that, and does not diverge in the other direction either.
 *    A malformed count that yields a PLAUSIBLE slice is the dangerous outcome —
 *    worse than one that reads out of bounds, because it silently compares the
 *    wrong range of one transaction against the right range of another.
 *
 * 2. Signer misuse. Graphite is a pre-signature gate and never verifies a
 *    signature, so nothing downstream notices the wrong key, a missing required
 *    signature, or an extra one. The requirement is read out of the message.
 *
 * 3. Property-based mutation. Hand-picked cases prove the cases someone thought
 *    of. This mutates an approved transaction at random offsets and structural
 *    positions and requires every execution-affecting change to be refused.
 *
 * Nothing here contacts a network or submits anything.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
} from "@solana/web3.js";
import { BoundTransaction, messageOf } from "./artifact.js";

const payer = Keypair.generate();
const destination = Keypair.generate().publicKey;
const BLOCKHASH = "11111111111111111111111111111111";

function transfer(lamports = 2_000_000): TransactionInstruction {
  return SystemProgram.transfer({
    fromPubkey: payer.publicKey,
    toPubkey: destination,
    lamports,
  });
}

function build(instructions = [transfer()]) {
  return BoundTransaction.build({
    instructions,
    feePayer: payer.publicKey,
    recentBlockhash: BLOCKHASH,
    lastValidBlockHeight: 1,
  });
}

function digestOf(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

/** A frame with `encoded` as its compact-u16 count and `sigs` signature slots. */
function frame(encoded: number[], sigs: number, body = [1, 2, 3, 4]): Uint8Array {
  return Uint8Array.from([...encoded, ...new Uint8Array(64 * sigs), ...body]);
}

// ── 1. messageOf: the acceptance language ──────────────────────────────────

test("messageOf accepts every legal signature count at the boundaries", () => {
  const body = [9, 9, 9];
  // Single byte: 0..127. Two bytes: 128..16383. Three: 16384..65535.
  for (const count of [0, 1, 2, 3, 127]) {
    assert.deepEqual(
      Array.from(messageOf(frame([count], count, body))),
      body,
      `count=${count}`,
    );
  }
  for (const [count, encoded] of [
    [128, [0x80, 0x01]],
    [129, [0x81, 0x01]],
    [255, [0xff, 0x01]],
    [256, [0x80, 0x02]],
  ] as [number, number[]][]) {
    assert.deepEqual(
      Array.from(messageOf(frame(encoded, count, body))),
      body,
      `count=${count}`,
    );
  }
});

test("messageOf accepts 65535 and refuses 65536", () => {
  // 65535 is the largest legal value and its canonical encoding looks like an
  // overflow vector. Refusing it would refuse legal wire format.
  const legal = Uint8Array.from([0xff, 0xff, 0x03, ...new Uint8Array(4)]);
  assert.throws(
    () => messageOf(legal),
    /runs past the transaction/,
    "65535 must be accepted as a COUNT and fail only on the missing bytes",
  );
  // 65536 is one past the type.
  assert.throws(
    () => messageOf(Uint8Array.from([0x80, 0x80, 0x04, ...new Uint8Array(4)])),
    /does not fit the u16/,
  );
});

test("messageOf refuses the maximal three-byte encoding", () => {
  assert.throws(
    () => messageOf(Uint8Array.from([0xff, 0xff, 0x7f, ...new Uint8Array(4)])),
    /does not fit the u16/,
    "2,097,151 is representable and is not a u16",
  );
});

test("messageOf refuses a count that never terminates", () => {
  // Continuation bit still set on the third byte. The earlier implementation
  // fell out of the loop here and carried on with a truncated count, reaching
  // the bounds check by luck rather than by rule.
  assert.throws(
    () => messageOf(Uint8Array.from([0x80, 0x80, 0x80, 1, 2, 3, 4])),
    /continues past its third byte/,
  );
  assert.throws(
    () => messageOf(Uint8Array.from([0xff, 0xff, 0xff, 1, 2, 3, 4])),
    /continues past its third byte/,
  );
});

test("messageOf refuses non-minimal encodings", () => {
  for (const encoded of [
    [0x80, 0x00], // 0 in two bytes
    [0x81, 0x00], // 1 in two bytes
    [0xff, 0x80, 0x00], // 127 in three bytes
  ]) {
    assert.throws(
      () => messageOf(frame(encoded, 0)),
      /not minimally encoded/,
      `${JSON.stringify(encoded)} is a second spelling of a shorter number`,
    );
  }
});

test("messageOf refuses truncated and empty input", () => {
  assert.throws(() => messageOf(Uint8Array.from([])), /truncated signature count/);
  assert.throws(() => messageOf(Uint8Array.from([0x80])), /truncated signature count/);
  assert.throws(
    () => messageOf(Uint8Array.from([0x80, 0x80])),
    /truncated signature count/,
  );
});

test("messageOf handles the exact boundary between signatures and message", () => {
  // Signature array exactly fills the input: a zero-length message, which is
  // legal framing and must not be confused with an error.
  assert.deepEqual(Array.from(messageOf(frame([1], 1, []))), []);
  // One byte short of that is an error.
  const short = frame([1], 1, []).subarray(0, 64);
  assert.throws(() => messageOf(short), /runs past the transaction/);
});

test("no malformed count ever produces a plausible slice", () => {
  // The dangerous failure is not an exception, it is a WRONG answer. Sweep
  // every one-, two- and three-byte prefix over a fixed body and require that
  // anything accepted slices at an offset the encoding actually implies.
  const body = new Uint8Array(200).fill(7);
  let accepted = 0;
  for (let a = 0; a < 256; a++) {
    for (let b = 0; b < 256; b += 17) {
      for (let c = 0; c < 256; c += 31) {
        const raw = Uint8Array.from([a, b, c, ...body]);
        let msg: Uint8Array | null = null;
        try {
          msg = messageOf(raw);
        } catch {
          continue;
        }
        accepted++;
        // Whatever came back must be a suffix of the input at an offset that
        // is a whole number of signatures past a valid count prefix.
        const offset = raw.length - msg.length;
        const headerLen = a < 0x80 ? 1 : b < 0x80 ? 2 : 3;
        assert.equal(
          (offset - headerLen) % 64,
          0,
          `offset ${offset} is not a whole number of signatures past a ${headerLen}-byte count`,
        );
      }
    }
  }
  assert.ok(accepted > 0, "the sweep accepted nothing, so it proves nothing");
  console.log(`  swept ${256 * 16 * 9} prefixes, ${accepted} accepted, all well-formed`);
});

// ── 2. Signer misuse ───────────────────────────────────────────────────────

test("signing with the wrong key is refused", () => {
  const bound = build();
  const digest = digestOf(bound.artifactBytes);
  assert.throws(
    () => bound.signApproved(digest, [Keypair.generate()]),
    /signer set does not match/,
  );
});

test("signing with an extra signer is refused", () => {
  const bound = build();
  const digest = digestOf(bound.artifactBytes);
  assert.throws(
    () => bound.signApproved(digest, [payer, Keypair.generate()]),
    /signer set does not match/,
    "an unexpected signer changes who authorized this",
  );
});

test("signing with no signers is refused", () => {
  const bound = build();
  const digest = digestOf(bound.artifactBytes);
  assert.throws(() => bound.signApproved(digest, []), /signer set does not match/);
});

test("a transaction requiring two signers refuses a partial set", () => {
  const cosigner = Keypair.generate();
  const twoSigners = new TransactionInstruction({
    programId: SystemProgram.programId,
    keys: [
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: cosigner.publicKey, isSigner: true, isWritable: false },
      { pubkey: destination, isSigner: false, isWritable: true },
    ],
    data: Buffer.from([2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
  });
  const bound = build([twoSigners]);
  const digest = digestOf(bound.artifactBytes);

  assert.throws(
    () => bound.signApproved(digest, [payer]),
    /signer set does not match/,
    "one of two required signatures is not the approved transaction",
  );
  // The complete set, in either order, is accepted.
  const raw = bound.signApproved(digest, [cosigner, payer]);
  assert.deepEqual(Array.from(messageOf(raw)), Array.from(bound.messageBytes));
});

// ── 3. Property-based mutation ─────────────────────────────────────────────

test("no byte-level mutation of the approved artifact survives the digest", () => {
  // Not a claim about the transaction object — a claim about SHA-256 — but it
  // is the property the whole gate rests on, and it costs little to pin.
  const bound = build([transfer(), transfer(3)]);
  const approved = digestOf(bound.artifactBytes);
  let checked = 0;
  for (let i = 0; i < bound.artifactBytes.length; i += 7) {
    for (const bit of [0x01, 0x80]) {
      const mutated = Uint8Array.from(bound.artifactBytes);
      mutated[i] ^= bit;
      assert.notEqual(digestOf(mutated), approved, `byte ${i} bit ${bit}`);
      checked++;
    }
  }
  assert.ok(checked > 50, `only ${checked} mutations tested`);
  console.log(`  ${checked} single-bit mutations, none collided`);
});

test("structural mutations of the live object are all refused", () => {
  // Each entry mutates the approved transaction through a reference an attacker
  // with any foothold would hold, then requires the gate to refuse.
  const mutations: [string, (b: BoundTransaction) => void][] = [
    ["blockhash", (b) => { b.tx.recentBlockhash = "So11111111111111111111111111111111111111112"; }],
    ["fee payer", (b) => { b.tx.feePayer = Keypair.generate().publicKey; }],
    ["append instruction", (b) => { b.tx.add(transfer(1)); }],
    ["drop instruction", (b) => { b.tx.instructions.pop(); }],
    ["reorder instructions", (b) => { b.tx.instructions.reverse(); }],
    ["instruction data", (b) => { b.tx.instructions[0].data[4] ^= 0xff; }],
    ["program id", (b) => { b.tx.instructions[0].programId = Keypair.generate().publicKey; }],
    ["account pubkey", (b) => { b.tx.instructions[0].keys[1].pubkey = Keypair.generate().publicKey; }],

    ["swap account order", (b) => { b.tx.instructions[0].keys.reverse(); }],
    ["append account", (b) => {
      b.tx.instructions[0].keys.push({
        pubkey: Keypair.generate().publicKey,
        isSigner: false,
        isWritable: true,
      });
    }],
  ];

  // Privilege flags get their own single-instruction cases below: with two
  // instructions touching the same account, web3.js UNIONS the metas at compile
  // time, so lowering one instruction's flag changes nothing about the compiled
  // message. See `per_instruction_privilege_flags_are_compilation_inputs`.
  mutations.push([
    "isWritable (single instruction)",
    (b) => { b.tx.instructions[0].keys[1].isWritable = false; },
  ]);
  mutations.push([
    "isSigner (single instruction)",
    (b) => { b.tx.instructions[0].keys[1].isSigner = true; },
  ]);

  for (const [label, mutate] of mutations) {
    const single = label.includes("single instruction");
    const bound = single ? build([transfer()]) : build([transfer(), transfer(3)]);
    const digest = digestOf(bound.artifactBytes);
    mutate(bound);
    assert.throws(
      () => bound.signApproved(digest, [payer]),
      /changed between approval and signing|signer set does not match/,
      `${label}: an execution-affecting mutation reached the signature`,
    );
  }
  console.log(`  ${mutations.length} structural mutations, all refused`);
});

/**
 * Per-instruction privilege flags are inputs to compilation, not facts about
 * execution — and the digest binds the compiled message.
 *
 * This surfaced as a failing assertion in the campaign above: lowering
 * `isWritable` on one of two instructions that share an account did NOT change
 * the digest, and the first reading of that is a hole. It is the opposite.
 * Solana's privileges are per-MESSAGE: an account writable in the compiled
 * message is writable for every instruction that receives it, so web3.js unions
 * the metas and the lowered flag is discarded before the bytes exist. An
 * unchanged compiled message is unchanged execution, and a gate that refused
 * here would be refusing a transaction that is byte-identical to the approved
 * one.
 *
 * Worth pinning because the reasoning runs the other way from intuition, and
 * because the Core agrees with it for the same reason: it derives privileges
 * from the message HEADER, which is the compiled view, not from per-instruction
 * flags.
 */
test("per_instruction_privilege_flags_are_compilation_inputs", () => {
  const shared = destination;
  const readonlyFirst = new TransactionInstruction({
    programId: SystemProgram.programId,
    keys: [
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: shared, isSigner: false, isWritable: false },
    ],
    data: Buffer.from([2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]),
  });
  const writableSecond = new TransactionInstruction({
    programId: SystemProgram.programId,
    keys: [
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: shared, isSigner: false, isWritable: true },
    ],
    data: Buffer.from([2, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0]),
  });

  const bound = build([readonlyFirst, writableSecond]);
  const digest = digestOf(bound.artifactBytes);

  // The union already happened: the account is writable in the compiled
  // message despite instruction 0 asking for read-only.
  const compiled = bound.tx.compileMessage();
  const index = compiled.accountKeys.findIndex((k) => k.equals(shared));
  assert.ok(compiled.isAccountWritable(index), "the union makes it writable");

  // So lowering instruction 0's flag changes nothing that executes, and the
  // gate correctly does not refuse it.
  bound.tx.instructions[0].keys[1].isWritable = false;
  assert.doesNotThrow(() => bound.signApproved(digest, [payer]));

  // Lowering it on the instruction that actually determines the union DOES
  // change the message, and is refused.
  const other = build([readonlyFirst, writableSecond]);
  const otherDigest = digestOf(other.artifactBytes);
  other.tx.instructions[1].keys[1].isWritable = false;
  assert.throws(
    () => other.signApproved(otherDigest, [payer]),
    /changed between approval and signing/,
  );
});

test("mutation through an ALIASED instruction reference is refused", () => {
  // The caller keeps its own handle on the instruction it passed in. JavaScript
  // shares that object by reference, so `BoundTransaction` holding it is not
  // the caller giving it up. This is the realistic shape: a plugin or helper
  // that kept a pointer.
  const ix = transfer();
  const bound = build([ix]);
  const digest = digestOf(bound.artifactBytes);

  ix.data.writeBigUInt64LE(900_000_000n, 4); // drained through the alias
  assert.throws(
    () => bound.signApproved(digest, [payer]),
    /changed between approval and signing/,
    "an alias the caller kept must not be a way around the gate",
  );
});

test("mutation through an aliased AccountMeta is refused", () => {
  const ix = transfer();
  const keys = ix.keys;
  const bound = build([ix]);
  const digest = digestOf(bound.artifactBytes);

  keys[1].pubkey = Keypair.generate().publicKey;
  assert.throws(
    () => bound.signApproved(digest, [payer]),
    /changed between approval and signing/,
  );
});

test("the honest control still passes after all of that", () => {
  // Anti-vacuity for every refusal above: if the gate refused everything, each
  // of those assertions would hold for the wrong reason.
  const bound = build([transfer(), transfer(3)]);
  const raw = bound.signApproved(digestOf(bound.artifactBytes), [payer]);
  assert.deepEqual(Array.from(messageOf(raw)), Array.from(bound.messageBytes));
});
