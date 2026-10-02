/**
 * The artifact this bridge sends must be the transaction it is about to run.
 *
 * These are the properties the Rust Core depends on and cannot check for us:
 * that the bytes deserialize as a Solana message at all, that the instructions
 * survive the round trip unchanged, that the primary is identified the same way
 * the Core identifies it, and that the sibling declarations describe the
 * instructions actually present rather than a convenient subset.
 *
 * Nothing here signs, sends, or contacts a network.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
import {
  serializeUnsignedArtifact,
  findPrimaryIndex,
  declareSiblings,
  realAccountMetas,
} from "./artifact.js";

const SYSTEM = new PublicKey("11111111111111111111111111111111");
const COMPUTE_BUDGET = new PublicKey(
  "ComputeBudget111111111111111111111111111111",
);
// A blockhash is 32 bytes of base58; any valid pubkey-shaped string serializes.
const BLOCKHASH = "11111111111111111111111111111111";

const payer = Keypair.generate();
const destination = Keypair.generate().publicKey;

/** System transfer of 2_000_000 lamports: 0x02 then a u64 LE amount. */
function transfer(): TransactionInstruction {
  const data = Buffer.alloc(12);
  data.writeUInt32LE(2, 0);
  data.writeBigUInt64LE(2_000_000n, 4);
  return new TransactionInstruction({
    programId: SYSTEM,
    keys: [
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: destination, isSigner: false, isWritable: true },
    ],
    data,
  });
}

/** SetComputeUnitLimit: 0x02 then a u32. Takes no accounts. */
function computeLimit(): TransactionInstruction {
  const data = Buffer.alloc(5);
  data.writeUInt8(2, 0);
  data.writeUInt32LE(200_000, 1);
  return new TransactionInstruction({
    programId: COMPUTE_BUDGET,
    keys: [],
    data,
  });
}

const PRIMARY = {
  programId: SYSTEM.toBase58(),
  instructionDiscriminator: "02000000",
  accountAddresses: [payer.publicKey.toBase58(), destination.toBase58()],
};

test("the serialized artifact deserializes as a Solana transaction", () => {
  const bytes = serializeUnsignedArtifact({
    instructions: [computeLimit(), transfer()],
    feePayer: payer.publicKey,
    recentBlockhash: BLOCKHASH,
  });
  assert.ok(bytes.length > 0);

  const back = Transaction.from(Buffer.from(bytes));
  assert.equal(back.instructions.length, 2);
  assert.equal(
    back.instructions[1].programId.toBase58(),
    SYSTEM.toBase58(),
    "the transfer must survive the round trip in the same position",
  );
  assert.deepEqual(
    Array.from(back.instructions[1].data),
    Array.from(transfer().data),
    "the amount is in the data and must not be altered by serialization",
  );
  assert.equal(
    back.instructions[1].keys[1].pubkey.toBase58(),
    destination.toBase58(),
    "the destination must survive the round trip",
  );
});

test("an unsigned artifact is what gets sent — Graphite verifies before signing", () => {
  const bytes = serializeUnsignedArtifact({
    instructions: [transfer()],
    feePayer: payer.publicKey,
    recentBlockhash: BLOCKHASH,
  });
  const back = Transaction.from(Buffer.from(bytes));
  assert.equal(back.signatures.length, 1, "one signature slot for the payer");
  assert.equal(
    back.signatures[0].signature,
    null,
    "and it is empty: nothing here signs anything",
  );
});

test("the primary instruction is found wherever it sits", () => {
  assert.equal(findPrimaryIndex([transfer()], PRIMARY), 0);
  assert.equal(findPrimaryIndex([computeLimit(), transfer()], PRIMARY), 1);
  assert.equal(
    findPrimaryIndex([computeLimit(), computeLimit()], PRIMARY),
    -1,
    "a described instruction that is not present must be reported, not guessed at",
  );
});

test("a different destination is a different primary", () => {
  const elsewhere = new TransactionInstruction({
    programId: SYSTEM,
    keys: [
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      {
        pubkey: Keypair.generate().publicKey,
        isSigner: false,
        isWritable: true,
      },
    ],
    data: transfer().data,
  });
  assert.equal(
    findPrimaryIndex([elsewhere], PRIMARY),
    -1,
    "same program, same data, another destination: not the described instruction",
  );
});

test("siblings are every instruction except the primary, described from the bytes", () => {
  const instructions = [computeLimit(), transfer(), computeLimit()];
  const siblings = declareSiblings(instructions, 1);
  assert.equal(siblings.length, 2);
  for (const s of siblings) {
    assert.equal(s.program_id, COMPUTE_BUDGET.toBase58());
    assert.deepEqual(s.account_addresses, []);
    assert.equal(
      s.instruction_discriminator,
      Buffer.from(computeLimit().data).toString("hex"),
      "the declaration carries the instruction's full data, so the Core's " +
        "prefix match succeeds and a manifest selector still resolves",
    );
  }
});

test("two identical siblings produce two declarations", () => {
  // One declaration covering both would leave a real instruction unexamined
  // while the count looked right — the Core spends each declaration once.
  const siblings = declareSiblings(
    [transfer(), computeLimit(), computeLimit()],
    0,
  );
  assert.equal(siblings.length, 2);
});

test("no primary found still declares every instruction", () => {
  // -1 matches no index, so nothing is excluded. The Core then reports that the
  // described instruction is not in these bytes, which is the truth and is not
  // this bridge's call to suppress.
  const siblings = declareSiblings([computeLimit(), transfer()], -1);
  assert.equal(siblings.length, 2);
});

test("account metas are read off the instruction, in its own order", () => {
  const metas = realAccountMetas(transfer());
  assert.deepEqual(metas, [
    { is_signer: true, is_writable: true },
    { is_signer: false, is_writable: true },
  ]);
});
