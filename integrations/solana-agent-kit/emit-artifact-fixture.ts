/**
 * Emit the exact artifact and sibling declarations this bridge sends, so the
 * Rust Core can assert against them.
 *
 * The bridge and the Core are two implementations of one agreement: the bridge
 * serializes a transaction and describes its instructions, and the Core reads
 * both and decides whether they agree. A test on either side alone proves only
 * that it is self-consistent. This writes the TypeScript side's real output to
 * a fixture the Rust side consumes, so a change to either that breaks the
 * agreement fails a test rather than an integration.
 *
 * Run: npx tsx emit-artifact-fixture.ts   (regenerates the committed fixture)
 *
 * Deterministic on purpose — fixed keypairs, a fixed blockhash — so the
 * committed fixture only changes when the encoding does.
 */

import { writeFileSync } from "node:fs";
import {
  Keypair,
  PublicKey,
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
const BLOCKHASH = "11111111111111111111111111111111";

// Fixed seeds: the fixture must not change when nothing about the encoding has.
const payer = Keypair.fromSeed(Uint8Array.from({ length: 32 }, (_, i) => i + 1));
const destination = Keypair.fromSeed(
  Uint8Array.from({ length: 32 }, (_, i) => 200 - i),
).publicKey;

const transferData = Buffer.alloc(12);
transferData.writeUInt32LE(2, 0);
transferData.writeBigUInt64LE(2_000_000n, 4);
const transfer = new TransactionInstruction({
  programId: SYSTEM,
  keys: [
    { pubkey: payer.publicKey, isSigner: true, isWritable: true },
    { pubkey: destination, isSigner: false, isWritable: true },
  ],
  data: transferData,
});

const limitData = Buffer.alloc(5);
limitData.writeUInt8(2, 0);
limitData.writeUInt32LE(200_000, 1);
const computeLimit = new TransactionInstruction({
  programId: COMPUTE_BUDGET,
  keys: [],
  data: limitData,
});

const priceData = Buffer.alloc(9);
priceData.writeUInt8(3, 0);
priceData.writeBigUInt64LE(1_000n, 1);
const computePrice = new TransactionInstruction({
  programId: COMPUTE_BUDGET,
  keys: [],
  data: priceData,
});

// The shape of nearly every real Solana transaction: a compute budget pair in
// front of the instruction that does the work.
const instructions = [computeLimit, computePrice, transfer];

const primary = {
  programId: SYSTEM.toBase58(),
  instructionDiscriminator: "02000000",
  accountAddresses: [payer.publicKey.toBase58(), destination.toBase58()],
};
const primaryIndex = findPrimaryIndex(instructions, primary);
if (primaryIndex < 0) {
  throw new Error("the fixture's primary instruction must be found");
}

const fixture = {
  _: "Emitted by integrations/solana-agent-kit/emit-artifact-fixture.ts. The " +
    "artifact and declarations the SAK bridge really sends, so the Rust Core " +
    "can assert the two sides agree. Unsigned: Graphite verifies before signing.",
  primary: {
    program_id: primary.programId,
    instruction_discriminator: primary.instructionDiscriminator,
    account_addresses: primary.accountAddresses,
    instruction_data: Array.from(transferData),
    real_account_metas: realAccountMetas(transfer),
  },
  signed_transaction: serializeUnsignedArtifact({
    instructions,
    feePayer: payer.publicKey,
    recentBlockhash: BLOCKHASH,
  }),
  transaction_instructions: declareSiblings(instructions, primaryIndex),
  instruction_count: instructions.length,
};

const out = "../../graphite-core/fixtures/artifacts/sak_bridge_artifact.json";
writeFileSync(new URL(out, import.meta.url), JSON.stringify(fixture, null, 2) + "\n");
console.log(
  `wrote ${out}: ${fixture.signed_transaction.length} bytes, ` +
    `${fixture.instruction_count} instructions, ` +
    `${fixture.transaction_instructions.length} declared siblings`,
);
