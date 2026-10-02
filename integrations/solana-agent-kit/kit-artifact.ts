/**
 * The unsigned artifact, compiled by `@solana/kit` (roadmap gap R-P8, phase 1).
 *
 * The bridge compiles its transactions with `@solana/web3.js` 1.x, which cannot
 * build a version-1 message. `@solana/kit` 8 can (legacy, v0 and v1). Before any
 * bytes the Core verifies come from kit, kit has to be shown to produce the SAME
 * bytes web3.js produces for every legacy and v0 transaction the bridge builds:
 * the Core's verdict is bound to bytes, and a second compiler that orders an
 * account or a lookup entry differently would be a second transaction.
 *
 * This module is that second compiler, taking the inputs the bridge already
 * has (web3.js instructions, fee payer, blockhash, lookup-table accounts) so
 * `kit-artifact.test.ts` can compare the two byte for byte. Nothing here signs,
 * sends or reads an account.
 */
import {
  AccountRole,
  address,
  appendTransactionMessageInstructions,
  compileTransaction,
  compressTransactionMessageUsingAddressLookupTables,
  createTransactionMessage,
  getTransactionEncoder,
  pipe,
  setTransactionMessageFeePayer,
  setTransactionMessageLifetimeUsingBlockhash,
  type Address,
  type Blockhash,
  type Instruction,
} from "@solana/kit";
import type { AddressLookupTableAccount, PublicKey, TransactionInstruction } from "@solana/web3.js";

/** The kit role for a web3.js account meta. */
function roleOf(isSigner: boolean, isWritable: boolean): AccountRole {
  if (isSigner) return isWritable ? AccountRole.WRITABLE_SIGNER : AccountRole.READONLY_SIGNER;
  return isWritable ? AccountRole.WRITABLE : AccountRole.READONLY;
}

/** A web3.js instruction as a kit instruction, field for field. */
export function toKitInstruction(ix: TransactionInstruction): Instruction {
  return {
    programAddress: address(ix.programId.toBase58()),
    accounts: ix.keys.map((k) => ({
      address: address(k.pubkey.toBase58()),
      role: roleOf(k.isSigner, k.isWritable),
    })),
    data: Uint8Array.from(ix.data),
  };
}

/**
 * The unsigned wire bytes of a legacy or v0 transaction, compiled by kit:
 * every signature slot is 64 zero bytes, as the web3.js path produces.
 */
export function compileUnsignedWithKit(params: {
  instructions: TransactionInstruction[];
  feePayer: PublicKey;
  recentBlockhash: string;
  lastValidBlockHeight: number;
  version: "legacy" | 0;
  addressLookupTables?: AddressLookupTableAccount[];
}): Uint8Array {
  const tables = params.addressLookupTables ?? [];
  if (params.version === "legacy" && tables.length > 0) {
    throw new Error("kit-artifact: lookup tables were given for a legacy message, which cannot read them");
  }
  const feePayer = address(params.feePayer.toBase58()) as Address;
  const lifetime = {
    blockhash: params.recentBlockhash as Blockhash,
    lastValidBlockHeight: BigInt(params.lastValidBlockHeight),
  };
  const instructions = params.instructions.map(toKitInstruction);
  if (params.version === "legacy") {
    const message = pipe(
      createTransactionMessage({ version: "legacy" }),
      (m) => setTransactionMessageFeePayer(feePayer, m),
      (m) => setTransactionMessageLifetimeUsingBlockhash(lifetime, m),
      (m) => appendTransactionMessageInstructions(instructions, m),
    );
    return Uint8Array.from(getTransactionEncoder().encode(compileTransaction(message)));
  }
  const base = pipe(
    createTransactionMessage({ version: 0 }),
    (m) => setTransactionMessageFeePayer(feePayer, m),
    (m) => setTransactionMessageLifetimeUsingBlockhash(lifetime, m),
    (m) => appendTransactionMessageInstructions(instructions, m),
  );
  const message =
    tables.length > 0
      ? compressTransactionMessageUsingAddressLookupTables(
          base,
          Object.fromEntries(
            tables.map((t) => [
              address(t.key.toBase58()),
              t.state.addresses.map((a) => address(a.toBase58())),
            ]),
          ),
        )
      : base;
  const tx = compileTransaction(message);
  return Uint8Array.from(getTransactionEncoder().encode(tx));
}
