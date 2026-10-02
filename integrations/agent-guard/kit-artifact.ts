/**
 * The unsigned artifact, compiled by `@solana/kit` (roadmap gap R-P8).
 *
 * The bridge used to compile with `@solana/web3.js` 1.x, which cannot build a
 * version-1 message. `@solana/kit` 8 can (legacy, v0 and v1). Phase 1 moved the
 * legacy and v0 paths here and `kit-artifact.test.ts` shows they produce the
 * bytes web3.js produced (legacy) or the same transaction with accounts sorted
 * within each privilege class (v0). Phase 2 adds version 1 (SIMD-0385).
 *
 * The inputs are the ones the bridge already has (web3.js instructions, fee
 * payer, blockhash, lookup-table accounts). Nothing here signs, sends or reads
 * an account.
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
  setTransactionMessageConfig,
  setTransactionMessageFeePayer,
  setTransactionMessageLifetimeUsingBlockhash,
  type Address,
  type Blockhash,
  type Instruction,
  type Transaction,
} from "@solana/kit";
import type { AddressLookupTableAccount, PublicKey, TransactionInstruction } from "@solana/web3.js";

/** The message versions the bridge builds. */
export type MessageVersion = "legacy" | 0 | 1;

/**
 * The resource limits a version-1 message carries in its config (SIMD-0385).
 *
 * In legacy and v0 an unset limit means a runtime default. In v1 an unset
 * compute-unit limit is ZERO compute units and an unset loaded-accounts-data
 * limit is ZERO bytes, so a v1 transaction without both fails at execution.
 * They are therefore required here, not defaulted: the bridge does not guess
 * a budget on someone's behalf.
 */
export interface V1Limits {
  /** Compute units the transaction may consume; 1 to 1,400,000. */
  computeUnitLimit: number;
  /** Bytes of account data the transaction may load; 1 to 64 MiB. */
  loadedAccountsDataSizeLimit: number;
  /** The TOTAL priority fee in lamports (not a per-unit price). Omitted = none. */
  priorityFeeLamports?: bigint;
  /** Heap frame in bytes: a multiple of 1024 in [32 KiB, 256 KiB]. Omitted = 32 KiB. */
  heapSize?: number;
}

/** The runtime's ceiling on a transaction's compute units. */
export const MAX_COMPUTE_UNIT_LIMIT = 1_400_000;
/** The runtime's ceiling on loaded account data (MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES). */
export const MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES = 64 * 1024 * 1024;
/** The ComputeBudget program. Its instructions do nothing in a v1 message. */
export const COMPUTE_BUDGET_PROGRAM_ID = "ComputeBudget111111111111111111111111111111";

/**
 * Refuse limits the runtime would refuse, or would accept and then fail on.
 * A heap size outside its bounds is a sanitization failure: the transaction
 * never lands and never shows a program error, so it is caught here.
 */
export function assertValidV1Limits(limits: V1Limits | undefined): asserts limits is V1Limits {
  if (!limits) {
    throw new Error(
      "kit-artifact: a version-1 message needs v1Limits. An unset compute-unit limit is zero compute " +
        "units and an unset loaded-accounts-data limit is zero bytes in v1, so it would fail at execution.",
    );
  }
  const { computeUnitLimit: cu, loadedAccountsDataSizeLimit: data, priorityFeeLamports: fee, heapSize: heap } =
    limits;
  if (!Number.isSafeInteger(cu) || cu < 1 || cu > MAX_COMPUTE_UNIT_LIMIT) {
    throw new Error(`kit-artifact: computeUnitLimit ${String(cu)} is not an integer in [1, ${MAX_COMPUTE_UNIT_LIMIT}]`);
  }
  if (!Number.isSafeInteger(data) || data < 1 || data > MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES) {
    throw new Error(
      `kit-artifact: loadedAccountsDataSizeLimit ${String(data)} is not an integer in [1, ${MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES}]`,
    );
  }
  if (fee !== undefined && (typeof fee !== "bigint" || fee < 0n || fee > 0xffff_ffff_ffff_ffffn)) {
    throw new Error(`kit-artifact: priorityFeeLamports ${String(fee)} is not a u64 bigint`);
  }
  if (
    heap !== undefined &&
    (!Number.isSafeInteger(heap) || heap % 1024 !== 0 || heap < 32 * 1024 || heap > 256 * 1024)
  ) {
    throw new Error(`kit-artifact: heapSize ${String(heap)} is not a multiple of 1024 in [32768, 262144]`);
  }
}

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
 * The unsigned wire bytes of a transaction, compiled by kit: every signature
 * slot is 64 zero bytes (leading for legacy and v0, trailing for v1).
 */
export function compileUnsignedWithKit(params: Parameters<typeof compileWithKit>[0]): Uint8Array {
  return Uint8Array.from(getTransactionEncoder().encode(compileWithKit(params)));
}

/** The compiled (unsigned) kit transaction of a legacy, v0 or v1 message. */
export function compileWithKit(params: {
  instructions: TransactionInstruction[];
  feePayer: PublicKey;
  recentBlockhash: string;
  lastValidBlockHeight: number;
  version: MessageVersion;
  addressLookupTables?: AddressLookupTableAccount[];
  /** Required for, and only accepted with, `version: 1`. */
  v1Limits?: V1Limits;
}): Transaction {
  const tables = params.addressLookupTables ?? [];
  if (params.version !== 0 && tables.length > 0) {
    throw new Error(
      `kit-artifact: lookup tables were given for a ${params.version === 1 ? "v1" : "legacy"} message, which cannot read them`,
    );
  }
  if (params.version !== 1 && params.v1Limits !== undefined) {
    throw new Error(
      "kit-artifact: v1Limits were given for a legacy or v0 message, which carries its budget as ComputeBudget instructions",
    );
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
    return compileTransaction(message);
  }
  if (params.version === 1) {
    assertValidV1Limits(params.v1Limits);
    // A ComputeBudget instruction in a v1 message is executed as a no-op: it
    // sets nothing, costs 150 compute units and an instruction slot. A caller
    // that put one there meant a budget it would not get, so it is refused
    // rather than carried.
    const budgetIx = params.instructions.findIndex((ix) => ix.programId.toBase58() === COMPUTE_BUDGET_PROGRAM_ID);
    if (budgetIx >= 0) {
      throw new Error(
        `kit-artifact: instruction ${budgetIx} is a ComputeBudget instruction, which does nothing in a v1 message. ` +
          "Put the budget in v1Limits instead.",
      );
    }
    const { computeUnitLimit, loadedAccountsDataSizeLimit, priorityFeeLamports, heapSize } = params.v1Limits;
    const message = pipe(
      createTransactionMessage({ version: 1 }),
      (m) => setTransactionMessageFeePayer(feePayer, m),
      (m) => setTransactionMessageLifetimeUsingBlockhash(lifetime, m),
      (m) =>
        setTransactionMessageConfig(
          {
            computeUnitLimit,
            loadedAccountsDataSizeLimit,
            ...(priorityFeeLamports !== undefined ? { priorityFeeLamports } : {}),
            ...(heapSize !== undefined ? { heapSize } : {}),
          },
          m,
        ),
      (m) => appendTransactionMessageInstructions(instructions, m),
    );
    return compileTransaction(message);
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
  return compileTransaction(message);
}
