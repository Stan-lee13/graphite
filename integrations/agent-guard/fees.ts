/**
 * What a transaction makes its fee payer pay before any instruction runs, read
 * from the message's own bytes (Round 32).
 *
 * Round 30 recorded that the spend cap and the rolling aggregate counted a
 * transfer's amount but not its fee: a transfer exactly at the cap took the
 * cap plus the fee out of the wallet. The guard signs as fee payer, so the
 * fee is the guard's outflow as much as the amount is, and both limits now
 * count it.
 *
 * The rules are the runtime's, as `compute_budget_request` in
 * `graphite-core/src/tx_artifact.rs` reads them:
 *   - the base fee is 5,000 lamports per required signature;
 *   - a v1 message states its priority fee, in lamports, in its header;
 *   - a legacy or v0 message prices compute with a ComputeBudget
 *     `SetComputeUnitPrice` (micro-lamports per unit) over the limit it sets
 *     with `SetComputeUnitLimit`, or the default limit's upper bound (200,000
 *     per instruction outside the ComputeBudget program, capped at 1.4M),
 *     rounded up.
 * Where the runtime would refuse the message (a repeated ComputeBudget
 * instruction), the larger value is taken: this is a bound on what may be
 * charged, never a guess below it.
 */
import bs58 from "bs58";

/** The fee per required signature, in lamports (`DEFAULT_TARGET_LAMPORTS_PER_SIGNATURE`). */
export const LAMPORTS_PER_SIGNATURE = 5_000n;

const COMPUTE_BUDGET_PROGRAM = "ComputeBudget111111111111111111111111111111";
const DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT = 200_000n;
const MAX_COMPUTE_UNIT_LIMIT = 1_400_000n;
const V1_PREFIX = 0x81;
const V1_MASK_PRIORITY_FEE = 0b11;
const V1_MASK_COMPUTE_UNIT_LIMIT = 0b100;
const V1_MASK_LOADED_ACCOUNTS_DATA_SIZE = 0b1000;
const V1_MASK_HEAP_SIZE = 0b1_0000;

export interface TransactionFee {
  /** Required signatures × 5,000 lamports. */
  baseFeeLamports: bigint;
  /** The priority fee the message asks for (at most this, under the default limit). */
  priorityFeeLamports: bigint;
  /** Both together: what the fee payer is charged before any instruction runs. */
  totalLamports: bigint;
}

class Reader {
  #i = 0;
  constructor(readonly b: Uint8Array) {}
  take(n: number, what: string): Uint8Array {
    if (this.#i + n > this.b.length) throw new Error(`[Graphite] fee: message truncated at ${what}`);
    const out = this.b.subarray(this.#i, this.#i + n);
    this.#i += n;
    return out;
  }
  u8(what: string): number {
    return this.take(1, what)[0];
  }
  u32(what: string): number {
    const b = this.take(4, what);
    return (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0;
  }
  u64(what: string): bigint {
    const b = this.take(8, what);
    return new DataView(b.buffer, b.byteOffset, 8).getBigUint64(0, true);
  }
  shortU16(what: string): number {
    let value = 0;
    for (let g = 0; g < 3; g++) {
      const x = this.u8(what);
      value |= (x & 0x7f) << (7 * g);
      if ((x & 0x80) === 0) break;
    }
    return value;
  }
}

function priorityFee(priceMicroLamports: bigint, limit: bigint): bigint {
  return (priceMicroLamports * limit + 999_999n) / 1_000_000n;
}

/** The fee a message (legacy, v0 or v1; the message bytes, not the signed frame) costs its fee payer. */
export function transactionFee(message: Uint8Array): TransactionFee {
  const r = new Reader(message);
  if (message[0] === V1_PREFIX) {
    r.u8("message version");
    const signers = r.u8("num_required_signatures");
    r.take(2, "header");
    const mask = r.u32("v1 config mask");
    r.take(32, "lifetime specifier");
    r.u8("instruction count");
    const keyCount = r.u8("account address count");
    r.take(32 * keyCount, "account addresses");
    let priority = 0n;
    if ((mask & V1_MASK_PRIORITY_FEE) === V1_MASK_PRIORITY_FEE) priority = r.u64("v1 priority fee");
    if (mask & V1_MASK_COMPUTE_UNIT_LIMIT) r.u32("v1 compute unit limit");
    if (mask & V1_MASK_LOADED_ACCOUNTS_DATA_SIZE) r.u32("v1 loaded accounts data size limit");
    if (mask & V1_MASK_HEAP_SIZE) r.u32("v1 heap size");
    const base = LAMPORTS_PER_SIGNATURE * BigInt(signers);
    return { baseFeeLamports: base, priorityFeeLamports: priority, totalLamports: base + priority };
  }
  if ((message[0] & 0x80) !== 0) r.u8("message version");
  const signers = r.u8("num_required_signatures");
  r.take(2, "header");
  const keyCount = r.shortU16("account key count");
  const keys: string[] = [];
  for (let k = 0; k < keyCount; k++) keys.push(bs58.encode(r.take(32, "account key")));
  r.take(32, "recent blockhash");
  const instructionCount = r.shortU16("instruction count");
  let others = 0n;
  let limit: bigint | undefined;
  let price = 0n;
  for (let x = 0; x < instructionCount; x++) {
    const program = r.u8("instruction program index");
    r.take(r.shortU16("instruction account count"), "instruction accounts");
    const data = r.take(r.shortU16("instruction data length"), "instruction data");
    if (keys[program] !== COMPUTE_BUDGET_PROGRAM) {
      others += 1n;
      continue;
    }
    const value = new DataView(data.buffer, data.byteOffset, data.length);
    if (data[0] === 2 && data.length >= 5) {
      const v = BigInt(value.getUint32(1, true));
      limit = limit === undefined || v > limit ? v : limit;
    } else if (data[0] === 3 && data.length >= 9) {
      const v = value.getBigUint64(1, true);
      if (v > price) price = v;
    }
  }
  const defaultLimit = others * DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT;
  const effective = (() => {
    const l = limit ?? defaultLimit;
    return l > MAX_COMPUTE_UNIT_LIMIT ? MAX_COMPUTE_UNIT_LIMIT : l;
  })();
  const base = LAMPORTS_PER_SIGNATURE * BigInt(signers);
  const priority = priorityFee(price, effective);
  return { baseFeeLamports: base, priorityFeeLamports: priority, totalLamports: base + priority };
}
