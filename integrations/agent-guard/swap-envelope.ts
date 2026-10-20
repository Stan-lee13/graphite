/**
 * The instructions the guard itself puts around a swap.
 *
 * Round 29 (audit 2026-10-20, L4): a swap was ONE instruction — no compute
 * budget, no token account for what it delivers. A route on a busy pool ran
 * on the default budget and the default (zero) priority fee, and a route
 * delivering a token the wallet had never held failed for want of the
 * account. The envelope adds, when the operator configures it:
 *
 *   - ComputeBudget `SetComputeUnitLimit` / `SetComputeUnitPrice`, with
 *     values from configuration (GRAPHITE_SWAP_COMPUTE_UNIT_LIMIT,
 *     GRAPHITE_SWAP_COMPUTE_UNIT_PRICE in micro-lamports), bounded so the
 *     priority fee they allow is at most `MAX_SWAP_PRIORITY_FEE_LAMPORTS`;
 *     not in a v1 message, whose budget is part of the message itself;
 *   - Associated Token Account `CreateIdempotent` for the WALLET'S OWN
 *     associated account of the output mint (GRAPHITE_SWAP_CREATE_OUTPUT_ATA=1),
 *     and only when the route names that account as writable — the token
 *     program it is derived under is whichever one makes the derived address
 *     one the route actually uses.
 *
 * Every instruction is built here from configuration and the wallet's own
 * key. Nothing in the payload is copied into the envelope. They reach the
 * Core as declared sibling instructions (both programs have seed manifests)
 * and are in the bytes the Core hashes; the wallet effect is measured by
 * simulating the whole transaction, envelope included, and the priority fee
 * the envelope permits is added to the measured outflow on top of that.
 *
 * NOT built, and why: wrapping SOL into the wallet's wrapped-SOL account
 * before a SOL-input swap (System transfer + SyncNative) and unwrapping it
 * after (SPL Token CloseAccount back to the wallet). The Core's risk engine
 * refuses SPL Token CloseAccount by discriminator in every transaction, so an
 * unwrap would turn every SOL-output swap into a block; and a wrap without an
 * unwrap leaves the rent and any remainder in wrapped SOL. A SOL-input swap
 * spends wrapped SOL the wallet already holds; a SOL-output swap delivers
 * wrapped SOL into the wallet's own account. Both count as SOL in the
 * measured effect.
 */
import {
  ComputeBudgetProgram,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
} from "@solana/web3.js";
import type { BoundInstructionPayload } from "./bound-instruction.js";

export const ASSOCIATED_TOKEN_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
export const SPL_TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
export const TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

/** The runtime's ceiling on a transaction's compute units. */
export const MAX_COMPUTE_UNIT_LIMIT = 1_400_000;
/** The most priority fee the envelope may allow: 0.005 SOL. */
export const MAX_SWAP_PRIORITY_FEE_LAMPORTS = 5_000_000n;

export interface SwapEnvelopeConfig {
  /** SetComputeUnitLimit, 1..1,400,000. */
  computeUnitLimit?: number;
  /** SetComputeUnitPrice in micro-lamports per compute unit. */
  computeUnitPriceMicroLamports?: bigint;
  /** CreateIdempotent of the wallet's own associated account for the output mint. */
  createOutputAta?: boolean;
}

/** The priority fee a configuration permits at most, in lamports (rounded up). */
export function maxPriorityFeeLamports(config: SwapEnvelopeConfig): bigint {
  const price = config.computeUnitPriceMicroLamports ?? 0n;
  if (price === 0n) return 0n;
  const units = BigInt(config.computeUnitLimit ?? MAX_COMPUTE_UNIT_LIMIT);
  return (units * price + 999_999n) / 1_000_000n;
}

/** Refuse to start on an envelope outside its bounds. */
export function assertSwapEnvelopeUsable(config: SwapEnvelopeConfig): void {
  const limit = config.computeUnitLimit;
  if (limit !== undefined && (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_COMPUTE_UNIT_LIMIT)) {
    throw new Error(
      `[Graphite] swap compute-unit limit ${limit} is not an integer from 1 to ${MAX_COMPUTE_UNIT_LIMIT}. REFUSING TO START.`,
    );
  }
  const price = config.computeUnitPriceMicroLamports;
  if (price !== undefined && price < 0n) {
    throw new Error(`[Graphite] swap compute-unit price ${price} is negative. REFUSING TO START.`);
  }
  const fee = maxPriorityFeeLamports(config);
  if (fee > MAX_SWAP_PRIORITY_FEE_LAMPORTS) {
    throw new Error(
      `[Graphite] the swap compute budget allows a priority fee of up to ${fee} lamports, above the ` +
        `${MAX_SWAP_PRIORITY_FEE_LAMPORTS} the guard permits (lower GRAPHITE_SWAP_COMPUTE_UNIT_PRICE, or set ` +
        "GRAPHITE_SWAP_COMPUTE_UNIT_LIMIT). REFUSING TO START.",
    );
  }
}

/**
 * Read GRAPHITE_SWAP_COMPUTE_UNIT_LIMIT, GRAPHITE_SWAP_COMPUTE_UNIT_PRICE and
 * GRAPHITE_SWAP_CREATE_OUTPUT_ATA. Unset: no envelope at all. A malformed
 * value refuses to start.
 */
export function swapEnvelopeFromEnv(env: Record<string, string | undefined> = process.env): SwapEnvelopeConfig {
  const config: SwapEnvelopeConfig = {};
  const limit = env.GRAPHITE_SWAP_COMPUTE_UNIT_LIMIT;
  if (limit !== undefined && limit !== "") {
    if (!/^[0-9]{1,7}$/.test(limit)) {
      throw new Error(`[Graphite] GRAPHITE_SWAP_COMPUTE_UNIT_LIMIT=${JSON.stringify(limit)} is not an integer. REFUSING TO START.`);
    }
    config.computeUnitLimit = Number(limit);
  }
  const price = env.GRAPHITE_SWAP_COMPUTE_UNIT_PRICE;
  if (price !== undefined && price !== "") {
    if (!/^[0-9]{1,15}$/.test(price)) {
      throw new Error(
        `[Graphite] GRAPHITE_SWAP_COMPUTE_UNIT_PRICE=${JSON.stringify(price)} is not an integer of micro-lamports. REFUSING TO START.`,
      );
    }
    config.computeUnitPriceMicroLamports = BigInt(price);
  }
  const ata = env.GRAPHITE_SWAP_CREATE_OUTPUT_ATA;
  if (ata !== undefined && ata !== "" && ata !== "0" && ata !== "1") {
    throw new Error(`[Graphite] GRAPHITE_SWAP_CREATE_OUTPUT_ATA=${JSON.stringify(ata)} is not "1" or "0". REFUSING TO START.`);
  }
  if (ata === "1") config.createOutputAta = true;
  assertSwapEnvelopeUsable(config);
  return config;
}

export function associatedTokenAddress(owner: PublicKey, mint: PublicKey, tokenProgram: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [owner.toBuffer(), tokenProgram.toBuffer(), mint.toBuffer()],
    new PublicKey(ASSOCIATED_TOKEN_PROGRAM),
  )[0];
}

/**
 * The envelope's instructions, in order: those that go before the swap.
 * (Nothing goes after it; see the module comment.)
 */
export function buildSwapEnvelope(params: {
  wallet: PublicKey;
  payload: BoundInstructionPayload;
  outputMint: string;
  config: SwapEnvelopeConfig;
  /** v1 carries its budget in the message: no ComputeBudget instruction. */
  version: "legacy" | 1;
  log?: (line: string) => void;
}): TransactionInstruction[] {
  const { wallet, payload, outputMint, config, version } = params;
  const log = params.log ?? ((line: string) => console.log(line));
  const pre: TransactionInstruction[] = [];
  if (version !== 1) {
    if (config.computeUnitLimit !== undefined) {
      pre.push(ComputeBudgetProgram.setComputeUnitLimit({ units: config.computeUnitLimit }));
    }
    if (config.computeUnitPriceMicroLamports !== undefined && config.computeUnitPriceMicroLamports > 0n) {
      pre.push(ComputeBudgetProgram.setComputeUnitPrice({ microLamports: config.computeUnitPriceMicroLamports }));
    }
  }
  if (config.createOutputAta) {
    const mint = new PublicKey(outputMint);
    const writable = new Set(payload.accounts.filter((a) => a.isWritable).map((a) => a.pubkey));
    const tokenProgram = [SPL_TOKEN_PROGRAM, TOKEN_2022_PROGRAM]
      .map((p) => new PublicKey(p))
      .find((p) => writable.has(associatedTokenAddress(wallet, mint, p).toBase58()));
    if (tokenProgram === undefined) {
      log(
        "[Graphite] swap envelope: the route does not write to the wallet's associated account for the output " +
          "mint; no account is created for it",
      );
    } else {
      const ata = associatedTokenAddress(wallet, mint, tokenProgram);
      pre.push(
        new TransactionInstruction({
          programId: new PublicKey(ASSOCIATED_TOKEN_PROGRAM),
          keys: [
            { pubkey: wallet, isSigner: true, isWritable: true },
            { pubkey: ata, isSigner: false, isWritable: true },
            { pubkey: wallet, isSigner: false, isWritable: false },
            { pubkey: mint, isSigner: false, isWritable: false },
            { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
            { pubkey: tokenProgram, isSigner: false, isWritable: false },
          ],
          // AssociatedTokenAccountInstruction::CreateIdempotent.
          data: Buffer.from([1]),
        }),
      );
    }
  }
  return pre;
}
