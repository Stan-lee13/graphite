/**
 * Round 32: the fee a message asks for, read from its bytes the way the Core
 * reads it (`compute_budget_request`, graphite-core/src/tx_artifact.rs). The
 * legacy vectors are the Core's own (tests/round21_open_list.rs,
 * `the_priority_fee_is_price_times_limit_rounded_up`), built byte for byte.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { Keypair, PublicKey, SystemProgram, TransactionInstruction } from "@solana/web3.js";
import bs58 from "bs58";
import { LAMPORTS_PER_SIGNATURE, transactionFee } from "./fees.js";
import { BoundTransaction } from "./artifact.js";

const CB = "ComputeBudget111111111111111111111111111111";

/** The Core's `legacy` frame from round21_open_list.rs, as message bytes (no signatures). */
function legacy(budget: Uint8Array[]): Uint8Array {
  const keys = [new Uint8Array(32).fill(1), new Uint8Array(32).fill(2), new Uint8Array(32), bs58.decode(CB)];
  const out: number[] = [1, 0, 2, keys.length];
  for (const k of keys) out.push(...k);
  out.push(...new Uint8Array(32).fill(9));
  out.push(budget.length + 1);
  for (const data of budget) out.push(3, 0, data.length, ...data);
  const transfer = [2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0];
  out.push(2, 2, 0, 1, transfer.length, ...transfer);
  return Uint8Array.from(out);
}
const limit = (n: number) => {
  const d = Buffer.alloc(5);
  d[0] = 2;
  d.writeUInt32LE(n, 1);
  return d;
};
const price = (n: bigint) => {
  const d = Buffer.alloc(9);
  d[0] = 3;
  d.writeBigUInt64LE(n, 1);
  return d;
};

test("legacy: the priority fee is price × limit, rounded up, as the Core computes it", () => {
  assert.equal(transactionFee(legacy([limit(200_000), price(1_000_000n)])).priorityFeeLamports, 200_000n);
  assert.equal(transactionFee(legacy([limit(3), price(1n)])).priorityFeeLamports, 1n, "rounded up, never down");
  // A limit above the runtime's ceiling is capped, as the runtime caps it.
  assert.equal(transactionFee(legacy([limit(5_000_000), price(1_000_000n)])).priorityFeeLamports, 1_400_000n);
  // No limit: the default's upper bound, 200,000 per other instruction.
  assert.equal(transactionFee(legacy([price(1_000_000n)])).priorityFeeLamports, 200_000n);
  // No price: no priority fee; the base fee is per required signature.
  const none = transactionFee(legacy([]));
  assert.deepEqual(none, { baseFeeLamports: LAMPORTS_PER_SIGNATURE, priorityFeeLamports: 0n, totalLamports: 5_000n });
});

test("a repeated ComputeBudget instruction (which the runtime refuses) is read at its larger value", () => {
  const f = transactionFee(legacy([price(1n), price(1_000_000n), limit(200_000)]));
  assert.equal(f.priorityFeeLamports, 200_000n);
});

test("every built message: legacy, v0 and v1, read from the bound transaction's own bytes", () => {
  const payer = Keypair.generate();
  const transfer = SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: Keypair.generate().publicKey, lamports: 1 });
  const blockhash = bs58.encode(new Uint8Array(32).fill(7));
  const cbProgram = new PublicKey(CB);
  const budgetIxs = [
    new TransactionInstruction({ programId: cbProgram, keys: [], data: limit(100_000) }),
    new TransactionInstruction({ programId: cbProgram, keys: [], data: price(2_000_000n) }),
  ];
  for (const version of ["legacy", 0] as const) {
    const bound = BoundTransaction.build({
      instructions: [...budgetIxs, transfer],
      feePayer: payer.publicKey,
      recentBlockhash: blockhash,
      lastValidBlockHeight: 1,
      version,
    });
    assert.deepEqual(
      transactionFee(bound.messageBytes),
      { baseFeeLamports: 5_000n, priorityFeeLamports: 200_000n, totalLamports: 205_000n },
      `version ${version}`,
    );
  }
  const v1 = BoundTransaction.build({
    instructions: [transfer],
    feePayer: payer.publicKey,
    recentBlockhash: blockhash,
    lastValidBlockHeight: 1,
    version: 1,
    v1Limits: { computeUnitLimit: 450, loadedAccountsDataSizeLimit: 32_768, priorityFeeLamports: 7_777n } as never,
  });
  assert.deepEqual(transactionFee(v1.messageBytes), {
    baseFeeLamports: 5_000n,
    priorityFeeLamports: 7_777n,
    totalLamports: 12_777n,
  });
});

test("a truncated message is refused, never read as a smaller fee", () => {
  const whole = legacy([limit(200_000), price(1_000_000n)]);
  assert.throws(() => transactionFee(whole.subarray(0, whole.length - 3)), /truncated/);
});
