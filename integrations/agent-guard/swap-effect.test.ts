/**
 * External review (2026-10-16), the measurement under the swap grounding:
 * what a transaction does to the wallet is read from ONE simulation's own
 * pre- and post-balances; lamports are exact or refused; an RPC answer is
 * bounded before it is parsed.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import {
  MAX_RPC_RESPONSE_BYTES,
  exactLamports,
  readJsonBounded,
  walletEffectOf,
  WRAPPED_SOL_MINT,
} from "./rpc-simulator.js";
import { assertSwapEffectMatches, groundSwapRequest, SWAP_SOL_OVERHEAD_LAMPORTS } from "./intent-grounding.js";

const WALLET = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
const OTHER = "6bSsP4p6wXqFJdD2TkYgNcVmLzHfWq7pRyA8tCzE5nBj";
const USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

const balance = (accountIndex: number, mint: string, owner: string, amount: bigint, decimals = 6) => ({
  accountIndex,
  mint,
  owner,
  uiTokenAmount: { amount: amount.toString(), decimals },
});

test("the effect is the wallet's own: its lamports, wrapped SOL as SOL, and its token accounts only", () => {
  const effect = walletEffectOf(
    {
      preBalances: [10_000_000_000, 2_039_280, 2_039_280, 0],
      postBalances: [9_997_955_720, 0, 2_039_280, 2_039_280],
      preTokenBalances: [
        balance(1, WRAPPED_SOL_MINT, WALLET, 1_000_000_000n, 9),
        balance(2, USDC, OTHER, 50_000_000n), // someone else's account: not the wallet's effect
      ],
      postTokenBalances: [balance(2, USDC, OTHER, 0n), balance(3, USDC, WALLET, 150_000_000n)],
    },
    WALLET,
  );
  // 2,044,280 lamports from the wallet itself, plus the 1 SOL of wrapped SOL it held and spent.
  assert.equal(effect.solOut, 2_044_280n + 1_000_000_000n);
  assert.equal(effect.tokenDelta.get(USDC), 150_000_000n);
  assert.equal(effect.decimals.get(USDC), 6);
});

test("a balance that is not an exact integer, or a simulation without both arrays, is refused", () => {
  assert.throws(() => exactLamports(2 ** 53 + 2, "x"), /not an exact lamport balance/);
  assert.throws(() => exactLamports(1.5, "x"), /not an exact lamport balance/);
  assert.equal(exactLamports(Number.MAX_SAFE_INTEGER, "x"), BigInt(Number.MAX_SAFE_INTEGER));
  assert.throws(
    () => walletEffectOf({ postBalances: [1], preTokenBalances: [], postTokenBalances: [] }, WALLET),
    /preBalances and postBalances/,
  );
  assert.throws(
    () => walletEffectOf({ preBalances: [1, 2], postBalances: [1], preTokenBalances: [], postTokenBalances: [] }, WALLET),
    /preBalances and postBalances/,
  );
  assert.throws(
    () => walletEffectOf({ preBalances: [1], postBalances: [1], postTokenBalances: [] }, WALLET),
    /did not report preTokenBalances/,
  );
  assert.throws(
    () =>
      walletEffectOf(
        { preBalances: [1], postBalances: [1], preTokenBalances: [{ accountIndex: 0, mint: USDC }], postTokenBalances: [] },
        WALLET,
      ),
    /not a complete token balance/,
  );
});

test("the overhead allowance is the only SOL a swap may spend beyond the amount requested", () => {
  const grounded = groundSwapRequest("Swap 1 SOL for USDC", { input_token: "SOL", output_token: "USDC", amount: "1" });
  const effect = (solOut: bigint) => ({
    solOut,
    tokenDelta: new Map([[USDC, 1n]]),
    decimals: new Map([[USDC, 6]]),
  });
  assertSwapEffectMatches(grounded, effect(1_000_000_000n + SWAP_SOL_OVERHEAD_LAMPORTS));
  assert.throws(
    () => assertSwapEffectMatches(grounded, effect(1_000_000_000n + SWAP_SOL_OVERHEAD_LAMPORTS + 1n)),
    /more than 1000000000 plus 10000000/,
  );
});

async function serve(body: Buffer, contentLength?: number) {
  const server = createServer((_req, res) => {
    res.writeHead(200, {
      "content-type": "application/json",
      ...(contentLength === undefined ? {} : { "content-length": String(contentLength) }),
    });
    res.end(body);
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return { url, close: () => new Promise<void>((r) => server.close(() => r())) };
}

test("an RPC answer over the bound is refused before it is parsed, declared or not", async () => {
  const big = Buffer.alloc(2048, 0x20);
  // Declared too large.
  let s = await serve(Buffer.from("{}"), MAX_RPC_RESPONSE_BYTES + 1);
  try {
    const r = await fetch(s.url);
    await assert.rejects(readJsonBounded(r), /declares \d+ bytes, over the/);
  } finally {
    await s.close();
  }
  // Undeclared (chunked) and larger than a small bound.
  s = await serve(big);
  try {
    const r = await fetch(s.url);
    await assert.rejects(readJsonBounded(r, 1024), /exceeds the 1024-byte bound/);
  } finally {
    await s.close();
  }
  // Within the bound: parsed.
  s = await serve(Buffer.from('{"result":42}'));
  try {
    assert.deepEqual(await readJsonBounded(await fetch(s.url), 1024), { result: 42 });
  } finally {
    await s.close();
  }
});
