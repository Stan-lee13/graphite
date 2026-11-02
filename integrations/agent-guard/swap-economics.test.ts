/**
 * Round 29 (audit 2026-10-20, H2 + H4): what a decoded route must be worth.
 * The rules, on plain values; guard-round29.test.ts drives them through
 * executeSwap.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { groundSwapRequest, type WalletEffect } from "./intent-grounding.js";
import {
  assertSwapEconomics,
  describeSwapPolicy,
  parseSwapMinRates,
  swapPolicyFromEnv,
  SWAP_SLIPPAGE_CEILING_BPS,
  type SwapPolicy,
} from "./swap-economics.js";
import type { DecodedSwap } from "./swap-instructions.js";

const USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const SOL_MINT = "So11111111111111111111111111111111111111112";

const decoded = (amountIn: bigint, minOut: bigint): DecodedSwap => ({
  programId: "x",
  name: "route",
  discriminator: "00",
  amountIn,
  minOut,
});
const effectUsdc = (received: bigint): WalletEffect => ({
  solOut: 1_000_005_000n,
  tokenDelta: new Map([[USDC, received]]),
  decimals: new Map([[USDC, 6]]),
  wrappedSolDelta: -1_000_000_000n,
});
const policy = (o: Partial<SwapPolicy> = {}): SwapPolicy => ({ maxSlippageBps: 100, minRates: [], allowUnpriced: true, ...o });
const g = (text: string, out = "USDC", inTok = "SOL", amount = "1") =>
  groundSwapRequest(text, { amount, input_token: inTok, output_token: out });

test("the minimum must be above zero, at most what was simulated, and within the slippage of it", () => {
  const grounded = g("Swap 1 SOL for USDC");
  assert.throws(() => assertSwapEconomics({ grounded, decoded: decoded(1_000_000_000n, 0n), effect: effectUsdc(150n), policy: policy() }), /output of zero/);
  assert.throws(() => assertSwapEconomics({ grounded, decoded: decoded(1_000_000_000n, 151n), effect: effectUsdc(150n), policy: policy() }), /delivered 150/);
  // 1% exactly is allowed; one unit below is not.
  const ok = assertSwapEconomics({ grounded, decoded: decoded(1_000_000_000n, 9_900n), effect: effectUsdc(10_000n), policy: policy() });
  assert.equal(ok.maxSlippageBps, 100);
  assert.throws(() => assertSwapEconomics({ grounded, decoded: decoded(1_000_000_000n, 9_899n), effect: effectUsdc(10_000n), policy: policy() }), /more than 100 bps below/);
});

test("SOL out is measured on the wrapped SOL the route credits, not the wallet's net lamports", () => {
  const grounded = g("Swap 150 USDC for SOL", "SOL", "USDC", "150");
  const effect: WalletEffect = {
    solOut: -497_955_720n, // 0.5 SOL in wrapped SOL, less fee and rent
    tokenDelta: new Map([[USDC, -150_000_000n]]),
    decimals: new Map([[USDC, 6], [SOL_MINT, 9]]),
    wrappedSolDelta: 500_000_000n,
  };
  const r = assertSwapEconomics({ grounded, decoded: decoded(150_000_000n, 497_500_000n), effect, policy: policy() });
  assert.equal(r.simulatedOut, 500_000_000n);
});

test("the price floor: the request's minimum, else the operator's rate, else a refusal unless accepted", () => {
  const base = { decoded: decoded(1_000_000_000n, 149_250_000n), effect: effectUsdc(150_000_000n) };
  assert.equal(
    assertSwapEconomics({ ...base, grounded: g("Swap 1 SOL for USDC for at least 149.25 USDC"), policy: policy({ allowUnpriced: false }) }).floor.source,
    "request",
  );
  assert.throws(
    () => assertSwapEconomics({ ...base, grounded: g("Swap 1 SOL for USDC for at least 149.26 USDC"), policy: policy() }),
    /asks for at least 149\.26 USDC/,
  );
  const rates = (r: string) => policy({ allowUnpriced: false, minRates: parseSwapMinRates(r) });
  assert.equal(assertSwapEconomics({ ...base, grounded: g("Swap 1 SOL for USDC"), policy: rates("SOL/USDC=149.25") }).floor.source, "operator");
  assert.throws(() => assertSwapEconomics({ ...base, grounded: g("Swap 1 SOL for USDC"), policy: rates("SOL/USDC=149.250001") }), /requires 149250001/);
  // A floor for another pair does not price this one.
  assert.throws(() => assertSwapEconomics({ ...base, grounded: g("Swap 1 SOL for USDC"), policy: rates("SOL/USDT=1") }), /nothing prices SOL → USDC/);
  assert.equal(assertSwapEconomics({ ...base, grounded: g("Swap 1 SOL for USDC"), policy: policy() }).floor.source, "unpriced");
});

test("the route may not spend more than the request names, in the request's units", () => {
  assert.throws(
    () => assertSwapEconomics({ grounded: g("Swap 1 SOL for USDC"), decoded: decoded(1_000_000_001n, 149n), effect: effectUsdc(150n), policy: policy() }),
    /spends 1000000001 base units of SOL; the request spends 1 \(1000000000\)/,
  );
});

test("environment: strict parsing, a slippage ceiling, and a startup line naming accepted risk", () => {
  assert.deepEqual(swapPolicyFromEnv({}), { maxSlippageBps: 100, minRates: [], allowUnpriced: false });
  assert.equal(swapPolicyFromEnv({ GRAPHITE_SWAP_MAX_SLIPPAGE_BPS: "50" }).maxSlippageBps, 50);
  for (const bad of ["-1", "1.5", String(SWAP_SLIPPAGE_CEILING_BPS + 1), "x"]) {
    assert.throws(() => swapPolicyFromEnv({ GRAPHITE_SWAP_MAX_SLIPPAGE_BPS: bad }), /REFUSING TO START/, bad);
  }
  for (const bad of ["SOL-USDC=1", "SOL/USDC=0", "SOL/USDC=-1", "SOL/FOO=1", "SOL/SOL=1", "SOL/USDC=1,SOL/USDC=2", "SOL/USDC=1e3"]) {
    assert.throws(() => swapPolicyFromEnv({ GRAPHITE_SWAP_MIN_RATES: bad }), /REFUSING TO START/, bad);
  }
  assert.throws(() => swapPolicyFromEnv({ GRAPHITE_SWAP_ALLOW_UNPRICED: "yes" }), /REFUSING TO START/);
  const rates = swapPolicyFromEnv({ GRAPHITE_SWAP_MIN_RATES: " SOL/USDC=100 , USDC/SOL=0.0065" }).minRates;
  assert.deepEqual(rates.map((r) => [r.pair, r.inMint, r.outMint, r.rate]), [
    ["SOL/USDC", SOL_MINT, USDC, "100"],
    ["USDC/SOL", USDC, SOL_MINT, "0.0065"],
  ]);
  assert.match(describeSwapPolicy(swapPolicyFromEnv({ GRAPHITE_SWAP_ALLOW_UNPRICED: "1" })), /ACCEPTED RISK \(GRAPHITE_SWAP_ALLOW_UNPRICED=1\)/);
  assert.match(describeSwapPolicy(swapPolicyFromEnv({})), /is refused/);
});

test("Audit A003: the request's text can raise the operator's floor and tighten its slippage, never lower or widen them", () => {
  const rates = (r: string, o: Partial<SwapPolicy> = {}) => policy({ allowUnpriced: false, minRates: parseSwapMinRates(r), ...o });
  // The injected request: "for at least 0.01 USDC" against an operator floor of 140 per SOL.
  const dust = { decoded: decoded(1_000_000_000n, 10_000n), effect: effectUsdc(10_100n) };
  assert.throws(
    () => assertSwapEconomics({ ...dust, grounded: g("Swap 1 SOL for USDC for at least 0.01 USDC"), policy: rates("SOL/USDC=140") }),
    /operator's floor for SOL\/USDC .* requires 140000000 for this input, whatever the request states/,
  );
  // An honest request above the operator's floor binds at the higher of the two.
  const base = { decoded: decoded(1_000_000_000n, 149_250_000n), effect: effectUsdc(150_000_000n) };
  const r = assertSwapEconomics({ ...base, grounded: g("Swap 1 SOL for USDC for at least 149 USDC"), policy: rates("SOL/USDC=140") });
  assert.deepEqual(r.floor, { baseUnits: 149_000_000n, source: "request" });
  const o = assertSwapEconomics({ ...base, grounded: g("Swap 1 SOL for USDC for at least 100 USDC"), policy: rates("SOL/USDC=140") });
  assert.deepEqual(o.floor, { baseUnits: 140_000_000n, source: "operator" });
  // Slippage: a stated 5% does not widen the operator's 1%; a stated 0.5% tightens it.
  const wide = { decoded: decoded(1_000_000_000n, 9_500n), effect: effectUsdc(10_000n) };
  assert.throws(
    () => assertSwapEconomics({ ...wide, grounded: g("Swap 1 SOL for USDC with 5% slippage"), policy: policy() }),
    /more than 100 bps below .* GRAPHITE_SWAP_MAX_SLIPPAGE_BPS; a request can tighten it, not widen it/,
  );
  assert.equal(assertSwapEconomics({ ...wide, grounded: g("Swap 1 SOL for USDC with 5% slippage"), policy: policy({ maxSlippageBps: 500 }) }).maxSlippageBps, 500);
  const tight = { decoded: decoded(1_000_000_000n, 9_940n), effect: effectUsdc(10_000n) };
  assert.throws(
    () => assertSwapEconomics({ ...tight, grounded: g("Swap 1 SOL for USDC with 0.5% slippage"), policy: policy() }),
    /more than 50 bps below .*\(the slippage the request states\)/,
  );
});
