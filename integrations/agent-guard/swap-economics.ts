/**
 * What a swap must be worth: the route's own minimum output, held to what was
 * simulated, to the slippage allowed, and to a price floor.
 *
 * Round 29 (audit 2026-10-20, H2 + H4). The guard measured a swap's effect in
 * one simulation and required only that SOME of the requested token arrived.
 * The chain enforces none of what a simulation shows: at landing a route is
 * held to its own minimum output, and that minimum is whatever the route
 * builder wrote — one base unit passed. Now, from the instruction's own data
 * (`swap-instructions.ts`):
 *
 *   1. it is exact-in, and the amount it spends is at most the amount the
 *      request names (so the spend is bounded by the bytes, not by one
 *      simulation);
 *   2. its minimum output is above zero, the simulation received at least
 *      that minimum, and the minimum is within the allowed slippage of what
 *      was simulated:  minOut ≥ received × (1 − maxSlippage). The chain then
 *      enforces, at landing, at most `maxSlippage` less than was simulated;
 *   3. the minimum meets a price floor: the minimum the request states ("for
 *      at least 140 USDC"), or the operator's rate for the pair
 *      (GRAPHITE_SWAP_MIN_RATES, output units per input unit). With neither,
 *      the swap is refused, unless the operator has accepted unpriced swaps
 *      (GRAPHITE_SWAP_ALLOW_UNPRICED=1, logged at startup as an accepted
 *      risk): a simulation shows what a pool pays now, not whether that is a
 *      price anyone would agree to — a pool the route's author controls pays
 *      whatever its author likes.
 *
 * `maxSlippage` is the slippage the request states ("with 0.5% slippage"),
 * else GRAPHITE_SWAP_MAX_SLIPPAGE_BPS (default 100 = 1%), never above
 * `SWAP_SLIPPAGE_CEILING_BPS`.
 */
import {
  KNOWN_TOKEN_MINTS,
  NATIVE_MINT,
  solLiteralToLamports,
  tokenAmountToBaseUnits,
  type GroundedSwap,
  type WalletEffect,
} from "./intent-grounding.js";
import { SwapRouteRefusal, type DecodedSwap } from "./swap-instructions.js";
export { SwapRouteRefusal };

/** The default slippage a route's minimum may sit below what was simulated: 1%. */
export const DEFAULT_SWAP_MAX_SLIPPAGE_BPS = 100;
/** No request and no operator setting may allow more than 5%. */
export const SWAP_SLIPPAGE_CEILING_BPS = 500;

export interface SwapMinRate {
  /** e.g. "SOL/USDC", as configured. */
  pair: string;
  inMint: string;
  outMint: string;
  /** Output units per input unit, as a decimal string ("100", "0.0065"). */
  rate: string;
}

export interface SwapPolicy {
  /** The slippage allowed when the request states none, in basis points. */
  maxSlippageBps: number;
  /** Operator price floors, by pair. */
  minRates: readonly SwapMinRate[];
  /** Build a swap with no price floor at all (an accepted risk, logged). */
  allowUnpriced: boolean;
}

export const DEFAULT_SWAP_POLICY: SwapPolicy = Object.freeze({
  maxSlippageBps: DEFAULT_SWAP_MAX_SLIPPAGE_BPS,
  minRates: Object.freeze([]) as readonly SwapMinRate[],
  allowUnpriced: false,
});

const DECIMAL = /^[0-9]+(?:\.[0-9]+)?$/;
const BASE58_ADDRESS = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

function mintOf(word: string, what: string): string {
  if (BASE58_ADDRESS.test(word)) return word;
  const mint = KNOWN_TOKEN_MINTS[word.toUpperCase()];
  if (!mint) {
    throw new Error(
      `[Graphite] ${what}: "${word}" is not a token symbol the guard resolves (${Object.keys(KNOWN_TOKEN_MINTS).join(", ")}) ` +
        "or a mint address. REFUSING TO START.",
    );
  }
  return mint;
}

/** Parse GRAPHITE_SWAP_MIN_RATES ("SOL/USDC=100,SOL/USDT=100"). A malformed entry refuses to start. */
export function parseSwapMinRates(value: string): SwapMinRate[] {
  const out: SwapMinRate[] = [];
  for (const raw of value.split(",")) {
    const entry = raw.trim();
    if (entry === "") continue;
    const m = /^([^/=\s]+)\/([^/=\s]+)=([^=\s]+)$/.exec(entry);
    if (!m || !DECIMAL.test(m[3]) || !/[1-9]/.test(m[3])) {
      throw new Error(
        `[Graphite] GRAPHITE_SWAP_MIN_RATES entry ${JSON.stringify(entry)} is not "<in>/<out>=<positive decimal>". REFUSING TO START.`,
      );
    }
    const inMint = mintOf(m[1], "GRAPHITE_SWAP_MIN_RATES");
    const outMint = mintOf(m[2], "GRAPHITE_SWAP_MIN_RATES");
    if (inMint === outMint) {
      throw new Error(`[Graphite] GRAPHITE_SWAP_MIN_RATES entry ${JSON.stringify(entry)} prices a token in itself. REFUSING TO START.`);
    }
    if (out.some((r) => r.inMint === inMint && r.outMint === outMint)) {
      throw new Error(`[Graphite] GRAPHITE_SWAP_MIN_RATES names ${m[1]}/${m[2]} twice. REFUSING TO START.`);
    }
    out.push({ pair: `${m[1]}/${m[2]}`, inMint, outMint, rate: m[3] });
  }
  return out;
}

/**
 * Read GRAPHITE_SWAP_MAX_SLIPPAGE_BPS (integer, 0..ceiling),
 * GRAPHITE_SWAP_MIN_RATES and GRAPHITE_SWAP_ALLOW_UNPRICED ("1", or unset /
 * "0"). A malformed value is a startup error, never a silently absent bound.
 */
export function swapPolicyFromEnv(env: Record<string, string | undefined> = process.env): SwapPolicy {
  let maxSlippageBps = DEFAULT_SWAP_MAX_SLIPPAGE_BPS;
  const slip = env.GRAPHITE_SWAP_MAX_SLIPPAGE_BPS;
  if (slip !== undefined && slip !== "") {
    if (!/^[0-9]+$/.test(slip) || Number(slip) > SWAP_SLIPPAGE_CEILING_BPS) {
      throw new Error(
        `[Graphite] GRAPHITE_SWAP_MAX_SLIPPAGE_BPS=${JSON.stringify(slip)} is not an integer from 0 to ` +
          `${SWAP_SLIPPAGE_CEILING_BPS}. REFUSING TO START.`,
      );
    }
    maxSlippageBps = Number(slip);
  }
  const rates = env.GRAPHITE_SWAP_MIN_RATES;
  const minRates = rates === undefined ? [] : parseSwapMinRates(rates);
  const unpriced = env.GRAPHITE_SWAP_ALLOW_UNPRICED;
  if (unpriced !== undefined && unpriced !== "" && unpriced !== "0" && unpriced !== "1") {
    throw new Error(`[Graphite] GRAPHITE_SWAP_ALLOW_UNPRICED=${JSON.stringify(unpriced)} is not "1" or "0". REFUSING TO START.`);
  }
  return { maxSlippageBps, minRates, allowUnpriced: unpriced === "1" };
}

/** Check a configured policy (one passed in code rather than read from the environment). */
export function assertSwapPolicyUsable(policy: SwapPolicy): void {
  if (!Number.isSafeInteger(policy.maxSlippageBps) || policy.maxSlippageBps < 0 || policy.maxSlippageBps > SWAP_SLIPPAGE_CEILING_BPS) {
    throw new Error(
      `[Graphite] swapPolicy.maxSlippageBps ${policy.maxSlippageBps} is not an integer from 0 to ${SWAP_SLIPPAGE_CEILING_BPS}. REFUSING TO START.`,
    );
  }
  for (const r of policy.minRates) {
    if (!DECIMAL.test(r.rate) || !/[1-9]/.test(r.rate)) {
      throw new Error(`[Graphite] swapPolicy rate ${JSON.stringify(r.rate)} for ${r.pair} is not a positive decimal. REFUSING TO START.`);
    }
  }
}

/** The startup line that states the swap policy in force. */
export function describeSwapPolicy(policy: SwapPolicy): string {
  const floors =
    policy.minRates.length > 0
      ? `price floors ${policy.minRates.map((r) => `${r.pair}≥${r.rate}`).join(", ")}`
      : "no operator price floors";
  return (
    `[Graphite] swap policy: route minimum within ${policy.maxSlippageBps} bps of the simulated output ` +
    `(a request may state less, never more than ${SWAP_SLIPPAGE_CEILING_BPS}); ${floors}; ` +
    (policy.allowUnpriced
      ? "ACCEPTED RISK (GRAPHITE_SWAP_ALLOW_UNPRICED=1): a swap with neither a stated minimum nor a floor is built at whatever price its route sets"
      : "a swap with neither a stated minimum nor a floor for its pair is refused")
  );
}

/** ceil(a / b) for positive b. */
function ceilDiv(a: bigint, b: bigint): bigint {
  return (a + b - 1n) / b;
}

/** A decimal string as numerator / 10^scale. */
function decimalParts(text: string): { num: bigint; scale: bigint } {
  const [whole, frac = ""] = text.split(".");
  return { num: BigInt(whole + frac), scale: 10n ** BigInt(frac.length) };
}

/** What `assertSwapEconomics` established, for the log and the person who confirms. */
export interface SwapEconomics {
  amountIn: bigint;
  minOut: bigint;
  /** What the simulation delivered into the account the minimum is enforced on. */
  simulatedOut: bigint;
  maxSlippageBps: number;
  /** The floor the minimum was held to, and where it came from. */
  floor: { baseUnits: bigint; source: "request" | "operator" } | { source: "unpriced" };
}

/**
 * Refuse a swap whose route the chain would not hold to what was simulated,
 * or to a price anyone agreed to. See the module comment for the rules.
 */
export function assertSwapEconomics(params: {
  grounded: GroundedSwap;
  decoded: DecodedSwap;
  effect: WalletEffect;
  policy: SwapPolicy;
}): SwapEconomics {
  const { grounded, decoded, effect, policy } = params;
  const inMint = grounded.input.mint;
  const outMint = grounded.output.mint;
  const inDecimals = inMint === NATIVE_MINT ? 9 : effect.decimals.get(inMint);
  const outDecimals = outMint === NATIVE_MINT ? 9 : effect.decimals.get(outMint);
  if (inDecimals === undefined || outDecimals === undefined) {
    throw new SwapRouteRefusal(
      `the simulation reported no decimals for ${inDecimals === undefined ? grounded.input.written : grounded.output.written}, ` +
        "so the route's amounts cannot be read in the request's units",
    );
  }

  // 1. The spend, from the bytes: an exact-in instruction spends exactly its
  //    amount in, so this bounds the landing, not only the simulation (H4).
  const requested =
    inMint === NATIVE_MINT ? solLiteralToLamports(grounded.amountText) : tokenAmountToBaseUnits(grounded.amountText, inDecimals);
  if (decoded.amountIn > requested) {
    throw new SwapRouteRefusal(
      `${decoded.name} spends ${decoded.amountIn} base units of ${grounded.input.written}; the request spends ` +
        `${grounded.amountText} (${requested})`,
    );
  }

  // 2. The minimum the chain will enforce, against what was simulated.
  if (decoded.minOut === 0n) {
    throw new SwapRouteRefusal(`${decoded.name} accepts an output of zero: the chain would hold it to nothing`);
  }
  const simulatedOut =
    outMint === NATIVE_MINT ? (effect.wrappedSolDelta ?? 0n) : (effect.tokenDelta.get(outMint) ?? 0n);
  if (simulatedOut < decoded.minOut) {
    throw new SwapRouteRefusal(
      `${decoded.name}'s minimum output is ${decoded.minOut}, but the simulation delivered ${simulatedOut} base units of ` +
        `${grounded.output.written} into the wallet's token accounts`,
    );
  }
  const stated = grounded.slippageBps;
  if (stated !== undefined && stated > SWAP_SLIPPAGE_CEILING_BPS) {
    throw new SwapRouteRefusal(
      `the request allows ${stated / 100}% slippage; the guard allows at most ${SWAP_SLIPPAGE_CEILING_BPS / 100}%`,
    );
  }
  const maxSlippageBps = stated ?? policy.maxSlippageBps;
  if (decoded.minOut * 10_000n < simulatedOut * BigInt(10_000 - maxSlippageBps)) {
    throw new SwapRouteRefusal(
      `${decoded.name}'s minimum output is ${decoded.minOut}, more than ${maxSlippageBps} bps below the ${simulatedOut} ` +
        "the simulation delivered: at landing the chain would accept that much less than was verified" +
        (stated === undefined ? " (state a slippage in the request, or set GRAPHITE_SWAP_MAX_SLIPPAGE_BPS)" : ""),
    );
  }

  // 3. A price floor for the minimum: the request's, else the operator's.
  if (grounded.minOutText !== undefined) {
    const floor = tokenAmountToBaseUnits(grounded.minOutText, outDecimals);
    if (decoded.minOut < floor) {
      throw new SwapRouteRefusal(
        `the request asks for at least ${grounded.minOutText} ${grounded.output.written} (${floor} base units); ` +
          `${decoded.name}'s minimum output is ${decoded.minOut}`,
      );
    }
    return { amountIn: decoded.amountIn, minOut: decoded.minOut, simulatedOut, maxSlippageBps, floor: { baseUnits: floor, source: "request" } };
  }
  const rate = policy.minRates.find((r) => r.inMint === inMint && r.outMint === outMint);
  if (rate !== undefined) {
    // minOut ≥ rate × amountIn / 10^inDecimals × 10^outDecimals, rounded up.
    const { num, scale } = decimalParts(rate.rate);
    const floor = ceilDiv(num * decoded.amountIn * 10n ** BigInt(outDecimals), scale * 10n ** BigInt(inDecimals));
    if (decoded.minOut < floor) {
      throw new SwapRouteRefusal(
        `${decoded.name}'s minimum output is ${decoded.minOut} base units of ${grounded.output.written}; the operator's ` +
          `floor for ${rate.pair} (${rate.rate} per unit, GRAPHITE_SWAP_MIN_RATES) requires ${floor} for this input`,
      );
    }
    return { amountIn: decoded.amountIn, minOut: decoded.minOut, simulatedOut, maxSlippageBps, floor: { baseUnits: floor, source: "operator" } };
  }
  if (!policy.allowUnpriced) {
    throw new SwapRouteRefusal(
      `nothing prices ${grounded.input.written} → ${grounded.output.written}: the request states no minimum ` +
        `("… for at least <amount> ${grounded.output.written}") and the operator sets no floor for the pair ` +
        "(GRAPHITE_SWAP_MIN_RATES). A simulation shows what a pool pays now, not that it is a price anyone agreed to",
    );
  }
  return { amountIn: decoded.amountIn, minOut: decoded.minOut, simulatedOut, maxSlippageBps, floor: { source: "unpriced" } };
}
