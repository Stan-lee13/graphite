/**
 * The swap instructions the guard can read: their amount in, their minimum
 * out, and whether they are exact-in at all.
 *
 * Round 29 (audit 2026-10-20, H2 + H4). The guard used to accept a swap
 * payload for any of 46 programs and never read its data. Two things followed:
 *
 *   - H2: what a swap DELIVERS was bounded by nothing. `assertSwapEffectMatches`
 *     required only that some of the requested token arrived in a simulation,
 *     and its comment said "the route's own minimum is the Core's to read" —
 *     the Core reads no route's minimum. A route whose minimum output is one
 *     base unit passed, and at landing could deliver exactly that.
 *   - H4: what a swap SPENDS was one simulation's snapshot. Exact-output
 *     instructions (Jupiter `exact_out_route`, Whirlpool with
 *     `amount_specified_is_input = false`, Raydium CLMM base-output, CPMM
 *     `swap_base_output`, DLMM `swap_exact_out`) bound their input only by a
 *     caller-chosen maximum: 1 SOL at simulation, up to that maximum at landing.
 *
 * The guard now builds a swap only from an instruction it decodes here, with
 * certainty, from the layouts committed in this repository:
 *
 *   Jupiter v6 `route`, `shared_accounts_route`
 *       graphite-core/scripts/idls/jupiter.json
 *   Orca Whirlpools `swap`, `swapV2`
 *       graphite-core/scripts/idls/orca-whirlpools.json (+ scripts/whirlpool_idl.json)
 *   Raydium CPMM `swap_base_input`        graphite-core/scripts/idls/raydium_cpmm.json
 *   Raydium CLMM `swap`, `swap_v2`        graphite-core/scripts/idls/raydium_clmm.json
 *   Raydium AMM v4 `SwapBaseIn` (tag 9)   graphite-core/protocols/raydium-amm-v4.json
 *       (native: u8 tag, amount_in u64, minimum_amount_out u64)
 *   Meteora DLMM `swap`, `swap2`          graphite-core/scripts/idls/meteora-dlmm.json
 *
 * Each decode reads every byte: the data must end exactly where the layout
 * ends. Anchor deserializes arguments with `deserialize`, which ignores
 * trailing bytes, so a decoder that read the amounts from the END of the data
 * (or stopped early) could be shown one set of numbers while the program
 * reads another. A Borsh `bool` or `Option` tag other than 0/1, an enum tag
 * this file does not know, or a length past the data is a refusal.
 *
 * Left out, deliberately:
 *   - Jupiter `route_v2` / `shared_accounts_route_v2` (bb64facc31c4af14 /
 *     d19853937cfed8e9) and the `*_with_token_ledger` routes. No committed IDL
 *     carries the deployed v2 argument layout (`jupiter_v6_surfpool.json`'s
 *     discriminators are not the deployed ones), and a token-ledger route's
 *     input amount is not in its data. A route the guard cannot read is a
 *     route whose minimum it cannot hold anyone to.
 *   - Jupiter's platform fee: a route with `platform_fee_bps > 0` is refused,
 *     because the fee is taken from the output the minimum is computed on.
 *   - Every exact-output form, named by its own refusal below.
 */

/** A refusal of the swap route itself: unreadable, exact-out, or not worth what was asked. */
export class SwapRouteRefusal extends Error {
  constructor(message: string) {
    super(`[Graphite] swap route: ${message}. REFUSED; nothing was signed or sent.`);
    this.name = "SwapRouteRefusal";
  }
}

export const JUPITER_V6 = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
export const ORCA_WHIRLPOOLS = "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc";
export const RAYDIUM_CPMM = "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C";
export const RAYDIUM_CLMM = "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK";
export const RAYDIUM_AMM_V4 = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8";
export const METEORA_DLMM = "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo";

/** What the guard read out of a swap instruction's data. */
export interface DecodedSwap {
  programId: string;
  /** e.g. "Orca Whirlpools swap". */
  name: string;
  /**
   * The instruction's selector, lowercase hex, exactly the bytes the program
   * dispatches on (8 for Anchor, 1 for Raydium AMM v4). Round 29 (L1): this
   * string is what is sent to the Core as `instruction_discriminator` and
   * what AuditBind binds, so the two sides hash the same text.
   */
  discriminator: string;
  /** The exact input the instruction spends, in the input token's base units. */
  amountIn: bigint;
  /** The least output the program will accept, in the output token's base units. */
  minOut: bigint;
}

const U64_MAX = (1n << 64n) - 1n;

/** A strict Borsh reader: every read is bounds-checked; `end()` requires the data be used up. */
class Reader {
  #data: Uint8Array;
  #at: number;
  readonly #what: string;
  constructor(data: Uint8Array, at: number, what: string) {
    this.#data = data;
    this.#at = at;
    this.#what = what;
  }
  #take(n: number, field: string): Uint8Array {
    if (this.#at + n > this.#data.length) {
      throw new SwapRouteRefusal(`${this.#what}: the data ends inside ${field}`);
    }
    const out = this.#data.subarray(this.#at, this.#at + n);
    this.#at += n;
    return out;
  }
  u8(field: string): number {
    return this.#take(1, field)[0];
  }
  u16(field: string): number {
    const b = this.#take(2, field);
    return b[0] | (b[1] << 8);
  }
  u32(field: string): number {
    const b = this.#take(4, field);
    return (b[0] | (b[1] << 8) | (b[2] << 16)) + b[3] * 0x1000000;
  }
  u64(field: string): bigint {
    const b = this.#take(8, field);
    let v = 0n;
    for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
    return v;
  }
  skip(n: number, field: string): void {
    this.#take(n, field);
  }
  /** Borsh bool: exactly 0 or 1. */
  bool(field: string): boolean {
    const b = this.u8(field);
    if (b > 1) throw new SwapRouteRefusal(`${this.#what}: ${field} is ${b}, not a Borsh bool`);
    return b === 1;
  }
  /** Borsh Option tag: exactly 0 (None) or 1 (Some). */
  option(field: string): boolean {
    const b = this.u8(field);
    if (b > 1) throw new SwapRouteRefusal(`${this.#what}: ${field} has Option tag ${b}`);
    return b === 1;
  }
  /** Borsh Vec length (u32), bounded so a hostile length cannot become a long loop. */
  vecLen(field: string, max: number): number {
    const n = this.u32(field);
    if (n > max) throw new SwapRouteRefusal(`${this.#what}: ${field} has ${n} entries, more than ${max}`);
    return n;
  }
  end(): void {
    if (this.#at !== this.#data.length) {
      throw new SwapRouteRefusal(
        `${this.#what}: ${this.#data.length - this.#at} byte(s) follow the last argument. The program ` +
          "ignores trailing bytes, so data that does not end with its layout is data the guard and the " +
          "program could read differently",
      );
    }
  }
}

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

/**
 * Jupiter v6 `Swap` enum (graphite-core/scripts/idls/jupiter.json, variants
 * 0..61): the argument bytes each variant carries. `swap-instructions.test.ts`
 * checks this table against the committed IDL, variant by variant.
 *   "unit": none; "bool"; "side" (enum Side, tag 0..1); "u64u64"; "u32";
 *   "clone" (u8, bool, bool); "whirlpoolV2" (bool, Option<RemainingAccountsInfo>).
 */
export type JupiterSwapPayload = "unit" | "bool" | "side" | "u64u64" | "u32" | "clone" | "whirlpoolV2";
export const JUPITER_SWAP_VARIANTS: readonly JupiterSwapPayload[] = [
  "unit", "unit", "unit", "unit", "unit", "unit", "unit", "unit", // 0-7 Saber..Raydium
  "bool", // 8 Crema
  "unit", "unit", "unit", // 9-11 Lifinity, Mercurial, Cykura
  "side", // 12 Serum
  "unit", "unit", // 13-14 MarinadeDeposit, MarinadeUnstake
  "side", "side", // 15-16 Aldrin, AldrinV2
  "bool", "bool", // 17-18 Whirlpool, Invariant
  "unit", "unit", // 19-20 Meteora, GooseFX
  "bool", // 21 DeltaFi
  "unit", // 22 Balansol
  "bool", // 23 MarcoPolo
  "side", // 24 Dradex
  "unit", "unit", // 25-26 LifinityV2, RaydiumClmm
  "side", "side", // 27-28 Openbook, Phoenix
  "u64u64", // 29 Symmetry
  "unit", "unit", "unit", // 30-32 TokenSwapV2, HeliumTreasury…, StakeDexStakeWrappedSol
  "u32", // 33 StakeDexSwapViaStake
  "unit", "unit", "unit", "unit", "unit", // 34-38 GooseFXV2, Perps…, MeteoraDlmm
  "side", // 39 OpenBookV2
  "unit", // 40 RaydiumClmmV2
  "clone", // 41 Clone
  "whirlpoolV2", // 42 WhirlpoolSwapV2
  "unit", "unit", "unit", "unit", "unit", "unit", "unit", "unit", "unit", "unit", // 43-52
  "bool", // 53 Obric
  "unit", // 54 FoxBuyFromEstimatedCost
  "bool", "bool", // 55-56 FoxClaimPartial, SolFi
  "unit", "unit", // 57-58 Solayer…
  "side", // 59 TokenMill
  "unit", "unit", // 60-61 DaosFunBuy, DaosFunSell
];
/** Jupiter's `AccountsType` (TransferHookA, TransferHookB): unit variants only. */
const JUPITER_ACCOUNTS_TYPES = 2;
/** Orca Whirlpools' `AccountsType`: nine unit variants. */
const WHIRLPOOL_ACCOUNTS_TYPES = 9;
/** A route longer than this is not a route this guard has a reason to read. */
const MAX_ROUTE_STEPS = 32;
const MAX_REMAINING_SLICES = 16;

function jupiterSwapPayload(r: Reader, step: number): void {
  const tag = r.u8(`route_plan[${step}].swap`);
  const kind = JUPITER_SWAP_VARIANTS[tag];
  if (kind === undefined) {
    throw new SwapRouteRefusal(
      `Jupiter route step ${step} uses Swap variant ${tag}, past the ${JUPITER_SWAP_VARIANTS.length} ` +
        "variants of the committed IDL; its layout is not one the guard can read",
    );
  }
  const f = `route_plan[${step}].swap(${tag})`;
  switch (kind) {
    case "unit":
      return;
    case "bool":
      r.bool(f);
      return;
    case "side": {
      const side = r.u8(f);
      if (side > 1) throw new SwapRouteRefusal(`Jupiter ${f} has Side ${side}`);
      return;
    }
    case "u64u64":
      r.u64(f);
      r.u64(f);
      return;
    case "u32":
      r.u32(f);
      return;
    case "clone":
      r.u8(f);
      r.bool(f);
      r.bool(f);
      return;
    case "whirlpoolV2":
      r.bool(f);
      if (r.option(f)) remainingAccountsInfo(r, f, JUPITER_ACCOUNTS_TYPES, false);
      return;
  }
}

/** `RemainingAccountsInfo { slices: Vec<{ accounts_type: AccountsType, length: u8 }> }`. */
function remainingAccountsInfo(r: Reader, f: string, unitVariants: number, dlmmMultiReward: boolean): void {
  const n = r.vecLen(`${f}.slices`, MAX_REMAINING_SLICES);
  for (let i = 0; i < n; i++) {
    const t = r.u8(`${f}.slices[${i}].accounts_type`);
    if (dlmmMultiReward && t === 3) {
      r.u8(`${f}.slices[${i}].TransferHookMultiReward`);
    } else if (t >= unitVariants) {
      throw new SwapRouteRefusal(`${f}.slices[${i}] has AccountsType ${t}, which the committed IDL does not define`);
    }
    r.u8(`${f}.slices[${i}].length`);
  }
}

/**
 * Jupiter's own minimum for an exact-in route: `quoted_out_amount` less
 * `slippage_bps` of it, rounded down (the quote API's `otherAmountThreshold`
 * for ExactIn). Rounding down is the conservative side: whatever the program
 * enforces is at least this.
 */
export function jupiterMinimumOut(quotedOut: bigint, slippageBps: number): bigint {
  return (quotedOut * BigInt(10_000 - slippageBps)) / 10_000n;
}

function decodeJupiterRoute(data: Uint8Array, shared: boolean, name: string, disc: string): DecodedSwap {
  const r = new Reader(data, 8, name);
  if (shared) r.u8("id");
  const steps = r.vecLen("route_plan", MAX_ROUTE_STEPS);
  if (steps === 0) throw new SwapRouteRefusal(`${name}: the route has no steps`);
  for (let i = 0; i < steps; i++) {
    jupiterSwapPayload(r, i);
    r.u8(`route_plan[${i}].percent`);
    r.u8(`route_plan[${i}].input_index`);
    r.u8(`route_plan[${i}].output_index`);
  }
  const amountIn = r.u64("in_amount");
  const quotedOut = r.u64("quoted_out_amount");
  const slippageBps = r.u16("slippage_bps");
  const platformFeeBps = r.u8("platform_fee_bps");
  r.end();
  if (slippageBps > 10_000) throw new SwapRouteRefusal(`${name}: slippage_bps ${slippageBps} is over 100%`);
  if (platformFeeBps !== 0) {
    throw new SwapRouteRefusal(
      `${name}: platform_fee_bps is ${platformFeeBps}. A platform fee is taken from the output the ` +
        "route's minimum is computed on, to an account the route names; the guard builds fee-free routes only",
    );
  }
  return { programId: JUPITER_V6, name, discriminator: disc, amountIn, minOut: jupiterMinimumOut(quotedOut, slippageBps) };
}

/** `amount, other_amount_threshold, sqrt_price_limit (u128), <exact-in flag>, [a_to_b]` (Whirlpool / CLMM). */
function decodeConcentrated(
  data: Uint8Array,
  programId: string,
  name: string,
  disc: string,
  opts: { aToB: boolean; remaining: "none" | "whirlpoolOption" },
): DecodedSwap {
  const r = new Reader(data, 8, name);
  const amount = r.u64("amount");
  const threshold = r.u64("other_amount_threshold");
  r.skip(16, "sqrt_price_limit");
  const exactIn = r.bool(opts.aToB ? "amount_specified_is_input" : "is_base_input");
  if (opts.aToB) r.bool("a_to_b");
  if (opts.remaining === "whirlpoolOption" && r.option("remaining_accounts_info")) {
    remainingAccountsInfo(r, "remaining_accounts_info", WHIRLPOOL_ACCOUNTS_TYPES, false);
  }
  r.end();
  if (!exactIn) {
    throw new SwapRouteRefusal(
      `${name} is exact-OUTPUT (${opts.aToB ? "amount_specified_is_input" : "is_base_input"} = false): its input ` +
        "is bounded only by a maximum the route chose, so what it spends at landing is not what was simulated",
    );
  }
  return { programId, name, discriminator: disc, amountIn: amount, minOut: threshold };
}

/** `amount_in u64, minimum_amount_out u64` after the selector (CPMM, AMM v4, DLMM `swap`). */
function decodeInMin(data: Uint8Array, at: number, programId: string, name: string, disc: string, dlmmRemaining = false): DecodedSwap {
  const r = new Reader(data, at, name);
  const amountIn = r.u64("amount_in");
  const minOut = r.u64("minimum_amount_out");
  if (dlmmRemaining) remainingAccountsInfo(r, "remaining_accounts_info", 3, true);
  r.end();
  return { programId, name, discriminator: disc, amountIn, minOut };
}

type Decoder = (data: Uint8Array) => DecodedSwap;

/** Exact-in instructions, by program and selector. */
const DECODERS: ReadonlyMap<string, ReadonlyMap<string, Decoder>> = new Map<string, Map<string, Decoder>>([
  [
    JUPITER_V6,
    new Map<string, Decoder>([
      ["e517cb977ae3ad2a", (d) => decodeJupiterRoute(d, false, "Jupiter v6 route", "e517cb977ae3ad2a")],
      ["c1209b3341d69c81", (d) => decodeJupiterRoute(d, true, "Jupiter v6 shared_accounts_route", "c1209b3341d69c81")],
    ]),
  ],
  [
    ORCA_WHIRLPOOLS,
    new Map<string, Decoder>([
      ["f8c69e91e17587c8", (d) => decodeConcentrated(d, ORCA_WHIRLPOOLS, "Orca Whirlpools swap", "f8c69e91e17587c8", { aToB: true, remaining: "none" })],
      ["2b04ed0b1ac91e62", (d) => decodeConcentrated(d, ORCA_WHIRLPOOLS, "Orca Whirlpools swapV2", "2b04ed0b1ac91e62", { aToB: true, remaining: "whirlpoolOption" })],
    ]),
  ],
  [
    RAYDIUM_CLMM,
    new Map<string, Decoder>([
      ["f8c69e91e17587c8", (d) => decodeConcentrated(d, RAYDIUM_CLMM, "Raydium CLMM swap", "f8c69e91e17587c8", { aToB: false, remaining: "none" })],
      ["2b04ed0b1ac91e62", (d) => decodeConcentrated(d, RAYDIUM_CLMM, "Raydium CLMM swap_v2", "2b04ed0b1ac91e62", { aToB: false, remaining: "none" })],
    ]),
  ],
  [
    RAYDIUM_CPMM,
    new Map<string, Decoder>([
      ["8fbe5adac41e33de", (d) => decodeInMin(d, 8, RAYDIUM_CPMM, "Raydium CPMM swap_base_input", "8fbe5adac41e33de")],
    ]),
  ],
  [
    RAYDIUM_AMM_V4,
    new Map<string, Decoder>([["09", (d) => decodeInMin(d, 1, RAYDIUM_AMM_V4, "Raydium AMM v4 SwapBaseIn", "09")]]),
  ],
  [
    METEORA_DLMM,
    new Map<string, Decoder>([
      ["f8c69e91e17587c8", (d) => decodeInMin(d, 8, METEORA_DLMM, "Meteora DLMM swap", "f8c69e91e17587c8")],
      ["414b3f4ceb5b5b88", (d) => decodeInMin(d, 8, METEORA_DLMM, "Meteora DLMM swap2", "414b3f4ceb5b5b88", true)],
    ]),
  ],
]);

/** Exact-output instructions on the same programs, refused by name. */
const EXACT_OUT: ReadonlyMap<string, ReadonlyMap<string, string>> = new Map([
  [
    JUPITER_V6,
    new Map([
      ["d033ef977b2bed5c", "exact_out_route"],
      ["b0d169a89a7d453e", "shared_accounts_exact_out_route"],
      ["9d8ab85215f4f324", "exact_out_route_v2"],
      ["3560e5cad8bbfa18", "shared_accounts_exact_out_route_v2"],
    ]),
  ],
  [RAYDIUM_CPMM, new Map([["37d96256a34ab4ad", "swap_base_output"]])],
  [RAYDIUM_AMM_V4, new Map([["0b", "SwapBaseOut"], ["11", "SwapBaseOutV2"]])],
  [
    METEORA_DLMM,
    new Map([
      ["fa49652126cf4bb8", "swap_exact_out"],
      ["2bd7f784893cf351", "swap_exact_out2"],
    ]),
  ],
]);

/** The programs `decodeSwapInstruction` reads. `SWAP_PROGRAM_IDS` is exactly this set. */
export const DECODED_SWAP_PROGRAMS: ReadonlySet<string> = new Set(DECODERS.keys());

/** A selector as the Core and AuditBind see it: lowercase hex, no `0x` (Round 29, L1). */
export function normalizeDiscriminator(d: string): string {
  return d.replace(/^0x/i, "").toLowerCase();
}

/**
 * Decode a swap instruction's data, or refuse. `declared` is the selector the
 * payload claims; it must be the one the data starts with, normalised the
 * way it is sent to the Core.
 */
export function decodeSwapInstruction(programId: string, data: Uint8Array, declared?: string): DecodedSwap {
  const decoders = DECODERS.get(programId);
  if (!decoders) {
    throw new SwapRouteRefusal(`${programId} is not a program whose swap instruction the guard decodes`);
  }
  const width = programId === RAYDIUM_AMM_V4 ? 1 : 8;
  if (data.length < width) throw new SwapRouteRefusal(`the instruction data is ${data.length} bytes, shorter than a selector`);
  const selector = hex(data.subarray(0, width));
  if (declared !== undefined && normalizeDiscriminator(declared) !== selector) {
    throw new SwapRouteRefusal(
      `the payload declares discriminator ${JSON.stringify(declared)}, but its data starts with ${selector}`,
    );
  }
  const exactOut = EXACT_OUT.get(programId)?.get(selector);
  if (exactOut !== undefined) {
    throw new SwapRouteRefusal(
      `${exactOut} is an exact-OUTPUT instruction: its input is bounded only by a maximum the route chose, so ` +
        "what it spends at landing is not what was simulated",
    );
  }
  const decode = decoders.get(selector);
  if (!decode) {
    throw new SwapRouteRefusal(
      `instruction ${selector} on ${programId} is not an exact-in swap whose data the guard decodes ` +
        `(decoded: ${[...decoders.keys()].join(", ")})`,
    );
  }
  const decoded = decode(data);
  if (decoded.amountIn === 0n || decoded.amountIn > U64_MAX) {
    throw new SwapRouteRefusal(`${decoded.name}: the input amount is ${decoded.amountIn}`);
  }
  return decoded;
}
