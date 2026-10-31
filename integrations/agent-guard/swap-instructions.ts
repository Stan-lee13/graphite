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
 *   Jupiter v6 `route`, `shared_accounts_route`, `route_v2`,
 *   `shared_accounts_route_v2` (Round 41, D-23)
 *       graphite-core/scripts/out/onchain_idls/JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4.json
 *       (the deployed program's IDL; `scripts/idls/jupiter.json` agrees with
 *       it on the v1 arguments but not on the Swap enum past variant 40)
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
 *   - Jupiter's `*_with_token_ledger` routes: their input amount is not in
 *     their data. A route the guard cannot read is a route whose minimum it
 *     cannot hold anyone to.
 *   - Jupiter `route_v2` / `shared_accounts_route_v2` with a non-zero
 *     `positive_slippage_bps`: nothing committed says what it takes from the
 *     output, so the delivered amount is not bounded by the route's bytes.
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
 * Jupiter v6 `Swap` enum, as the committed ON-CHAIN IDL states it
 * (graphite-core/scripts/out/onchain_idls/JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4.json,
 * variants 0..203): one Borsh field per token (Round 41, D-23; 188..203 from
 * the IDL deployed on 2026-10-31, D-27).
 *   "bool", "u8", "u16", "u32", "u64", "u128": the scalar (a bool is 0 or 1);
 *   "enumN": a unit enum with N variants (Side is "enum2");
 *   "u8xN", "u64xN": a fixed array; "bytes": a Vec<u8>;
 *   "rai": RemainingAccountsInfo { slices: Vec<{ accounts_type: u8, length: u8 }> };
 *   "option<T>": an Option (tag 0 or 1) of T;
 *   "vec<candidate>" / "vec<candidate_bps>": Vec<CandidateSwap> /
 *   Vec<CandidateSwapWithBps { candidate_swap, bps: u32 }>, each CandidateSwap
 *   read from JUPITER_CANDIDATE_SWAPS.
 * Until Round 41 this was the 62 variants of scripts/idls/jupiter.json, which
 * agrees with the deployed program only up to variant 40.
 * `swap-instructions.test.ts` checks both tables against the on-chain IDL,
 * variant by variant; the Core's `round36_intent_binding` checks they are the
 * Core's tables.
 */
export const JUPITER_SWAP_VARIANTS: readonly (readonly string[])[] = [
  [], // 0 Saber
  [], // 1 SaberAddDecimalsDeposit
  [], // 2 SaberAddDecimalsWithdraw
  [], // 3 TokenSwap
  [], // 4 Sencha
  [], // 5 Step
  [], // 6 Cropper
  [], // 7 Raydium
  ["bool"], // 8 Crema
  [], // 9 Lifinity
  [], // 10 Mercurial
  [], // 11 Cykura
  ["enum2"], // 12 Serum
  [], // 13 MarinadeDeposit
  [], // 14 MarinadeUnstake
  ["enum2"], // 15 Aldrin
  ["enum2"], // 16 AldrinV2
  ["bool"], // 17 Whirlpool
  ["bool"], // 18 Invariant
  [], // 19 Meteora
  [], // 20 GooseFX
  ["bool"], // 21 DeltaFi
  [], // 22 Balansol
  ["bool"], // 23 MarcoPolo
  ["enum2"], // 24 Dradex
  [], // 25 LifinityV2
  [], // 26 RaydiumClmm
  ["enum2"], // 27 Openbook
  ["enum2"], // 28 Phoenix
  ["u64", "u64"], // 29 Symmetry
  [], // 30 TokenSwapV2
  [], // 31 HeliumTreasuryManagementRedeemV0
  [], // 32 StakeDexStakeWrappedSol
  ["u32"], // 33 StakeDexSwapViaStake
  [], // 34 GooseFXV2
  [], // 35 Perps
  [], // 36 PerpsAddLiquidity
  [], // 37 PerpsRemoveLiquidity
  [], // 38 MeteoraDlmm
  ["enum2"], // 39 OpenBookV2
  [], // 40 RaydiumClmmV2
  ["u32"], // 41 StakeDexPrefundWithdrawStakeAndDepositStake
  ["u8", "bool", "bool"], // 42 Clone
  ["u8", "u8", "u32", "u32"], // 43 SanctumS
  ["u8", "u32"], // 44 SanctumSAddLiquidity
  ["u8", "u32"], // 45 SanctumSRemoveLiquidity
  [], // 46 RaydiumCP
  ["bool", "option<rai>"], // 47 WhirlpoolSwapV2
  [], // 48 OneIntro
  [], // 49 PumpWrappedBuy
  [], // 50 PumpWrappedSell
  [], // 51 PerpsV2
  [], // 52 PerpsV2AddLiquidity
  [], // 53 PerpsV2RemoveLiquidity
  [], // 54 MoonshotWrappedBuy
  [], // 55 MoonshotWrappedSell
  [], // 56 StabbleStableSwap
  [], // 57 StabbleWeightedSwap
  ["bool"], // 58 Obric
  [], // 59 FoxBuyFromEstimatedCost
  ["bool"], // 60 FoxClaimPartial
  ["bool"], // 61 SolFi
  [], // 62 SolayerDelegateNoInit
  [], // 63 SolayerUndelegateNoInit
  ["enum2"], // 64 TokenMill
  [], // 65 DaosFunBuy
  [], // 66 DaosFunSell
  [], // 67 ZeroFi
  [], // 68 StakeDexWithdrawWrappedSol
  [], // 69 VirtualsBuy
  [], // 70 VirtualsSell
  ["u8", "u8"], // 71 Perena
  [], // 72 PumpSwapBuy
  [], // 73 PumpSwapSell
  [], // 74 Gamma
  ["rai"], // 75 MeteoraDlmmSwapV2
  [], // 76 Woofi
  [], // 77 MeteoraDammV2
  [], // 78 MeteoraDynamicBondingCurveSwap
  [], // 79 StabbleStableSwapV2
  [], // 80 StabbleWeightedSwapV2
  ["u64"], // 81 RaydiumLaunchlabBuy
  ["u64"], // 82 RaydiumLaunchlabSell
  [], // 83 BoopdotfunWrappedBuy
  [], // 84 BoopdotfunWrappedSell
  ["enum2"], // 85 Plasma
  ["bool", "u8"], // 86 GoonFi
  ["u64", "bool"], // 87 HumidiFi
  [], // 88 MeteoraDynamicBondingCurveSwapWithRemainingAccounts
  ["enum2"], // 89 TesseraV
  [], // 90 PumpWrappedBuyV2
  [], // 91 PumpWrappedSellV2
  [], // 92 PumpSwapBuyV2
  [], // 93 PumpSwapSellV2
  ["bool"], // 94 Heaven
  ["bool"], // 95 SolFiV2
  [], // 96 Aquifer
  [], // 97 PumpWrappedBuyV3
  [], // 98 PumpWrappedSellV3
  [], // 99 PumpSwapBuyV3
  [], // 100 PumpSwapSellV3
  [], // 101 JupiterLendDeposit
  [], // 102 JupiterLendRedeem
  ["bool", "option<rai>"], // 103 DefiTuna
  ["bool"], // 104 AlphaQ
  [], // 105 RaydiumV2
  ["bool"], // 106 SarosDlmm
  ["enum2"], // 107 Futarchy
  [], // 108 MeteoraDammV2WithRemainingAccounts
  [], // 109 Obsidian
  ["enum2"], // 110 WhaleStreet
  ["vec<candidate>", "option<u8>"], // 111 DynamicV1
  [], // 112 PumpWrappedBuyV4
  [], // 113 PumpWrappedSellV4
  [], // 114 CarrotIssue
  [], // 115 CarrotRedeem
  ["enum2"], // 116 Manifest
  ["bool"], // 117 BisonFi
  ["u64", "bool"], // 118 HumidiFiV2
  ["bool"], // 119 PerenaStar
  ["enum2", "bytes"], // 120 JupiterRfqV2
  ["bool"], // 121 GoonFiV2
  ["u128"], // 122 Scorch
  ["u64x5", "u64"], // 123 VaultLiquidUnstake
  [], // 124 XOrca
  ["enum2"], // 125 Quantum
  ["enum2", "u64", "u64"], // 126 WhaleStreetV2
  ["bool"], // 127 Riptide
  [], // 128 RunnerRodeo
  ["bool"], // 129 TaurusFi
  [], // 130 Omnipair
  [], // 131 MSwap
  ["enum8"], // 132 Hylo
  [], // 133 VoltrDeposit
  [], // 134 VoltrWithdraw
  ["u8", "u8", "u32", "u32"], // 135 SanctumSV2
  ["bool"], // 136 LemmingsFi
  [], // 137 ScaleVmmBuy
  [], // 138 ScaleVmmSell
  [], // 139 ScaleAmmBuy
  [], // 140 ScaleAmmSell
  ["bool"], // 141 BisonFiV2
  [], // 142 Trends
  [], // 143 HumaDeposit
  [], // 144 HumaInstantWithdraw
  ["bool"], // 145 Kipseli
  ["vec<candidate_bps>", "u8", "u8"], // 146 DynamicV2
  [], // 147 PumpSwapBuyV3WithCashbackClaim
  [], // 148 PumpSwapSellV3WithCashbackClaim
  [], // 149 PumpWrappedBuyV4WithCashbackClaim
  [], // 150 PumpWrappedSellV4WithCashbackClaim
  ["bool"], // 151 GoonFiV3
  ["bool"], // 152 PumpWrappedBuyV5
  ["bool"], // 153 PumpWrappedSellV5
  [], // 154 ZeroFiSwapV2
  ["enum2", "bool"], // 155 BisonFiPredict
  [], // 156 ByrealDynamicV3
  ["u64", "bool"], // 157 Flux
  [], // 158 VaultLiquidSellLst
  ["u64"], // 159 VaultLiquidBuyLst
  ["bool"], // 160 KipseliV2
  ["enum2", "u32"], // 161 Deriverse
  ["bool"], // 162 Hadron
  [], // 163 BinaryFi
  ["bool"], // 164 Metric
  ["bool"], // 165 JupiterLendDexSwap
  ["bool"], // 166 Gatorswap
  ["bool", "bool"], // 167 Flint
  ["bool"], // 168 Denali
  [], // 169 PerenaStarV2Deposit
  ["u8"], // 170 PerenaStarV2WithdrawFromExternal
  ["enum3"], // 171 SanctumSols
  ["enum8"], // 172 HyloV2
  [], // 173 SanctumPamm
  ["enum2"], // 174 Archer
  [], // 175 TrenchWrappedBuy
  [], // 176 TrenchWrappedSell
  ["bool"], // 177 BisonFiMarketBacked
  ["enum2"], // 178 TesseraVV2
  [], // 179 Stableswap
  [], // 180 BinaryFiV2
  ["bool"], // 181 KipseliV3
  ["enum2"], // 182 PerenaStarV2TrancheDeposit
  ["enum2", "option<u8>"], // 183 PerenaStarV2TrancheWithdrawFromExternal
  ["bool"], // 184 Quay
  ["u64", "u8x32", "u8x16", "bool"], // 185 HumidiFiRouter
  ["u64", "u64", "u8x32", "u8x16", "bool"], // 186 HumidiFiRouterV2
  ["bool", "bool"], // 187 PumpWrappedBuyV6
  [], // 188 HyloRouter
  ["bool"], // 189 Memefun
  ["u64", "u64", "u64", "u64", "u8x32", "u8x16", "bool"], // 190 HumidiFiRouterV3
  ["bool", "bool"], // 191 PumpWrappedBuyV7
  ["bool"], // 192 PumpWrappedSellV6
  ["bool"], // 193 PumpSwapBuyV4
  ["bool"], // 194 PumpSwapSellV4
  [], // 195 ZeroFiSwapV3
  ["bool"], // 196 DenaliV2
  ["enum2"], // 197 QuantumV2
  [], // 198 DrFraudsworthSolBuy
  ["bool"], // 199 DrFraudsworthSolSell
  [], // 200 DrFraudsworthSplBuy
  [], // 201 DrFraudsworthSplSell
  [], // 202 DrFraudsworthVaultConvert
  ["bool"], // 203 BisonFiMarketBackedV2
];
/** Jupiter v6 `CandidateSwap` (the on-chain IDL, variants 0..19), tokens as above. */
export const JUPITER_CANDIDATE_SWAPS: readonly (readonly string[])[] = [
  ["u64", "bool"], // 0 HumidiFi
  ["enum2"], // 1 TesseraV
  ["u64", "bool"], // 2 HumidiFiV2
  [], // 3 RaydiumV2
  [], // 4 RaydiumClmm
  ["bool"], // 5 Whirlpool
  [], // 6 ZeroFi
  ["bool"], // 7 BisonFiV2
  ["bool"], // 8 GoonFiV2
  ["bool"], // 9 GoonFiV3
  ["bool", "option<rai>"], // 10 WhirlpoolV2
  [], // 11 ZeroFiSwapV2
  ["bool"], // 12 BisonFiMarketBacked
  [], // 13 RaydiumClmmV2
  ["enum2"], // 14 TesseraVV2
  ["u64", "u8x32", "u8x16", "bool"], // 15 HumidiFiRouter
  ["u64", "u64", "u8x32", "u8x16", "bool"], // 16 HumidiFiRouterV2
  ["u64", "u64", "u64", "u64", "u8x32", "u8x16", "bool"], // 17 HumidiFiRouterV3
  [], // 18 ZeroFiSwapV3
  ["bool"], // 19 BisonFiMarketBackedV2
];
/** Orca Whirlpools' `AccountsType`: nine unit variants. */
const WHIRLPOOL_ACCOUNTS_TYPES = 9;
/** A route longer than this is not a route this guard has a reason to read. */
const MAX_ROUTE_STEPS = 32;
const MAX_REMAINING_SLICES = 16;

const MAX_CANDIDATE_SWAPS = 32;
const MAX_SWAP_BYTES = 1024;

/** One Borsh field of a Jupiter Swap / CandidateSwap payload, by its token. An unknown token is a refusal. */
function jupiterField(r: Reader, token: string, f: string): void {
  switch (token) {
    case "bool":
      r.bool(f);
      return;
    case "u8":
      r.u8(f);
      return;
    case "u16":
      r.u16(f);
      return;
    case "u32":
      r.u32(f);
      return;
    case "u64":
      r.u64(f);
      return;
    case "u128":
    case "u8x16":
      r.skip(16, f);
      return;
    case "u8x32":
      r.skip(32, f);
      return;
    case "u64x5":
      r.skip(40, f);
      return;
    case "bytes":
      r.skip(r.vecLen(f, MAX_SWAP_BYTES), f);
      return;
    case "rai": {
      const n = r.vecLen(`${f}.slices`, MAX_REMAINING_SLICES);
      for (let i = 0; i < n; i++) {
        r.u8(`${f}.slices[${i}].accounts_type`);
        r.u8(`${f}.slices[${i}].length`);
      }
      return;
    }
    case "option<u8>":
      if (r.option(f)) r.u8(f);
      return;
    case "option<rai>":
      if (r.option(f)) jupiterField(r, "rai", f);
      return;
    case "vec<candidate>":
    case "vec<candidate_bps>": {
      const n = r.vecLen(f, MAX_CANDIDATE_SWAPS);
      for (let i = 0; i < n; i++) {
        const tag = r.u8(`${f}[${i}]`);
        const fields = JUPITER_CANDIDATE_SWAPS[tag];
        if (fields === undefined) {
          throw new SwapRouteRefusal(
            `Jupiter ${f}[${i}] names CandidateSwap variant ${tag}, past the ${JUPITER_CANDIDATE_SWAPS.length} of the committed on-chain IDL`,
          );
        }
        for (const t of fields) jupiterField(r, t, `${f}[${i}](${tag})`);
        if (token === "vec<candidate_bps>") r.u32(`${f}[${i}].bps`);
      }
      return;
    }
  }
  const variants = /^enum(\d+)$/.exec(token);
  if (variants) {
    const tag = r.u8(f);
    if (tag >= Number(variants[1])) throw new SwapRouteRefusal(`Jupiter ${f} has enum tag ${tag}, past its ${variants[1]} variants`);
    return;
  }
  throw new SwapRouteRefusal(`Jupiter ${f} has a field of type ${token}, which the guard does not read`);
}

function jupiterSwapPayload(r: Reader, step: number): void {
  const tag = r.u8(`route_plan[${step}].swap`);
  const fields = JUPITER_SWAP_VARIANTS[tag];
  if (fields === undefined) {
    throw new SwapRouteRefusal(
      `Jupiter route step ${step} uses Swap variant ${tag}, past the ${JUPITER_SWAP_VARIANTS.length} ` +
        "variants of the committed on-chain IDL; its layout is not one the guard can read",
    );
  }
  for (const t of fields) jupiterField(r, t, `route_plan[${step}].swap(${tag})`);
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

/**
 * Jupiter v6 `route_v2` / `shared_accounts_route_v2` (Round 41, D-23), as the
 * on-chain IDL lays them out: [id u8], in_amount u64, quoted_out_amount u64,
 * slippage_bps u16, platform_fee_bps u16, positive_slippage_bps u16, then
 * route_plan: Vec<RoutePlanStepV2 { swap, bps u16, input_index u8,
 * output_index u8 }>. Every byte read; platform and positive-slippage fees
 * must be 0; the minimum is the v1 route's.
 */
function decodeJupiterRouteV2(data: Uint8Array, shared: boolean, name: string, disc: string): DecodedSwap {
  const r = new Reader(data, 8, name);
  if (shared) r.u8("id");
  const amountIn = r.u64("in_amount");
  const quotedOut = r.u64("quoted_out_amount");
  const slippageBps = r.u16("slippage_bps");
  const platformFeeBps = r.u16("platform_fee_bps");
  const positiveSlippageBps = r.u16("positive_slippage_bps");
  const steps = r.vecLen("route_plan", MAX_ROUTE_STEPS);
  if (steps === 0) throw new SwapRouteRefusal(`${name}: the route has no steps`);
  for (let i = 0; i < steps; i++) {
    jupiterSwapPayload(r, i);
    r.u16(`route_plan[${i}].bps`);
    r.u8(`route_plan[${i}].input_index`);
    r.u8(`route_plan[${i}].output_index`);
  }
  r.end();
  if (slippageBps > 10_000) throw new SwapRouteRefusal(`${name}: slippage_bps ${slippageBps} is over 100%`);
  if (platformFeeBps !== 0) {
    throw new SwapRouteRefusal(
      `${name}: platform_fee_bps is ${platformFeeBps}. A platform fee is taken from the output the ` +
        "route's minimum is computed on; the guard builds fee-free routes only",
    );
  }
  if (positiveSlippageBps !== 0) {
    throw new SwapRouteRefusal(
      `${name}: positive_slippage_bps is ${positiveSlippageBps}; nothing committed says what it takes from the ` +
        "output, so the delivered amount is not bounded by the route's bytes",
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
      ["bb64facc31c4af14", (d) => decodeJupiterRouteV2(d, false, "Jupiter v6 route_v2", "bb64facc31c4af14")],
      ["d19853937cfed8e9", (d) => decodeJupiterRouteV2(d, true, "Jupiter v6 shared_accounts_route_v2", "d19853937cfed8e9")],
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
