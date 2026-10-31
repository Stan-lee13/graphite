/**
 * Round 29 (audit 2026-10-20, H2 + H4): the swap decoders. Each layout is
 * checked against the IDL committed under graphite-core/scripts — the
 * selectors, the argument lists, and Jupiter's Swap enum variant by variant —
 * so the decoder and its source cannot drift apart silently. Then: every byte
 * is read (trailing bytes refused), exact-out is refused by name, Borsh tags
 * are strict.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import bs58 from "bs58";
import {
  decodeSwapInstruction,
  jupiterMinimumOut,
  JUPITER_CANDIDATE_SWAPS,
  JUPITER_SWAP_VARIANTS,
  JUPITER_V6,
  METEORA_DLMM,
  ORCA_WHIRLPOOLS,
  RAYDIUM_AMM_V4,
  RAYDIUM_CLMM,
  RAYDIUM_CPMM,
  SwapRouteRefusal,
} from "./swap-instructions.js";
import { concentratedData, inMinData, jupiterRouteData, jupiterRouteV2Data, raydiumAmmV4Data } from "./swap-fixtures.js";

const SCRIPTS = new URL("../../graphite-core/scripts/", import.meta.url);
type Idl = {
  instructions: { name: string; discriminator?: number[]; args: { name: string; type: unknown }[] }[];
  types?: { name: string; type: { kind: string; variants?: { name: string; fields?: { name?: string; type: unknown }[] | unknown[] }[] } }[];
};
const idl = (path: string): Idl => JSON.parse(readFileSync(new URL(path, SCRIPTS), "utf8"));
const anchor = (name: string) => createHash("sha256").update(`global:${name}`).digest("hex").slice(0, 16);
const argsOf = (i: Idl, name: string) => i.instructions.find((x) => x.name === name)!.args.map((a) => [a.name, a.type]);

test("the decoded layouts are the committed IDLs' layouts", () => {
  const jup = idl("idls/jupiter.json");
  for (const [name, disc] of [["route", "e517cb977ae3ad2a"], ["shared_accounts_route", "c1209b3341d69c81"]] as const) {
    assert.equal(Buffer.from(jup.instructions.find((x) => x.name === name)!.discriminator!).toString("hex"), disc);
  }
  const plan = { vec: { defined: { name: "RoutePlanStep" } } };
  assert.deepEqual(argsOf(jup, "route"), [
    ["route_plan", plan], ["in_amount", "u64"], ["quoted_out_amount", "u64"], ["slippage_bps", "u16"], ["platform_fee_bps", "u8"],
  ]);
  assert.deepEqual(argsOf(jup, "shared_accounts_route"), [
    ["id", "u8"], ["route_plan", plan], ["in_amount", "u64"], ["quoted_out_amount", "u64"], ["slippage_bps", "u16"], ["platform_fee_bps", "u8"],
  ]);

  const whirl = idl("idls/orca-whirlpools.json");
  assert.deepEqual(argsOf(whirl, "swap"), [
    ["amount", "u64"], ["otherAmountThreshold", "u64"], ["sqrtPriceLimit", "u128"], ["amountSpecifiedIsInput", "bool"], ["aToB", "bool"],
  ]);
  assert.deepEqual(argsOf(whirl, "swapV2").slice(0, 5), argsOf(whirl, "swap"));
  assert.deepEqual(argsOf(whirl, "swapV2")[5], ["remainingAccountsInfo", { option: { defined: "RemainingAccountsInfo" } }]);
  assert.equal(anchor("swap"), "f8c69e91e17587c8");
  assert.equal(anchor("swap_v2"), "2b04ed0b1ac91e62");
  const whirlTypes = whirl.types!.find((t) => t.name === "AccountsType")!.type.variants!;
  assert.equal(whirlTypes.length, 9);
  assert.ok(whirlTypes.every((v) => v.fields === undefined), "every Whirlpool AccountsType is a unit variant");

  const clmm = idl("idls/raydium_clmm.json");
  for (const name of ["swap", "swap_v2"]) {
    assert.deepEqual(argsOf(clmm, name), [
      ["amount", "u64"], ["other_amount_threshold", "u64"], ["sqrt_price_limit_x64", "u128"], ["is_base_input", "bool"],
    ]);
  }
  const cpmm = idl("idls/raydium_cpmm.json");
  assert.equal(Buffer.from(cpmm.instructions.find((x) => x.name === "swap_base_input")!.discriminator!).toString("hex"), "8fbe5adac41e33de");
  assert.deepEqual(argsOf(cpmm, "swap_base_input"), [["amount_in", "u64"], ["minimum_amount_out", "u64"]]);

  const dlmm = idl("idls/meteora-dlmm.json");
  assert.deepEqual(argsOf(dlmm, "swap"), [["amount_in", "u64"], ["min_amount_out", "u64"]]);
  assert.equal(Buffer.from(dlmm.instructions.find((x) => x.name === "swap2")!.discriminator!).toString("hex"), "414b3f4ceb5b5b88");
  assert.deepEqual(argsOf(dlmm, "swap2").slice(0, 2), argsOf(dlmm, "swap"));

  const amm = JSON.parse(readFileSync(new URL("../protocols/raydium-amm-v4.json", SCRIPTS), "utf8")) as {
    instructions: { name: string; discriminator: string }[];
  };
  assert.equal(amm.instructions.find((i) => i.name === "SwapBaseIn")!.discriminator, "09");
});

/** The deployed Jupiter v6 program's IDL (Round 41, D-23). */
const ONCHAIN_JUPITER = "out/onchain_idls/JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4.json";

test("Jupiter v1 and v2 routes: the decoded layouts are the deployed program's IDL", () => {
  const jup = idl(ONCHAIN_JUPITER);
  const disc = (name: string) => Buffer.from(jup.instructions.find((x) => x.name === name)!.discriminator!).toString("hex");
  assert.equal(disc("route"), "e517cb977ae3ad2a");
  assert.equal(disc("shared_accounts_route"), "c1209b3341d69c81");
  assert.equal(disc("route_v2"), "bb64facc31c4af14");
  assert.equal(disc("shared_accounts_route_v2"), "d19853937cfed8e9");
  const plan = { vec: { defined: { name: "RoutePlanStep" } } };
  assert.deepEqual(argsOf(jup, "route"), [
    ["route_plan", plan], ["in_amount", "u64"], ["quoted_out_amount", "u64"], ["slippage_bps", "u16"], ["platform_fee_bps", "u8"],
  ]);
  assert.deepEqual(argsOf(jup, "shared_accounts_route"), [["id", "u8"], ...argsOf(jup, "route")]);
  const v2 = [
    ["in_amount", "u64"], ["quoted_out_amount", "u64"], ["slippage_bps", "u16"], ["platform_fee_bps", "u16"],
    ["positive_slippage_bps", "u16"], ["route_plan", { vec: { defined: { name: "RoutePlanStepV2" } } }],
  ];
  assert.deepEqual(argsOf(jup, "route_v2"), v2);
  assert.deepEqual(argsOf(jup, "shared_accounts_route_v2"), [["id", "u8"], ...v2]);
  const struct = (name: string) =>
    (jup.types!.find((t) => t.name === name)!.type as unknown as { fields: { name: string; type: unknown }[] }).fields.map((f) => [f.name, f.type]);
  assert.deepEqual(struct("RoutePlanStep"), [["swap", { defined: { name: "Swap" } }], ["percent", "u8"], ["input_index", "u8"], ["output_index", "u8"]]);
  assert.deepEqual(struct("RoutePlanStepV2"), [["swap", { defined: { name: "Swap" } }], ["bps", "u16"], ["input_index", "u8"], ["output_index", "u8"]]);
  assert.deepEqual(struct("RemainingAccountsSlice"), [["accounts_type", "u8"], ["length", "u8"]]);
  assert.deepEqual(struct("CandidateSwapWithBps"), [["candidate_swap", { defined: { name: "CandidateSwap" } }], ["bps", "u32"]]);
});

test("Jupiter's Swap and CandidateSwap enums: the decoder's payload tables match the deployed IDL, variant by variant", () => {
  const jup = idl(ONCHAIN_JUPITER);
  type T = string | { defined?: { name: string }; array?: [unknown, number]; option?: unknown; vec?: { defined: { name: string } } };
  const typeOf = (name: string) => jup.types!.find((t) => t.name === name)!.type;
  const token = (t: T): string => {
    if (typeof t === "string") return t;
    if (t.defined) {
      if (t.defined.name === "RemainingAccountsInfo") return "rai";
      const e = typeOf(t.defined.name);
      assert.equal(e.kind, "enum", t.defined.name);
      assert.ok(e.variants!.every((v) => v.fields === undefined), `${t.defined.name} is a unit enum`);
      return `enum${e.variants!.length}`;
    }
    if (t.array) return `${token(t.array[0] as T)}x${t.array[1]}`;
    if (t.option) return `option<${token(t.option as T)}>`;
    if (t.vec) return ({ CandidateSwap: "vec<candidate>", CandidateSwapWithBps: "vec<candidate_bps>" } as Record<string, string>)[t.vec.defined.name]!;
    throw new Error(`unmapped ${JSON.stringify(t)}`);
  };
  for (const [name, table] of [["Swap", JUPITER_SWAP_VARIANTS], ["CandidateSwap", JUPITER_CANDIDATE_SWAPS]] as const) {
    const variants = typeOf(name).variants!;
    assert.equal(table.length, variants.length, name);
    variants.forEach((v, i) => {
      const fields = (v.fields ?? []) as { type: T }[];
      assert.deepEqual(table[i], fields.map((f) => token(f.type)), `${name} variant ${i} ${v.name}`);
    });
  }
  assert.equal(JUPITER_SWAP_VARIANTS.length, 204);
  assert.equal(JUPITER_CANDIDATE_SWAPS.length, 20);
});

test("Jupiter route_v2: amounts, minimum and refusals, and a v2 route reads as its v1 twin", () => {
  for (const shared of [false, true]) {
    const sel = shared ? "d19853937cfed8e9" : "bb64facc31c4af14";
    const d = decodeSwapInstruction(JUPITER_V6, Uint8Array.from(jupiterRouteV2Data({ shared })), sel);
    assert.deepEqual([d.amountIn, d.minOut, d.discriminator], [1_000_000_000n, 149_250_000n, sel]);
    const v1 = decodeSwapInstruction(JUPITER_V6, Uint8Array.from(jupiterRouteData({ shared })));
    assert.deepEqual([d.amountIn, d.minOut], [v1.amountIn, v1.minOut], "a v2 route and its v1 twin read alike");
  }
  const refused = (data: number[], why: RegExp) => assert.throws(() => decodeSwapInstruction(JUPITER_V6, Uint8Array.from(data)), why);
  refused(jupiterRouteV2Data({ platformFeeBps: 1 }), /platform_fee_bps is 1/);
  refused(jupiterRouteV2Data({ positiveSlippageBps: 1 }), /positive_slippage_bps is 1/);
  refused(jupiterRouteV2Data({ slippageBps: 10_001 }), /over 100%/);
  refused(jupiterRouteV2Data({ trailing: [0] }), /follow the last argument/);
  refused(jupiterRouteV2Data({ rawPlan: [0, 0, 0, 0] }), /no steps/);
  refused(jupiterRouteV2Data({ rawPlan: [1, 0, 0, 0, 204, 0x10, 0x27, 0, 1] }), /Swap variant 204/);
  refused(jupiterRouteV2Data({ rawPlan: [1, 0, 0, 0, 12, 2, 0x10, 0x27, 0, 1] }), /enum tag 2, past its 2 variants/);
  refused(jupiterRouteV2Data().slice(0, -1), /ends inside/);
  // A DynamicV2 step: two candidates (Whirlpool a_to_b, RaydiumClmm), each with bps, then two u8.
  const dynamic = [1, 0, 0, 0, 146, 2, 0, 0, 0, 5, 1, 0x88, 0x13, 0, 0, 4, 0x88, 0x13, 0, 0, 3, 3, 0x10, 0x27, 0, 1];
  assert.equal(decodeSwapInstruction(JUPITER_V6, Uint8Array.from(jupiterRouteV2Data({ rawPlan: dynamic }))).minOut, 149_250_000n);
  refused(jupiterRouteV2Data({ rawPlan: [1, 0, 0, 0, 111, 1, 0, 0, 0, 20, 0, 0x10, 0x27, 0, 1] }), /CandidateSwap variant 20/);
});

test("each decoded program yields its amount in and its own minimum out", () => {
  const route = decodeSwapInstruction(JUPITER_V6, Uint8Array.from(jupiterRouteData()), "e517cb977ae3ad2a");
  assert.deepEqual([route.amountIn, route.minOut, route.discriminator], [1_000_000_000n, 149_250_000n, "e517cb977ae3ad2a"]);
  const shared = decodeSwapInstruction(JUPITER_V6, Uint8Array.from(jupiterRouteData({ shared: true, slippageBps: 0 })));
  assert.equal(shared.minOut, 150_000_000n);
  assert.equal(jupiterMinimumOut(10_001n, 1), 9_999n, "10,001 × 0.9999 = 9,999.9, rounded down");

  for (const [program, sel, whirlpool, v2] of [
    [ORCA_WHIRLPOOLS, "f8c69e91e17587c8", true, false],
    [ORCA_WHIRLPOOLS, "2b04ed0b1ac91e62", true, true],
    [RAYDIUM_CLMM, "f8c69e91e17587c8", false, false],
    [RAYDIUM_CLMM, "2b04ed0b1ac91e62", false, false],
  ] as const) {
    const d = decodeSwapInstruction(program, Uint8Array.from(concentratedData(sel, { amount: 7n, threshold: 5n, exactIn: true, whirlpool, v2Option: v2 })));
    assert.deepEqual([d.amountIn, d.minOut], [7n, 5n], `${program} ${sel}`);
  }
  assert.equal(decodeSwapInstruction(RAYDIUM_CPMM, Uint8Array.from(inMinData("8fbe5adac41e33de", 9n, 4n))).minOut, 4n);
  assert.equal(decodeSwapInstruction(METEORA_DLMM, Uint8Array.from(inMinData("f8c69e91e17587c8", 9n, 3n))).minOut, 3n);
  // DLMM swap2: a RemainingAccountsInfo with one TransferHookMultiReward(2) slice.
  const swap2 = [...inMinData("414b3f4ceb5b5b88", 9n, 3n), 1, 0, 0, 0, 3, 2, 4];
  assert.equal(decodeSwapInstruction(METEORA_DLMM, Uint8Array.from(swap2)).minOut, 3n);
  const amm = decodeSwapInstruction(RAYDIUM_AMM_V4, Uint8Array.from(raydiumAmmV4Data(11n, 2n)), "09");
  assert.deepEqual([amm.amountIn, amm.minOut, amm.discriminator], [11n, 2n, "09"]);
});

test("H4: every exact-output form is refused, by selector or by flag", () => {
  const refuse = (program: string, data: number[]) =>
    assert.throws(() => decodeSwapInstruction(program, Uint8Array.from(data)), (e: unknown) => e instanceof SwapRouteRefusal && /exact-OUTPUT/.test(String(e)));
  for (const sel of ["d033ef977b2bed5c", "b0d169a89a7d453e", "9d8ab85215f4f324", "3560e5cad8bbfa18"]) {
    refuse(JUPITER_V6, [...Buffer.from(sel, "hex"), 0, 0, 0, 0]);
  }
  refuse(RAYDIUM_CPMM, inMinData("37d96256a34ab4ad", 1n, 1n));
  refuse(RAYDIUM_AMM_V4, raydiumAmmV4Data(1n, 1n, 0x0b));
  refuse(RAYDIUM_AMM_V4, raydiumAmmV4Data(1n, 1n, 0x11));
  refuse(METEORA_DLMM, inMinData("fa49652126cf4bb8", 1n, 1n));
  refuse(METEORA_DLMM, inMinData("2bd7f784893cf351", 1n, 1n));
  refuse(ORCA_WHIRLPOOLS, concentratedData("f8c69e91e17587c8", { amount: 1n, threshold: 1n, exactIn: false, whirlpool: true }));
  refuse(RAYDIUM_CLMM, concentratedData("2b04ed0b1ac91e62", { amount: 1n, threshold: 1n, exactIn: false, whirlpool: false }));
});

test("the data must end where the layout ends, and Borsh tags are strict", () => {
  const refused = (program: string, data: number[], why: RegExp) =>
    assert.throws(() => decodeSwapInstruction(program, Uint8Array.from(data)), why);
  // Trailing bytes: a decoder reading from the end would see these instead.
  refused(JUPITER_V6, jupiterRouteData({ trailing: [...jupiterRouteData({ quotedOut: 10n ** 12n }).slice(-19)] }), /follow the last argument/);
  refused(RAYDIUM_AMM_V4, [...raydiumAmmV4Data(1n, 1n), 0], /follow the last argument/);
  refused(RAYDIUM_CPMM, inMinData("8fbe5adac41e33de", 1n, 1n).slice(0, -1), /ends inside minimum_amount_out/);
  // A bool of 2, an Option tag of 2, an unknown Swap variant, an unknown AccountsType.
  const whirl = concentratedData("f8c69e91e17587c8", { amount: 1n, threshold: 1n, exactIn: true, whirlpool: true });
  whirl[8 + 32] = 2;
  refused(ORCA_WHIRLPOOLS, whirl, /not a Borsh bool/);
  refused(ORCA_WHIRLPOOLS, [...concentratedData("2b04ed0b1ac91e62", { amount: 1n, threshold: 1n, exactIn: true, whirlpool: true }), 2], /Option tag 2/);
  // Round 41 (D-23, D-27): the deployed enum has 204 variants (62 was the first past the old table), and
  // WhirlpoolSwapV2 is variant 47, whose remaining-accounts Option must have a tag of 0 or 1.
  refused(JUPITER_V6, jupiterRouteData({ rawPlan: [1, 0, 0, 0, 204, 100, 0, 1] }), /Swap variant 204/);
  refused(JUPITER_V6, jupiterRouteData({ rawPlan: [1, 0, 0, 0, 47, 1, 2, 100, 0, 1] }), /Option tag 2/);
  refused(JUPITER_V6, jupiterRouteData({ rawPlan: [0, 0, 0, 0] }), /no steps/);
  refused(JUPITER_V6, jupiterRouteData({ rawPlan: [255, 255, 255, 255] }), /more than 32/);
  refused(JUPITER_V6, jupiterRouteData({ slippageBps: 10_001 }), /over 100%/);
});

test("a selector the guard does not decode, on a program it does, is refused; so is a mismatched declaration", () => {
  assert.throws(
    // `route_with_token_ledger`: its input amount is not in its data.
    () => decodeSwapInstruction(JUPITER_V6, Uint8Array.from([...Buffer.from("96564774a75d0e68", "hex"), 0])),
    /not an exact-in swap whose data the guard decodes/,
  );
  assert.throws(
    () => decodeSwapInstruction(RAYDIUM_AMM_V4, Uint8Array.from(raydiumAmmV4Data(1n, 1n, 0x10))),
    /instruction 10 .* not an exact-in swap/,
  );
  assert.throws(
    () => decodeSwapInstruction(JUPITER_V6, Uint8Array.from(jupiterRouteData()), "c1209b3341d69c81"),
    /declares discriminator "c1209b3341d69c81", but its data starts with e517cb977ae3ad2a/,
  );
  assert.throws(() => decodeSwapInstruction("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", new Uint8Array(9)), /not a program/);
  assert.throws(() => decodeSwapInstruction(RAYDIUM_CPMM, Uint8Array.from(inMinData("8fbe5adac41e33de", 0n, 1n))), /input amount is 0/);
});

test("the pinned mainnet route_v2 (slot 438012579) reads to its end; refused for its 150 bps platform fee only", () => {
  const fixture = JSON.parse(readFileSync(new URL("../tests/fixtures/real_mainnet_jup.json", SCRIPTS), "utf8")) as {
    transaction: { message: { accountKeys: string[]; instructions: { programIdIndex: number; data: string }[] } };
  };
  const m = fixture.transaction.message;
  const route = m.instructions.find((ix) => m.accountKeys[ix.programIdIndex] === JUPITER_V6)!;
  const data = bs58.decode(route.data);
  assert.equal(Buffer.from(data.subarray(0, 8)).toString("hex"), "bb64facc31c4af14");
  assert.throws(() => decodeSwapInstruction(JUPITER_V6, data), /platform_fee_bps is 150/);
  const feeFree = Uint8Array.from(data);
  feeFree[26] = 0;
  feeFree[27] = 0;
  const d = decodeSwapInstruction(JUPITER_V6, feeFree);
  assert.deepEqual([d.amountIn, d.minOut], [2_200_000_000n, (85_363_099_743n * 9_100n) / 10_000n]);
});
