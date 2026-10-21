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
import {
  decodeSwapInstruction,
  jupiterMinimumOut,
  JUPITER_SWAP_VARIANTS,
  JUPITER_V6,
  METEORA_DLMM,
  ORCA_WHIRLPOOLS,
  RAYDIUM_AMM_V4,
  RAYDIUM_CLMM,
  RAYDIUM_CPMM,
  SwapRouteRefusal,
} from "./swap-instructions.js";
import { concentratedData, inMinData, jupiterRouteData, raydiumAmmV4Data } from "./swap-fixtures.js";

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

test("Jupiter's Swap enum: the decoder's payload table matches the IDL, variant by variant", () => {
  const jup = idl("idls/jupiter.json");
  const variants = jup.types!.find((t) => t.name === "Swap")!.type.variants!;
  assert.equal(JUPITER_SWAP_VARIANTS.length, variants.length);
  variants.forEach((v, i) => {
    const fields = (v.fields ?? []) as { type: unknown }[];
    const sig = JSON.stringify(fields.map((f) => f.type));
    const expected: Record<string, string> = {
      "[]": "unit",
      '["bool"]': "bool",
      '[{"defined":{"name":"Side"}}]': "side",
      '["u64","u64"]': "u64u64",
      '["u32"]': "u32",
      '["u8","bool","bool"]': "clone",
      '["bool",{"option":{"defined":{"name":"RemainingAccountsInfo"}}}]': "whirlpoolV2",
    };
    assert.equal(JUPITER_SWAP_VARIANTS[i], expected[sig], `variant ${i} ${v.name} ${sig}`);
  });
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
  refused(JUPITER_V6, jupiterRouteData({ rawPlan: [1, 0, 0, 0, 62, 100, 0, 1] }), /Swap variant 62/);
  refused(JUPITER_V6, jupiterRouteData({ rawPlan: [1, 0, 0, 0, 42, 1, 1, 1, 0, 0, 0, 2, 3, 100, 0, 1] }), /AccountsType 2/);
  refused(JUPITER_V6, jupiterRouteData({ rawPlan: [0, 0, 0, 0] }), /no steps/);
  refused(JUPITER_V6, jupiterRouteData({ rawPlan: [255, 255, 255, 255] }), /more than 32/);
  refused(JUPITER_V6, jupiterRouteData({ slippageBps: 10_001 }), /over 100%/);
});

test("a selector the guard does not decode, on a program it does, is refused; so is a mismatched declaration", () => {
  assert.throws(
    () => decodeSwapInstruction(JUPITER_V6, Uint8Array.from([...Buffer.from("bb64facc31c4af14", "hex"), 0])),
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
