/**
 * Swap instruction data, encoded by hand from the committed IDLs, for tests
 * only (Round 29, H2/H4). Each encoder writes exactly the layout
 * `swap-instructions.ts` decodes, so a test can say "a route whose minimum is
 * one base unit" in one line.
 */

function u64(v: bigint): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(v);
  return b;
}

/**
 * Jupiter v6 `route` (e517cb977ae3ad2a; `shared` = `shared_accounts_route`,
 * c1209b3341d69c81, with its leading `id`): one RaydiumClmm step, then
 * in_amount, quoted_out_amount, slippage_bps and platform_fee_bps. Defaults:
 * 1 SOL in, 150 USDC quoted at 0.5% → minimum 149.25 USDC.
 */
export function jupiterRouteData(
  o: {
    amountIn?: bigint;
    quotedOut?: bigint;
    slippageBps?: number;
    platformFeeBps?: number;
    shared?: boolean;
    /** Replace the one RaydiumClmm step with these raw step bytes (count included). */
    rawPlan?: number[];
    trailing?: number[];
  } = {},
): number[] {
  const head = Buffer.from(o.shared ? "c1209b3341d69c81" : "e517cb977ae3ad2a", "hex");
  const plan = Buffer.from(o.rawPlan ?? [1, 0, 0, 0, 26, 100, 0, 1]);
  const tail = Buffer.alloc(3);
  tail.writeUInt16LE(o.slippageBps ?? 50, 0);
  tail.writeUInt8(o.platformFeeBps ?? 0, 2);
  return [
    ...head,
    ...(o.shared ? [0] : []),
    ...plan,
    ...u64(o.amountIn ?? 1_000_000_000n),
    ...u64(o.quotedOut ?? 150_000_000n),
    ...tail,
    ...(o.trailing ?? []),
  ];
}

/**
 * Jupiter v6 `route_v2` / `shared_accounts_route_v2` (Round 41, D-23), the
 * on-chain IDL's layout: [id], in_amount, quoted_out_amount, slippage_bps u16,
 * platform_fee_bps u16, positive_slippage_bps u16, then the route plan (one
 * RaydiumClmm step at 10,000 bps unless `rawPlan` replaces it, count included).
 */
export function jupiterRouteV2Data(
  o: {
    amountIn?: bigint;
    quotedOut?: bigint;
    slippageBps?: number;
    platformFeeBps?: number;
    positiveSlippageBps?: number;
    shared?: boolean;
    rawPlan?: number[];
    trailing?: number[];
  } = {},
): number[] {
  const head = Buffer.from(o.shared ? "d19853937cfed8e9" : "bb64facc31c4af14", "hex");
  const fees = Buffer.alloc(6);
  fees.writeUInt16LE(o.slippageBps ?? 50, 0);
  fees.writeUInt16LE(o.platformFeeBps ?? 0, 2);
  fees.writeUInt16LE(o.positiveSlippageBps ?? 0, 4);
  return [
    ...head,
    ...(o.shared ? [0] : []),
    ...u64(o.amountIn ?? 1_000_000_000n),
    ...u64(o.quotedOut ?? 150_000_000n),
    ...fees,
    ...(o.rawPlan ?? [1, 0, 0, 0, 26, 0x10, 0x27, 0, 1]),
    ...(o.trailing ?? []),
  ];
}

/** `<8-byte selector> amount_in u64 minimum_amount_out u64` (CPMM swap_base_input, DLMM swap). */
export function inMinData(selectorHex: string, amountIn: bigint, minOut: bigint): number[] {
  return [...Buffer.from(selectorHex, "hex"), ...u64(amountIn), ...u64(minOut)];
}

/** Raydium AMM v4 `SwapBaseIn`: tag 9, amount_in, minimum_amount_out (17 bytes). */
export function raydiumAmmV4Data(amountIn: bigint, minOut: bigint, tag = 9): number[] {
  return [tag, ...u64(amountIn), ...u64(minOut)];
}

/**
 * Orca Whirlpools `swap` / `swapV2` and Raydium CLMM `swap` / `swap_v2`:
 * amount, other_amount_threshold, sqrt_price_limit (u128), the exact-in flag,
 * and for Whirlpools `a_to_b` (and for swapV2 an `Option` tag, None).
 */
export function concentratedData(
  selectorHex: string,
  o: { amount: bigint; threshold: bigint; exactIn: boolean; whirlpool: boolean; v2Option?: boolean },
): number[] {
  return [
    ...Buffer.from(selectorHex, "hex"),
    ...u64(o.amount),
    ...u64(o.threshold),
    ...Buffer.alloc(16),
    o.exactIn ? 1 : 0,
    ...(o.whirlpool ? [1] : []),
    ...(o.v2Option ? [0] : []),
  ];
}
