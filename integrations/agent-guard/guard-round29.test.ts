/**
 * Round 29 (audit 2026-10-20): the guard end to end against loopback
 * stand-ins, for what the audit found and for the path no test drove before —
 * an APPROVED, artifact-bound verdict carried through executeTransfer and
 * executeSwap to signing, the trail, submission, confirmation and L8.
 *
 *   coverage  approved transfer and swap, full lifecycle, real digests
 *   H2/H4     the route's own minimum and exact-in flag, decoded and held
 *   L1        a 1-byte selector and an upper-case selector bind after approval
 *   L2        an ambiguous send keeps its signature; a repeat waits for it
 *   L4        the compute budget and output account the guard builds
 *   M3        the RPC never follows a redirect
 *   M6        the aggregate limit over a window
 *   M7        a confirmation hook after the verdict, before signing
 *   M8        the key leaves the environment; the guard cannot be rewired
 *   Info      the AI layer's answer is bounded and only grounded values travel
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { Keypair, PublicKey } from "@solana/web3.js";
import bs58 from "bs58";
import {
  ConfirmationDeclined,
  GraphiteGuard,
  PriorSubmissionUnresolved,
  SpendPolicyRefusal,
  SubmissionOutcomeUnknown,
  SwapRouteRefusal,
  swapPolicyFromEnv,
  type ConfirmationSummary,
  type SpendPolicy,
  type SwapEnvelopeConfig,
  type SwapPolicy,
} from "./guard.js";
import {
  BLOCKED_VERDICT,
  mockApprovingCore,
  mockRpc,
  mockService,
  tokenAccountData,
  wireTransactionId,
  type MockRpc,
  type MockService,
} from "./loopback-mocks.js";
import { concentratedData, jupiterRouteData, raydiumAmmV4Data } from "./swap-fixtures.js";
import { associatedTokenAddress, SPL_TOKEN_PROGRAM } from "./swap-envelope.js";

const DEST = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
const REQUEST = `Transfer 1.5 SOL to ${DEST}`;
const SWAP = "Swap 1 SOL for USDC";
const SYSTEM = "11111111111111111111111111111111";
const SPL_TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const WSOL = "So11111111111111111111111111111111111111112";
const JUPITER_V6 = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
const WHIRLPOOLS = "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc";
const RAYDIUM_AMM_V4 = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8";
const OUT_ACCOUNT = "p2Yicb86aZig616Eav2VWG9vuXR5mEqhtzshZYBxzsV";
const SOL = 1_000_000_000;
const PRICED: SwapPolicy = swapPolicyFromEnv({ GRAPHITE_SWAP_MIN_RATES: "SOL/USDC=100" });

interface H {
  agent: GraphiteGuard;
  wallet: Keypair;
  rpc: MockRpc;
  core: MockService;
  ai: MockService;
  close(): Promise<void>;
}

/**
 * The wallet holds wrapped SOL in `DEST` (spent by the swap) and receives
 * USDC into `out`: what an honest 1 SOL → 150 USDC route does.
 */
function swapState(wallet: Keypair, o: { out?: string; received?: bigint } = {}) {
  const w = wallet.publicKey.toBase58();
  return {
    ledger: {
      [w]: { lamports: 10 * SOL, owner: SYSTEM },
      [DEST]: { lamports: 2_039_280, owner: SPL_TOKEN, data: tokenAccountData(WSOL, w, BigInt(SOL)) },
    },
    afterSimulation: {
      [w]: { lamports: 10 * SOL - 5_000 - 2_039_280, owner: SYSTEM },
      [DEST]: { lamports: 2_039_280, owner: SPL_TOKEN, data: tokenAccountData(WSOL, w, 0n) },
      [o.out ?? OUT_ACCOUNT]: {
        lamports: 2_039_280,
        owner: SPL_TOKEN,
        data: tokenAccountData(USDC, w, o.received ?? 150_000_000n),
      },
    },
    decimals: { [USDC]: 6, [WSOL]: 9 },
  };
}

async function harness(
  o: {
    approve?: boolean;
    spendPolicy?: SpendPolicy;
    swapPolicy?: SwapPolicy;
    swapEnvelope?: SwapEnvelopeConfig;
    rpc?: (w: Keypair) => Parameters<typeof mockRpc>[0];
    parse?: Record<string, unknown>;
    text?: string;
  } = {},
): Promise<H> {
  const wallet = Keypair.generate();
  const rpc = await mockRpc(o.rpc?.(wallet) ?? swapState(wallet));
  const core = o.approve ? await mockApprovingCore() : await mockService({ "GET /health": { status: "ok", service: "graphite", version: "test" } });
  if (!o.approve) core.answer.set("POST /verify", { status: 200, body: BLOCKED_VERDICT });
  const ai = await mockService();
  const text = o.text ?? REQUEST;
  ai.answer.set("POST /parse", {
    status: 200,
    body: o.parse ?? {
      intent_type: "transfer",
      raw_natural_language: text,
      confidence_of_parse: 0.9,
      extracted_parameters: { amount: "1.5", input_token: "SOL", destination: DEST },
    },
  });
  const agent = await GraphiteGuard.create({
    privateKey: bs58.encode(wallet.secretKey),
    rpcUrl: rpc.url,
    graphiteCoreUrl: core.url,
    aiLayerUrl: ai.url,
    spendPolicy: o.spendPolicy ?? { maxTransferLamports: 100n * BigInt(SOL) },
    swapPolicy: o.swapPolicy ?? PRICED,
    swapEnvelope: o.swapEnvelope ?? {},
  });
  return { agent, wallet, rpc, core, ai, close: async () => void (await Promise.all([rpc.close(), core.close(), ai.close()])) };
}

function swapParse(text: string, extra: Record<string, unknown> = {}) {
  return {
    intent_type: "swap",
    raw_natural_language: text,
    confidence_of_parse: 0.99,
    extracted_parameters: { input_token: "SOL", output_token: "USDC", amount: "1", ...extra },
  };
}

function swapPayload(wallet: Keypair, data: number[], o: { programId?: string; discriminator?: string; out?: string } = {}) {
  return {
    programId: o.programId ?? JUPITER_V6,
    discriminator: o.discriminator ?? "e517cb977ae3ad2a",
    accounts: [
      { pubkey: wallet.publicKey.toBase58(), isSigner: true, isWritable: true },
      { pubkey: DEST, isSigner: false, isWritable: true },
      { pubkey: o.out ?? OUT_ACCOUNT, isSigner: false, isWritable: true },
    ],
    instructionData: data,
  };
}

const coreAsked = (h: H) => h.core.calls.filter((c) => c.method === "POST /verify").length;
const events = (h: H) =>
  h.core.calls.filter((c) => c.method === "POST /audit/event").map((c) => c.params as { event_type: string; detail?: string; transaction_signature?: string });

// ---------------------------------------------------------------------------
// Coverage (audit 2026-10-20, M13): the approved path, end to end.

test("coverage: an approved transfer is signed, recorded, sent, confirmed and reconciled — in that order", async () => {
  const h = await harness({ approve: true });
  try {
    const outcome = await h.agent.executeTransfer(REQUEST);
    assert.equal(outcome.executed, true);
    assert.equal(outcome.verifiedExecution, true);
    const send = h.rpc.calls.find((c) => c.method === "sendTransaction")!;
    assert.ok(send, "submitted");
    assert.equal(send.signed, true, "the submitted bytes are signed");
    const wire = (send.params as { params: string[] }).params[0];
    assert.equal(outcome.signature, wireTransactionId(wire), "the id is the signed bytes' own");
    const lc = outcome.lifecycle!;
    assert.equal(lc.signingRecorded, true);
    assert.equal(lc.submissionRecorded, true);
    assert.equal(lc.confirmed, true, lc.confirmationError);
    assert.equal(lc.reconciliation?.reconciliation, "ApprovedAndExecuted");
    // Order: verify < signing event < send < submission event < L8.
    const seq = (m: string, n = 0) => h.core.calls.concat(h.rpc.calls).filter((c) => c.method === m)[n].seq;
    assert.ok(seq("POST /verify") < seq("POST /audit/event", 0));
    assert.ok(seq("POST /audit/event", 0) < seq("sendTransaction"));
    assert.ok(seq("sendTransaction") < seq("POST /audit/event", 1));
    assert.ok(seq("POST /audit/event", 1) < seq("POST /verify/execution"));
    assert.deepEqual(events(h).map((e) => e.event_type), ["signing", "submission"]);
    // Nothing signed reached the RPC before the verdict.
    const verifySeq = seq("POST /verify");
    for (const c of h.rpc.calls) if (c.seq < verifySeq) assert.notEqual(c.signed, true, c.method);
  } finally {
    await h.close();
  }
});

test("coverage: an approved Jupiter swap runs the same lifecycle on the bound bytes", async () => {
  const h = await harness({ approve: true, text: SWAP, parse: swapParse(SWAP) });
  try {
    const outcome = await h.agent.executeSwap(SWAP, swapPayload(h.wallet, jupiterRouteData()));
    assert.equal(outcome.executed, true);
    assert.equal(outcome.lifecycle?.confirmed, true);
    assert.equal(outcome.lifecycle?.reconciliation?.reconciliation, "ApprovedAndExecuted");
    const body = h.core.calls.find((c) => c.method === "POST /verify")!.params as {
      instruction_discriminator: string;
      proposed_intent: { intent_type: string; extracted_parameters: Record<string, unknown> };
    };
    assert.equal(body.instruction_discriminator, "e517cb977ae3ad2a");
    assert.deepEqual(body.proposed_intent.extracted_parameters, { amount: "1", input_token: "SOL", output_token: "USDC" });
  } finally {
    await h.close();
  }
});

// L1 (audit 2026-10-20): AuditBind re-derived an 8-byte selector, so swaps on
// 1-byte-selector programs, and payloads that wrote the selector in capitals,
// always aborted AFTER approval.
test("L1: a Raydium AMM v4 swap (1-byte selector) binds and executes after approval", async () => {
  const h = await harness({ approve: true, text: SWAP, parse: swapParse(SWAP) });
  try {
    const outcome = await h.agent.executeSwap(
      SWAP,
      swapPayload(h.wallet, raydiumAmmV4Data(BigInt(SOL), 149_000_000n), { programId: RAYDIUM_AMM_V4, discriminator: "09" }),
    );
    assert.equal(outcome.executed, true);
    const body = h.core.calls.find((c) => c.method === "POST /verify")!.params as { instruction_discriminator: string };
    assert.equal(body.instruction_discriminator, "09");
  } finally {
    await h.close();
  }
});

test("L1: an upper-case or 0x-prefixed selector is normalised once, for the Core and AuditBind alike", async () => {
  for (const discriminator of ["E517CB977AE3AD2A", "0xe517cb977ae3ad2a"]) {
    const h = await harness({ approve: true, text: SWAP, parse: swapParse(SWAP) });
    try {
      const outcome = await h.agent.executeSwap(SWAP, swapPayload(h.wallet, jupiterRouteData(), { discriminator }));
      assert.equal(outcome.executed, true, discriminator);
      const body = h.core.calls.find((c) => c.method === "POST /verify")!.params as { instruction_discriminator: string };
      assert.equal(body.instruction_discriminator, "e517cb977ae3ad2a");
    } finally {
      await h.close();
    }
  }
});

// ---------------------------------------------------------------------------
// M7: a confirmation after everything that can refuse, before signing.

test("M7: a declined confirmation aborts with nothing signed, recorded or sent; the person saw resolved values", async () => {
  const h = await harness({ approve: true });
  try {
    const seen: ConfirmationSummary[] = [];
    await assert.rejects(
      h.agent.executeTransfer(REQUEST, { confirm: async (s) => (seen.push(s), false) }),
      ConfirmationDeclined,
    );
    assert.equal(seen.length, 1);
    const s = seen[0];
    assert.equal(s.kind, "transfer");
    assert.equal(s.destination, DEST);
    assert.equal(s.lamports, "1500000000");
    assert.equal(s.sol, "1.5");
    assert.equal(s.programId, SYSTEM);
    assert.equal(s.verdict.approved, true);
    assert.match(s.verdict.transactionSha256 ?? "", /^[0-9a-f]{64}$/);
    assert.ok(typeof s.walletEffect.solOutLamports === "string");
    assert.equal(coreAsked(h), 1, "the hook ran after the verdict");
    assert.equal(h.rpc.calls.filter((c) => c.method === "sendTransaction").length, 0, "nothing sent");
    for (const c of h.rpc.calls) assert.notEqual(c.signed, true, `${c.method} carried a signature`);
    assert.deepEqual(events(h), [], "no signing on the trail: nothing was signed");
    // A hook that throws is a decline too.
    await assert.rejects(
      h.agent.executeTransfer(REQUEST, { confirm: async () => { throw new Error("ui closed"); } }),
      /not confirmed \(the confirmation failed: ui closed\)/,
    );
    assert.equal(h.rpc.calls.filter((c) => c.method === "sendTransaction").length, 0);
  } finally {
    await h.close();
  }
});

test("M7: the swap summary carries the route's decoded amounts and floor; accepting executes", async () => {
  const h = await harness({ approve: true, text: SWAP, parse: swapParse(SWAP) });
  try {
    let summary: ConfirmationSummary | undefined;
    const outcome = await h.agent.executeSwap(SWAP, swapPayload(h.wallet, jupiterRouteData()), {
      confirm: async (s) => ((summary = s), true),
    });
    assert.equal(outcome.executed, true);
    assert.deepEqual(summary?.swap, {
      route: "Jupiter v6 route",
      input: { token: "SOL", mint: WSOL, amountIn: "1000000000" },
      output: { token: "USDC", mint: USDC, minimumOut: "149250000", simulatedOut: "150000000" },
      maxSlippageBps: 100,
      priceFloor: "100000000 base units (operator)",
    });
    assert.deepEqual(summary?.walletEffect.tokens, [{ mint: USDC, delta: "150000000" }]);
    assert.equal(summary?.programId, JUPITER_V6);
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// H2 + H4: what the route is held to, before the Core is asked.

async function swapRefused(data: number[], why: RegExp, o: { text?: string; swapPolicy?: SwapPolicy; programId?: string; discriminator?: string } = {}) {
  const text = o.text ?? SWAP;
  const h = await harness({ text, parse: swapParse(text), swapPolicy: o.swapPolicy });
  try {
    await assert.rejects(
      h.agent.executeSwap(text, swapPayload(h.wallet, data, o)),
      (e: unknown) => {
        assert.ok(e instanceof SwapRouteRefusal, String(e));
        assert.match((e as Error).message, why);
        return true;
      },
    );
    assert.equal(coreAsked(h), 0, "refused before the Core was asked");
    for (const c of h.rpc.calls) assert.notEqual(c.signed, true);
  } finally {
    await h.close();
  }
}

async function swapAccepted(data: number[], o: { text?: string; swapPolicy?: SwapPolicy } = {}) {
  const text = o.text ?? SWAP;
  const h = await harness({ text, parse: swapParse(text), swapPolicy: o.swapPolicy });
  try {
    const outcome = await h.agent.executeSwap(text, swapPayload(h.wallet, data));
    assert.equal(outcome.executed, false, "the loopback Core blocked");
    assert.equal(coreAsked(h), 1, `${text}: every guard check passed`);
  } finally {
    await h.close();
  }
}

test("H2: a dust route — a minimum of nothing, or of a couple of base units — is refused", async () => {
  await swapRefused(jupiterRouteData({ quotedOut: 1n }), /accepts an output of zero/);
  await swapRefused(jupiterRouteData({ quotedOut: 2n, slippageBps: 0 }), /more than 100 bps below the 150000000/);
});

test("H4: exact-output instructions are refused by name", async () => {
  const exactOut = [...Buffer.from("d033ef977b2bed5c", "hex"), ...jupiterRouteData().slice(8)];
  await swapRefused(exactOut, /exact_out_route is an exact-OUTPUT instruction/, { discriminator: "d033ef977b2bed5c" });
  await swapRefused(
    concentratedData("f8c69e91e17587c8", { amount: 150_000_000n, threshold: BigInt(SOL), exactIn: false, whirlpool: true }),
    /exact-OUTPUT \(amount_specified_is_input = false\)/,
    { programId: WHIRLPOOLS, discriminator: "f8c69e91e17587c8" },
  );
});

test("H2: a minimum far below what was simulated is refused; a stated slippage can widen it, never past 5%", async () => {
  // 140 USDC minimum against 150 simulated: 6.7% below.
  await swapRefused(jupiterRouteData({ quotedOut: 140_000_000n, slippageBps: 0 }), /more than 100 bps below/);
  await swapRefused(jupiterRouteData({ quotedOut: 140_000_000n, slippageBps: 0 }), /more than 500 bps below/, {
    text: `${SWAP} with 5% slippage`,
  });
  await swapRefused(jupiterRouteData({ quotedOut: 140_000_000n, slippageBps: 0 }), /allows 7% slippage; the guard allows at most 5%/, {
    text: `${SWAP} with 7% slippage`,
  });
  // 145 against 150: 3.3% below, within a stated 4%.
  await swapAccepted(jupiterRouteData({ quotedOut: 145_000_000n, slippageBps: 0 }), { text: `${SWAP} with 4% slippage` });
});

test("H2: the chain must hold the route to at least what the simulation delivered was measured against", async () => {
  // A minimum above what the simulation delivered: the simulation is not what lands.
  await swapRefused(jupiterRouteData({ quotedOut: 160_000_000n, slippageBps: 0 }), /delivered 150000000/);
});

test("H4: the route may spend no more than the request names, read from its data", async () => {
  await swapRefused(jupiterRouteData({ amountIn: 2n * BigInt(SOL) }), /spends 2000000000 base units of SOL; the request spends 1/);
});

test("H2: a route with a platform fee is refused", async () => {
  await swapRefused(jupiterRouteData({ platformFeeBps: 20 }), /platform_fee_bps is 20/);
});

test("H2: a minimum the request states is honoured", async () => {
  await swapRefused(jupiterRouteData(), /asks for at least 149\.5 USDC \(149500000 base units\)/, {
    text: `${SWAP} for at least 149.5 USDC`,
  });
  await swapAccepted(jupiterRouteData(), { text: `${SWAP} for at least 149 USDC`, swapPolicy: swapPolicyFromEnv({}) });
});

test("H2: the operator's rate floor is honoured", async () => {
  await swapRefused(jupiterRouteData(), /floor for SOL\/USDC \(150 per unit/, {
    swapPolicy: swapPolicyFromEnv({ GRAPHITE_SWAP_MIN_RATES: "SOL/USDC=150" }),
  });
  await swapAccepted(jupiterRouteData(), { swapPolicy: swapPolicyFromEnv({ GRAPHITE_SWAP_MIN_RATES: "SOL/USDC=149.25" }) });
});

test("H2: an unpriced swap is refused by default, and built only when the operator accepts that risk by name", async () => {
  await swapRefused(jupiterRouteData(), /nothing prices SOL → USDC/, { swapPolicy: swapPolicyFromEnv({}) });
  await swapAccepted(jupiterRouteData(), { swapPolicy: swapPolicyFromEnv({ GRAPHITE_SWAP_ALLOW_UNPRICED: "1" }) });
});

// ---------------------------------------------------------------------------
// L2: an ambiguous submission.

test("L2: an ambiguous send keeps the signature, puts the attempt on the trail, and a repeat waits for it", async () => {
  const h = await harness({ approve: true, rpc: (w) => ({ ...swapState(w), sendFails: "lost" }) });
  try {
    let signature = "";
    await assert.rejects(h.agent.executeTransfer(REQUEST), (e: unknown) => {
      assert.ok(e instanceof SubmissionOutcomeUnknown, String(e));
      signature = (e as SubmissionOutcomeUnknown).signature;
      assert.equal((e as SubmissionOutcomeUnknown).attemptRecorded, true);
      assert.match((e as Error).message, /Check this signature's status before retrying/);
      return true;
    });
    const sent = h.rpc.calls.find((c) => c.method === "sendTransaction")!;
    assert.equal(signature, wireTransactionId((sent.params as { params: string[] }).params[0]));
    const attempt = events(h).find((e) => e.event_type === "submission")!;
    assert.equal(attempt.transaction_signature, signature);
    assert.match(attempt.detail ?? "", /ATTEMPT, outcome unknown/);
    // The same request again, while the first can still land: refused, nothing built.
    h.rpc.behaviour.sendFails = false;
    await assert.rejects(h.agent.executeTransfer(REQUEST), (e: unknown) => {
      assert.ok(e instanceof PriorSubmissionUnresolved);
      assert.match((e as Error).message, /can still land until block height 1000/);
      return true;
    });
    assert.equal(coreAsked(h), 1, "no second verification");
    // Once its blockhash has expired unlanded, the request may be built again.
    h.rpc.behaviour.blockHeight = 5_000;
    const outcome = await h.agent.executeTransfer(REQUEST);
    assert.equal(outcome.executed, true);
  } finally {
    await h.close();
  }
});

test("L2: if the ambiguous send did land, a repeat is refused once, naming it", async () => {
  const h = await harness({ approve: true, rpc: (w) => ({ ...swapState(w), sendFails: "landed" }) });
  try {
    await assert.rejects(h.agent.executeTransfer(REQUEST), SubmissionOutcomeUnknown);
    h.rpc.behaviour.sendFails = false;
    await assert.rejects(h.agent.executeTransfer(REQUEST), /LANDED/);
    assert.equal(coreAsked(h), 1);
    // Told once; a repeat after that is a deliberate second transfer.
    assert.equal((await h.agent.executeTransfer(REQUEST)).executed, true);
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// M6: the aggregate limit.

test("M6: executed transfers count against the window's aggregate; blocked ones do not", async () => {
  const policy: SpendPolicy = { maxTransferLamports: 2n * BigInt(SOL), maxTotalLamports: 2n * BigInt(SOL) };
  const blocked = await harness({ spendPolicy: policy });
  try {
    for (let i = 0; i < 3; i++) assert.equal((await blocked.agent.executeTransfer(REQUEST)).executed, false);
    assert.equal(coreAsked(blocked), 3, "a refusal releases what it reserved");
  } finally {
    await blocked.close();
  }
  const h = await harness({ approve: true, spendPolicy: policy });
  try {
    assert.equal((await h.agent.executeTransfer(REQUEST)).executed, true);
    await assert.rejects(h.agent.executeTransfer(REQUEST), (e: unknown) => {
      assert.ok(e instanceof SpendPolicyRefusal);
      assert.match((e as Error).message, /above the aggregate limit of 2000000000/);
      return true;
    });
    assert.equal(coreAsked(h), 1, "refused before the Core was asked");
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// L4: the envelope.

test("L4: the compute budget and the wallet's own output account are built by the guard and declared to the Core", async () => {
  const wallet = Keypair.generate();
  const ata = associatedTokenAddress(wallet.publicKey, new PublicKey(USDC), new PublicKey(SPL_TOKEN_PROGRAM)).toBase58();
  const rpc = await mockRpc(swapState(wallet, { out: ata }));
  const core = await mockService({ "GET /health": { status: "ok", service: "graphite", version: "test" } });
  core.answer.set("POST /verify", { status: 200, body: BLOCKED_VERDICT });
  const ai = await mockService();
  ai.answer.set("POST /parse", { status: 200, body: swapParse(SWAP) });
  try {
    const agent = await GraphiteGuard.create({
      privateKey: bs58.encode(wallet.secretKey),
      rpcUrl: rpc.url,
      graphiteCoreUrl: core.url,
      aiLayerUrl: ai.url,
      spendPolicy: { maxTransferLamports: 100n * BigInt(SOL) },
      swapPolicy: PRICED,
      swapEnvelope: { computeUnitLimit: 300_000, computeUnitPriceMicroLamports: 1_000n, createOutputAta: true },
    });
    await agent.executeSwap(SWAP, swapPayload(wallet, jupiterRouteData(), { out: ata }));
    const body = core.calls.find((c) => c.method === "POST /verify")!.params as {
      program_id: string;
      transaction_instructions: { program_id: string; instruction_discriminator: string; account_addresses: string[] }[];
    };
    assert.equal(body.program_id, JUPITER_V6);
    assert.deepEqual(
      body.transaction_instructions.map((i) => [i.program_id, i.instruction_discriminator.slice(0, 2)]),
      [
        ["ComputeBudget111111111111111111111111111111", "02"],
        ["ComputeBudget111111111111111111111111111111", "03"],
        ["ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", "01"],
      ],
      "the envelope, declared as siblings; the route is the primary",
    );
    assert.equal(body.transaction_instructions[2].account_addresses[1], ata, "the wallet's own account, nobody else's");
  } finally {
    await Promise.all([rpc.close(), core.close(), ai.close()]);
  }
  // A budget that allows more than 0.005 SOL of priority fee refuses to start.
  await assert.rejects(
    GraphiteGuard.create({
      privateKey: bs58.encode(wallet.secretKey),
      rpcUrl: "http://127.0.0.1:1",
      graphiteCoreUrl: "http://127.0.0.1:1",
      spendPolicy: { maxTransferLamports: 1n },
      swapEnvelope: { computeUnitLimit: 1_400_000, computeUnitPriceMicroLamports: 10_000_000n },
    }),
    /priority fee of up to 14000000 lamports/,
  );
});

// ---------------------------------------------------------------------------
// M8, M3, Info.

test("M8: SOLANA_PRIVATE_KEY is gone from the environment once read, and the guard cannot be rewired", async () => {
  const wallet = Keypair.generate();
  const core = await mockService({ "GET /health": { status: "ok", service: "graphite", version: "test" } });
  const saved = process.env.SOLANA_PRIVATE_KEY;
  try {
    process.env.SOLANA_PRIVATE_KEY = bs58.encode(wallet.secretKey);
    const agent = await GraphiteGuard.create({
      rpcUrl: "http://127.0.0.1:1",
      graphiteCoreUrl: core.url,
      spendPolicy: { maxTransferLamports: 1n },
    });
    assert.equal(agent.publicKey, wallet.publicKey.toBase58(), "the key was read");
    assert.equal(process.env.SOLANA_PRIVATE_KEY, undefined, "and is no longer in the environment");
    assert.equal(Object.isFrozen(agent), true);
    assert.equal(Object.isFrozen(GraphiteGuard.prototype), true);
    assert.throws(() => {
      (agent as unknown as Record<string, unknown>).executeTransfer = async () => ({ executed: true });
    }, TypeError);
    assert.throws(() => {
      (GraphiteGuard.prototype as unknown as Record<string, unknown>).executeSwap = () => undefined;
    }, TypeError);
    assert.deepEqual(Object.keys(agent.getGraphiteClient()).sort(), ["health", "listManifests"]);
  } finally {
    if (saved === undefined) delete process.env.SOLANA_PRIVATE_KEY;
    else process.env.SOLANA_PRIVATE_KEY = saved;
    await core.close();
  }
});

test("M3: the RPC is held to the transport rule and never followed through a redirect", async () => {
  await assert.rejects(
    GraphiteGuard.create({
      privateKey: bs58.encode(Keypair.generate().secretKey),
      rpcUrl: "http://rpc.example.com/?api-key=SECRET",
      graphiteCoreUrl: "http://127.0.0.1:1",
      spendPolicy: { maxTransferLamports: 1n },
    }),
    (e: unknown) => /SOLANA_RPC_URL is refused/.test(String(e)) && !String(e).includes("SECRET"),
  );
  // An RPC that answers every request with 307 to somewhere else.
  let targetHits = 0;
  const target = createServer((_q, r) => (targetHits++, r.end("{}")));
  await new Promise<void>((r) => target.listen(0, "127.0.0.1", r));
  const redirector = createServer((_q, r) => {
    r.writeHead(307, { location: `http://127.0.0.1:${(target.address() as AddressInfo).port}/` });
    r.end();
  });
  await new Promise<void>((r) => redirector.listen(0, "127.0.0.1", r));
  const core = await mockService({ "GET /health": { status: "ok", service: "graphite", version: "test" } });
  const ai = await mockService();
  ai.answer.set("POST /parse", {
    status: 200,
    body: { intent_type: "transfer", raw_natural_language: REQUEST, confidence_of_parse: 0.9, extracted_parameters: { amount: "1.5", input_token: "SOL", destination: DEST } },
  });
  try {
    const agent = await GraphiteGuard.create({
      privateKey: bs58.encode(Keypair.generate().secretKey),
      rpcUrl: `http://127.0.0.1:${(redirector.address() as AddressInfo).port}`,
      graphiteCoreUrl: core.url,
      aiLayerUrl: ai.url,
      spendPolicy: { maxTransferLamports: 100n * BigInt(SOL) },
    });
    await assert.rejects(agent.executeTransfer(REQUEST));
    assert.equal(targetHits, 0, "the redirect target was never contacted");
    assert.equal(core.calls.filter((c) => c.method === "POST /verify").length, 0);
  } finally {
    for (const s of [target, redirector]) {
      s.closeAllConnections();
      await new Promise<void>((r) => s.close(() => r()));
    }
    await Promise.all([core.close(), ai.close()]);
  }
});

test("Info: the AI layer's answer is bounded, and only grounded values reach the Core", async () => {
  const h = await harness({
    parse: {
      intent_type: "transfer",
      raw_natural_language: REQUEST,
      confidence_of_parse: 7,
      extracted_parameters: {
        amount: "1.5",
        input_token: "SOL",
        destination: DEST,
        output_token: "BONK",
        slippage_bps: 9_999,
        note: "x".repeat(100),
      },
    },
  });
  try {
    await h.agent.executeTransfer(REQUEST);
    const body = h.core.calls.find((c) => c.method === "POST /verify")!.params as {
      proposed_intent: { intent_type: string; confidence_of_parse: number; extracted_parameters: unknown };
    };
    assert.equal(body.proposed_intent.intent_type, "transfer");
    assert.equal(body.proposed_intent.confidence_of_parse, 0, "an out-of-range confidence is not forwarded");
    assert.deepEqual(body.proposed_intent.extracted_parameters, { amount: "1.5", destination: DEST, input_token: "SOL" });
    // An answer over 64 KiB is refused before it is parsed.
    h.ai.answer.set("POST /parse", { status: 200, body: { pad: "x".repeat(70 * 1024) } });
    await assert.rejects(h.agent.executeTransfer(REQUEST), /the AI layer's answer (declares|exceeds)/);
  } finally {
    await h.close();
  }
});
