/**
 * The guard end to end, against loopback stand-ins for the RPC, the Graphite
 * Core and the AI layer (loopback-mocks.ts). A throwaway keypair generated per
 * test; no public RPC, no funds. These were the SAK bridge's tests until the
 * guard moved out of it (R-P8 phase 3); every framework adapter inherits them.
 *
 *   F-19-C1  nothing signed reaches the RPC before (or without) a verdict
 *   F-19-C5  destination and amount come from the user's text, not the AI's
 *   F-19-C6  a legacy env var name refuses to start instead of defaulting
 *   A5-01    a swap's class is the method's, grounded in the user's text; the
 *            AI layer's URL obeys the Core's transport rule and is bounded
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { Keypair } from "@solana/web3.js";
import bs58 from "bs58";
import {
  GraphiteGuard,
  IntentGroundingError,
  parseTransactionVersion,
  SpendPolicyRefusal,
  swapPolicyFromEnv,
  type SpendPolicy,
  type SwapPolicy,
} from "./guard.js";
import {
  BLOCKED_VERDICT,
  mockRpc,
  mockService,
  tokenAccountData,
  type Loopback,
  type MockService,
} from "./loopback-mocks.js";
import { jupiterRouteData } from "./swap-fixtures.js";

const DEST = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
const ATTACKER = "6bSsP4p6wXqFJdD2TkYgNcVmLzHfWq7pRyA8tCzE5nBj";
const REQUEST = `Transfer 1.5 SOL to ${DEST}`;
/** A Core API key that must not be reachable through the guard (Round 29, M8). */
const CORE_API_KEY = `loopback-core-key-${Math.random().toString(36).slice(2)}`;
/** Floors below what the loopback routes pay: SOL/USDC 100, USDC/SOL 0.003. */
const DEFAULT_TEST_SWAP_POLICY = swapPolicyFromEnv({ GRAPHITE_SWAP_MIN_RATES: "SOL/USDC=100,USDC/SOL=0.003" });

/** What the real AI layer answers for REQUEST (intent_parser.py). */
function honestParse(text = REQUEST) {
  return {
    intent_type: "transfer",
    raw_natural_language: text,
    confidence_of_parse: 0.9,
    extracted_parameters: { amount: "1.5", input_token: "SOL", destination: DEST },
  };
}

interface Harness {
  agent: GraphiteGuard;
  wallet: Keypair;
  rpc: Loopback;
  core: MockService;
  ai: MockService;
  close(): Promise<void>;
}

async function harness(
  opts: {
    aiLayerTimeoutMs?: number;
    transactionVersion?: "legacy" | 1;
    spendPolicy?: SpendPolicy;
    swapPolicy?: SwapPolicy;
    rpc?: (wallet: Keypair) => Parameters<typeof mockRpc>[0];
  } = {},
): Promise<Harness> {
  const wallet = Keypair.generate();
  const rpc = await mockRpc(opts.rpc?.(wallet));
  const core = await mockService({ "GET /health": { status: "ok", service: "graphite", version: "test" } });
  core.answer.set("POST /verify", { status: 200, body: BLOCKED_VERDICT });
  const ai = await mockService();
  ai.answer.set("POST /parse", { status: 200, body: honestParse() });
  const agent = await GraphiteGuard.create({
    privateKey: bs58.encode(wallet.secretKey),
    rpcUrl: rpc.url,
    graphiteCoreUrl: core.url,
    aiLayerUrl: ai.url,
    aiLayerTimeoutMs: opts.aiLayerTimeoutMs,
    transactionVersion: opts.transactionVersion,
    // Round 29 (M6): a cap is required; these tests are about other things,
    // so the default cap is far above anything they move.
    spendPolicy: opts.spendPolicy ?? { maxTransferLamports: 1_000_000_000_000n },
    // Round 29 (H2): a price floor for the pairs these tests swap.
    swapPolicy: opts.swapPolicy ?? DEFAULT_TEST_SWAP_POLICY,
    graphiteApiKey: CORE_API_KEY,
  });
  return {
    agent,
    wallet,
    rpc,
    core,
    ai,
    close: async () => {
      await Promise.all([rpc.close(), core.close(), ai.close()]);
    },
  };
}

test("F-19-C1: executeTransfer puts no signed transaction on the wire before the verdict, and none after a block", async () => {
  const h = await harness();
  try {
    const outcome = await h.agent.executeTransfer(REQUEST);
    assert.equal(outcome.executed, false, "the loopback Core blocked; nothing may execute");

    const verify = h.core.calls.find((c) => c.method === "POST /verify");
    assert.ok(verify, "the bridge must have asked the Core");
    const sims = h.rpc.calls.filter((c) => c.method === "simulateTransaction");
    assert.equal(sims.length, 1, "the pre-verdict simulation must still run");
    assert.ok(sims[0].seq < verify!.seq, "the simulation is the pre-verdict step");
    for (const call of h.rpc.calls) {
      assert.notEqual(
        call.signed,
        true,
        `${call.method} carried a signed transaction — the RPC held a broadcastable transfer ` +
          "Graphite had not approved",
      );
    }
    assert.equal(h.rpc.calls.filter((c) => c.method === "sendTransaction").length, 0);
    // The artifact Graphite was shown is unsigned too.
    const body = verify!.params as { signed_transaction?: number[] };
    assert.ok(Array.isArray(body.signed_transaction));
    assert.ok(body.signed_transaction!.slice(1, 65).every((b) => b === 0));
  } finally {
    await h.close();
  }
});

test("F-19-C5: an AI-layer destination the user never wrote is refused before anything is built or sent", async () => {
  const h = await harness();
  try {
    h.ai.answer.set("POST /parse", {
      status: 200,
      body: { ...honestParse(), extracted_parameters: { amount: "1.5", input_token: "SOL", destination: ATTACKER } },
    });
    await assert.rejects(h.agent.executeTransfer(REQUEST), IntentGroundingError);
    assert.equal(h.core.calls.filter((c) => c.method === "POST /verify").length, 0, "the Core was never asked");
    assert.equal(h.rpc.calls.length, 0, "nothing reached the RPC");
  } finally {
    await h.close();
  }
});

test("F-19-C5: an AI-layer amount the user never wrote is refused", async () => {
  const h = await harness();
  try {
    h.ai.answer.set("POST /parse", {
      status: 200,
      body: { ...honestParse(), extracted_parameters: { amount: "150", input_token: "SOL", destination: DEST } },
    });
    await assert.rejects(h.agent.executeTransfer(REQUEST), IntentGroundingError);
    assert.equal(h.core.calls.filter((c) => c.method === "POST /verify").length, 0);
  } finally {
    await h.close();
  }
});

test("F-19-C5: an AI-layer answer to a different request is refused", async () => {
  const h = await harness();
  try {
    const other = `Transfer 1.5 SOL to ${ATTACKER}`;
    h.ai.answer.set("POST /parse", { status: 200, body: honestParse(other) });
    await assert.rejects(h.agent.executeTransfer(REQUEST), /raw_natural_language is not the text that was sent/);
    assert.equal(h.core.calls.filter((c) => c.method === "POST /verify").length, 0);
  } finally {
    await h.close();
  }
});

test("F-19-C5: the Core is shown the user's text and a transaction built from it", async () => {
  const h = await harness();
  try {
    await h.agent.executeTransfer(REQUEST);
    const verify = h.core.calls.find((c) => c.method === "POST /verify");
    const body = verify!.params as {
      proposed_intent: { raw_natural_language: string; extracted_parameters: Record<string, unknown> };
      account_addresses: string[];
      instruction_data: number[];
    };
    assert.equal(body.proposed_intent.raw_natural_language, REQUEST);
    assert.equal(body.proposed_intent.extracted_parameters.destination, DEST);
    assert.equal(body.proposed_intent.extracted_parameters.amount, "1.5");
    assert.deepEqual(body.account_addresses, [h.wallet.publicKey.toBase58(), DEST]);
    // System transfer: u32 LE 2, then u64 LE 1_500_000_000 lamports.
    const data = Buffer.from(body.instruction_data);
    assert.equal(data.readUInt32LE(0), 2);
    assert.equal(data.readBigUInt64LE(4), 1_500_000_000n);
  } finally {
    await h.close();
  }
});

test("F-19-C6: a legacy env var name without its replacement refuses to start", async () => {
  const saved = { ...process.env };
  try {
    delete process.env.GRAPHITE_CORE_URL;
    process.env.GRAPHITE_SERVER_URL = "http://127.0.0.1:1";
    await assert.rejects(
      GraphiteGuard.create({ privateKey: bs58.encode(Keypair.generate().secretKey), rpcUrl: "http://127.0.0.1:1" }),
      /GRAPHITE_SERVER_URL is set but the bridge reads GRAPHITE_CORE_URL/,
    );
    delete process.env.GRAPHITE_SERVER_URL;
    delete process.env.GRAPHITE_AI_LAYER_URL;
    process.env.AI_LAYER_URL = "http://127.0.0.1:1";
    await assert.rejects(
      GraphiteGuard.create({ privateKey: bs58.encode(Keypair.generate().secretKey), rpcUrl: "http://127.0.0.1:1" }),
      /AI_LAYER_URL is set but the bridge reads GRAPHITE_AI_LAYER_URL/,
    );
  } finally {
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
    Object.assign(process.env, saved);
  }
});

// ---------------------------------------------------------------------------
// A5-01 (2026-09-29 audit): executeSwap forwarded the AI layer's intent_type
// to the Core unchanged and accepted a payload for any program. The Core's
// intent-mismatch checks are keyed on that label, so an AI answering
// "approve" to "Swap 1 SOL for USDC" switched off the Approve check for an
// SPL Token Approve of u64::MAX to an attacker delegate.

const SWAP_REQUEST = "Swap 1 SOL for USDC";
const JUPITER_V6 = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
const SPL_TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

function swapParse(intent_type: string, text = SWAP_REQUEST) {
  return {
    intent_type,
    raw_natural_language: text,
    confidence_of_parse: 0.99,
    extracted_parameters: { input_token: "SOL", output_token: "USDC", amount: "1" },
  };
}

/** The attacker's "route": SPL Token Approve (0x04) of u64::MAX to ATTACKER. */
function approvePayload(wallet: Keypair) {
  return {
    programId: SPL_TOKEN,
    discriminator: "04",
    accounts: [
      { pubkey: DEST, isSigner: false, isWritable: true },
      { pubkey: ATTACKER, isSigner: false, isWritable: false },
      { pubkey: wallet.publicKey.toBase58(), isSigner: true, isWritable: false },
    ],
    instructionData: [4, 255, 255, 255, 255, 255, 255, 255, 255],
  };
}

/** The wallet's account for what a swap delivers (a fixed, valid address). */
const OUT_ACCOUNT = "p2Yicb86aZig616Eav2VWG9vuXR5mEqhtzshZYBxzsV";

/** A Jupiter V6 route payload the guard can read; the rest is the Core's to judge. */
function jupiterPayload(wallet: Keypair, route: Parameters<typeof jupiterRouteData>[0] = {}) {
  return {
    programId: JUPITER_V6,
    discriminator: "e517cb977ae3ad2a",
    accounts: [
      { pubkey: wallet.publicKey.toBase58(), isSigner: true, isWritable: true },
      { pubkey: DEST, isSigner: false, isWritable: true },
      { pubkey: OUT_ACCOUNT, isSigner: false, isWritable: true },
    ],
    instructionData: jupiterRouteData(route),
  };
}

test("A5-01: executeSwap refuses an AI label outside the swap class before the Core is asked", async () => {
  const h = await harness();
  try {
    h.ai.answer.set("POST /parse", { status: 200, body: swapParse("approve") });
    await assert.rejects(h.agent.executeSwap(SWAP_REQUEST, approvePayload(h.wallet)), IntentGroundingError);
    // Even addressed to a swap program, the label is not the AI's to choose.
    await assert.rejects(
      h.agent.executeSwap(SWAP_REQUEST, jupiterPayload(h.wallet)),
      /labelled a swap request as "approve"/,
    );
    assert.equal(h.core.calls.filter((c) => c.method === "POST /verify").length, 0, "the Core was never asked");
    assert.equal(h.rpc.calls.length, 0, "nothing reached the RPC");
  } finally {
    await h.close();
  }
});

test("A5-01: executeSwap refuses a payload for a program that does not swap, honest label or not", async () => {
  const h = await harness();
  try {
    h.ai.answer.set("POST /parse", { status: 200, body: swapParse("swap") });
    await assert.rejects(
      h.agent.executeSwap(SWAP_REQUEST, approvePayload(h.wallet)),
      /not one of the swap programs whose instruction data the guard decodes/,
    );
    assert.equal(h.core.calls.filter((c) => c.method === "POST /verify").length, 0);
    assert.equal(h.rpc.calls.length, 0);
  } finally {
    await h.close();
  }
});

test("A5-01: executeSwap refuses a request whose text does not ask for a swap", async () => {
  const h = await harness();
  try {
    const text = "Send 1 SOL for USDC";
    h.ai.answer.set("POST /parse", { status: 200, body: swapParse("swap", text) });
    await assert.rejects(h.agent.executeSwap(text, jupiterPayload(h.wallet)), /does not ask for a swap/);
    assert.equal(h.core.calls.filter((c) => c.method === "POST /verify").length, 0);
  } finally {
    await h.close();
  }
});

test("A5-01: the Core is told swap, not the AI layer's wording of it", async () => {
  const h = await harness({ rpc: swapLedger(10 * SOL - SOL - 5_000) });
  try {
    h.ai.answer.set("POST /parse", { status: 200, body: swapParse("exchange") });
    const outcome = await h.agent.executeSwap(SWAP_REQUEST, jupiterPayload(h.wallet));
    assert.equal(outcome.executed, false, "the loopback Core blocked");
    const verify = h.core.calls.find((c) => c.method === "POST /verify");
    const body = verify!.params as {
      proposed_intent: { intent_type: string; raw_natural_language: string };
      program_id: string;
    };
    assert.equal(body.proposed_intent.intent_type, "swap");
    assert.equal(body.proposed_intent.raw_natural_language, SWAP_REQUEST);
    assert.equal(body.program_id, JUPITER_V6);
  } finally {
    await h.close();
  }
});

test("A5-01: a hung AI layer times out instead of hanging the call", async () => {
  const hung = createServer(() => {
    /* never answers */
  });
  await new Promise<void>((resolve) => hung.listen(0, "127.0.0.1", resolve));
  const rpc = await mockRpc();
  const core = await mockService({ "GET /health": { status: "ok", service: "graphite", version: "test" } });
  try {
    const agent = await GraphiteGuard.create({
      privateKey: bs58.encode(Keypair.generate().secretKey),
      rpcUrl: rpc.url,
      graphiteCoreUrl: core.url,
      aiLayerUrl: `http://127.0.0.1:${(hung.address() as AddressInfo).port}`,
      aiLayerTimeoutMs: 200,
      spendPolicy: { maxTransferLamports: 1n },
    });
    const started = Date.now();
    await assert.rejects(agent.executeTransfer(REQUEST), /the AI layer did not answer within 200 ms/);
    assert.ok(Date.now() - started < 5_000, "the call was bounded by the configured timeout");
    assert.equal(core.calls.filter((c) => c.method === "POST /verify").length, 0);
  } finally {
    hung.closeAllConnections();
    await new Promise<void>((resolve) => hung.close(() => resolve()));
    await Promise.all([rpc.close(), core.close()]);
  }
});

test("A5-01: the AI layer URL follows the Core's transport rule: https://, or http:// to loopback", async () => {
  const create = (aiLayerUrl: string) =>
    GraphiteGuard.create({
      privateKey: bs58.encode(Keypair.generate().secretKey),
      rpcUrl: "http://127.0.0.1:1",
      graphiteCoreUrl: "http://127.0.0.1:1",
      aiLayerUrl,
    });
  for (const url of ["http://ai.internal:8081", "http://10.0.0.5:8081", "ftp://127.0.0.1:8081", "not a url"]) {
    await assert.rejects(create(url), /GRAPHITE_AI_LAYER_URL is refused/, url);
  }
});

test("R8: the wallet's secret key is not reachable through the guard object at runtime", async () => {
  // TypeScript `private` is a compile-time label: at runtime it is an
  // ordinary property any code holding the object can read. Every framework
  // adapter hands this object to code it does not control (an LLM tool, an
  // MCP request handler); this walks everything reachable from it for the
  // secret key.
  const h = await harness();
  try {
    const secret = Buffer.from(h.wallet.secretKey).toString("hex");
    const seen = new Set<unknown>();
    const found: string[] = [];
    const walk = (value: unknown, path: string, depth: number): void => {
      // Round 29 (M8): the Core's API key is as much a secret as the wallet's.
      if (typeof value === "string" && value.includes(CORE_API_KEY)) found.push(`${path} holds the Core API key`);
      if (value === null || typeof value !== "object" || seen.has(value) || depth > 6) return;
      seen.add(value);
      if (value instanceof Keypair) found.push(`${path} is a Keypair`);
      if (value instanceof Uint8Array && Buffer.from(value).toString("hex").includes(secret)) {
        found.push(`${path} holds the secret key bytes`);
      }
      for (const key of Reflect.ownKeys(value)) {
        let child: unknown;
        try {
          child = (value as Record<PropertyKey, unknown>)[key];
        } catch {
          continue;
        }
        walk(child, `${path}.${String(key)}`, depth + 1);
      }
      // Accessors live on the prototype, not the instance: a getter that
      // returns the key is as reachable as a field holding it. Every getter
      // on the chain up to Object.prototype is called on this object.
      for (let proto = Object.getPrototypeOf(value); proto && proto !== Object.prototype; proto = Object.getPrototypeOf(proto)) {
        for (const key of Reflect.ownKeys(proto)) {
          const desc = Object.getOwnPropertyDescriptor(proto, key);
          if (!desc?.get) continue;
          let child: unknown;
          try {
            child = desc.get.call(value);
          } catch {
            continue;
          }
          walk(child, `${path}.${String(key)} (getter)`, depth + 1);
        }
      }
    };
    walk(h.agent, "agent", 0);
    // What the guard hands out by method, too (Round 29, M8: this returned
    // the GraphiteClient, and `getGraphiteClient()["apiKey"]` was the key).
    walk(h.agent.getGraphiteClient(), "agent.getGraphiteClient()", 0);
    walk(h.agent.getConnection(), "agent.getConnection()", 0);
    assert.ok(seen.size > 1, "the walk reached past the guard object itself");
    assert.deepEqual(found, [], `the secret key is reachable: ${found.join("; ")}`);
  } finally {
    await h.close();
  }
});

test("R-P8 phase 2: with transactionVersion 1 the Core is shown an unsigned v1 transfer, budget measured first", async () => {
  const h = await harness({ transactionVersion: 1 });
  try {
    const outcome = await h.agent.executeTransfer(REQUEST);
    assert.equal(outcome.executed, false, "the loopback Core blocked; nothing may execute");
    const sims = h.rpc.calls.filter((c) => c.method === "simulateTransaction");
    // The advisory pre-verdict simulation and the v1 sizing simulation.
    assert.equal(sims.length, 2);
    for (const call of h.rpc.calls) assert.notEqual(call.signed, true, `${call.method} carried a signature`);
    assert.equal(h.rpc.calls.filter((c) => c.method === "sendTransaction").length, 0);
    const verify = h.core.calls.find((c) => c.method === "POST /verify")!;
    const body = verify.params as { signed_transaction: number[]; uses_versioned_transaction: boolean; lookup_table_count: number };
    const wire = Buffer.from(body.signed_transaction);
    assert.equal(wire[0], 0x81, "a v1 frame");
    assert.equal(body.uses_versioned_transaction, true, "the declaration describes v1 bytes as versioned");
    assert.equal(body.lookup_table_count, 0);
    // The loopback RPC measured 150 CU and 2,048 bytes: the message carries
    // 180 CU (20% headroom) and one 32 KiB page, in mask order.
    assert.equal(wire.readUInt32LE(4), 0b1100, "compute and loaded-data limits, nothing else");
    assert.ok(wire.subarray(wire.length - 64).every((b) => b === 0), "the trailing slot is empty");
    const keys = 3 * 32;
    const valuesAt = 1 + 3 + 4 + 32 + 2 + keys;
    assert.equal(wire.readUInt32LE(valuesAt), 180);
    assert.equal(wire.readUInt32LE(valuesAt + 4), 32 * 1024);
    // The sizing simulation ran before the Core was asked: the limits are
    // part of the verified bytes.
    assert.ok(sims.every((s) => s.seq < verify.seq));
  } finally {
    await h.close();
  }
});

test("GRAPHITE_TRANSACTION_VERSION: legacy and 1 are read, anything else refuses to start", () => {
  assert.equal(parseTransactionVersion(undefined), "legacy");
  assert.equal(parseTransactionVersion(""), "legacy");
  assert.equal(parseTransactionVersion("legacy"), "legacy");
  assert.equal(parseTransactionVersion("1"), 1);
  for (const bad of ["v1", "0", "2", " 1", "LEGACY"]) {
    assert.throws(() => parseTransactionVersion(bad), /REFUSING TO START/, bad);
  }
});

test("spend policy: a transfer over the cap is refused before the RPC or the Core is contacted", async () => {
  // REQUEST moves 1.5 SOL.
  const h = await harness({ spendPolicy: { maxTransferLamports: 1_499_999_999n } });
  try {
    await assert.rejects(h.agent.executeTransfer(REQUEST), SpendPolicyRefusal);
    assert.equal(h.core.calls.filter((c) => c.method === "POST /verify").length, 0, "the Core was never asked");
    assert.equal(h.rpc.calls.length, 0, "nothing reached the RPC");
  } finally {
    await h.close();
  }
});

test("spend policy: a destination outside the allowlist is refused; inside it, the transfer is verified", async () => {
  const outside = await harness({ spendPolicy: { maxTransferLamports: 10n * BigInt(1e9), allowedDestinations: [ATTACKER] } });
  try {
    await assert.rejects(outside.agent.executeTransfer(REQUEST), /not in the allowed destinations/);
    assert.equal(outside.rpc.calls.length, 0);
  } finally {
    await outside.close();
  }
  const inside = await harness({ spendPolicy: { maxTransferLamports: 1_500_000_000n, allowedDestinations: [DEST] } });
  try {
    const outcome = await inside.agent.executeTransfer(REQUEST);
    assert.equal(outcome.executed, false, "the loopback Core blocked; the policy only narrows");
    assert.equal(inside.core.calls.filter((c) => c.method === "POST /verify").length, 1, "within limits, the Core is asked");
    assert.deepEqual(inside.agent.limits, { maxTransferLamports: 1_500_000_000n, allowedDestinations: [DEST] });
  } finally {
    await inside.close();
  }
});

// W22 (external review, verified 2026-10-03): the spend policy bounded only
// executeTransfer, while both framework adapters expose a swap tool. A swap's
// outflow is whatever the bound transaction does, so it is measured there: the
// exact unsigned bytes are simulated and the wallet's own balances read before
// and after.

const SYSTEM = "11111111111111111111111111111111";
const USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const USDT = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";
const BONK = "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263";
const JUP = "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN";
const WSOL = "So11111111111111111111111111111111111111112";
const SOL = 1_000_000_000;

/**
 * A swap as the RPC would simulate it: the wallet's lamports before (10 SOL by
 * default) and after, a token account it spends from (`DEST`), and the account
 * it receives into (`OUT_ACCOUNT`, created by the route; 150 USDC by default).
 */
function swapLedger(
  walletAfter: number,
  token?: { mint: string; before: bigint; after: bigint },
  received: { mint: string; amount: bigint } | null = { mint: USDC, amount: 150_000_000n },
  walletBefore: number = 10 * SOL,
) {
  return (wallet: Keypair) => {
    const w = wallet.publicKey.toBase58();
    return {
      ledger: {
        [w]: { lamports: walletBefore, owner: SYSTEM },
        ...(token
          ? { [DEST]: { lamports: 2_039_280, owner: SPL_TOKEN, data: tokenAccountData(token.mint, w, token.before) } }
          : {}),
      },
      afterSimulation: {
        [w]: { lamports: walletAfter, owner: SYSTEM },
        ...(token
          ? { [DEST]: { lamports: 2_039_280, owner: SPL_TOKEN, data: tokenAccountData(token.mint, w, token.after) } }
          : {}),
        ...(received
          ? { [OUT_ACCOUNT]: { lamports: 2_039_280, owner: SPL_TOKEN, data: tokenAccountData(received.mint, w, received.amount) } }
          : {}),
      },
      decimals: { [USDC]: 6, [USDT]: 6, [BONK]: 5, [WSOL]: 9 },
    };
  };
}

async function swapUnder(policy: SpendPolicy, rpc: ReturnType<typeof swapLedger>) {
  const h = await harness({ spendPolicy: policy, rpc });
  h.ai.answer.set("POST /parse", { status: 200, body: swapParse("swap") });
  return h;
}

test("spend policy: a swap within the cap, measured on the transaction, goes to the Core", async () => {
  // Spends 1 SOL less one lamport, fee included, against a cap of 1 SOL.
  const h = await swapUnder({ maxTransferLamports: BigInt(SOL) }, swapLedger(10 * SOL - SOL + 1));
  try {
    const outcome = await h.agent.executeSwap(SWAP_REQUEST, jupiterPayload(h.wallet));
    assert.equal(outcome.executed, false, "the loopback Core blocked; the policy only narrows");
    assert.equal(h.core.calls.filter((c) => c.method === "POST /verify").length, 1);
    const sims = h.rpc.calls.filter((c) => c.method === "simulateTransaction");
    assert.ok(sims.length >= 1, "the effect was measured by a simulation");
    assert.ok(sims.every((c) => (c as { signed?: boolean }).signed === false), "never signed");
    assert.equal(
      h.rpc.calls.filter((c) => c.method === "getMultipleAccounts").length,
      0,
      "the balances are the simulation's own, not a separate read",
    );
  } finally {
    await h.close();
  }
});

test("spend policy: a swap taking more lamports than the cap is refused before the Core is asked", async () => {
  // Spends 1 SOL + a 5,000-lamport fee, against a cap of exactly 1 SOL.
  const h = await swapUnder({ maxTransferLamports: BigInt(SOL) }, swapLedger(10 * SOL - SOL - 5_000));
  try {
    await assert.rejects(h.agent.executeSwap(SWAP_REQUEST, jupiterPayload(h.wallet)), (e: unknown) => {
      assert.ok(e instanceof SpendPolicyRefusal);
      assert.match((e as Error).message, /1000005000 lamports out of the wallet/);
      return true;
    });
    assert.equal(h.core.calls.filter((c) => c.method === "POST /verify").length, 0, "the Core was never asked");
  } finally {
    await h.close();
  }
});

test("spend policy: wrapped SOL leaving the wallet counts against the lamport cap", async () => {
  const h = await swapUnder(
    { maxTransferLamports: BigInt(SOL) },
    swapLedger(10 * SOL - 5_000, { mint: WSOL, before: BigInt(2 * SOL), after: 0n }),
  );
  try {
    await assert.rejects(h.agent.executeSwap(SWAP_REQUEST, jupiterPayload(h.wallet)), /2000005000 lamports/);
  } finally {
    await h.close();
  }
});

test("spend policy: a swap spending a token a lamport cap cannot price is refused", async () => {
  const h = await swapUnder(
    { maxTransferLamports: 100n * BigInt(SOL) },
    swapLedger(10 * SOL - 5_000, { mint: USDC, before: 5_000_000n, after: 0n }, { mint: JUP, amount: 1_000_000n }),
  );
  try {
    await assert.rejects(h.agent.executeSwap(SWAP_REQUEST, jupiterPayload(h.wallet)), /spends 5000000 of token EPjF/);
    assert.equal(h.core.calls.filter((c) => c.method === "POST /verify").length, 0);
  } finally {
    await h.close();
  }
});

test("spend policy: a destination list alone cannot bound a swap, so the swap is refused", async () => {
  const h = await swapUnder({ allowedDestinations: [DEST], allowUncapped: true }, swapLedger(10 * SOL - 5_000));
  try {
    await assert.rejects(h.agent.executeSwap(SWAP_REQUEST, jupiterPayload(h.wallet)), /no destination to check/);
    assert.equal(h.core.calls.filter((c) => c.method === "POST /verify").length, 0);
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// External review (2026-10-16): the swap path grounded only that the request
// asks for A swap on a swap program. "Swap 1 SOL for USDC" signed whatever
// route it was handed if the Core found the route well-formed, and "Don't
// send 5 SOL to <address>" was a transfer of 5 SOL. Each case below goes
// through the whole executeSwap / executeTransfer path; "the Core was asked"
// is the step after every guard check.

function coreAsked(h: Harness): number {
  return h.core.calls.filter((c) => c.method === "POST /verify").length;
}

function parse(text: string, params: Record<string, string>, intent_type = "swap") {
  return { intent_type, raw_natural_language: text, confidence_of_parse: 0.99, extracted_parameters: params };
}

async function swapCase(
  text: string,
  params: Record<string, string>,
  rpc: ReturnType<typeof swapLedger>,
  spendPolicy?: SpendPolicy,
): Promise<Harness> {
  const h = await harness({ rpc, spendPolicy });
  h.ai.answer.set("POST /parse", { status: 200, body: parse(text, params) });
  return h;
}

const SOL_FOR_USDC = { input_token: "SOL", output_token: "USDC", amount: "1" };
/** 1 SOL, the 5,000-lamport fee and the new account's rent leave the wallet. */
const HONEST_AFTER = 10 * SOL - SOL - 5_000 - 2_039_280;

test("swap grounding: an honest swap of the requested amount and tokens goes to the Core", async () => {
  for (const text of ["Swap 1 SOL for USDC", "Swap 1 SOL for USDC with 1% slippage", "Buy USDC with 1 SOL"]) {
    const h = await swapCase(text, SOL_FOR_USDC, swapLedger(HONEST_AFTER));
    try {
      const outcome = await h.agent.executeSwap(text, jupiterPayload(h.wallet));
      assert.equal(outcome.executed, false, "the loopback Core blocked");
      assert.equal(coreAsked(h), 1, text);
    } finally {
      await h.close();
    }
  }
});

test("swap grounding: a route spending more SOL than requested is refused before the Core", async () => {
  // 2 SOL, and 100 SOL, for a request of 1 SOL.
  for (const [before, after] of [
    [10 * SOL, 8 * SOL - 5_000],
    [200 * SOL, 100 * SOL - 5_000],
  ]) {
    const h = await swapCase(SWAP_REQUEST, SOL_FOR_USDC, swapLedger(after, undefined, undefined, before));
    try {
      await assert.rejects(h.agent.executeSwap(SWAP_REQUEST, jupiterPayload(h.wallet)), (e: unknown) => {
        assert.ok(e instanceof IntentGroundingError, String(e));
        assert.match((e as Error).message, /takes \d+ lamports of SOL out of the wallet, more than 1000000000/);
        return true;
      });
      assert.equal(coreAsked(h), 0);
    } finally {
      await h.close();
    }
  }
});

test("swap grounding: a route delivering BONK for a USDC request is refused", async () => {
  const h = await swapCase(SWAP_REQUEST, SOL_FOR_USDC, swapLedger(HONEST_AFTER, undefined, { mint: BONK, amount: 9n }));
  try {
    await assert.rejects(h.agent.executeSwap(SWAP_REQUEST, jupiterPayload(h.wallet)), /asks for USDC; the transaction delivers none of it/);
    assert.equal(coreAsked(h), 0);
  } finally {
    await h.close();
  }
});

test("swap grounding: a route spending USDT for a SOL request is refused", async () => {
  const h = await swapCase(
    SWAP_REQUEST,
    SOL_FOR_USDC,
    swapLedger(10 * SOL - 5_000, { mint: USDT, before: 5_000_000n, after: 0n }),
    // Uncapped, so the grounding (not the lamport cap, which refuses any
    // token outflow) is what is under test.
    { allowUncapped: true },
  );
  try {
    await assert.rejects(h.agent.executeSwap(SWAP_REQUEST, jupiterPayload(h.wallet)), /spends 5000000 base units of Es9v/);
    assert.equal(coreAsked(h), 0);
  } finally {
    await h.close();
  }
});

test("swap grounding: a token-for-token swap is held to the token amount requested", async () => {
  const text = "Swap 150 USDC for SOL";
  const params = { input_token: "USDC", output_token: "SOL", amount: "150" };
  // A token input cannot be priced against a lamport cap (spend-policy.ts),
  // so this deployment runs uncapped, by name (Round 29, M6).
  const uncapped: SpendPolicy = { allowUncapped: true };
  // Round 29 (H2): the route pays 0.5 SOL as wrapped SOL into the wallet; its
  // minimum is 0.4975 SOL; the floor USDC/SOL=0.003 asks 0.45.
  const route = { amountIn: 150_000_000n, quotedOut: 500_000_000n };
  const delivers = { mint: WSOL, amount: 500_000_000n };
  // Spends 150 USDC and receives SOL: goes to the Core.
  let h = await swapCase(text, params, swapLedger(10 * SOL - 5_000 - 2_039_280, { mint: USDC, before: 150_000_000n, after: 0n }, delivers), uncapped);
  try {
    await h.agent.executeSwap(text, jupiterPayload(h.wallet, route));
    assert.equal(coreAsked(h), 1);
  } finally {
    await h.close();
  }
  // Spends 200 USDC for a request of 150: refused.
  h = await swapCase(text, params, swapLedger(10 * SOL - 5_000 - 2_039_280, { mint: USDC, before: 200_000_000n, after: 0n }, delivers), uncapped);
  try {
    await assert.rejects(h.agent.executeSwap(text, jupiterPayload(h.wallet, route)), /150 USDC \(150000000 base units\); the transaction takes 200000000/);
    assert.equal(coreAsked(h), 0);
  } finally {
    await h.close();
  }
});

test("swap grounding: an AI reading that disagrees with the text is refused before anything is built", async () => {
  for (const [params, why] of [
    [{ ...SOL_FOR_USDC, amount: "100" }, /read the amount as "100"; the request says "1"/],
    [{ ...SOL_FOR_USDC, output_token: "BONK" }, /read the token received as "BONK"; the request asks for USDC/],
    [{ ...SOL_FOR_USDC, input_token: "USDT" }, /read the token spent as "USDT"; the request spends SOL/],
  ] as const) {
    const h = await swapCase(SWAP_REQUEST, params, swapLedger(HONEST_AFTER));
    try {
      await assert.rejects(h.agent.executeSwap(SWAP_REQUEST, jupiterPayload(h.wallet)), why);
      assert.equal(coreAsked(h), 0);
      assert.equal(h.rpc.calls.length, 0, "nothing reached the RPC");
    } finally {
      await h.close();
    }
  }
});

test("swap grounding: a request that does not say what it spends is refused", async () => {
  for (const text of ["Buy 5 SOL with USDT", "Swap SOL for USDC", "Swap 1 SOL for USDC and 2 SOL for BONK"]) {
    const h = await swapCase(text, SOL_FOR_USDC, swapLedger(HONEST_AFTER));
    try {
      await assert.rejects(h.agent.executeSwap(text, jupiterPayload(h.wallet)), IntentGroundingError);
      assert.equal(coreAsked(h), 0, text);
    } finally {
      await h.close();
    }
  }
});

test("negation: a request that negates or cancels what it names is refused, transfer and swap", async () => {
  for (const text of [
    `Don't send 1.5 SOL to ${DEST}`,
    `do not transfer 1.5 SOL to ${DEST}`,
    `Never send 1.5 SOL to ${DEST}`,
    `Cancel the transfer of 1.5 SOL to ${DEST}`,
    `I said don\u2019t send 1.5 SOL to ${DEST}`,
  ]) {
    const h = await harness();
    try {
      h.ai.answer.set("POST /parse", { status: 200, body: honestParse(text) });
      await assert.rejects(h.agent.executeTransfer(text), /negates or cancels/, text);
      assert.equal(coreAsked(h), 0, text);
    } finally {
      await h.close();
    }
  }
  for (const text of ["Don't swap 1 SOL for USDC", "do not trade 1 SOL for USDC", "Never swap 1 SOL for USDC", "Don't buy USDC with 1 SOL"]) {
    const h = await swapCase(text, SOL_FOR_USDC, swapLedger(HONEST_AFTER));
    try {
      await assert.rejects(h.agent.executeSwap(text, jupiterPayload(h.wallet)), /negates or cancels/, text);
      assert.equal(coreAsked(h), 0, text);
      assert.equal(h.rpc.calls.length, 0, text);
    } finally {
      await h.close();
    }
  }
});
