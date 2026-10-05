/**
 * The AI SDK tools inside the AI SDK's own tool loop (`generateText`), with
 * the SDK's scripted test model (`ai/test`) standing in for a hosted model,
 * and loopback stand-ins for the RPC, the Graphite Core and the AI layer
 * (`../agent-guard/loopback-mocks.ts`). A throwaway keypair per test; no
 * public RPC, no funds.
 *
 * The scripted model plays the part a hosted model plays: it emits a tool
 * call with an input it chose. Everything after that is the real path — the
 * SDK validates the input against the tool's schema, applies the approval
 * configuration, runs the tool, and the tool runs the guard.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateText } from "ai";
import { MockLanguageModelV4 } from "ai/test";
import { GraphiteGuard } from "../agent-guard/guard.js";
import { BLOCKED_VERDICT, mockRpc, mockService, throwawayWallet } from "../agent-guard/loopback-mocks.js";
import { GRAPHITE_TOOL_APPROVAL, graphiteTools, type GraphiteToolResult } from "./graphite-tools.js";

const DEST = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
const ATTACKER = "6bSsP4p6wXqFJdD2TkYgNcVmLzHfWq7pRyA8tCzE5nBj";
const REQUEST = `Transfer 1.5 SOL to ${DEST}`;

const usage = {
  inputTokens: { total: 10, noCache: 10, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 5, text: 5, reasoning: 0 },
};

/** A model that calls one tool with the given input, then stops. */
function modelCalling(toolName: string, input: unknown) {
  return new MockLanguageModelV4({
    doGenerate: [
      {
        content: [{ type: "tool-call", toolCallId: "call-1", toolName, input: JSON.stringify(input) }],
        finishReason: { unified: "tool-calls", raw: "tool_calls" },
        usage,
        warnings: [],
      },
    ],
  });
}

async function services(aiAnswer: Record<string, unknown> = {}) {
  const rpc = await mockRpc();
  const core = await mockService({ "GET /health": { status: "ok", service: "graphite", version: "test" } });
  core.answer.set("POST /verify", { status: 200, body: BLOCKED_VERDICT });
  const ai = await mockService();
  ai.answer.set("POST /parse", {
    status: 200,
    body: {
      intent_type: "transfer",
      raw_natural_language: REQUEST,
      confidence_of_parse: 0.9,
      extracted_parameters: { amount: "1.5", input_token: "SOL", destination: DEST },
      ...aiAnswer,
    },
  });
  const guard = (maxTransferLamports?: bigint) =>
    GraphiteGuard.create({
      privateKey: throwawayWallet().secretKeyBase58,
      rpcUrl: rpc.url,
      graphiteCoreUrl: core.url,
      aiLayerUrl: ai.url,
      reporter: "vercel-ai",
      spendPolicy: maxTransferLamports === undefined ? {} : { maxTransferLamports },
    });
  return { rpc, core, ai, guard, close: () => Promise.all([rpc.close(), core.close(), ai.close()]) };
}

function toolResult(result: { toolResults: { output: unknown }[] }): GraphiteToolResult {
  assert.equal(result.toolResults.length, 1, "exactly one tool ran");
  return result.toolResults[0].output as GraphiteToolResult;
}

test("graphiteTools refuses a guard without a per-transfer cap", async () => {
  const s = await services();
  try {
    const guard = await s.guard();
    assert.throws(() => graphiteTools(guard), /needs a per-transfer cap/);
  } finally {
    await s.close();
  }
});

test("a model's transfer call runs through the guard: Graphite is shown the bytes; its block is the result", async () => {
  const s = await services();
  try {
    const guard = await s.guard(2_000_000_000n);
    const result = await generateText({
      model: modelCalling("graphite_transfer_sol", { request: REQUEST }),
      tools: graphiteTools(guard),
      prompt: REQUEST,
    });
    const out = toolResult(result);
    assert.equal(out.executed, false);
    assert.equal(out.refusedBy, "graphite");
    assert.equal(out.verdict?.approved, false);
    const verifies = s.core.calls.filter((c) => c.method === "POST /verify");
    assert.equal(verifies.length, 1, "the Core was asked once");
    const body = verifies[0].params as { signed_transaction: number[]; account_addresses: string[] };
    assert.deepEqual(body.account_addresses, [guard.publicKey, DEST]);
    assert.ok(body.signed_transaction.slice(1, 65).every((b) => b === 0), "the artifact is unsigned");
    for (const call of s.rpc.calls) assert.notEqual(call.signed, true, `${call.method} carried a signature`);
    assert.equal(s.rpc.calls.filter((c) => c.method === "sendTransaction").length, 0);
  } finally {
    await s.close();
  }
});

test("with GRAPHITE_TOOL_APPROVAL the tool waits for a person: nothing is built, verified or sent", async () => {
  const s = await services();
  try {
    const guard = await s.guard(2_000_000_000n);
    const result = await generateText({
      model: modelCalling("graphite_transfer_sol", { request: REQUEST }),
      tools: graphiteTools(guard),
      toolApproval: GRAPHITE_TOOL_APPROVAL,
      prompt: REQUEST,
    });
    assert.equal(result.toolResults.length, 0, "the tool did not run");
    const requests = result.content.filter((p) => p.type === "tool-approval-request");
    assert.equal(requests.length, 1, "the SDK asked for approval");
    assert.equal(s.core.calls.filter((c) => c.method === "POST /verify").length, 0);
    assert.equal(s.rpc.calls.length, 0);
  } finally {
    await s.close();
  }
});

test("a model-written transfer over the operator's cap is refused before the RPC or the Core", async () => {
  const s = await services();
  try {
    const guard = await s.guard(1_000_000_000n); // 1 SOL cap; the request moves 1.5
    const result = await generateText({
      model: modelCalling("graphite_transfer_sol", { request: REQUEST }),
      tools: graphiteTools(guard),
      prompt: REQUEST,
    });
    const out = toolResult(result);
    assert.equal(out.executed, false);
    assert.equal(out.refusedBy, "spend-policy");
    assert.match(out.reason ?? "", /exceeds the per-transfer cap/);
    assert.equal(s.core.calls.filter((c) => c.method === "POST /verify").length, 0);
    assert.equal(s.rpc.calls.length, 0);
  } finally {
    await s.close();
  }
});

test("a destination the request does not contain is refused by the guard's grounding", async () => {
  // The AI layer's reading names a destination the request never wrote.
  const s = await services({ extracted_parameters: { amount: "1.5", input_token: "SOL", destination: ATTACKER } });
  try {
    const guard = await s.guard(2_000_000_000n);
    const result = await generateText({
      model: modelCalling("graphite_transfer_sol", { request: REQUEST }),
      tools: graphiteTools(guard),
      prompt: REQUEST,
    });
    const out = toolResult(result);
    assert.equal(out.executed, false);
    assert.equal(out.refusedBy, "request-grounding");
    assert.equal(s.core.calls.filter((c) => c.method === "POST /verify").length, 0);
  } finally {
    await s.close();
  }
});

test("a malformed tool input never reaches the guard: the SDK's schema refuses it", async () => {
  const s = await services();
  try {
    const guard = await s.guard(2_000_000_000n);
    const result = await generateText({
      model: modelCalling("graphite_transfer_sol", { request: "" }),
      tools: graphiteTools(guard),
      prompt: REQUEST,
    });
    assert.equal(result.toolResults.length, 0);
    assert.equal(s.core.calls.length + s.rpc.calls.length, 1, "only the guard's startup health check");
  } finally {
    await s.close();
  }
});

test("graphite_wallet reports the address and limits and moves nothing", async () => {
  const s = await services();
  try {
    const guard = await s.guard(2_000_000_000n);
    const result = await generateText({
      model: modelCalling("graphite_wallet", {}),
      tools: graphiteTools(guard),
      prompt: "what is my wallet?",
    });
    const out = result.toolResults[0].output as { address: string; maxTransferLamports: string };
    assert.equal(out.address, guard.publicKey);
    assert.equal(out.maxTransferLamports, "2000000000");
    assert.equal(s.rpc.calls.length, 0);
  } finally {
    await s.close();
  }
});
