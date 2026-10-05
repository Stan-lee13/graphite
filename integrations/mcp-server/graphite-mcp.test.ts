/**
 * The MCP server through a real MCP `Client` (the SDK's own), against loopback
 * stand-ins for the RPC, the Graphite Core and the AI layer. The client's
 * elicitation handler plays the person who approves or declines. A throwaway
 * key per test; no public RPC, no funds.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { GraphiteGuard } from "../agent-guard/guard.js";
import { BLOCKED_VERDICT, mockRpc, mockService, throwawayWallet } from "../agent-guard/loopback-mocks.js";
import { createGraphiteMcpServer, parseConfirmation, type Confirmation } from "./graphite-mcp.js";

const DEST = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
const REQUEST = `Transfer 1.5 SOL to ${DEST}`;

async function services() {
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
    },
  });
  const wallet = throwawayWallet();
  const env = {
    SOLANA_PRIVATE_KEY: wallet.secretKeyBase58,
    SOLANA_RPC_URL: rpc.url,
    GRAPHITE_CORE_URL: core.url,
    GRAPHITE_AI_LAYER_URL: ai.url,
  };
  const guard = (maxTransferLamports?: bigint) =>
    GraphiteGuard.create({
      privateKey: env.SOLANA_PRIVATE_KEY,
      rpcUrl: rpc.url,
      graphiteCoreUrl: core.url,
      aiLayerUrl: ai.url,
      reporter: "mcp-server",
      spendPolicy: maxTransferLamports === undefined ? {} : { maxTransferLamports },
    });
  return { rpc, core, ai, env, wallet, guard, close: () => Promise.all([rpc.close(), core.close(), ai.close()]) };
}

/** A connected client; `person` answers elicitations, or the client cannot elicit when it is undefined. */
async function connect(
  guard: GraphiteGuard,
  confirmation: Confirmation,
  person?: (message: string) => { action: "accept" | "decline" | "cancel"; content?: Record<string, unknown> },
) {
  const server = createGraphiteMcpServer(guard, { confirmation });
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test", version: "0" }, { capabilities: person ? { elicitation: {} } : {} });
  const asked: string[] = [];
  if (person) {
    client.setRequestHandler(ElicitRequestSchema, async (req) => {
      asked.push(req.params.message);
      return person(req.params.message);
    });
  }
  await Promise.all([server.connect(serverSide), client.connect(clientSide)]);
  return { client, asked, close: () => Promise.all([client.close(), server.close()]) };
}

function result(r: Awaited<ReturnType<Client["callTool"]>>) {
  return r.structuredContent as { executed: boolean; refusedBy?: string; reason?: string; verdict?: { approved: boolean } };
}

test("the server refuses a guard without a per-transfer cap", async () => {
  const s = await services();
  try {
    const guard = await s.guard();
    assert.throws(() => createGraphiteMcpServer(guard, { confirmation: "elicit" }), /needs a per-transfer cap/);
  } finally {
    await s.close();
  }
});

test("the tools a client sees, with the hints a client uses to warn", async () => {
  const s = await services();
  try {
    const c = await connect(await s.guard(2_000_000_000n), "none");
    const { tools } = await c.client.listTools();
    const byName = Object.fromEntries(tools.map((t) => [t.name, t]));
    assert.deepEqual(Object.keys(byName).sort(), ["graphite_swap", "graphite_transfer_sol", "graphite_wallet"]);
    assert.equal(byName.graphite_transfer_sol.annotations?.destructiveHint, true);
    assert.equal(byName.graphite_swap.annotations?.destructiveHint, true);
    assert.equal(byName.graphite_wallet.annotations?.readOnlyHint, true);
    await c.close();
  } finally {
    await s.close();
  }
});

test("a person approves: the request runs through the guard and Graphite's block is the result", async () => {
  const s = await services();
  try {
    const guard = await s.guard(2_000_000_000n);
    const c = await connect(guard, "elicit", () => ({ action: "accept", content: { approve: true } }));
    const out = result(await c.client.callTool({ name: "graphite_transfer_sol", arguments: { request: REQUEST } }));
    assert.equal(c.asked.length, 1, "the person was asked once");
    assert.match(c.asked[0], new RegExp(DEST), "and was shown the request the guard acts on");
    assert.equal(out.executed, false);
    assert.equal(out.refusedBy, "graphite");
    assert.equal(s.core.calls.filter((x) => x.method === "POST /verify").length, 1);
    for (const call of s.rpc.calls) assert.notEqual(call.signed, true);
    assert.equal(s.rpc.calls.filter((x) => x.method === "sendTransaction").length, 0);
    await c.close();
  } finally {
    await s.close();
  }
});

test("a person declines: nothing is built, verified or sent", async () => {
  const s = await services();
  try {
    for (const answer of [
      { action: "decline" as const },
      { action: "cancel" as const },
      { action: "accept" as const, content: { approve: false } },
    ]) {
      const c = await connect(await s.guard(2_000_000_000n), "elicit", () => answer);
      const out = result(await c.client.callTool({ name: "graphite_transfer_sol", arguments: { request: REQUEST } }));
      assert.equal(out.executed, false);
      assert.equal(out.refusedBy, "person", JSON.stringify(answer));
      await c.close();
    }
    assert.equal(s.core.calls.filter((x) => x.method === "POST /verify").length, 0);
    assert.equal(s.rpc.calls.length, 0);
  } finally {
    await s.close();
  }
});

test("a client that cannot ask a person is refused, not executed for", async () => {
  const s = await services();
  try {
    const c = await connect(await s.guard(2_000_000_000n), "elicit");
    const out = result(await c.client.callTool({ name: "graphite_transfer_sol", arguments: { request: REQUEST } }));
    assert.equal(out.refusedBy, "person");
    assert.match(out.reason ?? "", /cannot ask a person/);
    assert.equal(s.core.calls.filter((x) => x.method === "POST /verify").length, 0);
    await c.close();
  } finally {
    await s.close();
  }
});

test("over the cap: refused by the spend policy after the person approved, before the RPC or the Core", async () => {
  const s = await services();
  try {
    const c = await connect(await s.guard(1_000_000_000n), "elicit", () => ({ action: "accept", content: { approve: true } }));
    const out = result(await c.client.callTool({ name: "graphite_transfer_sol", arguments: { request: REQUEST } }));
    assert.equal(out.refusedBy, "spend-policy");
    assert.equal(s.rpc.calls.length, 0);
    assert.equal(s.core.calls.filter((x) => x.method === "POST /verify").length, 0);
    await c.close();
  } finally {
    await s.close();
  }
});

test("GRAPHITE_MCP_CONFIRMATION: elicit by default, none only when said, anything else refuses to start", () => {
  assert.equal(parseConfirmation(undefined), "elicit");
  assert.equal(parseConfirmation(""), "elicit");
  assert.equal(parseConfirmation("elicit"), "elicit");
  assert.equal(parseConfirmation("none"), "none");
  for (const bad of ["off", "false", "NONE", " none"]) assert.throws(() => parseConfirmation(bad), /REFUSING TO START/);
});

test("the stdio server, as a process: stdout carries only the protocol; the guard's logs go to stderr", async () => {
  const s = await services();
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      fileURLToPath(new URL("./node_modules/tsx/dist/cli.mjs", import.meta.url)),
      fileURLToPath(new URL("./server.ts", import.meta.url)),
    ],
    env: {
      ...s.env,
      PATH: process.env.PATH ?? "",
      SYSTEMROOT: process.env.SYSTEMROOT ?? "",
      GRAPHITE_MAX_TRANSFER_LAMPORTS: "2000000000",
      GRAPHITE_MCP_CONFIRMATION: "none",
    },
    stderr: "pipe",
  });
  const client = new Client({ name: "test", version: "0" });
  // A line on stdout that is not a protocol message is dropped by this client
  // and reported here; a stricter client would fail the session on it.
  const protocolErrors: string[] = [];
  client.onerror = (e) => protocolErrors.push(e.message);
  try {
    await client.connect(transport);
    const { tools } = await client.listTools();
    assert.equal(tools.length, 3);
    // A call makes the guard log (parse, simulate, artifact, verdict). Had any
    // of it reached stdout, the client would have failed to parse a message.
    const out = result(await client.callTool({ name: "graphite_transfer_sol", arguments: { request: REQUEST } }));
    assert.equal(out.refusedBy, "graphite");
    const wallet = await client.callTool({ name: "graphite_wallet", arguments: {} });
    assert.equal((wallet.structuredContent as { address: string }).address, s.wallet.publicKey);
    assert.deepEqual(protocolErrors, [], "something other than the protocol reached stdout");
  } finally {
    await client.close();
    await s.close();
  }
});
