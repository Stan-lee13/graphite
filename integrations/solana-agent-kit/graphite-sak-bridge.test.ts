/**
 * Round 19: the bridge end to end, against loopback stand-ins for the RPC,
 * the Graphite Core and the AI layer (loopback-mocks.ts). A throwaway keypair
 * generated per test; no public RPC, no funds.
 *
 *   F-19-C1  nothing signed reaches the RPC before (or without) a verdict
 *   F-19-C2  the SolanaAgentKit agent the bridge exposes cannot sign
 *   F-19-C5  destination and amount come from the user's text, not the AI's
 *   F-19-C6  a legacy env var name refuses to start instead of defaulting
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { Keypair } from "@solana/web3.js";
import bs58 from "bs58";
import { VerifiedSakAgent, UngatedSigningRefused, IntentGroundingError } from "./graphite-sak-bridge.js";
import { BLOCKED_VERDICT, mockRpc, mockService, type Loopback, type MockService } from "./loopback-mocks.js";

const DEST = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
const ATTACKER = "6bSsP4p6wXqFJdD2TkYgNcVmLzHfWq7pRyA8tCzE5nBj";
const REQUEST = `Transfer 1.5 SOL to ${DEST}`;

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
  agent: VerifiedSakAgent;
  wallet: Keypair;
  rpc: Loopback;
  core: MockService;
  ai: MockService;
  close(): Promise<void>;
}

async function harness(opts: { withSak?: boolean } = {}): Promise<Harness> {
  const rpc = await mockRpc();
  const core = await mockService({ "GET /health": { status: "ok", service: "graphite", version: "test" } });
  core.answer.set("POST /verify", { status: 200, body: BLOCKED_VERDICT });
  const ai = await mockService();
  ai.answer.set("POST /parse", { status: 200, body: honestParse() });
  const wallet = Keypair.generate();
  const agent = await VerifiedSakAgent.create({
    privateKey: bs58.encode(wallet.secretKey),
    rpcUrl: rpc.url,
    graphiteCoreUrl: core.url,
    aiLayerUrl: ai.url,
    // SAK is only constructed with this set. It is never sent anywhere: no
    // code path in these tests calls a model.
    openAiApiKey: opts.withSak ? "loopback-test-placeholder-not-a-key" : undefined,
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

test("F-19-C2: the SolanaAgentKit agent the bridge exposes cannot sign, and the secret key is not in it", async () => {
  const h = await harness({ withSak: true });
  try {
    const sak = h.agent.getSakAgent();
    assert.ok(sak, "with an OpenAI key configured the agent exists (read-only use)");
    assert.equal((sak.wallet.publicKey as { toBase58(): string }).toBase58(), h.wallet.publicKey.toBase58());
    await assert.rejects(sak.wallet.signTransaction({}), UngatedSigningRefused);
    await assert.rejects(sak.wallet.signAndSendTransaction({}), UngatedSigningRefused);
    await assert.rejects(sak.wallet.signMessage(new Uint8Array([1])), UngatedSigningRefused);

    // Walk everything reachable from the agent: the wallet's 64-byte secret
    // must not be anywhere in it.
    const secret = Buffer.from(h.wallet.secretKey);
    const seen = new Set<unknown>();
    const stack: unknown[] = [sak];
    let visited = 0;
    while (stack.length > 0 && visited < 200_000) {
      const v = stack.pop();
      if (v === null || typeof v !== "object" || seen.has(v)) continue;
      seen.add(v);
      visited++;
      if (ArrayBuffer.isView(v)) {
        const bytes = Buffer.from(v.buffer, v.byteOffset, v.byteLength);
        assert.ok(!bytes.includes(secret), "the wallet's secret key is reachable from the SAK agent");
        continue;
      }
      for (const key of Reflect.ownKeys(v)) {
        try {
          stack.push((v as Record<string | symbol, unknown>)[key]);
        } catch {
          /* accessor that throws: nothing stored there */
        }
      }
    }
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
      VerifiedSakAgent.create({ privateKey: bs58.encode(Keypair.generate().secretKey), rpcUrl: "http://127.0.0.1:1" }),
      /GRAPHITE_SERVER_URL is set but the bridge reads GRAPHITE_CORE_URL/,
    );
    delete process.env.GRAPHITE_SERVER_URL;
    delete process.env.GRAPHITE_AI_LAYER_URL;
    process.env.AI_LAYER_URL = "http://127.0.0.1:1";
    await assert.rejects(
      VerifiedSakAgent.create({ privateKey: bs58.encode(Keypair.generate().secretKey), rpcUrl: "http://127.0.0.1:1" }),
      /AI_LAYER_URL is set but the bridge reads GRAPHITE_AI_LAYER_URL/,
    );
  } finally {
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
    Object.assign(process.env, saved);
  }
});
