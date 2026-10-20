/**
 * The SAK adapter, against loopback stand-ins for the RPC, the Graphite Core
 * and the AI layer (`../agent-guard/loopback-mocks.ts`). A throwaway keypair
 * per test; no public RPC, no funds.
 *
 * The verified paths are the guard's and are tested there
 * (`../agent-guard/guard.test.ts`, R-P8 phase 3). What is pinned here is what
 * this adapter adds:
 *
 *   F-19-C2  the SolanaAgentKit agent it exposes cannot sign, and the secret
 *            key is not reachable from it or from the adapter
 *   delegation  executeTransfer goes through the guard
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { Keypair, Transaction } from "@solana/web3.js";
import bs58 from "bs58";
import { VerifiedSakAgent, UngatedSigningRefused } from "./graphite-sak-bridge.js";
import { BLOCKED_VERDICT, mockRpc, mockService, type Loopback, type MockService } from "../agent-guard/loopback-mocks.js";

const DEST = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
const REQUEST = `Transfer 1.5 SOL to ${DEST}`;

interface Harness {
  agent: VerifiedSakAgent;
  wallet: Keypair;
  rpc: Loopback;
  core: MockService;
  ai: MockService;
  close(): Promise<void>;
}

/** Round 29 (M8): a Core API key and an OpenAI key that must not be reachable through the adapter. */
const CORE_API_KEY = `loopback-core-key-${Math.random().toString(36).slice(2)}`;
const OPENAI_KEY = `loopback-test-placeholder-not-a-key-${Math.random().toString(36).slice(2)}`;

async function harness(opts: { withSak?: boolean; spendPolicy?: { maxTransferLamports?: bigint } } = {}): Promise<Harness> {
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
  const wallet = Keypair.generate();
  const agent = await VerifiedSakAgent.create({
    privateKey: bs58.encode(wallet.secretKey),
    rpcUrl: rpc.url,
    graphiteCoreUrl: core.url,
    aiLayerUrl: ai.url,
    graphiteApiKey: CORE_API_KEY,
    // Round 29 (M6): the guard requires a per-transaction cap.
    spendPolicy: opts.spendPolicy ?? { maxTransferLamports: 2_000_000_000n },
    // SAK is only constructed with this set. It is never sent anywhere: no
    // code path in these tests calls a model.
    openAiApiKey: opts.withSak ? OPENAI_KEY : undefined,
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

test("F-19-C2: the SolanaAgentKit agent the bridge exposes cannot sign, and the secret key is not in it", async () => {
  const h = await harness({ withSak: true });
  try {
    const sak = h.agent.getSakAgent();
    assert.ok(sak, "with an OpenAI key configured the agent exists (read-only use)");
    assert.equal((sak.wallet.publicKey as { toBase58(): string }).toBase58(), h.wallet.publicKey.toBase58());
    await assert.rejects(sak.wallet.signTransaction(new Transaction()), UngatedSigningRefused);
    await assert.rejects(sak.wallet.signAndSendTransaction(new Transaction()), UngatedSigningRefused);
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

test("R8: the wallet's secret key is not reachable through the adapter or SAK at runtime", async () => {
  const h = await harness({ withSak: true });
  try {
    const secret = Buffer.from(h.wallet.secretKey).toString("hex");
    const seen = new Set<unknown>();
    const found: string[] = [];
    const walk = (value: unknown, path: string, depth: number): void => {
      if (typeof value === "string") {
        if (value.includes(CORE_API_KEY)) found.push(`${path} holds the Core API key`);
        if (value.includes(OPENAI_KEY)) found.push(`${path} holds the OpenAI key`);
      }
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
      // A getter that returns the key is as reachable as a field holding it.
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
    walk(h.agent.getGuard(), "guard", 0);
    // Round 29 (M8): getGraphiteClient used to return the Core client itself,
    // and with it the Core API key.
    walk(h.agent.getGraphiteClient(), "agent.getGraphiteClient()", 0);
    assert.deepEqual(found, [], `a secret is reachable through the adapter or the guard: ${found.join("; ")}`);
    // SolanaAgentKit itself keeps the OpenAI key in its own config (SAK's
    // design: it needs it to call a model). The wallet key and the Core key are
    // not there; the OpenAI key is, and that is the one thing it holds.
    walk(h.agent.getSakAgent(), "sak", 0);
    assert.ok((found as string[]).every((f) => f.endsWith("holds the OpenAI key")), found.join("; "));
  } finally {
    await h.close();
  }
});

test("executeTransfer goes through the guard: an unsigned artifact to the Core, nothing sent after a block", async () => {
  const h = await harness();
  try {
    const outcome = await h.agent.executeTransfer(REQUEST);
    assert.equal(outcome.executed, false, "the loopback Core blocked");
    const verify = h.core.calls.find((c) => c.method === "POST /verify");
    assert.ok(verify, "the Core was asked");
    const body = verify!.params as { signed_transaction?: number[]; account_addresses: string[] };
    assert.ok(body.signed_transaction!.slice(1, 65).every((b) => b === 0), "unsigned");
    assert.deepEqual(body.account_addresses, [h.wallet.publicKey.toBase58(), DEST]);
    for (const call of h.rpc.calls) assert.notEqual(call.signed, true, `${call.method} carried a signature`);
    assert.equal(h.rpc.calls.filter((c) => c.method === "sendTransaction").length, 0);
    assert.equal(h.agent.getSakAgent(), null, "no OpenAI key, no SAK agent; the verified path does not need one");
  } finally {
    await h.close();
  }
});

test("Round 29 (M6, audit S1): the adapter does not start without a per-transaction cap", async () => {
  const core = await mockService({ "GET /health": { status: "ok", service: "graphite", version: "test" } });
  try {
    await assert.rejects(
      VerifiedSakAgent.create({
        privateKey: bs58.encode(Keypair.generate().secretKey),
        rpcUrl: "http://127.0.0.1:1",
        graphiteCoreUrl: core.url,
        spendPolicy: {},
      }),
      /no per-transaction cap is set/,
    );
    assert.equal(core.calls.length, 0, "refused before the Core was contacted");
  } finally {
    await core.close();
  }
});

test("Round 29 (M8): getGraphiteClient is the Core's read-only endpoints, not the client", async () => {
  const h = await harness();
  try {
    const client = h.agent.getGraphiteClient();
    assert.deepEqual(Object.keys(client).sort(), ["health", "listManifests"]);
    assert.equal((client as unknown as Record<string, unknown>).apiKey, undefined);
    assert.equal(typeof (client as unknown as Record<string, unknown>).verify, "undefined");
  } finally {
    await h.close();
  }
});
