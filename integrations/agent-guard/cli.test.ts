/**
 * The command-line runner, as a process, against loopback stand-ins for the
 * RPC, the Core and the AI layer. Its exit status is what a script gates on,
 * so each one is pinned: a refusal by Graphite is 2, an error or a refusal
 * before the Core was asked is 1, and usage mistakes never reach the Core.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { Keypair } from "@solana/web3.js";
import bs58 from "bs58";
import { BLOCKED_VERDICT, mockRpc, mockService } from "./loopback-mocks.js";

const DEST = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
const REQUEST = `Transfer 1.5 SOL to ${DEST}`;
const CLI = fileURLToPath(new URL("./cli.ts", import.meta.url));
const TSX = fileURLToPath(new URL("./node_modules/tsx/dist/cli.mjs", import.meta.url));

function run(args: string[], env: Record<string, string>): Promise<{ code: number | null; out: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [TSX, CLI, ...args], {
      env: { PATH: process.env.PATH ?? "", SYSTEMROOT: process.env.SYSTEMROOT ?? "", ...env },
    });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (out += d));
    child.on("close", (code) => resolve({ code, out }));
  });
}

test("cli: a transfer Graphite blocks exits 2 and nothing is sent", async () => {
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
  try {
    const { code, out } = await run(["transfer", REQUEST], {
      SOLANA_PRIVATE_KEY: bs58.encode(Keypair.generate().secretKey),
      SOLANA_RPC_URL: rpc.url,
      GRAPHITE_CORE_URL: core.url,
      GRAPHITE_AI_LAYER_URL: ai.url,
      GRAPHITE_MAX_TRANSFER_LAMPORTS: "2000000000",
    });
    assert.equal(code, 2, out);
    // Round 29 (M6): the policy in force is stated at startup.
    assert.match(out, /spend policy: at most 2000000000 lamports per transaction/);
    assert.match(out, /NOT EXECUTED/);
    assert.equal(core.calls.filter((c) => c.method === "POST /verify").length, 1);
    assert.equal(rpc.calls.filter((c) => c.method === "sendTransaction").length, 0);
    for (const call of rpc.calls) assert.notEqual(call.signed, true, `${call.method} carried a signature`);
  } finally {
    await Promise.all([rpc.close(), core.close(), ai.close()]);
  }
});

test("cli: usage mistakes exit 1 before anything is contacted", async () => {
  const core = await mockService({ "GET /health": { status: "ok", service: "graphite", version: "test" } });
  try {
    const env = { GRAPHITE_CORE_URL: core.url, SOLANA_PRIVATE_KEY: bs58.encode(Keypair.generate().secretKey) };
    for (const args of [[], ["transfer"], ["drain", REQUEST], ["swap", "Swap 1 SOL for USDC"]]) {
      const { code, out } = await run(args, env);
      assert.equal(code, 1, `${JSON.stringify(args)}: ${out}`);
    }
    assert.equal(core.calls.length, 0, "the Core was never contacted");
  } finally {
    await core.close();
  }
});

test("Round 29 (M6): without a per-transaction cap the guard refuses to start, unless uncapped is accepted by name", async () => {
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
  try {
    const env = {
      SOLANA_PRIVATE_KEY: bs58.encode(Keypair.generate().secretKey),
      SOLANA_RPC_URL: rpc.url,
      GRAPHITE_CORE_URL: core.url,
      GRAPHITE_AI_LAYER_URL: ai.url,
    };
    const capless = await run(["transfer", REQUEST], env);
    assert.equal(capless.code, 1, capless.out);
    assert.match(capless.out, /no per-transaction cap is set/);
    assert.equal(core.calls.length, 0, "refused before the Core was contacted");
    const uncapped = await run(["transfer", REQUEST], { ...env, GRAPHITE_ALLOW_UNCAPPED: "1" });
    assert.equal(uncapped.code, 2, uncapped.out);
    assert.match(uncapped.out, /ACCEPTED RISK \(GRAPHITE_ALLOW_UNCAPPED=1\): NO per-transaction cap/);
  } finally {
    await Promise.all([rpc.close(), core.close(), ai.close()]);
  }
});

test("Round 29 (M3): an RPC URL that is plain http to a remote host refuses to start, without echoing it", async () => {
  const { code, out } = await run(["transfer", REQUEST], {
    SOLANA_PRIVATE_KEY: bs58.encode(Keypair.generate().secretKey),
    SOLANA_RPC_URL: "http://rpc.example.com/?api-key=SECRET123",
    GRAPHITE_CORE_URL: "http://127.0.0.1:1",
    GRAPHITE_MAX_TRANSFER_LAMPORTS: "1",
  });
  assert.equal(code, 1);
  assert.match(out, /SOLANA_RPC_URL is refused: http:\/\/rpc\.example\.com is not https/);
  assert.doesNotMatch(out, /SECRET123/);
});

test("cli: a missing key or RPC is a refusal, exit 1", async () => {
  const { code, out } = await run(["transfer", REQUEST], { GRAPHITE_CORE_URL: "http://127.0.0.1:1" });
  assert.equal(code, 1);
  assert.match(out, /refused: SOLANA_PRIVATE_KEY is required/);
});
