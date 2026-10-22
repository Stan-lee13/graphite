/**
 * Round 32: the spend limits hold what the wallet pays, not only what it
 * sends. Round 30 recorded that the per-transfer cap and the rolling
 * aggregate counted a transfer's amount but not its fee, so a transfer at the
 * cap took the cap plus the fee. Both now count the larger of the amount plus
 * the fee the message asks for and what a simulation of the exact bytes
 * takes from the fee payer.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { Keypair } from "@solana/web3.js";
import bs58 from "bs58";
import { GraphiteGuard, SpendPolicyRefusal, swapPolicyFromEnv, type SpendPolicy } from "./guard.js";
import { mockApprovingCore, mockRpc, mockService, type MockRpc, type MockService } from "./loopback-mocks.js";

const DEST = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
const OTHER = "p2Yicb86aZig616Eav2VWG9vuXR5mEqhtzshZYBxzsV";
const REQUEST = `Transfer 1.5 SOL to ${DEST}`;
const SYSTEM = "11111111111111111111111111111111";
const SOL = 1_000_000_000n;
const FEE = 5_000n;

interface H {
  agent: GraphiteGuard;
  rpc: MockRpc;
  core: MockService;
  close(): Promise<void>;
}

function parseOf(text: string, destination: string, amount: string) {
  return {
    intent_type: "transfer",
    raw_natural_language: text,
    confidence_of_parse: 0.9,
    extracted_parameters: { amount, input_token: "SOL", destination },
  };
}

async function harness(o: {
  spendPolicy: SpendPolicy;
  /** What the wallet holds after the simulation (default: the amount and fee gone). */
  walletAfter?: (w: string) => bigint;
  requests?: { text: string; destination: string; amount: string }[];
}): Promise<H & { ai: MockService }> {
  const wallet = Keypair.generate();
  const w = wallet.publicKey.toBase58();
  const rpc = await mockRpc({
    ledger: { [w]: { lamports: Number(10n * SOL), owner: SYSTEM } },
    afterSimulation: o.walletAfter
      ? { [w]: { lamports: Number(o.walletAfter(w)), owner: SYSTEM } }
      : { [w]: { lamports: Number(10n * SOL - 3n * SOL / 2n - FEE), owner: SYSTEM } },
  });
  const core = await mockApprovingCore();
  const ai = await mockService();
  ai.answer.set("POST /parse", { status: 200, body: parseOf(REQUEST, DEST, "1.5") });
  const agent = await GraphiteGuard.create({
    privateKey: bs58.encode(wallet.secretKey),
    rpcUrl: rpc.url,
    graphiteCoreUrl: core.url,
    aiLayerUrl: ai.url,
    spendPolicy: o.spendPolicy,
    swapPolicy: swapPolicyFromEnv({ GRAPHITE_SWAP_MIN_RATES: "SOL/USDC=100" }),
    swapEnvelope: {},
  });
  return {
    agent,
    rpc,
    core,
    ai,
    close: async () => {
      agent.close();
      await Promise.all([rpc.close(), core.close(), ai.close()]);
    },
  };
}

const sends = (h: H) => h.rpc.calls.filter((c) => c.method === "sendTransaction").length;
const coreAsked = (h: H) => h.core.calls.filter((c) => c.method === "POST /verify").length;
function assertNothingSigned(h: H): void {
  assert.equal(sends(h), 0, "nothing was sent");
  for (const c of h.rpc.calls) assert.notEqual(c.signed, true, `${c.method} carried a signature`);
}

test("fee: a transfer of exactly the cap is refused, because its fee takes the wallet's outflow over it", async () => {
  const h = await harness({ spendPolicy: { maxTransferLamports: 3n * SOL / 2n } });
  try {
    await assert.rejects(h.agent.executeTransfer(REQUEST), (e: unknown) => {
      assert.ok(e instanceof SpendPolicyRefusal, String(e));
      assert.match(
        (e as Error).message,
        /takes 1500005000 lamports out of the wallet \(1500000000 sent \+ 5000 fee; 1500005000 measured by simulation\), above the per-transfer cap of 1500000000/,
      );
      return true;
    });
    assert.equal(coreAsked(h), 0, "the Core is not asked about a transfer the operator's limits refuse");
    assertNothingSigned(h);
  } finally {
    await h.close();
  }
});

test("fee: the same transfer under a cap that holds its fee executes (control)", async () => {
  const h = await harness({ spendPolicy: { maxTransferLamports: 3n * SOL / 2n + FEE } });
  try {
    const outcome = await h.agent.executeTransfer(REQUEST);
    assert.equal(outcome.executed, true);
    assert.equal(coreAsked(h), 1);
    assert.equal(sends(h), 1);
  } finally {
    await h.close();
  }
});

test("fee: the aggregate counts each transfer's fee, so two transfers that sum to the limit exceed it", async () => {
  // The stand-in's simulation takes only the fee, so the stated amount plus
  // fee is the larger figure for both requests.
  const h = await harness({
    spendPolicy: { maxTransferLamports: 2n * SOL, maxTotalLamports: 2n * SOL },
    walletAfter: () => 10n * SOL - FEE,
  });
  try {
    assert.equal((await h.agent.executeTransfer(REQUEST)).executed, true);
    const next = `Transfer 0.5 SOL to ${OTHER}`;
    h.ai.answer.set("POST /parse", { status: 200, body: parseOf(next, OTHER, "0.5") });
    await assert.rejects(h.agent.executeTransfer(next), (e: unknown) => {
      assert.ok(e instanceof SpendPolicyRefusal, String(e));
      // 1.5 SOL + fee already spent, 0.5 SOL + fee asked: 2 SOL + 10,000 lamports.
      assert.match((e as Error).message, /500005000 lamports would bring this guard's outflow in the last 3600 s to 2000010000/);
      return true;
    });
    assert.equal(sends(h), 1, "only the first transfer was sent");
  } finally {
    await h.close();
  }
});

test("fee: a simulation that takes more than the amount and fee is what the cap holds", async () => {
  // Something in the exact bytes takes 3 SOL from the fee payer for a 1.5 SOL transfer.
  const h = await harness({
    spendPolicy: { maxTransferLamports: 2n * SOL },
    walletAfter: () => 7n * SOL,
  });
  try {
    await assert.rejects(h.agent.executeTransfer(REQUEST), (e: unknown) => {
      assert.ok(e instanceof SpendPolicyRefusal, String(e));
      assert.match((e as Error).message, /takes 3000000000 lamports out of the wallet .*3000000000 measured by simulation/);
      return true;
    });
    assert.equal(coreAsked(h), 0);
    assertNothingSigned(h);
  } finally {
    await h.close();
  }
});
