/**
 * Round 35: the guard's RPC transport (F-014), the verdict's age at signing
 * (F-017) and the spend accounting around submission (F-013), end to end
 * against loopback stand-ins. Nothing here reaches a public RPC.
 *
 *   F-014  every RPC request the guard makes — web3.js's included — has a
 *          deadline over headers and body, a body bound, no redirect, no
 *          hidden 429 retries, and no websocket
 *   F-017  a verdict older than the bound is not signed
 *   F-013  fee, priority fee and rent are counted; parallel calls cannot
 *          overspend; a send whose outcome is unknown is not sent again
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import bs58 from "bs58";
import {
  BoundTransaction,
  GraphiteGuard,
  ResidualPolicyRefusal,
  PriorSubmissionUnresolved,
  RpcTransportRefusal,
  SpendPolicyRefusal,
  StaleVerdict,
  SubmissionOutcomeUnknown,
  swapPolicyFromEnv,
  type GuardConfig,
  type SpendPolicy,
} from "./guard.js";
import { ResidualPolicy } from "./residual-policy.js";
import { executeBoundTransaction } from "./execution-lifecycle.js";
import { firstSignatureOf } from "./artifact.js";
import { toolRefusalOf } from "./tool-results.js";
import {
  MOCK_BLOCKHASH,
  mockApprovingCore,
  mockHostileRpcFront,
  mockRpc,
  mockService,
  tokenAccountData,
  type HostileFront,
  type MockRpc,
  type MockService,
} from "./loopback-mocks.js";
import { jupiterRouteData } from "./swap-fixtures.js";
import { associatedTokenAddress, SPL_TOKEN_PROGRAM } from "./swap-envelope.js";
import type { UnobservedCode, VerificationResult } from "../../sdk/typescript/src/types.js";

const DEST = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
const OTHER = "p2Yicb86aZig616Eav2VWG9vuXR5mEqhtzshZYBxzsV";
const REQUEST = `Transfer 1.5 SOL to ${DEST}`;
const SYSTEM = "11111111111111111111111111111111";
const SPL_TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const WSOL = "So11111111111111111111111111111111111111112";
const JUPITER_V6 = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
const SOL = 1_000_000_000;
const FEE = 5_000;
/** The deadline these tests give the guard's RPC requests. */
const RPC_TIMEOUT_MS = 1_000;

function transferParse(text: string) {
  const m = /Transfer ([0-9.]+) SOL to ([1-9A-HJ-NP-Za-km-z]{32,44})/.exec(text);
  return {
    intent_type: "transfer",
    raw_natural_language: text,
    confidence_of_parse: 0.9,
    extracted_parameters: { amount: m?.[1] ?? "0", input_token: "SOL", destination: m?.[2] ?? DEST },
  };
}

interface H {
  agent: GraphiteGuard;
  wallet: Keypair;
  rpc: MockRpc;
  front: HostileFront;
  core: MockService;
  ai: MockService;
  close(): Promise<void>;
}

/** The guard against an honest RPC stand-in behind a hostile front. */
async function harness(
  o: {
    wallet?: Keypair;
    spendPolicy?: SpendPolicy;
    config?: Partial<GuardConfig>;
    rpc?: (w: Keypair) => Parameters<typeof mockRpc>[0];
    parse?: (text: string) => unknown;
    verdict?: Parameters<typeof mockApprovingCore>[0];
  } = {},
): Promise<H> {
  const wallet = o.wallet ?? Keypair.generate();
  const w = wallet.publicKey.toBase58();
  const rpc = await mockRpc(
    o.rpc?.(wallet) ?? {
      ledger: { [w]: { lamports: 10 * SOL, owner: SYSTEM } },
      afterSimulation: { [w]: { lamports: 10 * SOL - FEE, owner: SYSTEM } },
    },
  );
  const front = await mockHostileRpcFront(rpc.url);
  const core = await mockApprovingCore(o.verdict ?? {});
  const ai = await mockService();
  ai.respond.set("POST /parse", (body) => ({
    status: 200,
    body: (o.parse ?? transferParse)((body as { text: string }).text),
  }));
  let agent: GraphiteGuard;
  try {
    agent = await GraphiteGuard.create({
      privateKey: bs58.encode(wallet.secretKey),
      rpcUrl: front.url,
      graphiteCoreUrl: core.url,
      aiLayerUrl: ai.url,
      spendPolicy: o.spendPolicy ?? { maxTransferLamports: 100n * BigInt(SOL) },
      swapPolicy: swapPolicyFromEnv({ GRAPHITE_SWAP_MIN_RATES: "SOL/USDC=100" }),
      swapEnvelope: {},
      rpcTimeoutMs: RPC_TIMEOUT_MS,
      ...o.config,
    });
  } catch (e) {
    await Promise.all([front.close(), rpc.close(), core.close(), ai.close()]);
    throw e;
  }
  return {
    agent,
    wallet,
    rpc,
    front,
    core,
    ai,
    close: async () => {
      agent.close();
      await Promise.all([front.close(), rpc.close(), core.close(), ai.close()]);
    },
  };
}

const sent = (h: H) => h.rpc.calls.filter((c) => c.method === "sendTransaction").length;
const coreAsked = (h: H) => h.core.calls.filter((c) => c.method === "POST /verify").length;
const trail = (h: H) =>
  h.core.calls.filter((c) => c.method === "POST /audit/event").map((c) => c.params as { event_type: string; detail?: string });

/**
 * Settle `p` within `ms`, or report that it hung. A guard call that hangs is
 * the failure these tests are about, so it is an assertion, not a test timeout.
 */
async function within<T>(p: Promise<T>, ms: number, what: string): Promise<{ ok: true; value: T } | { ok: false; error: unknown }> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const hung = new Promise<"hung">((resolve) => {
    timer = setTimeout(() => resolve("hung"), ms);
  });
  try {
    const r = await Promise.race([p.then((value) => ({ ok: true as const, value }), (error) => ({ ok: false as const, error })), hung]);
    if (r === "hung") {
      p.catch(() => {});
      assert.fail(`${what} did not settle within ${ms} ms: the guard waited on the RPC without a deadline`);
    }
    return r;
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// F-014: the transport.

test("F-014: an RPC that never answers is refused at the deadline, not waited on (web3.js getLatestBlockhash)", async () => {
  const h = await harness();
  try {
    h.front.modes.set("getLatestBlockhash", "hang");
    const started = Date.now();
    const r = await within(h.agent.executeTransfer(REQUEST), 5_000, "executeTransfer against a hanging RPC");
    assert.equal(r.ok, false);
    const error = (r as { error: unknown }).error;
    // web3.js wraps the transport's error in its own ("failed to get recent blockhash: …").
    assert.match(String(error), /RpcTransportRefusal: .*getLatestBlockhash did not complete within 1000 ms/);
    assert.ok(Date.now() - started < 4_000, "refused near the deadline");
    assert.equal(coreAsked(h), 0, "nothing was verified");
    assert.equal(sent(h), 0, "nothing was sent");
  } finally {
    await h.close();
  }
});

test("F-014: a body that trickles forever is cut at the deadline: confirmation ends, and the repeat is refused", async () => {
  const h = await harness();
  try {
    h.front.modes.set("getSignatureStatuses", "trickle");
    const r = await within(h.agent.executeTransfer(REQUEST), 5_000, "executeTransfer whose confirmation trickles");
    assert.equal(r.ok, true, String((r as { error?: unknown }).error));
    const outcome = (r as { value: Awaited<ReturnType<GraphiteGuard["executeTransfer"]>> }).value;
    assert.equal(outcome.executed, true);
    assert.equal(outcome.lifecycle?.confirmed, false);
    assert.match(outcome.lifecycle?.confirmationError ?? "", /getSignatureStatuses did not complete within 1000 ms/);
    // Not seen confirmed, so unresolved: the same request again asks the RPC
    // first, and an RPC that cannot answer is a refusal, not a second send.
    const again = await within(h.agent.executeTransfer(REQUEST), 5_000, "the repeat");
    assert.equal(again.ok, false);
    assert.ok((again as { error: unknown }).error instanceof RpcTransportRefusal, String((again as { error: unknown }).error));
    assert.equal(sent(h), 1, "one transaction sent, never two");
  } finally {
    await h.close();
  }
});

test("F-014: an answer over 32 MiB is refused before it is parsed (streamed, no content-length)", async () => {
  // A deadline long enough that the size bound, not the clock, is what refuses.
  const h = await harness({ config: { rpcTimeoutMs: 20_000 } });
  try {
    h.front.modes.set("getLatestBlockhash", "huge");
    const r = await within(h.agent.executeTransfer(REQUEST), 25_000, "executeTransfer against an oversized answer");
    assert.equal(r.ok, false, "an oversized answer was accepted");
    const error = (r as { error: unknown }).error;
    assert.match(String(error), /RpcTransportRefusal: .*getLatestBlockhash exceeds the 33554432-byte bound/);
    assert.equal(coreAsked(h), 0);
    assert.equal(sent(h), 0);
  } finally {
    await h.close();
  }
});

test("F-014: a 429 is one refused request, not five retries with a growing sleep inside one call", async () => {
  const h = await harness();
  try {
    h.front.modes.set("getLatestBlockhash", "rate-limit");
    const started = Date.now();
    await assert.rejects(h.agent.executeTransfer(REQUEST), /429/);
    assert.equal(h.front.counts.get("getLatestBlockhash"), 1, "web3.js retried behind the guard's back");
    assert.ok(Date.now() - started < 2_000);
    assert.equal(sent(h), 0);
  } finally {
    await h.close();
  }
});

test("F-014: no websocket — the guard's path polls over HTTP, and the handed-out connection confirms by polling and refuses subscriptions", async () => {
  const h = await harness();
  try {
    const outcome = await h.agent.executeTransfer(REQUEST);
    assert.equal(outcome.lifecycle?.confirmed, true);
    const connection = h.agent.getConnection();
    // web3.js's own confirmTransaction subscribes to the signature over
    // ws://host:<port + 1>, an endpoint the transport rule never checked.
    const confirmed = await within(
      connection.confirmTransaction({ signature: outcome.signature!, blockhash: MOCK_BLOCKHASH, lastValidBlockHeight: 1_000 }),
      5_000,
      "getConnection().confirmTransaction",
    );
    assert.equal(confirmed.ok, true, String((confirmed as { error?: unknown }).error));
    assert.deepEqual((confirmed as { value: { value: unknown } }).value.value, { err: null });
    assert.throws(() => connection.onSignature(outcome.signature!, () => {}), RpcTransportRefusal);
    assert.throws(() => connection.onSlotChange(() => {}), RpcTransportRefusal);
    await new Promise((resolve) => setTimeout(resolve, 300));
    assert.equal(h.front.upgrades, 0, "a websocket upgrade reached the RPC");
  } finally {
    await h.close();
  }
});

test("F-014 (regression guard, already held since Round 29 M3): a redirect mid-lifecycle is never followed to another host", async () => {
  let targetHits = 0;
  const target = createServer((_q, r) => (targetHits++, r.end("{}")));
  await new Promise<void>((r) => target.listen(0, "127.0.0.1", r));
  const h = await harness();
  try {
    h.front.redirectTo = `http://127.0.0.1:${(target.address() as AddressInfo).port}/`;
    h.front.modes.set("sendTransaction", "redirect");
    await assert.rejects(h.agent.executeTransfer(REQUEST), SubmissionOutcomeUnknown);
    h.front.modes.set("getLatestBlockhash", "redirect");
    await assert.rejects(h.agent.getConnection().getLatestBlockhash());
    assert.equal(targetHits, 0, "the redirect target was contacted");
  } finally {
    await h.close();
    target.closeAllConnections();
    await new Promise<void>((r) => target.close(() => r()));
  }
});

test("F-014: the RPC deadline is read strictly; a malformed one refuses to start", async () => {
  for (const bad of ["abc", "0", "-5", "120001", "1.5"]) {
    const saved = process.env.GRAPHITE_RPC_TIMEOUT_MS;
    process.env.GRAPHITE_RPC_TIMEOUT_MS = bad;
    try {
      await assert.rejects(
        GraphiteGuard.create({
          privateKey: bs58.encode(Keypair.generate().secretKey),
          rpcUrl: "http://127.0.0.1:1",
          graphiteCoreUrl: "http://127.0.0.1:1",
          spendPolicy: { maxTransferLamports: 1n },
        }),
        /GRAPHITE_RPC_TIMEOUT_MS/,
        bad,
      );
    } finally {
      if (saved === undefined) delete process.env.GRAPHITE_RPC_TIMEOUT_MS;
      else process.env.GRAPHITE_RPC_TIMEOUT_MS = saved;
    }
  }
});

// ---------------------------------------------------------------------------
// F-017: the verdict's age.

const payer = Keypair.generate();
const INHERENT: UnobservedCode[] = ["program_semantics", "inner_instructions"];

function verdictFor(bound: BoundTransaction): VerificationResult {
  return {
    approved: true,
    decision: "executable_approved",
    executable: true,
    layers: [],
    confidence: 0.64,
    breakdown: [],
    trust_tier: "OfficialManifest",
    risk_verdict: { status: "Clear", findings: [] },
    policy_verdict: "Approved",
    audit_trail_id: "gr-test",
    content_hash: "48c65c638aceb5de",
    transaction: { instructions: [], signers: [], recent_blockhash: SYSTEM } as unknown as VerificationResult["transaction"],
    resolved_accounts: [],
    protocol_name: "System Program",
    instruction_name: "Transfer",
    manifest_found: true,
    unknown_protocol: false,
    summary: "APPROVED",
    scope: {
      kind: "artifact_bound",
      transaction_sha256: createHash("sha256").update(bound.artifactBytes).digest("hex"),
      transaction_bytes: bound.artifactBytes.length,
      simulated: true,
      unobserved: INHERENT.map((c) => `prose ${c}`),
      unobserved_codes: INHERENT,
    },
  } as unknown as VerificationResult;
}

test("F-017: executeBoundTransaction refuses a verdict older than its bound, immediately before signing", async () => {
  const calls: string[] = [];
  const fakes = {
    sendRawTransaction: async (raw: Uint8Array) => (calls.push("send"), firstSignatureOf(raw)),
    confirmTransaction: async () => (calls.push("confirm"), { value: { err: null } }),
    recordLifecycleEvent: async () => {
      calls.push("record");
      throw new Error("unreachable");
    },
    verifyExecution: async () => {
      calls.push("l8");
      throw new Error("unreachable");
    },
  };
  const build = () =>
    BoundTransaction.build({
      instructions: [SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: new PublicKey(DEST), lamports: 1_000 })],
      feePayer: payer.publicKey,
      recentBlockhash: SYSTEM,
      lastValidBlockHeight: 42,
    });
  const bound = build();
  let clock = 1_000;
  await assert.rejects(
    executeBoundTransaction({
      bound,
      verification: verdictFor(bound),
      signers: [payer],
      connection: fakes,
      graphite: fakes as never,
      policy: new ResidualPolicy([]),
      reportedBy: "test",
      label: "transfer",
      log: () => {},
      // The verdict was asked for at t=1000; the person answered at t=1000+150,001.
      confirm: async () => ((clock += 150_001), true),
      verdictAge: { requestedAt: 1_000, maxMs: 150_000, now: () => clock },
    }),
    (e: unknown) => {
      assert.ok(e instanceof StaleVerdict, String(e));
      assert.match((e as Error).message, /150001 ms old, over the 150000 ms bound.*Nothing was signed or sent/);
      return true;
    },
  );
  assert.deepEqual(calls, [], "nothing recorded, signed or sent");
  assert.equal(bound.artifactBytes.length > 0, true);
  // The same bound, still unsigned (signApproved is one-shot: a refused
  // verdict did not consume it), signs at an age inside the bound.
  const fresh = await bound.signApproved(createHash("sha256").update(bound.artifactBytes).digest("hex"), [payer]);
  assert.ok(fresh.length > 0);
});

test("F-017: the guard does not sign a verdict that aged past GRAPHITE_MAX_VERDICT_AGE_MS while the confirmation was open", async () => {
  const h = await harness({
    spendPolicy: { maxTransferLamports: 2n * BigInt(SOL), maxTotalLamports: 2n * BigInt(SOL) },
    config: { maxVerdictAgeMs: 1_500, confirmTimeoutMs: 10_000 },
  });
  try {
    const slow = { confirm: async () => (await new Promise((r) => setTimeout(r, 2_500)), true) };
    await assert.rejects(h.agent.executeTransfer(REQUEST, slow), (e: unknown) => {
      assert.ok(e instanceof StaleVerdict, String(e));
      // What a framework adapter tells the model: refused, nothing sent.
      assert.equal(toolRefusalOf(e).refusedBy, "stale-verdict");
      return true;
    });
    assert.equal(sent(h), 0, "nothing was sent");
    assert.deepEqual(trail(h), [], "nothing was signed: no signing event on the trail");
    // The refusal returned its reservation: the same allowance takes one transfer.
    const outcome = await h.agent.executeTransfer(REQUEST, { confirm: async () => true });
    assert.equal(outcome.executed, true);
    assert.equal(sent(h), 1);
  } finally {
    await h.close();
  }
  for (const bad of ["0", "600001", "x"]) {
    const saved = process.env.GRAPHITE_MAX_VERDICT_AGE_MS;
    process.env.GRAPHITE_MAX_VERDICT_AGE_MS = bad;
    try {
      await assert.rejects(
        GraphiteGuard.create({
          privateKey: bs58.encode(Keypair.generate().secretKey),
          rpcUrl: "http://127.0.0.1:1",
          graphiteCoreUrl: "http://127.0.0.1:1",
          spendPolicy: { maxTransferLamports: 1n },
        }),
        /GRAPHITE_MAX_VERDICT_AGE_MS/,
        bad,
      );
    } finally {
      if (saved === undefined) delete process.env.GRAPHITE_MAX_VERDICT_AGE_MS;
      else process.env.GRAPHITE_MAX_VERDICT_AGE_MS = saved;
    }
  }
});

// ---------------------------------------------------------------------------
// F-013: spend accounting around submission.

test("F-013: a send whose answer never comes is outcome-unknown at the deadline; its reservation is kept and it is never sent twice", async () => {
  const h = await harness({ spendPolicy: { maxTransferLamports: 2n * BigInt(SOL), maxTotalLamports: 2n * BigInt(SOL) } });
  try {
    // The RPC forwards the transaction (it lands) and never answers.
    h.front.modes.set("sendTransaction", "deliver-hang");
    const r = await within(h.agent.executeTransfer(REQUEST), 5_000, "executeTransfer whose send never answers");
    assert.equal(r.ok, false);
    const error = (r as { error: unknown }).error;
    assert.ok(error instanceof SubmissionOutcomeUnknown, String(error));
    assert.match((error as Error).message, /sendTransaction did not complete within 1000 ms/);
    assert.ok(trail(h).some((e) => e.event_type === "submission" && /ATTEMPT, outcome unknown/.test(e.detail ?? "")));
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(h.rpc.landed.size, 1, "the bytes did reach the network");
    h.front.modes.delete("sendTransaction");
    // The same request: refused, naming what landed, nothing rebuilt.
    await assert.rejects(h.agent.executeTransfer(REQUEST), (e: unknown) => {
      assert.ok(e instanceof PriorSubmissionUnresolved, String(e));
      assert.match((e as Error).message, /LANDED/);
      return true;
    });
    // A different request: the unknown send's 1.5 SOL + fee still counts.
    await assert.rejects(h.agent.executeTransfer(`Transfer 0.5 SOL to ${OTHER}`), (e: unknown) => {
      assert.ok(e instanceof SpendPolicyRefusal, String(e));
      assert.match((e as Error).message, /to 2000010000, above the aggregate limit of 2000000000/);
      return true;
    });
    assert.equal(h.front.counts.get("sendTransaction"), 1, "one send, ever");
    assert.equal(coreAsked(h), 1);
  } finally {
    await h.close();
  }
});

test("F-013 (proof): eight parallel transfers under an allowance for three — exactly three are sent", async () => {
  const each = BigInt(SOL) / 2n + BigInt(FEE);
  const h = await harness({ spendPolicy: { maxTransferLamports: 2n * BigInt(SOL), maxTotalLamports: 3n * each } });
  try {
    const destinations = Array.from({ length: 8 }, () => Keypair.generate().publicKey.toBase58());
    const results = await Promise.allSettled(destinations.map((d) => h.agent.executeTransfer(`Transfer 0.5 SOL to ${d}`)));
    const executed = results.filter((r) => r.status === "fulfilled" && r.value.executed).length;
    const refused = results.filter((r) => r.status === "rejected") as PromiseRejectedResult[];
    assert.equal(executed, 3, "the allowance holds three");
    assert.equal(refused.length, 5);
    for (const r of refused) assert.ok(r.reason instanceof SpendPolicyRefusal, String(r.reason));
    assert.equal(sent(h), 3);
  } finally {
    await h.close();
  }
});

const RENT = 2_039_280;

/**
 * An honest 1 SOL → 150 USDC route for `wallet`: the simulation spends 1 SOL
 * of wrapped SOL, the base fee, and the rent of the output account (the
 * wallet's own USDC associated account, which the envelope may create).
 */
function swapFixture(wallet: Keypair) {
  const w = wallet.publicKey.toBase58();
  const ata = associatedTokenAddress(wallet.publicKey, new PublicKey(USDC), new PublicKey(SPL_TOKEN_PROGRAM)).toBase58();
  return {
    ata,
    state: {
      ledger: {
        [w]: { lamports: 10 * SOL, owner: SYSTEM },
        [DEST]: { lamports: RENT, owner: SPL_TOKEN, data: tokenAccountData(WSOL, w, BigInt(SOL)) },
      },
      afterSimulation: {
        [w]: { lamports: 10 * SOL - FEE - RENT, owner: SYSTEM },
        [DEST]: { lamports: RENT, owner: SPL_TOKEN, data: tokenAccountData(WSOL, w, 0n) },
        [ata]: { lamports: RENT, owner: SPL_TOKEN, data: tokenAccountData(USDC, w, 150_000_000n) },
      },
      decimals: { [USDC]: 6, [WSOL]: 9 },
    },
    payload: {
      programId: JUPITER_V6,
      discriminator: "e517cb977ae3ad2a",
      accounts: [
        { pubkey: w, isSigner: true, isWritable: true },
        { pubkey: DEST, isSigner: false, isWritable: true },
        { pubkey: ata, isSigner: false, isWritable: true },
      ],
      instructionData: jupiterRouteData(),
    },
    parse: (text: string) => ({
      intent_type: "swap",
      raw_natural_language: text,
      confidence_of_parse: 0.99,
      extracted_parameters: { input_token: "SOL", output_token: "USDC", amount: "1" },
    }),
  };
}

test("F-013 (proof): a swap's reservation counts the base fee, the priority fee (price × limit) and the rent it pays", async () => {
  const wallet = Keypair.generate();
  const f = swapFixture(wallet);
  // 300,000 units at 1,000 micro-lamports: 300 lamports of priority fee.
  const expected = BigInt(SOL) + BigInt(FEE) + BigInt(RENT) + 300n;
  const h = await harness({
    wallet,
    rpc: () => f.state,
    spendPolicy: { maxTransferLamports: 2n * BigInt(SOL), maxTotalLamports: expected - 1n },
    parse: f.parse,
    config: { swapEnvelope: { computeUnitLimit: 300_000, computeUnitPriceMicroLamports: 1_000n, createOutputAta: true } },
  });
  try {
    await assert.rejects(h.agent.executeSwap("Swap 1 SOL for USDC", f.payload), (e: unknown) => {
      assert.ok(e instanceof SpendPolicyRefusal, String(e));
      assert.match((e as Error).message, new RegExp(`^\\[Graphite\\] spend policy: ${expected} lamports would bring`));
      return true;
    });
    assert.equal(sent(h), 0);
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// Round 36 (F-003, guard side): the Core binds the request's parameters to
// the bytes, and names what it could not bind `intent_parameters`.

test("F-003: a swap sends the Core its grounded mints — \"SOL\" for the native mint — not the symbols as written", async () => {
  const wallet = Keypair.generate();
  const f = swapFixture(wallet);
  const h = await harness({ wallet, rpc: () => f.state, parse: f.parse });
  try {
    const outcome = await h.agent.executeSwap("Swap 1 SOL for USDC", f.payload);
    assert.equal(outcome.executed, true);
    const body = h.core.calls.find((c) => c.method === "POST /verify")!.params as {
      proposed_intent: { intent_type: string; extracted_parameters: Record<string, unknown> };
    };
    assert.equal(body.proposed_intent.intent_type, "swap");
    // The Core reads a token only as "SOL" or a base58 mint; "USDC" would be unbound.
    assert.deepEqual(body.proposed_intent.extracted_parameters, { amount: "1", input_token: "SOL", output_token: USDC });
  } finally {
    await h.close();
  }
});

test("F-003: an approval the Core could not bind to the request's parameters (intent_parameters) signs nothing by default", async () => {
  const h = await harness({ verdict: { unobservedCodes: [...INHERENT, "intent_parameters"] } });
  try {
    await assert.rejects(h.agent.executeTransfer(REQUEST), (e: unknown) => {
      assert.ok(e instanceof ResidualPolicyRefusal, String(e));
      assert.match((e as Error).message, /intent_parameters/);
      return true;
    });
    assert.equal(sent(h), 0, "nothing was sent");
    assert.deepEqual(trail(h), [], "nothing was signed");
  } finally {
    await h.close();
  }
});
