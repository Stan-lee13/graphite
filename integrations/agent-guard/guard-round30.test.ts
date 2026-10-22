/**
 * Round 30: the signing boundary against the escapes and the repeats.
 *
 *   G-01      the execution decision: only `executable_approved` (or an
 *             operator-accepted `analysis_only`) is signed, and the Core's
 *             decision must agree with its own scope
 *   repeat    a repeat is the same EFFECT, not the same words; a send not
 *             seen confirmed stays unresolved; a request in flight is not
 *             built twice; all of it survives a restart with a state file
 *   consent   a confirmation is bounded in time, exactly `true`, frozen and
 *             about the approved digest
 *   escapes   the connection handed out, the classes on the path, the key,
 *             the config, `fetch` — none of them reaches what is signed
 *   wSOL      a SOL-input swap the guard cannot fund is refused by capability
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inspect } from "node:util";
import { Keypair } from "@solana/web3.js";
import bs58 from "bs58";
import {
  BoundTransaction,
  ConfirmationDeclined,
  GraphiteGuard,
  GuardStateError,
  GUARD_CAPABILITIES,
  PriorSubmissionUnresolved,
  RequestInFlight,
  ResidualPolicyRefusal,
  SpendPolicyRefusal,
  SubmissionOutcomeUnknown,
  UnsupportedCapability,
  swapPolicyFromEnv,
  walletSignerFrom,
  type ConfirmationSummary,
  type GuardConfig,
  type SpendPolicy,
} from "./guard.js";
import { ResidualPolicy } from "./residual-policy.js";
import { SpendLedger } from "./spend-policy.js";
import { RpcSimulator } from "./rpc-simulator.js";
import { GuardState } from "./guard-state.js";
import { executeBoundTransaction } from "./execution-lifecycle.js";
import { toolRefusalOf, toolResultOf } from "./tool-results.js";
import {
  BLOCKED_VERDICT,
  mockApprovingCore,
  mockRpc,
  mockService,
  tokenAccountData,
  type MockRpc,
  type MockService,
} from "./loopback-mocks.js";
import { jupiterRouteData } from "./swap-fixtures.js";

const DEST = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
const OTHER = "p2Yicb86aZig616Eav2VWG9vuXR5mEqhtzshZYBxzsV";
const REQUEST = `Transfer 1.5 SOL to ${DEST}`;
const SWAP = "Swap 1 SOL for USDC";
const SYSTEM = "11111111111111111111111111111111";
const SPL_TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const WSOL = "So11111111111111111111111111111111111111112";
const JUPITER_V6 = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
const OUT_ACCOUNT = "p2Yicb86aZig616Eav2VWG9vuXR5mEqhtzshZYBxzsV";
const SOL = 1_000_000_000;

interface H {
  agent: GraphiteGuard;
  wallet: Keypair;
  rpc: MockRpc;
  core: MockService;
  ai: MockService;
  close(): Promise<void>;
}

function ledgerFor(wallet: Keypair) {
  const w = wallet.publicKey.toBase58();
  return {
    ledger: {
      [w]: { lamports: 10 * SOL, owner: SYSTEM },
      [DEST]: { lamports: 2_039_280, owner: SPL_TOKEN, data: tokenAccountData(WSOL, w, BigInt(SOL)) },
    },
    afterSimulation: {
      [w]: { lamports: 10 * SOL - 5_000 - 2_039_280, owner: SYSTEM },
      [DEST]: { lamports: 2_039_280, owner: SPL_TOKEN, data: tokenAccountData(WSOL, w, 0n) },
      [OUT_ACCOUNT]: { lamports: 2_039_280, owner: SPL_TOKEN, data: tokenAccountData(USDC, w, 150_000_000n) },
    },
    decimals: { [USDC]: 6, [WSOL]: 9 },
  };
}

function transferParse(text: string, destination = DEST, amount = "1.5") {
  return {
    intent_type: "transfer",
    raw_natural_language: text,
    confidence_of_parse: 0.9,
    extracted_parameters: { amount, input_token: "SOL", destination },
  };
}

async function harness(
  o: {
    approve?: boolean;
    verdict?: Parameters<typeof mockApprovingCore>[0];
    wallet?: Keypair;
    spendPolicy?: SpendPolicy;
    rpc?: (w: Keypair) => Parameters<typeof mockRpc>[0];
    parse?: Record<string, unknown>;
    text?: string;
    config?: Partial<GuardConfig>;
  } = {},
): Promise<H> {
  const wallet = o.wallet ?? Keypair.generate();
  const rpc = await mockRpc(o.rpc?.(wallet) ?? ledgerFor(wallet));
  const core =
    o.approve === false
      ? await mockService({ "GET /health": { status: "ok", service: "graphite", version: "test" } })
      : await mockApprovingCore(o.verdict ?? {});
  if (o.approve === false) core.answer.set("POST /verify", { status: 200, body: BLOCKED_VERDICT });
  const ai = await mockService();
  const text = o.text ?? REQUEST;
  ai.answer.set("POST /parse", { status: 200, body: o.parse ?? transferParse(text) });
  let agent: GraphiteGuard;
  try {
    agent = await GraphiteGuard.create({
      privateKey: bs58.encode(wallet.secretKey),
      rpcUrl: rpc.url,
      graphiteCoreUrl: core.url,
      aiLayerUrl: ai.url,
      spendPolicy: o.spendPolicy ?? { maxTransferLamports: 100n * BigInt(SOL) },
      swapPolicy: swapPolicyFromEnv({ GRAPHITE_SWAP_MIN_RATES: "SOL/USDC=100" }),
      swapEnvelope: {},
      ...o.config,
    });
  } catch (e) {
    // A refused start must not leave the stand-ins listening.
    await Promise.all([rpc.close(), core.close(), ai.close()]);
    throw e;
  }
  return {
    agent,
    wallet,
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
const trail = (h: H) =>
  h.core.calls.filter((c) => c.method === "POST /audit/event").map((c) => c.params as { event_type: string; detail?: string });

function assertNothingSigned(h: H): void {
  assert.equal(sends(h), 0, "nothing was sent");
  for (const c of h.rpc.calls) assert.notEqual(c.signed, true, `${c.method} carried a signature`);
  assert.deepEqual(trail(h), [], "no signing on the trail: nothing was signed");
}

function stateDir(): string {
  return mkdtempSync(join(tmpdir(), "graphite-guard-state-"));
}

// ---------------------------------------------------------------------------
// G-01: the execution decision.

test("G-01: an executable_approved verdict executes, and the lifecycle and tool result say so", async () => {
  const h = await harness();
  try {
    const outcome = await h.agent.executeTransfer(REQUEST);
    assert.equal(outcome.executed, true);
    assert.equal(outcome.lifecycle?.decision, "executable_approved");
    assert.equal(outcome.lifecycle?.reportedDecision, "executable_approved");
    assert.equal(toolResultOf(outcome).decision, "executable_approved");
  } finally {
    await h.close();
  }
});

test("G-01: a decision that disagrees with the verdict's own scope, or that the guard does not know, signs nothing", async () => {
  const cases: { name: string; verdict: Parameters<typeof mockApprovingCore>[0]; why: RegExp }[] = [
    { name: "analysis_only over inherent residuals", verdict: { decision: "analysis_only" }, why: /decided "analysis_only", but its own scope makes this verdict "executable_approved"/ },
    { name: "unknown decision", verdict: { decision: "executable" }, why: /not one this guard knows/ },
    { name: "blocked on an approval", verdict: { decision: "blocked" }, why: /its decision is "blocked"/ },
    { name: "inconclusive on an approval", verdict: { decision: "inconclusive" }, why: /its decision is "inconclusive"/ },
    { name: "executable false on executable_approved", verdict: { decision: "executable_approved", executable: false }, why: /`executable` \(false\) contradicts/ },
    { name: "executable not a boolean", verdict: { decision: "executable_approved", executable: "yes" }, why: /`executable` is not a boolean/ },
  ];
  for (const c of cases) {
    const h = await harness({ verdict: c.verdict });
    try {
      // Two layers refuse these: the SDK's response validator (Round 30,
      // WS-A) catches a self-contradicting decision before the guard sees
      // it; the guard's own recomputation is the second layer, unit-tested
      // directly in residual-policy.test.ts. Either way nothing is signed.
      await assert.rejects(h.agent.executeTransfer(REQUEST), (e: unknown) => {
        const message = (e as Error).message;
        if (/structurally invalid verification result/.test(message)) return true;
        assert.ok(e instanceof ResidualPolicyRefusal, `${c.name}: ${String(e)}`);
        assert.match(message, c.why, c.name);
        return true;
      });
      assertNothingSigned(h);
    } finally {
      await h.close();
    }
  }
});

test("G-01: a Core that calls a verdict with a non-inherent residual executable is refused even when the operator accepts that residual", async () => {
  const h = await harness({
    verdict: { unobservedCodes: ["not_simulated", "program_semantics"], decision: "executable_approved" },
    config: { acceptUnobserved: ["not_simulated"] },
  });
  try {
    await assert.rejects(
      h.agent.executeTransfer(REQUEST),
      /decided "executable_approved", but its own scope makes this verdict "analysis_only"|`executable` is true but the verdict's own fields do not permit execution/,
    );
    assertNothingSigned(h);
  } finally {
    await h.close();
  }
});

test("G-01: analysis_only proceeds only under a residual the operator accepted by name", async () => {
  const refused = await harness({ verdict: { unobservedCodes: ["not_simulated", "program_semantics"] } });
  try {
    await assert.rejects(refused.agent.executeTransfer(REQUEST), /not_simulated/);
    assertNothingSigned(refused);
  } finally {
    await refused.close();
  }
  const accepted = await harness({
    verdict: { unobservedCodes: ["not_simulated", "program_semantics"] },
    config: { acceptUnobserved: ["not_simulated"] },
  });
  try {
    const outcome = await accepted.agent.executeTransfer(REQUEST);
    assert.equal(outcome.executed, true);
    assert.equal(outcome.lifecycle?.decision, "analysis_only");
    assert.deepEqual(outcome.lifecycle?.acceptedUnobserved, ["not_simulated"]);
  } finally {
    await accepted.close();
  }
});

test("G-01: a server that predates `decision` is judged by the recomputation alone", async () => {
  const h = await harness({ verdict: { decision: null } });
  try {
    const outcome = await h.agent.executeTransfer(REQUEST);
    assert.equal(outcome.executed, true);
    assert.equal(outcome.lifecycle?.decision, "executable_approved");
    assert.equal(outcome.lifecycle?.reportedDecision, null);
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// Repeats: the same effect, a send not seen confirmed, a request in flight.

test("repeat: an ambiguous send blocks the same transfer however it is worded", async () => {
  const h = await harness({ rpc: (w) => ({ ...ledgerFor(w), sendFails: "lost" }) });
  try {
    await assert.rejects(h.agent.executeTransfer(REQUEST), SubmissionOutcomeUnknown);
    h.rpc.behaviour.sendFails = false;
    const reworded = `please send 1.5 SOL to ${DEST}`;
    h.ai.answer.set("POST /parse", { status: 200, body: transferParse(reworded) });
    await assert.rejects(h.agent.executeTransfer(reworded), (e: unknown) => {
      assert.ok(e instanceof PriorSubmissionUnresolved, String(e));
      assert.match((e as Error).message, /can still land until block height 1000/);
      return true;
    });
    assert.equal(coreAsked(h), 1, "no second transaction was built");
    assert.equal(sends(h), 1);
    // The refusal names the earlier signature for the model too.
    let refusal;
    try {
      await h.agent.executeTransfer(reworded);
    } catch (e) {
      refusal = toolRefusalOf(e);
    }
    assert.equal(refusal?.refusedBy, "submission-unknown");
    assert.match(refusal?.signature ?? "", /^[1-9A-HJ-NP-Za-km-z]{64,88}$/);
    // A different transfer is a different request.
    const other = `Transfer 1.5 SOL to ${OTHER}`;
    h.ai.answer.set("POST /parse", { status: 200, body: transferParse(other, OTHER) });
    assert.equal((await h.agent.executeTransfer(other)).executed, true);
  } finally {
    await h.close();
  }
});

test("repeat: a send that was accepted but not seen confirmed stays unresolved", async () => {
  const h = await harness();
  try {
    // The RPC accepts the bytes but cannot say whether they landed.
    h.rpc.behaviour.acceptWithoutLanding = true;
    h.rpc.behaviour.statusesFail = true;
    const first = await h.agent.executeTransfer(REQUEST);
    assert.equal(first.executed, true);
    assert.equal(first.lifecycle?.confirmed, false);
    // The RPC still cannot answer: a refusal, never a rebuild.
    await assert.rejects(h.agent.executeTransfer(REQUEST));
    h.rpc.behaviour.statusesFail = false;
    await assert.rejects(h.agent.executeTransfer(REQUEST), PriorSubmissionUnresolved);
    assert.equal(sends(h), 1, "one transaction, not two");
    // Expired unlanded: the request may be built again.
    h.rpc.behaviour.blockHeight = 5_000;
    h.rpc.behaviour.acceptWithoutLanding = false;
    assert.equal((await h.agent.executeTransfer(REQUEST)).executed, true);
  } finally {
    await h.close();
  }
});

test("repeat: two concurrent calls for the same transfer build one transaction (a model's double call, a missing await)", async () => {
  const h = await harness();
  try {
    const results = await Promise.allSettled([h.agent.executeTransfer(REQUEST), h.agent.executeTransfer(REQUEST)]);
    const ok = results.filter((r) => r.status === "fulfilled");
    const refused = results.filter((r) => r.status === "rejected") as PromiseRejectedResult[];
    assert.equal(ok.length, 1);
    assert.equal(refused.length, 1);
    assert.ok(refused[0].reason instanceof RequestInFlight, String(refused[0].reason));
    assert.equal(toolRefusalOf(refused[0].reason).refusedBy, "duplicate-request");
    assert.equal(sends(h), 1);
    // Once the first has finished, a repeat is a deliberate second transfer.
    assert.equal((await h.agent.executeTransfer(REQUEST)).executed, true);
    assert.equal(sends(h), 2);
  } finally {
    await h.close();
  }
});

test("repeat: a confirmation hook that calls back in for the same request is refused inside the hook", async () => {
  const h = await harness();
  try {
    let inner: unknown;
    const outcome = await h.agent.executeTransfer(REQUEST, {
      confirm: async () => {
        try {
          await h.agent.executeTransfer(REQUEST);
        } catch (e) {
          inner = e;
        }
        return true;
      },
    });
    assert.ok(inner instanceof RequestInFlight, String(inner));
    assert.equal(outcome.executed, true);
    assert.equal(sends(h), 1);
  } finally {
    await h.close();
  }
});

test("spend: concurrent different transfers cannot both fit under one remaining allowance", async () => {
  const policy: SpendPolicy = { maxTransferLamports: 2n * BigInt(SOL), maxTotalLamports: 2n * BigInt(SOL) };
  const h = await harness({ spendPolicy: policy });
  try {
    const a = REQUEST;
    const b = `Transfer 1.5 SOL to ${OTHER}`;
    // One AI-layer stand-in serves both requests: answer by echoing the text.
    h.ai.answer.delete("POST /parse");
    h.ai.respond.set("POST /parse", (body) => {
      const text = (body as { text: string }).text;
      return { status: 200, body: transferParse(text, text.endsWith(OTHER) ? OTHER : DEST) };
    });
    const results = await Promise.allSettled([h.agent.executeTransfer(a), h.agent.executeTransfer(b)]);
    const refused = results.filter((r) => r.status === "rejected") as PromiseRejectedResult[];
    assert.equal(refused.length, 1, "exactly one fits under 2 SOL");
    assert.ok(refused[0].reason instanceof SpendPolicyRefusal, String(refused[0].reason));
    assert.equal(sends(h), 1);
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// Durable state.

test("state: an unresolved submission survives a restart, and the repeat still waits for it", async () => {
  const dir = stateDir();
  const stateFile = join(dir, "guard.state");
  const wallet = Keypair.generate();
  const first = await harness({ wallet, config: { stateFile }, rpc: (w) => ({ ...ledgerFor(w), sendFails: "lost" }) });
  let signature = "";
  try {
    await assert.rejects(first.agent.executeTransfer(REQUEST), (e: unknown) => {
      signature = (e as SubmissionOutcomeUnknown).signature;
      return e instanceof SubmissionOutcomeUnknown;
    });
  } finally {
    await first.close();
  }
  assert.match(readFileSync(stateFile, "utf8"), new RegExp(signature));
  // A new process, the same key and state file; the RPC never saw it land.
  const second = await harness({ wallet, config: { stateFile } });
  try {
    await assert.rejects(second.agent.executeTransfer(REQUEST), (e: unknown) => {
      assert.ok(e instanceof PriorSubmissionUnresolved, String(e));
      assert.equal((e as PriorSubmissionUnresolved).signature, signature);
      return true;
    });
    assertNothingSigned(second);
  } finally {
    await second.close();
  }
  // In memory, the restart forgot it and built a second transaction — the
  // behaviour the state file exists to end.
  const forgetful = await harness({ wallet });
  try {
    assert.equal((await forgetful.agent.executeTransfer(REQUEST)).executed, true);
  } finally {
    await forgetful.close();
  }
});

test("state: the aggregate spent before a restart still counts after it", async () => {
  const dir = stateDir();
  const stateFile = join(dir, "guard.state");
  const wallet = Keypair.generate();
  const policy: SpendPolicy = { maxTransferLamports: 2n * BigInt(SOL), maxTotalLamports: 2n * BigInt(SOL) };
  const first = await harness({ wallet, spendPolicy: policy, config: { stateFile } });
  try {
    assert.equal((await first.agent.executeTransfer(REQUEST)).executed, true);
  } finally {
    await first.close();
  }
  const next = `Transfer 1 SOL to ${OTHER}`;
  const second = await harness({ wallet, spendPolicy: policy, config: { stateFile }, text: next, parse: transferParse(next, OTHER, "1") });
  try {
    await assert.rejects(second.agent.executeTransfer(next), (e: unknown) => {
      assert.ok(e instanceof SpendPolicyRefusal, String(e));
      assert.match((e as Error).message, /bring this guard's outflow in the last 3600 s to 2500000000/);
      return true;
    });
  } finally {
    await second.close();
  }
});

test("state: one guard process per state file; a stale lock is taken over; an unreadable file refuses to start", async () => {
  const dir = stateDir();
  const stateFile = join(dir, "guard.state");
  const a = GuardState.open(stateFile);
  try {
    assert.throws(() => GuardState.open(stateFile), (e: unknown) => {
      assert.ok(e instanceof GuardStateError);
      assert.match((e as Error).message, /is held by process \d+, which is running/);
      return true;
    });
  } finally {
    a.close();
  }
  assert.equal(existsSync(`${stateFile}.lock`), false, "closing releases the lock");
  // A lock left by a process that is gone.
  writeFileSync(`${stateFile}.lock`, "2147483646");
  GuardState.open(stateFile).close();
  // A line that does not parse may be an unresolved submission: refuse.
  writeFileSync(stateFile, '{"v":1,"t":"unresolved","key":"k","signature":"s","lvbh":5,"at":1}\n{"v":1,"t":"unresol');
  assert.throws(() => GuardState.open(stateFile), /line 2, is not JSON\. REFUSING TO START/);
  writeFileSync(stateFile, '{"v":1,"t":"forget-everything","at":1}\n');
  assert.throws(() => GuardState.open(stateFile), /names a record type .* this guard does not know/);
  assert.equal(existsSync(`${stateFile}.lock`), false, "a refused open releases the lock");
});

test("state: replay keeps unresolved submissions, drops releases and reservations outside the window, and compacts", () => {
  const dir = stateDir();
  const stateFile = join(dir, "guard.state");
  const s = GuardState.open(stateFile);
  const old = s.reserve(5n, 1_000);
  s.reserve(7n, 10_000);
  const released = s.reserve(11n, 10_000);
  s.release(released);
  s.markUnresolved("transfer:x:1", "sig1", 99, 1);
  s.markUnresolved("transfer:y:1", "sig2", 99, 1);
  s.markResolved("transfer:y:1");
  s.close();
  assert.ok(old);
  const r = GuardState.open(stateFile, { retainSince: 5_000 });
  try {
    assert.deepEqual(r.reservedSince(0).map((x) => x.lamports), [7n]);
    assert.equal(r.unresolved("transfer:x:1")?.signature, "sig1");
    assert.equal(r.unresolved("transfer:y:1"), undefined);
    assert.equal(readFileSync(stateFile, "utf8").trim().split("\n").length, 2, "compacted to what is live");
  } finally {
    r.close();
  }
});

// ---------------------------------------------------------------------------
// Consent.

test("consent: a confirmation that never answers is a decline after the timeout; nothing is signed", async () => {
  const h = await harness({ config: { confirmTimeoutMs: 150 } });
  try {
    // Raced against a bound of its own, so a guard that waits forever fails
    // this test instead of hanging the suite.
    const outcome = await Promise.race([
      h.agent.executeTransfer(REQUEST, { confirm: () => new Promise<boolean>(() => {}) }).then(
        () => "executed",
        (e: unknown) => e,
      ),
      new Promise((resolve) => setTimeout(() => resolve("still waiting after 10 s"), 10_000).unref()),
    ]);
    assert.ok(outcome instanceof ConfirmationDeclined, String(outcome));
    assert.match((outcome as Error).message, /no answer within 150 ms/);
    assertNothingSigned(h);
  } finally {
    await h.close();
  }
});

test("consent: only exactly `true` confirms; the summary is frozen and names the approved digest", async () => {
  const h = await harness();
  try {
    for (const answer of ["yes", 1, {}, "true"]) {
      await assert.rejects(
        h.agent.executeTransfer(REQUEST, { confirm: async () => answer as unknown as boolean }),
        /not confirmed \(declined\)/,
      );
    }
    assertNothingSigned(h);
    let seen: ConfirmationSummary | undefined;
    await assert.rejects(
      h.agent.executeTransfer(REQUEST, {
        confirm: async (s) => {
          seen = s;
          // A hook that "edits" what it approves fails loudly.
          (s as { destination?: string }).destination = OTHER;
          return true;
        },
      }),
      /not confirmed \(the confirmation failed: .*read only/,
    );
    assert.ok(seen && Object.isFrozen(seen) && Object.isFrozen(seen.verdict) && Object.isFrozen(seen.walletEffect));
    const sent = h.core.calls.filter((c) => c.method === "POST /verify").at(-1)!.params as { signed_transaction: number[] };
    const digest = createHash("sha256").update(Uint8Array.from(sent.signed_transaction)).digest("hex");
    assert.equal(seen!.transactionSha256, digest, "the summary is about the bytes Graphite approved");
    assert.equal(seen!.destination, DEST);
    // Plain data only: nothing in it reaches the key or the transaction.
    assert.deepEqual(JSON.parse(JSON.stringify(seen)), seen);
    assertNothingSigned(h);
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// Escapes.

test("escape: the connection a caller is handed is not the one the guard decides on", async () => {
  const h = await harness({ rpc: (w) => ({ ...ledgerFor(w), sendFails: "lost" }) });
  try {
    await assert.rejects(h.agent.executeTransfer(REQUEST), SubmissionOutcomeUnknown);
    // A caller rewrites "did it land?" on the object it was handed...
    const handed = h.agent.getConnection() as unknown as Record<string, unknown>;
    let called = 0;
    handed.getSignatureStatuses = async () => ((called += 1), { context: { slot: 1 }, value: [{ err: { failed: true } }] });
    handed.getBlockHeight = async () => ((called += 1), 1_000_000);
    handed.sendRawTransaction = async () => ((called += 1), "1".repeat(64));
    h.rpc.behaviour.sendFails = false;
    // ...and the guard still asks the RPC, which says the first may still land.
    await assert.rejects(h.agent.executeTransfer(REQUEST), PriorSubmissionUnresolved);
    assert.equal(called, 0, "the guard never used the handed-out connection");
  } finally {
    await h.close();
  }
});

test("escape: the classes on the signing path cannot be rewritten at runtime", () => {
  const attempts: [string, () => void][] = [
    ["BoundTransaction.signApproved", () => ((BoundTransaction.prototype as unknown as Record<string, unknown>).signApproved = () => undefined)],
    ["BoundTransaction.assertApproved", () => ((BoundTransaction.prototype as unknown as Record<string, unknown>).assertApproved = () => undefined)],
    ["BoundTransaction.build", () => ((BoundTransaction as unknown as Record<string, unknown>).build = () => undefined)],
    ["ResidualPolicy.assertExecutableVerdict", () => ((ResidualPolicy.prototype as unknown as Record<string, unknown>).assertExecutableVerdict = () => undefined)],
    ["ResidualPolicy.assertExecutable", () => ((ResidualPolicy.prototype as unknown as Record<string, unknown>).assertExecutable = () => undefined)],
    ["SpendLedger.reserve", () => ((SpendLedger.prototype as unknown as Record<string, unknown>).reserve = () => undefined)],
    ["RpcSimulator.measureWalletEffect", () => ((RpcSimulator.prototype as unknown as Record<string, unknown>).measureWalletEffect = () => undefined)],
    ["GuardState.markUnresolved", () => ((GuardState.prototype as unknown as Record<string, unknown>).markUnresolved = () => undefined)],
    ["GraphiteGuard.executeTransfer", () => ((GraphiteGuard.prototype as unknown as Record<string, unknown>).executeTransfer = () => undefined)],
    ["defineProperty on the prototype", () => Object.defineProperty(BoundTransaction.prototype, "signApproved", { value: () => undefined })],
  ];
  for (const [name, attempt] of attempts) assert.throws(attempt, TypeError, name);
  // A policy's accepted set is not reachable, and the instance is frozen.
  const policy = new ResidualPolicy();
  assert.equal((policy as unknown as Record<string, unknown>).acceptedCodes, undefined);
  assert.throws(() => ((policy as unknown as Record<string, unknown>).acceptedCodes = new Set(["not_simulated"])), TypeError);
  assert.throws(() => policy.assertExecutable({ kind: "artifact_bound", transaction_sha256: "0".repeat(64), transaction_bytes: 1, simulated: false, unobserved: ["x"], unobserved_codes: ["not_simulated"] }, "t"), ResidualPolicyRefusal);
});

test("escape: a bound transaction's fields cannot be rewritten", () => {
  const payer = Keypair.generate();
  const bound = BoundTransaction.build({
    instructions: [],
    feePayer: payer.publicKey,
    recentBlockhash: bs58.encode(new Uint8Array(32).fill(7)),
    lastValidBlockHeight: 1_000,
  });
  assert.throws(() => ((bound as unknown as Record<string, unknown>).lastValidBlockHeight = 10 ** 12), TypeError);
  assert.throws(() => ((bound as unknown as Record<string, unknown>).version = 1), TypeError);
  assert.equal(bound.lastValidBlockHeight, 1_000);
});

test("escape: the guard's wallet key is non-extractable, and nothing on the guard shows it", async () => {
  const wallet = Keypair.generate();
  const secret = bs58.encode(wallet.secretKey);
  const signer = await walletSignerFrom(secret);
  assert.equal(signer.publicKey.toBase58(), wallet.publicKey.toBase58());
  assert.equal(signer.keyPair.privateKey.extractable, false);
  await assert.rejects(crypto.subtle.exportKey("pkcs8", signer.keyPair.privateKey));
  await assert.rejects(walletSignerFrom(bs58.encode(new Uint8Array(32))), /not the 64 of a Solana secret key/);
  // Halves that do not belong together.
  const mismatched = Uint8Array.from(wallet.secretKey);
  mismatched.set(Keypair.generate().publicKey.toBytes(), 32);
  await assert.rejects(walletSignerFrom(bs58.encode(mismatched)), /not usable/);
  // The guard object, walked with everything shown, carries neither the
  // base58 key nor its bytes.
  const h = await harness({ wallet });
  try {
    const shown = inspect(h.agent, { showHidden: true, depth: 20, getters: true });
    assert.equal(shown.includes(secret), false);
    assert.equal(shown.includes(Buffer.from(wallet.secretKey.subarray(0, 32)).toString("hex")), false);
    assert.deepEqual(Object.getOwnPropertyNames(h.agent), []);
    assert.deepEqual(Object.getOwnPropertySymbols(h.agent), []);
  } finally {
    await h.close();
  }
});

test("escape: a config key the guard does not have is refused, not ignored", async () => {
  for (const key of ["connection", "wallet", "signer", "graphite", "spendpolicy"]) {
    let started: H | undefined;
    await assert.rejects(
      (async () => {
        started = await harness({ config: { [key]: {} } as unknown as Partial<GuardConfig> });
      })(),
      new RegExp(`unknown key\\(s\\) "${key}"`),
    ).finally(() => started?.close());
  }
});

test("escape: replacing globalThis.fetch after the guard loaded does not answer its Core, RPC or AI-layer calls", async () => {
  const h = await harness();
  const original = globalThis.fetch;
  const intercepted: string[] = [];
  // A later module answers every request: the guard's RPC and AI-layer calls
  // and — since the SDK client also captures fetch at load (Round 30
  // integration) — the Core's /verify.
  globalThis.fetch = (async (input: string | URL | Request) => {
    const url = String(input instanceof Request ? input.url : input);
    intercepted.push(url);
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: null }), { status: 200 });
  }) as typeof globalThis.fetch;
  try {
    const outcome = await h.agent.executeTransfer(REQUEST);
    assert.equal(outcome.executed, true);
    assert.deepEqual(intercepted, [], "no Core, RPC or AI-layer request went through the replaced fetch");
    assert.ok(h.rpc.calls.some((c) => c.method === "sendTransaction"), "the guard's RPC calls reached the RPC");
    assert.ok(h.ai.calls.length >= 1, "the AI layer was asked directly");
  } finally {
    globalThis.fetch = original;
    await h.close();
  }
});

test("escape: executeBoundTransaction signs nothing for a verdict the policy refuses", async () => {
  let signs = 0;
  const bound = {
    signApproved: async () => ((signs += 1), new Uint8Array()),
    lastValidBlockHeight: 1,
    recentBlockhash: "x",
  } as unknown as BoundTransaction;
  const graphite = {
    recordLifecycleEvent: async () => assert.fail("nothing to record"),
    verifyExecution: async () => assert.fail("nothing to reconcile"),
  };
  const connection = {
    sendRawTransaction: async () => assert.fail("nothing to send"),
    confirmTransaction: async () => assert.fail("nothing to confirm"),
  };
  const base = { ...BLOCKED_VERDICT, approved: true, risk_verdict: { status: "Clear", findings: [] }, policy_verdict: "Approved" };
  const scope = {
    kind: "artifact_bound",
    transaction_sha256: "0".repeat(64),
    transaction_bytes: 1,
    simulated: true,
    unobserved: ["a", "b"],
    unobserved_codes: ["program_semantics", "inner_instructions"],
  };
  const verdicts = [
    { ...base, scope: { kind: "descriptive", unobserved: [], unobserved_codes: [] } },
    { ...base, scope, decision: "analysis_only" },
    { ...base, scope, decision: "made_up" },
    { ...base, scope: { ...scope, unobserved: ["a"], unobserved_codes: ["not_simulated"] } },
  ];
  for (const verification of verdicts) {
    await assert.rejects(
      executeBoundTransaction({
        bound,
        verification: verification as never,
        signers: [Keypair.generate()],
        connection: connection as never,
        graphite: graphite as never,
        policy: new ResidualPolicy(),
        reportedBy: "test",
        label: "escape",
        log: () => {},
      }),
      ResidualPolicyRefusal,
    );
  }
  assert.equal(signs, 0);
});

test("anomaly: an RPC that answers a submission with another id is recorded on the trail and reported", async () => {
  const h = await harness();
  try {
    h.rpc.behaviour.reportedSignature = "1".repeat(64);
    const outcome = await h.agent.executeTransfer(REQUEST);
    assert.equal(outcome.lifecycle?.rpcReportedSignature, "1".repeat(64));
    const submission = trail(h).find((e) => e.event_type === "submission")!;
    assert.match(submission.detail ?? "", /RPC ANOMALY: sendTransaction answered 1{64}; the signed bytes carry /);
    assert.match(toolResultOf(outcome).anomalies?.join(" ") ?? "", /the RPC answered the submission with 1{64}/);
    assert.notEqual(outcome.signature, "1".repeat(64), "the id is the signed bytes' own");
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// Capabilities.

test("wSOL: a SOL-input swap whose simulation fails is refused as a missing capability, by code", async () => {
  const h = await harness({
    text: SWAP,
    parse: {
      intent_type: "swap",
      raw_natural_language: SWAP,
      confidence_of_parse: 0.99,
      extracted_parameters: { input_token: "SOL", output_token: "USDC", amount: "1" },
    },
    rpc: (w) => ({ ...ledgerFor(w), simulationErr: { InstructionError: [0, { Custom: 1 }] } }),
  });
  try {
    const payload = {
      programId: JUPITER_V6,
      discriminator: "e517cb977ae3ad2a",
      accounts: [
        { pubkey: h.wallet.publicKey.toBase58(), isSigner: true, isWritable: true },
        { pubkey: DEST, isSigner: false, isWritable: true },
        { pubkey: OUT_ACCOUNT, isSigner: false, isWritable: true },
      ],
      instructionData: jupiterRouteData(),
    };
    await assert.rejects(h.agent.executeSwap(SWAP, payload), (e: unknown) => {
      assert.ok(e instanceof UnsupportedCapability, String(e));
      assert.equal((e as UnsupportedCapability).code, "wrap_sol");
      assert.match((e as Error).message, /does not wrap SOL/);
      const r = toolRefusalOf(e);
      assert.equal(r.refusedBy, "unsupported");
      assert.equal(r.unsupported, "wrap_sol");
      return true;
    });
    assert.equal(coreAsked(h), 0);
    assertNothingSigned(h);
  } finally {
    await h.close();
  }
});

test("capabilities: what the guard does not build is stated as data", async () => {
  assert.equal(GUARD_CAPABILITIES.operations.wrapSol, false);
  assert.equal(GUARD_CAPABILITIES.operations.unwrapSol, false);
  assert.equal(GUARD_CAPABILITIES.operations.durableNonce, false);
  assert.equal(GUARD_CAPABILITIES.operations.swapExactOut, false);
  assert.equal(GUARD_CAPABILITIES.operations.tokenTransfer, false);
  assert.ok(Object.isFrozen(GUARD_CAPABILITIES) && Object.isFrozen(GUARD_CAPABILITIES.operations));
  assert.ok(GUARD_CAPABILITIES.swapPrograms.includes(JUPITER_V6));
  const h = await harness();
  try {
    assert.equal(h.agent.capabilities, GUARD_CAPABILITIES);
  } finally {
    await h.close();
  }
});
