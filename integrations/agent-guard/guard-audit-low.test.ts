/**
 * The low-severity findings of the November 2026 audit (A046..A058, A085)
 * against the guard, end to end against loopback stand-ins where the finding
 * is about the guard's behaviour. Nothing here reaches a public RPC.
 *
 *   A046/A052  the aggregate's refund loop settled a stale snapshot after an
 *              await, and deleted a newer unresolved submission of the same
 *              request
 *   A047       a confirmed transaction was reported as a GuardStateError when
 *              its "resolved" line could not be written
 *   A048       the handed-out connection shared a mutable prototype with the
 *              guard's own
 *   A049/A055  a GuardConfig policy was neither type-checked nor copied
 *   A050/A054  a relative lock directory or state file resolved against the
 *              working directory
 *   A051       the state file's location check followed a symlinked directory
 *              and looked at no ancestor
 *   A053       a misspelt GRAPHITE_* name was silently absent
 *   A057       a confirmation that failed was reported as a person's refusal
 *   A058       the confirmation summary had no execution decision
 *   A085       the grounding regexes backtracked quadratically on long text
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, symlinkSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Connection, Keypair } from "@solana/web3.js";
import bs58 from "bs58";
import {
  GraphiteGuard,
  GuardStateError,
  PriorSubmissionUnresolved,
  SpendPolicyRefusal,
  SubmissionOutcomeUnknown,
  swapPolicyFromEnv,
  type ConfirmationSummary,
  type ExecuteOptions,
  type GuardConfig,
  type SpendPolicy,
} from "./guard.js";
import { GuardState, WalletLock } from "./guard-state.js";
import { ConfirmationDeclined } from "./execution-lifecycle.js";
import { toolRefusalOf } from "./tool-results.js";
import { posixOnly } from "./posix-only.js";
import * as envNames from "./env-names.js";
import { groundSwapRequest, groundTransferIntent, IntentGroundingError } from "./intent-grounding.js";
import { mockApprovingCore, mockRpc, mockService, wireTransactionId, type MockRpc, type MockService } from "./loopback-mocks.js";
import { GraphiteClient } from "../../sdk/typescript/src/client.js";

const DEST = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
const OTHER = "p2Yicb86aZig616Eav2VWG9vuXR5mEqhtzshZYBxzsV";
const REQUEST = `Transfer 1.5 SOL to ${DEST}`;
const SYSTEM = "11111111111111111111111111111111";
const SOL = 1_000_000_000;
const FEE = 5_000;

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
  core: MockService;
  close(): Promise<void>;
}

async function harness(
  o: {
    spendPolicy?: SpendPolicy;
    config?: Partial<GuardConfig>;
    rpc?: (w: Keypair) => Parameters<typeof mockRpc>[0];
    verdict?: Parameters<typeof mockApprovingCore>[0];
  } = {},
): Promise<H> {
  const wallet = Keypair.generate();
  const w = wallet.publicKey.toBase58();
  const rpc = await mockRpc(
    o.rpc?.(wallet) ?? {
      ledger: { [w]: { lamports: 100 * SOL, owner: SYSTEM } },
      afterSimulation: { [w]: { lamports: 100 * SOL - FEE, owner: SYSTEM } },
    },
  );
  const core = await mockApprovingCore(o.verdict ?? {});
  const ai = await mockService();
  ai.respond.set("POST /parse", (body) => ({ status: 200, body: transferParse((body as { text: string }).text) }));
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
      rpcTimeoutMs: 10_000,
      ...o.config,
    });
  } catch (e) {
    await Promise.all([rpc.close(), core.close(), ai.close()]);
    throw e;
  }
  return {
    agent,
    wallet,
    rpc,
    core,
    close: async () => {
      agent.close();
      await Promise.all([rpc.close(), core.close(), ai.close()]);
    },
  };
}

const sent = (h: H) => h.rpc.calls.filter((c) => c.method === "sendTransaction");
const privateTmp = () => mkdtempSync(join(tmpdir(), "graphite-audit-low-"));

/** Run `fn` with these variables set (undefined: unset), and put them back. */
async function withEnv<T>(vars: Record<string, string | undefined>, fn: () => T | Promise<T>): Promise<T> {
  const saved: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(vars)) {
    saved[k] = process.env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    return await fn();
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

/**
 * A JSON-RPC front that forwards to `upstream`, can answer getLatestBlockhash
 * itself (so two builds of one request get different blockhashes, as on a
 * real cluster), and can hold the n-th getSignatureStatuses after `arm`.
 */
async function gatedFront() {
  const gate = {
    upstream: "",
    blockhash: undefined as undefined | { blockhash: string; lastValidBlockHeight: number },
    holdNth: 0,
    seen: 0,
    release: () => {},
    reached: Promise.resolve(),
    arm(n: number) {
      this.holdNth = n;
      this.seen = 0;
      let reached!: () => void;
      this.reached = new Promise<void>((r) => (reached = r));
      const held = new Promise<void>((r) => (this.release = r));
      this.wait = async () => {
        reached();
        await held;
      };
    },
    wait: async () => {},
  };
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", async () => {
      const text = Buffer.concat(chunks).toString("utf8");
      const body = JSON.parse(text) as { id?: unknown; method?: string };
      if (body.method === "getLatestBlockhash" && gate.blockhash) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: body.id ?? null, result: { context: { slot: 1 }, value: gate.blockhash } }));
        return;
      }
      if (body.method === "getSignatureStatuses" && gate.holdNth > 0) {
        gate.seen += 1;
        if (gate.seen === gate.holdNth) {
          gate.holdNth = 0;
          await gate.wait();
        }
      }
      const r = await fetch(gate.upstream, { method: "POST", headers: { "content-type": "application/json" }, body: text });
      res.writeHead(r.status, { "content-type": "application/json" });
      res.end(await r.text());
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return { gate, url, close: () => new Promise<void>((resolve) => server.close(() => resolve())) };
}

// ---------------------------------------------------------------------------
// A046 / A052

test("A046/A052 (repro): the refund loop does not settle a newer submission of the same request recorded while it awaited the RPC", async () => {
  const front = await gatedFront();
  // A per-transfer cap that admits 9 SOL, and an aggregate the 9 SOL call
  // overflows while the first 1.5 SOL submission is counted.
  const h = await harness({
    spendPolicy: { maxTransferLamports: 100n * BigInt(SOL), maxTotalLamports: 10n * BigInt(SOL) },
    config: { rpcUrl: front.url },
    rpc: (w) => ({
      ledger: { [w.publicKey.toBase58()]: { lamports: 100 * SOL, owner: SYSTEM } },
      afterSimulation: { [w.publicKey.toBase58()]: { lamports: 100 * SOL - FEE, owner: SYSTEM } },
      sendFails: "lost",
    }),
  });
  front.gate.upstream = h.rpc.url;
  try {
    // S1: outcome unknown, valid to block height 1,000.
    await assert.rejects(h.agent.executeTransfer(REQUEST), SubmissionOutcomeUnknown);
    // The chain moves past S1's window; later builds get a new blockhash, valid to 2,000.
    h.rpc.behaviour.blockHeight = 1_500;
    front.gate.blockhash = { blockhash: bs58.encode(randomBytes(32)), lastValidBlockHeight: 2_000 };
    // B (another request) overflows the aggregate and asks about S1; its
    // second status question (after the height) is held.
    front.gate.arm(2);
    const b = h.agent.executeTransfer(`Transfer 9 SOL to ${OTHER}`).then(
      () => "executed",
      (e: unknown) => e,
    );
    await front.gate.reached;
    // Meanwhile the same request again: S1 is settled, S2 is signed and its send fails ambiguously.
    await assert.rejects(h.agent.executeTransfer(REQUEST), SubmissionOutcomeUnknown);
    assert.equal(sent(h).length, 2);
    // B's answer about S1 arrives: S1 cannot land.
    front.gate.release();
    assert.ok((await b) instanceof SpendPolicyRefusal, String(await b));
    // S2 can still land (block height 1,500 <= 2,000): a third build is refused.
    h.rpc.behaviour.sendFails = false;
    await assert.rejects(h.agent.executeTransfer(REQUEST), PriorSubmissionUnresolved);
    assert.equal(sent(h).length, 2, "no third transaction was sent");
  } finally {
    await h.close();
    await front.close();
  }
});

test("A046/A052: GuardState settles a submission only when it is still the one asked about", () => {
  const dir = privateTmp();
  const s = GuardState.open(join(dir, "guard.state"));
  try {
    s.markUnresolved("transfer:x:1", "S2", 2_000);
    s.markResolved("transfer:x:1", "S1");
    assert.equal(s.unresolved("transfer:x:1")?.signature, "S2", "a settlement of S1 does not remove S2");
    s.markResolved("transfer:x:1", "S2");
    assert.equal(s.unresolved("transfer:x:1"), undefined);
  } finally {
    s.close();
  }
  // And the file agrees once replayed.
  const again = GuardState.open(join(dir, "guard.state"));
  try {
    assert.equal(again.unresolvedEntries().length, 0);
  } finally {
    again.close();
  }
});

// ---------------------------------------------------------------------------
// A047

test("A047 (repro): a transfer that confirms after the guard was closed is still reported as executed, with its signature", async () => {
  const dir = privateTmp();
  const h = await harness({ config: { stateFile: join(dir, "guard.state"), walletLockDir: dir } });
  try {
    // The RPC takes the bytes, and does not report them confirmed yet.
    h.rpc.behaviour.acceptWithoutLanding = true;
    const run = h.agent.executeTransfer(REQUEST).then(
      (o) => o,
      (e: unknown) => e,
    );
    while (sent(h).length === 0) await new Promise((r) => setTimeout(r, 10));
    // A graceful shutdown while the confirmation is polled; then it lands.
    h.agent.close();
    const wire = (sent(h)[0].params as { params: string[] }).params[0];
    h.rpc.landed.add(wireTransactionId(wire));
    const outcome = await run;
    assert.ok(!(outcome instanceof Error), `a confirmed transaction was reported as ${String(outcome)}`);
    const o = outcome as Awaited<ReturnType<GraphiteGuard["executeTransfer"]>>;
    assert.equal(o.executed, true);
    assert.equal(o.signature, wireTransactionId(wire));
    assert.equal(o.lifecycle?.confirmed, true);
    assert.match(o.lifecycle?.stateRecordError ?? "", /closed/);
  } finally {
    await h.close();
  }
});

test("A047: a 'resolved' line that cannot be written leaves the record held", () => {
  const dir = privateTmp();
  const s = GuardState.open(join(dir, "guard.state"));
  s.markUnresolved("transfer:x:1", "S1", 2_000);
  s.close();
  assert.throws(() => s.markResolved("transfer:x:1", "S1"), GuardStateError);
  assert.equal(s.unresolved("transfer:x:1")?.signature, "S1", "still held: a repeat asks the RPC first");
});

// ---------------------------------------------------------------------------
// A048

test("A048 (repro): replacing a method on the handed-out connection's prototypes does not reach the guard's connection or Core client", async () => {
  const h = await harness();
  const handed = Object.getPrototypeOf(h.agent.getConnection()) as Record<string, unknown>;
  const base = Connection.prototype as unknown as Record<string, unknown>;
  const client = GraphiteClient.prototype as unknown as Record<string, unknown>;
  const saved: [Record<string, unknown>, string, PropertyDescriptor | undefined][] = [];
  let called = 0;
  const replace = (o: Record<string, unknown>, name: string, f: unknown) => {
    saved.push([o, name, Object.getOwnPropertyDescriptor(o, name)]);
    o[name] = f;
  };
  const neverSent = async () => {
    called += 1;
    throw Object.assign(new Error("x"), { code: "ECONNREFUSED" });
  };
  try {
    replace(handed, "sendRawTransaction", neverSent);
    replace(base, "sendRawTransaction", neverSent);
    replace(base, "getSignatureStatuses", async () => ((called += 1), { context: { slot: 1 }, value: [null] }));
    replace(client, "recordLifecycleEvent", async () => ((called += 1), {}));
    const outcome = await h.agent.executeTransfer(REQUEST);
    assert.equal(outcome.executed, true);
    assert.equal(outcome.lifecycle?.confirmed, true);
    assert.equal(called, 0, "the guard used none of the replaced methods");
    assert.equal(sent(h).length, 1);
  } finally {
    for (const [o, name, d] of saved.reverse()) {
      if (d) Object.defineProperty(o, name, d);
      else delete o[name];
    }
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// A049 / A055

const startOnly = (extra: Partial<GuardConfig>): Promise<GraphiteGuard> =>
  GraphiteGuard.create({
    privateKey: bs58.encode(Keypair.generate().secretKey),
    rpcUrl: "http://127.0.0.1:1",
    graphiteCoreUrl: "http://127.0.0.1:1",
    aiLayerUrl: "http://127.0.0.1:1",
    spendPolicy: { maxTransferLamports: 1n },
    swapPolicy: swapPolicyFromEnv({}),
    swapEnvelope: {},
    ...extra,
  });

test("A049/A055 (repro): a policy value of the wrong type refuses to start, never silently disables a bound", async () => {
  const bad: [string, Partial<GuardConfig>][] = [
    ["NaN cap", { spendPolicy: { maxTransferLamports: Number.NaN as unknown as bigint } }],
    ["string cap", { spendPolicy: { maxTransferLamports: "1e8" as unknown as bigint } }],
    ["number cap", { spendPolicy: { maxTransferLamports: 100_000_000 as unknown as bigint } }],
    ["negative cap", { spendPolicy: { maxTransferLamports: -1n } }],
    ["NaN aggregate", { spendPolicy: { maxTransferLamports: 1n, maxTotalLamports: Number.NaN as unknown as bigint } }],
    ["string allowUncapped", { spendPolicy: { allowUncapped: "true" as unknown as boolean } }],
    ["string destinations", { spendPolicy: { maxTransferLamports: 1n, allowedDestinations: DEST as unknown as string[] } }],
    ["non-address destination", { spendPolicy: { maxTransferLamports: 1n, allowedDestinations: ["treasury"] } }],
    ["string allowUnpriced", { swapPolicy: { ...swapPolicyFromEnv({}), allowUnpriced: "false" as unknown as boolean } }],
    ["minRates not a list", { swapPolicy: { ...swapPolicyFromEnv({}), minRates: "SOL/USDC=100" as unknown as [] } }],
    ["string createOutputAta", { swapEnvelope: { createOutputAta: "false" as unknown as boolean } }],
    ["number unit price", { swapEnvelope: { computeUnitPriceMicroLamports: 5 as unknown as bigint } }],
    ["string allowSharedWallet", { allowSharedWallet: "false" as unknown as boolean }],
  ];
  for (const [name, config] of bad) {
    await assert.rejects(startOnly(config), /REFUSING TO START/, name);
  }
});

test("A049 (repro): the caller's policy object is copied at startup; changing it afterwards changes nothing", async () => {
  const policy: { maxTransferLamports: bigint; allowedDestinations: string[] } = {
    maxTransferLamports: 2n * BigInt(SOL),
    allowedDestinations: [DEST],
  };
  const h = await harness({ spendPolicy: policy });
  try {
    policy.maxTransferLamports = 10n ** 18n;
    policy.allowedDestinations.push(OTHER);
    await assert.rejects(h.agent.executeTransfer(`Transfer 5 SOL to ${DEST}`), SpendPolicyRefusal);
    await assert.rejects(h.agent.executeTransfer(`Transfer 1 SOL to ${OTHER}`), SpendPolicyRefusal);
    assert.equal(h.agent.limits.maxTransferLamports, 2n * BigInt(SOL));
    assert.equal(sent(h).length, 0);
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// A050 / A054

test("A050/A054 (repro): a relative lock directory or state file refuses to start", async () => {
  const cwd = process.cwd();
  const dir = privateTmp();
  process.chdir(dir);
  try {
    const wallet = Keypair.generate().publicKey.toBase58();
    assert.throws(() => WalletLock.take(wallet, "locks"), /not an absolute path.*REFUSING TO START/s);
    assert.equal(existsSync(join(dir, "locks")), false, "nothing was created relative to the working directory");
    assert.throws(() => GuardState.open("guard.state"), /not an absolute path.*REFUSING TO START/s);
    assert.equal(existsSync(join(dir, "guard.state.lock")), false);
    await withEnv({ GRAPHITE_GUARD_LOCK_DIR: "state/locks" }, () =>
      assert.rejects(startOnly({}), /GRAPHITE_GUARD_LOCK_DIR|not an absolute path/),
    );
    await assert.rejects(startOnly({ walletLockDir: "state/locks" }), /not an absolute path/);
  } finally {
    process.chdir(cwd);
  }
});

// ---------------------------------------------------------------------------
// A051

test("A051 (repro): a state file under a directory others can write, or behind a symlink placed there, refuses to start", { skip: posixOnly("directory modes and the sticky bit") }, () => {
  const base = privateTmp();
  const shared = join(base, "shared");
  mkdirSync(shared, { mode: 0o700 });
  const victim = join(shared, "graphite");
  mkdirSync(victim, { mode: 0o700 });
  chmodSync(shared, 0o775);
  // The state directory itself is private; its parent is group-writable and not sticky.
  assert.throws(() => GuardState.open(join(victim, "guard.state")), /writable by others.*REFUSING TO START/s);
  // A symbolic link in its place, to a private directory with no state file.
  const elsewhere = join(base, "elsewhere");
  mkdirSync(elsewhere, { mode: 0o700 });
  const link = join(shared, "link");
  symlinkSync(elsewhere, link);
  assert.throws(() => GuardState.open(join(link, "guard.state")), /REFUSING TO START/);
  // A sticky shared parent (like /tmp) lets no one else rename what is in it.
  chmodSync(shared, 0o1777);
  const s = GuardState.open(join(victim, "guard.state"));
  s.close();
});

// ---------------------------------------------------------------------------
// A053

test("A053 (repro): a near-miss of a name the guard reads refuses to start, naming the name it meant", async () => {
  const assertNoMisspeltGuardEnvNames = (envNames as unknown as Record<string, unknown>).assertNoMisspeltGuardEnvNames as
    | ((env: Record<string, string | undefined>) => void)
    | undefined;
  assert.equal(typeof assertNoMisspeltGuardEnvNames, "function");
  // The misspellings are built from a prefix: graphite-core/tests/
  // round36_env_names.rs reads every GRAPHITE_* word in a component's
  // sources as a name it reads, and these are deliberately no one's.
  const G = "GRAPHITE_";
  for (const [name, meant] of [
    [`${G}ALLOWED_DESTINATION`, "GRAPHITE_ALLOWED_DESTINATIONS"],
    [`${G}MAX_TOTAL_LAMPORT`, "GRAPHITE_MAX_TOTAL_LAMPORTS"],
    [`${G}GUARD_STATE_FIL`, "GRAPHITE_GUARD_STATE_FILE"],
    ["graphite_max_transfer_lamports", "GRAPHITE_MAX_TRANSFER_LAMPORTS"],
    ["GRAPHTIE_MAX_TRANSFER_LAMPORTS", "GRAPHITE_MAX_TRANSFER_LAMPORTS"],
  ]) {
    assert.throws(() => assertNoMisspeltGuardEnvNames!({ [name]: "1" }), new RegExp(`${name}.*${meant}.*REFUSING TO START`, "s"));
  }
  // Exact names, and names other components read, are not refused.
  assertNoMisspeltGuardEnvNames!({
    GRAPHITE_ALLOWED_DESTINATIONS: DEST,
    GRAPHITE_MCP_CONFIRMATION: "elicit",
    GRAPHITE_AI_LAYER_HOST: "127.0.0.1",
    GRAPHITE_API_KEY: "k",
    GRAPHITE_SWAP_STRICT: "1",
  });
  // And GraphiteGuard.create runs it before anything else is read.
  await withEnv({ [`${G}ALLOWED_DESTINATION`]: DEST }, () =>
    assert.rejects(startOnly({}), new RegExp(`${G}ALLOWED_DESTINATION .*GRAPHITE_ALLOWED_DESTINATIONS`)),
  );
});

test("A053: the guard's list is the names its sources read, and no name another Graphite component reads is a near-miss of one", () => {
  const { GUARD_ENV_NAMES, assertNoMisspeltGuardEnvNames } = envNames as unknown as {
    GUARD_ENV_NAMES: readonly string[];
    assertNoMisspeltGuardEnvNames: (env: Record<string, string | undefined>) => void;
  };
  const here = new URL(".", import.meta.url);
  const read = new Set<string>();
  for (const f of readdirSync(here)) {
    if (!f.endsWith(".ts") || f.endsWith(".test.ts")) continue;
    const src = readFileSync(new URL(f, here), "utf8");
    for (const m of src.matchAll(/(?:process\.env|env)(?:\.(GRAPHITE_[A-Z0-9_]+)|\["(GRAPHITE_[A-Z0-9_]+)"\])|_ENV = "(GRAPHITE_[A-Z0-9_]+)"/g)) {
      read.add(m[1] ?? m[2] ?? m[3]);
    }
  }
  assert.deepEqual([...GUARD_ENV_NAMES].sort(), [...read].sort());
  // Every name the Core and the other components read (graphite-core/src/operator_boundary.rs).
  const boundary = readFileSync(new URL("../../graphite-core/src/operator_boundary.rs", import.meta.url), "utf8");
  const others = [...boundary.matchAll(/"(GRAPHITE_[A-Z0-9_]+)"/g)].map((m) => m[1]);
  assert.ok(others.length > 50, "the Core's lists were read");
  assertNoMisspeltGuardEnvNames(Object.fromEntries(others.map((n) => [n, "1"])));
});

// ---------------------------------------------------------------------------
// A058

test("A058 (repro): the confirmation summary carries the execution decision, analysis_only under an accepted residual", async () => {
  for (const [o, expected] of [
    [{}, "executable_approved"],
    [{ verdict: { unobservedCodes: ["not_simulated", "program_semantics"] }, config: { acceptUnobserved: ["not_simulated"] } }, "analysis_only"],
  ] as const) {
    const h = await harness(o as Parameters<typeof harness>[0]);
    try {
      let seen: ConfirmationSummary | undefined;
      const outcome = await h.agent.executeTransfer(REQUEST, { confirm: async (s) => ((seen = s), true) });
      assert.equal(outcome.executed, true);
      assert.equal(seen?.verdict.decision, expected);
      assert.equal(outcome.lifecycle?.decision, expected);
    } finally {
      await h.close();
    }
  }
});

// ---------------------------------------------------------------------------
// A057 (the guard's half; the MCP server's is in its own tests)

test("A057 (repro): a confirmation that throws or never answers is not reported as a person's refusal; one that says no is", async () => {
  const h = await harness({ config: { confirmTimeoutMs: 150 } });
  try {
    const outcomes: [string, ExecuteOptions["confirm"], string][] = [
      ["throws", async () => {
        throw new Error("ui closed");
      }, "confirmation-unavailable"],
      ["never answers", () => new Promise<boolean>(() => {}), "confirmation-unavailable"],
      ["says no", async () => false, "person"],
    ];
    for (const [name, confirm, refusedBy] of outcomes) {
      const e = await h.agent.executeTransfer(REQUEST, { confirm }).then(
        () => null,
        (err: unknown) => err,
      );
      assert.ok(e instanceof ConfirmationDeclined, `${name}: ${String(e)}`);
      assert.equal(toolRefusalOf(e).refusedBy, refusedBy, name);
    }
    assert.equal(sent(h).length, 0, "nothing was sent");
    for (const c of h.rpc.calls) assert.notEqual(c.signed, true, `${c.method} carried a signature`);
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// A085

test("A085 (repro): a request text far longer than any accepted form is refused at once, not after seconds of regex backtracking", () => {
  const cases: [string, () => unknown][] = [
    ["transfer", () => groundTransferIntent(`send 1 SOL to ${DEST} ${".".repeat(65_000)}x`, { amount: "1", destination: DEST, input_token: "SOL" })],
    ["swap", () => groundSwapRequest(`swap 1 SOL for USDC${" ".repeat(65_000)}x`, { amount: "1", input_token: "SOL", output_token: "USDC" })],
  ];
  for (const [name, f] of cases) {
    const started = performance.now();
    assert.throws(f, IntentGroundingError, name);
    const ms = performance.now() - started;
    assert.ok(ms < 250, `${name}: ${Math.round(ms)} ms`);
  }
});
