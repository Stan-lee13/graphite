/**
 * Round 38: the guard's findings of the Round 37 re-audit, end to end against
 * loopback stand-ins. Nothing here reaches a public RPC.
 *
 *   R37-17  the default wallet-lock directory depended on the session's
 *           XDG variables, so a guard started from an SSH session and one
 *           started from cron, for one wallet, each took a lock of their own
 *           and each spent the whole aggregate allowance
 *   G2-2    after an outcome-unknown swap, the same swap through another
 *           route was not a repeat
 *   G2-3    the verdict's age was checked before the Core round trip that
 *           records the signing, not immediately before the send
 *   G2-4    every send failure was outcome-unknown, and an outcome-unknown
 *           reservation was never returned before its window ended
 *   G2-5    GRAPHITE_ACCEPT_UNOBSERVED could accept `intent_parameters`,
 *           which switched off the Core's binding of the request (F-003)
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir, userInfo } from "node:os";
import { join, win32 } from "node:path";
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import bs58 from "bs58";
import {
  BoundTransaction,
  GraphiteGuard,
  GuardStateError,
  PriorSubmissionUnresolved,
  SpendPolicyRefusal,
  StaleVerdict,
  SubmissionOutcomeUnknown,
  swapPolicyFromEnv,
  type GuardConfig,
  type SpendPolicy,
} from "./guard.js";
import * as guardModule from "./guard.js";
import { GuardState, walletLockPlan } from "./guard-state.js";
import * as guardState from "./guard-state.js";
import { ResidualPolicy } from "./residual-policy.js";
import { executeBoundTransaction } from "./execution-lifecycle.js";
import * as lifecycleModule from "./execution-lifecycle.js";
import { firstSignatureOf } from "./artifact.js";
import { toolRefusalOf } from "./tool-results.js";
import { RpcTransportRefusal } from "./rpc-transport.js";
import {
  mockApprovingCore,
  mockHostileRpcFront,
  mockRpc,
  mockService,
  tokenAccountData,
  type HostileFront,
  type MockRpc,
  type MockService,
} from "./loopback-mocks.js";
import { jupiterRouteData, raydiumAmmV4Data } from "./swap-fixtures.js";
import { associatedTokenAddress, SPL_TOKEN_PROGRAM } from "./swap-envelope.js";
import type { UnobservedCode, VerificationResult } from "../../sdk/typescript/src/types.js";

// Read off the modules rather than imported by name, so that this file runs
// (and its tests fail one by one) against a guard that predates them.
const SubmissionNotSent = (guardModule as unknown as Record<string, unknown>).SubmissionNotSent as typeof Error;
const neverReachedTheRpc = (lifecycleModule as unknown as Record<string, unknown>).neverReachedTheRpc as (e: unknown) => boolean;
const defaultWalletLockDir = (guardState as unknown as Record<string, unknown>).defaultWalletLockDir as (o?: {
  platform?: NodeJS.Platform;
  userInfo?: () => { homedir: string };
}) => string;

const DEST = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
const OTHER = "p2Yicb86aZig616Eav2VWG9vuXR5mEqhtzshZYBxzsV";
const REQUEST = `Transfer 1.5 SOL to ${DEST}`;
const SWAP = "Swap 1 SOL for USDC";
const SYSTEM = "11111111111111111111111111111111";
const SPL_TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const WSOL = "So11111111111111111111111111111111111111112";
const JUPITER_V6 = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
const RAYDIUM_AMM_V4 = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8";
const SOL = 1_000_000_000;
const FEE = 5_000;
const RENT = 2_039_280;
const INHERENT: UnobservedCode[] = ["program_semantics", "inner_instructions"];
const TWO_SOL: SpendPolicy = { maxTransferLamports: 2n * BigInt(SOL), maxTotalLamports: 2n * BigInt(SOL) };

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

/** The guard against an honest RPC stand-in behind a (here, passing) front. */
async function harness(
  o: {
    wallet?: Keypair;
    spendPolicy?: SpendPolicy;
    config?: Partial<GuardConfig>;
    rpc?: (w: Keypair) => Parameters<typeof mockRpc>[0];
    parse?: (text: string) => unknown;
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
  const core = await mockApprovingCore();
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
      rpcTimeoutMs: 2_000,
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

/** A fresh directory only this user can enter. */
const privateTmp = () => mkdtempSync(join(tmpdir(), "graphite-r38-"));

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
 * An honest 1 SOL → 150 USDC swap for `wallet`, and two routes for it: a
 * Jupiter v6 `route` and a Raydium AMM v4 `SwapBaseIn`, the same amount and
 * the same mints, the same minimum output.
 */
function swapFixture(wallet: Keypair) {
  const w = wallet.publicKey.toBase58();
  const ata = associatedTokenAddress(wallet.publicKey, new PublicKey(USDC), new PublicKey(SPL_TOKEN_PROGRAM)).toBase58();
  const accounts = [
    { pubkey: w, isSigner: true, isWritable: true },
    { pubkey: DEST, isSigner: false, isWritable: true },
    { pubkey: ata, isSigner: false, isWritable: true },
  ];
  return {
    state: {
      ledger: {
        [w]: { lamports: 10 * SOL, owner: SYSTEM },
        [DEST]: { lamports: RENT, owner: SPL_TOKEN, data: tokenAccountData(WSOL, w, BigInt(SOL)) },
      },
      afterSimulation: {
        [w]: { lamports: 10 * SOL - FEE, owner: SYSTEM },
        [DEST]: { lamports: RENT, owner: SPL_TOKEN, data: tokenAccountData(WSOL, w, 0n) },
        [ata]: { lamports: RENT, owner: SPL_TOKEN, data: tokenAccountData(USDC, w, 150_000_000n) },
      },
      decimals: { [USDC]: 6, [WSOL]: 9 },
    },
    jupiter: { programId: JUPITER_V6, discriminator: "e517cb977ae3ad2a", accounts, instructionData: jupiterRouteData() },
    raydium: {
      programId: RAYDIUM_AMM_V4,
      discriminator: "09",
      accounts,
      instructionData: raydiumAmmV4Data(BigInt(SOL), 149_250_000n),
    },
    parse: (text: string) => ({
      intent_type: "swap",
      raw_natural_language: text,
      confidence_of_parse: 0.99,
      extracted_parameters: { input_token: "SOL", output_token: "USDC", amount: "1" },
    }),
  };
}

const payer = Keypair.generate();

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

const boundTransfer = () =>
  BoundTransaction.build({
    instructions: [SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: new PublicKey(DEST), lamports: 1_000 })],
    feePayer: payer.publicKey,
    recentBlockhash: SYSTEM,
    lastValidBlockHeight: 42,
  });

const receipt = (event_type: string) => ({
  recorded: true,
  event_type,
  content_hash: "48c65c638aceb5de",
  verdict_on_record: "approved",
  verdict_on_record_key: "audit_trail_id",
  sequence_anomalies: [],
});

// ---------------------------------------------------------------------------
// R37-17: one wallet lock per user, whatever the session's environment.

test("R37-17 (repro): a guard started from an SSH session and one from cron, for one wallet, take one lock — the second refuses to start", async () => {
  const wallet = Keypair.generate();
  const ssh = privateTmp();
  const cron = privateTmp();
  // An SSH login: pam_systemd sets XDG_RUNTIME_DIR, a profile sets XDG_STATE_HOME.
  const sshEnv = { GRAPHITE_GUARD_LOCK_DIR: undefined, XDG_RUNTIME_DIR: ssh, XDG_STATE_HOME: join(ssh, "state") };
  // cron: no runtime directory, and here another state directory.
  const cronEnv = { GRAPHITE_GUARD_LOCK_DIR: undefined, XDG_RUNTIME_DIR: undefined, XDG_STATE_HOME: cron };
  const a = await withEnv(sshEnv, () => harness({ wallet, spendPolicy: TWO_SOL }));
  try {
    const second = await withEnv(cronEnv, () => harness({ wallet, spendPolicy: TWO_SOL }).catch((e: unknown) => e));
    if (!(second instanceof Error)) {
      await (second as H).close();
      assert.fail("both guards started, each with the whole aggregate allowance");
    }
    assert.ok(second instanceof GuardStateError, String(second));
    assert.match(second.message, /another guard \(process \d+\) is running for wallet/);
    // One allowance: the guard that runs spends it, and no second guard does.
    assert.equal((await a.agent.executeTransfer(REQUEST)).executed, true);
    await assert.rejects(a.agent.executeTransfer(`Transfer 1.5 SOL to ${OTHER}`), SpendPolicyRefusal);
    // Neither session's XDG directory holds a lock.
    assert.deepEqual(readdirSync(ssh), [], "nothing under the SSH session's XDG_RUNTIME_DIR");
    assert.deepEqual(readdirSync(cron), [], "nothing under cron's XDG_STATE_HOME");
  } finally {
    await a.close();
  }
  // Once the first is gone, the cron guard takes the same lock.
  const b = await withEnv(cronEnv, () => harness({ wallet, spendPolicy: TWO_SOL }));
  await b.close();
});

test("R37-17: the default lock directory is derived from this user's account (its passwd home), never from the session's variables", async () => {
  const expected = join(userInfo().homedir, ".local", "state", "graphite-guard");
  const sessions: Record<string, string | undefined>[] = [
    {}, // cron
    { XDG_RUNTIME_DIR: "/run/user/1000", XDG_STATE_HOME: "/home/a/.st" }, // an SSH login
    { XDG_STATE_HOME: "/elsewhere" },
    { HOME: "/tmp/not-home", XDG_RUNTIME_DIR: "/tmp/x" }, // sudo -E, a container's HOME
    { LOCALAPPDATA: "C:\\Users\\b\\AppData\\Local" },
  ];
  for (const env of sessions) {
    assert.deepEqual(walletLockPlan({}, env), { shared: false, dir: expected }, JSON.stringify(env));
  }
  // The process's own HOME is not read either.
  await withEnv({ HOME: "/nowhere", XDG_RUNTIME_DIR: "/run/user/9", GRAPHITE_GUARD_LOCK_DIR: undefined }, () =>
    assert.deepEqual(walletLockPlan({}), { shared: false, dir: expected }),
  );
  // A directory the operator names still overrides it.
  assert.deepEqual(walletLockPlan({}, { GRAPHITE_GUARD_LOCK_DIR: "/srv/locks", XDG_RUNTIME_DIR: "/run/user/1" }), {
    shared: false,
    dir: "/srv/locks",
  });
  assert.deepEqual(walletLockPlan({ lockDir: "/cfg/locks" }, { GRAPHITE_GUARD_LOCK_DIR: "/srv/locks" }), {
    shared: false,
    dir: "/cfg/locks",
  });
  // Per platform, from the account's home directory.
  const account = (homedir: string) => () => ({ homedir });
  assert.equal(defaultWalletLockDir({ platform: "linux", userInfo: account("/home/a") }), "/home/a/.local/state/graphite-guard");
  assert.equal(defaultWalletLockDir({ platform: "darwin", userInfo: account("/Users/a") }), "/Users/a/.local/state/graphite-guard");
  assert.equal(
    defaultWalletLockDir({ platform: "win32", userInfo: account("C:\\Users\\a") }),
    win32.join("C:\\Users\\a", "AppData", "Local", "graphite-guard"),
  );
  // No account home (a uid with no passwd entry), or not an absolute one: refuse, naming the override.
  const none = () => {
    throw new Error("ENOENT: no such user");
  };
  for (const userInfoOf of [none, account(""), account("relative/home")]) {
    assert.throws(() => defaultWalletLockDir({ platform: "linux", userInfo: userInfoOf }), (e: unknown) => {
      assert.ok(e instanceof GuardStateError, String(e));
      assert.match((e as Error).message, /GRAPHITE_GUARD_LOCK_DIR.*REFUSING TO START/);
      return true;
    });
  }
});
