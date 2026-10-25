/**
 * Round 39 (campaign 11): the agent guard's signing boundary against a signer
 * that is not what it says, and a guard process killed mid-submission.
 * Loopback stand-ins only; nothing reaches a public RPC.
 *
 *   R39-CLIENTS-4  a signer whose key pair's private half is not its public
 *                  half's passed the signer-set check (which compares the
 *                  signer's `publicKey` field) and kit signed with it: the
 *                  bytes carried a fee-payer signature that verifies under no
 *                  key the message names, and the lifecycle recorded them as
 *                  signed and sent them
 *   R39-CLIENTS-6  the state file's directory was never checked: in one
 *                  another user can write, the file could be replaced by one
 *                  that forgets the reservations and the unresolved
 *                  submissions, and the next start replayed it
 *   crash          SIGKILL after the submission was recorded as unresolved
 *                  and before it was settled: the next guard for the wallet
 *                  takes the dead process's locks, still counts its spend and
 *                  does not build the same request a second time
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import { createKeyPairFromBytes } from "@solana/kit";
import bs58 from "bs58";
import { BoundTransaction, firstSignatureOf, messageOf } from "./artifact.js";
import { executeBoundTransaction, type LifecycleReporter, type SubmitConnection } from "./execution-lifecycle.js";
import { GraphiteGuard, PriorSubmissionUnresolved, SubmissionOutcomeUnknown, swapPolicyFromEnv } from "./guard.js";
import { GuardState } from "./guard-state.js";
import { ResidualPolicy } from "./residual-policy.js";
import { mockApprovingCore, mockRpc, mockService, tokenAccountData } from "./loopback-mocks.js";
import { raydiumAmmV4Data } from "./swap-fixtures.js";
import { associatedTokenAddress, SPL_TOKEN_PROGRAM } from "./swap-envelope.js";
import { RAYDIUM_AMM_V4 } from "./swap-instructions.js";
import type { VerificationResult } from "../../sdk/typescript/src/types.js";

const SYSTEM = "11111111111111111111111111111111";
const BLOCKHASH = "11111111111111111111111111111111";
const SOL = 1_000_000_000;
const DEST = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
const REQUEST = `Transfer 1 SOL to ${DEST}`;

const privateTmp = () => mkdtempSync(join(tmpdir(), "graphite-r39-"));

function transferBound(payer: Keypair): BoundTransaction {
  return BoundTransaction.build({
    instructions: [SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: Keypair.generate().publicKey, lamports: 5 })],
    feePayer: payer.publicKey,
    recentBlockhash: BLOCKHASH,
    lastValidBlockHeight: 42,
  });
}

const digestOf = (b: BoundTransaction) => createHash("sha256").update(b.artifactBytes).digest("hex");

/** A signer that names `payer`'s address but holds another key's private half. */
async function mismatchedSigner(payer: Keypair) {
  const real = await createKeyPairFromBytes(payer.secretKey, false);
  const other = await createKeyPairFromBytes(Keypair.generate().secretKey, false);
  return { publicKey: payer.publicKey, keyPair: { publicKey: real.publicKey, privateKey: other.privateKey } as CryptoKeyPair };
}

test("R39-CLIENTS-4 (repro): a signer whose key pair halves belong to two keys is refused; nothing is returned", async () => {
  const payer = Keypair.generate();
  const bound = transferBound(payer);
  const signer = await mismatchedSigner(payer);
  await assert.rejects(() => bound.signApproved(digestOf(bound), [signer]), /does not verify over the approved message/);
  // The transaction is spent: a second attempt, even with the right key, is
  // refused — rebuild and re-verify.
  await assert.rejects(() => bound.signApproved(digestOf(bound), [payer]), /already being signed|changed between approval/);
});

test("R39-CLIENTS-4 (control): the honest signer's signature verifies under the key the message names", async () => {
  const payer = Keypair.generate();
  const bound = transferBound(payer);
  const raw = await bound.signApproved(digestOf(bound), [payer]);
  const key = await globalThis.crypto.subtle.importKey("raw", Uint8Array.from(payer.publicKey.toBytes()), { name: "Ed25519" }, false, ["verify"]);
  const ok = await globalThis.crypto.subtle.verify(
    "Ed25519",
    key,
    Uint8Array.from(bs58.decode(firstSignatureOf(raw))),
    Uint8Array.from(messageOf(raw)),
  );
  assert.equal(ok, true);
  // And the guard's own signer (a non-extractable WebCrypto pair) signs too.
  const kp = await createKeyPairFromBytes(Keypair.generate().secretKey, false);
  const { getAddressFromPublicKey } = await import("@solana/kit");
  const { PublicKey } = await import("@solana/web3.js");
  const signer = { publicKey: new PublicKey(await getAddressFromPublicKey(kp.publicKey)), keyPair: kp };
  const b2 = BoundTransaction.build({
    instructions: [SystemProgram.transfer({ fromPubkey: signer.publicKey, toPubkey: Keypair.generate().publicKey, lamports: 5 })],
    feePayer: signer.publicKey,
    recentBlockhash: BLOCKHASH,
    lastValidBlockHeight: 42,
  });
  assert.ok((await b2.signApproved(digestOf(b2), [signer])).length > 64);
});

test("R39-CLIENTS-4 (repro, lifecycle): with that signer nothing is recorded as signed and nothing is sent", async () => {
  const payer = Keypair.generate();
  const bound = transferBound(payer);
  const calls: string[] = [];
  const connection: SubmitConnection = {
    async sendRawTransaction(raw) {
      calls.push("send");
      return firstSignatureOf(raw);
    },
    async confirmTransaction() {
      calls.push("confirm");
      return {};
    },
  };
  const graphite = {
    async recordLifecycleEvent(e: { event_type: string }) {
      calls.push(`record:${e.event_type}`);
      return { recorded: true, event_type: e.event_type, content_hash: "48c65c638aceb5de", verdict_on_record: "approved", verdict_on_record_key: "audit_trail_id" };
    },
    async verifyExecution() {
      calls.push("l8");
      throw new Error("not reached");
    },
  } as unknown as LifecycleReporter;
  const verification = {
    approved: true,
    decision: "executable_approved",
    executable: true,
    layers: [],
    risk_verdict: { status: "Clear", findings: [] },
    policy_verdict: "Approved",
    audit_trail_id: "gr-test",
    content_hash: "48c65c638aceb5de",
    scope: {
      kind: "artifact_bound",
      transaction_sha256: digestOf(bound),
      transaction_bytes: bound.artifactBytes.length,
      simulated: true,
      unobserved: ["a", "b"],
      unobserved_codes: ["program_semantics", "inner_instructions"],
    },
  } as unknown as VerificationResult;
  await assert.rejects(
    executeBoundTransaction({
      bound,
      verification,
      signers: [await mismatchedSigner(payer)],
      connection,
      graphite,
      policy: new ResidualPolicy(),
      reportedBy: "t",
      label: "t",
      log: () => {},
    }),
    /does not verify over the approved message/,
  );
  assert.deepEqual(calls, [], "nothing recorded, nothing sent");
});

// ---------------------------------------------------------------------------
// R39-CLIENTS-7: the repeat of a swap is the request's amount, not the route's.

const USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const WSOL = "So11111111111111111111111111111111111111112";
const SPL_TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const RENT = 2_039_280;
const SWAP = "Swap 1 SOL for USDC";

async function swapHarness(wallet: Keypair) {
  const w = wallet.publicKey.toBase58();
  const ata = associatedTokenAddress(wallet.publicKey, new PublicKey(USDC), new PublicKey(SPL_TOKEN_PROGRAM)).toBase58();
  const accounts = [
    { pubkey: w, isSigner: true, isWritable: true },
    { pubkey: DEST, isSigner: false, isWritable: true },
    { pubkey: ata, isSigner: false, isWritable: true },
  ];
  const rpc = await mockRpc({
    ledger: {
      [w]: { lamports: 10 * SOL, owner: SYSTEM },
      [DEST]: { lamports: RENT, owner: SPL_TOKEN, data: tokenAccountData(WSOL, w, BigInt(SOL)) },
    },
    afterSimulation: {
      [w]: { lamports: 10 * SOL - 5_000, owner: SYSTEM },
      [DEST]: { lamports: RENT, owner: SPL_TOKEN, data: tokenAccountData(WSOL, w, 0n) },
      [ata]: { lamports: RENT, owner: SPL_TOKEN, data: tokenAccountData(USDC, w, 150_000_000n) },
    },
    decimals: { [USDC]: 6, [WSOL]: 9 },
    sendFails: "lost",
  });
  const core = await mockApprovingCore();
  const ai = await mockService();
  ai.respond.set("POST /parse", (body) => ({
    status: 200,
    body: {
      intent_type: "swap",
      raw_natural_language: (body as { text: string }).text,
      confidence_of_parse: 0.99,
      extracted_parameters: { input_token: "SOL", output_token: "USDC", amount: (body as { text: string }).text.split(" ")[1] },
    },
  }));
  const agent = await GraphiteGuard.create({
    privateKey: bs58.encode(wallet.secretKey),
    rpcUrl: rpc.url,
    graphiteCoreUrl: core.url,
    aiLayerUrl: ai.url,
    spendPolicy: { maxTransferLamports: 100n * BigInt(SOL) },
    swapPolicy: swapPolicyFromEnv({ GRAPHITE_SWAP_MIN_RATES: "SOL/USDC=100" }),
    swapEnvelope: {},
    rpcTimeoutMs: 2_000,
    walletLockDir: privateTmp(),
  });
  const route = (amountIn: bigint) => ({
    programId: RAYDIUM_AMM_V4,
    discriminator: "09",
    accounts,
    instructionData: raydiumAmmV4Data(amountIn, 149_250_000n),
  });
  return {
    agent,
    rpc,
    route,
    sent: () => rpc.calls.filter((c) => c.method === "sendTransaction").length,
    close: async () => {
      agent.close();
      await Promise.all([rpc.close(), core.close(), ai.close()]);
    },
  };
}

test("R39-CLIENTS-7 (repro): after an outcome-unknown swap, the same request through a route spending one base unit less is a repeat", async () => {
  const h = await swapHarness(Keypair.generate());
  try {
    await assert.rejects(h.agent.executeSwap(SWAP, h.route(BigInt(SOL))), SubmissionOutcomeUnknown);
    h.rpc.behaviour.sendFails = false;
    // Round 38's key named the route's amount in: 999,999,999 lamports was a
    // different request from 1,000,000,000, so both were built and sent.
    await assert.rejects(h.agent.executeSwap(SWAP, h.route(BigInt(SOL) - 1n)), PriorSubmissionUnresolved);
    await assert.rejects(h.agent.executeSwap("Swap 1.0 SOL for USDC", h.route(BigInt(SOL) - 1n)), PriorSubmissionUnresolved);
    assert.equal(h.sent(), 1, "one send");
  } finally {
    await h.close();
  }
});

test("R39-CLIENTS-7 (control): a different request (another amount) is not held back by it", async () => {
  const h = await swapHarness(Keypair.generate());
  try {
    await assert.rejects(h.agent.executeSwap(SWAP, h.route(BigInt(SOL))), SubmissionOutcomeUnknown);
    h.rpc.behaviour.sendFails = false;
    // "Swap 2 SOL" is another request; its route may spend less than it allows.
    assert.equal((await h.agent.executeSwap("Swap 2 SOL for USDC", h.route(BigInt(SOL)))).executed, true);
    assert.equal(h.sent(), 2);
  } finally {
    await h.close();
  }
});

test("R39-CLIENTS-7: a swap recorded under Round 38's key (the route's amount) still holds back that swap", async () => {
  const dir = privateTmp();
  try {
    const wallet = Keypair.generate();
    const w = wallet.publicKey.toBase58();
    const stateFile = join(dir, "guard.state");
    const signature = bs58.encode(randomBytes(64));
    writeFileSync(
      stateFile,
      `${JSON.stringify({ v: 1, t: "unresolved", key: `swap:v2:${w}:${WSOL}:${USDC}:${SOL}`, signature, lvbh: 1_000, at: Date.now() })}\n`,
      { mode: 0o600 },
    );
    const g = GuardState.open(stateFile);
    assert.equal(g.unresolved(`swap:v2:${w}:${WSOL}:${USDC}:${SOL}`)?.signature, signature);
    g.close();
    const h = await swapHarnessWithState(wallet, stateFile, dir);
    try {
      await assert.rejects(h.agent.executeSwap(SWAP, h.route(BigInt(SOL))), (e: unknown) => {
        assert.ok(e instanceof PriorSubmissionUnresolved, String(e));
        assert.equal((e as PriorSubmissionUnresolved).signature, signature);
        return true;
      });
      assert.equal(h.sent(), 0);
    } finally {
      await h.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

/** `swapHarness` with a state file and lock directory, sending honestly. */
async function swapHarnessWithState(wallet: Keypair, stateFile: string, dir: string) {
  const w = wallet.publicKey.toBase58();
  const ata = associatedTokenAddress(wallet.publicKey, new PublicKey(USDC), new PublicKey(SPL_TOKEN_PROGRAM)).toBase58();
  const rpc = await mockRpc({
    ledger: {
      [w]: { lamports: 10 * SOL, owner: SYSTEM },
      [DEST]: { lamports: RENT, owner: SPL_TOKEN, data: tokenAccountData(WSOL, w, BigInt(SOL)) },
    },
    afterSimulation: {
      [w]: { lamports: 10 * SOL - 5_000, owner: SYSTEM },
      [DEST]: { lamports: RENT, owner: SPL_TOKEN, data: tokenAccountData(WSOL, w, 0n) },
      [ata]: { lamports: RENT, owner: SPL_TOKEN, data: tokenAccountData(USDC, w, 150_000_000n) },
    },
    decimals: { [USDC]: 6, [WSOL]: 9 },
  });
  const core = await mockApprovingCore();
  const ai = await mockService();
  ai.respond.set("POST /parse", (body) => ({
    status: 200,
    body: {
      intent_type: "swap",
      raw_natural_language: (body as { text: string }).text,
      confidence_of_parse: 0.99,
      extracted_parameters: { input_token: "SOL", output_token: "USDC", amount: "1" },
    },
  }));
  const agent = await GraphiteGuard.create({
    privateKey: bs58.encode(wallet.secretKey),
    rpcUrl: rpc.url,
    graphiteCoreUrl: core.url,
    aiLayerUrl: ai.url,
    spendPolicy: { maxTransferLamports: 100n * BigInt(SOL) },
    swapPolicy: swapPolicyFromEnv({ GRAPHITE_SWAP_MIN_RATES: "SOL/USDC=100" }),
    swapEnvelope: {},
    rpcTimeoutMs: 2_000,
    stateFile,
    walletLockDir: dir,
  });
  const accounts = [
    { pubkey: w, isSigner: true, isWritable: true },
    { pubkey: DEST, isSigner: false, isWritable: true },
    { pubkey: ata, isSigner: false, isWritable: true },
  ];
  return {
    agent,
    route: (amountIn: bigint) => ({ programId: RAYDIUM_AMM_V4, discriminator: "09", accounts, instructionData: raydiumAmmV4Data(amountIn, 149_250_000n) }),
    sent: () => rpc.calls.filter((c) => c.method === "sendTransaction").length,
    close: async () => {
      agent.close();
      await Promise.all([rpc.close(), core.close(), ai.close()]);
    },
  };
}

// ---------------------------------------------------------------------------
// R39-CLIENTS-6: the state file's location.

test("R39-CLIENTS-6 (repro): a state file another user could replace refuses to start", { skip: process.platform === "win32" }, () => {
  const root = privateTmp();
  try {
    // The directory: group- or world-writable.
    for (const mode of [0o770, 0o777, 0o1777]) {
      const dir = join(root, `d${mode.toString(8)}`);
      mkdirSync(dir);
      chmodSync(dir, mode);
      assert.throws(() => GuardState.open(join(dir, "guard.state")), /writable by others.*REFUSING TO START/s, mode.toString(8));
    }
    // The file: writable by others, or a symbolic link to one elsewhere.
    const dir = join(root, "private");
    mkdirSync(dir, { mode: 0o700 });
    const writable = join(dir, "writable.state");
    writeFileSync(writable, "");
    chmodSync(writable, 0o666);
    assert.throws(() => GuardState.open(writable), /writable by others.*REFUSING TO START/s);
    const elsewhere = join(root, "elsewhere.state");
    writeFileSync(elsewhere, "", { mode: 0o600 });
    const link = join(dir, "link.state");
    symlinkSync(elsewhere, link);
    assert.throws(() => GuardState.open(link), /a symbolic link.*REFUSING TO START/s);
    // Nothing was locked or created by a refused open.
    assert.deepEqual(readdirSync(dir).sort(), ["link.state", "writable.state"]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("R39-CLIENTS-6 (control): a private directory, or one only its owner writes, opens", { skip: process.platform === "win32" }, () => {
  const root = privateTmp();
  try {
    for (const mode of [0o700, 0o755]) {
      const dir = join(root, `d${mode.toString(8)}`);
      mkdirSync(dir);
      chmodSync(dir, mode);
      const path = join(dir, "guard.state");
      GuardState.open(path).close();
      // And again, now that the guard created the file (0600).
      GuardState.open(path).close();
      assert.equal(statSync(path).mode & 0o777, 0o600);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Campaign 11: process crash.

/** Spawn the crash child; resolves with the pid of the process that holds the locks. */
function crashChild(args: string[]): Promise<{ pid: number; kill: () => Promise<void> }> {
  const tsx = fileURLToPath(new URL("./node_modules/tsx/dist/cli.mjs", import.meta.url));
  const script = fileURLToPath(new URL("./guard-crash-child.ts", import.meta.url));
  const child = spawn(process.execPath, [tsx, script, ...args], {
    env: { PATH: process.env.PATH ?? "", SYSTEMROOT: process.env.SYSTEMROOT ?? "" },
    stdio: ["ignore", "pipe", "inherit"],
  });
  return new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("exit", (code) => reject(new Error(`the crash child exited (${code}) before marking`)));
    createInterface({ input: child.stdout }).once("line", (line) => {
      const [word, pid] = line.split(" ");
      if (word !== "marked") return reject(new Error(line));
      child.removeAllListeners("exit");
      resolve({
        pid: Number(pid),
        kill: async () => {
          // SIGKILL: no exit hook, no close, nothing released.
          process.kill(Number(pid), "SIGKILL");
          child.kill("SIGKILL");
          for (let i = 0; i < 200; i++) {
            try {
              process.kill(Number(pid), 0);
            } catch {
              return;
            }
            await new Promise((r) => setTimeout(r, 25));
          }
          throw new Error("the crash child did not die");
        },
      });
    });
  });
}

test("crash: a guard SIGKILLed mid-submission leaves its spend counted and its submission unresolved; the next guard does not rebuild it", { skip: process.platform === "win32" }, async () => {
  const dir = privateTmp();
  try {
    const wallet = Keypair.generate();
    const w = wallet.publicKey.toBase58();
    const stateFile = join(dir, "guard.state");
    const key = `transfer:${DEST}:${SOL}`;
    const signature = bs58.encode(randomBytes(64));
    const child = await crashChild([w, dir, stateFile, key, signature]);
    await child.kill();

    // The next guard: the same wallet, lock directory and state file.
    const rpc = await mockRpc({
      ledger: { [w]: { lamports: 10 * SOL, owner: SYSTEM } },
      afterSimulation: { [w]: { lamports: 9 * SOL - 5_000, owner: SYSTEM } },
    });
    const core = await mockApprovingCore();
    const ai = await mockService();
    ai.respond.set("POST /parse", (body) => ({
      status: 200,
      body: {
        intent_type: "transfer",
        raw_natural_language: (body as { text: string }).text,
        confidence_of_parse: 0.9,
        extracted_parameters: { amount: "1", input_token: "SOL", destination: DEST },
      },
    }));
    let agent: GraphiteGuard | undefined;
    try {
      agent = await GraphiteGuard.create({
        privateKey: bs58.encode(wallet.secretKey),
        rpcUrl: rpc.url,
        graphiteCoreUrl: core.url,
        aiLayerUrl: ai.url,
        spendPolicy: { maxTransferLamports: 2n * BigInt(SOL), maxTotalLamports: 2n * BigInt(SOL) },
        swapPolicy: swapPolicyFromEnv({}),
        swapEnvelope: {},
        stateFile,
        walletLockDir: dir,
        rpcTimeoutMs: 2_000,
      });
      // It took the dead process's locks (it started at all), and refuses
      // the request whose submission may still land.
      await assert.rejects(agent.executeTransfer(REQUEST), (e: unknown) => {
        assert.ok(e instanceof PriorSubmissionUnresolved, String(e));
        assert.equal((e as PriorSubmissionUnresolved).signature, signature);
        return true;
      });
      assert.equal(rpc.calls.filter((c) => c.method === "sendTransaction").length, 0, "nothing sent");
      assert.equal(core.calls.filter((c) => c.method === "POST /verify").length, 0, "nothing built or verified");
    } finally {
      agent?.close();
      await Promise.all([rpc.close(), core.close(), ai.close()]);
    }
    // The crashed process's reservation is still counted.
    const replay = GuardState.open(stateFile);
    try {
      assert.equal(replay.unresolved(key)?.signature, signature);
      assert.deepEqual(replay.reservedSince(0).map((r) => r.lamports), [1_000_005_000n]);
    } finally {
      replay.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
