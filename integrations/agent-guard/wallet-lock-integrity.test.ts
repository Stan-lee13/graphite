/**
 * The wallet lock holds for as long as the guard spends (Round 34).
 *
 * Round 32 gave every guard a lock named for its wallet, so a second guard for
 * the same key refuses to start. That lock lived in the system temp directory
 * and was checked once, at start: a temp cleaner (systemd-tmpfiles' 10-day
 * age, macOS, Windows Storage Sense) that deleted it let a second guard start
 * with its own full aggregate allowance while the first kept spending. Taking
 * over a crashed guard's lock was a race two starting guards could both win.
 * The lock directory was trusted whatever its owner and mode, and the lock's
 * temporary file had a predictable name opened through a symlink. And a
 * closed guard still signed.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Keypair } from "@solana/web3.js";
import bs58 from "bs58";
import { GraphiteGuard, GuardStateError, swapPolicyFromEnv } from "./guard.js";
import * as guardState from "./guard-state.js";
import { GuardState, WalletLock, walletLockPlan } from "./guard-state.js";
import { mockApprovingCore, mockRpc, mockService, type MockRpc, type MockService } from "./loopback-mocks.js";

const DEST = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
const REQUEST = `Transfer 1.5 SOL to ${DEST}`;
const SYSTEM = "11111111111111111111111111111111";
const SOL = 1_000_000_000n;
const FEE = 5_000n;

const lockDir = () => mkdtempSync(join(tmpdir(), "graphite-lock-integrity-"));
const lockPathOf = (dir: string, wallet: Keypair) => join(dir, `wallet-${wallet.publicKey.toBase58()}.lock`);

interface G {
  agent: GraphiteGuard;
  rpc: MockRpc;
  core: MockService;
  ai: MockService;
  close(): Promise<void>;
}

/** A guard for `wallet` against loopback stand-ins that approve the one transfer. */
async function guardFor(wallet: Keypair, config: { walletLockDir?: string; stateFile?: string } = {}): Promise<G> {
  const w = wallet.publicKey.toBase58();
  const rpc = await mockRpc({
    ledger: { [w]: { lamports: Number(10n * SOL), owner: SYSTEM } },
    afterSimulation: { [w]: { lamports: Number(10n * SOL - 3n * SOL / 2n - FEE), owner: SYSTEM } },
  });
  const core = await mockApprovingCore();
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
    const agent = await GraphiteGuard.create({
      privateKey: bs58.encode(wallet.secretKey),
      rpcUrl: rpc.url,
      graphiteCoreUrl: core.url,
      aiLayerUrl: ai.url,
      spendPolicy: { maxTransferLamports: 2n * SOL, maxTotalLamports: 2n * SOL },
      swapPolicy: swapPolicyFromEnv({ GRAPHITE_SWAP_MIN_RATES: "SOL/USDC=100" }),
      swapEnvelope: {},
      ...config,
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
  } catch (e) {
    await Promise.all([rpc.close(), core.close(), ai.close()]);
    throw e;
  }
}

const sends = (g: G) => g.rpc.calls.filter((c) => c.method === "sendTransaction").length;

// ---------------------------------------------------------------------------
// R33-16: the default directory, and a lock that disappears under its guard.

test("lock dir: the default is a runtime directory no temp cleaner sweeps, never the system temp directory", () => {
  const def = (guardState as unknown as Record<string, unknown>).defaultWalletLockDir as
    | ((env: Record<string, string | undefined>, o?: Record<string, unknown>) => string)
    | undefined;
  // Whatever this host has: not under the temp directory.
  const plan = walletLockPlan({}, {});
  assert.equal(plan.shared, false);
  const dir = (plan as { dir: string }).dir;
  assert.ok(!dir.startsWith(tmpdir()), `the default lock directory ${dir} is under ${tmpdir()}, which temp cleaners empty`);
  assert.equal(typeof def, "function", "defaultWalletLockDir is exported");
  const never = () => false;
  const always = () => true;
  // XDG_RUNTIME_DIR first (a per-user tmpfs, not aged by systemd-tmpfiles).
  assert.equal(def!({ XDG_RUNTIME_DIR: "/run/user/1000" }, { platform: "linux", canWrite: always }), "/run/user/1000/graphite-guard");
  // Then /run/graphite-guard when this user can write there.
  assert.equal(def!({}, { platform: "linux", canWrite: always }), "/run/graphite-guard");
  // Then the user's state directory, never the temp directory.
  assert.equal(def!({ XDG_STATE_HOME: "/home/a/.st" }, { platform: "linux", canWrite: never }), "/home/a/.st/graphite-guard");
  assert.equal(def!({}, { platform: "darwin", canWrite: never, homedir: () => "/Users/a" }), "/Users/a/.local/state/graphite-guard");
  // A relative XDG value is not a directory to trust (the spec says ignore it).
  assert.equal(def!({ XDG_RUNTIME_DIR: "run" }, { platform: "linux", canWrite: always }), "/run/graphite-guard");
  // Windows: %LOCALAPPDATA%\graphite-guard; none named refuses to start.
  assert.equal(
    def!({ LOCALAPPDATA: "C:\\Users\\a\\AppData\\Local" }, { platform: "win32", canWrite: always }),
    join("C:\\Users\\a\\AppData\\Local", "graphite-guard"),
  );
  assert.throws(() => def!({}, { platform: "win32", canWrite: always }), /GRAPHITE_GUARD_LOCK_DIR/);
  // The override still wins.
  assert.deepEqual(walletLockPlan({}, { GRAPHITE_GUARD_LOCK_DIR: "/srv/locks" }), { shared: false, dir: "/srv/locks" });
});

test("lock gone: a guard whose wallet lock was deleted refuses its next spend; the guard that took the wallet spends", async () => {
  const dir = lockDir();
  const wallet = Keypair.generate();
  const a = await guardFor(wallet, { walletLockDir: dir });
  let b: G | undefined;
  try {
    // What a temp cleaner does.
    unlinkSync(lockPathOf(dir, wallet));
    // Nothing on disk says A exists, so B starts (design: A stops spending,
    // because B cannot see A; see guard-state.ts).
    b = await guardFor(wallet, { walletLockDir: dir });
    await assert.rejects(a.agent.executeTransfer(REQUEST), (e: unknown) => {
      assert.ok(e instanceof GuardStateError, String(e));
      assert.match((e as Error).message, /is no longer this guard's/);
      return true;
    });
    assert.equal(sends(a), 0, "the guard that lost its lock sent nothing");
    assert.equal(a.ai.calls.length > 0, true, "the refusal is at the spend, after the request was read");
    // Refused before it reserves anything or asks the Core: the check runs
    // before the reservation, not only before signing.
    assert.equal(a.core.calls.filter((c) => c.method === "POST /verify").length, 0, "the Core was not asked");
    const outcome = await b.agent.executeTransfer(REQUEST);
    assert.equal(outcome.executed, true, "the guard that holds the lock spends");
    assert.equal(sends(b), 1);
  } finally {
    await b?.close();
    await a.close();
  }
});

test("lock replaced: the same content under a new inode, or new content in the same inode, is not this guard's lock", async () => {
  const dir = lockDir();
  for (const how of ["copied", "rewritten"] as const) {
    const wallet = Keypair.generate();
    const path = lockPathOf(dir, wallet);
    const a = await guardFor(wallet, { walletLockDir: dir });
    try {
      const content = readFileSync(path, "utf8");
      if (how === "copied") {
        // Another file with the identical pid and token renamed over it (made
        // while the original exists, so it cannot reuse its inode number):
        // the inode tells them apart.
        writeFileSync(`${path}.copy`, content);
        renameSync(`${path}.copy`, path);
      } else {
        writeFileSync(path, `${process.pid} ${"0".repeat(32)}`);
      }
      await assert.rejects(a.agent.executeTransfer(REQUEST), /is no longer this guard's/, how);
      assert.equal(sends(a), 0, how);
      assert.equal(a.core.calls.filter((c) => c.method === "POST /verify").length, 0, `${how}: the Core was not asked`);
    } finally {
      await a.close();
    }
    assert.equal(existsSync(path), true, `${how}: closing leaves a lock that is not this guard's`);
    unlinkSync(path);
  }
});

test("lock gone: the state file's lock is re-checked the same way", async () => {
  const dir = lockDir();
  const wallet = Keypair.generate();
  const stateFile = join(dir, "guard.state");
  const a = await guardFor(wallet, { walletLockDir: dir, stateFile });
  try {
    unlinkSync(`${stateFile}.lock`);
    await assert.rejects(a.agent.executeTransfer(REQUEST), /is no longer this guard's/);
    assert.equal(sends(a), 0);
  } finally {
    await a.close();
  }
});

// ---------------------------------------------------------------------------
// R33-17: taking over a crashed guard's lock, by two guards at once.

class Contender {
  readonly #child: ChildProcessWithoutNullStreams;
  readonly #lines: string[] = [];
  readonly #waiters: ((line: string) => void)[] = [];

  constructor(wallet: string, dir: string) {
    const tsx = fileURLToPath(new URL("./node_modules/tsx/dist/cli.mjs", import.meta.url));
    const script = fileURLToPath(new URL("./wallet-lock-race-child.ts", import.meta.url));
    this.#child = spawn(process.execPath, [tsx, script, wallet, dir], {
      env: { PATH: process.env.PATH ?? "", SYSTEMROOT: process.env.SYSTEMROOT ?? "" },
    });
    createInterface({ input: this.#child.stdout }).on("line", (line) => {
      const w = this.#waiters.shift();
      if (w) w(line);
      else this.#lines.push(line);
    });
  }

  next(): Promise<string> {
    const line = this.#lines.shift();
    if (line !== undefined) return Promise.resolve(line);
    return new Promise((resolve) => this.#waiters.push(resolve));
  }

  async ask(cmd: string): Promise<string> {
    this.#child.stdin.write(`${cmd}\n`);
    return this.next();
  }

  /** The pid of the process that takes the lock, from its "ready" line. */
  pid = 0;

  exit(): Promise<void> {
    return new Promise((resolve) => {
      this.#child.on("close", () => resolve());
      this.#child.stdin.write("exit\n");
    });
  }
}

const RACE_ITERATIONS = 1000;

test(`takeover: two guards that find the same stale lock never both take it (${RACE_ITERATIONS} rounds)`, { timeout: 180_000 }, async () => {
  const dir = lockDir();
  const wallet = Keypair.generate().publicKey.toBase58();
  const path = join(dir, `wallet-${wallet}.lock`);
  const contenders = [new Contender(wallet, dir), new Contender(wallet, dir)];
  try {
    for (const c of contenders) {
      const ready = (await c.next()).split(" ");
      assert.equal(ready[0], "ready");
      c.pid = Number(ready[1]);
    }
    // Both started: each believed it took the wallet (the race). Lost: one
    // started and then found its lock was not its own (the re-check would
    // stop it spending, but it should never have started). None: neither.
    let both = 0;
    let lost = 0;
    let none = 0;
    for (let i = 0; i < RACE_ITERATIONS; i++) {
      // A crashed guard's lock: a pid no process has.
      writeFileSync(path, "2147483646 ffffffffffffffffffffffffffffffff");
      const at = Date.now() + 5;
      const took = await Promise.all(contenders.map((c) => c.ask(`go ${at}`)));
      const held = await Promise.all(contenders.map((c) => c.ask("check")));
      const owners = took.map((t, k) => t === "acquired" && held[k] === "held");
      const holders = owners.filter(Boolean).length;
      const started = took.filter((t) => t === "acquired").length;
      if (started > 1) both++;
      if (started > holders) lost++;
      if (started === 0) none++;
      if (holders === 1) {
        // The one that holds it is the one named in the file.
        const k = owners.indexOf(true);
        assert.match(readFileSync(path, "utf8"), new RegExp(`^${contenders[k].pid}(\\s|$)`), `round ${i}`);
      }
      for (const c of contenders) assert.equal(await c.ask("release"), "released");
      assert.equal(existsSync(path), false, `round ${i}: the holder's release removed the lock`);
    }
    assert.equal(both, 0, `in ${both} of ${RACE_ITERATIONS} rounds both contenders took the lock`);
    assert.equal(lost, 0, `in ${lost} of ${RACE_ITERATIONS} rounds a contender took the lock and lost it`);
    assert.equal(none, 0, `in ${none} of ${RACE_ITERATIONS} rounds neither did`);
    assert.deepEqual(readdirSync(dir), [], "no temporary or set-aside file is left behind");
  } finally {
    await Promise.all(contenders.map((c) => c.exit()));
  }
});

// ---------------------------------------------------------------------------
// G-3: the lock directory and the lock's temporary file.

test("lock dir: an existing directory that is not private, or not a directory, refuses to start", { skip: process.platform === "win32" }, () => {
  const wallet = Keypair.generate().publicKey.toBase58();
  const open = lockDir();
  chmodSync(open, 0o755);
  assert.throws(() => WalletLock.take(wallet, open), (e: unknown) => {
    assert.ok(e instanceof GuardStateError, String(e));
    assert.match((e as Error).message, /mode 0755, not 0700/);
    return true;
  });
  assert.deepEqual(readdirSync(open), [], "nothing was written into it");
  const real = lockDir();
  const link = join(lockDir(), "via-symlink");
  symlinkSync(real, link);
  assert.throws(() => WalletLock.take(wallet, link), /is a symbolic link/);
  // Owned by someone else: the check compares the owner with this user.
  const assertPrivate = (guardState as unknown as Record<string, unknown>).assertPrivateDirectory as
    | ((dir: string, euid?: number) => void)
    | undefined;
  assert.equal(typeof assertPrivate, "function", "assertPrivateDirectory is exported");
  const mine = lockDir();
  assertPrivate!(mine);
  assert.throws(() => assertPrivate!(mine, (process.geteuid?.() ?? 0) + 1), /is owned by uid \d+, not this user/);
  // The control: a fresh directory is created private and used.
  const fresh = join(lockDir(), "new");
  WalletLock.take(wallet, fresh).close();
  assert.equal(statSync(fresh).mode & 0o777, 0o700);
});

test("temp files: a symlink planted at the lock's or the state file's temporary name is not followed", () => {
  const dir = lockDir();
  const victim = join(lockDir(), "victim");
  writeFileSync(victim, "precious");
  const wallet = Keypair.generate().publicKey.toBase58();
  const lock = join(dir, `wallet-${wallet}.lock`);
  const stateFile = join(dir, "guard.state");
  // Every name the old scheme (`<path>.<pid>.<Date.now()>.tmp`) could pick in
  // the next few seconds.
  const start = Date.now();
  for (let t = start; t < start + 4000; t++) {
    symlinkSync(victim, `${lock}.${process.pid}.${t}.tmp`);
    symlinkSync(victim, `${stateFile}.lock.${process.pid}.${t}.tmp`);
    symlinkSync(victim, `${stateFile}.${process.pid}.${t}.tmp`);
  }
  const taken = WalletLock.take(wallet, dir);
  const state = GuardState.open(stateFile);
  try {
    assert.equal(readFileSync(victim, "utf8"), "precious", "the victim behind the symlink was not written");
    assert.equal(statSync(stateFile).isFile(), true);
    assert.equal(readFileSync(stateFile, "utf8"), "");
  } finally {
    state.close();
    taken.close();
  }
});

// ---------------------------------------------------------------------------
// G-4: a closed guard.

test("close: a closed guard refuses to execute, with or without a state file, before anything is asked", async () => {
  const dir = lockDir();
  for (const stateFile of [undefined, join(dir, "closed.state")]) {
    const g = await guardFor(Keypair.generate(), { walletLockDir: dir, stateFile });
    try {
      g.agent.close();
      await assert.rejects(g.agent.executeTransfer(REQUEST), /this guard is closed/);
      await assert.rejects(g.agent.executeSwap(REQUEST), /this guard is closed/);
      assert.equal(sends(g), 0);
      assert.equal(g.ai.calls.length, 0, "the AI layer was not asked");
      g.agent.close(); // idempotent
    } finally {
      await g.close();
    }
  }
});

test("close: a guard closed while a person confirms neither signs nor submits", async () => {
  const g = await guardFor(Keypair.generate(), { walletLockDir: lockDir() });
  try {
    await assert.rejects(
      g.agent.executeTransfer(REQUEST, {
        confirm: async () => {
          g.agent.close();
          return true;
        },
      }),
      /this guard is closed/,
    );
    assert.equal(sends(g), 0);
    // Refused before signing, not only before sending: a signing goes on the
    // trail before anything is sent, and none was recorded.
    assert.deepEqual(
      g.core.calls.filter((c) => c.method === "POST /audit/event"),
      [],
      "nothing was signed after close()",
    );
  } finally {
    await g.close();
  }
});

// ---------------------------------------------------------------------------
// G-7: the guard's write to the trail is not a public method.

test("surface: verifyTransaction is not reachable on the guard", async () => {
  const g = await guardFor(Keypair.generate(), { walletLockDir: lockDir() });
  try {
    assert.equal((g.agent as unknown as Record<string, unknown>).verifyTransaction, undefined);
    assert.equal(
      Object.getOwnPropertyNames(GraphiteGuard.prototype).includes("verifyTransaction"),
      false,
      "no prototype method writes a verification under the deployment's key for an arbitrary caller",
    );
  } finally {
    await g.close();
  }
});
