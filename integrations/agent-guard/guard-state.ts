/**
 * What the guard must not forget across a restart (Round 30).
 *
 * Two things the guard decides on were held in memory only (Round 29, M6 and
 * L2): the aggregate spend over the rolling window, and the submissions whose
 * outcome is unknown. A restart — a crash, a deploy, an operator's ctrl-C —
 * reset both: the window's allowance came back in full, and a request whose
 * last submission may still land was rebuilt and signed a second time. With
 * `GRAPHITE_GUARD_STATE_FILE` set, both live in an append-only file that is
 * written and fsync'd BEFORE the step it protects:
 *
 *   - a spend is recorded when it is RESERVED, before signing, and a release
 *     is recorded when nothing was sent. A crash in between counts a spend
 *     that may not have happened: the safe direction.
 *   - a submission is recorded as unresolved BEFORE its bytes are handed to
 *     the RPC, and resolved only once the RPC confirmed it. A crash in between
 *     leaves it unresolved, so the same request waits for the RPC's answer
 *     about it instead of being built again.
 *
 * The file is one JSON object per line. A line that does not parse, or names
 * a record this version does not know, refuses to start: a state file that
 * cannot be read is exactly the case where an unresolved submission could be
 * lost. One process uses one file: a lock file next to it holds the owner's
 * pid, and a second process refuses to start while that pid is alive.
 *
 * One guard per wallet (Round 32). The aggregate limit is kept per state
 * file, so two guards signing for the same key with different state files
 * (or none) each spent the whole allowance: the limit held per process, not
 * per wallet. Every guard now also takes a lock named for its wallet's
 * public key in a directory every guard on the host shares
 * (`GRAPHITE_GUARD_LOCK_DIR`, default `<tmpdir>/graphite-guard`), and a
 * second guard for the same wallet refuses to start while the first runs.
 * `GRAPHITE_GUARD_ALLOW_SHARED_WALLET=1` lets it start, logged as the limits
 * holding per guard. The lock names its owner by pid, so it sees only
 * processes that share the directory AND a pid namespace: guards on other
 * hosts or in other containers are not seen, even through a shared volume
 * (a pid from another namespace reads as dead, or as an unrelated process),
 * and their spend is not counted. One guard per wallet across hosts is the
 * operator's to arrange.
 *
 * Without the variable, the same state is kept in memory, as before, and the
 * startup log says a restart forgets it.
 */
import {
  closeSync,
  existsSync,
  fsyncSync,
  linkSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** Every lock this process holds, by path; released when the process exits. */
const HELD = new Set<string>();
let exitHooked = false;

/** Environment variable naming the guard's state file. */
export const GUARD_STATE_FILE_ENV = "GRAPHITE_GUARD_STATE_FILE";
/** The directory every guard on a host shares for its per-wallet locks (Round 32). */
export const GUARD_LOCK_DIR_ENV = "GRAPHITE_GUARD_LOCK_DIR";
/** "1": a guard may sign for a wallet another running guard holds (Round 32). */
export const GUARD_ALLOW_SHARED_WALLET_ENV = "GRAPHITE_GUARD_ALLOW_SHARED_WALLET";

/** A submission whose outcome the guard has not seen confirmed. */
export interface UnresolvedSubmission {
  signature: string;
  lastValidBlockHeight: number;
  /** Milliseconds since the epoch, when it was recorded. */
  at: number;
}

/** A claim on the aggregate limit that was not released. */
export interface ReservedSpend {
  id: string;
  lamports: bigint;
  at: number;
}

/** The state file could not be read or written; nothing is assumed about it. */
export class GuardStateError extends Error {
  constructor(message: string) {
    super(`[Graphite] guard state: ${message}`);
    this.name = "GuardStateError";
  }
}

type Line =
  | { v: 1; t: "unresolved"; key: string; signature: string; lvbh: number; at: number }
  | { v: 1; t: "resolved"; key: string; at: number }
  | { v: 1; t: "reserve"; id: string; lamports: string; at: number }
  | { v: 1; t: "release"; id: string; at: number };

function isPositiveSafeInteger(n: unknown): n is number {
  return typeof n === "number" && Number.isSafeInteger(n) && n >= 0;
}

function parseLine(text: string, where: string): Line {
  let o: unknown;
  try {
    o = JSON.parse(text);
  } catch {
    throw new GuardStateError(`${where} is not JSON. REFUSING TO START: a state file that cannot be read may hide an unresolved submission.`);
  }
  const r = o as Record<string, unknown>;
  const bad = (why: string) =>
    new GuardStateError(`${where} ${why}. REFUSING TO START: a state file that cannot be read may hide an unresolved submission.`);
  if (typeof r !== "object" || r === null || r.v !== 1) throw bad("is not a version-1 record");
  if (!isPositiveSafeInteger(r.at)) throw bad("has no valid `at`");
  switch (r.t) {
    case "unresolved":
      if (typeof r.key !== "string" || typeof r.signature !== "string" || !isPositiveSafeInteger(r.lvbh)) {
        throw bad("is not a complete `unresolved` record");
      }
      return r as Line;
    case "resolved":
      if (typeof r.key !== "string") throw bad("is not a complete `resolved` record");
      return r as Line;
    case "reserve":
      if (typeof r.id !== "string" || typeof r.lamports !== "string" || !/^\d{1,30}$/.test(r.lamports)) {
        throw bad("is not a complete `reserve` record");
      }
      return r as Line;
    case "release":
      if (typeof r.id !== "string") throw bad("is not a complete `release` record");
      return r as Line;
    default:
      throw bad(`names a record type (${JSON.stringify(r.t)}) this guard does not know`);
  }
}

/** Whether a process with this pid is running (EPERM: it is, and is someone else's). */
function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

/**
 * Take the lock at `lockPath` for this process, or throw `GuardStateError`
 * with `held(owner)` while another live process (or this one) holds it.
 *
 * The pid is written to a private file first and linked into place, so the
 * lock never exists without its owner in it: a second process that finds it
 * always reads a pid, never an empty file it would take for a crash's.
 */
function acquirePidLock(lockPath: string, held: (owner: number) => string): void {
  const tmp = `${lockPath}.${process.pid}.${Date.now()}.tmp`;
  const fd = openSync(tmp, "w", 0o600);
  try {
    writeSync(fd, String(process.pid));
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  try {
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        linkSync(tmp, lockPath);
        HELD.add(lockPath);
        if (!exitHooked) {
          exitHooked = true;
          process.once("exit", () => {
            for (const path of [...HELD]) releasePidLock(path);
          });
        }
        return;
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== "EEXIST") {
          throw new GuardStateError(`the lock ${lockPath} could not be created: ${(e as Error).message}. REFUSING TO START.`);
        }
        const owner = Number(readFileSync(lockPath, "utf8").trim());
        // This process holds it when it took it and has not released it. The
        // same pid with no hold here is an earlier incarnation that crashed
        // (in a container the guard is often pid 1 every time).
        const heldHere = owner === process.pid && HELD.has(lockPath);
        const heldElsewhere = owner !== process.pid && Number.isSafeInteger(owner) && owner > 0 && pidAlive(owner);
        if (heldHere || heldElsewhere) throw new GuardStateError(held(owner));
        // The owner is gone (a crash): the lock is stale.
        unlinkSync(lockPath);
      }
    }
    throw new GuardStateError(`the lock ${lockPath} could not be taken. REFUSING TO START.`);
  } finally {
    try {
      unlinkSync(tmp);
    } catch {
      // already gone
    }
  }
}

/** Drop a lock this process holds. Idempotent; never removes another process's. */
function releasePidLock(lockPath: string): void {
  if (!HELD.delete(lockPath)) return;
  try {
    if (readFileSync(lockPath, "utf8").trim() === String(process.pid)) unlinkSync(lockPath);
  } catch {
    // already gone
  }
}

/**
 * One guard per wallet on this host (Round 32): a lock named for the
 * wallet's public key in a directory every guard shares. See the header.
 */
export class WalletLock {
  readonly #wallet: string;
  readonly #path: string | null;

  private constructor(wallet: string, path: string | null) {
    this.#wallet = wallet;
    this.#path = path;
  }

  /**
   * Take the lock for `wallet` in `dir` (created, private, if missing).
   * Throws `GuardStateError` while another running guard holds it.
   */
  static take(wallet: string, dir: string): WalletLock {
    if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(wallet)) {
      throw new GuardStateError(`${JSON.stringify(wallet)} is not a base58 public key. REFUSING TO START.`);
    }
    if (dir.trim() === "") throw new GuardStateError(`${GUARD_LOCK_DIR_ENV} is empty. REFUSING TO START.`);
    try {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
    } catch (e) {
      throw new GuardStateError(`the lock directory ${dir} could not be created: ${(e as Error).message}. REFUSING TO START.`);
    }
    const path = join(dir, `wallet-${wallet}.lock`);
    acquirePidLock(
      path,
      (owner) =>
        `another guard (process ${owner}) is running for wallet ${wallet} (${path}). Each guard keeps its own ` +
        "aggregate spend, so two guards for one wallet could each spend the whole allowance. Stop the other " +
        `guard, or set ${GUARD_ALLOW_SHARED_WALLET_ENV}=1 to run both with limits that hold per guard, not per ` +
        "wallet. REFUSING TO START.",
    );
    return new WalletLock(wallet, path);
  }

  /** No lock: the operator allowed a shared wallet (`GRAPHITE_GUARD_ALLOW_SHARED_WALLET=1`). */
  static shared(wallet: string): WalletLock {
    return new WalletLock(wallet, null);
  }

  /** For the startup log. */
  describe(): string {
    return this.#path === null
      ? `[Graphite] wallet lock: NONE — ${GUARD_ALLOW_SHARED_WALLET_ENV}=1: other guards may sign for ${this.#wallet}, ` +
          "and the spend limits hold per guard, not per wallet"
      : `[Graphite] wallet lock: ${this.#path} — one guard per wallet on this host`;
  }

  /** Release the lock. Idempotent. */
  close(): void {
    if (this.#path !== null) releasePidLock(this.#path);
  }
}
Object.freeze(WalletLock.prototype);
Object.freeze(WalletLock);

/** Where a guard's wallet lock lives, or that the operator waived it. */
export type WalletLockPlan = { shared: true } | { shared: false; dir: string };

/**
 * The wallet lock the configuration (or, where it is silent, the
 * environment) asks for, read before anything is contacted.
 * `GRAPHITE_GUARD_ALLOW_SHARED_WALLET` is "1" or "0"; anything else refuses
 * to start.
 */
export function walletLockPlan(
  config: { lockDir?: string; allowSharedWallet?: boolean } = {},
  env: Record<string, string | undefined> = process.env,
): WalletLockPlan {
  let shared = config.allowSharedWallet;
  if (shared === undefined) {
    const raw = env[GUARD_ALLOW_SHARED_WALLET_ENV];
    if (raw !== undefined && raw !== "" && raw !== "0" && raw !== "1") {
      throw new GuardStateError(`${GUARD_ALLOW_SHARED_WALLET_ENV}=${JSON.stringify(raw)} is not "1" or "0". REFUSING TO START.`);
    }
    shared = raw === "1";
  }
  if (shared) return { shared: true };
  return { shared: false, dir: config.lockDir ?? env[GUARD_LOCK_DIR_ENV] ?? join(tmpdir(), "graphite-guard") };
}

/** Take the lock `plan` names for `wallet` (none, when the operator waived it). */
export function takeWalletLock(wallet: string, plan: WalletLockPlan): WalletLock {
  return plan.shared ? WalletLock.shared(wallet) : WalletLock.take(wallet, plan.dir);
}

export class GuardState {
  readonly #path: string | null;
  #fd: number | null = null;
  #lockPath: string | null = null;
  readonly #unresolved = new Map<string, UnresolvedSubmission>();
  readonly #reserved = new Map<string, ReservedSpend>();
  #next = 0;

  private constructor(path: string | null) {
    this.#path = path;
  }

  /** State held in this process only: a restart forgets it. */
  static inMemory(): GuardState {
    return new GuardState(null);
  }

  /**
   * Open (or create) the state file at `path`, take its lock, and replay it.
   * Throws `GuardStateError` on a file it cannot read or a lock another live
   * process holds.
   */
  static open(path: string, opts: { retainSince?: number } = {}): GuardState {
    if (path.trim() === "") throw new GuardStateError(`${GUARD_STATE_FILE_ENV} is empty. REFUSING TO START.`);
    const state = new GuardState(path);
    state.#lock(`${path}.lock`);
    try {
      if (existsSync(path)) state.#replay(readFileSync(path, "utf8"));
      // Reservations older than the aggregate window no longer count; the
      // file is rewritten with what still does, so it does not grow forever.
      // Unresolved submissions are always kept: only the RPC resolves them.
      const since = opts.retainSince ?? 0;
      for (const [id, r] of state.#reserved) if (r.at <= since) state.#reserved.delete(id);
      state.#compact();
      state.#fd = openSync(path, "a", 0o600);
    } catch (e) {
      state.close();
      if (e instanceof GuardStateError) throw e;
      throw new GuardStateError(`${path} could not be opened: ${(e as Error).message}. REFUSING TO START.`);
    }
    return state;
  }

  /** Where the state lives, for the startup log. */
  describe(): string {
    return this.#path === null
      ? `[Graphite] guard state: IN MEMORY — a restart forgets the aggregate spend and any submission whose outcome is unknown (set ${GUARD_STATE_FILE_ENV})`
      : `[Graphite] guard state: ${this.#path} (${this.#unresolved.size} unresolved submission(s), ${this.#reserved.size} reserved spend(s) replayed)`;
  }

  #lock(lockPath: string): void {
    acquirePidLock(
      lockPath,
      (owner) =>
        `${lockPath} is held by process ${owner}, which is running. One guard per state file: two would ` +
        "each spend the whole aggregate allowance. REFUSING TO START.",
    );
    this.#lockPath = lockPath;
  }

  #replay(text: string): void {
    const lines = text.split("\n");
    lines.forEach((raw, i) => {
      if (raw === "" && i === lines.length - 1) return;
      const line = parseLine(raw, `${this.#path}, line ${i + 1},`);
      switch (line.t) {
        case "unresolved":
          this.#unresolved.set(line.key, { signature: line.signature, lastValidBlockHeight: line.lvbh, at: line.at });
          break;
        case "resolved":
          this.#unresolved.delete(line.key);
          break;
        case "reserve":
          this.#reserved.set(line.id, { id: line.id, lamports: BigInt(line.lamports), at: line.at });
          break;
        case "release":
          this.#reserved.delete(line.id);
          break;
      }
    });
  }

  /** Rewrite the file with exactly the live state: a temporary file, fsync'd, renamed over it. */
  #compact(): void {
    const path = this.#path as string;
    const now = Date.now();
    const lines: Line[] = [
      ...[...this.#unresolved].map(([key, u]) => ({
        v: 1 as const, t: "unresolved" as const, key, signature: u.signature, lvbh: u.lastValidBlockHeight, at: u.at,
      })),
      ...[...this.#reserved.values()].map((r) => ({
        v: 1 as const, t: "reserve" as const, id: r.id, lamports: r.lamports.toString(), at: r.at,
      })),
    ];
    const tmp = `${path}.${process.pid}.${now}.tmp`;
    const fd = openSync(tmp, "w", 0o600);
    try {
      for (const line of lines) writeSync(fd, `${JSON.stringify(line)}\n`);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, path);
  }

  #append(line: Line): void {
    if (this.#fd === null) {
      if (this.#path !== null) throw new GuardStateError(`${this.#path} is closed.`);
      return;
    }
    try {
      writeSync(this.#fd, `${JSON.stringify(line)}\n`);
      fsyncSync(this.#fd);
    } catch (e) {
      throw new GuardStateError(`${this.#path} could not be written: ${(e as Error).message}.`);
    }
  }

  unresolved(key: string): UnresolvedSubmission | undefined {
    return this.#unresolved.get(key);
  }

  /** Record, durably, that `key`'s submission is in flight or of unknown outcome. Throws if it cannot. */
  markUnresolved(key: string, signature: string, lastValidBlockHeight: number, at: number = Date.now()): void {
    this.#append({ v: 1, t: "unresolved", key, signature, lvbh: lastValidBlockHeight, at });
    this.#unresolved.set(key, { signature, lastValidBlockHeight, at });
  }

  /** The submission is settled (confirmed, landed and failed, or expired). */
  markResolved(key: string, at: number = Date.now()): void {
    if (!this.#unresolved.has(key)) return;
    this.#unresolved.delete(key);
    this.#append({ v: 1, t: "resolved", key, at });
  }

  /** Record a reservation on the aggregate limit; returns its id. Throws if it cannot be recorded. */
  reserve(lamports: bigint, at: number): string {
    const id = `${process.pid}-${at}-${++this.#next}`;
    this.#append({ v: 1, t: "reserve", id, lamports: lamports.toString(), at });
    this.#reserved.set(id, { id, lamports, at });
    return id;
  }

  /** Nothing was sent: the reservation is returned. */
  release(id: string, at: number = Date.now()): void {
    if (!this.#reserved.delete(id)) return;
    this.#append({ v: 1, t: "release", id, at });
  }

  /** Reservations recorded after `since` (ms since the epoch). */
  reservedSince(since: number): ReservedSpend[] {
    return [...this.#reserved.values()].filter((r) => r.at > since);
  }

  /** Close the file and drop the lock. Idempotent. */
  close(): void {
    if (this.#fd !== null) {
      try {
        closeSync(this.#fd);
      } catch {
        // already closed
      }
      this.#fd = null;
    }
    if (this.#lockPath !== null) {
      releasePidLock(this.#lockPath);
      this.#lockPath = null;
    }
  }
}
Object.freeze(GuardState.prototype);
Object.freeze(GuardState);

/**
 * The state at `path` (config) or GRAPHITE_GUARD_STATE_FILE, or in-memory
 * state when neither names one. `retainSince`: reservations recorded at or
 * before this time (ms since the epoch) are outside the aggregate window.
 */
export function openGuardState(
  path: string | undefined,
  retainSince: number,
  env: Record<string, string | undefined> = process.env,
): GuardState {
  const named = path ?? env[GUARD_STATE_FILE_ENV];
  return named === undefined ? GuardState.inMemory() : GuardState.open(named, { retainSince });
}
