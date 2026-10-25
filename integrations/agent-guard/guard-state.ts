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
 * public key in a directory every guard of this OS user on the host shares
 * (`GRAPHITE_GUARD_LOCK_DIR`; the default is `defaultWalletLockDir`'s), and
 * a second guard for the same wallet refuses to start while the first runs.
 * `GRAPHITE_GUARD_ALLOW_SHARED_WALLET=1` lets it start, logged as the limits
 * holding per guard. The lock names its owner by pid, so it sees only
 * processes that share the directory AND a pid namespace: guards on other
 * hosts or in other containers are not seen, even through a shared volume
 * (a pid from another namespace reads as dead, or as an unrelated process),
 * and their spend is not counted. One guard per wallet across hosts is the
 * operator's to arrange.
 *
 * The lock is held, not just taken (Round 34). Node has no flock, fcntl lock
 * or LockFileEx without a native addon, and the guard loads none, so a lock
 * is a file, and a file can be deleted under its owner: a temp cleaner
 * (systemd-tmpfiles ages /tmp entries out after 10 days; macOS and Windows
 * Storage Sense clean their temp directories too) or an operator. The next
 * guard for the wallet then started with a full allowance while the first
 * kept spending. Now:
 *
 *   - the default directory is one no temp cleaner sweeps (since Round 38,
 *     R37-17, one per user, from the account alone; see
 *     `defaultWalletLockDir`): `~/.local/state/graphite-guard`, `~` being
 *     the home directory of this user's account entry, not `$HOME`; on
 *     Windows `<profile>\AppData\Local\graphite-guard`;
 *   - the lock file holds the owner's pid AND a random token, and the guard
 *     remembers its inode. Before every reservation and every submission it
 *     re-reads it (`assertHeld`): a lock that is gone, is another file, or
 *     says something else refuses the spend. A guard that lost its lock stops
 *     spending — the guard that took the wallet after it cannot know it
 *     exists — and only a restart takes a lock again;
 *   - a crashed owner's lock is taken over by moving it aside under a unique
 *     name and removing it only if it is still the same file with the same
 *     content; anything else is put back. Two guards that judge the same
 *     lock stale no longer both take the wallet (each deleted the other's
 *     fresh lock);
 *   - the directory must be a real directory (not a symbolic link) owned by
 *     this user with mode 0700 — an existing one is checked, not assumed —
 *     and every file this code creates is opened O_EXCL|O_NOFOLLOW under a
 *     random name. On Windows the owner and mode are NOT checked (Round 38,
 *     G2-6: a documented limitation). Windows has no uid or mode bits;
 *     its owner and access live in an ACL, which Node cannot read without a
 *     native addon, and the guard loads none. The default directory sits in
 *     the user's own profile, whose ACL admits the user, SYSTEM and the
 *     Administrators only; a `GRAPHITE_GUARD_LOCK_DIR` named on Windows is
 *     the operator's to keep private. The startup log says so.
 *
 * A directory each OS user owns means one guard per wallet per user: guards
 * for one wallet under two users are not seen by each other.
 *
 * Round 38 (R37-17): the default used to follow the session's environment —
 * `$XDG_RUNTIME_DIR`, else `/run`, else `$XDG_STATE_HOME`. An SSH login has
 * `XDG_RUNTIME_DIR` (pam_systemd sets it) and cron has not, so two guards for
 * one wallet and one user, one started from each, took locks in two
 * directories and each spent the whole aggregate allowance. The default is
 * now derived from the account (its home directory as the user database
 * holds it), never from a variable a session sets: every guard of one user
 * on one host finds the same directory. A directory the operator names
 * (`walletLockDir`, `GRAPHITE_GUARD_LOCK_DIR`) still overrides it, and is
 * then the operator's to name the same way for every guard.
 *
 * Without the variable, the same state is kept in memory, as before, and the
 * startup log says a restart forgets it.
 */
import {
  closeSync,
  constants as fsConstants,
  existsSync,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { randomBytes } from "node:crypto";
import { userInfo } from "node:os";
import { join, posix, win32 } from "node:path";

/** Opened with this, a path that is a symbolic link fails (ELOOP) instead of being followed. */
const O_NOFOLLOW = fsConstants.O_NOFOLLOW ?? 0;

/** A lock this process took: where, what it wrote, and which file it is. */
interface HeldLock {
  readonly path: string;
  readonly content: string;
  readonly dev: bigint;
  readonly ino: bigint;
}

/** Every lock this process holds; released when the process exits. */
const HELD = new Set<HeldLock>();
let exitHooked = false;

/** Environment variable naming the guard's state file. */
export const GUARD_STATE_FILE_ENV = "GRAPHITE_GUARD_STATE_FILE";
/** The directory every guard of a user on a host shares for its per-wallet locks (Round 32). */
export const GUARD_LOCK_DIR_ENV = "GRAPHITE_GUARD_LOCK_DIR";
/** "1": a guard may sign for a wallet another running guard holds (Round 32). */
export const GUARD_ALLOW_SHARED_WALLET_ENV = "GRAPHITE_GUARD_ALLOW_SHARED_WALLET";

/** A submission whose outcome the guard has not seen confirmed. */
export interface UnresolvedSubmission {
  signature: string;
  lastValidBlockHeight: number;
  /** Milliseconds since the epoch, when it was recorded. */
  at: number;
  /**
   * Round 38 (G2-4): the reservation that pays for it, returned once the
   * chain says it did not land and cannot. Absent in records written before.
   */
  reservation?: string;
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
  | { v: 1; t: "unresolved"; key: string; signature: string; lvbh: number; at: number; rid?: string }
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
      if (
        typeof r.key !== "string" ||
        typeof r.signature !== "string" ||
        !isPositiveSafeInteger(r.lvbh) ||
        (r.rid !== undefined && typeof r.rid !== "string")
      ) {
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

/** A random hex string, for tokens and private file names. */
function randomHex(): string {
  return randomBytes(16).toString("hex");
}

/** What a lock file holds and which file it is, or null when there is none at `path`. */
function readLock(path: string): { content: string; dev: bigint; ino: bigint } | null {
  let fd: number;
  try {
    fd = openSync(path, fsConstants.O_RDONLY | O_NOFOLLOW);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new GuardStateError(`the lock ${path} could not be read: ${(e as Error).message}.`);
  }
  try {
    const st = fstatSync(fd, { bigint: true });
    if (!st.isFile()) throw new GuardStateError(`the lock ${path} is not a regular file.`);
    const buf = Buffer.alloc(256);
    const n = readSync(fd, buf, 0, buf.length, 0);
    return { content: buf.subarray(0, n).toString("utf8").trim(), dev: st.dev, ino: st.ino };
  } finally {
    closeSync(fd);
  }
}

/** The pid a lock names: its first field (a lock from before Round 34 is the pid alone). */
function lockOwner(content: string): number {
  return Number(content.split(/\s+/)[0]);
}

/**
 * Remove the lock at `path` only if it is still `expected` (the same file
 * with the same content). It is renamed aside under a unique name first —
 * atomically, so no other process can be between the check and the removal
 * — and re-read there; a file that is not `expected` (another guard's lock
 * that replaced it since it was read) is linked back into place.
 */
function removeIfSame(path: string, expected: { content: string; dev: bigint; ino: bigint }): void {
  const aside = `${path}.${randomHex()}.aside`;
  try {
    renameSync(path, aside);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return;
    throw e;
  }
  let moved: { content: string; dev: bigint; ino: bigint } | null = null;
  try {
    moved = readLock(aside);
  } catch {
    // not a lock file: not the one expected, so it goes back
  }
  if (!(moved && moved.dev === expected.dev && moved.ino === expected.ino && moved.content === expected.content)) {
    try {
      // Back where it was, the same file: its owner's `assertHeld` still
      // passes. EEXIST means a third process took the path meanwhile; the
      // moved lock's owner then finds its lock gone and stops spending.
      linkSync(aside, path);
    } catch {
      // see above
    }
  }
  unlinkSync(aside);
}

/**
 * Take the lock at `lockPath` for this process, or throw `GuardStateError`
 * with `held(owner)` while another live process (or this one) holds it.
 *
 * The pid and a random token are written to a private file first (O_EXCL,
 * O_NOFOLLOW, a random name) and linked into place, so the lock never exists
 * without its owner in it: a second process that finds it always reads a
 * pid, never an empty file it would take for a crash's.
 */
function acquirePidLock(lockPath: string, held: (owner: number) => string): HeldLock {
  const token = randomHex();
  const content = `${process.pid} ${token}`;
  const tmp = `${lockPath}.${token}.tmp`;
  let mine: { dev: bigint; ino: bigint };
  try {
    const fd = openSync(tmp, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | O_NOFOLLOW, 0o600);
    try {
      writeSync(fd, content);
      fsyncSync(fd);
      const st = fstatSync(fd, { bigint: true });
      mine = { dev: st.dev, ino: st.ino };
    } finally {
      closeSync(fd);
    }
  } catch (e) {
    throw new GuardStateError(`the lock ${lockPath} could not be created: ${(e as Error).message}. REFUSING TO START.`);
  }
  try {
    for (let attempt = 0; attempt < 8; attempt++) {
      try {
        linkSync(tmp, lockPath);
        const lock: HeldLock = Object.freeze({ path: lockPath, content, ...mine });
        HELD.add(lock);
        if (!exitHooked) {
          exitHooked = true;
          process.once("exit", () => {
            for (const l of [...HELD]) releasePidLock(l);
          });
        }
        return lock;
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== "EEXIST") {
          throw new GuardStateError(`the lock ${lockPath} could not be created: ${(e as Error).message}. REFUSING TO START.`);
        }
      }
      const current = readLock(lockPath);
      if (current === null) continue; // released meanwhile: try again
      const owner = lockOwner(current.content);
      // This process holds it when it is one of the locks it took. The same
      // pid in a file this process did not take is an earlier incarnation
      // that crashed (in a container the guard is often pid 1 every time).
      const heldHere = [...HELD].some((l) => l.path === lockPath && l.dev === current.dev && l.ino === current.ino);
      const heldElsewhere = owner !== process.pid && Number.isSafeInteger(owner) && owner > 0 && pidAlive(owner);
      if (heldHere || heldElsewhere) throw new GuardStateError(held(owner));
      // The owner is gone (a crash): the lock is stale. Remove exactly that
      // file, never one another contender has put there since.
      removeIfSame(lockPath, current);
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
function releasePidLock(lock: HeldLock): void {
  if (!HELD.delete(lock)) return;
  try {
    removeIfSame(lock.path, lock);
  } catch {
    // already gone, or not ours to remove
  }
}

/**
 * Refuse unless the lock this process took is still in place: the same file
 * (device and inode) with the same pid and token in it.
 */
function assertLockHeld(lock: HeldLock, what: string): void {
  let current: { content: string; dev: bigint; ino: bigint } | null;
  let unreadable: string | null = null;
  try {
    current = readLock(lock.path);
  } catch (e) {
    current = null;
    unreadable = (e as Error).message;
  }
  const why =
    current === null
      ? unreadable !== null
        ? `it cannot be read (${unreadable})`
        : "it is gone (a temp cleaner or an operator deleted it?)"
      : current.dev !== lock.dev || current.ino !== lock.ino
        ? "another file is in its place"
        : current.content !== lock.content
          ? `it now reads ${JSON.stringify(current.content.slice(0, 80))}`
          : null;
  if (why === null) return;
  throw new GuardStateError(
    `${what} ${lock.path} is no longer this guard's: ${why}. Another guard may have started for this wallet with ` +
      "its own allowance, and this one cannot know. REFUSING TO SPEND; restart this guard to take the lock again.",
  );
}

/**
 * Refuse unless `dir` is a real directory (not a symbolic link) owned by
 * `euid` with no access for anyone else (mode 0700). On Windows only the
 * first is checked: there is no uid or mode to compare.
 */
export function assertPrivateDirectory(dir: string, euid: number | undefined = process.geteuid?.()): void {
  let st;
  try {
    st = lstatSync(dir);
  } catch (e) {
    throw new GuardStateError(`the lock directory ${dir} could not be read: ${(e as Error).message}. REFUSING TO START.`);
  }
  if (st.isSymbolicLink()) {
    throw new GuardStateError(`the lock directory ${dir} is a symbolic link. Name the directory itself. REFUSING TO START.`);
  }
  if (!st.isDirectory()) throw new GuardStateError(`the lock directory ${dir} is not a directory. REFUSING TO START.`);
  if (process.platform === "win32" || euid === undefined) return;
  if (st.uid !== euid) {
    throw new GuardStateError(
      `the lock directory ${dir} is owned by uid ${st.uid}, not this user (uid ${euid}): another user could remove ` +
        "or plant this guard's locks. Use a directory of this user's. REFUSING TO START.",
    );
  }
  const mode = st.mode & 0o777;
  if (mode !== 0o700) {
    throw new GuardStateError(
      `the lock directory ${dir} has mode 0${mode.toString(8)}, not 0700: other users could remove or plant this ` +
        `guard's locks. \`chmod 700 ${dir}\`, or use another directory. REFUSING TO START.`,
    );
  }
}

/**
 * One guard per wallet on this host (Round 32): a lock named for the
 * wallet's public key in a directory every guard shares. See the header.
 */
export class WalletLock {
  readonly #wallet: string;
  readonly #path: string | null;
  #held: HeldLock | null;

  private constructor(wallet: string, path: string | null, held: HeldLock | null) {
    this.#wallet = wallet;
    this.#path = path;
    this.#held = held;
  }

  /**
   * Take the lock for `wallet` in `dir` (created, private, if missing; an
   * existing one must already be private). Throws `GuardStateError` while
   * another running guard holds it.
   */
  static take(wallet: string, dir: string): WalletLock {
    if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(wallet)) {
      throw new GuardStateError(`${JSON.stringify(wallet)} is not a base58 public key. REFUSING TO START.`);
    }
    if (dir.trim() === "") throw new GuardStateError(`${GUARD_LOCK_DIR_ENV} is empty. REFUSING TO START.`);
    try {
      // The mode applies to directories this creates; an existing one is
      // checked below, never assumed.
      mkdirSync(dir, { recursive: true, mode: 0o700 });
    } catch (e) {
      throw new GuardStateError(`the lock directory ${dir} could not be created: ${(e as Error).message}. REFUSING TO START.`);
    }
    assertPrivateDirectory(dir);
    const path = join(dir, `wallet-${wallet}.lock`);
    const held = acquirePidLock(
      path,
      (owner) =>
        `another guard (process ${owner}) is running for wallet ${wallet} (${path}). Each guard keeps its own ` +
        "aggregate spend, so two guards for one wallet could each spend the whole allowance. Stop the other " +
        `guard, or set ${GUARD_ALLOW_SHARED_WALLET_ENV}=1 to run both with limits that hold per guard, not per ` +
        "wallet. REFUSING TO START.",
    );
    return new WalletLock(wallet, path, held);
  }

  /** No lock: the operator allowed a shared wallet (`GRAPHITE_GUARD_ALLOW_SHARED_WALLET=1`). */
  static shared(wallet: string): WalletLock {
    return new WalletLock(wallet, null, null);
  }

  /** For the startup log. */
  describe(): string {
    return this.#path === null
      ? `[Graphite] wallet lock: NONE — ${GUARD_ALLOW_SHARED_WALLET_ENV}=1: other guards may sign for ${this.#wallet}, ` +
          "and the spend limits hold per guard, not per wallet"
      : `[Graphite] wallet lock: ${this.#path} — one guard per wallet on this host, re-checked before every spend` +
          (process.platform === "win32"
            ? " (on Windows the directory's owner and access are not checked: keep it private to this user)"
            : "");
  }

  /**
   * Refuse (`GuardStateError`) unless this guard still holds its wallet's
   * lock (Round 34): the same file, with this guard's pid and token in it.
   * Nothing to check for a shared wallet; a closed lock is not held.
   */
  assertHeld(): void {
    if (this.#path === null) return;
    if (this.#held === null) throw new GuardStateError(`the wallet lock ${this.#path} was released. REFUSING TO SPEND.`);
    assertLockHeld(this.#held, "the wallet lock");
  }

  /** Release the lock. Idempotent. */
  close(): void {
    if (this.#held !== null) {
      releasePidLock(this.#held);
      this.#held = null;
    }
  }
}
Object.freeze(WalletLock.prototype);
Object.freeze(WalletLock);

/** Where a guard's wallet lock lives, or that the operator waived it. */
export type WalletLockPlan = { shared: true } | { shared: false; dir: string };

/**
 * The wallet-lock directory when neither the configuration nor
 * `GRAPHITE_GUARD_LOCK_DIR` names one: one per user, derived from the
 * account alone (Round 38, R37-17), never from the session's environment.
 *
 *   - Linux, macOS and the other Unixes: `<home>/.local/state/graphite-guard`.
 *   - Windows: `<profile>\AppData\Local\graphite-guard`.
 *
 * `<home>` is the home directory of this process's effective user as the
 * user database holds it (`os.userInfo()`: getpwuid_r on Unix, the token's
 * profile directory on Windows), NOT `$HOME`, `$XDG_RUNTIME_DIR`,
 * `$XDG_STATE_HOME` or `%LOCALAPPDATA%`: an SSH session, cron, systemd,
 * `sudo -E` and a container set those differently for the same user, and
 * two guards for one wallet that found two directories each kept a full
 * allowance. It is never the system temp directory (Round 34: temp cleaners
 * delete what is in it), and it is not emptied at reboot: a lock left by a
 * crash names a pid that may later be some other process's, and then a guard
 * refuses to start naming the file, until it is removed. An account with no
 * home directory, or a relative one, refuses to start: name a directory.
 *
 * The directory is created owner-only (0700) and an existing one is checked
 * (`assertPrivateDirectory`) before any lock is taken in it.
 */
export function defaultWalletLockDir(
  o: { platform?: NodeJS.Platform; userInfo?: () => { homedir: string } } = {},
): string {
  const platform = o.platform ?? process.platform;
  const path = platform === "win32" ? win32 : posix;
  let home: unknown;
  let why = "";
  try {
    home = (o.userInfo ?? (() => userInfo()))().homedir;
  } catch (e) {
    why = ` (${(e as Error).message})`;
  }
  if (typeof home !== "string" || home === "" || !path.isAbsolute(home)) {
    throw new GuardStateError(
      `this user's account has no absolute home directory${why}, so there is no default wallet-lock directory. ` +
        `Set ${GUARD_LOCK_DIR_ENV} to a directory of this user's that nothing cleans, the same for every guard of ` +
        "this user. REFUSING TO START.",
    );
  }
  return platform === "win32"
    ? path.join(home, "AppData", "Local", "graphite-guard")
    : path.join(home, ".local", "state", "graphite-guard");
}

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
  // Round 38 (R37-17): the default reads no variable of the session.
  return { shared: false, dir: config.lockDir ?? env[GUARD_LOCK_DIR_ENV] ?? defaultWalletLockDir() };
}

/** Take the lock `plan` names for `wallet` (none, when the operator waived it). */
export function takeWalletLock(wallet: string, plan: WalletLockPlan): WalletLock {
  return plan.shared ? WalletLock.shared(wallet) : WalletLock.take(wallet, plan.dir);
}

export class GuardState {
  readonly #path: string | null;
  #fd: number | null = null;
  #held: HeldLock | null = null;
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
    this.#held = acquirePidLock(
      lockPath,
      (owner) =>
        `${lockPath} is held by process ${owner}, which is running. One guard per state file: two would ` +
        "each spend the whole aggregate allowance. REFUSING TO START.",
    );
  }

  /**
   * Refuse (`GuardStateError`) unless this process still holds the state
   * file's lock (Round 34): the same file, with its pid and token in it.
   * In-memory state has no lock.
   */
  assertHeld(): void {
    if (this.#path === null) return;
    if (this.#held === null) throw new GuardStateError(`${this.#path} is closed. REFUSING TO SPEND.`);
    assertLockHeld(this.#held, "the state file's lock");
  }

  #replay(text: string): void {
    const lines = text.split("\n");
    lines.forEach((raw, i) => {
      if (raw === "" && i === lines.length - 1) return;
      const line = parseLine(raw, `${this.#path}, line ${i + 1},`);
      switch (line.t) {
        case "unresolved":
          this.#unresolved.set(line.key, {
            signature: line.signature,
            lastValidBlockHeight: line.lvbh,
            at: line.at,
            ...(line.rid !== undefined ? { reservation: line.rid } : {}),
          });
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
    const lines: Line[] = [
      ...[...this.#unresolved].map(([key, u]) => ({
        v: 1 as const, t: "unresolved" as const, key, signature: u.signature, lvbh: u.lastValidBlockHeight, at: u.at,
        ...(u.reservation !== undefined ? { rid: u.reservation } : {}),
      })),
      ...[...this.#reserved.values()].map((r) => ({
        v: 1 as const, t: "reserve" as const, id: r.id, lamports: r.lamports.toString(), at: r.at,
      })),
    ];
    // Round 34: a random name, created exclusively and never through a
    // symbolic link. `<path>.<pid>.<now>.tmp` could be predicted, and a
    // symlink planted there had this write go wherever it pointed.
    const tmp = `${path}.${randomHex()}.tmp`;
    const fd = openSync(tmp, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | O_NOFOLLOW, 0o600);
    try {
      try {
        for (const line of lines) writeSync(fd, `${JSON.stringify(line)}\n`);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      renameSync(tmp, path);
    } catch (e) {
      try {
        unlinkSync(tmp);
      } catch {
        // renamed, or never written
      }
      throw e;
    }
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

  /** Every unresolved submission, by key (a copy). */
  unresolvedEntries(): [string, UnresolvedSubmission][] {
    return [...this.#unresolved].map(([key, u]) => [key, { ...u }]);
  }

  /**
   * Record, durably, that `key`'s submission is in flight or of unknown
   * outcome, and which reservation pays for it. Throws if it cannot.
   */
  markUnresolved(
    key: string,
    signature: string,
    lastValidBlockHeight: number,
    at: number = Date.now(),
    reservation?: string,
  ): void {
    this.#append({
      v: 1, t: "unresolved", key, signature, lvbh: lastValidBlockHeight, at,
      ...(reservation !== undefined ? { rid: reservation } : {}),
    });
    this.#unresolved.set(key, { signature, lastValidBlockHeight, at, ...(reservation !== undefined ? { reservation } : {}) });
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
    if (this.#held !== null) {
      releasePidLock(this.#held);
      this.#held = null;
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
