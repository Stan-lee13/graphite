/**
 * Round 40 (assurance): what the guard checks about its lock directory and
 * state file on every platform, Windows included — the branches Round 39
 * could only reason about (R39-CLIENTS-6, G2-6), now run by CI's
 * `agent-guard-windows` job as well as on Linux.
 *
 * On Windows the guard checks KINDS: a lock directory that is a link
 * (symbolic link or junction) or not a directory refuses, and so does a state
 * file that is a link or not a regular file. It does not check the owner or
 * the access of either — Windows keeps them in an ACL, which Node cannot read
 * without a native addon (the documented limitation), and the startup line
 * says so. On POSIX the owner and mode are checked as well; the tests here
 * pin both halves of that branch on whichever platform runs them.
 *
 * Links are made as junctions ("junction" is ignored off Windows, where a
 * directory symlink is made): a junction needs no privilege on Windows, and
 * Node reports it as a symbolic link there, so the refusal is exercised
 * without depending on the runner's right to create symlinks.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Keypair } from "@solana/web3.js";
import { GuardState, GuardStateError, WalletLock, assertPrivateDirectory, assertPrivateStateLocation } from "./guard-state.js";

const WINDOWS = process.platform === "win32";
const tmp = () => mkdtempSync(join(tmpdir(), "graphite-r40-"));
/** A uid that is not this user's (on Windows there is none to compare). */
const FOREIGN = (process.geteuid?.() ?? 0) + 1;
const wallet = () => Keypair.generate().publicKey.toBase58();

test("lock dir (every platform): a link or a file is not a lock directory; nothing is written through it", () => {
  const root = tmp();
  try {
    const real = join(root, "real");
    mkdirSync(real, { mode: 0o700 });
    const link = join(root, "link");
    symlinkSync(real, link, "junction");
    assert.throws(() => WalletLock.take(wallet(), link), (e: unknown) => {
      assert.ok(e instanceof GuardStateError, String(e));
      assert.match((e as Error).message, /is a symbolic link.*REFUSING TO START/s);
      return true;
    });
    assert.deepEqual(readdirSync(real), [], "no lock was written through the link");
    const file = join(root, "a-file");
    writeFileSync(file, "");
    assert.throws(() => assertPrivateDirectory(file), /is not a directory.*REFUSING TO START/s);
    // Control: the real directory is a lock directory, and its lock is released.
    const w = wallet();
    const lock = WalletLock.take(w, real);
    assert.match(readFileSync(join(real, `wallet-${w}.lock`), "utf8"), new RegExp(`^${process.pid} [0-9a-f]{32}$`));
    lock.close();
    assert.deepEqual(readdirSync(real), []);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("lock dir: owner and access are checked on POSIX and not on Windows, and the startup line says which", () => {
  const root = tmp();
  try {
    const dir = join(root, "locks");
    mkdirSync(dir, { mode: 0o700 });
    if (WINDOWS) {
      // The documented limitation: no uid, no mode — a foreign "owner"
      // cannot even be expressed, so nothing is refused for it.
      assertPrivateDirectory(dir, FOREIGN);
    } else {
      assert.throws(() => assertPrivateDirectory(dir, FOREIGN), /is owned by uid \d+, not this user/);
    }
    assertPrivateDirectory(dir);
    const lock = WalletLock.take(wallet(), dir);
    try {
      assert.equal(
        lock.describe().includes("on Windows the directory's owner and access are not checked"),
        WINDOWS,
        lock.describe(),
      );
    } finally {
      lock.close();
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("state file (every platform): a directory or a link at its path refuses to start; a regular file opens", () => {
  const root = tmp();
  try {
    const dir = join(root, "state");
    mkdirSync(dir, { mode: 0o700 });
    // A directory where the file should be.
    const notAFile = join(dir, "guard.state");
    mkdirSync(notAFile);
    assert.throws(() => GuardState.open(notAFile), /is not a regular file.*REFUSING TO START/s);
    // A link where the file should be.
    const target = join(root, "elsewhere");
    mkdirSync(target);
    const link = join(dir, "link.state");
    symlinkSync(target, link, "junction");
    assert.throws(() => GuardState.open(link), /is a symbolic link.*REFUSING TO START/s);
    // A refused open locked nothing and created nothing.
    assert.deepEqual(readdirSync(dir).sort(), ["guard.state", "link.state"]);
    // Control: a regular file opens, and opens again after the guard wrote it.
    const path = join(dir, "real.state");
    const s = GuardState.open(path);
    s.reserve(5n, Date.now());
    s.close();
    const again = GuardState.open(path);
    try {
      assert.deepEqual(again.reservedSince(0).map((r) => r.lamports), [5n]);
    } finally {
      again.close();
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("state file: its directory's owner is checked on POSIX and not on Windows", () => {
  const root = tmp();
  try {
    const dir = join(root, "state");
    mkdirSync(dir, { mode: 0o700 });
    const path = join(dir, "guard.state");
    if (WINDOWS) {
      assertPrivateStateLocation(path, FOREIGN);
    } else {
      assert.throws(() => assertPrivateStateLocation(path, FOREIGN), /owned by uid \d+, not this user/);
    }
    assertPrivateStateLocation(path);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("every platform skip in this package says why, through posixOnly", () => {
  // A bare `skip: true` or `skip: process.platform === ...` hides why a test
  // did not run; CI's Windows job counts `posixOnly(` uses as the skips it allows.
  const dir = new URL("./", import.meta.url);
  const files = readdirSync(dir).filter((f) => f.endsWith(".test.ts"));
  assert.ok(files.length >= 20, `${files.length} test files`);
  const bare: string[] = [];
  let reasoned = 0;
  for (const f of files) {
    const src = readFileSync(new URL(f, dir), "utf8");
    for (const m of src.matchAll(/\{\s*skip:\s*([^,}\n]+)/g)) {
      if (m[1].startsWith("posixOnly(\"")) reasoned++;
      else bare.push(`${f}: skip: ${m[1]}`);
    }
  }
  assert.deepEqual(bare, []);
  assert.ok(reasoned >= 1, "the POSIX-only tests are marked");
});
