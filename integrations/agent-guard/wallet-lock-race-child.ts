/**
 * A helper process for `wallet-lock-integrity.test.ts` (not a test itself):
 * one contender in the stale-lock takeover race. It reads commands from stdin,
 * one per line, and answers each on stdout:
 *
 *   go <epoch-ms>  spin until that instant, then try to take the wallet lock;
 *                  answers "acquired" or "refused"
 *   check          answers "held" when the lock this process took is still its
 *                  own, "lost" when it is not, "none" when it took none
 *   release        drops any lock it holds; answers "released"
 *
 * It announces itself with "ready <pid>" (its own pid: it runs under tsx, so
 * it is not the pid its parent spawned). The wallet and the lock directory
 * are its two arguments.
 */
import { createInterface } from "node:readline";
import { performance } from "node:perf_hooks";
import { WalletLock } from "./guard-state.js";

const [wallet, dir] = process.argv.slice(2);
let lock: WalletLock | null = null;

function now(): number {
  return performance.timeOrigin + performance.now();
}

const rl = createInterface({ input: process.stdin });
rl.on("line", (line) => {
  const [cmd, arg] = line.trim().split(" ");
  if (cmd === "go") {
    const at = Number(arg);
    while (now() < at) {
      // the barrier: both contenders start within the same instant
    }
    try {
      lock = WalletLock.take(wallet, dir);
      process.stdout.write("acquired\n");
    } catch {
      lock = null;
      process.stdout.write("refused\n");
    }
  } else if (cmd === "check") {
    if (lock === null) {
      process.stdout.write("none\n");
    } else {
      const held = lock as unknown as { assertHeld?: () => void };
      try {
        // A guard that predates `assertHeld` cannot tell; it believes it holds.
        held.assertHeld?.();
        process.stdout.write("held\n");
      } catch {
        process.stdout.write("lost\n");
      }
    }
  } else if (cmd === "release") {
    lock?.close();
    lock = null;
    process.stdout.write("released\n");
  } else if (cmd === "exit") {
    rl.close();
    process.exit(0);
  }
});
process.stdout.write(`ready ${process.pid}\n`);
