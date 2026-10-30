/**
 * A helper process for `guard-round39.test.ts` (not a test itself): a guard
 * process that is killed in the middle of a submission (Round 39, campaign
 * 11, process crash). It takes the wallet's lock and the state file's, records
 * a reservation and an unresolved submission exactly as the guard does
 * immediately before the bytes leave (`#signSubmitAndConfirm`'s
 * `beforeSubmit`), says "marked <pid>", and then waits to be SIGKILLed: no
 * exit hook, no close, nothing released.
 *
 *   tsx guard-crash-child.ts <wallet> <lock dir> <state file> <key> <signature>
 */
import { GuardState, WalletLock } from "./guard-state.js";

const [wallet, lockDir, stateFile, key, signature] = process.argv.slice(2);
const lock = WalletLock.take(wallet, lockDir);
const state = GuardState.open(stateFile);
const reservation = state.reserve(1_000_005_000n, Date.now());
state.markUnresolved(key, signature, 1_000, Date.now(), reservation);
process.stdout.write(`marked ${process.pid}\n`);
// Held open until the parent kills this process.
setInterval(() => lock.assertHeld(), 1_000);
