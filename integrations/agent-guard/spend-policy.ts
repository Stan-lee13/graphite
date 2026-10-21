/**
 * The operator's spending limits, enforced by the guard before anything is
 * built, simulated or shown to the Core.
 *
 * Graphite verifies that a transaction does what the request says, and refuses
 * what no request can make safe (drains, authority hand-overs, an intent that
 * does not describe the instruction). It cannot know whether the person behind
 * an agent wanted the request at all. In a framework integration the request
 * text is written by a model — an MCP client, an AI SDK tool call — and a
 * model can be talked into "Transfer 50 SOL to <someone>" by whatever it read.
 * The amount and the destination are the two facts that bound the damage, so
 * the operator states them here and the guard refuses anything beyond them,
 * whatever the Core would say.
 *
 * Limits only narrow: nothing here can make a transaction the Core refuses
 * executable.
 *
 * Round 29 (audit 2026-10-20, M6): a guard without a per-transaction cap used
 * to be the default — `spendPolicyFromEnv({})` is `{}` — silently, and only
 * two of the three adapters refused it. The guard itself now refuses to start
 * without `maxTransferLamports` unless the operator says, by name, that this
 * deployment runs uncapped (GRAPHITE_ALLOW_UNCAPPED=1: an accepted risk under
 * Constitution P14, logged at startup). The policy in force is logged at
 * startup either way, and an aggregate limit over a rolling window
 * (GRAPHITE_MAX_TOTAL_LAMPORTS per GRAPHITE_SPEND_WINDOW_SECONDS) bounds what
 * many capped requests add up to. The aggregate is PER GUARD PROCESS, kept in
 * memory unless GRAPHITE_GUARD_STATE_FILE names a file (Round 30, guard-state.ts).
 */
import { GuardState } from "./guard-state.js";

export interface SpendPolicy {
  /**
   * The most one transaction may take out of the wallet, in lamports: a
   * transfer's amount, or a swap's outflow as measured by simulating the
   * exact transaction (fee and wrapped SOL included). Required unless
   * `allowUncapped` (Round 29, M6).
   */
  maxTransferLamports?: bigint;
  /**
   * The only destinations a transfer may go to (base58). Unset = any
   * destination; an empty list = none (every transfer refused).
   */
  allowedDestinations?: readonly string[];
  /**
   * The most every executed transaction together may take out of the wallet
   * within `spendWindowSeconds`, in lamports (GRAPHITE_MAX_TOTAL_LAMPORTS).
   * Unset = no aggregate limit. Per guard process (durable with GRAPHITE_GUARD_STATE_FILE).
   */
  maxTotalLamports?: bigint;
  /** The aggregate's rolling window in seconds (GRAPHITE_SPEND_WINDOW_SECONDS, default 3600). */
  spendWindowSeconds?: number;
  /**
   * Run without a per-transaction cap (GRAPHITE_ALLOW_UNCAPPED=1). An accepted
   * risk the operator states by name; logged at startup.
   */
  allowUncapped?: boolean;
}

/** The aggregate window when GRAPHITE_MAX_TOTAL_LAMPORTS is set without one. */
export const DEFAULT_SPEND_WINDOW_SECONDS = 3600;

/**
 * Thrown when the operator's limits refuse a request. For a transfer that is
 * before anything is built; for a swap it is after the transaction was built
 * and simulated (its outflow is measured on the bytes) — in both cases before
 * anything is signed or sent.
 */
export class SpendPolicyRefusal extends Error {
  constructor(message: string) {
    super(`[Graphite] spend policy: ${message}. REFUSED; nothing was signed or sent.`);
    this.name = "SpendPolicyRefusal";
  }
}

const BASE58_ADDRESS = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

function lamportsFromEnv(name: string, value: string): bigint {
  if (!/^\d+$/.test(value.trim())) {
    throw new Error(
      `[Graphite] ${name}=${JSON.stringify(value)} is not a non-negative integer of lamports. REFUSING TO START.`,
    );
  }
  return BigInt(value.trim());
}

/**
 * Read the policy from GRAPHITE_MAX_TRANSFER_LAMPORTS (a non-negative integer),
 * GRAPHITE_ALLOWED_DESTINATIONS (comma-separated base58 addresses),
 * GRAPHITE_MAX_TOTAL_LAMPORTS, GRAPHITE_SPEND_WINDOW_SECONDS and
 * GRAPHITE_ALLOW_UNCAPPED ("1", or unset / "0"). A malformed value is a
 * startup error, never a silently absent limit.
 */
export function spendPolicyFromEnv(env: Record<string, string | undefined> = process.env): SpendPolicy {
  const policy: SpendPolicy = {};
  const max = env.GRAPHITE_MAX_TRANSFER_LAMPORTS;
  if (max !== undefined && max !== "") {
    policy.maxTransferLamports = lamportsFromEnv("GRAPHITE_MAX_TRANSFER_LAMPORTS", max);
  }
  const total = env.GRAPHITE_MAX_TOTAL_LAMPORTS;
  if (total !== undefined && total !== "") {
    policy.maxTotalLamports = lamportsFromEnv("GRAPHITE_MAX_TOTAL_LAMPORTS", total);
  }
  const window = env.GRAPHITE_SPEND_WINDOW_SECONDS;
  if (window !== undefined && window !== "") {
    if (!/^[1-9][0-9]{0,8}$/.test(window.trim())) {
      throw new Error(
        `[Graphite] GRAPHITE_SPEND_WINDOW_SECONDS=${JSON.stringify(window)} is not a positive integer of seconds. REFUSING TO START.`,
      );
    }
    if (policy.maxTotalLamports === undefined) {
      throw new Error(
        "[Graphite] GRAPHITE_SPEND_WINDOW_SECONDS is set without GRAPHITE_MAX_TOTAL_LAMPORTS, so it bounds nothing. REFUSING TO START.",
      );
    }
    policy.spendWindowSeconds = Number(window.trim());
  }
  const uncapped = env.GRAPHITE_ALLOW_UNCAPPED;
  if (uncapped !== undefined && uncapped !== "" && uncapped !== "0" && uncapped !== "1") {
    throw new Error(`[Graphite] GRAPHITE_ALLOW_UNCAPPED=${JSON.stringify(uncapped)} is not "1" or "0". REFUSING TO START.`);
  }
  if (uncapped === "1") policy.allowUncapped = true;
  const allowed = env.GRAPHITE_ALLOWED_DESTINATIONS;
  if (allowed !== undefined) {
    const list = allowed
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s !== "");
    for (const a of list) {
      if (!BASE58_ADDRESS.test(a)) {
        throw new Error(
          `[Graphite] GRAPHITE_ALLOWED_DESTINATIONS has ${JSON.stringify(a)}, which is not a base58 address. REFUSING TO START.`,
        );
      }
    }
    policy.allowedDestinations = list;
  }
  return policy;
}

/**
 * Refuse to start under a policy that does not bound a transaction (Round 29,
 * M6): no per-transaction cap, and no explicit `allowUncapped`.
 */
export function assertSpendPolicyUsable(policy: SpendPolicy): void {
  if (policy.maxTransferLamports === undefined && policy.allowUncapped !== true) {
    throw new Error(
      "[Graphite] no per-transaction cap is set. A request a model was talked into moves whatever it names; " +
        "set GRAPHITE_MAX_TRANSFER_LAMPORTS (or spendPolicy.maxTransferLamports), or accept running without one " +
        "by name with GRAPHITE_ALLOW_UNCAPPED=1 (spendPolicy.allowUncapped). REFUSING TO START.",
    );
  }
  if (policy.spendWindowSeconds !== undefined) {
    if (!Number.isSafeInteger(policy.spendWindowSeconds) || policy.spendWindowSeconds < 1) {
      throw new Error(`[Graphite] spendWindowSeconds ${policy.spendWindowSeconds} is not a positive integer. REFUSING TO START.`);
    }
    if (policy.maxTotalLamports === undefined) {
      throw new Error("[Graphite] spendWindowSeconds is set without maxTotalLamports, so it bounds nothing. REFUSING TO START.");
    }
  }
}

/** The startup line that states the spend policy in force (Round 29, M6). */
export function describeSpendPolicy(policy: SpendPolicy): string {
  const parts: string[] = [];
  parts.push(
    policy.maxTransferLamports !== undefined
      ? `at most ${policy.maxTransferLamports} lamports per transaction`
      : "ACCEPTED RISK (GRAPHITE_ALLOW_UNCAPPED=1): NO per-transaction cap",
  );
  parts.push(
    policy.maxTotalLamports !== undefined
      ? `at most ${policy.maxTotalLamports} lamports per ${policy.spendWindowSeconds ?? DEFAULT_SPEND_WINDOW_SECONDS} s ` +
          "across executed transactions (this guard process only)"
      : "no aggregate limit",
  );
  parts.push(
    policy.allowedDestinations === undefined
      ? "any transfer destination"
      : `transfers only to ${policy.allowedDestinations.length} allowed destination(s)`,
  );
  return `[Graphite] spend policy: ${parts.join("; ")}`;
}

/** A claim on the aggregate limit, made before signing and kept once sent. */
export interface SpendReservation {
  /** Keep it: the transaction left the process (or may have). */
  commit(): void;
  /** Return it: nothing was sent. Idempotent; a no-op after `commit`. */
  release(): void;
}

/**
 * The aggregate limit (Round 29, M6): lamports out of the wallet, over a
 * rolling window, across every transaction this process executes. A request
 * RESERVES its outflow before it is signed — synchronously, so two concurrent
 * requests cannot both fit under one remaining allowance — and the
 * reservation is released if nothing is sent. A bound on one running guard,
 * not on the wallet: another process with the same key has its own.
 *
 * Round 30: the reservations live in a `GuardState`. In memory by default (a
 * restart starts from zero, as before); with GRAPHITE_GUARD_STATE_FILE they
 * are written to disk before signing, so a restart inside the window still
 * counts what was spent in it.
 */
export class SpendLedger {
  readonly #max: bigint | undefined;
  readonly #windowMs: number;
  readonly #now: () => number;
  readonly #state: GuardState;

  constructor(policy: SpendPolicy, now: () => number = Date.now, state: GuardState = GuardState.inMemory()) {
    this.#max = policy.maxTotalLamports;
    this.#windowMs = (policy.spendWindowSeconds ?? DEFAULT_SPEND_WINDOW_SECONDS) * 1000;
    this.#now = now;
    this.#state = state;
  }

  /** Lamports counted in the current window. */
  spentInWindow(): bigint {
    const since = this.#now() - this.#windowMs;
    return this.#state.reservedSince(since).reduce((sum, e) => sum + e.lamports, 0n);
  }

  /**
   * Claim `lamports` of the window's allowance, or refuse. The check and the
   * claim are synchronous: no other request can run between them. With a
   * state file the claim is on disk before this returns, and a claim that
   * cannot be written is a refusal.
   */
  reserve(lamports: bigint): SpendReservation {
    if (this.#max === undefined) return { commit() {}, release() {} };
    const spent = this.spentInWindow();
    if (spent + lamports > this.#max) {
      throw new SpendPolicyRefusal(
        `${lamports} lamports would bring this guard's outflow in the last ${this.#windowMs / 1000} s to ` +
          `${spent + lamports}, above the aggregate limit of ${this.#max} (GRAPHITE_MAX_TOTAL_LAMPORTS)`,
      );
    }
    const state = this.#state;
    const id = state.reserve(lamports, this.#now());
    let settled = false;
    return {
      commit() {
        settled = true;
      },
      release() {
        if (!settled) {
          settled = true;
          state.release(id);
        }
      },
    };
  }
}
Object.freeze(SpendLedger.prototype);
Object.freeze(SpendLedger);

/** Refuse a transfer the policy does not allow. */
export function assertTransferAllowed(policy: SpendPolicy, destination: string, lamports: bigint): void {
  if (policy.maxTransferLamports !== undefined && lamports > policy.maxTransferLamports) {
    throw new SpendPolicyRefusal(
      `${lamports} lamports exceeds the per-transfer cap of ${policy.maxTransferLamports} (GRAPHITE_MAX_TRANSFER_LAMPORTS)`,
    );
  }
  if (policy.allowedDestinations !== undefined && !policy.allowedDestinations.includes(destination)) {
    throw new SpendPolicyRefusal(
      `${destination} is not in the allowed destinations (GRAPHITE_ALLOWED_DESTINATIONS)`,
    );
  }
}

/** What a swap takes out of the wallet, measured on the transaction itself. */
export interface MeasuredOutflow {
  lamports: bigint;
  tokens: readonly { mint: string; amount: bigint }[];
}

/**
 * Refuse a swap the policy does not allow. A swap has no destination to
 * check, so a destination list alone cannot bound it and is refused; under a
 * lamport cap the measured outflow must fit, and a token other than wrapped
 * SOL leaving the wallet cannot be priced against a lamport cap at all.
 */
export function assertSwapAllowed(policy: SpendPolicy, outflow: MeasuredOutflow): void {
  const cap = policy.maxTransferLamports;
  if (cap === undefined) {
    if (policy.allowedDestinations !== undefined) {
      throw new SpendPolicyRefusal(
        "a swap has no destination to check against GRAPHITE_ALLOWED_DESTINATIONS, and no " +
          "GRAPHITE_MAX_TRANSFER_LAMPORTS is set to bound it",
      );
    }
    return;
  }
  const priced = outflow.tokens.find((t) => t.amount > 0n);
  if (priced !== undefined) {
    throw new SpendPolicyRefusal(
      `the swap spends ${priced.amount} of token ${priced.mint} from the wallet's token accounts, which a lamport cap ` +
        "(GRAPHITE_MAX_TRANSFER_LAMPORTS) cannot bound",
    );
  }
  if (outflow.lamports > cap) {
    throw new SpendPolicyRefusal(
      `the swap takes ${outflow.lamports} lamports out of the wallet (measured on the transaction), above ` +
        `the cap of ${cap} (GRAPHITE_MAX_TRANSFER_LAMPORTS)`,
    );
  }
}
