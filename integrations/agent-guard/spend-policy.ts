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
 */

export interface SpendPolicy {
  /**
   * The most one transaction may take out of the wallet, in lamports: a
   * transfer's amount, or a swap's outflow as measured by simulating the
   * exact transaction (fee and wrapped SOL included). Unset = no cap.
   */
  maxTransferLamports?: bigint;
  /**
   * The only destinations a transfer may go to (base58). Unset = any
   * destination; an empty list = none (every transfer refused).
   */
  allowedDestinations?: readonly string[];
}

/** Thrown before anything is built or sent. */
export class SpendPolicyRefusal extends Error {
  constructor(message: string) {
    super(`[Graphite] spend policy: ${message}. REFUSED before anything was built or sent.`);
    this.name = "SpendPolicyRefusal";
  }
}

const BASE58_ADDRESS = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

/**
 * Read the policy from GRAPHITE_MAX_TRANSFER_LAMPORTS (a non-negative integer)
 * and GRAPHITE_ALLOWED_DESTINATIONS (comma-separated base58 addresses). A
 * malformed value is a startup error, never a silently absent limit.
 */
export function spendPolicyFromEnv(env: Record<string, string | undefined> = process.env): SpendPolicy {
  const policy: SpendPolicy = {};
  const max = env.GRAPHITE_MAX_TRANSFER_LAMPORTS;
  if (max !== undefined && max !== "") {
    if (!/^\d+$/.test(max.trim())) {
      throw new Error(
        `[Graphite] GRAPHITE_MAX_TRANSFER_LAMPORTS=${JSON.stringify(max)} is not a non-negative integer of lamports. REFUSING TO START.`,
      );
    }
    policy.maxTransferLamports = BigInt(max.trim());
  }
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
  tokens: readonly { mint: string; account: string; amount: bigint }[];
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
      `the swap spends ${priced.amount} of token ${priced.mint} from ${priced.account}, which a lamport cap ` +
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
