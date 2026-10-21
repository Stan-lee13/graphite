/**
 * What the guard can execute, as data (Round 30).
 *
 * A model choosing a tool, an operator reading a deployment, and a test all
 * need the same answer to "will this be built?", and prose spread over the
 * README was not one. Everything listed `false` is refused before anything is
 * signed, by a named error (`UnsupportedCapability`) or a grounding refusal,
 * never attempted and left to fail somewhere downstream.
 */
import { SWAP_PROGRAM_IDS } from "./swap-programs.js";

export interface GuardCapabilities {
  readonly operations: {
    /** Native SOL transfer, one System Transfer instruction. */
    readonly transferSol: true;
    /** Exact-in swaps on the decoded programs only. */
    readonly swapExactIn: true;
    readonly swapExactOut: false;
    /** SPL / Token-2022 token transfers. */
    readonly tokenTransfer: false;
    /**
     * Wrapping native SOL into wrapped SOL (System transfer + SyncNative).
     * A SOL-input swap spends wrapped SOL the wallet ALREADY holds.
     */
    readonly wrapSol: false;
    /**
     * Unwrapping (SPL Token CloseAccount of the wrapped-SOL account): the
     * Core refuses CloseAccount in every transaction. A SOL-output swap
     * delivers wrapped SOL and leaves it wrapped.
     */
    readonly unwrapSol: false;
    /** Durable-nonce transactions: they do not expire, so the verify-to-sign window would not end. */
    readonly durableNonce: false;
    /** Any instruction a caller hands in that is not one of the above. */
    readonly arbitraryInstructions: false;
  };
  readonly messageVersions: {
    readonly legacy: true;
    /** v0 is built only for a swap route that names address lookup tables. */
    readonly v0: "swap-routes-with-lookup-tables";
    /** v1 (SIMD-0385) when GRAPHITE_TRANSACTION_VERSION=1. */
    readonly v1: true;
  };
  /** The programs whose swap instruction the guard decodes. */
  readonly swapPrograms: readonly string[];
}

export const GUARD_CAPABILITIES: GuardCapabilities = Object.freeze({
  operations: Object.freeze({
    transferSol: true,
    swapExactIn: true,
    swapExactOut: false,
    tokenTransfer: false,
    wrapSol: false,
    unwrapSol: false,
    durableNonce: false,
    arbitraryInstructions: false,
  } as const),
  messageVersions: Object.freeze({ legacy: true, v0: "swap-routes-with-lookup-tables", v1: true } as const),
  swapPrograms: Object.freeze([...SWAP_PROGRAM_IDS]),
});

/** A capability `GUARD_CAPABILITIES` lists as unsupported. */
export type UnsupportedCapabilityCode = "wrap_sol" | "unwrap_sol" | "swap_exact_out" | "token_transfer" | "durable_nonce";

/**
 * The request needs something the guard does not do. A refusal, not an
 * error: nothing was signed or sent, and `code` says which capability.
 */
export class UnsupportedCapability extends Error {
  readonly code: UnsupportedCapabilityCode;
  constructor(code: UnsupportedCapabilityCode, message: string) {
    super(`[Graphite] unsupported (${code}): ${message} Nothing was signed or sent.`);
    this.name = "UnsupportedCapability";
    this.code = code;
  }
}
