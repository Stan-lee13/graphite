/**
 * GraphiteGuard — the verification gate between an AI agent and a Solana
 * signing key, independent of any agent framework (R-P8 phase 3).
 *
 * Architecture (Constitution P1: AI assists, never decides):
 *   NL -> AI layer (advisory parse) -> grounding in the user's own text ->
 *   build ONE transaction -> RPC simulate (unsigned) -> Graphite verify ->
 *   residual policy -> sign the approved bytes -> trail -> submit -> L8
 *
 * Every framework adapter (Solana Agent Kit, the Vercel AI SDK tools, the MCP
 * server) drives this class and nothing else that can sign. It used to live
 * inside the SAK bridge, which made every user of it depend on the
 * `solana-agent-kit` package and its `@solana/spl-token` 0.4 tree (the last
 * gated npm advisory, `bigint-buffer`). It depends on `@solana/kit`,
 * `@solana/web3.js` and `bs58` only.
 *
 *   1. RPC SIMULATION is UNSIGNED (Round 19, F-19-C1 — see rpc-simulator.ts):
 *      nothing is signed before a verdict exists. Its numbers are advisory:
 *      the Core zeroes request-body evidence (Constitution G4) and runs its
 *      own simulation of the artifact.
 *   2. ONE TRANSACTION (BoundTransaction): the bytes Graphite verifies are the
 *      bytes that are signed and submitted; the digest is re-checked before
 *      signing and the signed message is compared with the verified one.
 *   3. AUDITBIND re-computes the Core's content_hash over the live
 *      instruction as a secondary, instruction-level check.
 *   4. The key lives in an ES private field; the only code that signs with it
 *      is BoundTransaction.signApproved, after an artifact-bound approval the
 *      residual policy accepts.
 */

// `sendAndConfirmTransaction` is deliberately NOT imported: it prepares the
// transaction it is given, including fetching a blockhash when one is missing,
// and a mutation after approval is a mutation however benign. Signing goes
// through `signSubmitAndConfirm`, which submits bytes that are already final.
import {
  AddressLookupTableAccount,
  Connection,
  SystemProgram,
  PublicKey,
  TransactionInstruction,
  type SignatureStatus,
} from "@solana/web3.js";
import { createKeyPairFromBytes, getAddressFromPublicKey } from "@solana/kit";
import bs58 from "bs58";

// Round 19 (F-19-C1): simulation is unsigned by construction; the class
// lives in its own dependency-light module so its tests run without SAK.
import {
  RpcSimulator,
  assertEverySignatureSlotEmpty,
  capturedFetch,
  connectionWithoutRedirects,
  noRedirectFetch,
  readJsonBounded,
} from "./rpc-simulator.js";
// Round 35 (F-014): the one bounded transport every RPC request goes through.
import {
  BoundedConnection,
  DEFAULT_RPC_TIMEOUT_MS,
  MAX_RPC_TIMEOUT_MS,
  RpcTransportRefusal,
  resolveRpcTimeoutMs,
} from "./rpc-transport.js";
export { BoundedConnection, DEFAULT_RPC_TIMEOUT_MS, MAX_RPC_TIMEOUT_MS, RpcTransportRefusal };
// Round 30: what the guard can build, as data, and the refusal for the rest.
import { GUARD_CAPABILITIES, UnsupportedCapability, type GuardCapabilities } from "./capabilities.js";
export { GUARD_CAPABILITIES, UnsupportedCapability, type GuardCapabilities };
// Round 30: the aggregate spend and unresolved submissions, durable on request.
import {
  GuardState,
  GuardStateError,
  openGuardState,
  takeWalletLock,
  walletLockPlan,
  WalletLock,
  GUARD_ALLOW_SHARED_WALLET_ENV,
  GUARD_LOCK_DIR_ENV,
  GUARD_STATE_FILE_ENV,
  type UnresolvedSubmission,
} from "./guard-state.js";
export { GuardState, GuardStateError, WalletLock, GUARD_ALLOW_SHARED_WALLET_ENV, GUARD_LOCK_DIR_ENV, GUARD_STATE_FILE_ENV };
export { RpcSimulator, assertEverySignatureSlotEmpty };
// Round 19 (F-19-C5): the AI layer's answer is checked against the user's text.
import {
  assertAffirmative,
  assertEcho,
  assertSwapEffectMatches,
  groundSwapIntent,
  groundSwapRequest,
  groundTransferClass,
  groundTransferIntent,
  IntentGroundingError,
  NATIVE_MINT,
  type WalletEffect,
} from "./intent-grounding.js";
export {
  assertAffirmative,
  assertEcho,
  assertSwapEffectMatches,
  groundSwapIntent,
  groundSwapRequest,
  groundTransferClass,
  groundTransferIntent,
  IntentGroundingError,
};
// The operator's spending limits.
import {
  assertOutflowAllowed,
  assertSpendPolicyUsable,
  assertSwapAllowed,
  assertTransferAllowed,
  describeSpendPolicy,
  spendPolicyFromEnv,
  DEFAULT_SPEND_WINDOW_SECONDS,
  SpendLedger,
  SpendPolicyRefusal,
  type SpendPolicy,
  type MeasuredTransferOutflow,
  type SpendReservation,
} from "./spend-policy.js";
export { assertSwapAllowed, assertTransferAllowed, spendPolicyFromEnv, SpendPolicyRefusal, type SpendPolicy };
// Round 32: the fee a message makes its fee payer pay, read from its bytes.
import { transactionFee } from "./fees.js";
export { transactionFee };
// A5-01 / Round 29 (L3): the programs a swap payload may be addressed to —
// exactly those whose swap instruction the guard decodes.
import { SWAP_PROGRAM_IDS } from "./swap-programs.js";
export { SWAP_PROGRAM_IDS };
// Round 29 (H2 + H4): the route's own amounts, read from its data, and what
// they must be worth.
import { decodeSwapInstruction, normalizeDiscriminator, SwapRouteRefusal } from "./swap-instructions.js";
export { SwapRouteRefusal };
import {
  assertSwapEconomics,
  assertSwapPolicyUsable,
  describeSwapPolicy,
  swapPolicyFromEnv,
  type SwapEconomics,
  type SwapPolicy,
} from "./swap-economics.js";
export { swapPolicyFromEnv, type SwapPolicy };
// Round 29 (L4): the compute budget and output account the guard builds around a swap.
import {
  assertSwapEnvelopeUsable,
  buildSwapEnvelope,
  maxPriorityFeeLamports,
  swapEnvelopeFromEnv,
  type SwapEnvelopeConfig,
} from "./swap-envelope.js";
export { swapEnvelopeFromEnv, type SwapEnvelopeConfig };
import {
  ConfirmationDeclined,
  DEFAULT_CONFIRM_TIMEOUT_MS,
  DEFAULT_MAX_VERDICT_AGE_MS,
  MAX_MAX_VERDICT_AGE_MS,
  StaleVerdict,
  SubmissionNotSent,
  SubmissionOutcomeUnknown,
} from "./execution-lifecycle.js";
export {
  ConfirmationDeclined,
  DEFAULT_CONFIRM_TIMEOUT_MS,
  DEFAULT_MAX_VERDICT_AGE_MS,
  MAX_MAX_VERDICT_AGE_MS,
  StaleVerdict,
  SubmissionNotSent,
  SubmissionOutcomeUnknown,
};

// AuditBind lives in ./auditbind.ts — a dependency-free module (Node crypto
// only) so its cross-language pinned-vector tests run without the SAK tree.
import { AuditBind } from "./auditbind.js";
export { AuditBind };

// Graphite TS SDK
import { GraphiteClient, assertSecureBaseUrl } from "../../sdk/typescript/src/client.js";
import { ResidualPolicy, ResidualPolicyRefusal } from "./residual-policy.js";
export { ResidualPolicyRefusal };
import { executeBoundTransaction, type ExecutionLifecycle, type SubmitConnection } from "./execution-lifecycle.js";
import type {
  VerificationInput,
  VerificationResult,
  ProposedIntent,
  WalletProfile,
} from "../../sdk/typescript/src/types.js";

// Re-export types
export type { VerificationResult, VerificationInput, ProposedIntent, WalletProfile };

// TOCTOU closure for the swap payload path (P1 fix, 2026-09-05 audit) lives
// in its own module — see bound-instruction.ts's doc comment for why.
import { buildInstructionFromPayload, type BoundInstructionPayload } from "./bound-instruction.js";
export { buildInstructionFromPayload, type BoundInstructionPayload };

// Serializing the instructions the bridge already holds, so the Core verifies
// the transaction rather than a description of it. See artifact.ts.
import {
  serializeUnsignedArtifact,
  findPrimaryIndex,
  declareSiblings,
  BoundTransaction,
  messageOf,
} from "./artifact.js";
export {
  serializeUnsignedArtifact,
  findPrimaryIndex,
  declareSiblings,
  BoundTransaction,
  messageOf,
};

/**
 * What an execute call actually did, in a form a caller can gate on.
 *
 * `executed` alone was ambiguous: it was true for bytes the artifact-bound gate
 * signed AND for the explicit unverified swap opt-out. A caller reading the
 * result could not tell a verified execution from one Graphite never saw.
 * `verifiedExecution` is true only when `signApproved` signed the exact bytes
 * Graphite hashed; it is false for a block, and false for the opt-out.
 */
export interface ExecutionOutcome {
  executed: boolean;
  /** True only when the artifact-bound gate signed the submitted bytes. */
  verifiedExecution: boolean;
  verification: VerificationResult;
  signature?: string;
  /**
   * Named what the unverified swap opt-out did not verify. Never set since
   * Round 19 (F-19-C2): the opt-out executed through SAK's builder, SAK no
   * longer holds a key that can sign, and so the opt-out no longer exists.
   * Kept on the type so callers that read it still compile.
   */
  unverifiedReason?: string;
  /**
   * What happened after the verdict, stage by stage — the residuals the
   * policy accepted, whether signing and submission reached the audit
   * trail, confirmation, and L8's reconciliation. Present on every verified
   * execution (Round 9).
   */
  lifecycle?: ExecutionLifecycle;
}

/**
 * The phrase the retired swap opt-out required.
 *
 * Round 19 (F-19-C2): the opt-out executed swaps through SAK's own builder,
 * which signed with the wallet key SAK used to hold. SAK now holds no key that
 * can sign, so there is no unverified execution path left to opt into. The
 * constant stays exported so a deployment that still sets
 * `GRAPHITE_SWAP_ALLOW_UNVERIFIED_EXECUTION` to it is told, by name, that the
 * setting no longer does anything — rather than having it silently ignored.
 */
export const UNVERIFIED_SWAP_OPT_IN = "I_ACCEPT_UNVERIFIED_SWAP_EXECUTION";

/** The message formats the bridge can be configured to build. */
export type BridgeTransactionVersion = "legacy" | 1;

/**
 * `GRAPHITE_TRANSACTION_VERSION`: unset or `legacy` builds legacy (v0 for a
 * route with lookup tables), `1` builds v1 (SIMD-0385, live on mainnet since
 * epoch 1035). Anything else is refused at startup rather than read as the
 * default: an operator who asked for v1 and got legacy would not know.
 */
export function parseTransactionVersion(value: string | undefined): BridgeTransactionVersion {
  if (value === undefined || value === "" || value === "legacy") return "legacy";
  if (value === "1") return 1;
  throw new Error(
    `[Graphite] GRAPHITE_TRANSACTION_VERSION=${JSON.stringify(value)} is not "legacy" or "1". REFUSING TO START.`,
  );
}

// Round 19 (F-19-C6) / A5-07: the environment names, and the refusal of the
// legacy ones, live in a dependency-free module the dev scripts share.
import { LEGACY_ENV_NAMES, assertNoLegacyEnvNames } from "./env-names.js";
export { LEGACY_ENV_NAMES, assertNoLegacyEnvNames };

/**
 * How long `parseIntent` waits for the AI layer (A5-01). The layer is a local
 * regex labeller that answers in microseconds; one that has not answered in
 * five seconds is not going to, and without a limit a hung layer hung the
 * whole call.
 */
export const AI_LAYER_TIMEOUT_MS = 5_000;

/**
 * The AI layer's URL under the same transport rule as the Core's (A5-01):
 * https://, or http:// only to loopback. The request text and the parsed
 * intent cross this connection, and an answer rewritten in flight is an
 * answer the bridge acts on. Returns the URL without a trailing slash.
 */
export function assertSecureAiLayerUrl(url: string): string {
  try {
    return assertSecureBaseUrl(url);
  } catch (e) {
    throw new Error(
      `[Graphite] GRAPHITE_AI_LAYER_URL is refused: ${(e as Error).message} ` +
        "The same rule applies to the AI layer, which receives the user's request and whose " +
        "answer the bridge acts on (A5-01). REFUSING TO START.",
    );
  }
}

/**
 * Surface what a verdict is actually bound to, and what it did not observe.
 *
 * Added 2026-09-08 after the Rust Core grew `VerificationResult.scope` while
 * this integration kept gating on `approved` alone. The two verdict modes —
 * describing caller-supplied metadata, and binding real signed bytes — are the
 * same shape on the wire, so `approved` cannot distinguish them. Anything that
 * can move funds should know which one it is holding.
 *
 * Reports rather than refuses: the refusal of anything but an artifact-bound
 * verdict is the residual policy's, in `executeBoundTransaction`, on the path
 * to signing. (This comment used to say neither path hands the Core an
 * artifact; both have, since the BoundTransaction work.) This is the
 * human-readable half.
 */
function reportVerificationScope(verification: VerificationResult, path: string): void {
  const scope = (verification as { scope?: { kind?: string; unobserved?: string[] } }).scope;
  if (!scope) {
    console.warn(
      `[Graphite] ${path}: this server reported no verification scope (pre-2026-09-08). ` +
        "Whether the verdict was bound to a transaction artifact is unknown.",
    );
    return;
  }
  if (scope.kind !== "artifact_bound") {
    console.warn(
      `[Graphite] ${path}: the verdict is DESCRIPTIVE — Graphite was not given a transaction ` +
        "artifact, so nothing in it constrains what is actually signed. AuditBind binds the " +
        "live instruction; everything else in the transaction is unexamined.",
    );
  }
  for (const u of scope.unobserved ?? []) {
    console.warn(`[Graphite]   not observed: ${u}`);
  }
}

/** How a guard is configured. Every field falls back to its environment variable. */
export interface GuardConfig {
    /**
     * Base58 secret key (SOLANA_PRIVATE_KEY). Held in an ES private field.
     * Round 29 (M8): when it is read from the environment, the guard deletes
     * SOLANA_PRIVATE_KEY from `process.env` once read, so code loaded later in
     * the process cannot read it there.
     */
    privateKey?: string;
    /**
     * Solana JSON-RPC URL (SOLANA_RPC_URL). https://, or http:// only to a
     * loopback host (Round 29, M3): this endpoint alone measures what a swap
     * does to the wallet.
     */
    rpcUrl?: string;
    graphiteCoreUrl?: string; aiLayerUrl?: string; walletProfile?: WalletProfile;
    /** Bearer API key for a secured Graphite Core (GRAPHITE_API_KEY). */
    graphiteApiKey?: string;
    /**
     * Residual codes (`scope.unobserved_codes`) this deployment accepts on an
     * approved verdict, beyond the two inherent ones. Default: none — any
     * non-inherent residual refuses execution. Overrides
     * GRAPHITE_ACCEPT_UNOBSERVED. See `residual-policy.ts`.
     */
    acceptUnobserved?: string[];
    /** How long `parseIntent` waits for the AI layer. Default AI_LAYER_TIMEOUT_MS. */
    aiLayerTimeoutMs?: number;
    /**
     * The message format the bridge builds: `"legacy"` (the default, with v0
     * when a swap route names lookup tables) or `1` (SIMD-0385). Overrides
     * GRAPHITE_TRANSACTION_VERSION. See `parseTransactionVersion`.
     */
    transactionVersion?: BridgeTransactionVersion;
    /**
     * The `reported_by` prefix on every lifecycle row (`<reporter>:<key prefix>`),
     * so the trail says which integration executed. Default "agent-guard".
     */
    reporter?: string;
    /**
     * The operator's spending limits (see spend-policy.ts). Overrides
     * GRAPHITE_MAX_TRANSFER_LAMPORTS / GRAPHITE_ALLOWED_DESTINATIONS /
     * GRAPHITE_MAX_TOTAL_LAMPORTS / GRAPHITE_SPEND_WINDOW_SECONDS /
     * GRAPHITE_ALLOW_UNCAPPED. A per-transaction cap is required unless
     * `allowUncapped` (Round 29, M6).
     */
    spendPolicy?: SpendPolicy;
    /**
     * What a swap's route must be worth (see swap-economics.ts). Overrides
     * GRAPHITE_SWAP_MAX_SLIPPAGE_BPS / GRAPHITE_SWAP_MIN_RATES /
     * GRAPHITE_SWAP_ALLOW_UNPRICED (Round 29, H2).
     */
    swapPolicy?: SwapPolicy;
    /**
     * The compute budget and output account the guard builds around a swap
     * (see swap-envelope.ts). Overrides GRAPHITE_SWAP_COMPUTE_UNIT_LIMIT /
     * GRAPHITE_SWAP_COMPUTE_UNIT_PRICE / GRAPHITE_SWAP_CREATE_OUTPUT_ATA
     * (Round 29, L4). Default: none.
     */
    swapEnvelope?: SwapEnvelopeConfig;
    /**
     * Where the aggregate spend and unresolved submissions are kept across a
     * restart (Round 30, guard-state.ts). Overrides GRAPHITE_GUARD_STATE_FILE.
     * Unset in both: in memory, and a restart forgets them.
     */
    stateFile?: string;
    /**
     * The directory every guard of this user on this host shares for its
     * per-wallet locks (Round 32, guard-state.ts). Overrides
     * GRAPHITE_GUARD_LOCK_DIR. Default (Round 38, R37-17): one directory per
     * user, derived from the account alone and no session variable
     * (`defaultWalletLockDir`: `<home>/.local/state/graphite-guard`); it must
     * be this user's, mode 0700 (not checked on Windows).
     */
    walletLockDir?: string;
    /**
     * Let this guard start while another guard runs for the same wallet: the
     * spend limits then hold per guard, not per wallet. Overrides
     * GRAPHITE_GUARD_ALLOW_SHARED_WALLET. Default false (Round 32).
     */
    allowSharedWallet?: boolean;
    /**
     * How long a confirmation hook may take before it counts as declined, in
     * milliseconds. Default `DEFAULT_CONFIRM_TIMEOUT_MS` (Round 30).
     */
    confirmTimeoutMs?: number;
    /**
     * The deadline on every Solana RPC request, headers and whole answer, in
     * milliseconds (GRAPHITE_RPC_TIMEOUT_MS; 1 to `MAX_RPC_TIMEOUT_MS`,
     * default `DEFAULT_RPC_TIMEOUT_MS`). Round 35 (F-014): web3.js's own
     * requests had none.
     */
    rpcTimeoutMs?: number;
    /**
     * The oldest a verdict may be when it is signed, in milliseconds, counted
     * from the moment the verification was asked for (GRAPHITE_MAX_VERDICT_AGE_MS;
     * 1 to `MAX_MAX_VERDICT_AGE_MS`, default `DEFAULT_MAX_VERDICT_AGE_MS`).
     * Round 35 (F-017): an older one is refused (`StaleVerdict`), nothing signed.
     */
    maxVerdictAgeMs?: number;
}

/**
 * Every key `GuardConfig` has (Round 30). Any other key is refused: a
 * misspelt `spendpolicy` used to be ignored and the environment read in its
 * place, and a key a caller hoped would inject something (`connection`,
 * `wallet`, `signer`) was ignored silently, so the caller could not tell.
 */
export const GUARD_CONFIG_KEYS: readonly (keyof GuardConfig)[] = Object.freeze([
  "privateKey",
  "rpcUrl",
  "graphiteCoreUrl",
  "aiLayerUrl",
  "walletProfile",
  "graphiteApiKey",
  "acceptUnobserved",
  "aiLayerTimeoutMs",
  "transactionVersion",
  "reporter",
  "spendPolicy",
  "swapPolicy",
  "swapEnvelope",
  "stateFile",
  "walletLockDir",
  "allowSharedWallet",
  "confirmTimeoutMs",
  "rpcTimeoutMs",
  "maxVerdictAgeMs",
] as const);

/**
 * What a person (or a caller's hook) is shown before the guard signs
 * (Round 29, audit 2026-10-20, M7). Every value is the RESOLVED one — the
 * grounded destination and amount, the program the bytes call, what a
 * simulation of those exact bytes does to the wallet, and Graphite's verdict
 * on them — never the model's text alone. Amounts are decimal strings.
 */
export interface ConfirmationSummary {
  kind: "transfer" | "swap";
  /** The request, as the guard grounded it. */
  request: string;
  wallet: string;
  /**
   * The SHA-256 of exactly the bytes that will be signed if this is
   * confirmed (Round 30): the digest Graphite approved, which `signApproved`
   * re-checks after the answer. A confirmation is about these bytes and no
   * others; any change to them is a different transaction and a new question.
   */
  transactionSha256: string;
  /** The program the verified instruction calls. */
  programId: string;
  /** Transfer: where the lamports go. */
  destination?: string;
  /** Transfer: how many lamports, and the same in SOL. */
  lamports?: string;
  sol?: string;
  /** Swap: what the route's own data says, and what it must deliver. */
  swap?: {
    route: string;
    input: { token: string; mint: string; amountIn: string };
    output: {
      token: string;
      mint: string;
      minimumOut: string;
      simulatedOut: string;
      /**
       * Round 30: `wrapped_sol` when the output is SOL. The guard does not
       * unwrap (`GUARD_CAPABILITIES.operations.unwrapSol`), so SOL bought by
       * a swap arrives, and stays, as wrapped SOL in the wallet's account.
       */
      deliveredAs?: "wrapped_sol";
    };
    maxSlippageBps: number;
    priceFloor: string;
  };
  /** One simulation of the exact bytes: SOL leaving the wallet (lamports), and every token's change. */
  walletEffect: { solOutLamports: string; tokens: { mint: string; delta: string }[] };
  verdict: {
    approved: boolean;
    confidence: number;
    risk: string;
    auditTrailId: string;
    transactionSha256?: string;
    unobservedCodes: string[];
    /** Residuals the deployment's policy accepted for this execution. */
    acceptedUnobserved: string[];
  };
}

/** Per-call options for `executeTransfer` / `executeSwap`. */
export interface ExecuteOptions {
  /**
   * Called after grounding, the spend policy, building, simulation, Graphite's
   * verdict and the residual policy, immediately before signing. Anything but
   * `true` aborts with `ConfirmationDeclined`; nothing is signed or sent.
   */
  confirm?: (summary: ConfirmationSummary) => Promise<boolean>;
}

/**
 * The same request is already being executed by this guard (Round 30). A
 * model that calls a tool twice, or a caller that did not await the first
 * call, gets this instead of a second transaction. Nothing was built.
 */
export class RequestInFlight extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RequestInFlight";
  }
}

/**
 * The guard was closed (Round 34): it signs, submits and reserves nothing
 * after `close()`, with or without a state file. Its locks are released, so
 * another guard may already hold the wallet.
 */
export class GuardClosed extends Error {
  constructor() {
    super("[Graphite] this guard is closed: it signs and spends nothing after close(). Create a new guard. REFUSING.");
    this.name = "GuardClosed";
  }
}

/** The read-only part of the Core client a caller may use (Round 29, M8). */
export interface GraphiteReadClient {
  health(): Promise<{ status: string; service: string; version: string }>;
  listManifests(): ReturnType<GraphiteClient["listManifests"]>;
}

/**
 * A request whose earlier submission may still land (Round 29, L2). Thrown
 * before anything is built for a repeat of a request whose last submission
 * failed ambiguously and whose fate the RPC cannot yet tell.
 */
export class PriorSubmissionUnresolved extends Error {
  readonly signature: string;
  constructor(message: string, signature: string) {
    super(message);
    this.name = "PriorSubmissionUnresolved";
    this.signature = signature;
  }
}

/** The most bytes the AI layer's answer may carry (audit 2026-10-20, Info). */
export const MAX_AI_LAYER_RESPONSE_BYTES = 64 * 1024;

/**
 * Read GRAPHITE_MAX_VERDICT_AGE_MS (or the config value): a whole number of
 * milliseconds from 1 to `MAX_MAX_VERDICT_AGE_MS` (Round 35, F-017).
 */
export function resolveMaxVerdictAgeMs(value: number | string | undefined): number {
  if (value === undefined || value === "") return DEFAULT_MAX_VERDICT_AGE_MS;
  const n = typeof value === "string" && /^[0-9]{1,9}$/.test(value.trim()) ? Number(value.trim()) : value;
  if (typeof n !== "number" || !Number.isSafeInteger(n) || n < 1 || n > MAX_MAX_VERDICT_AGE_MS) {
    throw new Error(
      `[Graphite] the verdict age bound ${JSON.stringify(value)} is not a whole number of milliseconds from 1 to ` +
        `${MAX_MAX_VERDICT_AGE_MS} (GRAPHITE_MAX_VERDICT_AGE_MS / maxVerdictAgeMs). REFUSING TO START.`,
    );
  }
  return n;
}

/**
 * A grounded mint as the Core's intent binding reads a token (Round 36,
 * F-003): "SOL" for the native mint, the base58 mint otherwise.
 */
export function coreTokenOf(mint: string): string {
  return mint === NATIVE_MINT ? "SOL" : mint;
}

/** How long the guard waits for a submission to confirm, at most. */
const CONFIRMATION_MAX_MS = 90_000;
const CONFIRMATION_POLL_MS = 500;

function lamportsAsSol(lamports: bigint): string {
  const whole = lamports / 1_000_000_000n;
  const frac = (lamports % 1_000_000_000n).toString().padStart(9, "0").replace(/0+$/, "");
  return frac === "" ? whole.toString() : `${whole}.${frac}`;
}

/**
 * The summary a confirmation hook is handed, frozen all the way down (Round
 * 30). Nothing the hook does to it reaches what is signed — the bytes are the
 * bound transaction's — but a hook that "edits" a value and then approves
 * should fail loudly rather than believe it approved the edit.
 */
function deepFreeze<T>(value: T): T {
  if (typeof value === "object" && value !== null && !Object.isFrozen(value)) {
    for (const v of Object.values(value)) deepFreeze(v);
    Object.freeze(value);
  }
  return value;
}

function effectForSummary(effect: WalletEffect): ConfirmationSummary["walletEffect"] {
  return {
    solOutLamports: effect.solOut.toString(),
    tokens: [...effect.tokenDelta].map(([mint, delta]) => ({ mint, delta: delta.toString() })),
  };
}

/**
 * What makes two swaps the same request (Round 38, G2-2): the wallet, the
 * input mint, the output mint and the amount in. Not the route: the same
 * swap through Jupiter and through Raydium is one request, and after one of
 * them failed ambiguously the other is a repeat until the first cannot land.
 * The `v2` names this form; a key without it is the route-specific form of
 * Rounds 30-37 (`legacySwapKeyMatcher`).
 */
export function swapRequestKey(wallet: string, inputMint: string, outputMint: string, amountIn: bigint): string {
  return `swap:v2:${wallet}:${inputMint}:${outputMint}:${amountIn}`;
}

/**
 * The Round 30-37 key for a swap was `swap:<route program>:<in>:<out>:<amount>`.
 * A state file written then may hold an unresolved swap under it; it holds
 * back the same swap on any route (it names no wallet, so on any wallet that
 * reads the file: the stricter reading).
 */
function legacySwapKeyMatcher(inputMint: string, outputMint: string, amountIn: bigint): (key: string) => boolean {
  const tail = `:${inputMint}:${outputMint}:${amountIn}`;
  return (key) => key.endsWith(tail) && /^swap:[1-9A-HJ-NP-Za-km-z]{32,44}:/.test(key) && key.split(":").length === 5;
}

/**
 * The guard. One instance holds one wallet key and signs only through the
 * verified path.
 *
 * Flow: parse intent -> ground it in the user's text -> build ONE transaction
 * -> RPC simulate (unsigned) -> Graphite verify -> AuditBind -> residual
 * policy -> [confirm] -> sign the approved bytes -> trail -> submit -> L8.
 *
 * Round 29 (audit 2026-10-20, M8): every collaborator that takes part in a
 * decision — the Core client, the RPC connection and simulator, the residual
 * and spend policies, the swap policy, the AI layer's URL, the wallet profile
 * — is an ES private field. TypeScript `private` is a compile-time label: at
 * runtime `guard.graphite = stub` replaced the Core with a client that
 * approved anything over the real digest, and `guard.getGraphiteClient()`
 * handed out the Core's API key. The instance and its prototype are frozen,
 * so no method can be swapped for another either.
 */
export class GraphiteGuard {
  #graphite: GraphiteClient;
  #connection: Connection;
  #walletProfile: WalletProfile;
  #aiLayerUrl: string;
  #aiLayerTimeoutMs: number;
  #walletPublicKey: string;
  // An ES private field, not TypeScript `private`: TypeScript's is a
  // compile-time label, and the key was readable as `agent.walletKeypair` by
  // any code holding this object (review of the 2026-09-29 audit, R8). A `#`
  // field cannot be read from outside the class at runtime.
  //
  // Round 30: and what it holds is no longer the secret key's bytes. The key
  // is imported once, at `create`, into a NON-EXTRACTABLE WebCrypto key pair
  // and the decoded bytes are zeroed: nothing in this process — a later
  // module, a patched getter, a heap walk through the object graph — can read
  // the private key back out of the guard, only ask the one signing path to
  // sign with it.
  #signer: WalletSigner;
  #simulator: RpcSimulator;
  #residualPolicy: ResidualPolicy;
  #transactionVersion: BridgeTransactionVersion;
  #reporterName: string;
  #spendPolicy: SpendPolicy;
  #ledger: SpendLedger;
  #swapPolicy: SwapPolicy;
  #swapEnvelope: SwapEnvelopeConfig;
  /**
   * Submissions whose outcome is unknown, by request (Round 29, L2), and
   * since Round 30 the aggregate's reservations: durable with a state file.
   */
  #state: GuardState;
  /** This guard's claim on its wallet (Round 32): one guard per wallet on a host. */
  #walletLock: WalletLock;
  /**
   * Set by `close()` (Round 34). Checked first on every signing and spending
   * path: closing released the locks, and without a state file nothing else
   * stopped a closed guard from signing.
   */
  #closed = false;
  /** Requests being executed right now, by the same key (Round 30). */
  #inFlight = new Set<string>();
  #confirmTimeoutMs: number;
  /** The oldest verdict this guard signs (Round 35, F-017). */
  #maxVerdictAgeMs: number;
  /**
   * The connection handed out by `getConnection()` (Round 30): a second
   * instance to the same endpoint. Handing out the guard's own let a caller
   * reassign its `getSignatureStatuses` or `sendRawTransaction` and answer
   * the questions the guard decides a repeat or a submission on.
   */
  #readConnection: Connection;

  private constructor(c: {
    graphite: GraphiteClient; connection: Connection; walletProfile: WalletProfile; aiLayerUrl: string;
    signer: WalletSigner; residualPolicy: ResidualPolicy;
    aiLayerTimeoutMs: number; transactionVersion: BridgeTransactionVersion; reporterName: string;
    spendPolicy: SpendPolicy; swapPolicy: SwapPolicy; swapEnvelope: SwapEnvelopeConfig; rpcUrl: string;
    state: GuardState; walletLock: WalletLock; confirmTimeoutMs: number;
    rpcTimeoutMs: number; maxVerdictAgeMs: number;
  }) {
    this.#graphite = c.graphite;
    this.#connection = c.connection;
    // Round 35 (F-014): bounded like the guard's own, and without websockets.
    this.#readConnection = connectionWithoutRedirects(c.rpcUrl, c.rpcTimeoutMs);
    this.#walletProfile = c.walletProfile;
    this.#aiLayerUrl = c.aiLayerUrl;
    this.#aiLayerTimeoutMs = c.aiLayerTimeoutMs;
    this.#signer = c.signer;
    this.#walletPublicKey = c.signer.publicKey.toBase58();
    this.#simulator = new RpcSimulator(c.rpcUrl, c.rpcTimeoutMs);
    this.#residualPolicy = c.residualPolicy;
    this.#transactionVersion = c.transactionVersion;
    this.#reporterName = c.reporterName;
    this.#spendPolicy = c.spendPolicy;
    this.#state = c.state;
    this.#walletLock = c.walletLock;
    this.#ledger = new SpendLedger(c.spendPolicy, Date.now, c.state);
    this.#swapPolicy = c.swapPolicy;
    this.#swapEnvelope = c.swapEnvelope;
    this.#confirmTimeoutMs = c.confirmTimeoutMs;
    this.#maxVerdictAgeMs = c.maxVerdictAgeMs;
    Object.freeze(this);
  }

  /** The `reported_by` on every lifecycle row this bridge writes. */
  #reporter(): string {
    return `${this.#reporterName}:${this.#walletPublicKey.slice(0, 8)}`;
  }

  static async create(config?: GuardConfig): Promise<GraphiteGuard> {
    return GraphiteGuard.#createWith(config ?? {});
  }

  static async #createWith(config: GuardConfig): Promise<GraphiteGuard> {
    // Round 30: a key this config does not have is refused, not ignored.
    const unknownKeys = Object.keys(config).filter((k) => !(GUARD_CONFIG_KEYS as readonly string[]).includes(k));
    if (unknownKeys.length > 0) {
      throw new Error(
        `[Graphite] GuardConfig has unknown key(s) ${unknownKeys.map((k) => JSON.stringify(k)).join(", ")}. ` +
          `Known keys: ${GUARD_CONFIG_KEYS.join(", ")}. Nothing can be injected into the guard; a misspelt ` +
          "setting is an error, never a silent fallback to the environment. REFUSING TO START.",
      );
    }

    // Before any default is applied: a legacy variable name must not quietly
    // become "use localhost" (Round 19, F-19-C6).
    assertNoLegacyEnvNames();
    const privateKey = config?.privateKey ?? process.env.SOLANA_PRIVATE_KEY;
    // Round 29 (M8): the key is read once, here; it does not stay in the
    // environment of a process that loads frameworks, plugins and model tools.
    if (config?.privateKey === undefined) delete process.env.SOLANA_PRIVATE_KEY;
    const rpcUrl = config?.rpcUrl ?? process.env.SOLANA_RPC_URL;
    const graphiteCoreUrl = config?.graphiteCoreUrl ?? process.env.GRAPHITE_CORE_URL ?? "http://localhost:7331";
    // Secured Core deployments require the Bearer key on /verify and /manifests.
    const graphiteApiKey = config?.graphiteApiKey ?? process.env.GRAPHITE_API_KEY;
    // The Python AI Layer listens on 127.0.0.1:8081 by default (intent_parser.py
    // --serve). An IP literal, not "localhost": since Round 19 (F-19-C5) the
    // layer binds IPv4 loopback only, and "localhost" can resolve to ::1 first.
    // A5-01: refused here, before any request can carry the user's text.
    const aiLayerUrl = assertSecureAiLayerUrl(
      config?.aiLayerUrl ?? process.env.GRAPHITE_AI_LAYER_URL ?? "http://127.0.0.1:8081",
    );
    const aiLayerTimeoutMs = config?.aiLayerTimeoutMs ?? AI_LAYER_TIMEOUT_MS;
    // A misspelt version is a startup error, never a silent legacy build.
    const transactionVersion =
      config?.transactionVersion ?? parseTransactionVersion(process.env.GRAPHITE_TRANSACTION_VERSION);
    // Phase 1 calibration: with the three evidence-derived confidence signals
    // intentionally zeroed (Constitution G4 — request-body evidence is
    // attacker-controlled) and trust tiers capped at OfficialManifest (P7), the
    // achievable confidence for a known, clean, intent-aligned protocol is
    // ~0.44. The default below asks for 0.40, but the Core clamps every Custom
    // profile to the weakest built-in (Gaming: 0.55, HeuristicInferred), so in
    // practice it is Gaming and approves nothing until a protocol's evidence
    // has been earned (review of the 2026-09-29 audit, R7: the old comment said
    // a genuinely-known protocol could satisfy it, which is false — it fails
    // closed). Override with GRAPHITE_WALLET_PROFILE (or config.walletProfile)
    // for a stricter operator policy.
    const walletProfile: WalletProfile = config?.walletProfile
      ?? (process.env.GRAPHITE_WALLET_PROFILE as WalletProfile)
      ?? { Custom: { min_confidence: 0.40, min_trust_tier: "OfficialManifest" } };

    if (!privateKey) throw new Error("SOLANA_PRIVATE_KEY is required");
    if (!rpcUrl) throw new Error("SOLANA_RPC_URL is required");
    // Round 29 (M3): the RPC under the Core's transport rule. It decides what
    // a swap is measured to do, and a rewritten simulation is a rewritten
    // measurement.
    assertSecureRpcUrl(rpcUrl);

    // Limits and swap rules are read before anything is contacted: a
    // malformed or missing one is a startup error, never an absent bound.
    const spendPolicy = config?.spendPolicy ?? spendPolicyFromEnv();
    assertSpendPolicyUsable(spendPolicy);
    const swapPolicy = config?.swapPolicy ?? swapPolicyFromEnv();
    assertSwapPolicyUsable(swapPolicy);
    const swapEnvelope = config?.swapEnvelope ?? swapEnvelopeFromEnv();
    assertSwapEnvelopeUsable(swapEnvelope);

    const confirmTimeoutMs = config?.confirmTimeoutMs ?? DEFAULT_CONFIRM_TIMEOUT_MS;
    if (!Number.isSafeInteger(confirmTimeoutMs) || confirmTimeoutMs < 1) {
      throw new Error(`[Graphite] confirmTimeoutMs ${String(confirmTimeoutMs)} is not a positive integer. REFUSING TO START.`);
    }
    // Round 35 (F-014, F-017): the RPC deadline and the verdict's age bound,
    // read before anything is contacted; a malformed one refuses to start.
    const rpcTimeoutMs = resolveRpcTimeoutMs(config?.rpcTimeoutMs ?? process.env.GRAPHITE_RPC_TIMEOUT_MS);
    const maxVerdictAgeMs = resolveMaxVerdictAgeMs(config?.maxVerdictAgeMs ?? process.env.GRAPHITE_MAX_VERDICT_AGE_MS);
    if (confirmTimeoutMs >= maxVerdictAgeMs) {
      console.warn(
        `[Graphite] confirmTimeoutMs (${confirmTimeoutMs}) is not below the verdict age bound (${maxVerdictAgeMs} ms): ` +
          "a confirmation that takes that long is answered about a verdict too old to sign, and is refused.",
      );
    }
    const lockPlan = walletLockPlan({ lockDir: config?.walletLockDir, allowSharedWallet: config?.allowSharedWallet });
    // Built here, not lazily: a typo in the accepted list, or a code no
    // deployment may accept (Round 38, G2-5: `intent_parameters`), is a
    // startup error before anything is contacted, never a silent refusal at
    // execution time.
    const residualPolicy = config?.acceptUnobserved
      ? new ResidualPolicy(config.acceptUnobserved)
      : ResidualPolicy.fromEnv();

    const signer = await walletSignerFrom(privateKey);
    const connection = connectionWithoutRedirects(rpcUrl, rpcTimeoutMs);

    const graphite = new GraphiteClient({ baseUrl: graphiteCoreUrl, apiKey: graphiteApiKey });
    try { await graphite.health(); } catch {
      throw new Error(`Graphite Core not reachable at ${graphiteCoreUrl}. Start: GRAPHITE_API_KEY=... cargo run --release -- server`);
    }
    const accepted = residualPolicy.accepts();
    console.log(
      accepted.length === 0
        ? "[Graphite] residual policy: inherent residuals only — any other unobserved property refuses execution"
        : `[Graphite] residual policy: accepting ${accepted.join(", ")} in addition to the inherent residuals`,
    );
    // Round 29 (M6, H2): the limits in force are stated where an operator
    // reads them, accepted risks by name.
    console.log(describeSpendPolicy(spendPolicy));
    console.log(describeSwapPolicy(swapPolicy));
    // Round 30: opened last, after everything that can refuse to start, so a
    // refused start does not hold the state file's lock.
    // Round 32: the wallet's lock first, so a second guard for the same
    // wallet is refused before it touches any state file.
    const windowMs = (spendPolicy.spendWindowSeconds ?? DEFAULT_SPEND_WINDOW_SECONDS) * 1000;
    const walletLock = takeWalletLock(signer.publicKey.toBase58(), lockPlan);
    let state: GuardState;
    try {
      state = openGuardState(config?.stateFile, Date.now() - windowMs);
    } catch (e) {
      walletLock.close();
      throw e;
    }
    console.log(walletLock.describe());
    console.log(state.describe());

    return new GraphiteGuard({
      graphite, connection, walletProfile, aiLayerUrl, signer, residualPolicy, aiLayerTimeoutMs,
      transactionVersion, reporterName: config?.reporter ?? "agent-guard", spendPolicy, swapPolicy, swapEnvelope,
      rpcUrl, state, walletLock, confirmTimeoutMs, rpcTimeoutMs, maxVerdictAgeMs,
    });
  }

  /** What this guard can build, and what it refuses by name (Round 30). */
  get capabilities(): GuardCapabilities {
    return GUARD_CAPABILITIES;
  }

  /**
   * Release the state file's lock (Round 30) and the wallet's (Round 32).
   * The guard signs nothing after this (Round 34: every signing and spending
   * path refuses with `GuardClosed`, an execution already running included);
   * a process that exits releases the locks anyway. Idempotent.
   */
  close(): void {
    this.#closed = true;
    this.#state.close();
    this.#walletLock.close();
  }

  /** Refuse with `GuardClosed` once `close()` has run (Round 34). */
  #assertOpen(): void {
    if (this.#closed) throw new GuardClosed();
  }

  /**
   * Refuse unless this guard is open and still holds its locks (Round 34):
   * the wallet's, and the state file's when it has one. A lock deleted under
   * the guard (a temp cleaner, an operator) may already be another guard's,
   * with a full allowance; this guard stops spending. Run before every
   * reservation and immediately before the signed bytes leave the process.
   */
  #assertMaySpend(): void {
    this.#assertOpen();
    this.#walletLock.assertHeld();
    this.#state.assertHeld();
  }

  async parseIntent(naturalLanguage: string): Promise<ProposedIntent> {
    // A5-01: bounded, and never redirected — a redirect would carry the
    // request past the transport rule the URL was checked against.
    let response: Response;
    try {
      response = await capturedFetch(`${this.#aiLayerUrl}/parse`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ text: naturalLanguage }),
        signal: AbortSignal.timeout(this.#aiLayerTimeoutMs),
        redirect: "error",
      });
    } catch (e) {
      const timedOut = e instanceof Error && e.name === "TimeoutError";
      throw new Error(
        timedOut
          ? `[Graphite] the AI layer did not answer within ${this.#aiLayerTimeoutMs} ms. ABORTING.`
          : `[Graphite] the AI layer request failed: ${e instanceof Error ? e.message : String(e)}. ABORTING.`,
      );
    }
    if (!response.ok) throw new Error(`AI Layer error: ${response.status}`);
    // Audit 2026-10-20 (Info): bounded before it is parsed, like every RPC answer.
    const result = (await readJsonBounded(response, MAX_AI_LAYER_RESPONSE_BYTES, "[Graphite] the AI layer's answer")) as {
      intent_type?: unknown; raw_natural_language?: unknown; confidence_of_parse?: unknown;
      extracted_parameters?: unknown;
    };
    // Round 19 (F-19-C5): the answer must be an answer to THIS request. The
    // text the Core sees as the user's words is the bridge's own copy, never
    // the AI layer's echo of it.
    assertEcho(naturalLanguage, result?.raw_natural_language);
    // Audit 2026-10-20 (Info): only the fields grounding reads, and only as
    // strings. Nothing else the layer sends travels further; what reaches the
    // Core is rebuilt from grounded values in executeTransfer / executeSwap.
    const raw = (typeof result.extracted_parameters === "object" && result.extracted_parameters !== null
      ? result.extracted_parameters
      : {}) as Record<string, unknown>;
    const extracted: Record<string, string> = {};
    for (const key of ["amount", "input_token", "output_token", "destination"]) {
      if (typeof raw[key] === "string") extracted[key] = raw[key] as string;
    }
    const confidence = result.confidence_of_parse;
    return {
      intent_type: (typeof result.intent_type === "string" ? result.intent_type : "unknown") as any,
      raw_natural_language: naturalLanguage,
      confidence_of_parse:
        typeof confidence === "number" && Number.isFinite(confidence) && confidence >= 0 && confidence <= 1 ? confidence : 0,
      extracted_parameters: extracted,
    };
  }

  /**
   * Ask the Core about a transaction (Round 34, G-7: private). Every call
   * writes a verification to the audit trail under this deployment's key, so
   * like the client itself (`getGraphiteClient`, Round 29 M8) it is not
   * handed to whoever holds the guard: only `executeTransfer` and
   * `executeSwap` call it, about the transaction they built.
   */
  async #verifyTransaction(params: {
    programId: string; instructionDiscriminator: string; accountAddresses: string[];
    proposedIntent: ProposedIntent; instructions?: TransactionInstruction[];
    cpiTargets?: string[]; instructionData?: number[];
    // P1 fix (2026-09-05 audit, "signer/writable metadata is not grounded in
    // actual transaction AccountMeta data"): the REAL per-account
    // signer/writable bits, same order as accountAddresses, when the caller
    // has them (executeSwap's bound payload path does). Cross-checked by the
    // Core against the manifest's declared expectations and hard-blocked on
    // a security-relevant mismatch. Omitted here means "not supplied" — the
    // Core never assumes a match.
    realAccountMetas?: { is_signer: boolean; is_writable: boolean }[];
    /**
     * The instructions to serialize into the artifact, when they are not the
     * ones to simulate.
     */
    artifactInstructions?: TransactionInstruction[];
    /**
     * The transaction that will be signed and submitted.
     *
     * When present, ITS bytes are what Graphite verifies — not a separately
     * serialized copy of the same instructions. That is the whole point: a copy
     * proves the instructions match, and the executed transaction is more than
     * its instructions.
     */
    bound?: BoundTransaction;
  }): Promise<VerificationResult> {
    let computeUnits = 0, accountWrites = 0, cpiHops = 0;
    if (params.instructions && params.instructions.length > 0) {
      console.log("[Graphite] Running RPC simulation to feed the Simulation Integrity check...");
      // Round 19 (F-19-C1): the fee payer's PUBLIC key, never the keypair.
      // This used to pass `signers: [this.#walletKeypair]`, which made web3.js
      // sign the transfer on a live blockhash and send the signed bytes to the
      // RPC before Graphite had decided anything.
      const sim = await this.#simulator.simulate({ instructions: params.instructions, feePayer: this.#signer.publicKey });
      computeUnits = sim.computeUnits; accountWrites = sim.accountWrites; cpiHops = sim.cpiHops;
      console.log(`[Graphite] Simulation: CU=${computeUnits}, writes=${accountWrites}, CPI=${cpiHops}, success=${sim.success}`);
    }
    // Behavior evidence is advisory only: the Core deliberately ZEROES the
    // SimulationMatch/HistoricalVolume/CommunityVerification signal values
    // (Constitution G4 — request-body evidence is attacker-controlled) and caps
    // the trust tier at the manifest's declared tier (P7). Reporting
    // simulation_match_count here therefore CANNOT boost confidence in Phase 1;
    // it only documents the real RPC simulation in the audit trail. The trusted
    // simulation signal arrives in Phase 2 via the Core's own RPC client.
    const behavior_evidence = {
      has_signed_manifest: false,
      community_verified_count: 0,
      battle_tested_tx_count: 0,
      simulation_match_count: (computeUnits > 0 || accountWrites > 0) ? 3 : 0,
    };
    // The artifact. Without it every verification through this bridge is
    // Descriptive — the Core reasons over what this request SAYS about the
    // transaction — while the transaction itself sits in `params.instructions`,
    // already built and already simulated. With it the Core reads the header
    // for signer/writable flags, checks the instruction's account list position
    // by position, sees every other instruction in the transaction, and can
    // resolve lookup tables.
    //
    // Best-effort by construction: a failure to serialize or to reach the RPC
    // for a blockhash must not stop a verification that would otherwise happen,
    // and the Core reports which mode it used, so a caller is never told a
    // Descriptive verdict is artifact-bound.
    const artifactInstructions =
      params.bound?.instructions() ??
      params.artifactInstructions ??
      params.instructions;
    let signed_transaction: number[] | undefined;
    let transaction_instructions: ReturnType<typeof declareSiblings> | undefined;
    if (artifactInstructions && artifactInstructions.length > 0) {
      try {
        // A prepared transaction supplies its own bytes. Re-serializing the
        // same instructions into a fresh object would verify a copy and sign
        // the original, which is the gap this parameter exists to close.
        signed_transaction =
          params.bound?.artifact() ??
          serializeUnsignedArtifact({
            instructions: artifactInstructions,
            feePayer: this.#signer.publicKey,
            recentBlockhash: (await this.#connection.getLatestBlockhash()).blockhash,
          });
        const primary = findPrimaryIndex(artifactInstructions, {
          programId: params.programId,
          instructionDiscriminator: params.instructionDiscriminator,
          accountAddresses: params.accountAddresses,
        });
        // -1 means the described instruction is not among the ones about to be
        // built, which is a real disagreement rather than a reason to withhold
        // the bytes. Declaring every instruction as a sibling lets the Core say
        // so instead of this bridge deciding quietly.
        transaction_instructions = declareSiblings(artifactInstructions, primary);
        console.log(
          `[Graphite] Artifact: ${signed_transaction.length} bytes, ` +
            `${artifactInstructions.length} instruction(s), ` +
            `${transaction_instructions.length} declared as siblings` +
            (primary < 0 ? " (the described instruction is not among them)" : ""),
        );
      } catch (e) {
        console.warn(
          "[Graphite] Could not build the transaction artifact; verification " +
            "will be descriptive rather than artifact-bound:",
          e instanceof Error ? e.message : String(e),
        );
        signed_transaction = undefined;
        transaction_instructions = undefined;
      }
    }

    const input: VerificationInput = {
      proposed_intent: params.proposedIntent, program_id: params.programId,
      instruction_discriminator: params.instructionDiscriminator, account_addresses: params.accountAddresses,
      cpi_targets: params.cpiTargets ?? [], wallet_profile: this.#walletProfile,
      instruction_data: params.instructionData, compute_units: computeUnits,
      account_writes: accountWrites, cpi_hops: cpiHops,
      behavior_evidence, real_account_metas: params.realAccountMetas,
      signed_transaction, transaction_instructions,
      // Round 22: what the bytes are, so the declaration describes them. v0
      // and v1 are both versioned (the Core reads the prefix the same way).
      uses_versioned_transaction: params.bound !== undefined && params.bound.version !== "legacy",
      lookup_table_count: params.bound?.lookupTableCount ?? 0,
    } as any;
    return this.#graphite.verify(input);
  }

  /**
   * The RPC calls the execution path makes. Confirmation polls
   * `getSignatureStatuses` and `getBlockHeight` over HTTP (Round 29): the
   * web3.js confirmation opens a websocket subscription, which is a second
   * transport to the RPC that the URL rule above never checked.
   */
  #submitConnection(): SubmitConnection {
    const connection = this.#connection;
    return {
      sendRawTransaction: (raw) => connection.sendRawTransaction(raw),
      confirmTransaction: async ({ signature, lastValidBlockHeight }) => {
        const deadline = Date.now() + CONFIRMATION_MAX_MS;
        for (;;) {
          const status = (await connection.getSignatureStatuses([signature])).value[0];
          if (status) {
            if (status.err) throw new Error(`landed and FAILED: ${JSON.stringify(status.err).slice(0, 160)}`);
            if (status.confirmationStatus === "confirmed" || status.confirmationStatus === "finalized") return status;
          }
          const height = await connection.getBlockHeight("confirmed");
          if (height > lastValidBlockHeight) {
            throw new Error(`block height ${height} passed ${lastValidBlockHeight} before ${signature} confirmed`);
          }
          if (Date.now() > deadline) throw new Error(`not confirmed within ${CONFIRMATION_MAX_MS} ms`);
          await new Promise((resolve) => setTimeout(resolve, CONFIRMATION_POLL_MS));
        }
      },
    };
  }

  /**
   * Round 29 (L2): a repeat of a request whose last submission failed
   * ambiguously is not rebuilt until the RPC says that submission cannot land
   * — or has landed, in which case the repeat is refused once, naming it.
   * An RPC that cannot answer is a refusal too.
   *
   * Round 30: "the same request" is the same effect — the destination and
   * lamports of a transfer, the route program, mints and amount of a swap —
   * not the same text, so "Send 1 SOL to X" and "send 1 SOL to X." are one
   * request. A submission that was sent but not seen confirmed is unresolved
   * too, and the record survives a restart when a state file is configured.
   */
  async #assertNoUnresolvedSubmission(requestKey: string, alsoMatches?: (key: string) => boolean): Promise<void> {
    // Round 38 (G2-2): a record under another key that names the same request
    // (a swap's key before Round 38 named its route) holds it back too.
    let key = requestKey;
    let prior = this.#state.unresolved(key);
    if (!prior && alsoMatches) {
      const found = this.#state.unresolvedEntries().find(([k]) => alsoMatches(k));
      if (found) [key, prior] = found;
    }
    if (!prior) return;
    const landed = (status: SignatureStatus) => {
      this.#state.markResolved(key);
      if (status.err === null) {
        throw new PriorSubmissionUnresolved(
          `[Graphite] the last submission of this same request, ${prior.signature}, LANDED (its send had failed ` +
            "ambiguously). Not building it a second time; repeat the request if a second one is really meant.",
          prior.signature,
        );
      }
      // It landed and failed: nothing moved but its fee. Its reservation is
      // kept (the fee was paid; the window returns the rest).
    };
    const status = await this.#signatureStatus(prior.signature);
    if (status) return landed(status);
    const height = await this.#connection.getBlockHeight("confirmed");
    if (height <= prior.lastValidBlockHeight) {
      throw new PriorSubmissionUnresolved(
        `[Graphite] the last submission of this same request, ${prior.signature}, failed ambiguously and can ` +
          `still land until block height ${prior.lastValidBlockHeight} (now ${height}). Not building a second ` +
          "transaction for it until that has passed.",
        prior.signature,
      );
    }
    // Round 38 (G2-4): asked again now that the height has passed (see
    // `#cannotLand`), and only then settled.
    const again = await this.#signatureStatus(prior.signature);
    if (again) return landed(again);
    this.#returnReservationOf(key, prior);
  }

  /** The RPC's status for `signature`, searching its history; null when it knows none. */
  async #signatureStatus(signature: string): Promise<SignatureStatus | null> {
    return (await this.#connection.getSignatureStatuses([signature], { searchTransactionHistory: true })).value[0];
  }

  /**
   * Whether `prior` provably did not land and cannot (Round 38, G2-4): the
   * RPC knows no status for it, the confirmed block height is past its last
   * valid height, and — asked again AFTER that height was read — it still
   * knows none. A transaction that landed is in a block at or below its last
   * valid height, which is confirmed by the time the height is read past it,
   * so the second "none" cannot be a landing the RPC had not caught up with.
   * Throws when the RPC cannot answer; the caller then keeps it counted.
   */
  async #cannotLand(prior: UnresolvedSubmission): Promise<boolean> {
    if (await this.#signatureStatus(prior.signature)) return false;
    const height = await this.#connection.getBlockHeight("confirmed");
    if (height <= prior.lastValidBlockHeight) return false;
    return (await this.#signatureStatus(prior.signature)) === null;
  }

  /**
   * `key`'s submission did not land and cannot: it is settled, and the
   * aggregate reservation recorded with it is returned (Round 38, G2-4).
   * Before Round 38 an outcome-unknown reservation was kept for the whole
   * spend window whatever the chain said. A record written before Round 38
   * names no reservation; its spend counts until the window ends.
   */
  #returnReservationOf(key: string, prior: UnresolvedSubmission): void {
    if (prior.reservation !== undefined) this.#state.release(prior.reservation);
    this.#state.markResolved(key);
  }

  /**
   * Reserve `lamports` of the aggregate allowance (Round 29, M6). Round 38
   * (G2-4): when the allowance would refuse, the submissions whose outcome
   * was unknown are asked about first — each that provably did not land and
   * cannot (`#cannotLand`) returns its reservation — and the reservation is
   * tried once more. An RPC that cannot answer leaves them counted, and the
   * refusal stands. A request in flight is not asked about: its own call
   * settles it.
   */
  async #reserve(lamports: bigint): Promise<SpendReservation> {
    this.#assertMaySpend();
    try {
      return this.#ledger.reserve(lamports);
    } catch (refusal) {
      if (!(refusal instanceof SpendPolicyRefusal)) throw refusal;
      let returned = 0;
      for (const [key, prior] of this.#state.unresolvedEntries()) {
        if (prior.reservation === undefined || this.#inFlight.has(key)) continue;
        try {
          if (await this.#cannotLand(prior)) {
            this.#returnReservationOf(key, prior);
            returned += 1;
          }
        } catch {
          // The RPC could not say: it stays counted.
        }
      }
      if (returned === 0) throw refusal;
      // Checked and claimed synchronously again, as the first attempt was.
      this.#assertMaySpend();
      return this.#ledger.reserve(lamports);
    }
  }

  /**
   * Claim `key` for this call, synchronously (Round 30): a second call for
   * the same request while the first is still running — a model calling the
   * tool twice, a caller that did not await, a confirmation hook that calls
   * back in — is refused before anything is built. Returns the release.
   */
  #claim(key: string): () => void {
    if (this.#inFlight.has(key)) {
      throw new RequestInFlight(
        "[Graphite] this same request is already being executed by this guard. Not building a second " +
          "transaction for it; wait for the first call's outcome.",
      );
    }
    this.#inFlight.add(key);
    return () => {
      this.#inFlight.delete(key);
    };
  }

  /**
   * The last step, and the only place this bridge signs anything.
   *
   * Three things happen in one place on purpose. The verdict must be bound to
   * bytes at all; the transaction must still serialize to the digest Graphite
   * approved; and the bytes that go to the network must carry the message that
   * was approved. Splitting them across call sites is how the previous version
   * ended up verifying one transaction and submitting another.
   *
   * Round 9: the residual policy decides first, the signing is on the trail
   * before submission, the submission is on the trail after it, and L8
   * reconciles the signature at the end. Round 29: the caller's confirmation
   * runs after the policy and before signing (M7); the aggregate reservation
   * is kept once the bytes may have left (M6); an ambiguous send is remembered
   * against its request (L2). Round 30: the submission is recorded as
   * unresolved BEFORE it is sent, and resolved only once it is seen
   * confirmed; a send whose confirmation did not complete stays unresolved.
   */
  async #signSubmitAndConfirm(
    bound: BoundTransaction,
    verification: VerificationResult,
    label: string,
    key: string,
    reservation: SpendReservation,
    verdictRequestedAt: number,
    confirm?: (acceptedUnobserved: string[]) => Promise<boolean>,
  ): Promise<ExecutionLifecycle> {
    // The whole path — policy, signing, the lifecycle events, submission,
    // confirmation, L8 — is `executeBoundTransaction`, in that order. See
    // execution-lifecycle.ts for why each step sits where it does.
    try {
      // Round 34: open, and still holding the wallet, before signing.
      this.#assertMaySpend();
      const lifecycle = await executeBoundTransaction({
        bound,
        verification,
        signers: [this.#signer],
        connection: this.#submitConnection(),
        graphite: this.#graphite,
        policy: this.#residualPolicy,
        reportedBy: this.#reporter(),
        label,
        confirmTimeoutMs: this.#confirmTimeoutMs,
        // Round 35 (F-017): the verdict's age, checked immediately before
        // the digest is recomputed and the bytes signed.
        verdictAge: { requestedAt: verdictRequestedAt, maxMs: this.#maxVerdictAgeMs },
        ...(confirm ? { confirm: ({ acceptedUnobserved }) => confirm(acceptedUnobserved) } : {}),
        // Round 34: again before signing, after the confirmation, which can
        // take minutes; the guard can be closed or lose its lock meanwhile.
        beforeSign: () => this.#assertMaySpend(),
        // And as the last step before the bytes leave (the signing is
        // recorded on the trail in between). A refusal here sends nothing.
        // Round 38 (G2-4): with the reservation that pays for it, so that it
        // can be returned once the chain says this submission cannot land.
        beforeSubmit: (signature) => {
          this.#assertMaySpend();
          this.#state.markUnresolved(key, signature, bound.lastValidBlockHeight, Date.now(), reservation.id);
        },
      });
      reservation.commit();
      if (lifecycle.confirmed) this.#state.markResolved(key);
      return lifecycle;
    } catch (e) {
      if (e instanceof SubmissionOutcomeUnknown) {
        // Already recorded as unresolved by `beforeSubmit`.
        reservation.commit();
      } else {
        reservation.release();
        // Round 38 (G2-4): the RPC was never reached, so the submission
        // `beforeSubmit` recorded never happened.
        if (e instanceof SubmissionNotSent) this.#state.markResolved(key);
      }
      throw e;
    }
  }

  /**
   * Build the one transaction that will be verified, signed and submitted,
   * in the configured message format.
   *
   * Legacy (the default): a legacy message, or v0 reading through the lookup
   * tables a swap route names (Round 22). Every table must be readable; one
   * that is not is a refusal, never a smaller transaction than the route
   * asked for.
   *
   * Version 1 (R-P8 phase 2): v1 has no lookup tables and up to 64 inline
   * addresses in 4,096 bytes, so a route's accounts are carried inline and
   * its tables are not read; a route too large for that is refused by
   * `BoundTransaction.build`. The limits are measured by an unsigned
   * simulation first (`RpcSimulator.estimateV1Limits`): in v1 an unset limit
   * is zero, and the limits are part of the bytes Graphite verifies.
   */
  async #buildBound(
    instructions: TransactionInstruction[],
    tableAddresses: string[] = [],
  ): Promise<BoundTransaction> {
    const feePayer = this.#signer.publicKey;
    if (this.#transactionVersion === 1) {
      const limits = await this.#simulator.estimateV1Limits({ instructions, feePayer });
      console.log(
        `[Graphite] v1 budget measured: ${limits.unitsConsumed} CU used -> limit ${limits.computeUnitLimit}; ` +
          `${limits.loadedAccountsDataSize} bytes loaded -> limit ${limits.loadedAccountsDataSizeLimit}`,
      );
      const { blockhash, lastValidBlockHeight } = await this.#connection.getLatestBlockhash();
      return BoundTransaction.build({
        instructions,
        feePayer,
        recentBlockhash: blockhash,
        lastValidBlockHeight,
        version: 1,
        v1Limits: {
          computeUnitLimit: limits.computeUnitLimit,
          loadedAccountsDataSizeLimit: limits.loadedAccountsDataSizeLimit,
        },
      });
    }
    const addressLookupTables: AddressLookupTableAccount[] = [];
    for (const address of tableAddresses) {
      const table = (await this.#connection.getAddressLookupTable(new PublicKey(address))).value;
      if (!table) {
        throw new Error(
          `[Graphite] address lookup table ${address} named by the swap payload could not be read. ABORTING.`,
        );
      }
      addressLookupTables.push(table);
    }
    const { blockhash, lastValidBlockHeight } = await this.#connection.getLatestBlockhash();
    return BoundTransaction.build({
      instructions,
      feePayer,
      recentBlockhash: blockhash,
      lastValidBlockHeight,
      ...(addressLookupTables.length > 0 ? { version: 0 as const, addressLookupTables } : {}),
    });
  }

  #verdictSummary(verification: VerificationResult, acceptedUnobserved: string[]): ConfirmationSummary["verdict"] {
    const scope = verification.scope;
    return {
      approved: verification.approved,
      confidence: verification.confidence,
      risk: verification.risk_verdict.status,
      auditTrailId: verification.audit_trail_id,
      ...(scope?.kind === "artifact_bound" ? { transactionSha256: scope.transaction_sha256 } : {}),
      unobservedCodes: [...(scope?.unobserved_codes ?? [])],
      acceptedUnobserved: [...acceptedUnobserved],
    };
  }

  /**
   * The digest a confirmation is about (Round 30). The hook runs after the
   * residual policy, which has already required an artifact-bound verdict;
   * this is the same requirement, stated where the summary is built.
   */
  #approvedDigest(verification: VerificationResult): string {
    const scope = verification.scope;
    if (scope?.kind !== "artifact_bound") {
      throw new Error("[Graphite] a confirmation was asked for a verdict that is not artifact-bound. ABORTING.");
    }
    return scope.transaction_sha256;
  }

  async executeTransfer(naturalLanguage: string, options: ExecuteOptions = {}): Promise<ExecutionOutcome> {
    this.#assertOpen();
    const proposedIntent = await this.parseIntent(naturalLanguage);
    console.log(`[Graphite] Parsed intent: ${proposedIntent.intent_type} (conf: ${proposedIntent.confidence_of_parse})`);

    // Round 19 (F-19-C5): destination and amount are taken from the user's
    // own text, and the AI layer's reading is accepted only where it matches
    // that text exactly. Round 29 (H3 + M5): and the text must be, as a whole,
    // an imperative transfer of SOL to that address (`TRANSFER_GRAMMAR`).
    // The class is the method's; the AI layer's label must agree with it.
    const intentType = groundTransferClass(proposedIntent.intent_type);
    const grounded = groundTransferIntent(naturalLanguage, proposedIntent.extracted_parameters);
    const destination = grounded.destination;
    // The operator's limits, on the grounded values, before a blockhash is
    // fetched, anything is simulated or the Core is asked.
    assertTransferAllowed(this.#spendPolicy, destination, grounded.lamports);
    // Round 30: the request is its effect, not its wording.
    const key = `transfer:${destination}:${grounded.lamports}`;
    const releaseClaim = this.#claim(key);
    try {
      return await this.#executeTransferClaimed(naturalLanguage, options, proposedIntent, intentType, grounded, key);
    } finally {
      releaseClaim();
    }
  }

  async #executeTransferClaimed(
    naturalLanguage: string,
    options: ExecuteOptions,
    proposedIntent: ProposedIntent,
    intentType: ReturnType<typeof groundTransferClass>,
    grounded: ReturnType<typeof groundTransferIntent>,
    key: string,
  ): Promise<ExecutionOutcome> {
    const destination = grounded.destination;
    await this.#assertNoUnresolvedSubmission(key);
    // The intent sent to the Core is rebuilt from the grounded values and the
    // guard's own copy of the request — nothing the AI layer wrote beyond its
    // confidence travels (audit 2026-10-20, Info). The Core does not compare
    // the amount or the destination with the instruction; they are bound
    // here, because the transfer below is built from exactly these values.
    const groundedIntent: ProposedIntent = {
      intent_type: intentType,
      raw_natural_language: naturalLanguage,
      confidence_of_parse: proposedIntent.confidence_of_parse,
      extracted_parameters: {
        amount: grounded.amountText,
        destination: grounded.destination,
        input_token: "SOL",
      },
    };

    const destPubkey = new PublicKey(destination);
    const transferIx = SystemProgram.transfer({
      fromPubkey: this.#signer.publicKey,
      toPubkey: destPubkey,
      lamports: grounded.lamports,
    });

    const SYSTEM_PROGRAM = "11111111111111111111111111111111";
    const TRANSFER_DISCRIMINATOR = "02000000";

    // C22 TOCTOU closure: bind the AMOUNT, not just program+discriminator+
    // accounts. The transfer amount lives in `transferIx.data` (u64 LE
    // lamports after the 0x02 discriminator). Both sides must carry the same
    // raw data bytes: the Rust content_hash includes instruction_data only
    // when it is present (generate_audit_id), so we pass it to verification
    // AND to the AuditBind projection together.
    const transferData = Array.from(transferIx.data);
    // ONE transaction object, built before verification and carried through to
    // submission. The bytes Graphite verifies come out of it, the digest is
    // re-checked against it immediately before signing, and the signed bytes
    // come from it. There is no second transaction for the two to drift apart.
    const bound = await this.#buildBound([transferIx]);
    // Round 32: the limits count what the wallet pays, not only what it
    // sends — the amount plus the fee this message asks for, or what one
    // simulation of these exact bytes takes out of the wallet, whichever is
    // larger — and the aggregate reserves the same figure.
    const outflow = await this.#transferOutflow(bound, grounded.lamports);
    assertOutflowAllowed(this.#spendPolicy, outflow, "transfer");
    // Round 29 (M6): the aggregate limit, claimed now and returned unless
    // the bytes leave the process.
    const reservation = await this.#reserve(outflow.lamports);
    let handedOff = false;
    try {
      // Round 35 (F-017): the verdict's age is counted from before it was
      // asked for, so it is never under-counted.
      const verdictRequestedAt = performance.now();
      const verification = await this.#verifyTransaction({
        programId: SYSTEM_PROGRAM, instructionDiscriminator: TRANSFER_DISCRIMINATOR,
        accountAddresses: [this.#walletPublicKey, destination], proposedIntent: groundedIntent, instructions: [transferIx],
        instructionData: transferData,
        bound,
      });

      console.log(`[Graphite] ${verification.approved ? "APPROVED" : "BLOCKED"} (confidence: ${verification.confidence})`);
      if (!verification.approved) { console.log("[Graphite] Transfer BLOCKED."); return { executed: false, verifiedExecution: false, verification }; }
      // `approved` alone is not the gate: `#signSubmitAndConfirm` refuses
      // anything but an artifact-bound verdict whose residuals the policy
      // accepts. The report here is the human-readable half of that decision.
      reportVerificationScope(verification, "transfer");

      // AuditBind over the bound transaction's own instructions (copies, so
      // nothing it does reaches what is signed). The discriminator is passed
      // explicitly because System Transfer's is 4 bytes and the Anchor default
      // would read 8, picking up half the lamport amount.
      const instructions = bound.instructions();
      // 1. The verified instruction is still the one in the transaction.
      AuditBind.verifyInstruction(
        {
          programId: instructions[0].programId.toBase58(),
          data: instructions[0].data,
          accounts: instructions[0].keys.map((k) => k.pubkey.toBase58()),
          discriminator: TRANSFER_DISCRIMINATOR,
        },
        verification.content_hash ?? verification.audit_trail_id,
      );
      // 2. And nothing else joined it.
      if (instructions.length !== 1) {
        throw new Error(
          `AuditBind FAILED: ${instructions.length} instructions present, 1 verified. ABORTING.`,
        );
      }
      // Round 29 (audit 2026-10-20, Info): a `transactionBinding` taken here
      // and compared a line later, over two fresh copies of the same private
      // instructions with no await between, could not differ and so checked
      // nothing; it is gone. What covers the window up to signing is
      // `signApproved`, which re-serializes the transaction itself and
      // requires the digest Graphite approved.

      const confirm = options.confirm
        ? async (acceptedUnobserved: string[]) => {
            const effect = await this.#simulator.measureWalletEffect({ wire: bound.artifactBytes, wallet: this.#walletPublicKey });
            return options.confirm!(deepFreeze({
              kind: "transfer",
              request: naturalLanguage,
              wallet: this.#walletPublicKey,
              transactionSha256: this.#approvedDigest(verification),
              programId: SYSTEM_PROGRAM,
              destination,
              lamports: grounded.lamports.toString(),
              sol: lamportsAsSol(grounded.lamports),
              walletEffect: effectForSummary(effect),
              verdict: this.#verdictSummary(verification, acceptedUnobserved),
            }));
          }
        : undefined;
      console.log("[Graphite] Transfer approved + AuditBind verified — executing...");
      handedOff = true;
      const lifecycle = await this.#signSubmitAndConfirm(bound, verification, "transfer", key, reservation, verdictRequestedAt, confirm);
      console.log(`[Solana] ${lifecycle.confirmed ? "Confirmed" : "Submitted (not confirmed)"}: ${lifecycle.signature}`);
      return { executed: true, verifiedExecution: true, verification, signature: lifecycle.signature, lifecycle };
    } finally {
      // `#signSubmitAndConfirm` settles the reservation itself once handed off.
      if (!handedOff) reservation.release();
    }
  }

  /**
   * What a transfer takes out of the wallet (Round 32): its amount plus the
   * fee its message asks for, or what one simulation of the exact unsigned
   * bytes takes from the fee payer, whichever is larger. A simulation that
   * fails is a refusal: these are the bytes that would be signed.
   */
  async #transferOutflow(bound: BoundTransaction, amount: bigint): Promise<MeasuredTransferOutflow> {
    const fee = transactionFee(bound.messageBytes);
    const effect = await this.#simulator.measureWalletEffect({ wire: bound.artifactBytes, wallet: this.#walletPublicKey });
    const stated = amount + fee.totalLamports;
    const simulated = effect.solOut > 0n ? effect.solOut : 0n;
    return { lamports: stated > simulated ? stated : simulated, amount, fee, simulated };
  }

  /**
   * Execute a swap under the Graphite verification gate.
   *
   * TOCTOU hardening (audit finding C2, CLOSED 2026-09-05): `payload` is the
   * EXACT swap instruction (programId, discriminator, full account list WITH
   * per-account isSigner/isWritable, raw data bytes). This method builds the
   * `TransactionInstruction` from those same fields and submits it itself;
   * any mutation between verification and execution changes the content_hash
   * and ABORTS. The per-account flags are forwarded to Graphite as
   * `real_account_metas` (P1 fix, 2026-09-05). Without `payload` this
   * REFUSES (2026-09-08), and the unverified opt-out is gone (Round 19,
   * F-19-C2): a swap is a payload the bridge verifies and signs itself, or it
   * is refused.
   *
   * Round 29 (audit 2026-10-20, H2 + H4, L1, L4): the payload must be an
   * exact-in instruction whose data the guard decodes (`swap-instructions.ts`);
   * its own minimum output is held to what was simulated, the slippage
   * allowed and a price floor (`swap-economics.ts`); the selector sent to the
   * Core and bound by AuditBind is the decoded one, normalised once; and the
   * operator's compute budget and output account, when configured, are built
   * around it (`swap-envelope.ts`).
   */
  async executeSwap(
    naturalLanguage: string,
    payload?: BoundInstructionPayload,
    options: ExecuteOptions = {},
  ): Promise<ExecutionOutcome> {
    this.#assertOpen();
    const proposedIntent = await this.parseIntent(naturalLanguage);
    console.log(`[Graphite] Parsed intent: ${proposedIntent.intent_type} (conf: ${proposedIntent.confidence_of_parse})`);

    const params = proposedIntent.extracted_parameters;
    if (!params?.input_token || !params?.output_token || !params?.amount) throw new Error("Swap requires input_token, output_token, amount");

    // No payload, no swap. Round 19 (F-19-C2): the unverified opt-out that
    // used to live here executed through SAK's builder with the key SAK held;
    // SAK holds no signing key now, so there is nothing to opt into. An
    // operator who still sets the opt-in phrase is told so by name rather
    // than having it silently ignored.
    if (!payload) {
      const optOutStillSet =
        process.env.GRAPHITE_SWAP_ALLOW_UNVERIFIED_EXECUTION === UNVERIFIED_SWAP_OPT_IN;
      throw new Error(
        "[Graphite] a swap requires a built payload (programId / discriminator / accounts with " +
          "isSigner+isWritable / instructionData) so the instruction that is verified is the " +
          "instruction that is submitted. Without it Graphite would be asked to verify a " +
          "one-account projection while some other builder submits a different instruction entirely — " +
          "no destination, no vaults, no amounts, nothing about the real swap observed. " +
          "Build the route first and pass it. " +
          (optOutStillSet
            ? `GRAPHITE_SWAP_ALLOW_UNVERIFIED_EXECUTION=${UNVERIFIED_SWAP_OPT_IN} is set, but that ` +
              "opt-out was retired in Round 19 (F-19-C2): SAK's wallet cannot sign, so there is no " +
              "unverified execution path. "
            : "") +
          "ABORTING."
      );
    }
    // A5-01: the class of this request is a swap because this is the swap
    // method and the user's text asks for one — not because the AI layer said
    // so. The payload must also be addressed to a swap program the guard
    // decodes. All of it is decided here, before a blockhash is fetched or
    // the Core is asked.
    const intentType = groundSwapIntent(naturalLanguage, proposedIntent.intent_type, payload.programId);
    // Which swap: the amount and both tokens, read from the user's own text
    // and agreed by the AI layer's reading (external review, 2026-10-16), and
    // since Round 29 the whole request in one accepted form.
    const groundedSwap = groundSwapRequest(naturalLanguage, params);
    // Round 29 (H2/H4): the route's own amounts, from its data; exact-in only.
    const decoded = decodeSwapInstruction(
      payload.programId,
      Uint8Array.from(payload.instructionData ?? []),
      payload.discriminator,
    );
    // Round 30: the request is its effect, not its wording. Round 38 (G2-2):
    // and not its route — this wallet spending this amount of this mint for
    // that one. The key named the route program, so after an outcome-unknown
    // swap the same swap through another route was not a repeat, and both
    // could land.
    const key = swapRequestKey(this.#walletPublicKey, groundedSwap.input.mint, groundedSwap.output.mint, decoded.amountIn);
    const releaseClaim = this.#claim(key);
    try {
      return await this.#executeSwapClaimed(naturalLanguage, payload, options, proposedIntent, intentType, groundedSwap, decoded, key);
    } finally {
      releaseClaim();
    }
  }

  async #executeSwapClaimed(
    naturalLanguage: string,
    payload: BoundInstructionPayload,
    options: ExecuteOptions,
    proposedIntent: ProposedIntent,
    intentType: ReturnType<typeof groundSwapIntent>,
    groundedSwap: ReturnType<typeof groundSwapRequest>,
    decoded: ReturnType<typeof decodeSwapInstruction>,
    key: string,
  ): Promise<ExecutionOutcome> {
    await this.#assertNoUnresolvedSubmission(
      key,
      legacySwapKeyMatcher(groundedSwap.input.mint, groundedSwap.output.mint, decoded.amountIn),
    );
    const swapIntent: ProposedIntent = {
      intent_type: intentType,
      raw_natural_language: naturalLanguage,
      confidence_of_parse: proposedIntent.confidence_of_parse,
      // Round 36 (F-003): the Core binds these to the bytes, and it reads a
      // token only as "SOL" or a base58 mint — a symbol ("USDC") is unbound
      // and the verdict carries `intent_parameters`. So the grounded MINTS
      // travel, and "SOL" for the native mint, never the text as written.
      extracted_parameters: {
        amount: groundedSwap.amountText,
        input_token: coreTokenOf(groundedSwap.input.mint),
        output_token: coreTokenOf(groundedSwap.output.mint),
        ...(groundedSwap.slippageBps !== undefined ? { slippage_bps: groundedSwap.slippageBps } : {}),
      },
    };
    const accountAddresses = payload.accounts.map((a) => a.pubkey);
    // P1 fix (2026-09-05 audit): the bound payload already carries the REAL
    // per-account isSigner/isWritable flags — forward them as
    // real_account_metas so the Core cross-checks them against the manifest.
    const realAccountMetas = payload.accounts.map((a) => ({ is_signer: a.isSigner, is_writable: a.isWritable }));
    // Round 29 (L4): the envelope, built by the guard from configuration and
    // the wallet's own key — nothing in it comes from the payload.
    const envelope = buildSwapEnvelope({
      wallet: this.#signer.publicKey,
      payload,
      outputMint: groundedSwap.output.mint,
      config: this.#swapEnvelope,
      version: this.#transactionVersion,
    });
    // Built once, from the payload, before verification.
    const boundSwap = await this.#buildBound(
      [...envelope, buildInstructionFromPayload(payload)],
      payload.addressLookupTableAddresses ?? [],
    );
    // What this exact transaction does to the wallet, from one simulation of
    // the bytes that will be signed (pre- and post-balances of the same run),
    // never from the request, whose amounts are whatever the model wrote.
    // First the operator's limits, then the request itself, then what the
    // route must be worth.
    let effect: WalletEffect;
    try {
      effect = await this.#simulator.measureWalletEffect({
        wire: boundSwap.artifactBytes,
        wallet: this.#walletPublicKey,
      });
    } catch (e) {
      // Round 30 (G-12): a SOL-input swap spends wrapped SOL the wallet
      // already holds, because the guard does not wrap. The most common
      // reason such a simulation fails is that there is none to spend; say
      // so by capability rather than leave a bare simulation error.
      if (groundedSwap.input.mint === NATIVE_MINT) {
        throw new UnsupportedCapability(
          "wrap_sol",
          `the simulation of this SOL-input swap failed (${(e as Error).message.slice(0, 200)}). The guard does not ` +
            `wrap SOL (GUARD_CAPABILITIES.operations.wrapSol is false): the route must spend wrapped SOL the wallet ` +
            `already holds, ${decoded.amountIn} lamports' worth of it. Fund the wallet's wrapped-SOL account first.`,
        );
      }
      throw e;
    }
    // The priority fee the envelope permits is counted on top of what was
    // measured: conservative if the simulation charged it already. Round 32:
    // and never below the fee the signed message itself asks for (base fee
    // per signature plus its priority fee), read from its bytes.
    const swapFee = transactionFee(boundSwap.messageBytes);
    const measuredOutflow = (effect.solOut > 0n ? effect.solOut : 0n) + maxPriorityFeeLamports(this.#swapEnvelope);
    const outflowLamports = measuredOutflow > swapFee.totalLamports ? measuredOutflow : swapFee.totalLamports;
    assertSwapAllowed(this.#spendPolicy, {
      lamports: outflowLamports,
      tokens: [...effect.tokenDelta]
        .filter(([, delta]) => delta < 0n)
        .map(([mint, delta]) => ({ mint, amount: -delta })),
    });
    assertSwapEffectMatches(groundedSwap, effect);
    const economics: SwapEconomics = assertSwapEconomics({
      grounded: groundedSwap,
      decoded,
      effect,
      policy: this.#swapPolicy,
    });
    if (economics.floor.source === "unpriced") {
      console.warn(
        "[Graphite] swap: no price floor applies (GRAPHITE_SWAP_ALLOW_UNPRICED=1, an accepted risk); the route's " +
          `minimum of ${economics.minOut} is held only to the simulated ${economics.simulatedOut}.`,
      );
    }
    const reservation = await this.#reserve(outflowLamports);
    let handedOff = false;
    try {
      // Round 35 (F-017): the verdict's age is counted from before it was
      // asked for, so it is never under-counted.
      const verdictRequestedAt = performance.now();
      const verification = await this.#verifyTransaction({
        programId: payload.programId,
        // Round 29 (L1): the decoded selector, normalised once, is both what
        // the Core hashes and what AuditBind binds below.
        instructionDiscriminator: decoded.discriminator,
        accountAddresses, proposedIntent: swapIntent,
        instructionData: payload.instructionData,
        realAccountMetas,
        // The transaction that will be signed, not a copy of its instructions.
        bound: boundSwap,
      });

      console.log(`[Graphite] ${verification.approved ? "APPROVED" : "BLOCKED"} (confidence: ${verification.confidence})`);
      if (!verification.approved) { console.log("[Graphite] Swap BLOCKED."); return { executed: false, verifiedExecution: false, verification }; }
      reportVerificationScope(verification, "swap");

      // Bind the EXACT instruction that will be submitted (full data + accounts),
      // with the discriminator string the Core was sent. Round 29 (L1): this
      // used to omit it, so AuditBind re-derived an 8-byte selector from the
      // data; for a 1-byte program (Raydium AMM v4) or a payload that wrote
      // its selector in capitals, the two hashes never matched and every
      // approved swap aborted.
      AuditBind.verifyInstruction(
        {
          programId: payload.programId,
          data: Uint8Array.from(payload.instructionData ?? []),
          accounts: accountAddresses,
          discriminator: normalizeDiscriminator(decoded.discriminator),
        },
        verification.content_hash ?? verification.audit_trail_id,
      );
      console.log("[Graphite] Swap payload bound to AuditBind (instruction data + full account list).");

      const confirm = options.confirm
        ? (acceptedUnobserved: string[]) =>
            options.confirm!(deepFreeze({
              kind: "swap",
              request: naturalLanguage,
              wallet: this.#walletPublicKey,
              transactionSha256: this.#approvedDigest(verification),
              programId: payload.programId,
              swap: {
                route: decoded.name,
                input: { token: groundedSwap.input.written, mint: groundedSwap.input.mint, amountIn: economics.amountIn.toString() },
                output: {
                  token: groundedSwap.output.written,
                  mint: groundedSwap.output.mint,
                  minimumOut: economics.minOut.toString(),
                  simulatedOut: economics.simulatedOut.toString(),
                  ...(groundedSwap.output.mint === NATIVE_MINT ? { deliveredAs: "wrapped_sol" as const } : {}),
                },
                maxSlippageBps: economics.maxSlippageBps,
                priceFloor:
                  economics.floor.source === "unpriced"
                    ? "none (GRAPHITE_SWAP_ALLOW_UNPRICED=1)"
                    : `${economics.floor.baseUnits} base units (${economics.floor.source})`,
              },
              walletEffect: effectForSummary(effect),
              verdict: this.#verdictSummary(verification, acceptedUnobserved),
            }))
        : undefined;
      // `boundSwap` holds the instruction built from this same payload before
      // verification, and its bytes are what Graphite verified. Rebuilding here
      // would reintroduce the copy-versus-original gap one level down.
      console.log("[Graphite] Swap approved + AuditBind verified — submitting the bound transaction...");
      handedOff = true;
      const lifecycle = await this.#signSubmitAndConfirm(boundSwap, verification, "swap", key, reservation, verdictRequestedAt, confirm);
      console.log(`[Solana] ${lifecycle.confirmed ? "Confirmed" : "Submitted (not confirmed)"}: ${lifecycle.signature}`);
      return { executed: true, verifiedExecution: true, verification, signature: lifecycle.signature, lifecycle };
    } finally {
      if (!handedOff) reservation.release();
    }
  }

  /** The operator's spending limits, as configured (a copy). */
  get limits(): SpendPolicy {
    const p = this.#spendPolicy;
    return {
      ...(p.maxTransferLamports !== undefined ? { maxTransferLamports: p.maxTransferLamports } : {}),
      ...(p.allowedDestinations !== undefined ? { allowedDestinations: [...p.allowedDestinations] } : {}),
      ...(p.maxTotalLamports !== undefined ? { maxTotalLamports: p.maxTotalLamports } : {}),
      ...(p.spendWindowSeconds !== undefined ? { spendWindowSeconds: p.spendWindowSeconds } : {}),
      ...(p.allowUncapped !== undefined ? { allowUncapped: p.allowUncapped } : {}),
    };
  }

  /** The wallet's public key, base58. The secret key is not reachable from outside. */
  get publicKey(): string { return this.#walletPublicKey; }

  /**
   * The Core's read-only endpoints (Round 29, M8). This returned the
   * `GraphiteClient` itself, and with it the Core's API key
   * (`getGraphiteClient()["apiKey"]`) and a `verify` any caller could use to
   * write to the trail under this deployment's key. Callers that need more
   * build their own client with their own key.
   */
  getGraphiteClient(): GraphiteReadClient {
    const graphite = this.#graphite;
    return Object.freeze({
      health: () => graphite.health(),
      listManifests: () => graphite.listManifests(),
    });
  }

  /**
   * An RPC connection, for read-only use. Its endpoint is the operator's
   * SOLANA_RPC_URL, which for some providers carries an API key in the query.
   *
   * Round 30: a separate `Connection` to the same endpoint, not the one the
   * guard decides on. The guard's own answers whether a prior submission
   * landed (`getSignatureStatuses`), what blockhash and lookup tables a
   * transaction is built on, and where signed bytes are sent; a caller that
   * replaced one of those methods on the object it was handed rewrote the
   * guard's view of the chain. It now rewrites only its own.
   */
  getConnection(): Connection { return this.#readConnection; }
}
// Round 29 (M8): no method of the class can be replaced at runtime either.
Object.freeze(GraphiteGuard.prototype);
Object.freeze(GraphiteGuard);

/** What the guard signs with (Round 30): a public key and a non-extractable WebCrypto key pair. */
export interface WalletSigner {
  readonly publicKey: PublicKey;
  readonly keyPair: CryptoKeyPair;
}

/**
 * The wallet key, imported once into a NON-EXTRACTABLE WebCrypto key pair
 * (Round 30); the decoded bytes are zeroed whatever happens.
 * `createKeyPairFromBytes` checks that the public half belongs to the private
 * half by signing and verifying, so a 64-byte value whose halves do not match
 * is refused here. The base58 string itself cannot be zeroed (JavaScript
 * strings are immutable); the guard drops its reference to it, and to the
 * environment variable, once this returns.
 */
export async function walletSignerFrom(privateKeyBase58: string): Promise<WalletSigner> {
  let secret: Uint8Array;
  try {
    secret = Uint8Array.from(bs58.decode(privateKeyBase58));
  } catch {
    throw new Error("[Graphite] the wallet key is not base58. REFUSING TO START.");
  }
  try {
    if (secret.length !== 64) {
      throw new Error(`it decodes to ${secret.length} bytes, not the 64 of a Solana secret key`);
    }
    const keyPair = await createKeyPairFromBytes(secret, false);
    const publicKey = new PublicKey(await getAddressFromPublicKey(keyPair.publicKey));
    return Object.freeze({ publicKey, keyPair });
  } catch (e) {
    throw new Error(`[Graphite] the wallet key is not usable: ${(e as Error).message}. REFUSING TO START.`);
  } finally {
    secret.fill(0);
  }
}

/**
 * SOLANA_RPC_URL under the Core's transport rule (Round 29, audit 2026-10-20,
 * M3): https://, or http:// only to a loopback host. Every number a swap is
 * judged by — the wallet's balances before and after — comes from this
 * endpoint's simulation, and an answer rewritten in flight is a measurement
 * rewritten in flight. Never logs the URL (a provider URL can carry its key).
 */
export function assertSecureRpcUrl(url: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error("[Graphite] SOLANA_RPC_URL is not a valid URL. REFUSING TO START.");
  }
  try {
    assertSecureBaseUrl(url);
  } catch {
    throw new Error(
      `[Graphite] SOLANA_RPC_URL is refused: ${parsed.protocol}//${parsed.host} is not https://, nor http:// to a ` +
        "loopback host. The RPC alone measures what a swap does to the wallet, so it is held to the Core's " +
        "transport rule (Round 29, M3). REFUSING TO START.",
    );
  }
}

// Kept for callers that imported it (Round 29: the fetch every Connection uses).
export { noRedirectFetch };
