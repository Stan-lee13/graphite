/**
 * Graphite-SAK Bridge v2 — Production verification gate for Solana Agent Kit.
 *
 * Architecture (Constitution P1: AI assists, never decides):
 *   NL -> Python AI Layer (parse intent) -> Construct tx -> Graphite (verify) -> RPC simulate -> AuditBind -> Execute
 *
 * v2 improvements:
 *   1. RPC SIMULATION — calls simulateTransaction BEFORE verification to get real compute_units,
 *      account_writes, and cpi_hops, which feed the Simulation Integrity check (L3) and the
 *      audit trail. The simulated transaction is UNSIGNED (Round 19, F-19-C1 — see
 *      rpc-simulator.ts): nothing is signed before a verdict exists.
 *      NOTE: these do NOT boost the confidence score in Phase 1 — the Core
 *      intentionally zeroes the SimulationMatch/HistoricalVolume/CommunityVerification signal
 *      values (Constitution G4: request-body evidence is attacker-controlled) and caps trust
 *      tiers at the manifest's declared tier (P7). The achievable Phase 1 confidence for a
 *      known, clean, intent-aligned protocol is ~0.44. The default wallet profile below asks
 *      for 0.40, but the Core clamps every Custom profile to the weakest built-in (Gaming:
 *      0.55, HeuristicInferred), so it approves nothing until a protocol's evidence has been
 *      earned — it fails closed, it is not calibrated to pass.
 *   2. AUDITBIND MIDDLEWARE — after Graphite approves, re-computes the SAME deterministic
 *      content_hash the Rust Core produces (byte-for-byte: SHA-256 over programId, discriminator,
 *      account addresses, raw instruction-data bytes, and CPI targets, truncated to 16 hex chars)
 *      and compares against the verified content_hash. Blocks execution if the transaction was
 *      mutated in the TOCTOU window. The earlier "|"-joined/commas encoding never matched the
 *      Rust side and always aborted — this version mirrors the Core exactly.
 *   3. SAK plugins are loaded when the agent is created, each one on its own (rpc-websockets
 *      exports patched for compatibility). A plugin that fails to load is skipped with a
 *      warning; the bridge's own paths never depend on one.
 *   4. SAK NEVER HOLDS THE KEY (Round 19, F-19-C2 — see gated-wallet.ts). SolanaAgentKit is
 *      given a wallet with the public key only, whose every signing method refuses. The only
 *      code that signs with the wallet key is BoundTransaction.signApproved, after an
 *      artifact-bound approval.
 */

import { SolanaAgentKit } from "solana-agent-kit";
// `sendAndConfirmTransaction` is deliberately NOT imported: it prepares the
// transaction it is given, including fetching a blockhash when one is missing,
// and a mutation after approval is a mutation however benign. Signing goes
// through `signSubmitAndConfirm`, which submits bytes that are already final.
import { AddressLookupTableAccount, Keypair, Connection, SystemProgram, PublicKey, TransactionInstruction } from "@solana/web3.js";
import bs58 from "bs58";

// Round 19 (F-19-C1): simulation is unsigned by construction; the class
// lives in its own dependency-light module so its tests run without SAK.
import { RpcSimulator, assertEverySignatureSlotEmpty } from "./rpc-simulator.js";
export { RpcSimulator, assertEverySignatureSlotEmpty };
// Round 19 (F-19-C2): the wallet SAK is given cannot sign.
import { VerificationGatedWallet, UngatedSigningRefused, GATED_SIGNING_PATH } from "./gated-wallet.js";
export { VerificationGatedWallet, UngatedSigningRefused, GATED_SIGNING_PATH };
// Round 19 (F-19-C5): the AI layer's answer is checked against the user's text.
import { assertEcho, groundSwapIntent, groundTransferIntent, IntentGroundingError } from "./intent-grounding.js";
export { assertEcho, groundSwapIntent, groundTransferIntent, IntentGroundingError };
// A5-01: the programs a swap payload may be addressed to.
import { SWAP_PROGRAM_IDS } from "./swap-programs.js";
export { SWAP_PROGRAM_IDS };

// AuditBind lives in ./auditbind.ts — a dependency-free module (Node crypto
// only) so its cross-language pinned-vector tests run without the SAK tree.
import { AuditBind } from "./auditbind.js";
export { AuditBind };

// Graphite TS SDK
import { GraphiteClient, assertSecureBaseUrl } from "../../sdk/typescript/src/client.js";
import { ResidualPolicy } from "./residual-policy.js";
import { executeBoundTransaction, type ExecutionLifecycle } from "./execution-lifecycle.js";
import type {
  VerificationInput,
  VerificationResult,
  ProposedIntent,
  WalletProfile,
} from "../../sdk/typescript/src/types.js";

// Re-export types
export type { VerificationResult, VerificationInput, ProposedIntent, WalletProfile };

// TOCTOU closure for the swap payload path (P1 fix, 2026-09-05 audit) lives
// in its own module, deliberately isolated from the SAK plugin tree — see
// bound-instruction.ts's doc comment for why.
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
 * Load one SAK plugin, or say why not.
 *
 * The plugins used to be static imports, which made "fall back to raw web3.js
 * if plugin initialization fails" untrue: a plugin whose module failed to link
 * (the installed @solana-agent-kit/plugin-token and plugin-defi both fail on a
 * missing `@pump-fun/pump-sdk` export) took the whole bridge down at import,
 * verified paths included. Loaded here, a broken plugin costs only that
 * plugin's methods — and since Round 19 (F-19-C2) none of them can sign anyway.
 */
/**
 * Verified SAK Agent — wraps SolanaAgentKit with Graphite verification gate.
 *
 * Flow: Parse intent -> Construct tx -> RPC simulate -> Graphite verify -> AuditBind -> Execute
 */
/**
 * Surface what a verdict is actually bound to, and what it did not observe.
 *
 * Added 2026-09-08 after the Rust Core grew `VerificationResult.scope` while
 * this integration kept gating on `approved` alone. The two verdict modes —
 * describing caller-supplied metadata, and binding real signed bytes — are the
 * same shape on the wire, so `approved` cannot distinguish them. Anything that
 * can move funds should know which one it is holding.
 *
 * Reports rather than refuses, deliberately: neither bridge path hands the Core
 * a serialized artifact yet, so enforcing artifact binding here would refuse
 * everything. What protects these paths today is AuditBind against the live
 * instruction. Making the gap visible is the honest first step, and what stops
 * it being rediscovered later as a surprise.
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

export class VerifiedSakAgent {
  private sakAgent: SolanaAgentKit | null;
  private graphite: GraphiteClient;
  private connection: Connection;
  private walletProfile: WalletProfile;
  private aiLayerUrl: string;
  private aiLayerTimeoutMs: number;
  private walletPublicKey: string;
  // An ES private field, not TypeScript `private`: TypeScript's is a
  // compile-time label, and the key was readable as `agent.walletKeypair` by
  // any code holding this object (review of the 2026-09-29 audit, R8). A `#`
  // field cannot be read from outside the class at runtime.
  #walletKeypair: Keypair;
  private simulator: RpcSimulator;
  private residualPolicy: ResidualPolicy;
  private transactionVersion: BridgeTransactionVersion;

  private constructor(
    sakAgent: SolanaAgentKit | null, graphite: GraphiteClient, connection: Connection,
    walletProfile: WalletProfile, aiLayerUrl: string, walletPublicKey: string, walletKeypair: Keypair,
    residualPolicy: ResidualPolicy, aiLayerTimeoutMs: number, transactionVersion: BridgeTransactionVersion,
  ) {
    this.sakAgent = sakAgent; this.graphite = graphite; this.connection = connection;
    this.walletProfile = walletProfile; this.aiLayerUrl = aiLayerUrl; this.aiLayerTimeoutMs = aiLayerTimeoutMs;
    this.walletPublicKey = walletPublicKey; this.#walletKeypair = walletKeypair;
    this.simulator = new RpcSimulator(connection.rpcEndpoint);
    this.residualPolicy = residualPolicy;
    this.transactionVersion = transactionVersion;
  }

  /** The `reported_by` on every lifecycle row this bridge writes. */
  private reporter(): string {
    return `sak-bridge:${this.walletPublicKey.slice(0, 8)}`;
  }

  static async create(config?: {
    privateKey?: string; rpcUrl?: string; openAiApiKey?: string;
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
  }): Promise<VerifiedSakAgent> {
    // Before any default is applied: a legacy variable name must not quietly
    // become "use localhost" (Round 19, F-19-C6).
    assertNoLegacyEnvNames();
    const privateKey = config?.privateKey ?? process.env.SOLANA_PRIVATE_KEY;
    const rpcUrl = config?.rpcUrl ?? process.env.SOLANA_RPC_URL;
    const openAiApiKey = config?.openAiApiKey ?? process.env.OPENAI_API_KEY;
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

    const walletKeypair = Keypair.fromSecretKey(bs58.decode(privateKey));
    const walletPublicKey = walletKeypair.publicKey.toBase58();
    const connection = new Connection(rpcUrl, "confirmed");

    // Initialize the SAK agent — fallback to raw web3.js if runtime init fails.
    //
    // Round 19 (F-19-C2): SAK is given the PUBLIC key and nothing else. It
    // used to get `new KeypairWallet(walletKeypair)`, and with it the ability
    // to sign and send any transaction any plugin method or LLM-driven SAK
    // tool built, plus `signMessage` over arbitrary bytes — none of it through
    // Graphite. `VerificationGatedWallet` refuses every signing method, so
    // SAK's read-only uses keep working and everything that would sign fails
    // with an error naming the verified path.
    let sakAgent: SolanaAgentKit | null = null;
    try {
      if (!openAiApiKey) throw new Error("OPENAI_API_KEY required for SAK");
      const wallet = new VerificationGatedWallet(walletKeypair.publicKey);
      // No SAK plugins are loaded (2026-09-30). The bridge never calls them:
      // every transaction it signs is built here and verified by the Core.
      // They existed only for a caller's read-only use of `getSakAgent()`,
      // yet importing one executes its whole dependency tree in the process
      // that holds the private key. `@solana-agent-kit/plugin-defi` alone
      // brought 25 of the tree's 36 high/critical npm advisories, all three
      // criticals among them (Drift, OKX, Meteora, Orca SDKs). A caller that
      // needs a plugin's read-only helpers can load it in its own process.
      sakAgent = new SolanaAgentKit(wallet, rpcUrl, { OPENAI_API_KEY: openAiApiKey });
      console.log("[Graphite] SAK agent initialized (signing refused — gated wallet), no plugins loaded");
    } catch (err) {
      console.warn("[Graphite] SAK init failed — falling back to raw web3.js:", (err as Error).message?.slice(0, 80));
    }

    const graphite = new GraphiteClient({ baseUrl: graphiteCoreUrl, apiKey: graphiteApiKey });
    try { await graphite.health(); } catch {
      throw new Error(`Graphite Core not reachable at ${graphiteCoreUrl}. Start: GRAPHITE_API_KEY=... cargo run --release -- server`);
    }
    // Built here, not lazily: a typo in the accepted list is a startup error,
    // never a silent refusal at execution time.
    const residualPolicy = config?.acceptUnobserved
      ? new ResidualPolicy(config.acceptUnobserved)
      : ResidualPolicy.fromEnv();
    const accepted = residualPolicy.accepts();
    console.log(
      accepted.length === 0
        ? "[Graphite] residual policy: inherent residuals only — any other unobserved property refuses execution"
        : `[Graphite] residual policy: accepting ${accepted.join(", ")} in addition to the inherent residuals`,
    );

    return new VerifiedSakAgent(
      sakAgent, graphite, connection, walletProfile, aiLayerUrl, walletPublicKey, walletKeypair,
      residualPolicy, aiLayerTimeoutMs, transactionVersion,
    );
  }

  async parseIntent(naturalLanguage: string): Promise<ProposedIntent> {
    // A5-01: bounded, and never redirected — a redirect would carry the
    // request past the transport rule the URL was checked against.
    let response: Response;
    try {
      response = await fetch(`${this.aiLayerUrl}/parse`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ text: naturalLanguage }),
        signal: AbortSignal.timeout(this.aiLayerTimeoutMs),
        redirect: "error",
      });
    } catch (e) {
      const timedOut = e instanceof Error && e.name === "TimeoutError";
      throw new Error(
        timedOut
          ? `[Graphite] the AI layer did not answer within ${this.aiLayerTimeoutMs} ms. ABORTING.`
          : `[Graphite] the AI layer request failed: ${e instanceof Error ? e.message : String(e)}. ABORTING.`,
      );
    }
    if (!response.ok) throw new Error(`AI Layer error: ${response.status}`);
    const result = await response.json() as {
      intent_type: string; raw_natural_language: string; confidence_of_parse: number;
      extracted_parameters?: { input_token?: string; output_token?: string; amount?: string; destination?: string; slippage_bps?: number; };
    };
    // Round 19 (F-19-C5): the answer must be an answer to THIS request. The
    // text the Core sees as the user's words is the bridge's own copy, never
    // the AI layer's echo of it.
    assertEcho(naturalLanguage, result.raw_natural_language);
    return {
      intent_type: result.intent_type as any, raw_natural_language: naturalLanguage,
      confidence_of_parse: result.confidence_of_parse, extracted_parameters: result.extracted_parameters,
    };
  }

  async verifyTransaction(params: {
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
     *
     * `instructions` drives the RPC simulation, and the swap path deliberately
     * does not simulate here — SAK has already done that, and a second
     * simulation would add a round trip and a second authority on the same
     * question. But the swap path DOES hold the exact instruction it will
     * submit, and withholding it would leave the swap in Descriptive mode for
     * no reason other than the two concerns sharing a field.
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
      const sim = await this.simulator.simulate({ instructions: params.instructions, feePayer: this.#walletKeypair.publicKey });
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
            feePayer: this.#walletKeypair.publicKey,
            recentBlockhash: (await this.connection.getLatestBlockhash()).blockhash,
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
      cpi_targets: params.cpiTargets ?? [], wallet_profile: this.walletProfile,
      instruction_data: params.instructionData, compute_units: computeUnits,
      account_writes: accountWrites, cpi_hops: cpiHops,
      behavior_evidence, real_account_metas: params.realAccountMetas,
      signed_transaction, transaction_instructions,
      // Round 22: what the bytes are, so the declaration describes them. v0
      // and v1 are both versioned (the Core reads the prefix the same way).
      uses_versioned_transaction: params.bound !== undefined && params.bound.version !== "legacy",
      lookup_table_count: params.bound?.lookupTableCount ?? 0,
    } as any;
    return this.graphite.verify(input);
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
   * `sendRawTransaction` rather than `sendAndConfirmTransaction`: the latter
   * prepares the transaction itself, including fetching a blockhash if one is
   * missing, which is a mutation after approval no matter how benign. These
   * bytes are final.
   *
   * Round 9: the residual policy decides first, the signing is on the trail
   * before submission, the submission is on the trail after it, and L8
   * reconciles the signature at the end. The returned lifecycle says which
   * of those happened.
   */
  private async signSubmitAndConfirm(
    bound: BoundTransaction,
    verification: VerificationResult,
    label: string,
  ): Promise<ExecutionLifecycle> {
    // The whole path — policy, signing, the lifecycle events, submission,
    // confirmation, L8 — is `executeBoundTransaction`, in that order. See
    // execution-lifecycle.ts for why each step sits where it does.
    return executeBoundTransaction({
      bound,
      verification,
      signers: [this.#walletKeypair],
      connection: this.connection,
      graphite: this.graphite,
      policy: this.residualPolicy,
      reportedBy: this.reporter(),
      label,
    });
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
  private async buildBound(
    instructions: TransactionInstruction[],
    tableAddresses: string[] = [],
  ): Promise<BoundTransaction> {
    const feePayer = this.#walletKeypair.publicKey;
    if (this.transactionVersion === 1) {
      const limits = await this.simulator.estimateV1Limits({ instructions, feePayer });
      console.log(
        `[Graphite] v1 budget measured: ${limits.unitsConsumed} CU used -> limit ${limits.computeUnitLimit}; ` +
          `${limits.loadedAccountsDataSize} bytes loaded -> limit ${limits.loadedAccountsDataSizeLimit}`,
      );
      const { blockhash, lastValidBlockHeight } = await this.connection.getLatestBlockhash();
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
      const table = (await this.connection.getAddressLookupTable(new PublicKey(address))).value;
      if (!table) {
        throw new Error(
          `[Graphite] address lookup table ${address} named by the swap payload could not be read. ABORTING.`,
        );
      }
      addressLookupTables.push(table);
    }
    const { blockhash, lastValidBlockHeight } = await this.connection.getLatestBlockhash();
    return BoundTransaction.build({
      instructions,
      feePayer,
      recentBlockhash: blockhash,
      lastValidBlockHeight,
      ...(addressLookupTables.length > 0 ? { version: 0 as const, addressLookupTables } : {}),
    });
  }

  async executeTransfer(
    naturalLanguage: string
  ): Promise<ExecutionOutcome> {
    const proposedIntent = await this.parseIntent(naturalLanguage);
    console.log(`[Graphite] Parsed intent: ${proposedIntent.intent_type} (conf: ${proposedIntent.confidence_of_parse})`);

    // Round 19 (F-19-C5): destination and amount are taken from the user's
    // own text, and the AI layer's reading is accepted only where it matches
    // that text exactly. Both used to come from the AI layer's response alone
    // — and the same response went to the Core as `proposed_intent`, so the
    // Core's transaction-versus-intent check compared the response with
    // itself. The amount is converted to lamports on the string, not through
    // `parseFloat(...) * 1e9`.
    const grounded = groundTransferIntent(naturalLanguage, proposedIntent.extracted_parameters);
    const destination = grounded.destination;
    // The intent the Core compares against is rebuilt from the grounded
    // values and the bridge's own copy of the request.
    const groundedIntent: ProposedIntent = {
      ...proposedIntent,
      raw_natural_language: naturalLanguage,
      extracted_parameters: {
        ...proposedIntent.extracted_parameters,
        amount: grounded.amountText,
        destination: grounded.destination,
        input_token: "SOL",
      },
    };

    const destPubkey = new PublicKey(destination);
    const transferIx = SystemProgram.transfer({
      fromPubkey: this.#walletKeypair.publicKey,
      toPubkey: destPubkey,
      lamports: grounded.lamports,
    });

    const SYSTEM_PROGRAM = "11111111111111111111111111111111";
    const TRANSFER_DISCRIMINATOR = "02000000";

    // C22 TOCTOU closure: bind the AMOUNT, not just program+discriminator+
    // accounts. The transfer amount lives in `transferIx.data` (u64 LE lamports
    // after the 0x02 discriminator). The previous projection omitted it, so an
    // attacker who mutated the amount between verification and execution would
    // pass the AuditBind check unchanged. Both sides must carry the same raw
    // data bytes: the Rust content_hash includes instruction_data only when it
    // is present (generate_audit_id), so we pass it to verification AND to the
    // AuditBind projection together — changing only one side would make the
    // check permanently abort.
    const transferData = Array.from(transferIx.data);
    // ONE transaction object, built before verification and carried through to
    // submission. Everything downstream operates on this object: the bytes
    // Graphite verifies come out of it, the digest is re-checked against it
    // immediately before signing, and the signed bytes come from it. There is
    // no second transaction for the two to drift apart.
    const bound = await this.buildBound([transferIx]);
    const verification = await this.verifyTransaction({
      programId: SYSTEM_PROGRAM, instructionDiscriminator: TRANSFER_DISCRIMINATOR,
      accountAddresses: [this.walletPublicKey, destination], proposedIntent: groundedIntent, instructions: [transferIx],
      instructionData: transferData,
      bound,
    });

    console.log(`[Graphite] ${verification.approved ? "APPROVED" : "BLOCKED"} (confidence: ${verification.confidence})`);
    if (!verification.approved) { console.log("[Graphite] Transfer BLOCKED."); return { executed: false, verifiedExecution: false, verification }; }
    // `approved` alone is not the gate. A verdict that merely described
    // caller-supplied metadata and one bound to real signed bytes are the same
    // shape on the wire, so `approved` cannot tell whether Graphite was ever
    // shown a transaction. This path hands the Core the exact bytes it will
    // sign (`bound` above), and `signSubmitAndConfirm` refuses anything but
    // an artifact-bound verdict whose residuals the policy accepts. The
    // report here is the human-readable half of that decision.
    reportVerificationScope(verification, "transfer");

    // Build the transaction FIRST, then bind what is actually in it.
    //
    // This used to re-hash the local constants above — SYSTEM_PROGRAM,
    // `destination`, and a `transferData` copy taken before verification — and
    // then sign `transferIx`. Those are two different artifacts. The
    // reconstruction is a snapshot from before the window it was meant to
    // cover, so mutating the instruction object after approval left the check
    // passing and printing "Hash verified" while the redirected instruction
    // went to the signer (reproduced in toctou-signing-boundary.test.ts).
    //
    // Everything below is projected from the live objects on the path to
    // signing. The discriminator is passed explicitly
    // because System Transfer's is 4 bytes and the Anchor default would read 8,
    // picking up half the lamport amount and never matching Graphite's hash.
    // Copies, not the bound transaction's own objects: AuditBind projects
    // from these, and nothing it does to them can reach what gets signed.
    const tx = { instructions: bound.instructions() };
    const project = (ix: TransactionInstruction) => ({
      programId: ix.programId.toBase58(),
      data: ix.data,
      accounts: ix.keys.map((k) => k.pubkey.toBase58()),
      discriminator: TRANSFER_DISCRIMINATOR,
      // The privilege flags. Graphite checks these via `real_account_metas`,
      // so a binding that omits them would be checking less than the Core did
      // — flipping a verified read-only account to writable changes what the
      // instruction can do and leaves the projection hash untouched.
      accountMetas: ix.keys.map((k) => ({
        isSigner: k.isSigner,
        isWritable: k.isWritable,
      })),
    });

    // 1. The verified instruction is still the one in the transaction.
    AuditBind.verifyInstruction(
      project(tx.instructions[0]),
      verification.content_hash ?? verification.audit_trail_id,
    );
    // 2. And nothing else joined it. content_hash covers the instruction
    //    Graphite saw; it cannot cover one that did not exist yet, so an
    //    appended drain passes a per-instruction check untouched.
    if (tx.instructions.length !== 1) {
      throw new Error(
        `AuditBind FAILED: ${tx.instructions.length} instructions present, 1 verified. ABORTING.`,
      );
    }
    const binding = AuditBind.transactionBinding(tx.instructions.map(project));

    console.log("[Graphite] Transfer approved + AuditBind verified — executing...");
    // 3. Re-checked immediately before signing, so the binding covers the
    //    window rather than preceding it.
    AuditBind.verifyTransactionUnchanged(tx.instructions.map(project), binding);
    // 4. And the whole transaction, not only its instructions. AuditBind cannot
    //    see the fee payer, the blockhash, the header or the message version,
    //    because none of them are instruction-level facts. This compares the
    //    digest Graphite computed over the exact bytes.
    const lifecycle = await this.signSubmitAndConfirm(bound, verification, "transfer");
    console.log(`[Solana] ${lifecycle.confirmed ? "Confirmed" : "Submitted (not confirmed)"}: ${lifecycle.signature}`);
    return { executed: true, verifiedExecution: true, verification, signature: lifecycle.signature, lifecycle };
  }

  /**
   * Execute a swap under the Graphite verification gate.
   *
   * TOCTOU hardening (audit finding C2, CLOSED 2026-09-05 for the
   * payload-provided path — see P1 "SAK swap-path TOCTOU residual"): pass
   * `payload` — the EXACT swap instruction (programId, discriminator, full
   * account list WITH per-account isSigner/isWritable, raw data bytes) — to
   * bind AuditBind to the real instruction that will be submitted. Any
   * mutation of that instruction between verification and execution changes
   * the content_hash and ABORTS. Previously a bound payload was still handed
   * off to `sakAgent.methods.swap()`, which REBUILDS the swap instruction
   * internally — the executed instruction was not actually guaranteed to be
   * the verified one (the "HONEST BOUNDARY" this comment used to document).
   * That gap is now closed: when `payload` is supplied, this method builds
   * the `TransactionInstruction` directly from the SAME bound fields and
   * submits it itself (mirroring `executeTransfer`), never touching SAK's
   * internal builder. This requires the caller to supply the real
   * isSigner/isWritable flags (previously missing from the payload schema,
   * which is exactly why the bridge could not safely do this before).
   *
   * **Without `payload`, this now REFUSES (2026-09-08).** The unbound mode was
   * default-on with an opt-in `GRAPHITE_SWAP_STRICT=1` to disable it, which is
   * the wrong polarity for a security gate: the safe path should not be the one
   * you have to know to ask for.
   *
   * It was also worse than the "reduced projection" the comment here used to
   * claim. `accountAddresses` fell back to `[this.walletPublicKey]`, so
   * Graphite was asked to verify a Jupiter swap consisting of ONE account, the
   * wallet — no destination token account, no vaults, no authority, no
   * instruction data, no amounts, no route. AuditBind then "passed" by
   * re-hashing the same three constants the bridge had just sent, and SAK's
   * internal builder constructed and submitted an entirely different
   * instruction. Nothing about the executed swap was ever observed by anything.
   * That is not a residual window; it is a verdict about a transaction that
   * does not exist, printed next to the execution of one that does.
   *
   * The escape hatch that survived that change — `GRAPHITE_SWAP_ALLOW_UNVERIFIED_EXECUTION`
   * set to `UNVERIFIED_SWAP_OPT_IN`, which handed the swap to SAK's builder —
   * is gone as of Round 19 (F-19-C2). It could only execute because SAK held
   * the wallet key; SAK now holds a wallet that refuses to sign, so the
   * opt-out had nothing left to execute with. A swap is a payload the bridge
   * verifies and signs itself, or it is refused.
   *
   * Privilege grounding (P1 fix, 2026-09-05 audit, "signer/writable metadata
   * is not grounded in actual transaction AccountMeta data", CLOSED for the
   * payload-provided path): `payload.accounts` already carries the real
   * per-account isSigner/isWritable flags used to build the instruction —
   * they are also forwarded to Graphite as `real_account_metas` so the Core
   * cross-checks them against the manifest's declared expectations and
   * hard-blocks a security-relevant mismatch (a required signer that isn't
   * actually signed, or a readonly slot marked writable) BEFORE this
   * instruction is built or submitted. See `bound-instruction.ts`.
   */
  async executeSwap(
    naturalLanguage: string,
    payload?: BoundInstructionPayload,
  ): Promise<ExecutionOutcome> {
    const proposedIntent = await this.parseIntent(naturalLanguage);
    console.log(`[Graphite] Parsed intent: ${proposedIntent.intent_type} (conf: ${proposedIntent.confidence_of_parse})`);

    const params = proposedIntent.extracted_parameters;
    if (!params?.input_token || !params?.output_token || !params?.amount) throw new Error("Swap requires input_token, output_token, amount");

    // Deployed Jupiter V6 swap entrypoint: route_v2 = bb64facc31c4af14,
    // CONFIRMED on-chain (C22.3, base58-decoded live mainnet txs 2026-08-09 +
    // pinned fixture sig 57TAjPZXt49F9rSVZNEu… slot 438012579, SUCCESS). The
    // legacy `route` discriminator (e517cb977ae3ad2a) is also live but legacy.
    const JUPITER_SWAP_DISCRIMINATOR = "bb64facc31c4af14";
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
          "one-account projection while SAK's builder submits a different instruction entirely — " +
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
    // so. Its label used to go to the Core unchanged, and the Core's
    // intent-mismatch checks compare the transaction against that label: an
    // AI answering "approve" switched off the Approve check for an Approve
    // payload. The payload must also be addressed to a swap program. All of
    // it is decided here, before a blockhash is fetched or the Core is asked.
    const swapIntent: ProposedIntent = {
      ...proposedIntent,
      intent_type: groundSwapIntent(naturalLanguage, proposedIntent.intent_type, payload.programId),
      raw_natural_language: naturalLanguage,
    };
    const accountAddresses = payload.accounts.map((a) => a.pubkey);
    // P1 fix (2026-09-05 audit): the bound payload already carries the REAL
    // per-account isSigner/isWritable flags (that's what buildInstructionFromPayload
    // uses to construct the actual on-chain instruction) — forward them as
    // real_account_metas so the Core cross-checks them against the manifest's
    // declared expectations, not just the account addresses.
    const realAccountMetas = payload.accounts.map((a) => ({ is_signer: a.isSigner, is_writable: a.isWritable }));
    // Built once, from the payload, before verification — the same construction
    // that used to happen after approval.
    const boundSwap = await this.buildBound(
      [buildInstructionFromPayload(payload)],
      payload.addressLookupTableAddresses ?? [],
    );
    const verification = await this.verifyTransaction({
      // No Jupiter default: groundSwapIntent has already refused a payload
      // without a swap program.
      programId: payload.programId,
      instructionDiscriminator: payload.discriminator ?? JUPITER_SWAP_DISCRIMINATOR,
      accountAddresses, proposedIntent: swapIntent,
      instructionData: payload.instructionData,
      realAccountMetas,
      // The transaction that will be signed, not a copy of its instructions.
      bound: boundSwap,
    });

    console.log(`[Graphite] ${verification.approved ? "APPROVED" : "BLOCKED"} (confidence: ${verification.confidence})`);
    if (!verification.approved) { console.log("[Graphite] Swap BLOCKED."); return { executed: false, verifiedExecution: false, verification }; }
    reportVerificationScope(verification, "swap");

    // Bind the EXACT instruction that will be submitted (full data + accounts).
    AuditBind.verifyInstruction(
      {
        programId: payload.programId,
        data: Uint8Array.from(payload.instructionData ?? []),
        accounts: accountAddresses,
      },
      verification.content_hash ?? verification.audit_trail_id,
    );
    console.log("[Graphite] Swap payload bound to AuditBind (instruction data + full account list).");

    // TOCTOU closure: submit the SAME instruction that was just bound —
    // never SAK's internal rebuild. buildInstructionFromPayload uses the
    // identical (programId, accounts, instructionData) fields that were
    // just hashed above, so what executes is byte-identical to what was
    // verified by construction, not by trusting a second code path to
    // agree with the first.
    // `boundSwap` holds the instruction built from this same payload before
    // verification, and its bytes are what Graphite verified. Rebuilding here
    // would reintroduce the copy-versus-original gap one level down.
    console.log("[Graphite] Swap approved + AuditBind verified — submitting the bound transaction directly (bypassing SAK's builder)...");
    const lifecycle = await this.signSubmitAndConfirm(boundSwap, verification, "swap");
    console.log(`[Solana] ${lifecycle.confirmed ? "Confirmed" : "Submitted (not confirmed)"}: ${lifecycle.signature}`);
    return { executed: true, verifiedExecution: true, verification, signature: lifecycle.signature, lifecycle };
  }

  /**
   * The SolanaAgentKit agent, for READ-ONLY use (balances, prices, lookups).
   *
   * Round 19 (F-19-C2): this used to return an agent holding the wallet's
   * secret key, so any caller — or any LLM tool built from the agent — could
   * sign and send around the gate. The agent returned now is built on
   * `VerificationGatedWallet`: every signing method throws
   * `UngatedSigningRefused`. To move funds, use `executeTransfer` or
   * `executeSwap(payload)`.
   */
  getSakAgent(): SolanaAgentKit | null { return this.sakAgent; }
  getGraphiteClient(): GraphiteClient { return this.graphite; }
  getConnection(): Connection { return this.connection; }
}
