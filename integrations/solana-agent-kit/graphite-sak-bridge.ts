/**
 * Graphite-SAK Bridge v2 — Production verification gate for Solana Agent Kit.
 *
 * Architecture (Constitution P1: AI assists, never decides):
 *   NL -> Python AI Layer (parse intent) -> Construct tx -> Graphite (verify) -> RPC simulate -> AuditBind -> Execute
 *
 * v2 improvements:
 *   1. RPC SIMULATION — calls simulateTransaction BEFORE verification to get real compute_units,
 *      account_writes, and cpi_hops, which feed the Simulation Integrity check (L3) and the
 *      audit trail. NOTE: these do NOT boost the confidence score in Phase 1 — the Core
 *      intentionally zeroes the SimulationMatch/HistoricalVolume/CommunityVerification signal
 *      values (Constitution G4: request-body evidence is attacker-controlled) and caps trust
 *      tiers at the manifest's declared tier (P7). The achievable Phase 1 confidence for a
 *      known, clean, intent-aligned protocol is ~0.44, which is why the default wallet profile
 *      below is a Custom profile calibrated to that ceiling.
 *   2. AUDITBIND MIDDLEWARE — after Graphite approves, re-computes the SAME deterministic
 *      content_hash the Rust Core produces (byte-for-byte: SHA-256 over programId, discriminator,
 *      account addresses, raw instruction-data bytes, and CPI targets, truncated to 16 hex chars)
 *      and compares against the verified content_hash. Blocks execution if the transaction was
 *      mutated in the TOCTOU window. The earlier "|"-joined/commas encoding never matched the
 *      Rust side and always aborted — this version mirrors the Core exactly.
 *   3. SAK plugins are loaded statically (rpc-websockets exports patched for compatibility).
 *      Runtime fallback to raw web3.js if plugin initialization fails.
 */

import {
  SolanaAgentKit,
  KeypairWallet,
} from "solana-agent-kit";
import TokenPlugin from "@solana-agent-kit/plugin-token";
import DefiPlugin from "@solana-agent-kit/plugin-defi";
// `sendAndConfirmTransaction` is deliberately NOT imported: it prepares the
// transaction it is given, including fetching a blockhash when one is missing,
// and a mutation after approval is a mutation however benign. Signing goes
// through `signSubmitAndConfirm`, which submits bytes that are already final.
import { Keypair, Connection, SystemProgram, Transaction, PublicKey, TransactionInstruction } from "@solana/web3.js";
import bs58 from "bs58";

// AuditBind lives in ./auditbind.ts — a dependency-free module (Node crypto
// only) so its cross-language pinned-vector tests run without the SAK tree.
import { AuditBind } from "./auditbind.js";
export { AuditBind };

// Graphite TS SDK
import { GraphiteClient } from "../../sdk/typescript/src/client.js";
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
  /** Present on the opt-out path, naming what was not verified. */
  unverifiedReason?: string;
}

/**
 * The exact value the swap opt-out requires.
 *
 * Not "1", "true" or "yes". A bare `=1` is what gets copied from a README,
 * inherited from a shell profile, or left in a `.env` after a test; a phrase
 * that says what it does is not set by accident.
 */
export const UNVERIFIED_SWAP_OPT_IN = "I_ACCEPT_UNVERIFIED_SWAP_EXECUTION";

/**
 * RPC Simulation helper — calls simulateTransaction to get real resource usage.
 * The compute/writes/hops feed the Core's Simulation Integrity check (L3) and
 * the audit trail. NOTE: in Phase 1 they do NOT boost the confidence score (the
 * Core zeroes the SimulationMatch signal value — Constitution G4); the trusted
 * simulation signal arrives in Phase 2 via the Core's own RPC client.
 */
export class RpcSimulator {
  private connection: Connection;
  constructor(rpcUrl: string) { this.connection = new Connection(rpcUrl, "confirmed"); }

  async simulate(params: {
    instructions: TransactionInstruction[];
    signers: Keypair[];
  }): Promise<{ computeUnits: number; accountWrites: number; cpiHops: number; logs: string[]; success: boolean }> {
    try {
      // simulateTransaction handles blockhash + signing internally when signers are passed
      const tx = new Transaction({ feePayer: params.signers[0].publicKey });
      tx.add(...params.instructions);
      const simulation = await this.connection.simulateTransaction(tx, params.signers);
      if (simulation.value.err) {
        console.warn("[RpcSimulator] Simulation returned error:", JSON.stringify(simulation.value.err).slice(0, 80));
        return { computeUnits: 0, accountWrites: 0, cpiHops: 0, logs: simulation.value.logs ?? [], success: false };
      }
      const logs = simulation.value.logs ?? [];
      let computeUnits = 0;
      const cuMatch = logs.find((l: string) => l.includes("consumed"));
      if (cuMatch) { const m = cuMatch.match(/consumed (\d+)/); if (m) computeUnits = parseInt(m[1]); }
      // Count writable accounts from instructions (fallback if simulation doesn't report)
      let accountWrites = 0;
      if (simulation.value.accounts) accountWrites = simulation.value.accounts.filter((a: any) => a).length;
      if (accountWrites === 0) {
        const writableAccounts = new Set<string>();
        for (const ix of params.instructions) for (const key of ix.keys) if (key.isWritable) {
          const pk = typeof key.pubkey === 'string' ? key.pubkey : key.pubkey.toBase58();
          writableAccounts.add(pk);
        }
        accountWrites = writableAccounts.size;
      }
      let cpiHops = 0;
      for (const log of logs) { const m = log.match(/Program \w+ invoke \[(\d+)\]/); if (m) { const l = parseInt(m[1]); if (l > cpiHops) cpiHops = l; } }
      return { computeUnits, accountWrites, cpiHops, logs, success: true };
    } catch (err) {
      console.warn("[RpcSimulator] Simulation failed:", (err as Error).message);
      return { computeUnits: 0, accountWrites: 0, cpiHops: 0, logs: [], success: false };
    }
  }
}

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
  private walletPublicKey: string;
  private walletKeypair: Keypair;
  private simulator: RpcSimulator;

  private constructor(
    sakAgent: SolanaAgentKit | null, graphite: GraphiteClient, connection: Connection,
    walletProfile: WalletProfile, aiLayerUrl: string, walletPublicKey: string, walletKeypair: Keypair,
  ) {
    this.sakAgent = sakAgent; this.graphite = graphite; this.connection = connection;
    this.walletProfile = walletProfile; this.aiLayerUrl = aiLayerUrl;
    this.walletPublicKey = walletPublicKey; this.walletKeypair = walletKeypair;
    this.simulator = new RpcSimulator(connection.rpcEndpoint);
  }

  static async create(config?: {
    privateKey?: string; rpcUrl?: string; openAiApiKey?: string;
    graphiteCoreUrl?: string; aiLayerUrl?: string; walletProfile?: WalletProfile;
    /** Bearer API key for a secured Graphite Core (GRAPHITE_API_KEY). */
    graphiteApiKey?: string;
  }): Promise<VerifiedSakAgent> {
    const privateKey = config?.privateKey ?? process.env.SOLANA_PRIVATE_KEY;
    const rpcUrl = config?.rpcUrl ?? process.env.SOLANA_RPC_URL;
    const openAiApiKey = config?.openAiApiKey ?? process.env.OPENAI_API_KEY;
    const graphiteCoreUrl = config?.graphiteCoreUrl ?? process.env.GRAPHITE_CORE_URL ?? "http://localhost:7331";
    // Secured Core deployments require the Bearer key on /verify and /manifests.
    const graphiteApiKey = config?.graphiteApiKey ?? process.env.GRAPHITE_API_KEY;
    // The Python AI Layer listens on 8081 by default (intent_parser.py --serve).
    const aiLayerUrl = config?.aiLayerUrl ?? process.env.GRAPHITE_AI_LAYER_URL ?? "http://localhost:8081";
    // Phase 1 calibration: with the three evidence-derived confidence signals
    // intentionally zeroed (Constitution G4 — request-body evidence is
    // attacker-controlled) and trust tiers capped at OfficialManifest (P7), the
    // achievable confidence for a known, clean, intent-aligned protocol is
    // ~0.44. The built-in profiles (TradingBot 0.80, etc.) were tuned for the
    // Phase 2 signal set and would block EVERYTHING in Phase 1 — so the demo
    // default is a Custom profile that a genuinely-known protocol can satisfy.
    // Override with GRAPHITE_WALLET_PROFILE (or config.walletProfile) for a
    // stricter operator policy.
    const walletProfile: WalletProfile = config?.walletProfile
      ?? (process.env.GRAPHITE_WALLET_PROFILE as WalletProfile)
      ?? { Custom: { min_confidence: 0.40, min_trust_tier: "OfficialManifest" } };

    if (!privateKey) throw new Error("SOLANA_PRIVATE_KEY is required");
    if (!rpcUrl) throw new Error("SOLANA_RPC_URL is required");

    const walletKeypair = Keypair.fromSecretKey(bs58.decode(privateKey));
    const walletPublicKey = walletKeypair.publicKey.toBase58();
    const connection = new Connection(rpcUrl, "confirmed");

    // Initialize SAK agent with plugins — fallback to raw web3.js if runtime init fails
    let sakAgent: SolanaAgentKit | null = null;
    try {
      if (!openAiApiKey) throw new Error("OPENAI_API_KEY required for SAK");
      const wallet = new KeypairWallet(walletKeypair);
      sakAgent = new SolanaAgentKit(wallet, rpcUrl, { OPENAI_API_KEY: openAiApiKey })
        .use(TokenPlugin)
        .use(DefiPlugin);
      console.log("[Graphite] SAK agent initialized with TokenPlugin + DefiPlugin");
    } catch (err) {
      console.warn("[Graphite] SAK init failed — falling back to raw web3.js:", (err as Error).message?.slice(0, 80));
    }

    const graphite = new GraphiteClient({ baseUrl: graphiteCoreUrl, apiKey: graphiteApiKey });
    try { await graphite.health(); } catch {
      throw new Error(`Graphite Core not reachable at ${graphiteCoreUrl}. Start: cargo run --release -- server`);
    }

    return new VerifiedSakAgent(sakAgent, graphite, connection, walletProfile, aiLayerUrl, walletPublicKey, walletKeypair);
  }

  async parseIntent(naturalLanguage: string): Promise<ProposedIntent> {
    const response = await fetch(`${this.aiLayerUrl}/parse`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ text: naturalLanguage }),
    });
    if (!response.ok) throw new Error(`AI Layer error: ${response.status}`);
    const result = await response.json() as {
      intent_type: string; raw_natural_language: string; confidence_of_parse: number;
      extracted_parameters?: { input_token?: string; output_token?: string; amount?: string; destination?: string; slippage_bps?: number; };
    };
    return {
      intent_type: result.intent_type as any, raw_natural_language: result.raw_natural_language,
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
      const sim = await this.simulator.simulate({ instructions: params.instructions, signers: [this.walletKeypair] });
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
            feePayer: this.walletKeypair.publicKey,
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
   */
  private async signSubmitAndConfirm(
    bound: BoundTransaction,
    verification: VerificationResult,
    label: string,
  ): Promise<string> {
    const scope = verification.scope;
    if (scope?.kind !== "artifact_bound") {
      throw new Error(
        `[Graphite] ${label}: the verdict is ${scope?.kind ?? "unscoped"}, not artifact_bound. ` +
          "A descriptive verdict describes what the request SAID; it does not constrain what " +
          "gets signed. ABORTING.",
      );
    }
    // Recomputed now, over this object, and compared against what Graphite
    // hashed. Anything that touched the transaction since approval — a
    // refreshed blockhash, a changed fee payer, an appended instruction —
    // changes this digest.
    // One call: the digest check, the signer check and the signature are not
    // separately reachable, so no refactor can leave the signature without them.
    const raw = bound.signApproved(scope.transaction_sha256, [this.walletKeypair]);
    console.log(
      `[Graphite] ${label}: transaction matches the approved digest ` +
        `${scope.transaction_sha256.slice(0, 16)}… — signing and submitting those exact bytes.`,
    );
    const signature = await this.connection.sendRawTransaction(raw);
    await this.connection.confirmTransaction({
      signature,
      blockhash: bound.recentBlockhash,
      lastValidBlockHeight: bound.lastValidBlockHeight,
    });
    return signature;
  }

  async executeTransfer(
    naturalLanguage: string
  ): Promise<ExecutionOutcome> {
    const proposedIntent = await this.parseIntent(naturalLanguage);
    console.log(`[Graphite] Parsed intent: ${proposedIntent.intent_type} (conf: ${proposedIntent.confidence_of_parse})`);

    const params = proposedIntent.extracted_parameters;
    if (!params?.amount) throw new Error("Transfer requires amount");
    const destination = params?.destination || "";
    if (!destination) throw new Error("Transfer requires destination address");

    const destPubkey = new PublicKey(destination);
    const lamports = Math.floor(parseFloat(params.amount) * 1e9);
    const transferIx = SystemProgram.transfer({ fromPubkey: this.walletKeypair.publicKey, toPubkey: destPubkey, lamports });

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
    const { blockhash, lastValidBlockHeight } =
      await this.connection.getLatestBlockhash();
    const bound = BoundTransaction.build({
      instructions: [transferIx],
      feePayer: this.walletKeypair.publicKey,
      recentBlockhash: blockhash,
      lastValidBlockHeight,
    });
    const verification = await this.verifyTransaction({
      programId: SYSTEM_PROGRAM, instructionDiscriminator: TRANSFER_DISCRIMINATOR,
      accountAddresses: [this.walletPublicKey, destination], proposedIntent, instructions: [transferIx],
      instructionData: transferData,
      bound,
    });

    console.log(`[Graphite] ${verification.approved ? "APPROVED" : "BLOCKED"} (confidence: ${verification.confidence})`);
    if (!verification.approved) { console.log("[Graphite] Transfer BLOCKED."); return { executed: false, verifiedExecution: false, verification }; }
    // `approved` alone is not the gate. A verdict that merely described
    // caller-supplied metadata and one bound to real signed bytes are the same
    // shape on the wire, so `approved` cannot tell whether Graphite was ever
    // shown a transaction — which is how an integration ends up executing an
    // instruction nothing examined. Reported rather than enforced here: this
    // path does not yet hand the Core a serialized artifact, so requiring
    // artifact binding would refuse every transfer. AuditBind below binds the
    // live instruction, which is the protection this path actually has.
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
    const signature = await this.signSubmitAndConfirm(bound, verification, "transfer");
    console.log(`[Solana] Confirmed: ${signature}`);
    return { executed: true, verifiedExecution: true, verification, signature };
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
   * The escape hatch survives, inverted and named for what it does:
   * `GRAPHITE_SWAP_ALLOW_UNVERIFIED_EXECUTION` set to the exact opt-in phrase
   * `UNVERIFIED_SWAP_OPT_IN`. An operator who genuinely
   * needs SAK's router and accepts that Graphite is not verifying the submitted
   * instruction can set it, and the warning says exactly which properties went
   * unobserved.
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

    const JUPITER_V6_PROGRAM = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
    // Deployed Jupiter V6 swap entrypoint: route_v2 = bb64facc31c4af14,
    // CONFIRMED on-chain (C22.3, base58-decoded live mainnet txs 2026-08-09 +
    // pinned fixture sig 57TAjPZXt49F9rSVZNEu… slot 438012579, SUCCESS). The
    // legacy `route` discriminator (e517cb977ae3ad2a) is also live but legacy.
    const JUPITER_SWAP_DISCRIMINATOR = "bb64facc31c4af14";
    // Fail closed by default. `GRAPHITE_SWAP_STRICT=1` is still honoured for
    // compatibility, but it is now redundant: strict IS the default.
    const allowUnverified =
      process.env.GRAPHITE_SWAP_ALLOW_UNVERIFIED_EXECUTION === UNVERIFIED_SWAP_OPT_IN &&
      process.env.GRAPHITE_SWAP_STRICT !== "1";
    if (!payload && !allowUnverified) {
      throw new Error(
        "[Graphite] a swap requires a built payload (programId / discriminator / accounts with " +
          "isSigner+isWritable / instructionData) so the instruction that is verified is the " +
          "instruction that is submitted. Without it Graphite would be asked to verify a " +
          "one-account projection while SAK's builder submits a different instruction entirely — " +
          "no destination, no vaults, no amounts, nothing about the real swap observed. " +
          "Build the route first and pass it, or set GRAPHITE_SWAP_ALLOW_UNVERIFIED_EXECUTION={UNVERIFIED_SWAP_OPT_IN} " +
          "to execute swaps Graphite has not verified. ABORTING."
      );
    }
    const accountAddresses = payload?.accounts.map((a) => a.pubkey) ?? [this.walletPublicKey];
    // P1 fix (2026-09-05 audit): the bound payload already carries the REAL
    // per-account isSigner/isWritable flags (that's what buildInstructionFromPayload
    // uses to construct the actual on-chain instruction) — forward them as
    // real_account_metas so the Core cross-checks them against the manifest's
    // declared expectations, not just the account addresses.
    const realAccountMetas = payload?.accounts.map((a) => ({ is_signer: a.isSigner, is_writable: a.isWritable }));
    // Built once, from the payload, before verification — the same construction
    // that used to happen after approval.
    let boundSwap: BoundTransaction | undefined;
    if (payload) {
      const { blockhash, lastValidBlockHeight } =
        await this.connection.getLatestBlockhash();
      boundSwap = BoundTransaction.build({
        instructions: [buildInstructionFromPayload(payload)],
        feePayer: this.walletKeypair.publicKey,
        recentBlockhash: blockhash,
        lastValidBlockHeight,
      });
    }
    const verification = await this.verifyTransaction({
      programId: payload?.programId ?? JUPITER_V6_PROGRAM,
      instructionDiscriminator: payload?.discriminator ?? JUPITER_SWAP_DISCRIMINATOR,
      accountAddresses, proposedIntent,
      instructionData: payload?.instructionData,
      realAccountMetas,
      // The transaction that will be signed, not a copy of its instructions.
      // Without a payload there is nothing to build and the verification stays
      // descriptive — which the abort above already treats as the unverified
      // case.
      bound: boundSwap,
    });

    console.log(`[Graphite] ${verification.approved ? "APPROVED" : "BLOCKED"} (confidence: ${verification.confidence})`);
    if (!verification.approved) { console.log("[Graphite] Swap BLOCKED."); return { executed: false, verifiedExecution: false, verification }; }
    reportVerificationScope(verification, "swap");

    if (payload) {
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
      if (!boundSwap) {
        throw new Error(
          "[Graphite] a payload was supplied but no bound transaction was built; refusing to sign an unverified construction",
        );
      }
      console.log("[Graphite] Swap approved + AuditBind verified — submitting the bound transaction directly (bypassing SAK's builder)...");
      const signature = await this.signSubmitAndConfirm(boundSwap, verification, "swap");
      console.log(`[Solana] Confirmed: ${signature}`);
      return { executed: true, verifiedExecution: true, verification, signature };
    }

    // Only reachable with GRAPHITE_SWAP_ALLOW_UNVERIFIED_EXECUTION set to the
    // exact opt-in phrase.
    //
    // The AuditBind call below is deliberately NOT made. It would re-hash the
    // three constants this method just sent to Graphite and print "Hash
    // verified", which is a check that cannot fail and therefore tells the
    // operator nothing — the exact shape of the defect found at the transfer
    // path on 2026-09-08. A check that cannot fail is worse than no check,
    // because it reads like assurance in the log.
    console.warn(
      [
        "[Graphite] EXECUTING A SWAP GRAPHITE DID NOT VERIFY.",
        `  GRAPHITE_SWAP_ALLOW_UNVERIFIED_EXECUTION=${UNVERIFIED_SWAP_OPT_IN} is set.`,
        "  Verified: the wallet address, the Jupiter program id, and the swap discriminator.",
        "  NOT observed: destination token account, vaults, authority, every other account,",
        "  the instruction data, the amounts, the slippage, and the route.",
        "  SAK's internal builder will construct and submit an instruction this verdict does",
        "  not describe. AuditBind is intentionally not run here: binding a projection that",
        "  cannot disagree with itself would print assurance without providing any.",
      ].join(String.fromCharCode(10)),
    );

    if (!this.sakAgent) throw new Error("Swap requires SAK plugins. Use executeTransfer for raw web3.js mode.");

    console.log("[Graphite] Executing the swap through SAK's builder — unverified, see the warning above...");
    const result = await (this.sakAgent as any).methods.swap(
      params.input_token, params.output_token, params.amount, params.slippage_bps ?? 300,
    );
    console.log(`[SAK] Swap executed: ${result.signature ?? result}`);
    // Machine-readable, so a caller cannot mistake this for a verified
    // execution however it reads the log.
    return {
      executed: true,
      verifiedExecution: false,
      verification,
      signature: result.signature,
      unverifiedReason:
        "GRAPHITE_SWAP_ALLOW_UNVERIFIED_EXECUTION opt-in: SAK's builder constructed and " +
        "submitted an instruction Graphite did not verify — destination, vaults, authority, " +
        "amounts, slippage and route were not observed",
    };
  }

  getSakAgent(): SolanaAgentKit | null { return this.sakAgent; }
  getGraphiteClient(): GraphiteClient { return this.graphite; }
  getConnection(): Connection { return this.connection; }
}
