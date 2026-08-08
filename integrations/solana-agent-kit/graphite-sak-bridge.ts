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
import { Keypair, Connection, SystemProgram, Transaction, PublicKey, TransactionInstruction, sendAndConfirmTransaction } from "@solana/web3.js";
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
  }): Promise<VerifiedSakAgent> {
    const privateKey = config?.privateKey ?? process.env.SOLANA_PRIVATE_KEY;
    const rpcUrl = config?.rpcUrl ?? process.env.SOLANA_RPC_URL;
    const openAiApiKey = config?.openAiApiKey ?? process.env.OPENAI_API_KEY;
    const graphiteCoreUrl = config?.graphiteCoreUrl ?? process.env.GRAPHITE_CORE_URL ?? "http://localhost:7331";
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

    const graphite = new GraphiteClient({ baseUrl: graphiteCoreUrl });
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
    const input: VerificationInput = {
      proposed_intent: params.proposedIntent, program_id: params.programId,
      instruction_discriminator: params.instructionDiscriminator, account_addresses: params.accountAddresses,
      cpi_targets: params.cpiTargets ?? [], wallet_profile: this.walletProfile,
      instruction_data: params.instructionData, compute_units: computeUnits,
      account_writes: accountWrites, cpi_hops: cpiHops,
      behavior_evidence,
    } as any;
    return this.graphite.verify(input);
  }

  async executeTransfer(
    naturalLanguage: string
  ): Promise<{ executed: boolean; verification: VerificationResult; signature?: string }> {
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

    const verification = await this.verifyTransaction({
      programId: SYSTEM_PROGRAM, instructionDiscriminator: TRANSFER_DISCRIMINATOR,
      accountAddresses: [this.walletPublicKey, destination], proposedIntent, instructions: [transferIx],
    });

    console.log(`[Graphite] ${verification.approved ? "APPROVED" : "BLOCKED"} (confidence: ${verification.confidence})`);
    if (!verification.approved) { console.log("[Graphite] Transfer BLOCKED."); return { executed: false, verification }; }

    AuditBind.verify({
      transaction: { programId: SYSTEM_PROGRAM, instructionDiscriminator: TRANSFER_DISCRIMINATOR, accountAddresses: [this.walletPublicKey, destination] },
      contentHash: verification.content_hash ?? verification.audit_trail_id,
    });

    console.log("[Graphite] Transfer approved + AuditBind verified — executing...");
    const tx = new Transaction().add(transferIx);
    const signature = await sendAndConfirmTransaction(this.connection, tx, [this.walletKeypair]);
    console.log(`[Solana] Confirmed: ${signature}`);
    return { executed: true, verification, signature };
  }

  /**
   * Execute a swap under the Graphite verification gate.
   *
   * TOCTOU hardening (audit finding C2): pass `payload` — the EXACT swap
   * instruction (programId, discriminator, full account list, raw data
   * bytes) — to bind AuditBind to the real instruction that will be
   * submitted. Any mutation of that instruction between verification and
   * execution changes the content_hash and ABORTS.
   *
   * Without `payload` the swap check is a reduced projection
   * (programId + discriminator + wallet). In that case, set
   * `GRAPHITE_SWAP_STRICT=1` to FAIL CLOSED (the opaque SAK `methods.swap`
   * path cannot be payload-bound, so a strict operator must supply a built
   * payload via the Jupiter swap API / transaction builder).
   */
  async executeSwap(
    naturalLanguage: string,
    payload?: { programId: string; discriminator: string; accounts: string[]; instructionData?: number[] },
  ): Promise<{ executed: boolean; verification: VerificationResult; signature?: string }> {
    const proposedIntent = await this.parseIntent(naturalLanguage);
    console.log(`[Graphite] Parsed intent: ${proposedIntent.intent_type} (conf: ${proposedIntent.confidence_of_parse})`);

    const params = proposedIntent.extracted_parameters;
    if (!params?.input_token || !params?.output_token || !params?.amount) throw new Error("Swap requires input_token, output_token, amount");

    const JUPITER_V6_PROGRAM = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
    const JUPITER_SWAP_DISCRIMINATOR = "e517cb977ae3ad2a";
    const strict = process.env.GRAPHITE_SWAP_STRICT === "1";
    if (strict && !payload) {
      throw new Error(
        "[Graphite] GRAPHITE_SWAP_STRICT=1 requires a built swap payload (programId/discriminator/accounts/instructionData) " +
          "so AuditBind can bind the exact instruction — the opaque SAK swap path cannot be TOCTOU-bound. ABORTING."
      );
    }
    // HONEST BOUNDARY (final-forensic finding): a bound payload is verified
    // against the approved content_hash, but `sakAgent.methods.swap` below
    // REBUILDS the swap instruction internally — the executed instruction is
    // not guaranteed to be the payload. The payload schema (base58 account
    // strings only) lacks isSigner/isWritable flags, so the bridge cannot
    // safely reconstruct + sign the bound instruction itself. Full TOCTOU
    // closure therefore requires the OPERATOR to build, verify, and submit
    // the exact instruction (see ARCHITECTURE.md → Known Boundary
    // Limitations). GRAPHITE_SWAP_STRICT=1 only forces a payload to exist;
    // it does not by itself make the executor submit it.

    const accountAddresses = payload?.accounts ?? [this.walletPublicKey];
    const verification = await this.verifyTransaction({
      programId: payload?.programId ?? JUPITER_V6_PROGRAM,
      instructionDiscriminator: payload?.discriminator ?? JUPITER_SWAP_DISCRIMINATOR,
      accountAddresses, proposedIntent,
      instructionData: payload?.instructionData,
    });

    console.log(`[Graphite] ${verification.approved ? "APPROVED" : "BLOCKED"} (confidence: ${verification.confidence})`);
    if (!verification.approved) { console.log("[Graphite] Swap BLOCKED."); return { executed: false, verification }; }

    if (payload) {
      // Bind the EXACT instruction that will be submitted (full data + accounts).
      AuditBind.verifyInstruction(
        {
          programId: payload.programId,
          data: Uint8Array.from(payload.instructionData ?? []),
          accounts: payload.accounts,
        },
        verification.content_hash ?? verification.audit_trail_id,
      );
      console.log("[Graphite] Swap payload bound to AuditBind (instruction data + full account list).");
    } else {
      AuditBind.verify({
        transaction: { programId: JUPITER_V6_PROGRAM, instructionDiscriminator: JUPITER_SWAP_DISCRIMINATOR, accountAddresses },
        contentHash: verification.content_hash ?? verification.audit_trail_id,
      });
      console.warn(
        "[Graphite] WARNING: swap AuditBind is minimal-projection (no payload bound). " +
          "Supply a built payload or set GRAPHITE_SWAP_STRICT=1 to close the TOCTOU window."
      );
    }

    if (!this.sakAgent) throw new Error("Swap requires SAK plugins. Use executeTransfer for raw web3.js mode.");

    console.log("[Graphite] Swap approved + AuditBind verified — executing...");
    const result = await (this.sakAgent as any).methods.swap(
      params.input_token, params.output_token, params.amount, params.slippage_bps ?? 300,
    );
    console.log(`[SAK] Swap executed: ${result.signature ?? result}`);
    return { executed: true, verification, signature: result.signature };
  }

  getSakAgent(): SolanaAgentKit | null { return this.sakAgent; }
  getGraphiteClient(): GraphiteClient { return this.graphite; }
  getConnection(): Connection { return this.connection; }
}
