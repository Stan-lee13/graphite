/**
 * Graphite for Solana Agent Kit — the SAK adapter over `GraphiteGuard`.
 *
 * Everything that verifies, signs and submits lives in the framework-
 * independent guard (`integrations/agent-guard/guard.ts`, R-P8 phase 3). This
 * module adds the one thing that is SAK's: a `SolanaAgentKit` agent for a
 * caller's READ-ONLY use (balances, prices, lookups), built on a wallet that
 * cannot sign (`VerificationGatedWallet`, Round 19 F-19-C2). Every SAK plugin
 * method and LLM-driven SAK tool that would sign is refused with an error
 * naming the verified path; funds move only through `executeTransfer` and
 * `executeSwap`, which are the guard's.
 *
 * This package is the only one in the repository that depends on the
 * `solana-agent-kit` npm package, and with it the gated `bigint-buffer`
 * advisory its `@solana/spl-token` 0.4 tree brings (native addon never built:
 * installs run with `--ignore-scripts`). The guard, and every other adapter,
 * does not carry it.
 */

import { SolanaAgentKit } from "solana-agent-kit";
import { PublicKey } from "@solana/web3.js";
import { GraphiteGuard, type GuardConfig } from "../agent-guard/guard.js";
// Round 19 (F-19-C2): the wallet SAK is given cannot sign.
import { VerificationGatedWallet, UngatedSigningRefused, GATED_SIGNING_PATH } from "./gated-wallet.js";

// Everything the bridge exported before the guard moved out of it, so existing
// callers keep compiling against this module.
export * from "../agent-guard/guard.js";
export { VerificationGatedWallet, UngatedSigningRefused, GATED_SIGNING_PATH };

/** The guard's configuration, plus the one key SAK itself needs. */
export interface SakBridgeConfig extends GuardConfig {
  /**
   * OPENAI_API_KEY, which `SolanaAgentKit` requires at construction. Without
   * it no SAK agent is built and `getSakAgent()` returns null; the verified
   * paths do not need it.
   */
  openAiApiKey?: string;
}

/**
 * Verified SAK agent: the guard's verified execution, plus a SAK agent that
 * cannot sign.
 */
export class VerifiedSakAgent {
  #guard: GraphiteGuard;
  #sakAgent: SolanaAgentKit | null;

  private constructor(guard: GraphiteGuard, sakAgent: SolanaAgentKit | null) {
    this.#guard = guard;
    this.#sakAgent = sakAgent;
  }

  static async create(config?: SakBridgeConfig): Promise<VerifiedSakAgent> {
    const { openAiApiKey: configuredOpenAi, ...guardConfig } = config ?? {};
    // The guard first: it refuses legacy environment names, an insecure AI
    // layer URL and an unreachable Core before anything else is built.
    const guard = await GraphiteGuard.create({ ...guardConfig, reporter: guardConfig.reporter ?? "sak-bridge" });
    const openAiApiKey = configuredOpenAi ?? process.env.OPENAI_API_KEY;
    const rpcUrl = guardConfig.rpcUrl ?? process.env.SOLANA_RPC_URL;
    let sakAgent: SolanaAgentKit | null = null;
    try {
      if (!openAiApiKey) throw new Error("OPENAI_API_KEY required for SAK");
      if (!rpcUrl) throw new Error("SOLANA_RPC_URL required for SAK");
      // SAK is given the PUBLIC key and nothing else (Round 19, F-19-C2). It
      // used to get the keypair, and with it the ability to sign and send any
      // transaction any plugin method or LLM-driven SAK tool built, plus
      // `signMessage` over arbitrary bytes — none of it through Graphite.
      //
      // No SAK plugins are loaded (2026-09-30). Importing one executes its
      // whole dependency tree in the process that holds the private key;
      // `@solana-agent-kit/plugin-defi` alone brought 25 of the tree's 36
      // high/critical npm advisories. A caller that needs a plugin's read-only
      // helpers can load it in its own process.
      const wallet = new VerificationGatedWallet(new PublicKey(guard.publicKey));
      sakAgent = new SolanaAgentKit(wallet, rpcUrl, { OPENAI_API_KEY: openAiApiKey });
      console.log("[Graphite] SAK agent initialized (signing refused — gated wallet), no plugins loaded");
    } catch (err) {
      console.warn("[Graphite] SAK agent not built:", (err as Error).message?.slice(0, 80));
    }
    return new VerifiedSakAgent(guard, sakAgent);
  }

  /** The guard that verifies and signs. Every method below delegates to it. */
  getGuard(): GraphiteGuard {
    return this.#guard;
  }

  parseIntent(...args: Parameters<GraphiteGuard["parseIntent"]>): ReturnType<GraphiteGuard["parseIntent"]> {
    return this.#guard.parseIntent(...args);
  }

  verifyTransaction(
    ...args: Parameters<GraphiteGuard["verifyTransaction"]>
  ): ReturnType<GraphiteGuard["verifyTransaction"]> {
    return this.#guard.verifyTransaction(...args);
  }

  executeTransfer(...args: Parameters<GraphiteGuard["executeTransfer"]>): ReturnType<GraphiteGuard["executeTransfer"]> {
    return this.#guard.executeTransfer(...args);
  }

  executeSwap(...args: Parameters<GraphiteGuard["executeSwap"]>): ReturnType<GraphiteGuard["executeSwap"]> {
    return this.#guard.executeSwap(...args);
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
  getSakAgent(): SolanaAgentKit | null {
    return this.#sakAgent;
  }

  getGraphiteClient(): ReturnType<GraphiteGuard["getGraphiteClient"]> {
    return this.#guard.getGraphiteClient();
  }

  getConnection(): ReturnType<GraphiteGuard["getConnection"]> {
    return this.#guard.getConnection();
  }
}
