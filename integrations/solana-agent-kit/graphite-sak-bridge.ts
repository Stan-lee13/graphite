/**
 * Graphite for Solana Agent Kit — the SAK adapter over `GraphiteGuard`.
 *
 * Everything that verifies, signs and submits lives in the framework-
 * independent guard (`integrations/agent-guard/guard.ts`, R-P8 phase 3). This
 * module adds the one thing that is SAK's: the wallet a caller gives its own
 * `SolanaAgentKit` agent, which cannot sign (`VerificationGatedWallet`,
 * Round 19 F-19-C2). Every SAK plugin method and LLM-driven SAK tool that
 * would sign through it is refused with an error naming the verified path;
 * funds move only through `executeTransfer` and `executeSwap`, which are the
 * guard's.
 *
 * Round 36 (F-001): this module no longer imports `solana-agent-kit`. It used
 * to build a `SolanaAgentKit` agent itself, with no plugins: an agent with no
 * actions and no methods, which gave a caller nothing a `Connection` does
 * not. Importing it loaded the whole SAK bundle — LangChain, the OpenAI agents
 * SDK, the Vercel AI SDK and two Zod lines, `zod/v3` among them — into the
 * process that holds the wallet key, with the Zod collection-validation
 * advisory (GHSA-mrhx-c7xc-m3w5, every Zod below 4.6.6; the `zod/v3` code is
 * unchanged even in 4.6.6) and the `bigint-buffer` one. A caller that wants a
 * SAK agent builds it in its own code on `getGatedWallet()`; nothing here
 * loads SAK, and `solana-agent-kit` is a development dependency only (the
 * tests that prove SAK's own signing helpers are refused).
 *
 * Round 29 (audit 2026-10-20, M6 / S1): this adapter used to start without a
 * per-transaction cap while the MCP and Vercel adapters refused to. The guard
 * itself now refuses to start without one (unless GRAPHITE_ALLOW_UNCAPPED=1),
 * so every adapter, this one included, is bounded the same way.
 *
 * Keys (M8): the wallet key and the Core API key are not reachable through
 * this object or the guard. Since Round 36 the adapter holds no OpenAI key
 * either: it builds no SAK agent.
 */

import { PublicKey } from "@solana/web3.js";
import { GraphiteGuard, type GuardConfig } from "../agent-guard/guard.js";
// Round 19 (F-19-C2): the wallet SAK is given cannot sign.
import { VerificationGatedWallet, UngatedSigningRefused, GATED_SIGNING_PATH } from "./gated-wallet.js";

// Everything the bridge exported before the guard moved out of it, so existing
// callers keep compiling against this module.
export * from "../agent-guard/guard.js";
export { VerificationGatedWallet, UngatedSigningRefused, GATED_SIGNING_PATH };

/** The guard's configuration (since Round 36 the adapter needs nothing more). */
export type SakBridgeConfig = GuardConfig;

/**
 * Verified SAK agent: the guard's verified execution, plus the wallet a SAK
 * agent is built on, which cannot sign.
 */
export class VerifiedSakAgent {
  #guard: GraphiteGuard;
  #wallet: VerificationGatedWallet;

  private constructor(guard: GraphiteGuard) {
    this.#guard = guard;
    // SAK is given the PUBLIC key and nothing else (Round 19, F-19-C2). It
    // used to get the keypair, and with it the ability to sign and send any
    // transaction any plugin method or LLM-driven SAK tool built, plus
    // `signMessage` over arbitrary bytes — none of it through Graphite.
    this.#wallet = new VerificationGatedWallet(new PublicKey(guard.publicKey));
  }

  static async create(config?: SakBridgeConfig): Promise<VerifiedSakAgent> {
    const guardConfig = config ?? {};
    if ("openAiApiKey" in guardConfig) {
      // Round 36: no SAK agent is built here, so the key would be held for
      // nothing. Said, not silently dropped.
      throw new Error(
        "[Graphite] openAiApiKey is no longer taken: the adapter builds no SolanaAgentKit agent (Round 36). " +
          "Build your agent on getGatedWallet() with your own OpenAI key.",
      );
    }
    // The guard first: it refuses legacy environment names, an insecure AI
    // layer URL and an unreachable Core before anything else is built.
    const guard = await GraphiteGuard.create({ ...guardConfig, reporter: guardConfig.reporter ?? "sak-bridge" });
    return new VerifiedSakAgent(guard);
  }

  /** The guard that verifies and signs. Every method below delegates to it. */
  getGuard(): GraphiteGuard {
    return this.#guard;
  }

  parseIntent(...args: Parameters<GraphiteGuard["parseIntent"]>): ReturnType<GraphiteGuard["parseIntent"]> {
    return this.#guard.parseIntent(...args);
  }

  // Round 34 (G-7): no `verifyTransaction`. The guard's is private: every
  // call writes a verification to the audit trail under the deployment's
  // Core key, about whatever the caller describes, and holding the adapter
  // must not be holding that key (the reason `getGraphiteClient` returns a
  // read-only facade, Round 29 M8). Verification happens inside
  // `executeTransfer` / `executeSwap`, about the transaction they built; a
  // caller that wants a verdict alone builds its own client with its own key.

  executeTransfer(...args: Parameters<GraphiteGuard["executeTransfer"]>): ReturnType<GraphiteGuard["executeTransfer"]> {
    return this.#guard.executeTransfer(...args);
  }

  executeSwap(...args: Parameters<GraphiteGuard["executeSwap"]>): ReturnType<GraphiteGuard["executeSwap"]> {
    return this.#guard.executeSwap(...args);
  }

  /**
   * The wallet to build a `SolanaAgentKit` agent on, for READ-ONLY use
   * (balances, prices, lookups): `new SolanaAgentKit(agent.getGatedWallet(),
   * rpcUrl, config)`, in the caller's own code.
   *
   * Round 19 (F-19-C2): the adapter used to hand SAK the wallet's secret key,
   * so any caller — or any LLM tool built from the agent — could sign and send
   * around the gate. This wallet holds the public key only: every signing
   * method throws `UngatedSigningRefused`. To move funds, use
   * `executeTransfer` or `executeSwap(payload)`. Round 36: this replaces
   * `getSakAgent()`, whose agent had no plugins and so no actions.
   */
  getGatedWallet(): VerificationGatedWallet {
    return this.#wallet;
  }

  /**
   * The Core's read-only endpoints (health, manifests). Round 29 (audit
   * 2026-10-20, M8): this returned the guard's `GraphiteClient`, and with it
   * the Core API key; the guard now hands out a read-only facade.
   */
  getGraphiteClient(): ReturnType<GraphiteGuard["getGraphiteClient"]> {
    return this.#guard.getGraphiteClient();
  }

  getConnection(): ReturnType<GraphiteGuard["getConnection"]> {
    return this.#guard.getConnection();
  }
}
