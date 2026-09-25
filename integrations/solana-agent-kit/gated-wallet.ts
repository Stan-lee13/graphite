/**
 * The wallet SolanaAgentKit is given: a public key, and no way to sign.
 *
 * Round 19 (F-19-C2). The bridge used to hand SAK `new KeypairWallet(walletKeypair)`
 * — the wallet's secret key — and expose the resulting agent through
 * `getSakAgent()`. Every `sakAgent.methods.*` call and every SAK action tool
 * (the LangChain / Vercel AI / OpenAI tool adapters an LLM drives) then signed
 * and sent with that key through SAK's own `signOrSendTX` / `sendTx`, and
 * `signMessage` signed arbitrary bytes, all with no Graphite verdict anywhere
 * on the path. The verification gate was one door of a house whose other doors
 * were open.
 *
 * This wallet holds only the public key. Every signing entry point in SAK's
 * `BaseWallet` interface refuses with an error naming the one gated path, so
 * the only code in the process that can produce a signature with the wallet
 * key is `BoundTransaction.signApproved` — reached through `executeTransfer`
 * or `executeSwap(payload)` after an artifact-bound approval, a digest
 * re-check and the residual policy. Read-only SAK use (balances, prices,
 * account lookups) needs `publicKey` and the connection, and keeps working.
 *
 * Refusing is structural, not a check on the way to signing: there is no
 * secret key in this object, so no bug in SAK, a plugin or a tool adapter can
 * sign with it by reaching past the refusal.
 */
import { PublicKey } from "@solana/web3.js";

/** Where signing lives. Named in every refusal so the fix is in the error. */
export const GATED_SIGNING_PATH =
  "VerifiedSakAgent.executeTransfer / executeSwap(payload) — Graphite verification, then " +
  "BoundTransaction.signApproved";

/** Thrown by every signing method of `VerificationGatedWallet`. */
export class UngatedSigningRefused extends Error {
  constructor(method: string) {
    super(
      `[Graphite] ${method} refused: the SolanaAgentKit wallet cannot sign. Signing is only ` +
        `reachable through the verified path (${GATED_SIGNING_PATH}), so nothing is signed ` +
        `without an artifact-bound Graphite approval (Round 19, F-19-C2).`,
    );
    this.name = "UngatedSigningRefused";
  }
}

/**
 * Implements SAK's `BaseWallet` (solana-agent-kit 2.x): `publicKey`,
 * `signTransaction`, `signAllTransactions`, `sendTransaction`,
 * `signAndSendTransaction`, `signMessage`. Only the first does anything.
 */
export class VerificationGatedWallet {
  readonly publicKey: PublicKey;

  constructor(publicKey: PublicKey) {
    // A copy by bytes, so the caller's object is not shared.
    this.publicKey = new PublicKey(publicKey.toBytes());
    Object.freeze(this);
  }

  async signTransaction<T>(_transaction: T): Promise<T> {
    throw new UngatedSigningRefused("signTransaction");
  }

  async signAllTransactions<T>(_transactions: T[]): Promise<T[]> {
    throw new UngatedSigningRefused("signAllTransactions");
  }

  async sendTransaction<T>(_transaction: T): Promise<string> {
    throw new UngatedSigningRefused("sendTransaction");
  }

  async signAndSendTransaction<T>(
    _transaction: T,
    _options?: unknown,
  ): Promise<{ signature: string }> {
    throw new UngatedSigningRefused("signAndSendTransaction");
  }

  async signMessage(_message: Uint8Array): Promise<Uint8Array> {
    throw new UngatedSigningRefused("signMessage");
  }
}
