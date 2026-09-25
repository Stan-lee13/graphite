/**
 * RPC simulation for the audit trail — never signed.
 *
 * Round 19 (F-19-C1). The simulator used to build a legacy `Transaction` and
 * call `connection.simulateTransaction(tx, [walletKeypair])`. In
 * @solana/web3.js 1.x passing signers is not a hint: the Connection fetches a
 * LIVE blockhash, calls `transaction.sign(...signers)` and sends the SIGNED
 * wire transaction to the RPC. `verifyTransaction` did that for every transfer,
 * before Graphite had said anything. The RPC therefore held a valid, signed,
 * broadcastable transfer that Graphite had not yet approved — it could land a
 * transfer Graphite then blocked, or land alongside the approved one (built on
 * a different blockhash, so a different signature) and pay twice.
 *
 * Nothing here can sign now, by construction rather than by care:
 *
 *   - the input is a fee payer's PUBLIC key, so there is no secret in reach;
 *   - the transaction is a `VersionedTransaction` compiled from the message,
 *     whose signature slots web3.js fills with zeros and never touches again;
 *   - it is simulated with `sigVerify: false` (the RPC does not need a
 *     signature to execute the message) and `replaceRecentBlockhash: true` (so
 *     no blockhash is fetched here and the one in the message is a placeholder
 *     the RPC overwrites — a transaction on a placeholder blockhash could not
 *     land even if someone signed it);
 *   - and immediately before the bytes leave, every signature slot is read
 *     back out of the serialized form and must be zero, or nothing is sent.
 *
 * What the numbers are for. The compute/writes/hops feed the request's
 * `compute_units` / `account_writes` / `cpi_hops` and the audit trail. They are
 * advisory: the Core zeroes the SimulationMatch signal value (Constitution G4 —
 * request-body evidence is attacker-controlled), runs its OWN simulation of
 * the artifact when it has an RPC client, and reports caller-supplied usage as
 * "caller-supplied … advisory only, cannot certify clean". An unsigned
 * simulation produces the same numbers the signed one did; only the risk is
 * gone.
 */
import {
  Connection,
  PublicKey,
  TransactionMessage,
  VersionedTransaction,
  type TransactionInstruction,
} from "@solana/web3.js";
import { readSignatureCount } from "./artifact.js";

export interface SimulationSummary {
  computeUnits: number;
  accountWrites: number;
  cpiHops: number;
  logs: string[];
  success: boolean;
}

/**
 * The blockhash the message carries. All zeros, base58 — a valid 32-byte
 * value that no cluster ever produced, so the message could not be executed
 * outside a simulation that replaces it, and nothing here has to ask the RPC
 * for a real one.
 */
export const PLACEHOLDER_BLOCKHASH = new PublicKey(new Uint8Array(32)).toBase58();

/**
 * Throw unless every signature slot in a serialized transaction is zero.
 *
 * Reads the compact-u16 count with the same strict reader the execution
 * boundary uses (`readSignatureCount`: minimal encoding, at most three bytes),
 * so a malformed count cannot make this look at the wrong range.
 */
export function assertEverySignatureSlotEmpty(wire: Uint8Array): void {
  const { count, offset } = readSignatureCount(wire);
  if (offset > wire.length) {
    throw new Error("[RpcSimulator] signature array runs past the transaction");
  }
  const start = offset - count * 64;
  for (let i = start; i < offset; i++) {
    if (wire[i] !== 0) {
      throw new Error(
        `[RpcSimulator] signature slot ${Math.floor((i - start) / 64)} is not empty. ` +
          "A simulation must never carry a signature: a signed transaction handed to an RPC " +
          "is a transaction that RPC can broadcast before Graphite has decided. REFUSING.",
      );
    }
  }
}

export class RpcSimulator {
  private connection: Connection;
  constructor(rpcUrl: string) {
    this.connection = new Connection(rpcUrl, "confirmed");
  }

  async simulate(params: {
    instructions: TransactionInstruction[];
    /** The fee payer's public key. A keypair is not accepted and not needed. */
    feePayer: PublicKey;
  }): Promise<SimulationSummary> {
    // Round 19 (F-19-C1): the previous signature of this method took
    // `signers: Keypair[]`. A caller still passing them — an old call site, a
    // cast — is refused loudly rather than having the keys silently ignored,
    // because a caller who thinks it is signing a simulation has the wrong
    // model of what is safe to do before a verdict.
    if ((params as { signers?: unknown }).signers !== undefined) {
      throw new Error(
        "[RpcSimulator] signers were passed to a simulation. Simulations are never signed " +
          "(Round 19, F-19-C1): pass `feePayer` (a public key) instead. REFUSING.",
      );
    }
    const failure = (logs: string[] = []): SimulationSummary => ({
      computeUnits: 0,
      accountWrites: 0,
      cpiHops: 0,
      logs,
      success: false,
    });

    let tx: VersionedTransaction;
    try {
      const message = new TransactionMessage({
        payerKey: params.feePayer,
        recentBlockhash: PLACEHOLDER_BLOCKHASH,
        instructions: params.instructions,
      }).compileToLegacyMessage();
      tx = new VersionedTransaction(message);
    } catch (err) {
      console.warn("[RpcSimulator] Could not compile the message:", (err as Error).message);
      return failure();
    }
    // Last look before anything leaves the process. Not caught: if this ever
    // fires, something signed the object between its construction and here,
    // and the right response is to stop the verification, not to report a
    // failed simulation and carry on.
    assertEverySignatureSlotEmpty(tx.serialize());

    try {
      const simulation = await this.connection.simulateTransaction(tx, {
        sigVerify: false,
        replaceRecentBlockhash: true,
        commitment: "confirmed",
      });
      if (simulation.value.err) {
        console.warn(
          "[RpcSimulator] Simulation returned error:",
          JSON.stringify(simulation.value.err).slice(0, 80),
        );
        return failure(simulation.value.logs ?? []);
      }
      const logs = simulation.value.logs ?? [];
      let computeUnits = simulation.value.unitsConsumed ?? 0;
      if (computeUnits === 0) {
        const cuMatch = logs.find((l: string) => l.includes("consumed"));
        if (cuMatch) {
          const m = cuMatch.match(/consumed (\d+)/);
          if (m) computeUnits = parseInt(m[1]);
        }
      }
      // Count writable accounts from instructions (fallback if simulation doesn't report)
      let accountWrites = 0;
      if (simulation.value.accounts) {
        accountWrites = simulation.value.accounts.filter((a: unknown) => a).length;
      }
      if (accountWrites === 0) {
        const writableAccounts = new Set<string>();
        for (const ix of params.instructions) {
          for (const key of ix.keys) if (key.isWritable) writableAccounts.add(key.pubkey.toBase58());
        }
        accountWrites = writableAccounts.size;
      }
      let cpiHops = 0;
      for (const log of logs) {
        const m = log.match(/Program \w+ invoke \[(\d+)\]/);
        if (m) {
          const l = parseInt(m[1]);
          if (l > cpiHops) cpiHops = l;
        }
      }
      return { computeUnits, accountWrites, cpiHops, logs, success: true };
    } catch (err) {
      console.warn("[RpcSimulator] Simulation failed:", (err as Error).message);
      return failure();
    }
  }
}
