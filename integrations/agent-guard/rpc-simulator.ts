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
import { messageOf, readSignatureCount, V1_PREFIX } from "./artifact.js";
import {
  compileUnsignedWithKit,
  MAX_COMPUTE_UNIT_LIMIT,
  MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES,
  type V1Limits,
} from "./kit-artifact.js";

/** The block cost model charges loaded account data in 32 KiB pages. */
export const LOADED_DATA_PAGE_BYTES = 32 * 1024;

/**
 * Compute headroom over the simulated figure, in percent. The simulation is
 * one run against one state; a route whose path depends on pool state can
 * cost more when it lands, and a v1 transaction that runs out of its budget
 * fails. Twenty percent is what kit's guidance leaves to the caller to add.
 */
export const V1_COMPUTE_HEADROOM_PERCENT = 20;

/**
 * The v1 limits to put in a message, from one simulation's measurements.
 *
 * Compute: the units consumed plus `V1_COMPUTE_HEADROOM_PERCENT`, at least
 * one more than consumed, at most the runtime's ceiling. Loaded data: the
 * next 32 KiB page strictly above what was loaded — the cost model charges by
 * page, so headroom below the boundary is free, and an account created
 * between simulation and landing (64 bytes of metadata where there were none)
 * fits in it.
 */
export function v1LimitsFromMeasurement(unitsConsumed: number, loadedAccountsDataSize: number): V1Limits {
  if (!Number.isSafeInteger(unitsConsumed) || unitsConsumed < 0) {
    throw new Error(`[RpcSimulator] unitsConsumed ${String(unitsConsumed)} is not a measurement`);
  }
  if (!Number.isSafeInteger(loadedAccountsDataSize) || loadedAccountsDataSize < 0) {
    throw new Error(`[RpcSimulator] loadedAccountsDataSize ${String(loadedAccountsDataSize)} is not a measurement`);
  }
  const computeUnitLimit = Math.min(
    MAX_COMPUTE_UNIT_LIMIT,
    Math.max(unitsConsumed + 1, Math.ceil((unitsConsumed * (100 + V1_COMPUTE_HEADROOM_PERCENT)) / 100)),
  );
  const loadedAccountsDataSizeLimit = Math.min(
    MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES,
    (Math.floor(loadedAccountsDataSize / LOADED_DATA_PAGE_BYTES) + 1) * LOADED_DATA_PAGE_BYTES,
  );
  if (unitsConsumed >= MAX_COMPUTE_UNIT_LIMIT) {
    throw new Error(`[RpcSimulator] the simulation consumed ${unitsConsumed} compute units, the whole budget`);
  }
  if (loadedAccountsDataSize >= MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES) {
    throw new Error(`[RpcSimulator] the simulation loaded ${loadedAccountsDataSize} bytes, the whole budget`);
  }
  return { computeUnitLimit, loadedAccountsDataSizeLimit };
}

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
  let start: number;
  let offset: number;
  if (wire[0] === V1_PREFIX) {
    // A v1 frame's slots trail the message; `messageOf` parses the frame in
    // full (the Core's own rules) to find where they begin.
    start = messageOf(wire).length;
    offset = wire.length;
  } else {
    const read = readSignatureCount(wire);
    if (read.offset > wire.length) {
      throw new Error("[RpcSimulator] signature array runs past the transaction");
    }
    offset = read.offset;
    start = offset - read.count * 64;
  }
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
  private rpcUrl: string;
  constructor(rpcUrl: string) {
    this.rpcUrl = rpcUrl;
    this.connection = new Connection(rpcUrl, "confirmed");
  }

  /**
   * Measure what a v1 message needs, before it is built for verification.
   *
   * In v1 an unset compute or loaded-data limit is ZERO, so the limits must
   * be in the message Graphite verifies. They are measured, not guessed: the
   * instructions are compiled as an UNSIGNED v1 draft carrying the runtime's
   * maximum limits (so the measurement cannot fail for want of what it is
   * measuring), on the all-zero placeholder blockhash, and simulated with
   * `sigVerify: false` and `replaceRecentBlockhash: true` — the same
   * nothing-can-be-signed construction as `simulate`. web3.js 1.x cannot
   * serialize a v1 transaction, so the request is plain JSON-RPC over base64.
   *
   * Refuses rather than estimating when the simulation errors or the RPC
   * withholds `unitsConsumed` or `loadedAccountsDataSize`: a v1 budget sized
   * on a missing number would be a transaction that cannot execute.
   */
  async estimateV1Limits(params: {
    instructions: TransactionInstruction[];
    feePayer: PublicKey;
  }): Promise<V1Limits & { unitsConsumed: number; loadedAccountsDataSize: number }> {
    const draft = compileUnsignedWithKit({
      instructions: params.instructions,
      feePayer: params.feePayer,
      recentBlockhash: PLACEHOLDER_BLOCKHASH,
      lastValidBlockHeight: 0,
      version: 1,
      v1Limits: {
        computeUnitLimit: MAX_COMPUTE_UNIT_LIMIT,
        loadedAccountsDataSizeLimit: MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES,
      },
    });
    assertEverySignatureSlotEmpty(draft);
    const response = await fetch(this.rpcUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "simulateTransaction",
        params: [
          Buffer.from(draft).toString("base64"),
          { encoding: "base64", sigVerify: false, replaceRecentBlockhash: true, commitment: "confirmed" },
        ],
      }),
      redirect: "error",
      signal: AbortSignal.timeout(30_000),
    });
    if (!response.ok) {
      throw new Error(`[RpcSimulator] v1 sizing simulation: HTTP ${response.status}`);
    }
    const body = (await response.json()) as {
      error?: { message?: string };
      result?: { value?: { err?: unknown; unitsConsumed?: unknown; loadedAccountsDataSize?: unknown } };
    };
    if (body.error) {
      throw new Error(`[RpcSimulator] v1 sizing simulation refused by the RPC: ${body.error.message ?? "error"}`);
    }
    const value = body.result?.value;
    if (!value) throw new Error("[RpcSimulator] v1 sizing simulation: no result");
    if (value.err !== null && value.err !== undefined) {
      throw new Error(
        `[RpcSimulator] v1 sizing simulation failed: ${JSON.stringify(value.err).slice(0, 160)}. ` +
          "A transaction that fails here cannot be given a budget.",
      );
    }
    if (typeof value.unitsConsumed !== "number" || typeof value.loadedAccountsDataSize !== "number") {
      throw new Error(
        "[RpcSimulator] the RPC did not report unitsConsumed and loadedAccountsDataSize; a v1 budget " +
          "cannot be sized without both (an RPC on Agave 4.2 or later reports them). REFUSING.",
      );
    }
    return {
      ...v1LimitsFromMeasurement(value.unitsConsumed, value.loadedAccountsDataSize),
      unitsConsumed: value.unitsConsumed,
      loadedAccountsDataSize: value.loadedAccountsDataSize,
    };
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

  /**
   * What the exact transaction would take out of the wallet: the wallet's own
   * lamports (fee included) and the balance of every token account the wallet
   * owns among `accounts`, each read before and after an unsigned simulation
   * of `wire` — the bytes that will be signed, not a description of them.
   * Wrapped SOL counts as lamports. Refuses (throws) rather than reporting a
   * number it did not read: a failed simulation, an account the RPC does not
   * return, or a wallet token account it cannot decode.
   */
  async measureWalletOutflow(params: {
    wire: Uint8Array;
    wallet: string;
    accounts: readonly string[];
  }): Promise<WalletOutflow> {
    assertEverySignatureSlotEmpty(params.wire);
    const addresses = [...new Set([params.wallet, ...params.accounts])];
    const pre = await this.rpc<{ value?: (RpcAccount | null)[] }>("getMultipleAccounts", [
      addresses,
      { encoding: "base64", commitment: "confirmed" },
    ]);
    const sim = await this.rpc<{
      value?: { err?: unknown; accounts?: (RpcAccount | null)[] | null };
    }>("simulateTransaction", [
      Buffer.from(params.wire).toString("base64"),
      {
        encoding: "base64",
        sigVerify: false,
        replaceRecentBlockhash: true,
        commitment: "confirmed",
        accounts: { encoding: "base64", addresses },
      },
    ]);
    const before = pre.value;
    const value = sim.value;
    if (!Array.isArray(before) || before.length !== addresses.length) {
      throw new Error("[RpcSimulator] the RPC did not return every account the outflow is measured on. REFUSING.");
    }
    if (!value || !("err" in value)) throw new Error("[RpcSimulator] outflow simulation: no result. REFUSING.");
    if (value.err !== null) {
      throw new Error(
        `[RpcSimulator] outflow simulation failed: ${JSON.stringify(value.err).slice(0, 160)}. REFUSING.`,
      );
    }
    const after = value.accounts;
    if (!Array.isArray(after) || after.length !== addresses.length) {
      throw new Error("[RpcSimulator] the simulation did not return the post-state of every account. REFUSING.");
    }
    const walletBefore = before[0];
    if (!walletBefore) throw new Error("[RpcSimulator] the wallet account does not exist. REFUSING.");
    let lamports = positiveDecrease(BigInt(walletBefore.lamports), BigInt(after[0]?.lamports ?? 0));
    const tokens: WalletOutflow["tokens"] = [];
    for (let i = 1; i < addresses.length; i++) {
      const b = before[i];
      if (!b || !TOKEN_PROGRAMS.has(b.owner)) continue;
      const data = Buffer.from(b.data[0], "base64");
      if (data.length < TOKEN_ACCOUNT_BASE_LEN) continue; // a mint or a multisig, not a token account
      if (new PublicKey(data.subarray(32, 64)).toBase58() !== params.wallet) continue;
      const mint = new PublicKey(data.subarray(0, 32)).toBase58();
      const a = after[i];
      let postAmount = 0n;
      if (a && TOKEN_PROGRAMS.has(a.owner)) {
        const post = Buffer.from(a.data[0], "base64");
        if (post.length < TOKEN_ACCOUNT_BASE_LEN) {
          throw new Error(`[RpcSimulator] ${addresses[i]} is not a token account after the simulation. REFUSING.`);
        }
        postAmount = post.readBigUInt64LE(64);
      }
      const spent = positiveDecrease(data.readBigUInt64LE(64), postAmount);
      if (spent === 0n) continue;
      if (mint === WRAPPED_SOL_MINT) lamports += spent;
      else tokens.push({ mint, account: addresses[i], amount: spent });
    }
    return { lamports, tokens };
  }

  private async rpc<T>(method: string, params: unknown[]): Promise<T> {
    const response = await fetch(this.rpcUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      redirect: "error",
      signal: AbortSignal.timeout(30_000),
    });
    if (!response.ok) throw new Error(`[RpcSimulator] ${method}: HTTP ${response.status}. REFUSING.`);
    const body = (await response.json()) as { error?: { message?: string }; result?: T };
    if (body.error || body.result === undefined) {
      throw new Error(`[RpcSimulator] ${method} refused by the RPC: ${body.error?.message ?? "no result"}. REFUSING.`);
    }
    return body.result;
  }
}

interface RpcAccount {
  lamports: number;
  owner: string;
  data: [string, string];
}

/** What one transaction takes out of the wallet (see `measureWalletOutflow`). */
export interface WalletOutflow {
  /** Lamports, the fee and wrapped SOL included. */
  lamports: bigint;
  /** Every other token balance the wallet's own accounts lose. */
  tokens: { mint: string; account: string; amount: bigint }[];
}

const TOKEN_PROGRAMS = new Set([
  "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
  "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
]);
/** mint(32) owner(32) amount(8) …: the SPL Token account layout Token-2022 extends. */
const TOKEN_ACCOUNT_BASE_LEN = 165;
export const WRAPPED_SOL_MINT = "So11111111111111111111111111111111111111112";

function positiveDecrease(before: bigint, after: bigint): bigint {
  return before > after ? before - after : 0n;
}
