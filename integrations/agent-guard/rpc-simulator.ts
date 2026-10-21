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
import type { WalletEffect } from "./intent-grounding.js";
export type { WalletEffect };
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

/**
 * `fetch` that refuses redirects. Round 29 (audit 2026-10-20, M3): the
 * guard's own JSON-RPC requests already said `redirect: "error"`, but
 * everything that went through a web3.js `Connection` — the advisory
 * simulation, blockhashes, lookup tables, submission — used web3.js's
 * default fetch, which follows them: an RPC answering 307 sent the request to
 * a location the transport rule never saw.
 */
export const noRedirectFetch: typeof globalThis.fetch = (input, init) =>
  capturedFetch(input, { ...(init ?? {}), redirect: "error" });

/**
 * The process's `fetch`, captured when this module loads (Round 30). Every
 * request the guard makes to the RPC and the AI layer goes through it, so a
 * tool or plugin loaded later that reassigns `globalThis.fetch` does not get
 * to answer the simulations and submissions the guard decides on. Code loaded
 * BEFORE this module is outside what this can help with; isolating the key
 * from that is a separate signing process's job.
 */
export const capturedFetch: typeof globalThis.fetch = globalThis.fetch.bind(globalThis);

/** A web3.js Connection that never follows a redirect (Round 29, M3). */
export function connectionWithoutRedirects(rpcUrl: string): Connection {
  return new Connection(rpcUrl, { commitment: "confirmed", fetch: noRedirectFetch });
}

export class RpcSimulator {
  #connection: Connection;
  #rpcUrl: string;
  constructor(rpcUrl: string) {
    this.#rpcUrl = rpcUrl;
    this.#connection = connectionWithoutRedirects(rpcUrl);
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
    const response = await capturedFetch(this.#rpcUrl, {
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
    const body = (await readJsonBounded(response)) as {
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
      const simulation = await this.#connection.simulateTransaction(tx, {
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
   * What the exact transaction does to the wallet, from ONE simulation of its
   * unsigned bytes: the RPC's `preBalances`/`postBalances` and
   * `preTokenBalances`/`postTokenBalances` of the same run, at the same slot.
   *
   * External review (2026-10-16): this used to read the wallet's accounts
   * with `getMultipleAccounts` and compare them with the simulation's
   * post-state. The two reads are not one snapshot: a deposit landing between
   * them made a 50 SOL spend look like no outflow at all, under a 1 SOL cap.
   * Both sides now come from the simulation itself.
   *
   * The fee payer is static key 0, and the guard builds every transaction
   * with its own wallet as fee payer, so `preBalances[0]` is the wallet's
   * lamports. Token balances carry their owner, so only the wallet's own token
   * accounts count, wherever they sit in the account list (lookup tables
   * included). Wrapped SOL counts as SOL. Refuses (throws) rather than
   * reporting what it did not read: a failed simulation, missing or uneven
   * balance arrays, a balance that is not an exact integer, or a token balance
   * without an owner.
   */
  async measureWalletEffect(params: { wire: Uint8Array; wallet: string }): Promise<WalletEffect> {
    assertEverySignatureSlotEmpty(params.wire);
    const sim = await this.#rpc<{
      value?: {
        err?: unknown;
        preBalances?: unknown;
        postBalances?: unknown;
        preTokenBalances?: unknown;
        postTokenBalances?: unknown;
      };
    }>("simulateTransaction", [
      Buffer.from(params.wire).toString("base64"),
      { encoding: "base64", sigVerify: false, replaceRecentBlockhash: true, commitment: "confirmed" },
    ]);
    const value = sim.value;
    if (!value || !("err" in value)) throw new Error("[RpcSimulator] effect simulation: no result. REFUSING.");
    if (value.err !== null) {
      throw new Error(
        `[RpcSimulator] effect simulation failed: ${JSON.stringify(value.err).slice(0, 160)}. REFUSING.`,
      );
    }
    return walletEffectOf(value, params.wallet);
  }

  async #rpc<T>(method: string, params: unknown[]): Promise<T> {
    const response = await capturedFetch(this.#rpcUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      redirect: "error",
      signal: AbortSignal.timeout(30_000),
    });
    if (!response.ok) throw new Error(`[RpcSimulator] ${method}: HTTP ${response.status}. REFUSING.`);
    const body = (await readJsonBounded(response)) as { error?: { message?: string }; result?: T };
    if (body.error || body.result === undefined) {
      throw new Error(`[RpcSimulator] ${method} refused by the RPC: ${body.error?.message ?? "no result"}. REFUSING.`);
    }
    return body.result;
  }
}
// Round 30: the measurement a swap is judged by (`measureWalletEffect`) and
// the unsigned-simulation check cannot be replaced at runtime.
Object.freeze(RpcSimulator.prototype);
Object.freeze(RpcSimulator);

/**
 * The most bytes one RPC answer may carry: the Core's own bound
 * (`rpc_client::MAX_RPC_RESPONSE_BYTES`, 32 MiB). External review
 * (2026-10-16): the guard parsed whatever an RPC sent with
 * `response.json()`, so a hostile or broken endpoint could hand the signing
 * process an answer of any size.
 */
export const MAX_RPC_RESPONSE_BYTES = 32 * 1024 * 1024;

/**
 * Read a JSON answer, refusing one larger than `max` bytes before it is
 * parsed. `what` names the answer in the refusal (the AI layer's answer goes
 * through here too since Round 29).
 */
export async function readJsonBounded(
  response: Response,
  max: number = MAX_RPC_RESPONSE_BYTES,
  what = "[RpcSimulator] the RPC answer",
): Promise<unknown> {
  const declared = response.headers.get("content-length");
  if (declared !== null && Number(declared) > max) {
    await response.body?.cancel();
    throw new Error(`${what} declares ${declared} bytes, over the ${max}-byte bound. REFUSING.`);
  }
  if (!response.body) throw new Error(`${what} has no body. REFUSING.`);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel();
      throw new Error(`${what} exceeds the ${max}-byte bound. REFUSING.`);
    }
    chunks.push(value);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  return JSON.parse(text);
}

export const WRAPPED_SOL_MINT = "So11111111111111111111111111111111111111112";

/**
 * A lamport balance from an RPC answer, exactly. JSON numbers lose integer
 * precision past 2^53, silently (external review, 2026-10-16: lamports were a
 * JavaScript `number`); a balance that is not a safe integer is refused, never
 * rounded.
 */
export function exactLamports(v: unknown, what: string): bigint {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) {
    throw new Error(`[RpcSimulator] ${what} is ${JSON.stringify(v)}, not an exact lamport balance. REFUSING.`);
  }
  return BigInt(v);
}

interface TokenBalanceEntry {
  accountIndex: number;
  mint: string;
  owner: string;
  amount: bigint;
  decimals: number;
}

function tokenBalances(v: unknown, which: string): TokenBalanceEntry[] {
  if (!Array.isArray(v)) {
    throw new Error(`[RpcSimulator] the simulation did not report ${which}; a swap's effect cannot be read without it. REFUSING.`);
  }
  return v.map((e: unknown, i) => {
    const t = e as { accountIndex?: unknown; mint?: unknown; owner?: unknown; uiTokenAmount?: { amount?: unknown; decimals?: unknown } };
    const amount = t?.uiTokenAmount?.amount;
    const decimals = t?.uiTokenAmount?.decimals;
    if (
      !Number.isSafeInteger(t?.accountIndex) ||
      typeof t?.mint !== "string" ||
      typeof t?.owner !== "string" ||
      typeof amount !== "string" ||
      !/^\d{1,20}$/.test(amount) ||
      !Number.isSafeInteger(decimals)
    ) {
      throw new Error(`[RpcSimulator] ${which}[${i}] is not a complete token balance (index, mint, owner, amount, decimals). REFUSING.`);
    }
    return {
      accountIndex: t.accountIndex as number,
      mint: t.mint,
      owner: t.owner,
      amount: BigInt(amount),
      decimals: decimals as number,
    };
  });
}

/** The wallet's effect from one simulation's balances (pure; see `measureWalletEffect`). */
export function walletEffectOf(
  value: { preBalances?: unknown; postBalances?: unknown; preTokenBalances?: unknown; postTokenBalances?: unknown },
  wallet: string,
): WalletEffect {
  const pre = value.preBalances;
  const post = value.postBalances;
  if (!Array.isArray(pre) || !Array.isArray(post) || pre.length === 0 || pre.length !== post.length) {
    throw new Error(
      "[RpcSimulator] the simulation did not report even preBalances and postBalances (an RPC on Agave " +
        "2.1 or later does); a transaction's effect is not read from two separate reads. REFUSING.",
    );
  }
  let solOut = exactLamports(pre[0], "the fee payer's pre-balance") - exactLamports(post[0], "the fee payer's post-balance");
  let wrappedSolDelta = 0n;
  const tokenDelta = new Map<string, bigint>();
  const decimals = new Map<string, number>();
  const add = (entries: TokenBalanceEntry[], sign: 1n | -1n) => {
    for (const e of entries) {
      if (e.owner !== wallet) continue;
      if (e.accountIndex >= pre.length) {
        throw new Error(`[RpcSimulator] a token balance names account ${e.accountIndex} of ${pre.length}. REFUSING.`);
      }
      const known = decimals.get(e.mint);
      if (known !== undefined && known !== e.decimals) {
        throw new Error(`[RpcSimulator] ${e.mint} is reported with ${known} and ${e.decimals} decimals. REFUSING.`);
      }
      decimals.set(e.mint, e.decimals);
      if (e.mint === WRAPPED_SOL_MINT) {
        solOut += sign * e.amount;
        wrappedSolDelta -= sign * e.amount;
      } else {
        tokenDelta.set(e.mint, (tokenDelta.get(e.mint) ?? 0n) - sign * e.amount);
      }
    }
  };
  // Held before and gone after counts as leaving; arriving counts as received.
  add(tokenBalances(value.preTokenBalances, "preTokenBalances"), 1n);
  add(tokenBalances(value.postTokenBalances, "postTokenBalances"), -1n);
  return { solOut, tokenDelta, decimals, wrappedSolDelta };
}
