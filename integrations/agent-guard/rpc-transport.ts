/**
 * The one transport every Solana RPC request of the guard goes through
 * (Round 35, F-014).
 *
 * The guard's own JSON-RPC reads (`RpcSimulator`'s effect simulation and v1
 * sizing) were bounded since Round 25 — a 30 s deadline, a 32 MiB body bound,
 * no redirects. Everything that went through a web3.js 1.x `Connection` was
 * not: `getLatestBlockhash`, `getAddressLookupTable`, the advisory
 * `simulateTransaction`, `sendRawTransaction`, and the `getSignatureStatuses` /
 * `getBlockHeight` polls behind confirmation and the repeat check. web3.js
 * calls `fetch` with no signal and reads the answer with `res.text()`, so
 *
 *   - an RPC that accepted the connection and never answered held
 *     `executeTransfer` / `executeSwap` open for as long as it liked (the
 *     confirmation loop checked its own 90 s deadline only BETWEEN calls, and
 *     a hung `sendTransaction` never reached the "outcome unknown" path);
 *   - an RPC could hand the signing process an answer of any size;
 *   - an HTTP 429 was retried five times with a growing sleep, inside one call.
 *
 * Redirects were already refused (Round 29, M3). Now every request — web3.js's
 * through its `fetch` option, and the raw ones — goes through
 * `boundedRpcFetch`: to the configured RPC URL only, never redirected, with a
 * deadline that covers the headers AND the whole body, and a body bound.
 *
 * Websockets. web3.js opens one for every subscription (`onSignature`,
 * `onAccountChange`, `onLogs`, …) and for its own `confirmTransaction`, to
 * `ws(s)://<host>:<port + 1>` — an endpoint the transport rule never checked
 * and that none of the bounds above apply to. The guard has confirmed by
 * polling over HTTP since Round 29; `BoundedConnection` now makes that the
 * only way for the connection `getConnection()` hands out too: its
 * `confirmTransaction` polls through the bounded transport, and a subscription
 * is refused (`RpcTransportRefusal`) before any socket is opened. The type is
 * still web3.js's `Connection`; a caller who wants subscriptions builds its
 * own, outside the guard's policy.
 */
import {
  Connection,
  TransactionExpiredBlockheightExceededError,
  TransactionExpiredTimeoutError,
  type Commitment,
  type RpcResponseAndContext,
  type SignatureResult,
  type TransactionConfirmationStrategy,
  type TransactionSignature,
} from "@solana/web3.js";

/**
 * The process's `fetch`, captured when this module loads (Round 30). Every
 * request the guard makes to the RPC and the AI layer goes through it, so a
 * tool or plugin loaded later that reassigns `globalThis.fetch` does not get
 * to answer the simulations and submissions the guard decides on. Code loaded
 * BEFORE this module is outside what this can help with; isolating the key
 * from that is a separate signing process's job.
 */
export const capturedFetch: typeof globalThis.fetch = globalThis.fetch.bind(globalThis);

/**
 * The most bytes one RPC answer may carry: the Core's own bound
 * (`rpc_client::MAX_RPC_RESPONSE_BYTES`, 32 MiB). External review
 * (2026-10-16): the guard parsed whatever an RPC sent with
 * `response.json()`, so a hostile or broken endpoint could hand the signing
 * process an answer of any size.
 */
export const MAX_RPC_RESPONSE_BYTES = 32 * 1024 * 1024;

/** How long one RPC request may take, headers and body, by default (GRAPHITE_RPC_TIMEOUT_MS). */
export const DEFAULT_RPC_TIMEOUT_MS = 30_000;
/** The longest deadline an operator may set: past it, a deadline is not a bound on a signing call. */
export const MAX_RPC_TIMEOUT_MS = 120_000;

/** How long `BoundedConnection.confirmTransaction` polls before giving up, and how often. */
export const CONFIRMATION_MAX_MS = 90_000;
export const CONFIRMATION_POLL_MS = 500;

/** A request the guard's RPC transport refused, or that broke one of its bounds. */
export class RpcTransportRefusal extends Error {
  constructor(message: string) {
    super(`[Graphite] RPC transport: ${message}. REFUSING.`);
    this.name = "RpcTransportRefusal";
  }
}

/**
 * Read GRAPHITE_RPC_TIMEOUT_MS (or the config value): a whole number of
 * milliseconds from 1 to `MAX_RPC_TIMEOUT_MS`. Anything else is a startup
 * error, never a silently absent deadline.
 */
export function resolveRpcTimeoutMs(value: number | string | undefined): number {
  if (value === undefined || value === "") return DEFAULT_RPC_TIMEOUT_MS;
  const n = typeof value === "string" && /^[0-9]{1,9}$/.test(value.trim()) ? Number(value.trim()) : value;
  if (typeof n !== "number" || !Number.isSafeInteger(n) || n < 1 || n > MAX_RPC_TIMEOUT_MS) {
    throw new Error(
      `[Graphite] the RPC timeout ${JSON.stringify(value)} is not a whole number of milliseconds from 1 to ` +
        `${MAX_RPC_TIMEOUT_MS} (GRAPHITE_RPC_TIMEOUT_MS / rpcTimeoutMs). REFUSING TO START.`,
    );
  }
  return n;
}

/**
 * Read a body, refusing one larger than `max` bytes — declared or streamed —
 * before it is used.
 */
export async function readBytesBounded(response: Response, max: number, what: string): Promise<Buffer> {
  const declared = response.headers.get("content-length");
  if (declared !== null && Number(declared) > max) {
    await response.body?.cancel().catch(() => {});
    throw new RpcTransportRefusal(`${what} declares ${declared} bytes, over the ${max}-byte bound`);
  }
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel().catch(() => {});
      throw new RpcTransportRefusal(`${what} exceeds the ${max}-byte bound`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}

function urlOf(input: Parameters<typeof globalThis.fetch>[0]): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

/**
 * A `fetch` for one RPC endpoint, bounded (Round 35, F-014):
 *
 *   - only `rpcUrl` itself: a request to any other URL is refused (web3.js
 *     only ever asks for the endpoint it was built with; anything else is not
 *     the endpoint the transport rule checked);
 *   - never redirected (`redirect: "error"`, Round 29, M3);
 *   - one deadline, `timeoutMs`, over the headers and the whole body, combined
 *     with any signal the caller passed;
 *   - at most `maxBytes` of body, declared or streamed.
 *
 * The answer is read here, inside the deadline and the bound, and handed back
 * as a fresh `Response` over those bytes, so web3.js's `res.text()` and the
 * guard's own JSON reads parse nothing that was not bounded. Errors name the
 * method, never the URL (a provider URL can carry its API key).
 */
export function boundedRpcFetch(
  rpcUrl: string,
  opts: { timeoutMs?: number; maxBytes?: number } = {},
): typeof globalThis.fetch {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_RPC_TIMEOUT_MS;
  const maxBytes = opts.maxBytes ?? MAX_RPC_RESPONSE_BYTES;
  return async (input, init) => {
    if (urlOf(input) !== rpcUrl) {
      throw new RpcTransportRefusal("a request to a URL other than the configured RPC endpoint");
    }
    const what = `the RPC answer to ${methodOf(init?.body)}`;
    const deadline = AbortSignal.timeout(timeoutMs);
    const signal = init?.signal ? AbortSignal.any([init.signal, deadline]) : deadline;
    let timer: ReturnType<typeof setTimeout> | undefined;
    // The signal aborts the request and the body stream; the timer is the
    // backstop that settles this call at the deadline whatever the stream does.
    const expired = new Promise<never>((_, reject) => {
      timer = setTimeout(
        () => reject(new RpcTransportRefusal(`${what} did not complete within ${timeoutMs} ms`)),
        timeoutMs + 50,
      );
    });
    const exchange = (async () => {
      let response: Response;
      try {
        response = await capturedFetch(input, { ...(init ?? {}), redirect: "error", signal });
      } catch (e) {
        if (deadline.aborted) throw new RpcTransportRefusal(`${what} did not complete within ${timeoutMs} ms`);
        throw e;
      }
      let body: Buffer;
      try {
        body = await readBytesBounded(response, maxBytes, what);
      } catch (e) {
        if (deadline.aborted && !(e instanceof RpcTransportRefusal)) {
          throw new RpcTransportRefusal(`${what} did not complete within ${timeoutMs} ms`);
        }
        throw e;
      }
      const noBody = response.status === 204 || response.status === 205 || response.status === 304;
      return new Response(noBody ? null : new Uint8Array(body), {
        status: response.status,
        statusText: response.statusText,
        headers: { "content-type": response.headers.get("content-type") ?? "application/json" },
      });
    })();
    exchange.catch(() => {});
    try {
      return await Promise.race([exchange, expired]);
    } finally {
      clearTimeout(timer);
    }
  };
}

/** The JSON-RPC method a request body names, for error messages. */
function methodOf(body: unknown): string {
  if (typeof body !== "string") return "a request";
  const m = /"method"\s*:\s*"([A-Za-z]{1,64})"/.exec(body);
  return m ? m[1] : "a request";
}

/**
 * A web3.js `Connection` whose every request goes through `boundedRpcFetch`,
 * that never retries a 429 behind the caller's back, and that opens no
 * websocket (Round 35, F-014).
 *
 * `confirmTransaction` keeps its signature and its answer (`{ context, value:
 * { err } }`, a failed transaction resolving with its error, an expired one
 * rejecting with web3.js's own expiry errors) but polls `getSignatureStatuses`
 * and `getBlockHeight` over HTTP. Every subscription method (`onSignature`,
 * `onAccountChange`, `onProgramAccountChange`, `onLogs`, `onSlotChange`,
 * `onSlotUpdate`, `onRootChange`, `onSignatureWithOptions`) goes through
 * web3.js's internal `_makeSubscription`, which is refused here before a
 * socket exists.
 */
export class BoundedConnection extends Connection {
  constructor(rpcUrl: string, opts: { timeoutMs?: number; maxBytes?: number } = {}) {
    super(rpcUrl, {
      commitment: "confirmed",
      fetch: boundedRpcFetch(rpcUrl, opts),
      disableRetryOnRateLimit: true,
      httpAgent: false,
    });
  }

  /** web3.js's one entry point for every websocket subscription: refused. */
  _makeSubscription(): never {
    throw new RpcTransportRefusal(
      "a websocket subscription on the guard's connection. The guard's transport rule covers the RPC's HTTP " +
        "endpoint only; poll over HTTP (getSignatureStatuses, confirmTransaction) or build your own Connection",
    );
  }

  confirmTransaction(
    strategy: TransactionConfirmationStrategy,
    commitment?: Commitment,
  ): Promise<RpcResponseAndContext<SignatureResult>>;
  /** @deprecated Instead, call `confirmTransaction` with a `TransactionConfirmationStrategy`. */
  confirmTransaction(
    strategy: TransactionSignature,
    commitment?: Commitment,
  ): Promise<RpcResponseAndContext<SignatureResult>>;
  async confirmTransaction(
    strategy: TransactionConfirmationStrategy | TransactionSignature,
    commitment?: Commitment,
  ): Promise<RpcResponseAndContext<SignatureResult>> {
    const signature = typeof strategy === "string" ? strategy : strategy.signature;
    const lastValidBlockHeight =
      typeof strategy === "object" && "lastValidBlockHeight" in strategy ? strategy.lastValidBlockHeight : undefined;
    const abortSignal = typeof strategy === "object" ? strategy.abortSignal : undefined;
    const wanted = commitment ?? this.commitment ?? "finalized";
    const started = Date.now();
    for (;;) {
      abortSignal?.throwIfAborted();
      const response = await this.getSignatureStatuses([signature]);
      const status = response.value[0];
      if (status) {
        if (status.err) return { context: response.context, value: { err: status.err } };
        const reached =
          status.confirmationStatus === "finalized" ||
          (status.confirmationStatus === "confirmed" && wanted !== "finalized" && wanted !== "max" && wanted !== "root") ||
          (status.confirmationStatus === "processed" && (wanted === "processed" || wanted === "recent"));
        if (reached) return { context: response.context, value: { err: null } };
      }
      if (lastValidBlockHeight !== undefined) {
        const height = await this.getBlockHeight(wanted === "finalized" ? "finalized" : "confirmed");
        if (height > lastValidBlockHeight) throw new TransactionExpiredBlockheightExceededError(signature);
      }
      if (Date.now() - started > CONFIRMATION_MAX_MS) {
        throw new TransactionExpiredTimeoutError(signature, CONFIRMATION_MAX_MS / 1000);
      }
      await new Promise((resolve) => setTimeout(resolve, CONFIRMATION_POLL_MS));
    }
  }
}
