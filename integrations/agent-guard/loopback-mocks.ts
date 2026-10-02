/**
 * Loopback HTTP stand-ins for the three services the bridge talks to — a
 * Solana JSON-RPC endpoint, a Graphite Core, and the Python AI layer — for
 * tests only. Every server binds 127.0.0.1 on an ephemeral port; nothing here
 * reaches a public RPC or moves real funds.
 *
 * The RPC stand-in records every call with its decoded parameters, and for the
 * two methods that carry a transaction (`simulateTransaction`,
 * `sendTransaction`) it records whether any signature slot was filled. That is
 * the observable the Round 19 F-19-C1 tests are about: a signed transaction
 * reaching an RPC before a verdict exists.
 */
import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import bs58 from "bs58";

export interface RecordedCall {
  /** JSON-RPC method, or `METHOD /path` for the REST stand-ins. */
  method: string;
  params: unknown;
  /** Monotonic across every stand-in in the process, so calls can be ordered. */
  seq: number;
  /** For transaction-carrying RPC calls: was any signature slot non-zero? */
  signed?: boolean;
}

let seq = 0;

export interface Loopback {
  url: string;
  calls: RecordedCall[];
  close(): Promise<void>;
}

async function listen(
  handler: (method: string, path: string, body: unknown) => { status: number; body: unknown },
  record: (call: RecordedCall) => void,
  name: (method: string, path: string, body: unknown) => string,
  extract?: (body: unknown) => Omit<RecordedCall, "seq" | "method">,
): Promise<{ server: Server; url: string }> {
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const text = Buffer.concat(chunks).toString("utf8");
      let body: unknown = undefined;
      try {
        body = text ? JSON.parse(text) : undefined;
      } catch {
        body = text;
      }
      const path = req.url ?? "/";
      const method = req.method ?? "GET";
      record({
        method: name(method, path, body),
        params: body,
        seq: ++seq,
        ...(extract ? extract(body) : {}),
      });
      const out = handler(method, path, body);
      res.writeHead(out.status, { "content-type": "application/json" });
      res.end(JSON.stringify(out.body));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return { server, url: `http://127.0.0.1:${port}` };
}

function closer(server: Server): () => Promise<void> {
  return () =>
    new Promise<void>((resolve) => {
      server.closeAllConnections();
      server.close(() => resolve());
    });
}

/**
 * The signature slots of a wire transaction, read independently of the code
 * under test. Legacy and v0: a compact-u16 count (at most 3 bytes), then
 * `count` 64-byte slots. v1 (first byte 0x81): the header's first byte is the
 * signer count, and the slots are the frame's last `count × 64` bytes.
 */
function signatureSlots(wire: Buffer): Buffer {
  if (wire[0] === 0x81) {
    const count = wire[1];
    return wire.subarray(wire.length - count * 64);
  }
  let count = 0;
  let offset = 0;
  for (let shift = 0; shift < 21; shift += 7) {
    const b = wire[offset++];
    count |= (b & 0x7f) << shift;
    if ((b & 0x80) === 0) break;
  }
  return wire.subarray(offset, offset + count * 64);
}

/** Every signature slot of a base64 wire transaction: is any of them filled? */
export function wireHasAnySignature(base64: string): boolean {
  return signatureSlots(Buffer.from(base64, "base64")).some((b) => b !== 0);
}

/** What an RPC answers to sendTransaction: the transaction's id, its first signature. */
export function wireTransactionId(base64: string): string {
  return bs58.encode(signatureSlots(Buffer.from(base64, "base64")).subarray(0, 64));
}

/** A blockhash the stand-in hands out — 32 bytes of 0x07, base58. */
export const MOCK_BLOCKHASH = bs58.encode(new Uint8Array(32).fill(7));

export async function mockRpc(
  opts: {
    unitsConsumed?: number;
    /** What simulateTransaction reports as `loadedAccountsDataSize`; null leaves the field out. */
    loadedAccountsDataSize?: number | null;
    /** A simulation error to report instead of success. */
    simulationErr?: unknown;
  } = {},
): Promise<Loopback> {
  const calls: RecordedCall[] = [];
  const { server, url } = await listen(
    (_m, _p, body) => {
      const req = body as { id?: unknown; method?: string };
      const ok = (result: unknown) => ({
        status: 200,
        body: { jsonrpc: "2.0", id: req?.id ?? null, result },
      });
      switch (req?.method) {
        case "getLatestBlockhash":
          return ok({ context: { slot: 1 }, value: { blockhash: MOCK_BLOCKHASH, lastValidBlockHeight: 1_000 } });
        case "simulateTransaction":
          return ok({
            context: { slot: 1 },
            value: {
              err: opts.simulationErr ?? null,
              logs: [
                "Program 11111111111111111111111111111111 invoke [1]",
                `Program 11111111111111111111111111111111 consumed ${opts.unitsConsumed ?? 150} of 200000 compute units`,
                "Program 11111111111111111111111111111111 success",
              ],
              accounts: null,
              unitsConsumed: opts.unitsConsumed ?? 150,
              ...(opts.loadedAccountsDataSize === null
                ? {}
                : { loadedAccountsDataSize: opts.loadedAccountsDataSize ?? 2_048 }),
            },
          });
        case "sendTransaction": {
          // A real RPC answers with the id the bytes carry.
          const wire = (req as { params?: unknown[] }).params?.[0];
          return ok(typeof wire === "string" ? wireTransactionId(wire) : null);
        }
        default:
          return {
            status: 200,
            body: { jsonrpc: "2.0", id: req?.id ?? null, error: { code: -32601, message: "not mocked" } },
          };
      }
    },
    (c) => calls.push(c),
    (_m, _p, body) => (body as { method?: string })?.method ?? "?",
    (body) => {
      const b = body as { method?: string; params?: unknown[] };
      if (b?.method === "simulateTransaction" || b?.method === "sendTransaction") {
        const wire = b.params?.[0];
        return { params: b, signed: typeof wire === "string" ? wireHasAnySignature(wire) : true };
      }
      return { params: b };
    },
  );
  return { url, calls, close: closer(server) };
}

export interface MockService extends Loopback {
  /** Replace the JSON answer for a route, e.g. `POST /parse`. */
  answer: Map<string, { status: number; body: unknown }>;
}

/** A REST stand-in answering from `answer` by `METHOD /path`; 404 otherwise. */
export async function mockService(initial: Record<string, unknown> = {}): Promise<MockService> {
  const calls: RecordedCall[] = [];
  const answer = new Map<string, { status: number; body: unknown }>(
    Object.entries(initial).map(([k, v]) => [k, { status: 200, body: v }]),
  );
  const { server, url } = await listen(
    (method, path) => answer.get(`${method} ${path}`) ?? { status: 404, body: { error: "not mocked" } },
    (c) => calls.push(c),
    (method, path) => `${method} ${path}`,
  );
  return { url, calls, answer, close: closer(server) };
}

/**
 * A verdict that does not approve, exactly as the Core emits one: the
 * repository's `examples/sample-verification-result.json`, which
 * `graphite-core/tests/verification_result_schema_contract.rs` holds to
 * `schemas/verification-result-v1.json`. A stand-in that answered with a shape
 * the Core never sends would let the code under test depend on that shape.
 */
export const BLOCKED_VERDICT: Record<string, unknown> = JSON.parse(
  readFileSync(new URL("../../examples/sample-verification-result.json", import.meta.url), "utf8"),
);
