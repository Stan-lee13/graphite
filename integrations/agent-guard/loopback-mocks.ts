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
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import bs58 from "bs58";
import { Keypair, VersionedTransaction } from "@solana/web3.js";
import { AuditBind } from "./auditbind.js";

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

/** An account as the stand-in RPC serves it. */
export interface MockAccount {
  lamports: number;
  owner: string;
  data?: Uint8Array;
}

/** An SPL Token account image: mint, owner, amount (the 165-byte base layout). */
export function tokenAccountData(mint: string, owner: string, amount: bigint): Uint8Array {
  const data = new Uint8Array(165);
  data.set(bs58.decode(mint), 0);
  data.set(bs58.decode(owner), 32);
  new DataView(data.buffer).setBigUint64(64, amount, true);
  return data;
}

const SPL_TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

/** The static account keys of a base64 legacy, v0 or v1 wire transaction. */
function staticKeysOf(wire: unknown): string[] {
  if (typeof wire !== "string") return [];
  const bytes = Buffer.from(wire, "base64");
  if (bytes[0] === 0x81) {
    // v1: prefix, header (3), config mask (u32), lifetime (32), instruction
    // count (u8), address count (u8), then the addresses (Round 32: the
    // stand-in reports v1 balances as an Agave RPC does).
    const at = 1 + 3 + 4 + 32;
    const count = bytes[at + 1] ?? 0;
    const keys: string[] = [];
    for (let k = 0; k < count; k++) keys.push(bs58.encode(bytes.subarray(at + 2 + 32 * k, at + 2 + 32 * (k + 1))));
    return keys;
  }
  return VersionedTransaction.deserialize(bytes).message.staticAccountKeys.map((k) => k.toBase58());
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
    /**
     * Accounts as the ledger holds them (getMultipleAccounts), and as a
     * simulation leaves them (simulateTransaction's `accounts`; an address
     * absent here keeps its ledger state). An address in neither does not exist.
     */
    ledger?: Record<string, MockAccount>;
    afterSimulation?: Record<string, MockAccount | null>;
    /** Decimals the simulation reports per mint (default 6). */
    decimals?: Record<string, number>;
    /** What getBlockHeight answers (default 1; blockhashes are valid to 1,000). */
    blockHeight?: number;
    /**
     * sendTransaction fails without saying whether the bytes went anywhere
     * (an HTTP 502), and — when "landed" — they did land anyway.
     */
    sendFails?: false | "lost" | "landed";
  } = {},
): Promise<MockRpc> {
  const encode = (a: MockAccount | null | undefined) =>
    a
      ? {
          lamports: a.lamports,
          owner: a.owner,
          data: [Buffer.from(a.data ?? new Uint8Array()).toString("base64"), "base64"],
          executable: false,
          rentEpoch: 0,
        }
      : null;
  const calls: RecordedCall[] = [];
  /** Signatures the stand-in reports as landed (confirmed). */
  const landed = new Set<string>();
  /** Mutable after start, so a test can change the RPC's behaviour mid-way. */
  const behaviour: MockRpc["behaviour"] = {
    sendFails: opts.sendFails ?? false,
    blockHeight: opts.blockHeight,
    statusesFail: false,
    acceptWithoutLanding: false,
    reportedSignature: undefined,
  };
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
        case "getMultipleAccounts": {
          const addresses = ((req as { params?: unknown[] }).params?.[0] ?? []) as string[];
          return ok({ context: { slot: 1 }, value: addresses.map((a) => encode(opts.ledger?.[a])) });
        }
        case "simulateTransaction": {
          const config = (req as { params?: unknown[] }).params?.[1] as
            | { accounts?: { addresses?: string[] } }
            | undefined;
          const requested = config?.accounts?.addresses;
          // As an Agave RPC answers: lamports and token balances of every
          // account the transaction references, before and after, from one run.
          const keys = staticKeysOf((req as { params?: unknown[] }).params?.[0]);
          const before = (k: string) => opts.ledger?.[k];
          const after = (k: string) =>
            opts.afterSimulation && k in opts.afterSimulation ? opts.afterSimulation[k] : opts.ledger?.[k];
          const tokenBalance = (state: (k: string) => MockAccount | null | undefined) =>
            keys.flatMap((k, accountIndex) => {
              const a = state(k);
              const data = a?.data;
              if (!a || a.owner !== SPL_TOKEN_PROGRAM || !data || data.length < 165) return [];
              const mint = bs58.encode(data.subarray(0, 32));
              const amount = new DataView(data.buffer, data.byteOffset).getBigUint64(64, true).toString();
              const decimals = opts.decimals?.[mint] ?? 6;
              return [{
                accountIndex,
                mint,
                owner: bs58.encode(data.subarray(32, 64)),
                programId: SPL_TOKEN_PROGRAM,
                uiTokenAmount: { amount, decimals, uiAmountString: amount },
              }];
            });
          return ok({
            context: { slot: 1 },
            value: {
              err: opts.simulationErr ?? null,
              logs: [
                "Program 11111111111111111111111111111111 invoke [1]",
                `Program 11111111111111111111111111111111 consumed ${opts.unitsConsumed ?? 150} of 200000 compute units`,
                "Program 11111111111111111111111111111111 success",
              ],
              accounts: requested
                ? requested.map((a) =>
                    encode(
                      opts.afterSimulation && a in opts.afterSimulation
                        ? opts.afterSimulation[a]
                        : opts.ledger?.[a],
                    ),
                  )
                : null,
              unitsConsumed: opts.unitsConsumed ?? 150,
              preBalances: keys.map((k) => before(k)?.lamports ?? 0),
              postBalances: keys.map((k) => after(k)?.lamports ?? 0),
              preTokenBalances: tokenBalance(before),
              postTokenBalances: tokenBalance(after),
              ...(opts.loadedAccountsDataSize === null
                ? {}
                : { loadedAccountsDataSize: opts.loadedAccountsDataSize ?? 2_048 }),
            },
          });
        }
        case "sendTransaction": {
          // A real RPC answers with the id the bytes carry.
          const wire = (req as { params?: unknown[] }).params?.[0];
          const id = typeof wire === "string" ? wireTransactionId(wire) : null;
          if (behaviour.sendFails) {
            if (behaviour.sendFails === "landed" && id) landed.add(id);
            return { status: 502, body: { error: "bad gateway" } };
          }
          if (id && !behaviour.acceptWithoutLanding) landed.add(id);
          return ok(behaviour.reportedSignature ?? id);
        }
        case "getSignatureStatuses": {
          if (behaviour.statusesFail) return { status: 503, body: { error: "unavailable" } };
          const sigs = ((req as { params?: unknown[] }).params?.[0] ?? []) as string[];
          return ok({
            context: { slot: 2 },
            value: sigs.map((s) =>
              landed.has(s) ? { slot: 2, confirmations: null, err: null, confirmationStatus: "confirmed" } : null,
            ),
          });
        }
        case "getBlockHeight":
          return ok(behaviour.blockHeight ?? 1);
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
  return { url, calls, landed, behaviour, close: closer(server) };
}

export interface MockRpc extends Loopback {
  /** Signatures reported as landed. */
  landed: Set<string>;
  /** Change what sendTransaction, getSignatureStatuses and getBlockHeight do from here on. */
  behaviour: {
    sendFails: false | "lost" | "landed";
    blockHeight?: number;
    /** getSignatureStatuses answers HTTP 503 (Round 30). */
    statusesFail: boolean;
    /** sendTransaction answers with the id, but the transaction never lands (Round 30). */
    acceptWithoutLanding: boolean;
    /** sendTransaction answers with this id instead of the bytes' own (Round 30). */
    reportedSignature?: string;
  };
}

export interface MockService extends Loopback {
  /** Replace the JSON answer for a route, e.g. `POST /parse`. */
  answer: Map<string, { status: number; body: unknown }>;
  /**
   * Answers computed from the request, by `METHOD /path`; consulted before
   * `answer`. Round 29: an approving Core must hash what it was sent.
   */
  respond: Map<string, (body: unknown) => { status: number; body: unknown }>;
}

/** A REST stand-in answering from `respond` / `answer` by `METHOD /path`; 404 otherwise. */
export async function mockService(initial: Record<string, unknown> = {}): Promise<MockService> {
  const calls: RecordedCall[] = [];
  const answer = new Map<string, { status: number; body: unknown }>(
    Object.entries(initial).map(([k, v]) => [k, { status: 200, body: v }]),
  );
  const respond = new Map<string, (body: unknown) => { status: number; body: unknown }>();
  const { server, url } = await listen(
    (method, path, body) =>
      respond.get(`${method} ${path}`)?.(body) ??
      answer.get(`${method} ${path}`) ?? { status: 404, body: { error: "not mocked" } },
    (c) => calls.push(c),
    (method, path) => `${method} ${path}`,
  );
  return { url, calls, answer, respond, close: closer(server) };
}

/**
 * An APPROVED, artifact-bound verdict for exactly the request the Core was
 * sent, as the Core would compute it (Round 29, audit 2026-10-20: no guard
 * test drove an approval through `executeTransfer` / `executeSwap`; the
 * stand-in only ever blocked). `transaction_sha256` is the SHA-256 of the
 * `signed_transaction` bytes and `content_hash` is the framed hash over
 * program, discriminator, accounts, data and CPI targets — the real digests,
 * so the guard's own checks (AuditBind, `signApproved`) run for real.
 */
export function approvedVerdictFor(
  request: unknown,
  opts: {
    auditTrailId?: string;
    unobservedCodes?: string[];
    /**
     * Round 30 (G-01): the Core's execution decision. Default: computed as
     * the Core computes it — `executable_approved` when every residual is
     * inherent, `analysis_only` otherwise. `null` leaves `decision` and
     * `executable` out, as a server that predates them does.
     */
    decision?: string | null;
    executable?: unknown;
  } = {},
): Record<string, unknown> {
  const r = request as {
    program_id: string;
    instruction_discriminator: string;
    account_addresses: string[];
    instruction_data?: number[];
    cpi_targets?: string[];
    signed_transaction: number[];
  };
  const bytes = Uint8Array.from(r.signed_transaction);
  const codes = opts.unobservedCodes ?? ["program_semantics", "inner_instructions"];
  const computed = codes.every((c) => c === "program_semantics" || c === "inner_instructions")
    ? "executable_approved"
    : "analysis_only";
  const decision = opts.decision === undefined ? computed : opts.decision;
  const contentHash = AuditBind.computeHash({
    programId: r.program_id,
    instructionDiscriminator: r.instruction_discriminator,
    accountAddresses: r.account_addresses,
    instructionData: r.instruction_data,
    cpiTargets: r.cpi_targets ?? [],
  });
  // The sample is a Round 30 verdict: drop its own decision fields and bind
  // key so a `decision: null` stand-in really is a server that predates them.
  const { decision: _d, executable: _e, instruction_bind_key: _k, ...base } = BLOCKED_VERDICT;
  return {
    ...base,
    ...(decision === null
      ? {}
      : {
          decision,
          executable: "executable" in opts ? opts.executable : decision === "executable_approved",
          instruction_bind_key: contentHash,
        }),
    approved: true,
    confidence: 0.64,
    risk_verdict: { status: "Clear", findings: [] },
    policy_verdict: "Approved",
    audit_trail_id: opts.auditTrailId ?? "gr-loopback-00000001",
    content_hash: contentHash,
    // An approval has no failed layer: the sample's L6 policy refusal passes.
    layers: (base.layers as Array<Record<string, unknown>>).map((l) =>
      l.status === "failed" ? { ...l, passed: true, status: "passed", reason: "Policy: Approved (loopback)" } : l,
    ),
    summary: "APPROVED (loopback stand-in)",
    scope: {
      kind: "artifact_bound",
      transaction_sha256: createHash("sha256").update(bytes).digest("hex"),
      transaction_bytes: bytes.length,
      simulated: true,
      unobserved: codes.map((c) => `loopback: ${c}`),
      unobserved_codes: codes,
    },
  };
}

/**
 * A Graphite Core stand-in that APPROVES what it is sent (artifact-bound,
 * real digests), records the lifecycle (`/audit/event` answers "approved" by
 * the exact audit_trail_id) and reconciles L8 as `ApprovedAndExecuted`.
 */
export async function mockApprovingCore(
  verdict: Omit<NonNullable<Parameters<typeof approvedVerdictFor>[1]>, "auditTrailId"> = {},
): Promise<MockService> {
  const core = await mockService({ "GET /health": { status: "ok", service: "graphite", version: "test" } });
  let n = 0;
  core.respond.set("POST /verify", (body) => ({
    status: 200,
    body: approvedVerdictFor(body, { ...verdict, auditTrailId: `gr-loopback-${String(++n).padStart(8, "0")}` }),
  }));
  core.respond.set("POST /audit/event", (body) => {
    const e = body as { event_type: string; content_hash: string };
    return {
      status: 200,
      body: {
        recorded: true,
        event_type: e.event_type,
        content_hash: e.content_hash,
        verdict_on_record: "approved",
        verdict_on_record_key: "audit_trail_id",
        sequence_anomalies: [],
      },
    };
  });
  core.respond.set("POST /verify/execution", (body) => {
    const e = body as { signature: string; transaction_sha256?: string; audit_trail_id?: string };
    return {
      status: 200,
      body: {
        signature: e.signature,
        chain_status: {
          Confirmed: { signature: e.signature, slot: 1, success: true, error: null, commitment: "finalized" },
        },
        recorded_approved: true,
        recorded_audit_trail_id: e.audit_trail_id ?? null,
        reconciliation: "ApprovedAndExecuted",
        discrepancy: false,
        recorded_transaction_sha256: e.transaction_sha256 ?? null,
        // What the Core serialises for `ExecutionAttribution::Chain`.
        attribution: "chain",
        chain_transaction_sha256: e.transaction_sha256 ?? null,
        caller_keys_disagree: [],
        audit_recorded: true,
      },
    };
  });
  return core;
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

/**
 * A wallet generated for one test and never funded: its secret key in the
 * base58 form the guard's `privateKey` takes, and its address. Lets an
 * adapter's tests build a guard without depending on @solana/web3.js
 * themselves.
 */
export function throwawayWallet(): { secretKeyBase58: string; publicKey: string } {
  const kp = Keypair.generate();
  return { secretKeyBase58: bs58.encode(kp.secretKey), publicKey: kp.publicKey.toBase58() };
}
