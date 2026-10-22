/**
 * Round 32 (R-M10): the lifecycle requests carry the instruction-level key
 * under its Round 30 name, `instruction_bind_key`, and under `content_hash`,
 * the name every earlier Core requires — the same value under both, so every
 * Core reads one key. Two different values are refused before anything is
 * sent. Loopback servers only.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { GraphiteClient, validateLifecycleEventReceipt, withInstructionBindKey } from "./client.js";

const KEY = "48c65c638aceb5de";
const SIGNATURE = "5".repeat(88);
const RECEIPT = {
  recorded: true,
  event_type: "signing",
  content_hash: KEY,
  verdict_on_record: "approved",
  verdict_on_record_key: "content_hash",
};
const EXECUTION = {
  signature: SIGNATURE,
  chain_status: { Unavailable: "no RPC" },
  recorded_approved: null,
  recorded_audit_trail_id: null,
  recorded_transaction_sha256: null,
  reconciliation: { Unavailable: "no RPC" },
  discrepancy: false,
  attribution: "none",
  chain_transaction_sha256: null,
  caller_keys_disagree: [],
  recorded_verdicts: { approved: 0, refused: 0 },
  audit_recorded: true,
};

async function core(): Promise<{ client: GraphiteClient; bodies: Record<string, unknown>[]; close(): Promise<void> }> {
  const bodies: Record<string, unknown>[] = [];
  const server = createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      bodies.push(JSON.parse(raw) as Record<string, unknown>);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(req.url === "/audit/event" ? RECEIPT : EXECUTION));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    client: new GraphiteClient({ baseUrl: `http://127.0.0.1:${port}`, apiKey: "k".repeat(32) }),
    bodies,
    close: () => {
      server.closeAllConnections();
      return new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

test("either name in, both names out, the same key", async () => {
  const c = await core();
  try {
    await c.client.recordLifecycleEvent({ event_type: "signing", instruction_bind_key: KEY });
    await c.client.recordLifecycleEvent({ event_type: "signing", content_hash: KEY });
    await c.client.recordLifecycleEvent({ event_type: "signing", content_hash: KEY, instruction_bind_key: KEY });
    await c.client.verifyExecution({ signature: SIGNATURE, instruction_bind_key: KEY });
    assert.equal(c.bodies.length, 4);
    for (const b of c.bodies) {
      assert.equal(b.instruction_bind_key, KEY, JSON.stringify(b));
      assert.equal(b.content_hash, KEY, JSON.stringify(b));
    }
    // No key on an execution check is still no key: nothing is invented.
    await c.client.verifyExecution({ signature: SIGNATURE });
    assert.equal("instruction_bind_key" in c.bodies[4], false);
    assert.equal("content_hash" in c.bodies[4], false);
  } finally {
    await c.close();
  }
});

test("two different values under the two names are refused before anything is sent", async () => {
  const c = await core();
  try {
    const differ = /same key under two names/;
    await assert.rejects(
      c.client.recordLifecycleEvent({ event_type: "signing", content_hash: KEY, instruction_bind_key: "0".repeat(16) }),
      differ,
    );
    await assert.rejects(
      c.client.verifyExecution({ signature: SIGNATURE, content_hash: KEY, instruction_bind_key: "0".repeat(16) }),
      differ,
    );
    assert.equal(c.bodies.length, 0, "nothing reached the Core");
    assert.throws(() => withInstructionBindKey({ content_hash: "a".repeat(16), instruction_bind_key: "b".repeat(16) }), differ);
  } finally {
    await c.close();
  }
});

test("the receipt is held to the key sent under the new name", () => {
  const sent = { event_type: "signing" as const, instruction_bind_key: KEY };
  assert.equal(validateLifecycleEventReceipt(RECEIPT, sent), null);
  assert.match(
    validateLifecycleEventReceipt({ ...RECEIPT, content_hash: "0".repeat(16) }, sent) ?? "",
    /different instruction key/,
  );
});
