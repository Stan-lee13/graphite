/**
 * Real-server conformance for the TypeScript SDK.
 *
 * The existing suite is hermetic and tests the client against its own idea of
 * the protocol. That cannot catch the failure that actually breaks an
 * integration: the SDK and the Rust server disagreeing about a field name, a
 * type, or what a verdict means. This one talks to a running Graphite.
 *
 *   GRAPHITE_URL=http://127.0.0.1:7331 GRAPHITE_API_KEY=... npm test
 *
 * Skipped when GRAPHITE_URL is unset, so `npm test` stays offline by default.
 */
import { test, skip } from "node:test";
import assert from "node:assert/strict";
import { GraphiteClient } from "./client.js";
import { computeContentHash } from "./auditbind.js";
import type { VerificationInput } from "./types.js";

const URL = process.env.GRAPHITE_URL;
const KEY = process.env.GRAPHITE_API_KEY;

function client() {
  return new GraphiteClient({ baseUrl: URL!, apiKey: KEY });
}

function transfer(destination: string): VerificationInput {
  return {
    proposed_intent: {
      intent_type: "transfer",
      raw_natural_language: "send SOL",
      confidence_of_parse: 0.95,
    },
    program_id: "11111111111111111111111111111111",
    protocol_version: "1.0.0",
    instruction_discriminator: "02000000",
    account_addresses: [
      "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
      destination,
    ],
    wallet_profile: "Gaming",
    compute_units: 150,
    account_writes: 2,
    cpi_hops: 0,
  } as VerificationInput;
}

const live = URL ? test : skip;

live("a verdict deserializes with every field the gate needs", async () => {
  const r = await client().verify(
    transfer("8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"),
  );
  assert.ok(r.content_hash, "content_hash is required for AuditBind");
  assert.ok(r.audit_trail_id, "audit_trail_id missing");
  assert.equal(r.layers?.length, 8, "all eight layers must be reported");
  assert.ok(typeof r.confidence === "number" && r.confidence > 0);
  // The invariant the schema calls load-bearing: these two can never disagree.
  assert.equal(
    r.policy_verdict === "Approved",
    r.approved,
    `policy_verdict ${r.policy_verdict} contradicts approved=${r.approved}`,
  );
});

live("a BLOCK survives the round trip as a block, not an error", async () => {
  // Unspendable destination: the System Program itself.
  const r = await client().verify(transfer("11111111111111111111111111111111"));
  assert.equal(r.approved, false, "the server blocks this; the SDK reported approved");
  assert.equal(r.risk_verdict.status, "Blocked");
  assert.ok(
    r.risk_verdict.findings.some((f) => f.pattern === "UnspendableDestination"),
    `risk findings did not deserialize: ${JSON.stringify(r.risk_verdict.findings)}`,
  );
});

live("AuditBind reproduces the server's content_hash", async () => {
  const input = transfer("8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR");
  const r = await client().verify(input);
  const local = computeContentHash({
    programId: input.program_id,
    instructionDiscriminator: input.instruction_discriminator,
    accountAddresses: input.account_addresses,
  });
  assert.equal(
    local,
    r.content_hash,
    "cross-language hash mismatch — the TOCTOU check would abort on every legitimate transaction",
  );
});

live("an unauthenticated client is rejected by a keyed server", async () => {
  if (!KEY) return;
  const anon = new GraphiteClient({ baseUrl: URL! });
  await assert.rejects(
    () => anon.verify(transfer("8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR")),
    "an unauthenticated verify succeeded against a keyed server",
  );
});
