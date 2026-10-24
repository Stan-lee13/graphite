/**
 * Round 34 (G-6): a response with a key twice in one object is refused.
 *
 * `JSON.parse` keeps the LAST of two equal keys, silently, so
 * `{"approved": false, …, "approved": true}` read as an approval here while
 * the Go SDK, which refuses duplicate keys (`sdk/go/validate.go`), refused the
 * same bytes. Two readers of one response must not see two verdicts in it.
 * Loopback servers only.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { GraphiteClient, readJsonBounded } from "./client.js";
import type { VerificationInput } from "./types.js";

const SAMPLE = JSON.parse(
  readFileSync(new URL("../../../examples/sample-verification-result.json", import.meta.url), "utf8"),
) as Record<string, unknown>;

/** An executable approval the validator accepts (as in responses.test.ts). */
const APPROVED: Record<string, unknown> = {
  ...SAMPLE,
  approved: true,
  policy_verdict: "Approved",
  risk_verdict: { status: "Clear", findings: [] },
  scope: {
    kind: "artifact_bound",
    transaction_sha256: "ab".repeat(32),
    transaction_bytes: 215,
    simulated: true,
    unobserved: ["program semantics", "inner instructions"],
    unobserved_codes: ["program_semantics", "inner_instructions"],
  },
  layers: (SAMPLE.layers as Array<Record<string, unknown>>).map((l) =>
    l.status === "failed" ? { ...l, status: "passed", passed: true } : l,
  ),
  decision: "executable_approved",
  executable: true,
};

const body = (text: string) => new Response(text);
const DUPLICATE = /duplicate key/;

test("duplicate keys: the second `approved` does not overrule the first — the response is refused", async () => {
  const text = `{"approved":false,${JSON.stringify(APPROVED).slice(1)}`;
  // What JSON.parse makes of it: the later `true` wins.
  assert.equal((JSON.parse(text) as { approved: boolean }).approved, true);
  await assert.rejects(readJsonBounded(body(text), 1 << 20), (e: unknown) => {
    assert.match((e as Error).message, DUPLICATE);
    assert.match((e as Error).message, /"approved"/);
    return true;
  });
});

test("duplicate keys: at any depth, inside arrays, and spelled with escapes", async () => {
  for (const text of [
    '{"scope":{"kind":"descriptive","kind":"artifact_bound"}}',
    '{"layers":[{"status":"failed","x":1,"status":"passed"}]}',
    '[[{"a":1,"b":{"c":[{"d":1,"d":2}]}}]]',
    '{"approved":false,"appr\\u006fved":true}',
    '{"a":1,"a":1}',
    '{"":1,"":2}',
  ]) {
    await assert.rejects(readJsonBounded(body(text), 1 << 20), DUPLICATE, text);
  }
});

test("duplicate keys (controls): one key per object parses exactly as JSON.parse does", async () => {
  for (const text of [
    '{"a":{"a":{"a":1}}}',
    '[{"a":1},{"a":2}]',
    '{"a":1,"A":2,"a ":3}',
    '{"s":"{\\"a\\":1,\\"a\\":2}","t":["\\"","\\\\"]}',
    '{"n":-1.5e-3,"t":true,"f":false,"z":null,"e":{},"l":[]}',
    '  "just a string"  ',
    "42",
    JSON.stringify(APPROVED),
  ]) {
    assert.deepEqual(await readJsonBounded(body(text), 1 << 20), JSON.parse(text), text);
  }
  // Malformed JSON is still JSON.parse's SyntaxError.
  await assert.rejects(readJsonBounded(body('{"a":1,'), 100), SyntaxError);
});

test("duplicate keys: verify() refuses a Core answer that says approved twice, differently", async () => {
  const answers = new Map<string, string>([["POST /verify", `{"approved":false,${JSON.stringify(APPROVED).slice(1)}`]]);
  const server: Server = createServer((req, res) => {
    req.resume();
    res.writeHead(200, { "content-type": "application/json" });
    res.end(answers.get(`${req.method} ${req.url}`) ?? "{}");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const client = new GraphiteClient({ baseUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}` });
  const input = { program_id: "11111111111111111111111111111111" } as VerificationInput;
  try {
    await assert.rejects(client.verify(input), DUPLICATE);
    // The control: the same verdict, each key once, is accepted.
    answers.set("POST /verify", JSON.stringify(APPROVED));
    assert.equal((await client.verify(input)).approved, true);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
