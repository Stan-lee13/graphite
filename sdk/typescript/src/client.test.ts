/**
 * Round 19 (F-19-C6): the client refuses to send the API key, or to receive a
 * verdict, over plain HTTP to anything but the local machine.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { GraphiteClient, assertSecureBaseUrl, isLoopbackHost } from "./client.js";
import type { VerificationInput } from "./types.js";

test("plain http:// to a non-loopback host is refused before any request", () => {
  for (const baseUrl of [
    "http://graphite.internal:7331",
    "http://10.0.0.5:7331",
    "http://192.168.1.10",
    "http://128.0.0.1",
    "http://[::2]:7331",
    "http://localhost.evil.example",
    "http://127.0.0.1.nip.io",
  ]) {
    assert.throws(
      () => new GraphiteClient({ baseUrl, apiKey: "k".repeat(32) }),
      /plain http:\/\/ to a non-loopback host/,
      baseUrl,
    );
  }
});

test("https:// anywhere, and http:// to loopback, are accepted", () => {
  for (const baseUrl of [
    "https://graphite.internal",
    "https://10.0.0.5:7331/",
    "http://localhost:7331",
    "http://LOCALHOST:7331",
    "http://127.0.0.1:7331/",
    "http://127.255.255.254",
    "http://127.1:7331", // canonicalised by the URL parser to 127.0.0.1
    "http://[::1]:7331",
  ]) {
    assert.doesNotThrow(() => new GraphiteClient({ baseUrl }), baseUrl);
  }
  assert.equal(assertSecureBaseUrl("http://127.0.0.1:7331/"), "http://127.0.0.1:7331");
});

test("other schemes and garbage are refused", () => {
  for (const baseUrl of ["ftp://127.0.0.1", "ws://127.0.0.1:7331", "not a url", "", "127.0.0.1:7331"]) {
    assert.throws(() => new GraphiteClient({ baseUrl }), Error, baseUrl);
  }
});

test("isLoopbackHost compares canonical forms only", () => {
  assert.equal(isLoopbackHost("127.0.0.1"), true);
  assert.equal(isLoopbackHost("[::1]"), true);
  assert.equal(isLoopbackHost("localhost"), true);
  assert.equal(isLoopbackHost("127.0.0.256"), false);
  assert.equal(isLoopbackHost("127.0.0.1.example"), false);
  assert.equal(isLoopbackHost("0.0.0.0"), false);
});

// A5-04 (2026-09-29 audit): fetch followed redirects, and the transport check
// covers only the configured base URL — a 307 took the request to a location
// the check never saw, and the verdict from there was accepted. Loopback
// http:// on both ends, which the base-URL rule allows.
async function listen(handler: Parameters<typeof createServer>[1]): Promise<{ server: Server; url: string }> {
  const server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
}

test("a redirect from the Core is refused on every call, and its target is never contacted", async () => {
  let targetHits = 0;
  const target = await listen((_req, res) => {
    targetHits++;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        approved: true,
        confidence: 0.99,
        audit_trail_id: "gr-x",
        content_hash: "0123456789abcdef",
        risk_verdict: { status: "Clear", findings: [] },
        recorded: true,
      }),
    );
  });
  const redirector = await listen((req, res) => {
    req.resume();
    res.writeHead(307, { location: `${target.url}${req.url}` });
    res.end();
  });
  try {
    const client = new GraphiteClient({ baseUrl: redirector.url, apiKey: "k".repeat(32) });
    const refused = /redirects are refused/;
    await assert.rejects(client.verify({ program_id: "11111111111111111111111111111111" } as VerificationInput), refused);
    await assert.rejects(client.health(), refused);
    await assert.rejects(client.listManifests(), refused);
    await assert.rejects(client.recordLifecycleEvent({ event_type: "signing" } as never), refused);
    await assert.rejects(client.verifyExecution({} as never), refused);
    assert.equal(targetHits, 0, "the redirect target must never be contacted");
  } finally {
    for (const { server } of [target, redirector]) {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  }
});

// W22 (external review, Round 24): the result guard checked five fields and
// never the scope, so a verdict claiming `artifact_bound` with no digest, an
// unknown residual code, or `approved` beside a Blocked risk verdict reached
// the caller typed as a VerificationResult.
test("a verdict is checked on every field a caller decides on", async () => {
  const { readFileSync } = await import("node:fs");
  const { validateVerificationResult } = await import("./client.js");
  const sample = JSON.parse(
    readFileSync(new URL("../../../examples/sample-verification-result.json", import.meta.url), "utf8"),
  ) as Record<string, unknown>;
  assert.equal(validateVerificationResult(sample), null, "the committed sample is valid");
  const bound = {
    kind: "artifact_bound",
    transaction_sha256: "ab".repeat(32),
    transaction_bytes: 215,
    simulated: true,
    unobserved: ["program semantics", "inner instructions"],
    unobserved_codes: ["program_semantics", "inner_instructions"],
  };
  assert.equal(validateVerificationResult({ ...sample, scope: bound }), null, "a whole artifact-bound scope is valid");
  const refused: [string, Record<string, unknown>, RegExp][] = [
    ["approved beside Blocked", { approved: true, risk_verdict: { status: "Blocked", findings: [] } }, /Clear risk verdict/],
    ["an unknown risk status", { risk_verdict: { status: "Fine", findings: [] } }, /risk_verdict.status/],
    ["findings missing", { risk_verdict: { status: "Clear" } }, /findings/],
    ["confidence above 1", { confidence: 1.5 }, /\[0, 1\]/],
    ["an unknown tier", { trust_tier: "Trusted" }, /trust_tier/],
    ["a layer without a reason", { layers: [{ layer: "L1", passed: true }] }, /reason/],
    ["a binding without its digest", { scope: { ...bound, transaction_sha256: undefined } }, /transaction_sha256/],
    ["an uppercase digest", { scope: { ...bound, transaction_sha256: "AB".repeat(32) } }, /transaction_sha256/],
    ["zero bytes bound", { scope: { ...bound, transaction_bytes: 0 } }, /transaction_bytes/],
    ["simulated not said", { scope: { ...bound, simulated: "yes" } }, /simulated/],
    ["nothing unobserved", { scope: { ...bound, unobserved: [], unobserved_codes: [] } }, /non-empty/],
    ["an unknown residual code", { scope: { ...bound, unobserved_codes: ["program_semantics", "made_up"] } }, /unknown code/],
    ["codes that do not name each entry", { scope: { ...bound, unobserved_codes: ["program_semantics"] } }, /name each entry/],
    ["an unknown scope kind", { scope: { ...bound, kind: "bound" } }, /scope.kind/],
  ];
  for (const [what, change, reason] of refused) {
    const violation = validateVerificationResult({ ...sample, ...change });
    assert.ok(violation !== null && reason.test(violation), `${what}: ${violation}`);
  }
});
