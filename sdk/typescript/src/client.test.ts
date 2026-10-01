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
