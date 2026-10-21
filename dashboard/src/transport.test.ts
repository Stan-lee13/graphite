// Round 19 (F-19-C6): the console refuses to send the operator key over
// plain http:// to another machine. Run: npm test.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { fetchFromCore, insecureBaseReason, isLoopbackHost } from "./transport.ts";

const LOCAL_PAGE = "http://127.0.0.1:5173";

test("plain http:// to another machine is refused", () => {
  for (const base of [
    "http://graphite.internal:7331",
    "http://10.0.0.5:7331",
    "http://128.0.0.1",
    "http://[::2]:7331",
    "http://localhost.evil.example",
  ]) {
    assert.match(insecureBaseReason(base, LOCAL_PAGE) ?? "", /plain http:\/\/ to another machine/, base);
  }
});

test("https:// anywhere and http:// on this machine are allowed", () => {
  for (const base of [
    "https://graphite.example",
    "http://localhost:7331",
    "http://127.0.0.1:7331",
    "http://127.1:7331",
  ]) {
    assert.equal(insecureBaseReason(base, LOCAL_PAGE), null, base);
  }
});

// Round 30: the built console's CSP cannot name an IPv6 literal or a
// 127.0.0.0/8 range, so these were let through here and then blocked by the
// browser as "No response". They are refused before sending, with the reason.
test("loopback addresses the CSP cannot name are refused with the reason", () => {
  for (const base of ["http://[::1]:7331", "http://127.0.0.2:7331"]) {
    assert.match(insecureBaseReason(base, LOCAL_PAGE) ?? "", /Content-Security-Policy can only name/, base);
  }
  // ...unless it is the build-time Core, which the CSP names explicitly.
  assert.equal(insecureBaseReason("http://127.0.0.2:7331", LOCAL_PAGE, "http://127.0.0.2:7331"), null);
  // Same origin is 'self', whatever the address the console is served from.
  assert.equal(insecureBaseReason("", "http://[::1]:5173"), null);
  // https:// to an IPv6 loopback is the CSP's https: scheme source.
  assert.equal(insecureBaseReason("https://[::1]:7331", LOCAL_PAGE), null);
});

test("an empty base means same origin, and the page's own origin is what is checked", () => {
  assert.equal(insecureBaseReason("", "http://localhost:5173"), null);
  assert.equal(insecureBaseReason("", "https://console.example"), null);
  assert.match(insecureBaseReason("", "http://192.168.1.20:7331") ?? "", /another machine/);
});

test("non-http schemes and garbage are refused", () => {
  assert.notEqual(insecureBaseReason("ftp://127.0.0.1", LOCAL_PAGE), null);
  assert.notEqual(insecureBaseReason("not a url", LOCAL_PAGE), null);
  assert.equal(isLoopbackHost("127.0.0.256"), false);
});

// A5-04 (2026-09-29 audit): fetch followed redirects, so a 307 took the
// console's request somewhere the transport rule never checked. Loopback on
// both ends; the target must never be contacted.
test("a redirect from the Core is a failed request, and its target is never contacted", async () => {
  let targetHits = 0;
  const target = createServer((_req, res) => {
    targetHits++;
    res.writeHead(200, { "content-type": "application/json" });
    res.end("{}");
  });
  const redirector = createServer((req, res) => {
    res.writeHead(307, { location: `http://127.0.0.1:${(target.address() as AddressInfo).port}${req.url}` });
    res.end();
  });
  for (const server of [target, redirector]) {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  }
  try {
    const base = `http://127.0.0.1:${(redirector.address() as AddressInfo).port}`;
    await assert.rejects(fetchFromCore(`${base}/graph`, { Authorization: "Bearer " + "k".repeat(32) }));
    assert.equal(targetHits, 0);
  } finally {
    for (const server of [target, redirector]) {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  }
});

// Round 29 (audit 2026-10-20, D3): a Core that accepts the connection and
// never answers used to hold the request — and with it the view's polling
// loop — forever. Both the header wait and a stalled body are bounded.
test("a Core that never answers is abandoned after the deadline", async () => {
  const silent = createServer(() => {
    /* accept, never answer */
  });
  const stalled = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.write('{"partial":');
    /* never end the body */
  });
  for (const server of [silent, stalled]) {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  }
  try {
    for (const server of [silent, stalled]) {
      const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api/graph`;
      const started = Date.now();
      await assert.rejects(fetchFromCore(url, {}, 200));
      assert.ok(Date.now() - started < 5_000, "the deadline, not the socket, ended the request");
    }
  } finally {
    for (const server of [silent, stalled]) {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  }
});

test("the whole body comes back with the status", async () => {
  const server = createServer((_req, res) => {
    res.writeHead(418, { "content-type": "text/plain" });
    res.end("short and stout");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const resp = await fetchFromCore(`http://127.0.0.1:${(server.address() as AddressInfo).port}/`, {});
    assert.deepEqual(resp, { ok: false, status: 418, text: "short and stout" });
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

// Round 29 (audit 2026-10-20, D7): an empty base on a page with no web
// origin (file:// gives "null") said `"" is not a URL`.
test("an empty base on a page with no origin names the real problem", () => {
  const why = insecureBaseReason("", "null") ?? "";
  assert.doesNotMatch(why, /"" is not a URL/);
  assert.match(why, /no web origin/);
  assert.match(insecureBaseReason("nope", LOCAL_PAGE) ?? "", /"nope" is not a URL/);
});
