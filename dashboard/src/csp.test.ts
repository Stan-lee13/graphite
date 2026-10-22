// Round 29 (audit 2026-10-20, D6): the production build carries a CSP that
// runs only the console's own bundle and connects only where transport.ts
// would send the key. Run: npm test.
import { test } from "node:test";
import assert from "node:assert/strict";
import { LOOPBACK_HTTP, contentSecurityPolicy, securityHeaders } from "./csp.ts";
import { CSP_LOOPBACK_HOSTS } from "./transport.ts";

const directives = (csp: string) =>
  new Map(
    csp.split(";").map((d) => {
      const [name, ...values] = d.trim().split(/\s+/);
      return [name, values] as const;
    }),
  );

test("scripts come from the console's own origin only", () => {
  const d = directives(contentSecurityPolicy());
  assert.deepEqual(d.get("script-src"), ["'self'"]);
  assert.deepEqual(d.get("default-src"), ["'none'"]);
  assert.deepEqual(d.get("object-src"), ["'none'"]);
  assert.deepEqual(d.get("base-uri"), ["'none'"]);
  for (const [name, values] of d) {
    for (const v of values) {
      assert.ok(!/unsafe-(inline|eval)/.test(v), `${name} must not allow ${v}`);
      assert.notEqual(v, "*", `${name} must not be a wildcard`);
    }
  }
});

test("connect-src allows what the transport rule allows, and no more", () => {
  const connect = directives(contentSecurityPolicy()).get("connect-src") ?? [];
  assert.ok(connect.includes("'self'"));
  assert.ok(connect.includes("https:"), "a Core on any https:// origin");
  for (const host of CSP_LOOPBACK_HOSTS) {
    assert.ok(connect.includes(`http://${host}:*`), host);
  }
  assert.ok(!connect.includes("http:"), "plain http:// to other machines stays closed");
  // Round 30: an IPv6 literal is not a valid CSP host source (Chrome logs
  // an error and ignores it); nothing in the policy may be one.
  assert.ok(!connect.some((s) => s.includes("[")), "no IPv6 literal in connect-src");
  assert.deepEqual(LOOPBACK_HTTP, CSP_LOOPBACK_HOSTS.map((h) => `http://${h}:*`), "csp.ts and transport.ts agree");
});

test("a build-time default Core on loopback http is allowed; junk is ignored", () => {
  const withApi = directives(contentSecurityPolicy("http://127.0.0.2:7331/api")).get("connect-src") ?? [];
  assert.ok(withApi.includes("http://127.0.0.2:7331"));
  assert.equal(contentSecurityPolicy("not a url"), contentSecurityPolicy());
  assert.equal(contentSecurityPolicy("https://core.example/api"), contentSecurityPolicy(), "already covered by https:");
});

// Round 30: what a <meta> CSP cannot do, the served headers do.
test("the served headers forbid framing and sniffing, and keep the meta policy", () => {
  const h = securityHeaders();
  assert.equal(h["Content-Security-Policy"], `${contentSecurityPolicy()}; frame-ancestors 'none'`);
  assert.equal(h["X-Frame-Options"], "DENY");
  assert.equal(h["X-Content-Type-Options"], "nosniff");
  assert.equal(h["Referrer-Policy"], "no-referrer");
});
