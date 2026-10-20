// Round 29 (audit 2026-10-20, D6): the production build carries a CSP that
// runs only the console's own bundle and connects only where transport.ts
// would send the key. Run: npm test.
import { test } from "node:test";
import assert from "node:assert/strict";
import { contentSecurityPolicy } from "./csp.ts";

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
  for (const loopback of ["http://localhost:*", "http://127.0.0.1:*", "http://[::1]:*"]) {
    assert.ok(connect.includes(loopback), loopback);
  }
  assert.ok(!connect.includes("http:"), "plain http:// to other machines stays closed");
});

test("a build-time default Core on loopback http is allowed; junk is ignored", () => {
  const withApi = directives(contentSecurityPolicy("http://127.0.0.2:7331/api")).get("connect-src") ?? [];
  assert.ok(withApi.includes("http://127.0.0.2:7331"));
  assert.equal(contentSecurityPolicy("not a url"), contentSecurityPolicy());
  assert.equal(contentSecurityPolicy("https://core.example/api"), contentSecurityPolicy(), "already covered by https:");
});
