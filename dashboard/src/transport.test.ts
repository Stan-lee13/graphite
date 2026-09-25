// Round 19 (F-19-C6): the console refuses to send the operator key over
// plain http:// to another machine. Run: npm test.
import { test } from "node:test";
import assert from "node:assert/strict";
import { insecureBaseReason, isLoopbackHost } from "./transport.ts";

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
    "http://[::1]:7331",
  ]) {
    assert.equal(insecureBaseReason(base, LOCAL_PAGE), null, base);
  }
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
