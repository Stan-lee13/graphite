/**
 * Round 19 (F-19-C6): the client refuses to send the API key, or to receive a
 * verdict, over plain HTTP to anything but the local machine.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { GraphiteClient, assertSecureBaseUrl, isLoopbackHost } from "./client.js";

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
