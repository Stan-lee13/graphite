/**
 * A5-07 (2026-09-30 audit): the dev scripts skipped the transport rules and
 * printed part of the RPC URL.
 *
 *   - `devnet-test.ts` verified with a raw `fetch` carrying the API key to
 *     `GRAPHITE_URL`, a name nothing else reads (the F-19-C6 pattern again),
 *     with no transport rule and no shape check on the verdict.
 *   - both scripts printed the first 45 / 50 characters of the RPC URL, which
 *     for a `…/?api-key=` provider URL includes part of the key.
 *
 * The scripts need a live Core and RPC to run, so their shape is pinned here
 * from the source, next to unit tests of the helpers they now use.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { assertNoLegacyEnvNames, rpcHostForLog } from "./env-names.js";

test("A5-07: the legacy GRAPHITE_URL name is refused without GRAPHITE_CORE_URL", () => {
  assert.throws(
    () => assertNoLegacyEnvNames({ GRAPHITE_URL: "http://127.0.0.1:7331" }),
    /GRAPHITE_URL is set but the bridge reads GRAPHITE_CORE_URL/,
  );
  assert.doesNotThrow(() =>
    assertNoLegacyEnvNames({ GRAPHITE_URL: "http://127.0.0.1:1", GRAPHITE_CORE_URL: "http://127.0.0.1:7331" }),
  );
  assert.doesNotThrow(() => assertNoLegacyEnvNames({ GRAPHITE_CORE_URL: "http://127.0.0.1:7331" }));
});

test("A5-07: an RPC URL is logged as its host only", () => {
  const secret = "0123456789abcdef-not-a-real-key";
  for (const url of [
    `https://mainnet.helius-rpc.example/?api-key=${secret}`,
    `https://user:${secret}@rpc.example:8443/v1/${secret}`,
    `https://rpc.example/${secret}`,
  ]) {
    const logged = rpcHostForLog(url);
    assert.ok(!logged.includes(secret.slice(0, 5)), `${logged} carries part of the credential`);
  }
  assert.equal(rpcHostForLog(`https://mainnet.helius-rpc.example/?api-key=${secret}`), "mainnet.helius-rpc.example");
  assert.equal(rpcHostForLog("http://127.0.0.1:8899"), "127.0.0.1:8899");
  assert.equal(rpcHostForLog(`not a url ${secret}`), "(unparseable RPC URL)");
});

test("A5-07: the dev scripts reach the Core only through GraphiteClient and never print the RPC URL", () => {
  for (const script of ["devnet-test.ts", "mainnet-benchmark.ts"]) {
    const src = readFileSync(new URL(script, import.meta.url), "utf8");
    assert.doesNotMatch(src, /\bfetch\(/, `${script}: a raw fetch bypasses the SDK's transport rule`);
    assert.doesNotMatch(src, /Bearer \$\{/, `${script}: builds its own Authorization header`);
    assert.doesNotMatch(src, /process\.env\.GRAPHITE_URL\b/, `${script}: reads the legacy GRAPHITE_URL`);
    assert.doesNotMatch(
      src,
      /\b(?:rpcUrl|RPC_URL)\s*\.\s*(?:slice|substring|substr)\(/,
      `${script}: prints a slice of the RPC URL`,
    );
    assert.match(src, /new GraphiteClient\(/, `${script}: must verify through GraphiteClient`);
    assert.match(src, /GRAPHITE_CORE_URL/, `${script}: must read GRAPHITE_CORE_URL`);
    assert.match(src, /assertNoLegacyEnvNames\(\)/, `${script}: must refuse the legacy names`);
    assert.match(src, /rpcHostForLog\(/, `${script}: must log the RPC host only`);
  }
});
