// Round 19 (F-19-C6): a malformed escape in the hash must not throw out of
// the router. Run: npm test (node --test with type stripping; no extra
// dependency).
import { test } from "node:test";
import assert from "node:assert/strict";
import { hrefFor, parseHash } from "./router.ts";

test("a malformed percent-escape is treated as no program, not an exception", () => {
  for (const hash of ["#/programs/%", "#/programs/%E0%A4%A", "#/graph/%zz", "#/programs/abc%"]) {
    let route;
    assert.doesNotThrow(() => {
      route = parseHash(hash);
    }, hash);
    assert.deepEqual(route, { view: hash.startsWith("#/graph") ? "graph" : "programs" }, hash);
  }
});

test("well-formed routes still round-trip", () => {
  const id = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
  assert.deepEqual(parseHash(hrefFor("programs", id)), { view: "programs", program: id });
  assert.deepEqual(parseHash(hrefFor("graph", "a/b c%")), { view: "graph", program: "a/b c%" });
  assert.deepEqual(parseHash("#/nowhere"), { view: "overview" });
  assert.deepEqual(parseHash(""), { view: "overview" });
});
