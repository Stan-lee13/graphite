// Round 30: a change of Core clears the previous Core's numbers, and a late
// answer from the previous Core is dropped. Run: npm test.
import { test } from "node:test";
import assert from "node:assert/strict";
import { initialPoll, pollReducer, type PollState } from "./poll-state.ts";

type S = PollState<string, string>;

test("a change of connection clears the old Core's payload, error and time", () => {
  let s: S = initialPoll();
  s = pollReducer(s, { type: "ok", epoch: 0, value: "core A: 37 verifications", at: 1000 });
  s = pollReducer(s, { type: "fail", epoch: 0, error: "429" });
  assert.equal(s.data, "core A: 37 verifications", "a transient failure keeps the last good data");
  s = pollReducer(s, { type: "connection-changed", epoch: 1 });
  assert.deepEqual(s, { data: null, error: null, loading: true, updatedAt: null, epoch: 1 });
});

test("an answer fetched under the old connection is not shown as the new Core's", () => {
  let s: S = pollReducer(initialPoll(), { type: "connection-changed", epoch: 3 });
  s = pollReducer(s, { type: "ok", epoch: 2, value: "core A", at: 5 });
  assert.equal(s.data, null);
  s = pollReducer(s, { type: "fail", epoch: 2, error: "old core down" });
  assert.equal(s.error, null);
  assert.equal(s.loading, true);
  s = pollReducer(s, { type: "ok", epoch: 3, value: "core B", at: 9 });
  assert.equal(s.data, "core B");
  assert.equal(s.updatedAt, 9);
});

test("the same epoch again is not a reset", () => {
  let s: S = pollReducer(initialPoll(), { type: "ok", epoch: 0, value: "x", at: 1 });
  s = pollReducer(s, { type: "connection-changed", epoch: 0 });
  assert.equal(s.data, "x");
});
