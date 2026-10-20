/**
 * The operator's spending limits: read strictly from the environment, and
 * enforced on exactly the grounded amount and destination.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  assertSpendPolicyUsable,
  assertTransferAllowed,
  describeSpendPolicy,
  SpendLedger,
  spendPolicyFromEnv,
  SpendPolicyRefusal,
} from "./spend-policy.js";

const A = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
const B = "6bSsP4p6wXqFJdD2TkYgNcVmLzHfWq7pRyA8tCzE5nBj";

test("unset variables mean no limit; set ones are read exactly", () => {
  assert.deepEqual(spendPolicyFromEnv({}), {});
  assert.deepEqual(spendPolicyFromEnv({ GRAPHITE_MAX_TRANSFER_LAMPORTS: "1500000000" }), {
    maxTransferLamports: 1_500_000_000n,
  });
  assert.deepEqual(spendPolicyFromEnv({ GRAPHITE_ALLOWED_DESTINATIONS: ` ${A}, ${B} ` }), {
    allowedDestinations: [A, B],
  });
  // Set but empty: no destination is allowed — never read as "any".
  assert.deepEqual(spendPolicyFromEnv({ GRAPHITE_ALLOWED_DESTINATIONS: "" }), { allowedDestinations: [] });
});

test("a malformed limit refuses to start rather than being absent", () => {
  for (const v of ["1.5", "-1", "1e9", "0x10", "ten", "1 000"]) {
    assert.throws(() => spendPolicyFromEnv({ GRAPHITE_MAX_TRANSFER_LAMPORTS: v }), /REFUSING TO START/, v);
  }
  assert.throws(() => spendPolicyFromEnv({ GRAPHITE_ALLOWED_DESTINATIONS: `${A},not-an-address` }), /REFUSING TO START/);
});

test("the cap and the allowlist bound the grounded transfer, inclusively", () => {
  const policy = { maxTransferLamports: 1_000n, allowedDestinations: [A] };
  assert.doesNotThrow(() => assertTransferAllowed(policy, A, 1_000n));
  assert.throws(() => assertTransferAllowed(policy, A, 1_001n), SpendPolicyRefusal);
  assert.throws(() => assertTransferAllowed(policy, B, 1n), SpendPolicyRefusal);
  assert.throws(() => assertTransferAllowed({ allowedDestinations: [] }, A, 1n), SpendPolicyRefusal);
  assert.doesNotThrow(() => assertTransferAllowed({}, B, 10n ** 18n), "no policy, no limit");
});

// Round 29 (audit 2026-10-20, M6): a cap is required unless uncapped is
// accepted by name; the policy is stated at startup; an aggregate limit
// bounds a rolling window.

test("M6: no cap refuses to start unless GRAPHITE_ALLOW_UNCAPPED=1", () => {
  assert.throws(() => assertSpendPolicyUsable(spendPolicyFromEnv({})), /no per-transaction cap is set/);
  assert.throws(() => assertSpendPolicyUsable({ allowedDestinations: [A] }), /no per-transaction cap is set/);
  assert.doesNotThrow(() => assertSpendPolicyUsable({ maxTransferLamports: 1n }));
  const uncapped = spendPolicyFromEnv({ GRAPHITE_ALLOW_UNCAPPED: "1" });
  assert.deepEqual(uncapped, { allowUncapped: true });
  assert.doesNotThrow(() => assertSpendPolicyUsable(uncapped));
  assert.deepEqual(spendPolicyFromEnv({ GRAPHITE_ALLOW_UNCAPPED: "0" }), {});
  assert.throws(() => spendPolicyFromEnv({ GRAPHITE_ALLOW_UNCAPPED: "yes" }), /REFUSING TO START/);
  assert.match(describeSpendPolicy(uncapped), /ACCEPTED RISK \(GRAPHITE_ALLOW_UNCAPPED=1\): NO per-transaction cap/);
  assert.match(describeSpendPolicy({ maxTransferLamports: 5n }), /at most 5 lamports per transaction; no aggregate limit; any transfer destination/);
});

test("M6: the aggregate window is read strictly", () => {
  assert.deepEqual(spendPolicyFromEnv({ GRAPHITE_MAX_TOTAL_LAMPORTS: "10", GRAPHITE_SPEND_WINDOW_SECONDS: "60" }), {
    maxTotalLamports: 10n,
    spendWindowSeconds: 60,
  });
  assert.throws(() => spendPolicyFromEnv({ GRAPHITE_SPEND_WINDOW_SECONDS: "60" }), /without GRAPHITE_MAX_TOTAL_LAMPORTS/);
  for (const bad of ["0", "-1", "1.5", "x"]) {
    assert.throws(() => spendPolicyFromEnv({ GRAPHITE_MAX_TOTAL_LAMPORTS: "1", GRAPHITE_SPEND_WINDOW_SECONDS: bad }), /REFUSING TO START/, bad);
  }
  assert.throws(() => spendPolicyFromEnv({ GRAPHITE_MAX_TOTAL_LAMPORTS: "1.5" }), /REFUSING TO START/);
  assert.match(describeSpendPolicy({ maxTransferLamports: 1n, maxTotalLamports: 10n }), /at most 10 lamports per 3600 s/);
});

test("M6: the ledger reserves synchronously, keeps what was sent, returns what was not, and forgets the past window", () => {
  let now = 1_000_000;
  const ledger = new SpendLedger({ maxTotalLamports: 10n, spendWindowSeconds: 60 }, () => now);
  const a = ledger.reserve(6n);
  // A concurrent request cannot fit under the same allowance.
  assert.throws(() => ledger.reserve(5n), SpendPolicyRefusal);
  a.release();
  const b = ledger.reserve(6n);
  b.commit();
  b.release(); // no effect after commit
  assert.equal(ledger.spentInWindow(), 6n);
  assert.throws(() => ledger.reserve(5n), /above the aggregate limit of 10/);
  assert.doesNotThrow(() => ledger.reserve(4n).commit());
  now += 61_000;
  assert.equal(ledger.spentInWindow(), 0n, "outside the window");
  assert.doesNotThrow(() => ledger.reserve(10n));
  // No aggregate configured: nothing is ever refused.
  assert.doesNotThrow(() => new SpendLedger({}).reserve(10n ** 20n));
});
