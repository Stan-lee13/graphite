/**
 * The operator's spending limits: read strictly from the environment, and
 * enforced on exactly the grounded amount and destination.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { assertTransferAllowed, spendPolicyFromEnv, SpendPolicyRefusal } from "./spend-policy.js";

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
