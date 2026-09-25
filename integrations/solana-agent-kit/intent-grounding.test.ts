/**
 * Round 19 (F-19-C5): the AI layer's reading of a transfer is accepted only
 * where it matches the user's own text.
 *
 * Before, destination and amount came from the AI layer's response alone and
 * the same response was sent to the Core as `proposed_intent`, so the Core's
 * transaction-versus-intent check compared one untrusted answer with itself.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  assertEcho,
  groundTransferIntent,
  IntentGroundingError,
  solLiteralToLamports,
} from "./intent-grounding.js";

const DEST = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
const OTHER = "6bSsP4p6wXqFJdD2TkYgNcVmLzHfWq7pRyA8tCzE5nBj";

test("a transfer the user wrote is grounded to exactly what they wrote", () => {
  const input = `Transfer 1.5 SOL to ${DEST}`;
  const g = groundTransferIntent(input, { amount: "1.5", destination: DEST, input_token: "SOL" });
  assert.deepEqual(g, { destination: DEST, amountText: "1.5", lamports: 1_500_000_000n });
  // A sentence full stop after the address, and a lowercase token, are fine.
  const g2 = groundTransferIntent(`send 2 sol to ${DEST}.`, { amount: "2", destination: DEST, input_token: "sol" });
  assert.equal(g2.lamports, 2_000_000_000n);
});

test("a destination the user did not write is refused", () => {
  assert.throws(
    () => groundTransferIntent(`Transfer 1 SOL to ${DEST}`, { amount: "1", destination: OTHER, input_token: "SOL" }),
    IntentGroundingError,
  );
  // A prefix of the written address is a different address.
  assert.throws(
    () =>
      groundTransferIntent(`Transfer 1 SOL to ${DEST}`, {
        amount: "1",
        destination: DEST.slice(0, 40),
        input_token: "SOL",
      }),
    IntentGroundingError,
  );
  // Two addresses in the text: picking either is a guess, so neither is taken.
  assert.throws(
    () =>
      groundTransferIntent(`Transfer 1 SOL to ${DEST}, not ${OTHER}`, {
        amount: "1",
        destination: OTHER,
        input_token: "SOL",
      }),
    /2 address-shaped tokens/,
  );
});

test("an amount the user did not write is refused, including digits inside the address", () => {
  const input = `Transfer 1 SOL to ${DEST}`;
  for (const amount of ["100", "1.0", "01", "all", "", "8"]) {
    assert.throws(
      () => groundTransferIntent(input, { amount, destination: DEST, input_token: "SOL" }),
      IntentGroundingError,
      `amount ${JSON.stringify(amount)} must be refused`,
    );
  }
  // Two numbers: the AI choosing the other one would pass a presence check.
  assert.throws(
    () =>
      groundTransferIntent(`Transfer 1 SOL to ${DEST} and keep 5 for fees`, {
        amount: "5",
        destination: DEST,
        input_token: "SOL",
      }),
    /2 distinct numbers/,
  );
});

test("only SOL moves through a System transfer", () => {
  assert.throws(
    () => groundTransferIntent(`Send 5 USDC to ${DEST}`, { amount: "5", destination: DEST, input_token: "USDC" }),
    /moves SOL/,
  );
  // The AI saying SOL does not make the user have said it.
  assert.throws(
    () => groundTransferIntent(`Send 5 USDC to ${DEST}`, { amount: "5", destination: DEST, input_token: "SOL" }),
    /does not name SOL/,
  );
  assert.throws(
    () => groundTransferIntent(`Send 5 WSOL to ${DEST}`, { amount: "5", destination: DEST, input_token: "SOL" }),
    /does not name SOL/,
  );
});

test("lamports are computed on the decimal string, never through a float", () => {
  assert.equal(solLiteralToLamports("0.000000001"), 1n);
  assert.equal(solLiteralToLamports("1.1"), 1_100_000_000n);
  assert.equal(solLiteralToLamports("18446744073.709551615"), (1n << 64n) - 1n);
  assert.throws(() => solLiteralToLamports("18446744073.709551616"), /u64/);
  assert.throws(() => solLiteralToLamports("0.0000000001"), /9 decimal places/);
  assert.throws(() => solLiteralToLamports("0"), /zero/);
  assert.throws(() => solLiteralToLamports("1e9"), /not a decimal/);
});

test("the AI layer's echo must be the text that was sent", () => {
  assert.doesNotThrow(() => assertEcho("Transfer 1 SOL", "Transfer 1 SOL"));
  assert.throws(() => assertEcho("Transfer 1 SOL", "Transfer 10 SOL"), IntentGroundingError);
  assert.throws(() => assertEcho("Transfer 1 SOL", undefined), IntentGroundingError);
  assert.throws(() => assertEcho("Transfer 1 SOL", " Transfer 1 SOL"), IntentGroundingError);
});
