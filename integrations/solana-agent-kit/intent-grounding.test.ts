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
  groundSwapIntent,
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

// A5-02 (2026-09-30 audit): a non-base58 character inside or at the end of a
// typed address split it into base58 runs, and the address-shaped prefix was
// taken as "the one address in the request". The Python parser stopped at the
// same character, so both sides agreed on an address the user never wrote.
const FULL = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";

test("A5-02: an address with a stray character is refused, never grounded to its prefix", () => {
  assert.equal(FULL.length, 44);
  const cases: Array<[typed: string, prefixTheParserSaw: string]> = [
    [FULL.slice(0, 43) + "0", FULL.slice(0, 43)], // digit zero for the letter o
    [FULL.slice(0, 43) + "А", FULL.slice(0, 43)], // Cyrillic A
    [FULL.slice(0, 43) + "-", FULL.slice(0, 43)],
    [FULL.slice(0, 40) + "." + FULL.slice(40), FULL.slice(0, 40)],
    [FULL.slice(0, 40) + "_" + FULL.slice(40), FULL.slice(0, 40)],
    [FULL.slice(0, 43) + "0.", FULL.slice(0, 43)], // a full stop after the typo changes nothing
  ];
  for (const [typed, prefix] of cases) {
    assert.throws(
      () =>
        groundTransferIntent(`Send 1 SOL to ${typed}`, {
          amount: "1",
          destination: prefix,
          input_token: "SOL",
        }),
      (e: unknown) => e instanceof IntentGroundingError && /not an address as written/.test(e.message),
      `${JSON.stringify(typed)} must be refused, not grounded to ${prefix}`,
    );
  }
});

test("A5-02: trailing sentence punctuation after an address is still just punctuation", () => {
  for (const tail of [".", ",", "!", "?", ";", ":", ")", "]", '"', "'", ").", '".']) {
    const g = groundTransferIntent(`Send 1 SOL to ${FULL}${tail}`, {
      amount: "1",
      destination: FULL,
      input_token: "SOL",
    });
    assert.equal(g.destination, FULL, `tail ${JSON.stringify(tail)}`);
  }
});

// A5-01 (2026-09-30 audit): the swap path forwarded the AI layer's label to
// the Core unchanged, and the Core's intent-mismatch checks are keyed on it.
const JUPITER_V6 = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
const SPL_TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

test("A5-01: a swap's class comes from the method and the user's text, not the AI label", () => {
  for (const text of ["Swap 1 SOL for USDC", "trade 5 USDC to SOL", "Exchange 1 SOL into BONK",
    "convert 2 SOL to USDC", "Sell 3 JUP for USDC", "buy 1 SOL with USDC"]) {
    for (const label of ["swap", "trade", "exchange", undefined, null, ""]) {
      assert.equal(groundSwapIntent(text, label, JUPITER_V6), "swap", `${text} / ${label}`);
    }
  }
});

test("A5-01: an AI label outside the swap class is refused", () => {
  for (const label of ["approve", "close", "create", "transfer", "revoke", "stake", "unknown", "Swap", 7, {}]) {
    assert.throws(
      () => groundSwapIntent("Swap 1 SOL for USDC", label, JUPITER_V6),
      (e: unknown) => e instanceof IntentGroundingError && /labelled a swap request/.test(e.message),
      JSON.stringify(label),
    );
  }
});

test("A5-01: a request that does not ask for a swap is refused, whatever the AI says", () => {
  for (const text of ["Send 1 SOL for USDC", "Approve USDC", "Swapping is fun", "Close my account"]) {
    assert.throws(
      () => groundSwapIntent(text, "swap", JUPITER_V6),
      (e: unknown) => e instanceof IntentGroundingError && /does not ask for a swap/.test(e.message),
      text,
    );
  }
});

test("A5-01: a swap payload for a program that does not swap is refused", () => {
  for (const programId of [SPL_TOKEN, "11111111111111111111111111111111", "", undefined, 42]) {
    assert.throws(
      () => groundSwapIntent("Swap 1 SOL for USDC", "swap", programId),
      (e: unknown) => e instanceof IntentGroundingError && /no seed manifest tags as a swap program/.test(e.message),
      String(programId),
    );
  }
});
