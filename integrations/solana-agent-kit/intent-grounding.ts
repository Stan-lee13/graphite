/**
 * Ground a parsed transfer in the words the user actually wrote.
 *
 * Round 19 (F-19-C5). `executeTransfer` took the destination and the amount
 * from the AI layer's HTTP response and sent that same response to the Core as
 * `proposed_intent`. The Core's intent check compares the transaction against
 * the proposed intent — and both had come out of one untrusted response. An AI
 * layer that is wrong, compromised, or simply answering from a different
 * request could name any destination and any amount, and the transaction built
 * from its answer would align perfectly with the intent built from the same
 * answer. The check was circular.
 *
 * The fix is deterministic and involves no model: the AI's answer is accepted
 * only where it can be checked against the user's own text, character for
 * character.
 *
 *   - The destination must be the ONE address-shaped token in the input. Not
 *     a substring (a prefix of a longer string is a different address), and
 *     not one of two (an AI that picks the other address out of "send to A,
 *     not B" would pass a presence check).
 *   - The amount must be the ONE numeric literal in the input, and the AI's
 *     amount string must equal it exactly. It is converted to lamports by
 *     decimal arithmetic on the string, never through a float.
 *   - The token must be SOL, and "SOL" must be a word in the input. A System
 *     transfer moves lamports; "send 5 USDC" labelled as a transfer used to
 *     move 5 SOL.
 *   - The AI layer's echoed `raw_natural_language` must be exactly what was
 *     sent (`assertEcho`), so a response to some other request is refused.
 *
 * Ambiguity refuses. The user can always rephrase; a transfer to the wrong
 * address cannot be taken back.
 */

import { SWAP_PROGRAM_IDS } from "./swap-programs.js";

/** An ed25519 public key is 32 bytes: 32–44 base58 characters. */
const ADDRESS_SHAPE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
/** A run of base58 long enough to be taken for an address. */
const ADDRESS_LENGTH_RUN = /[1-9A-HJ-NP-Za-km-z]{32,}/;
/**
 * Sentence punctuation a word may end with. Only this is stripped, and only
 * from the end: "to <address>." is an address followed by a full stop.
 */
const TRAILING_PUNCTUATION = /[.,;:!?)\]"'`]+$/;
/**
 * Quoting a word may begin with: "(<address>)", "\"<address>\"" and
 * "`<address>`" are the address, quoted. Only this is stripped, and only from
 * the start (review of the 2026-09-29 audit's fix, F12: a quoted address was
 * refused).
 */
const LEADING_QUOTING = /^[(\["'`]+/;
/**
 * A number standing on its own: not glued to letters or digits on either
 * side (so the digits inside an address never count), with an optional
 * fraction. A trailing sentence full stop is allowed; a trailing ".5" is part
 * of the number.
 */
const NUMERIC_LITERAL = /(?<![0-9A-Za-z.])\d+(?:\.\d+)?(?![0-9A-Za-z]|\.\d)/g;

const LAMPORTS_PER_SOL = 1_000_000_000n;
const U64_MAX = (1n << 64n) - 1n;

export class IntentGroundingError extends Error {
  constructor(message: string) {
    super(
      `[Graphite] ${message} The AI layer's reading of the request is only accepted where it ` +
        `matches the request's own text (Round 19, F-19-C5). REFUSING.`,
    );
    this.name = "IntentGroundingError";
  }
}

export interface GroundedTransfer {
  /** Base58, exactly as it appears in the user's text. */
  destination: string;
  /** The amount literal, exactly as it appears in the user's text. */
  amountText: string;
  /** `amountText` SOL in lamports, computed without floating point. */
  lamports: bigint;
}

/** The AI layer's echo of the text it parsed must be the text that was sent. */
export function assertEcho(sent: string, echoed: unknown): void {
  if (typeof echoed !== "string" || echoed !== sent) {
    throw new IntentGroundingError(
      "The AI layer's raw_natural_language is not the text that was sent to it, so its answer " +
        "is not an answer to this request.",
    );
  }
}

/**
 * The address-shaped words of the input, exactly as written.
 *
 * A5-02 (2026-09-29 audit): this used to collect base58 RUNS, so any
 * non-base58 character split a word — the digit 0, a Cyrillic homoglyph, a
 * '-', '.' or '_'. Typed as the last character of a 44-character address it
 * left a 43-character run, which was then "the one address in the request",
 * and a 43-character prefix of a key usually decodes to a valid key nobody
 * holds. The Python parser stopped at the same character, so the two agreed.
 *
 * Words are split on whitespace instead, and only trailing sentence
 * punctuation and leading quoting ("(", "[", quotes, a backtick) are
 * stripped. A word that carries an address-length base58 run
 * but is not itself address-shaped is refused, not trimmed into one.
 */
function addressTokens(input: string): string[] {
  const addresses: string[] = [];
  for (const word of input.split(/\s+/)) {
    const token = word.replace(TRAILING_PUNCTUATION, "").replace(LEADING_QUOTING, "");
    if (ADDRESS_SHAPE.test(token)) {
      addresses.push(token);
    } else if (ADDRESS_LENGTH_RUN.test(token)) {
      throw new IntentGroundingError(
        `${JSON.stringify(word)} contains an address-length base58 run but is not an address as ` +
          "written; a part of it is a different address.",
      );
    }
  }
  return addresses;
}

/** Parse a decimal SOL literal into lamports, exactly. */
export function solLiteralToLamports(text: string): bigint {
  const m = /^(\d+)(?:\.(\d+))?$/.exec(text);
  if (!m) {
    throw new IntentGroundingError(`The amount "${text}" is not a decimal number.`);
  }
  const fraction = m[2] ?? "";
  if (fraction.length > 9) {
    throw new IntentGroundingError(
      `The amount "${text}" has more than 9 decimal places; a lamport is 10^-9 SOL.`,
    );
  }
  const lamports = BigInt(m[1]) * LAMPORTS_PER_SOL + BigInt(fraction.padEnd(9, "0") || "0");
  if (lamports === 0n) {
    throw new IntentGroundingError(`The amount "${text}" is zero.`);
  }
  if (lamports > U64_MAX) {
    throw new IntentGroundingError(`The amount "${text}" does not fit in a u64 of lamports.`);
  }
  return lamports;
}

/**
 * Check the AI layer's transfer parameters against the user's input and
 * return the values to build the transaction from. Throws on any doubt.
 */
export function groundTransferIntent(
  input: string,
  params:
    | { amount?: unknown; destination?: unknown; input_token?: unknown }
    | undefined,
): GroundedTransfer {
  const destination = params?.destination;
  if (typeof destination !== "string" || !ADDRESS_SHAPE.test(destination)) {
    throw new IntentGroundingError("The transfer has no well-formed destination address.");
  }
  const addresses = addressTokens(input);
  const distinct = [...new Set(addresses)];
  if (distinct.length !== 1) {
    throw new IntentGroundingError(
      `The request contains ${distinct.length} address-shaped tokens; a transfer is only built ` +
        "when it names exactly one.",
    );
  }
  if (distinct[0] !== destination) {
    throw new IntentGroundingError(
      `The destination ${destination} does not appear in the request as written.`,
    );
  }

  const amountText = params?.amount;
  if (typeof amountText !== "string") {
    throw new IntentGroundingError("The transfer has no amount.");
  }
  const numbers = [...new Set(input.match(NUMERIC_LITERAL) ?? [])].filter(
    (n) => !distinct.includes(n),
  );
  if (numbers.length !== 1) {
    throw new IntentGroundingError(
      `The request contains ${numbers.length} distinct numbers; a transfer is only built when ` +
        "it names exactly one amount.",
    );
  }
  if (numbers[0] !== amountText) {
    throw new IntentGroundingError(
      `The amount "${amountText}" does not appear in the request as written.`,
    );
  }
  const lamports = solLiteralToLamports(amountText);

  const token = params?.input_token;
  if (typeof token !== "string" || token.toUpperCase() !== "SOL") {
    throw new IntentGroundingError(
      `A System transfer moves SOL; the parsed token is ${JSON.stringify(token ?? null)}.`,
    );
  }
  if (!/(?<![0-9A-Za-z])SOL(?![0-9A-Za-z])/i.test(input)) {
    throw new IntentGroundingError("The request does not name SOL as the token to transfer.");
  }

  return { destination, amountText, lamports };
}

/** A verb that asks for a swap, as a whole word (the AI layer's own vocabulary). */
// The base verb only, as the Python parser reads it: "Swapping is fun" is
// talk about swapping, not a request for one, and a request refused here is
// one the user can rephrase. The two sides must agree on what a swap
// request is (review F12 considered and kept this).
const SWAP_VERB = /(?<![0-9A-Za-z])(?:swap|trade|exchange|convert|sell|buy)(?![0-9A-Za-z])/i;
/** The labels the Core reads as the swap class (`risk_engine::canonical_intent`). */
const SWAP_CLASS_LABELS: ReadonlySet<string> = new Set(["swap", "trade", "exchange"]);

/**
 * Decide the intent class of a swap from the method and the user's text, never
 * from the AI layer's label, and refuse a payload for a program that does not
 * swap. Returns the `intent_type` to send: always `"swap"`.
 *
 * A5-01 (2026-09-29 audit): `executeSwap` forwarded the AI layer's
 * `intent_type` to the Core unchanged. The Core's intent-mismatch checks
 * (CloseAccount, Create/Allocate, Approve, and the program-supports-intent
 * check) fire when the transaction does something other than the declared
 * intent — so the untrusted label decided whether they fired. An AI layer
 * answering `approve` to "Swap 1 SOL for USDC" switched off the Approve check
 * for an Approve payload. The method defines the class; the text must ask for
 * it; the AI's label, when it gives one, must agree; and the program must be
 * one the Core treats as a swap program (`swap-programs.ts`).
 */
export function groundSwapIntent(input: string, aiIntentType: unknown, programId: unknown): "swap" {
  if (!SWAP_VERB.test(input)) {
    throw new IntentGroundingError(
      "The request does not ask for a swap: none of swap / trade / exchange / convert / sell / " +
        "buy appears in it as a word.",
    );
  }
  if (aiIntentType !== undefined && aiIntentType !== null && aiIntentType !== "") {
    if (typeof aiIntentType !== "string" || !SWAP_CLASS_LABELS.has(aiIntentType)) {
      throw new IntentGroundingError(
        `The AI layer labelled a swap request as ${JSON.stringify(aiIntentType)}; a swap is only ` +
          "built when every reading of the request agrees it is one.",
      );
    }
  }
  if (typeof programId !== "string" || !SWAP_PROGRAM_IDS.has(programId)) {
    throw new IntentGroundingError(
      `The swap payload is addressed to ${JSON.stringify(programId ?? null)}, which no seed ` +
        "manifest tags as a swap program; a swap is only built against a program that swaps.",
    );
  }
  return "swap";
}
