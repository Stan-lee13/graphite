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

/**
 * A word that negates, cancels or withholds the request (external review,
 * 2026-10-16). "Don't send 5 SOL to <address>" has one address, one amount and
 * the word SOL, and every other check accepted it: grounding established WHAT
 * the request names, never that the user asked for it. A request that carries
 * any of these words is refused, not interpreted. It costs a rephrase ("Send
 * 1 SOL to A, not B" already refused for its two addresses); guessing which
 * half of a negated sentence the user meant costs funds.
 */
const NEGATION =
  /(?<![0-9A-Za-z])(?:not|no|never|don'?t|dont|do\s+not|won'?t|shouldn'?t|mustn'?t|cancel(?:s|led|ling)?|stop|abort|undo|instead)(?![0-9A-Za-z])|n['\u2019]t(?![0-9A-Za-z])/i;

/** Refuse a request that negates, cancels or withholds what it names. */
export function assertAffirmative(input: string): void {
  const m = NEGATION.exec(input);
  if (m) {
    throw new IntentGroundingError(
      `The request contains ${JSON.stringify(m[0])}, which negates or cancels what it names; a ` +
        "transaction is only built for a request that plainly asks for it.",
    );
  }
}

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
  assertAffirmative(input);

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
  assertAffirmative(input);
  return "swap";
}

// ---------------------------------------------------------------------------
// What a swap is asked to do, and whether the transaction does it.
//
// External review (2026-10-16): `groundSwapIntent` established that the
// request asks for A swap, on a swap program — not THIS swap. "Swap 1 SOL for
// USDC" signed a route that spent 100 SOL, or bought BONK, or spent USDT,
// whenever the Core found the route itself well-formed; the operator's cap
// bounded the loss but did not tie it to the request. The amount and the two
// tokens are now read from the user's text, checked against the AI layer's
// reading, and compared with what the exact transaction does to the wallet
// in a simulation of its bytes.

/**
 * Symbols the guard resolves without a mint address, each checked against
 * Jupiter's verified token list on 2026-10-16 (USDC and USDT also appear in
 * this repository's own mainnet fixtures). Any other token is named by its
 * mint address in the request. A symbol is never resolved by asking anyone.
 */
export const KNOWN_TOKEN_MINTS: Readonly<Record<string, string>> = {
  SOL: "So11111111111111111111111111111111111111112",
  WSOL: "So11111111111111111111111111111111111111112",
  USDC: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
  USDT: "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
  JUP: "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN",
  BONK: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263",
  MSOL: "mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So",
  JITOSOL: "J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn",
};
/** Native SOL and wrapped SOL are one asset to a wallet. */
export const NATIVE_MINT = "So11111111111111111111111111111111111111112";

/** A token as the request names it: its mint, and the word the user wrote. */
export interface NamedToken {
  mint: string;
  written: string;
}

export interface GroundedSwap {
  /** The amount literal, exactly as the user wrote it. */
  amountText: string;
  /** What is spent: `amountText` of this token. */
  input: NamedToken;
  /** What must arrive. */
  output: NamedToken;
}

/** A token word: a symbol of 2-10 letters and digits, or a mint address. */
const TOKEN_WORD = "([A-Za-z][A-Za-z0-9]{1,9}|[1-9A-HJ-NP-Za-km-z]{32,44})";
const AMOUNT = "(\\d+(?:\\.\\d+)?)";
/** "swap 1 SOL for USDC" — the amount is what is spent. */
const SPEND_FIRST = new RegExp(
  `(?<![0-9A-Za-z])(?:swap|trade|exchange|convert|sell)\\s+${AMOUNT}\\s+${TOKEN_WORD}\\s+(?:for|to|into)\\s+${TOKEN_WORD}(?![0-9A-Za-z])`,
  "gi",
);
/** "buy USDC with 1 SOL" — the amount is still what is spent. */
const BUY_WITH = new RegExp(
  `(?<![0-9A-Za-z])buy\\s+${TOKEN_WORD}\\s+(?:with|using)\\s+${AMOUNT}\\s+${TOKEN_WORD}(?![0-9A-Za-z])`,
  "gi",
);
/** A percentage ("with 1% slippage") is a constraint, never an amount. */
const PERCENTAGE = /(?<![0-9A-Za-z.])\d+(?:\.\d+)?\s*%/g;

function namedToken(word: string): NamedToken {
  if (ADDRESS_SHAPE.test(word)) return { mint: word, written: word };
  const mint = KNOWN_TOKEN_MINTS[word.toUpperCase()];
  if (!mint) {
    throw new IntentGroundingError(
      `"${word}" is not a token symbol the guard resolves (${Object.keys(KNOWN_TOKEN_MINTS).join(", ")}); ` +
        "name any other token by its mint address.",
    );
  }
  return { mint, written: word };
}

function sameToken(ai: unknown, named: NamedToken): boolean {
  if (typeof ai !== "string") return false;
  if (ai === named.mint || ai === named.written) return true;
  return KNOWN_TOKEN_MINTS[ai.toUpperCase()] === named.mint;
}

/**
 * Read the swap the user asked for: one amount, the token it is of, and the
 * token to receive, from the text itself; the AI layer's reading must agree
 * on all three. Two grammars, both stating what is spent: "swap <amount>
 * <in> for <out>" and "buy <out> with <amount> <in>". "Buy 5 SOL with USDT"
 * names what is received, not what is spent, so nothing would bound the
 * spend: it is refused, to be rephrased.
 */
export function groundSwapRequest(
  input: string,
  params: { amount?: unknown; input_token?: unknown; output_token?: unknown } | undefined,
): GroundedSwap {
  assertAffirmative(input);
  const matches: { amountText: string; inWord: string; outWord: string }[] = [];
  for (const m of input.matchAll(SPEND_FIRST)) matches.push({ amountText: m[1], inWord: m[2], outWord: m[3] });
  for (const m of input.matchAll(BUY_WITH)) matches.push({ amountText: m[2], inWord: m[3], outWord: m[1] });
  if (matches.length !== 1) {
    throw new IntentGroundingError(
      matches.length === 0
        ? 'The request does not state what it spends: write "swap <amount> <token> for <token>" or ' +
            '"buy <token> with <amount> <token>".'
        : `The request describes ${matches.length} swaps; a swap is only built when it describes one.`,
    );
  }
  const numbers = [...new Set(input.replace(PERCENTAGE, " ").match(NUMERIC_LITERAL) ?? [])];
  if (numbers.length !== 1) {
    throw new IntentGroundingError(
      `The request contains ${numbers.length} distinct amounts; a swap is only built when it names exactly one.`,
    );
  }
  const { amountText, inWord, outWord } = matches[0];
  const inputToken = namedToken(inWord);
  const outputToken = namedToken(outWord);
  if (inputToken.mint === outputToken.mint) {
    throw new IntentGroundingError(`The request swaps ${inWord} for ${outWord}, the same token.`);
  }
  if (params?.amount !== amountText) {
    throw new IntentGroundingError(
      `The AI layer read the amount as ${JSON.stringify(params?.amount ?? null)}; the request says "${amountText}".`,
    );
  }
  if (!sameToken(params?.input_token, inputToken)) {
    throw new IntentGroundingError(
      `The AI layer read the token spent as ${JSON.stringify(params?.input_token ?? null)}; the request spends ${inWord}.`,
    );
  }
  if (!sameToken(params?.output_token, outputToken)) {
    throw new IntentGroundingError(
      `The AI layer read the token received as ${JSON.stringify(params?.output_token ?? null)}; the request asks for ${outWord}.`,
    );
  }
  return { amountText, input: inputToken, output: outputToken };
}

/**
 * What one transaction does to the wallet, from ONE simulation of its exact
 * bytes (the RPC's pre- and post-balances of the same run).
 */
export interface WalletEffect {
  /**
   * Native SOL leaving the wallet, in lamports: its own account (fee and rent
   * included) plus the wrapped SOL in token accounts it owns. Negative when
   * the wallet gains SOL.
   */
  solOut: bigint;
  /** Every other mint's net change across the wallet's token accounts (positive = received). */
  tokenDelta: ReadonlyMap<string, bigint>;
  /** Each mint's decimals, as the simulation reports them. */
  decimals: ReadonlyMap<string, number>;
}

/**
 * What a swap may spend in native SOL beyond the amount requested: the
 * transaction fee, a priority fee, and rent for the token accounts a route
 * creates (about 0.002 SOL each). 0.01 SOL. A route that needs more than this
 * is refused, not trusted; the operator's cap still bounds the total.
 */
export const SWAP_SOL_OVERHEAD_LAMPORTS = 10_000_000n;

/** A decimal amount of a token with `decimals` places, in base units, exactly. */
export function tokenAmountToBaseUnits(text: string, decimals: number): bigint {
  const m = /^(\d+)(?:\.(\d+))?$/.exec(text);
  if (!m || !Number.isSafeInteger(decimals) || decimals < 0 || decimals > 18) {
    throw new IntentGroundingError(`The amount "${text}" cannot be read with ${decimals} decimals.`);
  }
  const fraction = m[2] ?? "";
  if (fraction.length > decimals) {
    throw new IntentGroundingError(
      `The amount "${text}" has more decimal places than the token's ${decimals}.`,
    );
  }
  const units = BigInt(m[1]) * 10n ** BigInt(decimals) + BigInt(fraction.padEnd(decimals, "0") || "0");
  if (units === 0n) throw new IntentGroundingError(`The amount "${text}" is zero.`);
  if (units > U64_MAX) throw new IntentGroundingError(`The amount "${text}" does not fit in a u64.`);
  return units;
}

/**
 * Refuse a swap transaction that does not do what the request asked: spend
 * no more than the requested amount of the requested token (plus
 * `SWAP_SOL_OVERHEAD_LAMPORTS` of SOL), spend no other token, and deliver the
 * requested token. The output amount is not compared: a request rarely states
 * one, and the route's own minimum is the Core's to read.
 */
export function assertSwapEffectMatches(grounded: GroundedSwap, effect: WalletEffect): void {
  const inMint = grounded.input.mint;
  const outMint = grounded.output.mint;
  const name = (t: NamedToken) => t.written;
  if (inMint === NATIVE_MINT) {
    const requested = solLiteralToLamports(grounded.amountText);
    if (effect.solOut > requested + SWAP_SOL_OVERHEAD_LAMPORTS) {
      throw new IntentGroundingError(
        `The request spends ${grounded.amountText} ${name(grounded.input)}; the transaction takes ` +
          `${effect.solOut} lamports of SOL out of the wallet, more than ${requested} plus ` +
          `${SWAP_SOL_OVERHEAD_LAMPORTS} for fees and rent.`,
      );
    }
  } else {
    const decimals = effect.decimals.get(inMint);
    if (decimals === undefined) {
      throw new IntentGroundingError(
        `The transaction touches none of the wallet's ${name(grounded.input)} accounts, so it cannot be spending what the request names.`,
      );
    }
    const requested = tokenAmountToBaseUnits(grounded.amountText, decimals);
    const spent = -(effect.tokenDelta.get(inMint) ?? 0n);
    if (spent > requested) {
      throw new IntentGroundingError(
        `The request spends ${grounded.amountText} ${name(grounded.input)} (${requested} base units); ` +
          `the transaction takes ${spent}.`,
      );
    }
    if (effect.solOut > SWAP_SOL_OVERHEAD_LAMPORTS) {
      throw new IntentGroundingError(
        `The request spends ${name(grounded.input)}, not SOL; the transaction also takes ${effect.solOut} ` +
          `lamports of SOL out of the wallet, more than ${SWAP_SOL_OVERHEAD_LAMPORTS} for fees and rent.`,
      );
    }
  }
  for (const [mint, delta] of effect.tokenDelta) {
    if (delta < 0n && mint !== inMint) {
      throw new IntentGroundingError(
        `The transaction spends ${-delta} base units of ${mint}, a token the request does not spend.`,
      );
    }
  }
  const received = outMint === NATIVE_MINT ? -effect.solOut : (effect.tokenDelta.get(outMint) ?? 0n);
  if (received <= 0n) {
    throw new IntentGroundingError(
      `The request asks for ${name(grounded.output)}; the transaction delivers none of it to the wallet.`,
    );
  }
}
