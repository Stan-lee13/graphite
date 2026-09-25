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

/** Base58 alphabet runs: the only characters a Solana address can contain. */
const BASE58_RUN = /[1-9A-HJ-NP-Za-km-z]+/g;
/** An ed25519 public key is 32 bytes: 32–44 base58 characters. */
const ADDRESS_SHAPE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
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
  const addresses = (input.match(BASE58_RUN) ?? []).filter((t) => ADDRESS_SHAPE.test(t));
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
