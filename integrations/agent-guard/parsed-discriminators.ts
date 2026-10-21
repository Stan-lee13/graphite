/**
 * The discriminator of a System or SPL Token instruction, at the program's own
 * width — what the guard sends to the Core and what the manifests name. Used
 * by `build_exploit_corpus.mts`, which reads `getParsedTransaction` output
 * (parsed instructions carry a type name, not their data).
 *
 * Round 29 (audit 2026-10-20, L5): the corpus builder used ONE table for both
 * programs, so SPL Token `transfer` became 02 (InitializeMultisig; Transfer
 * is 03) and System `allocate` became 3 (CreateAccountWithSeed; Allocate is
 * 8); System discriminators were padded to 8 bytes where the guard uses 4
 * (bincode u32); an unknown type became "00…", a discriminator the
 * transaction never carried. Here each program has its own table, an unknown
 * type is `undefined`, and the caller skips it.
 */
export const SYSTEM_PROGRAM = "11111111111111111111111111111111";
export const SPL_TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

/** bincode u32 LE, as System instructions are tagged. */
const u32 = (n: number) => Buffer.from(Uint32Array.of(n).buffer).toString("hex");

const PARSED: Readonly<Record<string, Readonly<Record<string, string>>>> = {
  // solana-program SystemInstruction, in enum order.
  [SYSTEM_PROGRAM]: {
    createAccount: u32(0),
    assign: u32(1),
    transfer: u32(2),
    createAccountWithSeed: u32(3),
    advanceNonce: u32(4),
    withdrawNonce: u32(5),
    initializeNonce: u32(6),
    authorizeNonce: u32(7),
    allocate: u32(8),
    allocateWithSeed: u32(9),
    assignWithSeed: u32(10),
    transferWithSeed: u32(11),
  },
  // spl-token TokenInstruction tags.
  [SPL_TOKEN_PROGRAM]: {
    transfer: "03",
    approve: "04",
    revoke: "05",
    setAuthority: "06",
    mintTo: "07",
    burn: "08",
    closeAccount: "09",
    freezeAccount: "0a",
    thawAccount: "0b",
    transferChecked: "0c",
    approveChecked: "0d",
  },
};

/** The discriminator of a parsed System / SPL Token instruction, or undefined. */
export function parsedDiscriminator(programId: string, parsedType: string): string | undefined {
  return Object.hasOwn(PARSED, programId) && Object.hasOwn(PARSED[programId], parsedType)
    ? PARSED[programId][parsedType]
    : undefined;
}

/**
 * A raw instruction's selector at its program's width: 4 bytes for System,
 * 1 for SPL Token, 8 (Anchor) otherwise.
 */
export function rawSelector(programId: string, data: Uint8Array): string {
  const width = programId === SYSTEM_PROGRAM ? 4 : programId === SPL_TOKEN_PROGRAM ? 1 : 8;
  return Buffer.from(data.subarray(0, width)).toString("hex");
}
