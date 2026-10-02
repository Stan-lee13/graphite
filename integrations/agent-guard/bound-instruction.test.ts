/**
 * P1 regression coverage (2026-09-05 audit finding): "SolanaAgentKit
 * swap-path TOCTOU residual."
 *
 * Before this fix, `executeSwap(naturalLanguage, payload)` hash-verified a
 * caller-supplied payload against Graphite's approved content_hash via
 * AuditBind, but then STILL executed via `sakAgent.methods.swap(...)`,
 * which rebuilds the swap instruction internally from live routing data —
 * the executed instruction was never actually guaranteed to be the payload
 * that was verified. That gap is closed for the payload-provided path:
 * `buildInstructionFromPayload` derives the submitted `TransactionInstruction`
 * from the EXACT SAME fields (programId, account pubkeys in order, raw
 * instruction data) that `AuditBind.verifyInstruction` hashes, so there is
 * no second code path that could disagree with the first — what executes
 * is deterministically derived from what was verified, not independently
 * reconstructed. (The no-payload path is unchanged and still executes via
 * SAK's opaque builder; `GRAPHITE_SWAP_STRICT=1` refuses that path
 * entirely — see graphite-sak-bridge.ts's executeSwap doc comment.)
 *
 * These tests exercise `buildInstructionFromPayload` directly (the pure,
 * dependency-light piece the TOCTOU closure rests on) rather than the full
 * `executeSwap` method, which requires a live Graphite Core server, a
 * funded devnet wallet, and network access to construct end-to-end — out of
 * reach for a unit test. What IS independently verifiable without a network
 * is the property that actually matters: the instruction that would be
 * submitted is byte-identical, field-for-field, to what AuditBind hashed.
 *
 * Run: npx tsx --test bound-instruction.test.ts
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { PublicKey } from "@solana/web3.js";
import { AuditBind } from "./auditbind.ts";
import { buildInstructionFromPayload, type BoundInstructionPayload } from "./bound-instruction.ts";

const JUPITER_V6 = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
const WALLET = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const SOURCE_ATA = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";
const DEST_ATA = "9wDJULnQ6to8Z8kYqxJy9hrrwX8G4WmNy8G6pqm5m6X7";
const ATTACKER_ATA = "3npQNsA9S1K9xJ9gTYn1BZu2xw2sBvZK9QG4pLkXVcBz";

function samplePayload(): BoundInstructionPayload {
  return {
    programId: JUPITER_V6,
    discriminator: "bb64facc31c4af14",
    accounts: [
      { pubkey: WALLET, isSigner: true, isWritable: false },
      { pubkey: SOURCE_ATA, isSigner: false, isWritable: true },
      { pubkey: DEST_ATA, isSigner: false, isWritable: true },
    ],
    instructionData: [0xbb, 0x64, 0xfa, 0xcc, 0x31, 0xc4, 0xaf, 0x14, 1, 2, 3, 4],
  };
}

test("buildInstructionFromPayload constructs the exact bound instruction", () => {
  const payload = samplePayload();
  const ix = buildInstructionFromPayload(payload);

  assert.equal(ix.programId.toBase58(), payload.programId);
  assert.equal(ix.keys.length, payload.accounts.length);
  payload.accounts.forEach((a, i) => {
    assert.equal(ix.keys[i].pubkey.toBase58(), a.pubkey);
    assert.equal(ix.keys[i].isSigner, a.isSigner);
    assert.equal(ix.keys[i].isWritable, a.isWritable);
  });
  assert.deepEqual(Array.from(ix.data), payload.instructionData);
});

test("the instruction built from a payload hashes identically to what AuditBind verified — no divergence possible between verified and submitted", () => {
  const payload = samplePayload();
  const accountAddresses = payload.accounts.map((a) => a.pubkey);

  // What the bridge hashes BEFORE building the instruction (mirrors
  // executeSwap's AuditBind.verifyInstruction call).
  const boundHash = AuditBind.computeHash({
    programId: payload.programId,
    instructionDiscriminator: payload.discriminator,
    accountAddresses,
    instructionData: payload.instructionData,
  });

  // What actually gets built and submitted.
  const ix = buildInstructionFromPayload(payload);

  // Re-derive the hash from the BUILT instruction's own fields (as if we
  // only had the TransactionInstruction, not the original payload) — this
  // is the property that matters: the submitted instruction re-hashes to
  // the SAME value that was verified, by construction, not by a second
  // independently-maintained code path merely agreeing today.
  const rehash = AuditBind.computeHash({
    programId: ix.programId.toBase58(),
    instructionDiscriminator: payload.discriminator,
    accountAddresses: ix.keys.map((k) => k.pubkey.toBase58()),
    instructionData: Array.from(ix.data),
  });

  assert.equal(rehash, boundHash, "the built instruction must re-hash to the exact hash that was verified");
});

test("a tampered account in the payload changes the hash before the instruction is ever built (abort, not silent execution)", () => {
  const payload = samplePayload();
  const accountAddresses = payload.accounts.map((a) => a.pubkey);
  const approvedHash = AuditBind.computeHash({
    programId: payload.programId,
    instructionDiscriminator: payload.discriminator,
    accountAddresses,
    instructionData: payload.instructionData,
  });

  // Attacker substitutes the destination token account after "verification"
  // (simulating a payload object mutated in the TOCTOU window).
  const tampered: BoundInstructionPayload = {
    ...payload,
    accounts: [
      payload.accounts[0],
      payload.accounts[1],
      { pubkey: ATTACKER_ATA, isSigner: false, isWritable: true },
    ],
  };

  assert.throws(
    () =>
      AuditBind.verifyInstruction(
        {
          programId: tampered.programId,
          data: Uint8Array.from(tampered.instructionData ?? []),
          accounts: tampered.accounts.map((a) => a.pubkey),
        },
        approvedHash,
      ),
    /AuditBind FAILED: hash mismatch/,
    "a tampered destination must fail AuditBind BEFORE buildInstructionFromPayload is ever reached",
  );
});

test("a tampered instruction amount/data changes the hash", () => {
  const payload = samplePayload();
  const accountAddresses = payload.accounts.map((a) => a.pubkey);
  const approvedHash = AuditBind.computeHash({
    programId: payload.programId,
    instructionDiscriminator: payload.discriminator,
    accountAddresses,
    instructionData: payload.instructionData,
  });

  const tamperedData = [...(payload.instructionData ?? [])];
  tamperedData[tamperedData.length - 1] = 0xff; // flip the last byte

  assert.throws(
    () =>
      AuditBind.verifyInstruction(
        { programId: payload.programId, data: Uint8Array.from(tamperedData), accounts: accountAddresses },
        approvedHash,
      ),
    /AuditBind FAILED: hash mismatch/,
  );
});

test("PublicKey construction rejects a malformed payload address rather than silently truncating it", () => {
  const payload = samplePayload();
  payload.accounts[1] = { pubkey: "not-a-valid-pubkey", isSigner: false, isWritable: true };
  assert.throws(() => buildInstructionFromPayload(payload));
});

test("real PublicKey parity: every account in the built instruction round-trips through PublicKey unchanged", () => {
  const payload = samplePayload();
  const ix = buildInstructionFromPayload(payload);
  for (let i = 0; i < payload.accounts.length; i++) {
    assert.ok(ix.keys[i].pubkey instanceof PublicKey);
    assert.equal(ix.keys[i].pubkey.toBase58(), payload.accounts[i].pubkey);
  }
});
