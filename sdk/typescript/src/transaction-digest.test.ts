/**
 * Round 19 (F-19-C3): `verifyTransactionDigest` against fixed vectors.
 *
 * The vector is the SolanaAgentKit bridge's real artifact — the bytes in
 * graphite-core/fixtures/artifacts/sak_bridge_artifact.json, whose
 * `transaction_sha256` the Rust Core asserts. The Go SDK pins the same bytes
 * and the same digest (sdk/go/digest_test.go); if the three disagree about
 * what a transaction's digest is, one of them fails.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { AuditBindError } from "./auditbind.js";
import { readSignatureCount, transactionDigest, verifyTransactionDigest } from "./transaction-digest.js";

/** sak_bridge_artifact.json `signed_transaction` (unsigned: one empty slot), 267 bytes. */
export const FIXTURE_HEX =
  "01" +
  "00".repeat(64) +
  "0100020479b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664274ed6b26805d2fe" +
  "8d060529ee9a2f28763b6976d9c5fd1dee38ff36b3b769390000000000000000000000000000000000000000" +
  "0000000000000000000000000306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a40000000" +
  "00000000000000000000000000000000000000000000000000000000000000000303000502400d0300030009" +
  "03e803000000000000020200010c0200000080841e0000000000";
/** sak_bridge_artifact.json `transaction_sha256`. */
export const FIXTURE_SHA256 = "c9a8ca018072273203dfae99ef91a6e03b0edd3ffc9153aba7bae814df269661";

const fixture = () => Uint8Array.from(Buffer.from(FIXTURE_HEX, "hex"));
const approved = (sha = FIXTURE_SHA256) => ({
  approved: true,
  scope: { kind: "artifact_bound", transaction_sha256: sha },
});

test("the fixed vector: 267 bytes, digest pinned against the Rust Core's fixture", () => {
  const bytes = fixture();
  assert.equal(bytes.length, 267);
  assert.equal(transactionDigest(bytes), FIXTURE_SHA256);
  // Unsigned, the digest is plain SHA-256 of the bytes.
  assert.equal(createHash("sha256").update(bytes).digest("hex"), FIXTURE_SHA256);
  verifyTransactionDigest(bytes, approved());
  verifyTransactionDigest(Array.from(bytes), approved());
});

test("the SIGNED bytes of the approved transaction still bind: only the slots are zeroed", () => {
  const signed = fixture();
  signed.fill(0xab, 1, 65);
  // Raw SHA-256 of the signed bytes is a different value (pinned in Go too)…
  assert.equal(
    createHash("sha256").update(signed).digest("hex"),
    "68982d9a0ae17ff538108df9084a3b79c577f09ce446ebb3934ce05b7cbd295b",
  );
  // …but the digest the Core binds is over the frame with empty slots.
  verifyTransactionDigest(signed, approved());
});

test("any change to the message fails, wherever it is", () => {
  for (const index of [65, 66, 100, 200, 266]) {
    const mutated = fixture();
    mutated[index] ^= 0x01;
    assert.throws(() => verifyTransactionDigest(mutated, approved()), /digest mismatch/, `byte ${index}`);
  }
  // Appending an instruction's worth of bytes is a change too.
  const longer = Uint8Array.from([...fixture(), 0]);
  assert.throws(() => verifyTransactionDigest(longer, approved()), /digest mismatch/);
});

test("fails closed on every verdict that does not bind these bytes", () => {
  const bytes = fixture();
  const cases: [string, unknown][] = [
    ["null", null],
    ["blocked", { approved: false, scope: { kind: "artifact_bound", transaction_sha256: FIXTURE_SHA256 } }],
    ["approved missing", { scope: { kind: "artifact_bound", transaction_sha256: FIXTURE_SHA256 } }],
    ["approved truthy but not true", { approved: "true", scope: { kind: "artifact_bound", transaction_sha256: FIXTURE_SHA256 } }],
    ["no scope", { approved: true }],
    ["descriptive", { approved: true, scope: { kind: "descriptive", unobserved: [] } }],
    ["digest missing", { approved: true, scope: { kind: "artifact_bound" } }],
    ["digest uppercase", approved(FIXTURE_SHA256.toUpperCase())],
    ["digest truncated", approved(FIXTURE_SHA256.slice(0, 16))],
    ["other digest", approved("00".repeat(32))],
  ];
  for (const [name, result] of cases) {
    assert.throws(
      () => verifyTransactionDigest(bytes, result as never),
      AuditBindError,
      `${name} must be refused`,
    );
  }
});

test("the signature count is parsed strictly: minimal, at most three bytes, and a message must follow", () => {
  const msg = fixture().subarray(65);
  const slot = new Uint8Array(64);
  // One signature, spelled with a redundant continuation byte: refused by
  // the count reader. As a whole frame, 0x81 first is the v1 marker (Round
  // 19), and a v1 frame declaring 0 signers is refused too.
  assert.throws(() => readSignatureCount(Uint8Array.from([0x81, 0x00, ...slot])), /minimally encoded/);
  assert.throws(() => transactionDigest(Uint8Array.from([0x81, 0x00, ...slot, ...msg])), AuditBindError);
  // A count that continues past its third byte.
  assert.throws(() => readSignatureCount(Uint8Array.from([0x80, 0x80, 0x80, 0x01])), /third byte/);
  // A count too large for a u16 (0x7f | 0x7f<<7 | 0x7f<<14).
  assert.throws(() => readSignatureCount(Uint8Array.from([0xff, 0xff, 0x7f])), /u16/);
  // The largest legal three-byte form still parses.
  assert.deepEqual(readSignatureCount(Uint8Array.from([0xff, 0xff, 0x03])), { count: 0xffff, offset: 3 });
  assert.throws(() => transactionDigest(new Uint8Array(0)), /truncated/);
  assert.throws(() => transactionDigest(Uint8Array.from([0x00, ...msg])), /no signatures/);
  assert.throws(() => transactionDigest(Uint8Array.from([0x02, ...slot, ...slot])), /run past/);
  assert.throws(() => transactionDigest(new Uint8Array(1233).fill(1)), /at most 1232/);
});


// Round 19: the v1 vector pinned in graphite-core
// (tests/round19_v1_transactions.rs::the_cross_language_v1_digest_vector_is_the_cores_answer)
// and in the Go SDK. 232 bytes, signed: one 0xAB-filled trailing slot.
const V1_FRAME_HEX =
  "8101000107000000090909090909090909090909090909090909090909090909" +
  "0909090909090909010301010101010101010101010101010101010101010101" +
  "0101010101010101010107070707070707070707070707070707070707070707" +
  "0707070707070707070700000000000000000000000000000000000000000000" +
  "000000000000000000008813000000000000400d030002020c00000102000000" +
  "40420f0000000000abababababababababababababababababababababababab" +
  "abababababababababababababababababababababababababababababababab" +
  "abababababababab";
const V1_SHA256 = "761b1f93c15a9758ff5885294853d3df69445aeb84a27392ad9a833eaeeb337b";
const v1Frame = () => Uint8Array.from(Buffer.from(V1_FRAME_HEX, "hex"));

test("a v1 frame's digest zeroes its TRAILING signature slots, as the Core does", () => {
  const frame = v1Frame();
  assert.equal(frame.length, 232);
  assert.equal(transactionDigest(frame), V1_SHA256);
  const unsigned = Uint8Array.from(frame);
  unsigned.fill(0, frame.length - 64);
  assert.equal(transactionDigest(unsigned), V1_SHA256, "signing changes only the slots");
  verifyTransactionDigest(frame, approved(V1_SHA256));
});

test("a v1 frame differing outside its signature slots does not match", () => {
  const frame = v1Frame();
  frame[frame.length - 65] ^= 1; // last byte of the transfer amount
  assert.throws(() => verifyTransactionDigest(frame, approved(V1_SHA256)), AuditBindError);
});

test("a v1 frame the runtime could not accept is refused, not hashed", () => {
  const noSigners = v1Frame();
  noSigners[1] = 0;
  assert.throws(() => transactionDigest(noSigners), /required signature/);
  const tooMany = v1Frame();
  tooMany[1] = 13;
  assert.throws(() => transactionDigest(tooMany), /required signature/);
  assert.throws(() => transactionDigest(Uint8Array.from([0x81, 1, 0, 1])), /do not fit/);
  const huge = new Uint8Array(4097);
  huge[0] = 0x81;
  huge[1] = 1;
  assert.throws(() => transactionDigest(huge), /at most 4096/);
});
