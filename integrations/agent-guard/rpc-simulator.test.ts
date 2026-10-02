/**
 * Round 19 (F-19-C1): the simulation that runs before a verdict must never
 * put a signed transaction in an RPC's hands.
 *
 * The simulator used to call `connection.simulateTransaction(tx, [keypair])`,
 * which in @solana/web3.js 1.x fetches a live blockhash, signs, and sends the
 * SIGNED wire transaction to the RPC — a broadcastable transfer, handed over
 * before Graphite had decided whether it should exist. These tests stand up a
 * loopback JSON-RPC endpoint and read what actually arrives on the wire.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { Keypair, SystemProgram, Transaction } from "@solana/web3.js";
import { createHash } from "node:crypto";
import { BoundTransaction } from "./artifact.js";
import {
  RpcSimulator,
  assertEverySignatureSlotEmpty,
  PLACEHOLDER_BLOCKHASH,
  v1LimitsFromMeasurement,
} from "./rpc-simulator.js";
import { MOCK_BLOCKHASH, mockRpc } from "./loopback-mocks.js";

function transfer(from: Keypair) {
  return SystemProgram.transfer({
    fromPubkey: from.publicKey,
    toPubkey: Keypair.generate().publicKey,
    lamports: 1_000_000,
  });
}

test("the simulation reaches the RPC unsigned, with sigVerify off and the blockhash left to the RPC", async () => {
  const rpc = await mockRpc({ unitsConsumed: 150 });
  try {
    const wallet = Keypair.generate();
    const sim = await new RpcSimulator(rpc.url).simulate({
      instructions: [transfer(wallet)],
      feePayer: wallet.publicKey,
    });
    assert.equal(sim.success, true, "the simulation must actually run");
    assert.equal(sim.computeUnits, 150);

    const sims = rpc.calls.filter((c) => c.method === "simulateTransaction");
    assert.equal(sims.length, 1, "exactly one simulation reached the RPC");
    assert.equal(sims[0].signed, false, "every signature slot on the wire must be empty");
    const config = (sims[0].params as { params: [string, Record<string, unknown>] }).params[1];
    assert.equal(config.sigVerify, false);
    assert.equal(config.replaceRecentBlockhash, true);
    // Signing needs a real blockhash; the simulator never asks for one, and
    // the one inside the message is the all-zero placeholder.
    assert.equal(
      rpc.calls.filter((c) => c.method === "getLatestBlockhash").length,
      0,
      "a simulation that fetches a blockhash is preparing to sign",
    );
    const wire = Buffer.from((sims[0].params as { params: [string] }).params[0], "base64");
    assert.ok(
      !wire.includes(Buffer.alloc(32, 7)), // MOCK_BLOCKHASH's bytes
      "the RPC's blockhash must not have been written into the transaction",
    );
    assert.equal(PLACEHOLDER_BLOCKHASH, "11111111111111111111111111111111");
    assert.equal(rpc.calls.filter((c) => c.method === "sendTransaction").length, 0);
  } finally {
    await rpc.close();
  }
});

test("a keypair handed to the simulator is refused, and nothing signed leaves the process", async () => {
  const rpc = await mockRpc();
  try {
    const wallet = Keypair.generate();
    // The pre-Round-19 call shape. A caller that still passes signers — an
    // old call site, a cast — must get an error, not a signature.
    await assert.rejects(
      new RpcSimulator(rpc.url).simulate({
        instructions: [transfer(wallet)],
        signers: [wallet],
      } as never),
      /Simulations are never signed/,
    );
    assert.equal(
      rpc.calls.filter((c) => c.signed === true).length,
      0,
      "a signed transaction reached the RPC before any verdict existed",
    );
    assert.equal(rpc.calls.length, 0, "a refused simulation must not reach the RPC at all");
  } finally {
    await rpc.close();
  }
});

test("assertEverySignatureSlotEmpty refuses a signed transaction and accepts an unsigned one", () => {
  const wallet = Keypair.generate();
  const tx = new Transaction({ feePayer: wallet.publicKey, recentBlockhash: MOCK_BLOCKHASH });
  tx.add(transfer(wallet));
  const unsigned = Uint8Array.from(tx.serialize({ requireAllSignatures: false, verifySignatures: false }));
  assert.doesNotThrow(() => assertEverySignatureSlotEmpty(unsigned));
  tx.sign(wallet);
  assert.throws(() => assertEverySignatureSlotEmpty(Uint8Array.from(tx.serialize())), /signature slot 0 is not empty/);
  // A malformed count cannot redirect the check to a different range.
  const nonMinimal = Uint8Array.from([0x80, 0x00, ...unsigned.subarray(1)]);
  assert.throws(() => assertEverySignatureSlotEmpty(nonMinimal), /minimally encoded/);
  // A first byte of 0x81 is a v1 frame to the runtime, not a count; these
  // bytes are no v1 frame, so the check refuses rather than reading a range.
  const v1Shaped = Uint8Array.from([0x81, 0x00, ...unsigned.subarray(1)]);
  assert.throws(() => assertEverySignatureSlotEmpty(v1Shaped), /v1 frame/);
});

test("assertEverySignatureSlotEmpty reads a v1 frame's TRAILING slots", async () => {
  const wallet = Keypair.generate();
  const bound = BoundTransaction.build({
    instructions: [transfer(wallet)],
    feePayer: wallet.publicKey,
    recentBlockhash: MOCK_BLOCKHASH,
    lastValidBlockHeight: 1,
    version: 1,
    v1Limits: { computeUnitLimit: 450, loadedAccountsDataSizeLimit: 32 * 1024 },
  });
  assert.doesNotThrow(() => assertEverySignatureSlotEmpty(bound.artifactBytes));
  const approved = createHash("sha256").update(bound.artifactBytes).digest("hex");
  const signed = await bound.signApproved(approved, [wallet]);
  assert.throws(() => assertEverySignatureSlotEmpty(signed), /signature slot 0 is not empty/);
  // A legacy reading of the same bytes would look at the wrong range: the
  // first byte is 0x81, which no legacy count of a packet-sized frame is.
  assert.equal(signed[0], 0x81);
});

test("v1 sizing: an unsigned v1 draft at the maximum limits, base64, sigVerify off, placeholder blockhash", async () => {
  const rpc = await mockRpc({ unitsConsumed: 150, loadedAccountsDataSize: 40_000 });
  try {
    const wallet = Keypair.generate();
    const limits = await new RpcSimulator(rpc.url).estimateV1Limits({
      instructions: [transfer(wallet)],
      feePayer: wallet.publicKey,
    });
    assert.deepEqual(limits, {
      computeUnitLimit: 180,
      loadedAccountsDataSizeLimit: 65_536,
      unitsConsumed: 150,
      loadedAccountsDataSize: 40_000,
    });
    const sims = rpc.calls.filter((c) => c.method === "simulateTransaction");
    assert.equal(sims.length, 1);
    assert.equal(sims[0].signed, false, "every (trailing) signature slot on the wire is empty");
    const [wireB64, config] = (sims[0].params as { params: [string, Record<string, unknown>] }).params;
    assert.equal(config.encoding, "base64", "v1 travels as base64 (base58 stays capped at 1232 bytes)");
    assert.equal(config.sigVerify, false);
    assert.equal(config.replaceRecentBlockhash, true);
    const wire = Buffer.from(wireB64, "base64");
    assert.equal(wire[0], 0x81, "the draft is a v1 frame");
    // The config mask (bytes 4..8) carries the compute and loaded-data limits
    // at the runtime's maxima, so the measurement cannot fail for want of them.
    assert.equal(wire.readUInt32LE(4), 0b1100);
    assert.ok(wire.includes(Buffer.from([0xc0, 0x5c, 0x15, 0x00])), "1,400,000 compute units");
    assert.ok(wire.includes(Buffer.from([0x00, 0x00, 0x00, 0x04])), "64 MiB of loaded data");
    assert.equal(rpc.calls.filter((c) => c.method === "getLatestBlockhash").length, 0);
    assert.equal(rpc.calls.filter((c) => c.method === "sendTransaction").length, 0);
  } finally {
    await rpc.close();
  }
});

test("v1 sizing refuses when the RPC withholds a measurement or the draft fails", async () => {
  const wallet = Keypair.generate();
  for (const [opts, why] of [
    [{ loadedAccountsDataSize: null }, /did not report unitsConsumed and loadedAccountsDataSize/],
    [{ simulationErr: { InstructionError: [0, "Custom"] } }, /sizing simulation failed/],
  ] as const) {
    const rpc = await mockRpc(opts);
    try {
      await assert.rejects(
        new RpcSimulator(rpc.url).estimateV1Limits({ instructions: [transfer(wallet)], feePayer: wallet.publicKey }),
        why,
      );
    } finally {
      await rpc.close();
    }
  }
});

test("v1 limits from a measurement: headroom on compute, the next 32 KiB page on data", () => {
  assert.deepEqual(v1LimitsFromMeasurement(1_000, 0), { computeUnitLimit: 1_200, loadedAccountsDataSizeLimit: 32_768 });
  assert.deepEqual(v1LimitsFromMeasurement(0, 32_767), { computeUnitLimit: 1, loadedAccountsDataSizeLimit: 32_768 });
  // Exactly on a page boundary still gets the next page: an account created
  // between simulation and landing adds at least 64 bytes.
  assert.deepEqual(v1LimitsFromMeasurement(150, 32_768), { computeUnitLimit: 180, loadedAccountsDataSizeLimit: 65_536 });
  assert.equal(v1LimitsFromMeasurement(1_300_000, 10).computeUnitLimit, 1_400_000, "capped at the runtime ceiling");
  assert.throws(() => v1LimitsFromMeasurement(1_400_000, 10), /whole budget/);
  assert.throws(() => v1LimitsFromMeasurement(10, 64 * 1024 * 1024), /whole budget/);
  assert.throws(() => v1LimitsFromMeasurement(-1, 10), /not a measurement/);
  assert.throws(() => v1LimitsFromMeasurement(10, Number.NaN), /not a measurement/);
});
