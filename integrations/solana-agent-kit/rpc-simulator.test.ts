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
import { RpcSimulator, assertEverySignatureSlotEmpty, PLACEHOLDER_BLOCKHASH } from "./rpc-simulator.js";
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
  const nonMinimal = Uint8Array.from([0x81, 0x00, ...unsigned.subarray(1)]);
  assert.throws(() => assertEverySignatureSlotEmpty(nonMinimal), /minimally encoded/);
});
