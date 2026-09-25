/**
 * Round 19 (F-19-C2): SolanaAgentKit must not be able to sign.
 *
 * The bridge handed SAK a `KeypairWallet` built from the wallet's secret key.
 * Every plugin method and every SAK action tool an LLM drives then signed and
 * sent through SAK's own helpers (`signOrSendTX`, `sendTx`) — and
 * `signMessage` signed arbitrary bytes — with no Graphite verdict on the path.
 * These tests drive SAK's real signing helper against the wallet the bridge
 * now gives it. No network: the transaction paths below reach the wallet
 * before any RPC call.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { Keypair, SystemProgram, Transaction, VersionedTransaction, TransactionMessage } from "@solana/web3.js";
import { SolanaAgentKit, signOrSendTX } from "solana-agent-kit";
import { VerificationGatedWallet, UngatedSigningRefused, GATED_SIGNING_PATH } from "./gated-wallet.js";

const UNUSED_RPC = "http://127.0.0.1:9"; // discard port; nothing below may reach it

function legacyTransfer(from: Keypair): Transaction {
  const tx = new Transaction({
    feePayer: from.publicKey,
    recentBlockhash: "11111111111111111111111111111111",
  });
  tx.add(SystemProgram.transfer({ fromPubkey: from.publicKey, toPubkey: Keypair.generate().publicKey, lamports: 1 }));
  return tx;
}

test("every signing method of the gated wallet refuses, naming the verified path", async () => {
  const kp = Keypair.generate();
  const wallet = new VerificationGatedWallet(kp.publicKey);
  const tx = legacyTransfer(kp);
  const v0 = new VersionedTransaction(
    new TransactionMessage({
      payerKey: kp.publicKey,
      recentBlockhash: "11111111111111111111111111111111",
      instructions: tx.instructions,
    }).compileToV0Message(),
  );
  const attempts: [string, () => Promise<unknown>][] = [
    ["signTransaction", () => wallet.signTransaction(tx)],
    ["signTransaction(v0)", () => wallet.signTransaction(v0)],
    ["signAllTransactions", () => wallet.signAllTransactions([tx])],
    ["sendTransaction", () => wallet.sendTransaction(tx)],
    ["signAndSendTransaction", () => wallet.signAndSendTransaction(tx)],
    ["signMessage", () => wallet.signMessage(new TextEncoder().encode("anything"))],
  ];
  for (const [name, attempt] of attempts) {
    await assert.rejects(attempt, (e: unknown) => {
      assert.ok(e instanceof UngatedSigningRefused, `${name} must refuse with UngatedSigningRefused`);
      assert.ok((e as Error).message.includes(GATED_SIGNING_PATH), `${name}'s refusal must name the gated path`);
      return true;
    });
  }
  // Nothing was signed as a side effect of the refusals.
  assert.ok(tx.signatures.every((s) => s.signature === null), "the legacy transaction must stay unsigned");
  assert.ok(v0.signatures.every((s) => s.every((b) => b === 0)), "the v0 transaction must stay unsigned");
});

test("SAK's own signOrSendTX cannot sign or send through an agent built on the gated wallet", async () => {
  const kp = Keypair.generate();
  const agent = new SolanaAgentKit(new VerificationGatedWallet(kp.publicKey), UNUSED_RPC, {});
  // The path plugin actions take for a built transaction: signAndSendTransaction.
  await assert.rejects(signOrSendTX(agent, legacyTransfer(kp)), UngatedSigningRefused);
  // And the sign-only configuration: signTransaction / signAllTransactions.
  const signOnly = new SolanaAgentKit(new VerificationGatedWallet(kp.publicKey), UNUSED_RPC, { signOnly: true });
  await assert.rejects(signOrSendTX(signOnly, legacyTransfer(kp)), UngatedSigningRefused);
  await assert.rejects(signOrSendTX(signOnly, [legacyTransfer(kp)]), UngatedSigningRefused);
  await assert.rejects(agent.wallet.signMessage(new Uint8Array([1, 2, 3])), UngatedSigningRefused);
});

test("the gated wallet holds the public key and nothing that can sign", () => {
  const kp = Keypair.generate();
  const wallet = new VerificationGatedWallet(kp.publicKey);
  // Read-only SAK use needs the address, and gets it.
  assert.equal(wallet.publicKey.toBase58(), kp.publicKey.toBase58());
  assert.deepEqual(Object.keys(wallet), ["publicKey"]);
  assert.ok(Object.isFrozen(wallet), "the wallet cannot be given a key after construction");
  assert.throws(() => {
    (wallet as unknown as { payer: Keypair }).payer = kp;
  });
});
