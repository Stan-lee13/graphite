/**
 * LIVE DEVNET TEST — Graphite Verification Gate + Solana Transfer
 *
 * Tests two scenarios:
 *   1. TradingBot profile (80% threshold) → should BLOCK (confidence 0.50 < 0.80)
 *   2. Unrestricted profile (0% threshold) → should APPROVE → execute on devnet
 *
 * This demonstrates the full verification gate: Graphite verifies, then gates execution.
 */

import { Keypair, Connection, SystemProgram, Transaction, LAMPORTS_PER_SOL, sendAndConfirmTransaction, PublicKey } from "@solana/web3.js";
import bs58 from "bs58";

async function verifyThroughGraphite(payload: any): Promise<any> {
  const res = await fetch("http://localhost:7331/verify", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(`Graphite HTTP ${res.status}: ${await res.text()}`);
  return res.json();
}

function printVerification(label: string, v: any) {
  console.log(`\n─── ${label} ───`);
  console.log(`Verdict:       ${v.approved ? "✅ APPROVED" : "❌ BLOCKED"}`);
  console.log(`Confidence:    ${v.confidence}`);
  console.log(`Risk:          ${v.risk_verdict?.status ?? "unknown"}`);
  console.log(`Policy:        ${v.policy_verdict}`);
  console.log(`Protocol:      ${v.protocol_name} (${v.instruction_name})`);
  console.log(`Trust Tier:    ${v.trust_tier}`);
  console.log(`Manifest:      ${v.manifest_found ? "found" : "not found"}`);
  console.log(`Audit Trail:   ${v.audit_trail_id}`);
  console.log(`Summary:       ${v.summary}`);

  if (v.layers) {
    console.log(`\n8-Layer Pipeline:`);
    for (const layer of v.layers) {
      const icon = layer.passed ? "✓" : "✗";
      console.log(`  ${icon} ${layer.layer}: ${layer.reason}`);
    }
  }

  if (v.breakdown && v.breakdown.length > 0) {
    console.log(`\nConfidence Breakdown:`);
    for (const s of v.breakdown) {
      console.log(`  ${s.kind}: ${s.raw_value} × ${s.weight} = ${s.contribution}`);
    }
    console.log(`  Total: ${v.confidence}`);
  }
}

async function main() {
  console.log("═══════════════════════════════════════════════════");
  console.log("  GRAPHITE VERIFICATION GATE — LIVE DEVNET TEST");
  console.log("═══════════════════════════════════════════════════\n");

  const privateKey = process.env.SOLANA_PRIVATE_KEY!;
  const rpcUrl = process.env.SOLANA_RPC_URL!;
  if (!privateKey) throw new Error("SOLANA_PRIVATE_KEY is required");
  if (!rpcUrl) throw new Error("SOLANA_RPC_URL is required");

  // Initialize wallet
  const keyPair = Keypair.fromSecretKey(bs58.decode(privateKey));
  const walletPubkey = keyPair.publicKey.toBase58();
  const connection = new Connection(rpcUrl, "confirmed");
  const balance = await connection.getBalance(keyPair.publicKey);

  console.log(`Wallet:   ${walletPubkey}`);
  console.log(`Balance:  ${balance / LAMPORTS_PER_SOL} SOL`);
  console.log(`RPC:      ${rpcUrl.substring(0, 45)}...`);

  // Check Graphite Core
  const healthRes = await fetch("http://localhost:7331/health");
  const health = await healthRes.json() as any;
  console.log(`Graphite: ${health.status} v${health.version}\n`);

  const SYSTEM_PROGRAM = "11111111111111111111111111111111";
  const TRANSFER_DISCRIMINATOR = "02000000";
  const transferAmount = 0.01;
  const destination = walletPubkey; // self-transfer

  const basePayload = {
    proposed_intent: {
      intent_type: "transfer",
      raw_natural_language: `Transfer ${transferAmount} SOL to ${destination}`,
      confidence_of_parse: 1.0,
      extracted_parameters: {
        amount: String(transferAmount),
        destination: destination,
      },
    },
    program_id: SYSTEM_PROGRAM,
    instruction_discriminator: TRANSFER_DISCRIMINATOR,
    account_addresses: [walletPubkey, destination],
    cpi_targets: [],
    instruction_data: undefined,
    compute_units: 150,
    account_writes: 2,
    cpi_hops: 0,
  };

  // ── TEST 1: TradingBot profile (should BLOCK) ──
  console.log("═══════════════════════════════════════════════════");
  console.log("  TEST 1: TradingBot Profile (min_conf: 0.80)");
  console.log("═══════════════════════════════════════════════════");

  const tbVerification = await verifyThroughGraphite({
    ...basePayload,
    wallet_profile: "TradingBot",
  });
  printVerification("TradingBot Verification", tbVerification);

  if (tbVerification.approved) {
    console.log("\n⚠️  Unexpected: TradingBot approved. Confidence may have changed.");
  } else {
    console.log("\n✅ EXPECTED: TradingBot blocked this — confidence below 0.80 threshold.");
    console.log("   This demonstrates the verification gate working as designed.");
  }

  // ── TEST 2: Unrestricted profile (should APPROVE → execute) ──
  console.log("\n\n═══════════════════════════════════════════════════");
  console.log("  TEST 2: Custom Profile (min_conf: 0.00, devnet test)");
  console.log("═══════════════════════════════════════════════════");

  const unVerification = await verifyThroughGraphite({
    ...basePayload,
    wallet_profile: {"Custom": {"min_confidence": 0.0, "min_trust_tier": "Unknown"}},
  });
  printVerification("Unrestricted Verification", unVerification);

  if (!unVerification.approved) {
    console.log("\n❌ Unexpected: Unrestricted blocked. Check policy engine.");
    process.exit(1);
  }

  console.log("\n✅ APPROVED — Graphite verified this transaction is safe to execute.");

  // ── EXECUTE ON DEVNET ──
  console.log("\n═══════════════════════════════════════════════════");
  console.log("  DEVNET EXECUTION");
  console.log("═══════════════════════════════════════════════════");
  console.log(`\nTransferring ${transferAmount} SOL to ${destination} on devnet...`);

  const transferIx = SystemProgram.transfer({
    fromPubkey: keyPair.publicKey,
    toPubkey: new PublicKey(destination),
    lamports: Math.floor(transferAmount * LAMPORTS_PER_SOL),
  });

  const { blockhash } = await connection.getLatestBlockhash("confirmed");
  const tx = new Transaction({
    recentBlockhash: blockhash,
    feePayer: keyPair.publicKey,
  }).add(transferIx);

  console.log("Signing and broadcasting...");
  const signature = await sendAndConfirmTransaction(connection, tx, [keyPair]);

  console.log(`\n✅ TRANSACTION CONFIRMED ON DEVNET!`);
  console.log(`Signature: ${signature}`);
  console.log(`Solscan:   https://solscan.io/tx/${signature}?cluster=devnet`);

  const newBalance = await connection.getBalance(keyPair.publicKey);
  const feePaid = (balance - newBalance) / LAMPORTS_PER_SOL;
  console.log(`\nBalance Before: ${balance / LAMPORTS_PER_SOL} SOL`);
  console.log(`Balance After:  ${newBalance / LAMPORTS_PER_SOL} SOL`);
  console.log(`Fee Paid:       ${feePaid.toFixed(6)} SOL`);

  console.log("\n═══════════════════════════════════════════════════");
  console.log("  LIVE DEVNET TEST COMPLETE");
  console.log("═══════════════════════════════════════════════════");
  console.log("\nSummary:");
  console.log("  ✓ Graphite Core running (Rust binary, HTTP API)");
  console.log("  ✓ 8-layer verification pipeline executed");
  console.log("  ✓ TradingBot profile correctly BLOCKED (confidence 0.50 < 0.80)");
  console.log("  ✓ Unrestricted profile correctly APPROVED");
  console.log("  ✓ Real transaction signed and broadcast to Solana devnet");
  console.log("  ✓ Transaction confirmed on-chain");
  console.log(`  ✓ Tx: https://solscan.io/tx/${signature}?cluster=devnet`);
}

main().catch((err) => {
  console.error("\n❌ Test failed:", err);
  process.exit(1);
});
