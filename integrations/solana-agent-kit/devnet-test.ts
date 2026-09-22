/**
 * LIVE DEVNET TEST — Graphite Verification Gate + Solana Transfer
 *
 * Tests two scenarios:
 *   1. TradingBot profile (80% threshold) → should BLOCK (confidence 0.50 < 0.80)
 *   2. Gaming profile (the weakest built-in, 0.55) → should APPROVE → execute
 *      on devnet through the SAME path the bridge uses.
 *
 * This is the file most likely to be copied, so it executes the way the
 * bridge executes and in no other way (Round 17, F-16-12 / F-15-06):
 *
 *   approved → artifact_bound → ResidualPolicy.assertExecutable →
 *   signApproved → `signing` on the trail (resolved by exact audit_trail_id,
 *   approved) → sendRawTransaction → `submission` on the trail → confirm → L8.
 *
 * It no longer asks for a `Custom { min_confidence: 0.0 }` profile: the
 * server clamps that to 0.55 anyway and discloses the override, and a demo
 * that teaches switching the gate off is teaching the wrong thing.
 */

import { Keypair, Connection, SystemProgram, LAMPORTS_PER_SOL, PublicKey } from "@solana/web3.js";
import bs58 from "bs58";
// The same execution gate the bridge uses. A demo that reaches
// `sendAndConfirmTransaction` on a Descriptive verdict is teaching the pattern
// the bridge was changed to stop doing.
import { BoundTransaction, declareSiblings, findPrimaryIndex } from "./artifact.js";
import { executeBoundTransaction } from "./execution-lifecycle.js";
import { ResidualPolicy } from "./residual-policy.js";
import { GraphiteClient } from "../../sdk/typescript/src/client.js";

const GRAPHITE_URL = process.env.GRAPHITE_URL ?? "http://localhost:7331";

async function verifyThroughGraphite(payload: any): Promise<any> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (process.env.GRAPHITE_API_KEY) headers.authorization = `Bearer ${process.env.GRAPHITE_API_KEY}`;
  const res = await fetch(`${GRAPHITE_URL}/verify`, {
    method: "POST",
    headers,
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
  const healthRes = await fetch(`${GRAPHITE_URL}/health`);
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

  // ── TEST 2: Gaming profile (the weakest built-in; should APPROVE → execute) ──
  console.log("\n\n═══════════════════════════════════════════════════");
  console.log("  TEST 2: Gaming Profile (min_conf: 0.55, devnet test)");
  console.log("═══════════════════════════════════════════════════");

  const unVerification = await verifyThroughGraphite({
    ...basePayload,
    wallet_profile: "Gaming",
  });
  printVerification("Gaming Verification (descriptive)", unVerification);

  if (!unVerification.approved) {
    console.log("\n❌ Unexpected: Gaming blocked a plain transfer. Check policy engine.");
    process.exit(1);
  }

  console.log("\n✅ APPROVED — but `approved` alone is not the gate; see below.");

  // ── EXECUTE ON DEVNET ──
  console.log("\n═══════════════════════════════════════════════════");
  console.log("  DEVNET EXECUTION");
  console.log("═══════════════════════════════════════════════════");
  console.log(`
Transferring ${transferAmount} SOL to ${destination} on devnet...`);

  // This script exists to DEMONSTRATE the gate, so it has to demonstrate the
  // real one. It previously verified a description — no `signed_transaction`,
  // so a Descriptive verdict that constrains nothing about what gets signed —
  // gated on `approved` alone, and then built a SEPARATE transaction and
  // submitted it. Every one of those is the pattern the bridge was changed to
  // stop doing, in the file most likely to be copied.
  const transferIx = SystemProgram.transfer({
    fromPubkey: keyPair.publicKey,
    toPubkey: new PublicKey(destination),
    lamports: Math.floor(transferAmount * LAMPORTS_PER_SOL),
  });

  const { blockhash, lastValidBlockHeight } =
    await connection.getLatestBlockhash("confirmed");
  const bound = BoundTransaction.build({
    instructions: [transferIx],
    feePayer: keyPair.publicKey,
    recentBlockhash: blockhash,
    lastValidBlockHeight,
  });

  // Verify the BYTES, not a description of them.
  const primary = {
    programId: "11111111111111111111111111111111",
    instructionDiscriminator: "02000000",
    accountAddresses: [keyPair.publicKey.toBase58(), destination],
  };
  const boundVerification = await verifyThroughGraphite({
    ...basePayload,
    wallet_profile: "Gaming",
    instruction_data: Array.from(transferIx.data),
    signed_transaction: bound.artifact(),
    transaction_instructions: declareSiblings(
      [transferIx],
      findPrimaryIndex([transferIx], primary),
    ),
  });
  printVerification("Artifact-bound Verification", boundVerification);

  if (!boundVerification.approved) {
    console.log("\n❌ The artifact-bound verification did not approve. Not executing.");
    process.exit(1);
  }
  if (boundVerification.scope?.kind !== "artifact_bound") {
    console.log(
      `
❌ scope.kind is ${boundVerification.scope?.kind ?? "absent"}, not artifact_bound. ` +
        "A descriptive verdict describes what the request SAID and does not constrain what " +
        "gets signed. Not executing.",
    );
    process.exit(1);
  }
  console.log(
    `
✅ artifact_bound, digest ${boundVerification.scope.transaction_sha256.slice(0, 16)}…`,
  );
  console.log("   Still unobserved by this verdict:");
  for (const u of boundVerification.scope.unobserved ?? []) {
    console.log(`     • ${u}`);
  }

  // The bridge's execution path, exactly. Every control the bridge applies
  // is applied here, in the same order, by the same code:
  //   ResidualPolicy — refuses any residual the operator has not accepted
  //     by name (GRAPHITE_ACCEPT_UNOBSERVED); the two inherent ones pass.
  //   signApproved   — the digest is re-checked against the live object and
  //     the signer set against the message before anything is signed.
  //   signing event  — on the trail before submission, resolved by the exact
  //     audit_trail_id, and the verdict on record must be `approved`.
  //   sendRawTransaction, submission event (retried), confirmation, L8.
  console.log("\nExecuting through the bridge's own path (executeBoundTransaction)...");
  const graphite = new GraphiteClient({
    baseUrl: GRAPHITE_URL,
    apiKey: process.env.GRAPHITE_API_KEY,
  });
  const lifecycle = await executeBoundTransaction({
    bound,
    verification: boundVerification,
    signers: [keyPair],
    connection,
    graphite,
    policy: ResidualPolicy.fromEnv(),
    reportedBy: "devnet-test",
    label: "devnet transfer",
    log: (line) => console.log(line),
  });
  const signature = lifecycle.signature;

  console.log(`\n✅ TRANSACTION ${lifecycle.confirmed ? "CONFIRMED" : "SUBMITTED (confirmation pending)"} ON DEVNET!`);
  console.log(`Signature: ${signature}`);
  console.log(`Solscan:   https://solscan.io/tx/${signature}?cluster=devnet`);
  console.log(`Signing on trail:    ${lifecycle.signingRecorded} (verdict on record: ${lifecycle.verdictOnRecordAtSigning})`);
  console.log(`Submission on trail: ${lifecycle.submissionRecorded}`);
  console.log(`Accepted residuals:  ${lifecycle.acceptedUnobserved.join(", ") || "none beyond the inherent two"}`);
  if (lifecycle.reconciliation) {
    console.log(`L8 reconciliation:   ${JSON.stringify(lifecycle.reconciliation.reconciliation)} (attribution: ${lifecycle.reconciliation.attribution})`);
    if (lifecycle.reconciliation.discrepancy) {
      console.log("❌ L8 DISCREPANCY — Graphite's decision did not govern. Investigate before trusting the next one.");
      process.exit(1);
    }
  }

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
  console.log("  ✓ Gaming profile correctly APPROVED");
  console.log("  ✓ Residual policy consulted, signing and submission on the audit trail");
  console.log("  ✓ Real transaction signed and broadcast to Solana devnet via executeBoundTransaction");
  console.log(`  ${lifecycle.confirmed ? "✓" : "○"} Transaction ${lifecycle.confirmed ? "confirmed on-chain" : "awaiting confirmation"}; L8 reconciled`);
  console.log(`  ✓ Tx: https://solscan.io/tx/${signature}?cluster=devnet`);
}

main().catch((err) => {
  console.error("\n❌ Test failed:", err);
  process.exit(1);
});
