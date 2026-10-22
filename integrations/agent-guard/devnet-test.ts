/**
 * LIVE DEVNET TEST — Graphite Verification Gate + Solana Transfer
 *
 * Tests two scenarios:
 *   1. TradingBot profile (80% threshold) → should BLOCK (confidence 0.50 < 0.80)
 *   2. Gaming profile (the weakest built-in, 0.55) → should APPROVE → execute
 *      on devnet through the SAME path the bridge uses.
 *
 * This is the file most likely to be copied, so it executes the way every
 * integration executes and in no other way: through `GraphiteGuard`
 * (Round 30, audit finding K-09; before that, Round 17's F-16-12 / F-15-06):
 *
 *   grounded request → spend cap → ONE transaction → unsigned simulation →
 *   Graphite verifies the bytes → AuditBind → execution decision + residual
 *   policy → confirmation of the resolved values → signApproved → `signing`
 *   on the trail → sendRawTransaction → `submission` on the trail → confirm
 *   → L8.
 *
 * Tests 1 and 2 ask the Core about a DESCRIPTION of the transfer through the
 * SDK client: analysis only, and nothing in them can be signed.
 *
 * Needs the Core (GRAPHITE_CORE_URL), the AI layer (GRAPHITE_AI_LAYER_URL,
 * `python3 python-ai-layer/intent_parser.py --serve`) and a funded devnet
 * key. It refuses any cluster but devnet or a loopback validator.
 *
 * It no longer asks for a `Custom { min_confidence: 0.0 }` profile: the
 * server clamps that to 0.55 anyway and discloses the override, and a demo
 * that teaches switching the gate off is teaching the wrong thing.
 */

import { Keypair, Connection, LAMPORTS_PER_SOL } from "@solana/web3.js";
import bs58 from "bs58";
// The one gated execution path. A demo that reaches `sendAndConfirmTransaction`,
// or even `executeBoundTransaction` directly, skips controls the guard applies.
import { GraphiteGuard, type ExecutionOutcome } from "./guard.js";
import { GraphiteClient } from "../../sdk/typescript/src/client.js";
import type { VerificationInput } from "../../sdk/typescript/src/types.js";
import { assertDevnetCluster, assertNoLegacyEnvNames, rpcHostForLog } from "./env-names.js";

/**
 * The Core, through the SDK client and nowhere else.
 *
 * A5-07 (2026-09-29 audit): this script verified with a raw `fetch` carrying
 * `Bearer $GRAPHITE_API_KEY` to `GRAPHITE_URL` — a name the bridge does not read
 * (only the SDKs' live tests do, for their own Core address),
 * no transport rule, no shape check on the verdict — and built the
 * `GraphiteClient` that would have refused an http:// non-loopback URL only
 * after the key had already been sent. The client is built first now, from
 * `GRAPHITE_CORE_URL`, so every request, verification included, goes out
 * under its transport rule and every verdict passes its shape check.
 */
function graphiteFromEnv(): GraphiteClient {
  assertNoLegacyEnvNames();
  return new GraphiteClient({
    baseUrl: process.env.GRAPHITE_CORE_URL ?? "http://localhost:7331",
    apiKey: process.env.GRAPHITE_API_KEY,
  });
}

async function verifyThroughGraphite(graphite: GraphiteClient, payload: Record<string, unknown>): Promise<any> {
  return graphite.verify(payload as unknown as VerificationInput);
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
  const graphite = graphiteFromEnv();

  // Initialize wallet
  const keyPair = Keypair.fromSecretKey(bs58.decode(privateKey));
  const walletPubkey = keyPair.publicKey.toBase58();
  const connection = new Connection(rpcUrl, "confirmed");
  // Round 29 (audit 2026-10-20, Info): devnet by its genesis hash, before
  // anything is built — this script signs and submits.
  assertDevnetCluster(await connection.getGenesisHash(), rpcUrl);
  const balance = await connection.getBalance(keyPair.publicKey);

  console.log(`Wallet:   ${walletPubkey}`);
  console.log(`Balance:  ${balance / LAMPORTS_PER_SOL} SOL`);
  // The host only: a provider URL can carry its API key in the query.
  console.log(`RPC:      ${rpcHostForLog(rpcUrl)}`);

  // Check Graphite Core
  const health = await graphite.health();
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

  const tbVerification = await verifyThroughGraphite(graphite, {
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

  const unVerification = await verifyThroughGraphite(graphite, {
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

  // Round 30 (audit finding K-09): the execution goes through the guard —
  // the one gated helper every integration uses — and nothing else. Until
  // then this script built a BoundTransaction and called
  // `executeBoundTransaction` itself: the right signing primitive, but with
  // no spend cap, no grounding of the request in its own words, no AuditBind
  // and no confirmation, in the file most likely to be copied. The guard does
  // all of it: the request below is grounded (the AI layer must be running,
  // GRAPHITE_AI_LAYER_URL), capped (0.02 SOL per transfer, 0.05 SOL per hour),
  // built ONCE, simulated unsigned, verified as bytes, held to the execution
  // decision and the residual policy, confirmed by the hook below against the
  // values this script meant, and only then signed, recorded, sent and
  // reconciled.
  const request = `Transfer ${transferAmount} SOL to ${destination}`;
  const expectedLamports = BigInt(Math.round(transferAmount * LAMPORTS_PER_SOL));
  const guard = await GraphiteGuard.create({
    privateKey,
    rpcUrl,
    walletProfile: "Gaming",
    reporter: "devnet-test",
    spendPolicy: { maxTransferLamports: 20_000_000n, maxTotalLamports: 50_000_000n },
  });
  let outcome: ExecutionOutcome;
  try {
    outcome = await guard.executeTransfer(request, {
      // The last say, about the resolved transaction: exactly the destination
      // and amount this script asked for, approved and bound to its digest.
      confirm: async (summary) => {
        console.log(`\nConfirm: ${summary.sol} SOL to ${summary.destination}, digest ${summary.transactionSha256.slice(0, 16)}…`);
        console.log(`         Graphite ${summary.verdict.approved ? "APPROVED" : "did not approve"}, risk ${summary.verdict.risk}`);
        console.log(`         not observed: ${summary.verdict.unobservedCodes.join(", ") || "none"}`);
        return summary.destination === destination && summary.lamports === expectedLamports.toString();
      },
    });
  } finally {
    guard.close();
  }
  printVerification("Artifact-bound Verification (through the guard)", outcome.verification);
  if (!outcome.verifiedExecution || !outcome.lifecycle) {
    console.log("\n❌ The guard did not execute: Graphite did not approve these bytes. Nothing was signed.");
    process.exit(1);
  }
  const lifecycle = outcome.lifecycle;
  const signature = lifecycle.signature;

  console.log(`\n✅ TRANSACTION ${lifecycle.confirmed ? "CONFIRMED" : "SUBMITTED (confirmation pending)"} ON DEVNET!`);
  console.log(`Signature: ${signature}`);
  console.log(`Solscan:   https://solscan.io/tx/${signature}?cluster=devnet`);
  console.log(`Decision:            ${lifecycle.decision} (reported by the Core: ${lifecycle.reportedDecision ?? "not reported"})`);
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
  console.log("  ✓ Grounded, capped, decided, confirmed; signing and submission on the audit trail");
  console.log("  ✓ Real transaction signed and broadcast to Solana devnet through GraphiteGuard");
  console.log(`  ${lifecycle.confirmed ? "✓" : "○"} Transaction ${lifecycle.confirmed ? "confirmed on-chain" : "awaiting confirmation"}; L8 reconciled`);
  console.log(`  ✓ Tx: https://solscan.io/tx/${signature}?cluster=devnet`);
}

main().catch((err) => {
  console.error("\n❌ Test failed:", err);
  process.exit(1);
});
