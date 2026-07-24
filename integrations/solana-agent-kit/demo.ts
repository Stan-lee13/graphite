/**
 * Graphite + Solana Agent Kit — End-to-End Demo
 *
 * Demonstrates the full flow:
 *   Natural Language → AI Layer (parse) → SAK (construct) → Graphite (verify) → SAK (execute if approved)
 *
 * Prerequisites:
 *   1. Graphite Core running:  cargo run --release -- server  (in graphite-core/)
 *   2. Python AI Layer running:  python3 intent_parser.py --serve  (in python-ai-layer/)
 *   3. Environment variables set:
 *        SOLANA_PRIVATE_KEY — base58-encoded keypair secret key
 *        SOLANA_RPC_URL — Solana RPC endpoint (devnet or mainnet)
 *        OPENAI_API_KEY — OpenAI API key for SAK
 *
 * Run:
 *   npx tsx demo.ts              # Interactive mode
 *   npx tsx demo.ts "Swap 1 SOL for USDC"  # Single command
 *
 * Phase 1.5 Exit Criteria (ROADMAP.md):
 *   "Solana Agent Kit integration demonstrates one real, working end-to-end agent flow
 *    (natural language -> verified transaction -> execution) as a public demo."
 */

import { VerifiedSakAgent } from "./graphite-sak-bridge.js";

async function main() {
  const command = process.argv[2];

  console.log("\n╔══════════════════════════════════════════════════════════════╗");
  console.log("║  Graphite + Solana Agent Kit — Verified Transaction Demo    ║");
  console.log("║  Every transaction verified by Graphite before execution     ║");
  console.log("╚══════════════════════════════════════════════════════════════╝\n");

  // Initialize the verified agent
  console.log("[1/4] Initializing verified SAK agent...");
  let agent: VerifiedSakAgent;
  try {
    agent = await VerifiedSakAgent.create();
  } catch (e) {
    console.error("Failed to initialize agent:", (e as Error).message);
    console.error("\nMake sure:");
    console.error("  1. Graphite Core is running: cargo run --release -- server");
    console.error("  2. Python AI Layer is running: python3 intent_parser.py --serve");
    console.error("  3. SOLANA_PRIVATE_KEY, SOLANA_RPC_URL, and OPENAI_API_KEY are set");
    process.exit(1);
  }
  console.log("[1/4] ✅ Agent initialized\n");

  // Determine what to do
  const intent = command ?? "Swap 0.1 SOL for USDC";

  console.log(`[2/4] Parsing intent: "${intent}"`);

  // Parse intent through AI Layer (advisory only — P1)
  const proposedIntent = await agent.parseIntent(intent);
  console.log(`[2/4] ✅ Parsed: ${proposedIntent.intent_type} (parse confidence: ${proposedIntent.confidence_of_parse})`);
  console.log(`       Parameters: ${JSON.stringify(proposedIntent.extracted_parameters ?? {})}\n`);

  // Execute based on intent type
  console.log(`[3/4] Verifying and executing...\n`);

  let result;
  switch (proposedIntent.intent_type) {
    case "swap":
    case "trade":
    case "exchange":
      result = await agent.executeSwap(intent);
      break;
    case "transfer":
    case "send":
      result = await agent.executeTransfer(intent);
      break;
    default:
      console.log(`[3/4] Intent type "${proposedIntent.intent_type}" not supported for execution demo.`);
      console.log("       Supported: swap, transfer");
      process.exit(0);
  }

  // Report results
  console.log(`\n[4/4] Result:`);
  console.log(`  Executed: ${result.executed ? "✅ YES" : "❌ NO (blocked by Graphite)"}`);
  console.log(`  Verification:`);
  console.log(`    Approved: ${result.verification.approved}`);
  console.log(`    Confidence: ${result.verification.confidence}`);
  console.log(`    Trust Tier: ${result.verification.trust_tier}`);
  console.log(`    Risk: ${result.verification.risk_verdict.status}`);
  if (result.verification.risk_verdict.findings.length > 0) {
    console.log(`    Findings:`);
    for (const f of result.verification.risk_verdict.findings) {
      console.log(`      — ${f.pattern}: ${f.reason}`);
    }
  }
  console.log(`    Summary: ${result.verification.summary}`);
  if (result.executed && result.result) {
    console.log(`  SAK Result: ${JSON.stringify(result.result, null, 2)}`);
  }
  console.log("");
}

main().catch((e) => {
  console.error("Fatal error:", e);
  process.exit(1);
});
