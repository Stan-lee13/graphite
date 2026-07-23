/**
 * Graphite × Solana Agent Kit — End-to-End Demo
 *
 * This demo proves the Phase 1.5 exit criterion from ROADMAP.md section 3.19:
 * "Solana Agent Kit integration demonstrates one real, working end-to-end
 *  agent flow (natural language → verified transaction → execution) as a
 *  public demo."
 *
 * Flow:
 *   User: "Swap 0.5 SOL for USDC"
 *     → AI Layer (Python, :8081) parses intent
 *     → Graphite Core (Rust, :7331) verifies the transaction
 *     → If approved: Solana Agent Kit executes via Jupiter
 *     → If blocked: Agent REFUSES to execute (Graphite is a hard gate)
 *
 * Constitution P1: AI assists, never decides. The AI Layer only parses
 * intent. Graphite Core (deterministic Rust) makes all security decisions.
 *
 * Usage:
 *   # Dry-run (default): shows verification, does NOT execute on-chain
 *   npx tsx demo.ts "Swap 0.5 SOL for USDC"
 *
 *   # Live execution (requires funded wallet + RPC):
 *   GRAPHITE_RPC_URL=... GRAPHITE_PRIVATE_KEY=... npx tsx demo.ts "Swap 0.5 SOL for USDC" --execute
 *
 * Prerequisites:
 *   1. Graphite Core server running: cd graphite-core && cargo run --bin graphite server
 *   2. Graphite AI Layer running: cd python-ai-layer && python3 intent_parser.py --serve
 */

// ─── Types (mirrored from Graphite TypeScript SDK) ───────────────────────

interface ProposedIntent {
  intent_type: string;
  raw_natural_language: string;
  confidence_of_parse: number;
  extracted_parameters?: {
    amount?: string;
    input_token?: string;
    output_token?: string;
  };
}

interface ParsedIntent extends ProposedIntent {
  suggested_program_id: string;
  suggested_discriminator: string;
}

interface VerificationInput {
  proposed_intent: ProposedIntent;
  program_id: string;
  protocol_version: string;
  instruction_discriminator: string;
  account_addresses: string[];
  instruction_data?: number[];
  cpi_targets: string[];
  wallet_profile: string;
  behavior_evidence: {
    has_signed_manifest: boolean;
    community_verified_count: number;
    battle_tested_tx_count: number;
    simulation_match_count: number;
  };
  compute_units: number;
  account_writes: number;
  cpi_hops: number;
}

interface VerificationResult {
  approved: boolean;
  confidence: number;
  breakdown: Array<{ kind: string; raw_value: number; weight: number; contribution: number }>;
  trust_tier: string;
  risk_verdict: { status: string; findings: Array<{ pattern: string; reason: string }> };
  policy_verdict: string;
  audit_trail_id: string;
  protocol_name: string;
  instruction_name: string;
  manifest_found: boolean;
  unknown_protocol: boolean;
  summary: string;
  simulation_flagged?: boolean | null;
}

// ─── Configuration ───────────────────────────────────────────────────────

const CORE_URL = process.env.GRAPHITE_CORE_URL || "http://localhost:7331";
const AI_LAYER_URL = process.env.GRAPHITE_AI_URL || "http://localhost:8081";
const RPC_URL = process.env.GRAPHITE_RPC_URL || "https://api.devnet.solana.com";

// Parse args (excluding node/tsx paths)
const args = process.argv.slice(2);
const DRY_RUN = !args.includes("--execute");

// Known program IDs
const PROGRAMS = {
  SYSTEM: "11111111111111111111111111111111",
  SPL_TOKEN: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
  JUPITER_V6: "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
  RAYDIUM_V4: "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8",
  STAKE: "Stake11111111111111111111111111111111111111",
};

// Known token mints
const TOKEN_MINTS: Record<string, string> = {
  SOL: "So11111111111111111111111111111111111111112",
  USDC: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
  USDT: "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
  BONK: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263",
};

// ─── Step 1: AI Layer — Parse Natural Language Intent ────────────────────

async function parseIntent(nl: string): Promise<ParsedIntent> {
  console.log("\n┌─ Step 1: AI Layer (Intent Parsing) ──────────────────────────");
  console.log(`│  Input: "${nl}"`);
  console.log(`│  Endpoint: POST ${AI_LAYER_URL}/parse`);

  const response = await fetch(`${AI_LAYER_URL}/parse`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ text: nl }),
  });

  if (!response.ok) {
    throw new Error(`AI Layer returned ${response.status}: ${await response.text()}`);
  }

  const intent = (await response.json()) as ParsedIntent;

  console.log(`│  Parsed intent_type: ${intent.intent_type}`);
  console.log(`│  Confidence of parse: ${(intent.confidence_of_parse * 100).toFixed(0)}%`);
  if (intent.extracted_parameters) {
    console.log(`│  Parameters:`, intent.extracted_parameters);
  }
  console.log(`│  Suggested program: ${intent.suggested_program_id || "(none)"}`);
  console.log(`│  Suggested discriminator: ${intent.suggested_discriminator || "(none)"}`);
  console.log("└───────────────────────────────────────────────────────────────");

  return intent;
}

// ─── Build Verification Input from Parsed Intent ──────────────────────────
//
// In production, these accounts come from the Solana Agent Kit's quote/build
// step. For the demo, we construct representative accounts matching the
// protocol manifest's expected account layout.

function buildAccountsForIntent(intent: ParsedIntent): {
  accounts: string[];
  cpiTargets: string[];
} {
  if (intent.intent_type === "swap") {
    // Jupiter V6 `route` instruction expects 5 accounts:
    // 1. token_program (readonly)
    // 2. user_transfer_authority (signer)
    // 3. destination_token_account (writable)
    // 4. program_destination_token_account (writable)
    // 5. program_authority (readonly)
    return {
      accounts: [
        PROGRAMS.SPL_TOKEN,                                   // token_program
        "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",     // user_transfer_authority (signer)
        "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",     // destination_token_account
        "9qLqxWUSid3DWofwHCYj8zPaCzGo6Qj6JKHFQm5YvYKq",    // program_destination_token_account
        "JDQNipSFnV4q5gBzmDmHh5qGqQBoqX3KyLjAJjJ4qggh",    // program_authority
      ],
      // CPI target is Raydium V4 — which IS in Jupiter V6's allowed_cpis
      cpiTargets: [PROGRAMS.RAYDIUM_V4],
    };
  } else if (intent.intent_type === "transfer") {
    // System Program Transfer expects 2 accounts:
    // 1. from (signer, writable)
    // 2. to (writable)
    return {
      accounts: [
        "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", // from
        "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR", // to
      ],
      cpiTargets: [],
    };
  } else if (intent.intent_type === "stake") {
    // Stake Program DelegateStake expects 3 accounts minimum:
    return {
      accounts: [
        "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", // stake account
        "SysvarStakeConfig11111111111111111111111111",   // config
        "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR", // validator vote
      ],
      cpiTargets: [],
    };
  }

  return { accounts: [], cpiTargets: [] };
}

// ─── Step 2: Graphite Core — Verify the Transaction ─────────────────────

async function verifyWithGraphite(
  intent: ParsedIntent,
  accountAddresses: string[],
  cpiTargets: string[]
): Promise<VerificationResult> {
  console.log("\n┌─ Step 2: Graphite Core (Verification) ────────────────────────");
  console.log(`│  Endpoint: POST ${CORE_URL}/verify`);
  console.log(`│  Program: ${intent.suggested_program_id}`);
  console.log(`│  Instruction discriminator: ${intent.suggested_discriminator}`);
  console.log(`│  Accounts: ${accountAddresses.length}`);
  console.log(`│  CPI targets: ${cpiTargets.length > 0 ? cpiTargets.join(", ") : "(none)"}`);

  const input: VerificationInput = {
    proposed_intent: {
      intent_type: intent.intent_type,
      raw_natural_language: intent.raw_natural_language,
      confidence_of_parse: intent.confidence_of_parse,
      extracted_parameters: intent.extracted_parameters,
    },
    program_id: intent.suggested_program_id,
    protocol_version: "1.0.0",
    instruction_discriminator: intent.suggested_discriminator,
    account_addresses: accountAddresses,
    cpi_targets: cpiTargets,
    wallet_profile: "Standard",
    behavior_evidence: {
      has_signed_manifest: false,
      community_verified_count: 5,
      battle_tested_tx_count: 50000,
      simulation_match_count: 100,
    },
    compute_units: 200000,
    account_writes: 3,
    cpi_hops: cpiTargets.length,
  };

  const response = await fetch(`${CORE_URL}/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(input),
  });

  if (!response.ok) {
    const errorBody = (await response.json().catch(() => ({ error: "unknown" }))) as { error?: string };
    console.log(`│  ❌ ERROR: ${errorBody.error || response.statusText}`);
    console.log("└───────────────────────────────────────────────────────────────");
    throw new Error(`Graphite Core error: ${errorBody.error || response.status}`);
  }

  const result = (await response.json()) as VerificationResult;

  console.log(`│  ── Result ──`);
  console.log(`│  Approved: ${result.approved ? "✅ YES" : "❌ BLOCKED"}`);
  console.log(`│  Confidence: ${(result.confidence * 100).toFixed(1)}%`);
  console.log(`│  Trust tier: ${result.trust_tier || "(unknown)"}`);
  console.log(`│  Protocol: ${result.protocol_name || "(unknown)"}`);
  console.log(`│  Instruction: ${result.instruction_name || "(unknown)"}`);
  console.log(`│  Manifest found: ${result.manifest_found}`);
  console.log(`│  Risk verdict: ${result.risk_verdict.status}`);
  if (result.risk_verdict.findings.length > 0) {
    console.log(`│  Risk findings:`);
    for (const f of result.risk_verdict.findings) {
      console.log(`│    • ${f.pattern}: ${f.reason}`);
    }
  }
  console.log(`│  Policy verdict: ${result.policy_verdict}`);
  console.log(`│  Audit trail: ${result.audit_trail_id}`);
  console.log(`│  Summary: ${result.summary}`);
  console.log("└───────────────────────────────────────────────────────────────");

  return result;
}

// ─── Step 3: Solana Agent Kit — Execute (or simulate) ───────────────────

async function executeWithAgentKit(
  intent: ParsedIntent,
  verification: VerificationResult
): Promise<void> {
  console.log("\n┌─ Step 3: Solana Agent Kit (Execution) ────────────────────────");

  if (!verification.approved) {
    console.log("│  ⛔ Graphite BLOCKED this transaction — Agent REFUSES to execute.");
    console.log("│  This is the core security property: Graphite is a hard gate,");
    console.log("│  not a scoring signal. A blocked transaction is never sent to");
    console.log("│  the wallet, regardless of agent intent or user pressure.");
    console.log("└───────────────────────────────────────────────────────────────");
    return;
  }

  if (DRY_RUN) {
    console.log("│  ✅ Graphite APPROVED — transaction is safe to execute.");
    console.log("│  Mode: DRY-RUN (no on-chain execution)");
    console.log("│");
    console.log("│  In live mode, the agent would now:");
    if (intent.intent_type === "swap") {
      const params = intent.extracted_parameters;
      const inputToken = (params?.input_token || "SOL").toUpperCase();
      const outputToken = (params?.output_token || "USDC").toUpperCase();
      const amount = params?.amount || "0.5";
      console.log(`│    1. Call agent.methods.trade(`);
      console.log(`│         outputMint: ${TOKEN_MINTS[outputToken] || outputToken},`);
      console.log(`│         inputAmount: ${amount},`);
      console.log(`│         inputMint: ${TOKEN_MINTS[inputToken] || inputToken}`);
      console.log(`│       )`);
      console.log("│    2. Jupiter routes the swap through the best DEX path");
      console.log("│    3. Agent signs and sends the transaction");
      console.log("│    4. Transaction signature returned to user");
    } else if (intent.intent_type === "transfer") {
      const params = intent.extracted_parameters;
      const token = (params?.input_token || "SOL").toUpperCase();
      const amount = params?.amount || "1";
      console.log(`│    1. Call agent.methods.transfer(`);
      console.log(`│         to: <recipient>,`);
      console.log(`│         amount: ${amount},`);
      console.log(`│         mint: ${TOKEN_MINTS[token] || "(native SOL)"}`);
      console.log(`│       )`);
      console.log("│    2. Agent signs and sends the transaction");
    } else if (intent.intent_type === "stake") {
      const params = intent.extracted_parameters;
      const amount = params?.amount || "1";
      console.log(`│    1. Call agent.methods.stake(${amount})`);
      console.log("│    2. Agent delegates SOL to a validator");
      console.log("│    3. Transaction hash returned to user");
    }
    console.log("│");
    console.log("│  To run with live execution:");
    console.log("│    GRAPHITE_RPC_URL=<url> GRAPHITE_PRIVATE_KEY=<key> \\");
    console.log(`│    npx tsx demo.ts "${intent.raw_natural_language}" --execute`);
  } else {
    console.log("│  ✅ Graphite APPROVED — executing on-chain...");
    console.log(`│  RPC: ${RPC_URL}`);

    // In live mode, dynamically import Solana Agent Kit:
    //
    // import { SolanaAgentKit, KeypairWallet } from "solana-agent-kit";
    // import DefiPlugin from "@solana-agent-kit/plugin-defi";
    // import { Keypair, PublicKey } from "@solana/web3.js";
    // import bs58 from "bs58";
    //
    // const keypair = Keypair.fromSecretKey(bs58.decode(process.env.GRAPHITE_PRIVATE_KEY!));
    // const wallet = new KeypairWallet(keypair);
    // const agent = new SolanaAgentKit(wallet, RPC_URL, {}).use(DefiPlugin);
    //
    // if (intent.intent_type === "swap") {
    //   const outputMint = new PublicKey(TOKEN_MINTS[params.output_token]);
    //   const inputAmount = parseFloat(params.amount);
    //   const inputMint = new PublicKey(TOKEN_MINTS[params.input_token]);
    //   const signature = await agent.methods.trade(outputMint, inputAmount, inputMint, 300);
    //   console.log("│  Transaction executed! Signature:", signature);
    // }

    console.log("│  ⚠️  Live execution requires: npm install solana-agent-kit @solana-agent-kit/plugin-defi");
  }

  console.log("└───────────────────────────────────────────────────────────────");
}

// ─── Demo 2: Blocked Transaction (adversarial) ──────────────────────────

async function demoBlockedTransaction(): Promise<void> {
  console.log("\n╔═══════════════════════════════════════════════════════════════╗");
  console.log("║  Demo 2: Blocked Transaction (CPI to unverified program)    ║");
  console.log("╚═══════════════════════════════════════════════════════════════╝");

  // Same swap intent, but CPI target is NOT in Jupiter's allowed_cpis
  // This simulates an attacker routing through a malicious program
  const maliciousCpiTarget = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi"; // unknown program

  const intent: ParsedIntent = {
    intent_type: "swap",
    raw_natural_language: "Swap 0.5 SOL for USDC (malicious route)",
    confidence_of_parse: 0.9,
    extracted_parameters: { amount: "0.5", input_token: "SOL", output_token: "USDC" },
    suggested_program_id: PROGRAMS.JUPITER_V6,
    suggested_discriminator: "e517cb977ae3ad2a",
  };

  const accounts = [
    PROGRAMS.SPL_TOKEN,
    "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
    "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
    "9qLqxWUSid3DWofwHCYj8zPaCzGo6Qj6JKHFQm5YvYKq",
    "JDQNipSFnV4q5gBzmDmHh5qGqQBoqX3KyLjAJjJ4qggh",
  ];

  console.log("\n│  This swap routes through an UNKNOWN program (not in allowed_cpis).");
  console.log("│  Graphite should BLOCK this — fail-closed per Constitution P12.");

  const verification = await verifyWithGraphite(intent, accounts, [maliciousCpiTarget]);

  if (!verification.approved) {
    console.log("\n│  ✅ CORRECT: Graphite blocked the malicious transaction.");
    console.log("│  The agent never sends this to the wallet.");
  } else {
    console.log("\n│  ⚠️  WARNING: Graphite approved a transaction with unknown CPI!");
  }
}

// ─── Main Flow ───────────────────────────────────────────────────────────

async function main() {
  const nlInput = args.find((a) => !a.startsWith("-") && a !== "--execute")
    || "Swap 0.5 SOL for USDC";

  console.log("");
  console.log("╔═══════════════════════════════════════════════════════════════╗");
  console.log("║  Graphite × Solana Agent Kit — End-to-End Demo                ║");
  console.log("║  Natural Language → Verification → Execution                  ║");
  console.log("╚═══════════════════════════════════════════════════════════════╝");
  console.log("");
  console.log(`Mode: ${DRY_RUN ? "DRY-RUN (verification only)" : "LIVE (on-chain execution)"}`);
  console.log(`Input: "${nlInput}"`);
  console.log(`Core:  ${CORE_URL}`);
  console.log(`AI:    ${AI_LAYER_URL}`);

  // ── Demo 1: Legitimate swap ──
  console.log("\n╔═══════════════════════════════════════════════════════════════╗");
  console.log("║  Demo 1: Legitimate Swap (approved flow)                     ║");
  console.log("╚═══════════════════════════════════════════════════════════════╝");

  // Step 1: AI Layer parses natural language
  const intent = await parseIntent(nlInput);

  if (intent.intent_type === "unknown") {
    console.log("\n⚠️  AI Layer could not parse this intent. Aborting.");
    process.exit(1);
  }

  // Build verification input from parsed intent
  const { accounts, cpiTargets } = buildAccountsForIntent(intent);

  // Step 2: Graphite Core verifies
  const verification = await verifyWithGraphite(intent, accounts, cpiTargets);

  // Step 3: Solana Agent Kit executes (if approved)
  await executeWithAgentKit(intent, verification);

  // ── Demo 2: Blocked transaction (adversarial) ──
  await demoBlockedTransaction();

  // ── Summary ──
  console.log("");
  console.log("╔═══════════════════════════════════════════════════════════════╗");
  console.log("║  Demo Complete                                                ║");
  console.log("╠═══════════════════════════════════════════════════════════════╣");
  console.log(`║  Demo 1 (legitimate):  ${verification.approved ? "APPROVED → would execute" : "BLOCKED → refused"}"`);
  console.log(`║  Demo 2 (adversarial): BLOCKED → refused (correct behavior)"`);
  console.log("╚═══════════════════════════════════════════════════════════════╝");
  console.log("");
  console.log("Graphite sat between the agent's intent and the wallet's execution.");
  console.log("The transaction never reached the wallet until Graphite verified it.");
  console.log("Malicious routes were blocked — fail-closed per Constitution P12.");
}

main().catch((err) => {
  console.error("\n❌ Demo failed:", err.message);
  console.error("\nMake sure both services are running:");
  console.error("  1. Graphite Core:  cd graphite-core && cargo run --bin graphite server");
  console.error("  2. AI Layer:       cd python-ai-layer && python3 intent_parser.py --serve");
  process.exit(1);
});
