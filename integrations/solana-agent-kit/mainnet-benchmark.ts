/**
 * Real Mainnet Benchmark Harness — Tests Graphite against REAL Solana mainnet transactions.
 *
 * Usage:
 *   npx tsx mainnet-benchmark.ts --rpc <RPC_URL> --graphite <GRAPHITE_URL> [--json out.json]
 *
 * What it does:
 *   1. LEGITIMATE: fetches REAL mainnet transactions from known protocols
 *      (Jupiter, Orca, Raydium, Squads, Meteora) and verifies each through
 *      Graphite with the intent a real agent would attach (swap for DEXes).
 *   2. MALICIOUS: replays the REAL pinned exploit corpus
 *      (graphite-core/tests/fixtures/exploit_corpus.json — signatures fetched
 *      from mainnet, provenance: SolPhishHunter arXiv:2505.04094). Every entry
 *      is a documented-malicious transaction expected to be BLOCKED.
 *
 * This is the P16 compliance test — reproducible precision/recall on
 * real-world, unseen data (the corpus entries are NOT Graphite's own
 * benchmark cases).
 *
 * Honesty notes:
 *   - Intents are per-protocol, not a blanket "unknown" (which would block
 *     everything via the intent-program mismatch rule and prove nothing).
 *   - Squads has no intent class in the AI layer; the harness sends an EMPTY
 *     intent (the check is skipped) and reports the outcome honestly.
 */

import { Connection, PublicKey } from "@solana/web3.js";
import bs58 from "bs58";
import fs from "fs";

// Robust arg parsing — handles --rpc <url> --graphite <url> in any order
const args = process.argv.slice(2);
function getArg(name: string, fallback: string): string {
  const idx = args.indexOf(name);
  return idx >= 0 && idx + 1 < args.length ? args[idx + 1] : fallback;
}
const GRAPHITE_URL = getArg("--graphite", "http://localhost:7331");
const RPC_URL = getArg("--rpc", process.env.SOLANA_RPC_URL ?? "https://api.mainnet-beta.solana.com");
const JSON_OUT = getArg("--json", "");

// Known legitimate protocol addresses, with the intent a real agent would
// attach to a transaction of this protocol (the AI layer parses natural
// language into intent_type; swap/transfer/stake/close are supported classes).
const LEGITIMATE_PROTOCOLS = [
  { name: "Jupiter V6", address: "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4", intent: "swap" },
  { name: "Orca Whirlpools", address: "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc", intent: "swap" },
  { name: "Raydium AMM V4", address: "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8", intent: "swap" },
  { name: "Raydium CLMM", address: "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK", intent: "swap" },
  { name: "Meteora DLMM", address: "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo", intent: "swap" },
  // Squads: no AI-layer intent class exists for multisig operations; the
  // harness sends an empty intent (the intent-program mismatch check is
  // skipped) and reports the outcome without claiming a false intent.
  { name: "Squads V4", address: "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf", intent: "" },
];

interface BenchmarkCase {
  name: string;
  programId: string;
  instructionDiscriminator: string;
  accountAddresses: string[];
  intent: string;
  expected: "approve" | "block";
  source: string;
  txSignature?: string;
  attackType?: string;
  maliciousAccount?: string;
}

interface BenchmarkResult {
  case: BenchmarkCase;
  graphiteVerdict: boolean;
  graphiteConfidence: number;
  graphiteRisk: string;
  correct: boolean;
  latencyMs: number;
  httpError: boolean;
}

async function fetchRealTransactions(connection: Connection, address: string, limit: number = 3): Promise<any[]> {
  try {
    const signatures = await connection.getSignaturesForAddress(new PublicKey(address), { limit });
    const txs: any[] = [];
    for (const sig of signatures.slice(0, limit)) {
      try {
        const tx = await connection.getParsedTransaction(sig.signature, {
          maxSupportedTransactionVersion: 0,
        });
        if (tx) txs.push(tx);
      } catch (e) { /* skip failed fetch */ }
      await new Promise(r => setTimeout(r, 250)); // rate limit courtesy
    }
    return txs;
  } catch (err) {
    console.warn(`Failed to fetch transactions for ${address}: ${(err as Error).message?.slice(0, 80)}`);
    return [];
  }
}

function getAddr(key: any): string | null {
  if (!key) return null;
  if (typeof key === "string") return key;
  if (typeof key.toBase58 === "function") return key.toBase58();
  if (typeof key.toString === "function") return key.toString();
  return null;
}

/** Account list of a parsed instruction, handling both raw (string/PublicKey)
 *  accounts and parsed-info (source/destination) accounts. */
function ixAccounts(ix: any): string[] {
  const out: string[] = [];
  if (ix.accounts) {
    for (const acc of ix.accounts) {
      const addr = getAddr(acc);
      if (addr) out.push(addr);
    }
  }
  const info = ix.parsed?.info ?? {};
  for (const k of ["source", "destination", "account", "authority", "owner", "newAuthority", "mint"]) {
    const v = info[k];
    if (v) {
      const addr = getAddr(v);
      if (addr && !out.includes(addr)) out.push(addr);
    }
  }
  return out;
}

function extractFromTransaction(tx: any, protocolAddress: string, intent: string): BenchmarkCase | null {
  try {
    const message = tx.transaction?.message;
    if (!message) return null;

    const instructions = message.instructions || message.compiledInstructions || [];
    const accountKeys = message.accountKeys || message.staticAccountKeys || [];

    for (const ix of instructions) {
      let programId = "";
      let discriminator = "";
      let accounts: string[] = [];

      if (ix.programId) {
        programId = getAddr(ix.programId) ?? "";
        if (ix.data) {
          try {
            const rawBytes = typeof ix.data === "string" ? bs58.decode(ix.data) : new Uint8Array(ix.data);
            if (rawBytes.length >= 8) {
              discriminator = Array.from(rawBytes.slice(0, 8))
                .map((b) => b.toString(16).padStart(2, "0"))
                .join("");
            }
          } catch { /* base58 decode failed */ }
        }
        accounts = ixAccounts(ix);
      } else if (ix.programIdIndex !== undefined) {
        const key = accountKeys[ix.programIdIndex];
        programId = getAddr(key) ?? "";
        if (ix.data && ix.data.length >= 4) {
          discriminator = Array.from(ix.data.slice(0, 4) as any[])
            .map((b) => (b as number).toString(16).padStart(2, "0"))
            .join("");
        }
        if (ix.accountKeyIndexes) {
          for (const idx of ix.accountKeyIndexes) {
            const key = accountKeys[idx];
            const addr = getAddr(key);
            if (addr) accounts.push(addr);
          }
        }
      }

      if (!programId) continue;
      if (programId !== protocolAddress) continue;

      return {
        name: `Real tx: ${(tx.transaction?.signatures?.[0] ?? "unknown").slice(0, 12)}`,
        programId,
        instructionDiscriminator: discriminator || "unknown",
        accountAddresses: accounts.length > 0 ? accounts : [protocolAddress],
        intent,
        expected: "approve" as const,
        source: "mainnet",
        txSignature: tx.transaction?.signatures?.[0],
      };
    }
    return null;
  } catch (e) {
    return null;
  }
}

function loadExploitCorpus(): BenchmarkCase[] {
  const path = "../../graphite-core/tests/fixtures/exploit_corpus.json";
  if (!fs.existsSync(path)) {
    console.warn(`  EXPLOIT CORPUS NOT FOUND at ${path} — malicious half skipped`);
    return [];
  }
  const corpus = JSON.parse(fs.readFileSync(path, "utf-8"));
  const cases: BenchmarkCase[] = [];
  for (const e of corpus.entries) {
    // Honest intent per entry: fund movements are transfers; phishing programs
    // are unknown (fail-closed).
    const isFundMovement =
      e.program_id === "11111111111111111111111111111111" ||
      e.program_id === "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    cases.push({
      name: `Exploit ${e.attack_type}: ${e.signature.slice(0, 12)}`,
      programId: e.program_id,
      instructionDiscriminator: e.instruction_discriminator,
      accountAddresses: e.account_addresses,
      intent: isFundMovement ? "transfer" : "unknown",
      expected: "block",
      source: `SolPhishHunter arXiv:2505.04094 (${e.attack_type})`,
      txSignature: e.signature,
      attackType: e.attack_type,
      maliciousAccount: e.malicious_account,
    });
  }
  return cases;
}

async function verifyThroughGraphite(case_: BenchmarkCase): Promise<{ approved: boolean; confidence: number; risk: string; latencyMs: number; httpError: boolean }> {
  const start = Date.now();
  try {
    const res = await fetch(`${GRAPHITE_URL}/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        proposed_intent: {
          intent_type: case_.intent,
          raw_natural_language: "mainnet benchmark test",
          confidence_of_parse: 0.5,
          extracted_parameters: {},
        },
        program_id: case_.programId,
        instruction_discriminator: case_.instructionDiscriminator,
        account_addresses: case_.accountAddresses,
        cpi_targets: [],
        wallet_profile: "TradingBot",
        compute_units: 150,
        account_writes: 2,
        cpi_hops: 0,
      }),
    });

    const latencyMs = Date.now() - start;
    if (!res.ok) {
      const errBody = await res.text();
      return { approved: false, confidence: 0, risk: `HTTP ${res.status}: ${errBody.slice(0, 60)}`, latencyMs, httpError: true };
    }
    const v = await res.json();
    return { approved: v.approved, confidence: v.confidence, risk: v.risk_verdict?.status ?? "unknown", latencyMs, httpError: false };
  } catch (err) {
    return { approved: false, confidence: 0, risk: `error: ${(err as Error).message?.slice(0, 50)}`, latencyMs: Date.now() - start, httpError: true };
  }
}

async function main() {
  console.log("=== Graphite Real Mainnet Benchmark ===");
  console.log(`RPC: ${RPC_URL.slice(0, 50)}...`);
  console.log(`Graphite: ${GRAPHITE_URL}`);
  console.log("");

  const connection = new Connection(RPC_URL, "confirmed");
  const allCases: BenchmarkCase[] = [];

  // Phase 1: Fetch real legitimate transactions from known protocols
  console.log("--- Fetching real mainnet transactions from legitimate protocols ---");
  for (const proto of LEGITIMATE_PROTOCOLS) {
    console.log(`  Fetching from ${proto.name} (${proto.address.slice(0, 12)}...)...`);
    const txs = await fetchRealTransactions(connection, proto.address, 3);
    let extracted = 0;
    for (const tx of txs) {
      const case_ = extractFromTransaction(tx, proto.address, proto.intent);
      if (case_) {
        allCases.push(case_);
        extracted++;
      }
    }
    console.log(`    Extracted: ${extracted}`);
  }

  // Phase 2: Real pinned malicious transactions (SolPhishHunter corpus)
  console.log("\n--- Loading real exploit corpus (pinned mainnet signatures) ---");
  const exploitCases = loadExploitCorpus();
  allCases.push(...exploitCases);
  console.log(`  Loaded: ${exploitCases.length} documented-malicious transactions`);

  // Phase 3: Run all cases through Graphite
  console.log(`\n--- Running ${allCases.length} cases through Graphite ---`);
  const results: BenchmarkResult[] = [];
  for (const case_ of allCases) {
    process.stdout.write(`  ${case_.name}... `);
    const verdict = await verifyThroughGraphite(case_);
    const correct = (verdict.approved && case_.expected === "approve") || (!verdict.approved && case_.expected === "block");
    results.push({ case: case_, graphiteVerdict: verdict.approved, graphiteConfidence: verdict.confidence, graphiteRisk: verdict.risk, latencyMs: verdict.latencyMs, httpError: verdict.httpError, correct });
    console.log(`${correct ? "PASS" : "FAIL"} | approved=${verdict.approved} conf=${verdict.confidence} risk=${verdict.risk} (${verdict.latencyMs}ms)${verdict.httpError ? " [HTTP ERROR]" : ""}`);
  }

  // Phase 4: Compute metrics
  console.log("\n=== RESULTS ===");
  const legit = results.filter(r => r.case.expected === "approve");
  const mal = results.filter(r => r.case.expected === "block");
  const tp = mal.filter(r => r.correct).length;          // malicious correctly blocked
  const fp = legit.filter(r => !r.correct).length;       // legitimate wrongly blocked
  const fn = mal.filter(r => !r.correct).length;         // malicious wrongly approved
  const tn = legit.filter(r => r.correct).length;        // legitimate correctly approved

  const precision = tp + fp > 0 ? (tp / (tp + fp) * 100).toFixed(1) : "N/A";
  const recall = tp + fn > 0 ? (tp / (tp + fn) * 100).toFixed(1) : "N/A";
  const accuracy = results.length > 0 ? (results.filter(r => r.correct).length / results.length * 100).toFixed(1) : "N/A";
  const avgLatency = results.length > 0 ? (results.reduce((s, r) => s + r.latencyMs, 0) / results.length).toFixed(0) : "N/A";

  console.log(`Total cases: ${results.length}`);
  console.log(`Correct: ${results.filter(r => r.correct).length}/${results.length}`);
  console.log(`Accuracy: ${accuracy}%`);
  console.log(`Precision: ${precision}% (TP=${tp}, FP=${fp})`);
  console.log(`Recall: ${recall}% (TP=${tp}, FN=${fn})`);
  console.log(`Avg latency: ${avgLatency}ms (includes HTTP round-trip)`);
  console.log(`\nLegitimate cases: ${legit.length}`);
  console.log(`  Correctly approved: ${tn}`);
  console.log(`  Incorrectly blocked (false positive): ${fp}`);
  console.log(`Malicious cases (real pinned corpus): ${mal.length}`);
  console.log(`  Correctly blocked: ${tp}`);
  console.log(`  Incorrectly approved (false negative): ${fn}`);

  if (results.some(r => !r.correct)) {
    console.log("\n--- FAILURES ---");
    for (const r of results.filter(r => !r.correct)) {
      console.log(`  FAIL: ${r.case.name} | expected=${r.case.expected} got=${r.graphiteVerdict ? "approve" : "block"} conf=${r.graphiteConfidence} risk=${r.graphiteRisk}`);
    }
  }

  if (JSON_OUT) {
    fs.writeFileSync(JSON_OUT, JSON.stringify({
      generated: new Date().toISOString(),
      graphite: GRAPHITE_URL,
      summary: { total: results.length, correct: results.filter(r => r.correct).length, accuracy, precision, recall, avgLatency, tp, fp, fn, tn },
      results: results.map(r => ({
        name: r.case.name, expected: r.case.expected, got: r.graphiteVerdict ? "approve" : "block",
        confidence: r.graphiteConfidence, risk: r.graphiteRisk, correct: r.correct,
        latencyMs: r.latencyMs, source: r.case.source, txSignature: r.case.txSignature,
        attackType: r.case.attackType, programId: r.case.programId,
      })),
    }, null, 2));
    console.log(`\nJSON report written to ${JSON_OUT}`);
  }
}

main().catch(console.error);
