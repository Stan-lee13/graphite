/**
 * Run one request through the guard from a terminal.
 *
 *   npx tsx cli.ts transfer "Transfer 0.05 SOL to <address>"
 *   npx tsx cli.ts swap "Swap 0.1 SOL for USDC" route.json
 *
 * This is the guard's real path, not a simulation of it: when Graphite Core
 * approves, the transaction is signed with SOLANA_PRIVATE_KEY and submitted to
 * SOLANA_RPC_URL, on whatever cluster that names. Everything is configured by
 * the environment `GraphiteGuard.create()` reads (SOLANA_PRIVATE_KEY,
 * SOLANA_RPC_URL, GRAPHITE_CORE_URL, GRAPHITE_API_KEY, GRAPHITE_AI_LAYER_URL,
 * GRAPHITE_WALLET_PROFILE, GRAPHITE_TRANSACTION_VERSION,
 * GRAPHITE_ACCEPT_UNOBSERVED).
 *
 * A swap needs the exact route instruction (`BoundInstructionPayload`: program,
 * accounts with their signer/writable flags, data, optional lookup tables) in a
 * JSON file; without it the guard refuses, because a verdict about a
 * description is not a verdict about the instruction that would be signed.
 *
 * Exit status: 0 for a verified execution, 2 for a refusal by Graphite, 1 for
 * an error (including any refusal raised before the Core was asked).
 */
import { readFileSync } from "node:fs";
import { GraphiteGuard, type BoundInstructionPayload, type ExecutionOutcome } from "./guard.js";

const USAGE =
  'usage: tsx cli.ts transfer "<request>"\n' + '       tsx cli.ts swap "<request>" <route-payload.json>';

function report(outcome: ExecutionOutcome): number {
  const v = outcome.verification;
  console.log(`approved:   ${v.approved}`);
  console.log(`confidence: ${v.confidence}`);
  console.log(`trust tier: ${v.trust_tier}`);
  console.log(`risk:       ${v.risk_verdict.status}`);
  for (const f of v.risk_verdict.findings) console.log(`  - ${f.pattern}: ${f.reason}`);
  console.log(`audit id:   ${v.audit_trail_id}`);
  if (!outcome.verifiedExecution) {
    console.log("NOT EXECUTED: Graphite did not approve these bytes.");
    return 2;
  }
  const lc = outcome.lifecycle;
  console.log(`executed:   ${outcome.signature}`);
  if (lc) {
    console.log(`confirmed:  ${lc.confirmed}${lc.confirmationError ? ` (${lc.confirmationError})` : ""}`);
    if (lc.rpcReportedSignature) console.log(`WARNING: the RPC reported ${lc.rpcReportedSignature}`);
    if (lc.reconciliation) {
      console.log(`L8:         ${JSON.stringify(lc.reconciliation.reconciliation)}`);
      if (lc.reconciliation.discrepancy) console.log("L8 DISCREPANCY: Graphite's decision did not govern.");
    } else if (lc.reconciliationError) {
      console.log(`L8 error:   ${lc.reconciliationError}`);
    }
  }
  return 0;
}

async function main(argv: string[]): Promise<number> {
  const [command, request, payloadPath] = argv;
  if (!command || !request || (command !== "transfer" && command !== "swap")) {
    console.error(USAGE);
    return 1;
  }
  if (command === "swap" && !payloadPath) {
    console.error("a swap needs the route instruction as a JSON payload file\n" + USAGE);
    return 1;
  }
  const guard = await GraphiteGuard.create({ reporter: "agent-guard-cli" });
  console.log(`wallet:     ${guard.publicKey}`);
  if (command === "transfer") {
    return report(await guard.executeTransfer(request));
  }
  const payload = JSON.parse(readFileSync(payloadPath!, "utf8")) as BoundInstructionPayload;
  return report(await guard.executeSwap(request, payload));
}

// `process.exitCode`, not `process.exit()`: exiting while the RPC client's
// sockets are still open crashes Node on Windows (0xC0000409) and loses the
// report's last lines.
main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (e) => {
    console.error(`refused: ${e instanceof Error ? e.message : String(e)}`);
    process.exitCode = 1;
  },
);
