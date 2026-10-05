/**
 * Run Graphite as a stdio MCP server.
 *
 *   GRAPHITE_MAX_TRANSFER_LAMPORTS=100000000 npx tsx server.ts
 *
 * Configured entirely by the environment `GraphiteGuard.create()` reads
 * (SOLANA_PRIVATE_KEY, SOLANA_RPC_URL, GRAPHITE_CORE_URL, GRAPHITE_API_KEY,
 * GRAPHITE_AI_LAYER_URL, GRAPHITE_WALLET_PROFILE,
 * GRAPHITE_TRANSACTION_VERSION, GRAPHITE_ACCEPT_UNOBSERVED,
 * GRAPHITE_MAX_TRANSFER_LAMPORTS — required — and
 * GRAPHITE_ALLOWED_DESTINATIONS), plus GRAPHITE_MCP_CONFIRMATION ("elicit",
 * the default, or "none").
 *
 * This is the real path: a confirmed request that Graphite approves is signed
 * and submitted on whatever cluster SOLANA_RPC_URL names.
 *
 * stdout carries the MCP protocol. Every log line — the guard's included —
 * goes to stderr, or a log line would be read as a malformed message.
 */
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { GraphiteGuard } from "../agent-guard/guard.js";
import { createGraphiteMcpServer, parseConfirmation } from "./graphite-mcp.js";

console.log = (...args: unknown[]) => console.error(...args);
console.info = (...args: unknown[]) => console.error(...args);

async function main(): Promise<void> {
  const confirmation = parseConfirmation(process.env.GRAPHITE_MCP_CONFIRMATION);
  const guard = await GraphiteGuard.create({ reporter: "mcp-server" });
  const server = createGraphiteMcpServer(guard, { confirmation });
  await server.connect(new StdioServerTransport());
  console.error(
    `[Graphite] MCP server on stdio — wallet ${guard.publicKey}, confirmation ${confirmation}, ` +
      `cap ${guard.limits.maxTransferLamports} lamports per transfer`,
  );
}

main().catch((e) => {
  console.error(`[Graphite] MCP server refused to start: ${e instanceof Error ? e.message : String(e)}`);
  process.exitCode = 1;
});
