/**
 * Run Graphite as a stdio MCP server.
 *
 *   GRAPHITE_MAX_TRANSFER_LAMPORTS=100000000 npx tsx server.ts
 *
 * Configured entirely by the environment `GraphiteGuard.create()` reads
 * (SOLANA_PRIVATE_KEY, SOLANA_RPC_URL, GRAPHITE_CORE_URL, GRAPHITE_API_KEY,
 * GRAPHITE_AI_LAYER_URL, GRAPHITE_WALLET_PROFILE,
 * GRAPHITE_TRANSACTION_VERSION, GRAPHITE_ACCEPT_UNOBSERVED,
 * GRAPHITE_MAX_TRANSFER_LAMPORTS — required — GRAPHITE_ALLOWED_DESTINATIONS,
 * GRAPHITE_MAX_TOTAL_LAMPORTS, GRAPHITE_SPEND_WINDOW_SECONDS and the swap
 * settings GRAPHITE_SWAP_*; see ../solana-agent-kit/.env.example for the full
 * list), plus GRAPHITE_MCP_CONFIRMATION ("elicit", the default, or "none").
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

// Every console method that writes to stdout, not only log/info (audit
// 2026-10-20, Info: debug, dir and table still went to stdout). warn, error
// and trace already write to stderr.
const toStderr = (...args: unknown[]) => console.error(...args);
console.log = toStderr;
console.info = toStderr;
console.debug = toStderr;
console.dir = (item: unknown) => console.error(item);
console.table = (data: unknown) => console.error(data);

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
