/**
 * Graphite as an MCP server: fund-moving tools for any MCP client (Claude,
 * Cursor, ElizaOS's MCP plugin, LangChain's MCP adapters, the AI SDK's MCP
 * client), each of which executes only through `GraphiteGuard`.
 *
 * The client's model writes the tool input — a request in words, and for a
 * swap the route instruction. The guard re-derives amount and destination from
 * the words and refuses a reading that disagrees, builds ONE transaction, has
 * Graphite Core verify those exact bytes and signs only on an artifact-bound
 * approval. Because a model can be talked into a request, two more bounds hold
 * whatever the Core says:
 *
 *   - a per-transfer cap is REQUIRED (`createGraphiteMcpServer` refuses a
 *     guard without one);
 *   - confirmation `"elicit"` (the default) asks a PERSON through MCP
 *     elicitation before every fund-moving call, showing the request the
 *     guard will act on. A client that cannot elicit is refused rather than
 *     executed for: the operator must choose `"none"` explicitly to run
 *     without a person in the loop.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { GraphiteGuard, type BoundInstructionPayload } from "../agent-guard/guard.js";
import { toolRefusalOf, toolResultOf, type GraphiteToolResult } from "../agent-guard/tool-results.js";

export type Confirmation = "elicit" | "none";

/** `GRAPHITE_MCP_CONFIRMATION`: unset or "elicit" asks a person; "none" does not. Anything else refuses to start. */
export function parseConfirmation(value: string | undefined): Confirmation {
  if (value === undefined || value === "" || value === "elicit") return "elicit";
  if (value === "none") return "none";
  throw new Error(
    `[Graphite] GRAPHITE_MCP_CONFIRMATION=${JSON.stringify(value)} is not "elicit" or "none". REFUSING TO START.`,
  );
}

function asContent(result: GraphiteToolResult) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(result) }],
    structuredContent: result as unknown as Record<string, unknown>,
    isError: !result.executed && result.refusedBy !== "graphite" && result.refusedBy !== "person" ? true : undefined,
  };
}

const accountMeta = z.object({
  pubkey: z.string().min(32).max(44),
  isSigner: z.boolean(),
  isWritable: z.boolean(),
});

/**
 * The server, bound to one guard. Throws unless the guard has a per-transfer
 * cap: an MCP client's model writes the requests these tools act on.
 */
export function createGraphiteMcpServer(guard: GraphiteGuard, options: { confirmation: Confirmation }): McpServer {
  if (guard.limits.maxTransferLamports === undefined) {
    throw new Error(
      "[Graphite] the MCP server needs a per-transfer cap: a client's model writes the requests its tools act on. " +
        "Set GRAPHITE_MAX_TRANSFER_LAMPORTS. REFUSING TO START.",
    );
  }
  const server = new McpServer({ name: "graphite", version: "0.1.0" });

  /** Ask a person, or say why the call is not run. Returns null when confirmed. */
  async function confirm(summary: string): Promise<GraphiteToolResult | null> {
    if (options.confirmation === "none") return null;
    if (!server.server.getClientCapabilities()?.elicitation) {
      return {
        executed: false,
        refusedBy: "person",
        reason:
          "this MCP client cannot ask a person to confirm (no elicitation capability), and the server is " +
          "configured to require confirmation (GRAPHITE_MCP_CONFIRMATION=elicit). Not executed.",
      };
    }
    const answer = await server.server.elicitInput({
      message: `Graphite: approve this request from the agent's wallet ${guard.publicKey}?\n\n${summary}`,
      requestedSchema: {
        type: "object",
        properties: { approve: { type: "boolean", title: "Approve", description: "Approve this request" } },
        required: ["approve"],
      },
    });
    if (answer.action === "accept" && answer.content?.approve === true) return null;
    return { executed: false, refusedBy: "person", reason: `the person did not approve (${answer.action}). Not executed.` };
  }

  server.registerTool(
    "graphite_wallet",
    {
      title: "Agent wallet",
      description: "The agent wallet's address and the operator's spending limits. Moves nothing.",
      inputSchema: {},
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async () => {
      const limits = guard.limits;
      const out = {
        address: guard.publicKey,
        maxTransferLamports: limits.maxTransferLamports?.toString(),
        allowedDestinations: limits.allowedDestinations,
      };
      return { content: [{ type: "text", text: JSON.stringify(out) }], structuredContent: out };
    },
  );

  server.registerTool(
    "graphite_transfer_sol",
    {
      title: "Transfer SOL (verified by Graphite)",
      description:
        "Transfer SOL from the agent wallet. Pass the user's own request, e.g. 'Transfer 0.05 SOL to <address>'. " +
        "Graphite re-derives the amount and destination from that text, verifies the exact transaction, and " +
        "signs only on its approval; anything over the operator's per-transfer cap is refused.",
      inputSchema: { request: z.string().min(1).max(500) },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    },
    async ({ request }) => {
      const refused = await confirm(`Transfer: ${request}`);
      if (refused) return asContent(refused);
      try {
        return asContent(toolResultOf(await guard.executeTransfer(request)));
      } catch (e) {
        return asContent(toolRefusalOf(e));
      }
    },
  );

  server.registerTool(
    "graphite_swap",
    {
      title: "Swap tokens (verified by Graphite)",
      description:
        "Swap tokens through a swap program, given the user's request and the EXACT route instruction (from a " +
        "route API). Graphite verifies that instruction as the bytes to be signed; without a route the swap is refused.",
      inputSchema: {
        request: z.string().min(1).max(500),
        route: z.object({
          programId: z.string().min(32).max(44),
          discriminator: z.string().regex(/^[0-9a-fA-F]{2,64}$/),
          accounts: z.array(accountMeta).min(1).max(64),
          instructionData: z.array(z.number().int().min(0).max(255)).max(4096),
          addressLookupTableAddresses: z.array(z.string().min(32).max(44)).max(8).optional(),
        }),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    },
    async ({ request, route }) => {
      const refused = await confirm(`Swap: ${request}\nprogram ${route.programId}`);
      if (refused) return asContent(refused);
      try {
        return asContent(toolResultOf(await guard.executeSwap(request, route satisfies BoundInstructionPayload)));
      } catch (e) {
        return asContent(toolRefusalOf(e));
      }
    },
  );

  return server;
}
