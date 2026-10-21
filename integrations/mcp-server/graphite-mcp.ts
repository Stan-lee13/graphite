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
 *     elicitation before every fund-moving call. A client that cannot elicit
 *     is refused rather than executed for: the operator must choose `"none"`
 *     explicitly to run without a person in the loop.
 *
 * Round 29 (audit 2026-10-20, M7): the person used to be asked FIRST, shown
 * the model's raw text before anything had been parsed, grounded, capped,
 * built, simulated or verified — so they approved words, never the
 * destination, amount or effect the guard then resolved, and were asked to
 * approve requests the cap refused a moment later. The question is now the
 * guard's confirmation hook: asked after grounding, the spend policy, the
 * build, the simulation, Graphite's verdict and the residual policy,
 * immediately before signing, and it shows the resolved destination and
 * amount, the program, the measured wallet effect and the verdict. A decline
 * aborts with nothing signed or sent.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { GraphiteGuard, type BoundInstructionPayload, type ConfirmationSummary } from "../agent-guard/guard.js";
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

/**
 * What the person reads before the guard signs (Round 29, M7): the resolved
 * transaction, not the model's words alone. Every value comes from the guard
 * — grounded, built, simulated and verified — and the request is quoted last,
 * as what it is.
 */
export function describeForPerson(s: ConfirmationSummary): string {
  const lines: string[] = [`Graphite: sign and send this ${s.kind} from the agent's wallet ${s.wallet}?`, ""];
  if (s.kind === "transfer") {
    lines.push(`Send ${s.sol} SOL (${s.lamports} lamports)`, `to ${s.destination}`);
  } else if (s.swap) {
    const w = s.swap;
    lines.push(
      `Swap ${w.input.amountIn} base units of ${w.input.token} (${w.input.mint})`,
      `for at least ${w.output.minimumOut} base units of ${w.output.token} (${w.output.mint})`,
      `  simulated: ${w.output.simulatedOut}; allowed slippage ${w.maxSlippageBps} bps; price floor ${w.priceFloor}`,
      `  route: ${w.route}`,
    );
  }
  lines.push(`Program: ${s.programId}`, "", "Simulated effect on the wallet (these exact bytes):");
  lines.push(`  SOL out: ${s.walletEffect.solOutLamports} lamports (fee and rent included; negative = received)`);
  for (const t of s.walletEffect.tokens) lines.push(`  ${t.mint}: ${t.delta} base units`);
  const v = s.verdict;
  lines.push(
    "",
    `Graphite: ${v.approved ? "APPROVED" : "NOT APPROVED"}, risk ${v.risk}, confidence ${v.confidence}`,
    `  audit trail ${v.auditTrailId}${v.transactionSha256 ? `, transaction ${v.transactionSha256}` : ""}`,
    `  not observed: ${v.unobservedCodes.join(", ") || "none"}` +
      (v.acceptedUnobserved.length > 0 ? `; accepted by this deployment: ${v.acceptedUnobserved.join(", ")}` : ""),
    "",
    `Request (as written by the agent): ${s.request}`,
  );
  return lines.join("\n");
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

  /**
   * Whether this call can be confirmed at all: with confirmation required, a
   * client that cannot elicit is refused before anything is built. Returns
   * null when the call may proceed.
   */
  function confirmable(): GraphiteToolResult | null {
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
    return null;
  }

  /** The guard's confirmation hook: ask the person about the resolved transaction. */
  function hook(): { confirm?: (summary: ConfirmationSummary) => Promise<boolean> } {
    if (options.confirmation === "none") return {};
    return {
      confirm: async (summary) => {
        const answer = await server.server.elicitInput({
          message: describeForPerson(summary),
          requestedSchema: {
            type: "object",
            properties: { approve: { type: "boolean", title: "Approve", description: "Sign and send this transaction" } },
            required: ["approve"],
          },
        });
        return answer.action === "accept" && answer.content?.approve === true;
      },
    };
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
      const refused = confirmable();
      if (refused) return asContent(refused);
      try {
        return asContent(toolResultOf(await guard.executeTransfer(request, hook())));
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
      const refused = confirmable();
      if (refused) return asContent(refused);
      try {
        return asContent(toolResultOf(await guard.executeSwap(request, route satisfies BoundInstructionPayload, hook())));
      } catch (e) {
        return asContent(toolRefusalOf(e));
      }
    },
  );

  return server;
}
