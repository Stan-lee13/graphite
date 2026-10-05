/**
 * Graphite for the Vercel AI SDK: tools a model can call to move funds, each
 * of which executes only through `GraphiteGuard`.
 *
 *   const guard = await GraphiteGuard.create({ spendPolicy: { maxTransferLamports: 100_000_000n } });
 *   const result = await generateText({
 *     model,
 *     tools: graphiteTools(guard),
 *     toolApproval: GRAPHITE_TOOL_APPROVAL,   // a person approves every fund movement
 *     prompt: "Send 0.05 SOL to <address>",
 *   });
 *
 * What the model controls, and what it does not. The model writes the tool
 * input: the request text, and for a swap the route instruction. It does not
 * build, sign or submit anything. The guard re-derives the amount and the
 * destination from the request text and refuses a reading that disagrees,
 * builds ONE transaction, has Graphite Core verify those exact bytes, and
 * signs only on an artifact-bound approval whose digest matches. A model that
 * was talked into a request is still a request; so two more bounds apply
 * that no verdict can lift:
 *
 *   - a per-transfer cap is REQUIRED (`graphiteTools` refuses a guard without
 *     one): the operator's statement of the most any single tool call may
 *     move, enforced before anything is built;
 *   - `GRAPHITE_TOOL_APPROVAL` marks every fund-moving tool `user-approval`,
 *     so the AI SDK asks a person before the tool runs. The SDK enforces it
 *     where the application passes it to `generateText`/`streamText`; a tool
 *     cannot force its caller to, which is why the cap does not depend on it.
 *
 * Tool results are structured outcomes, never exceptions the model has to
 * interpret: a refusal says who refused (the spend policy, the grounding of
 * the request, or Graphite) and why.
 */
import { tool, type ToolApprovalStatus } from "ai";
import { z } from "zod";
import { GraphiteGuard, type BoundInstructionPayload } from "../agent-guard/guard.js";
import { toolRefusalOf, toolResultOf, type GraphiteToolResult } from "../agent-guard/tool-results.js";

export type { GraphiteToolResult };

/** The approval configuration for `generateText` / `streamText`: a person approves every fund movement. */
export const GRAPHITE_TOOL_APPROVAL = {
  graphite_transfer_sol: {
    type: "user-approval",
    reason: "Moves SOL from the agent's wallet. Graphite verifies the transaction; a person confirms the request.",
  },
  graphite_swap: {
    type: "user-approval",
    reason: "Swaps tokens from the agent's wallet. Graphite verifies the transaction; a person confirms the request.",
  },
  graphite_wallet: "not-applicable",
} as const satisfies Record<string, ToolApprovalStatus>;

const accountMeta = z.object({
  pubkey: z.string().min(32).max(44).describe("base58 account address"),
  isSigner: z.boolean(),
  isWritable: z.boolean(),
});

/**
 * The tools, bound to one guard. Throws unless the guard has a per-transfer
 * cap: a model writes the requests these tools act on.
 */
export function graphiteTools(guard: GraphiteGuard) {
  if (guard.limits.maxTransferLamports === undefined) {
    throw new Error(
      "[Graphite] graphiteTools needs a per-transfer cap: a model writes the requests these tools act on. " +
        "Set GRAPHITE_MAX_TRANSFER_LAMPORTS or GraphiteGuard.create({ spendPolicy: { maxTransferLamports } }). REFUSING.",
    );
  }
  return {
    graphite_wallet: tool({
      description: "The agent wallet's address and the operator's spending limits. Moves nothing.",
      inputSchema: z.object({}),
      execute: async () => {
        const limits = guard.limits;
        return {
          address: guard.publicKey,
          maxTransferLamports: limits.maxTransferLamports?.toString(),
          allowedDestinations: limits.allowedDestinations,
        };
      },
    }),

    graphite_transfer_sol: tool({
      description:
        "Transfer SOL from the agent wallet. Pass the user's own request, e.g. 'Transfer 0.05 SOL to <address>'. " +
        "Graphite re-derives the amount and destination from that text, verifies the exact transaction, and " +
        "signs only on its approval; anything over the operator's per-transfer cap is refused.",
      inputSchema: z.object({
        request: z
          .string()
          .min(1)
          .max(500)
          .describe("The user's request in their own words, naming the SOL amount and the destination address."),
      }),
      execute: async ({ request }): Promise<GraphiteToolResult> => {
        try {
          return toolResultOf(await guard.executeTransfer(request));
        } catch (e) {
          return toolRefusalOf(e);
        }
      },
    }),

    graphite_swap: tool({
      description:
        "Swap tokens through a swap program, given the user's request and the EXACT route instruction (from a " +
        "route API): program, accounts with signer/writable flags, instruction data, and any lookup tables. " +
        "Graphite verifies that instruction as the bytes to be signed; without a route the swap is refused.",
      inputSchema: z.object({
        request: z.string().min(1).max(500).describe("The user's swap request in their own words."),
        route: z.object({
          programId: z.string().min(32).max(44),
          discriminator: z.string().regex(/^[0-9a-fA-F]{2,64}$/).describe("hex selector of the route instruction"),
          accounts: z.array(accountMeta).min(1).max(64),
          instructionData: z.array(z.number().int().min(0).max(255)).max(4096),
          addressLookupTableAddresses: z.array(z.string().min(32).max(44)).max(8).optional(),
        }),
      }),
      execute: async ({ request, route }): Promise<GraphiteToolResult> => {
        try {
          return toolResultOf(await guard.executeSwap(request, route satisfies BoundInstructionPayload));
        } catch (e) {
          return toolRefusalOf(e);
        }
      },
    }),
  };
}
