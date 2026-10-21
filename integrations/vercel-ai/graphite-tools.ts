/**
 * Graphite for the Vercel AI SDK: tools a model can call to move funds, each
 * of which executes only through `GraphiteGuard`.
 *
 *   const guard = await GraphiteGuard.create({ spendPolicy: { maxTransferLamports: 100_000_000n } });
 *   const result = await generateText({
 *     model,
 *     tools: graphiteTools(guard, { confirm: async (summary) => askThePerson(summary) }),
 *     // Fund-moving tools need approval by default (needsApproval); a secret
 *     // lets the SDK reject approvals a client forged in replayed history.
 *     experimental_toolApprovalSecret: process.env.TOOL_APPROVAL_SECRET,
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
 *   - every fund-moving tool carries `needsApproval: true`, so the AI SDK asks
 *     a person before it runs by default. Round 29 (audit 2026-10-20, M7):
 *     approval used to be opt-in — only an application that passed
 *     `GRAPHITE_TOOL_APPROVAL` as `toolApproval` got it. The SDK lets an
 *     application's own `toolApproval` override a tool's setting (a generic
 *     approval function decides every tool; a per-tool entry decides that
 *     tool), so an application can still switch it off, explicitly, for a
 *     tool it names. `GRAPHITE_TOOL_APPROVAL` stays exported for applications
 *     that configure approval centrally. Approvals travel back in the message
 *     history the client sends; pass `experimental_toolApprovalSecret` so the
 *     SDK can tell an approval it issued from one a client forged (README);
 *   - Round 30 (audit finding K-01): that approval is about the model's
 *     request, before anything is resolved, so `graphiteTools` also requires
 *     a `confirm` hook, which the guard calls with the resolved transaction
 *     and the digest of its exact bytes immediately before signing — unless
 *     the operator states `{ confirmation: "request-only" }` by name
 *     (`GraphiteToolsOptions`).
 *
 * Tool results are structured outcomes, never exceptions the model has to
 * interpret: a refusal says who refused (the spend policy, the grounding of
 * the request, or Graphite) and why.
 */
import { tool, type ToolApprovalStatus } from "ai";
import { z } from "zod";
import { GraphiteGuard, type BoundInstructionPayload, type ConfirmationSummary } from "../agent-guard/guard.js";
import { toolRefusalOf, toolResultOf, type GraphiteToolResult } from "../agent-guard/tool-results.js";

export type { GraphiteToolResult, ConfirmationSummary };

/**
 * How a person confirms (Round 30, audit finding K-01).
 *
 * The SDK's `needsApproval` asks a person about the TOOL INPUT — the model's
 * request text and, for a swap, the route it wrote — before the tool runs:
 * before the guard has grounded the destination and amount, built and
 * simulated the transaction, or heard Graphite's verdict. The MCP server
 * moved its question after all of that in Round 29 (M7); these tools did not.
 *
 *   - `"resolved"` (the default): `confirm` is REQUIRED and is the guard's
 *     confirmation hook — called after grounding, the spend policy, the
 *     build, the simulation, the verdict and the residual policy,
 *     immediately before signing, with the resolved destination, amount,
 *     route minimum, measured wallet effect, verdict and the SHA-256 of the
 *     exact bytes. Anything but `true` signs nothing. `needsApproval` still
 *     applies first.
 *   - `"request-only"`: the operator states, by name, that the person
 *     approves only the request (`needsApproval`) and nothing after it. For a
 *     transfer that request IS the destination and amount — the guard builds
 *     exactly what its text says or refuses — but nothing resolved after it is
 *     shown to anyone.
 */
export interface GraphiteToolsOptions {
  confirmation?: "resolved" | "request-only";
  /** Required with `confirmation: "resolved"`; refused with `"request-only"`. */
  confirm?: (summary: ConfirmationSummary) => Promise<boolean>;
}

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
export function graphiteTools(guard: GraphiteGuard, options: GraphiteToolsOptions = {}) {
  if (guard.limits.maxTransferLamports === undefined) {
    throw new Error(
      "[Graphite] graphiteTools needs a per-transfer cap: a model writes the requests these tools act on. " +
        "Set GRAPHITE_MAX_TRANSFER_LAMPORTS or GraphiteGuard.create({ spendPolicy: { maxTransferLamports } }). REFUSING.",
    );
  }
  const confirmation = options.confirmation ?? "resolved";
  if (confirmation !== "resolved" && confirmation !== "request-only") {
    throw new Error(`[Graphite] graphiteTools confirmation ${JSON.stringify(confirmation)} is not "resolved" or "request-only". REFUSING.`);
  }
  if (confirmation === "resolved" && typeof options.confirm !== "function") {
    throw new Error(
      "[Graphite] graphiteTools needs a `confirm` hook: the SDK's approval is asked before the destination, amount, " +
        "route minimum, simulated effect and Graphite's verdict are known, so a person would approve the model's words " +
        "and nothing resolved. Pass graphiteTools(guard, { confirm }) — it is called with the resolved transaction " +
        "immediately before signing — or state that approving the request is enough with " +
        '{ confirmation: "request-only" }. REFUSING.',
    );
  }
  if (confirmation === "request-only" && options.confirm !== undefined) {
    throw new Error('[Graphite] graphiteTools: a `confirm` hook with confirmation "request-only" would never be called. REFUSING.');
  }
  const hook = options.confirm ? { confirm: options.confirm } : {};
  return {
    graphite_wallet: tool({
      description:
        "The agent wallet's address, the operator's spending limits, and what the guard can and cannot build. Moves nothing.",
      inputSchema: z.object({}),
      execute: async () => {
        const limits = guard.limits;
        return {
          address: guard.publicKey,
          maxTransferLamports: limits.maxTransferLamports?.toString(),
          allowedDestinations: limits.allowedDestinations,
          // Round 30: so a model can tell "unsupported" from "refused".
          capabilities: guard.capabilities,
        };
      },
    }),

    graphite_transfer_sol: tool({
      // Round 29 (M7): a person approves by default.
      needsApproval: true,
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
          return toolResultOf(await guard.executeTransfer(request, hook));
        } catch (e) {
          return toolRefusalOf(e);
        }
      },
    }),

    graphite_swap: tool({
      needsApproval: true,
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
          return toolResultOf(await guard.executeSwap(request, route satisfies BoundInstructionPayload, hook));
        } catch (e) {
          return toolRefusalOf(e);
        }
      },
    }),
  };
}
