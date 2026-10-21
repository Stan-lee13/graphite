# Graphite for the Vercel AI SDK

Tools a model can call to move funds from an agent wallet, each of which executes only
through [`GraphiteGuard`](../agent-guard/README.md): the request is grounded in its own
words, ONE transaction is built, Graphite Core verifies those exact bytes, and the guard
signs only on an artifact-bound approval. Status is the project's: security-hardened
alpha, no independent third-party audit yet ([docs/CURRENT.md](../../docs/CURRENT.md)).

Built on AI SDK 7 (`ai` 7.x, `zod` 4). Its lockfile has no npm advisory at any level, and
CI fails on any high or critical one (`.github/npm-audit/vercel-ai.allow`).

## Usage

```typescript
import { generateText } from "ai";
import { GraphiteGuard } from "../agent-guard/guard.js";
import { graphiteTools, GRAPHITE_TOOL_APPROVAL } from "./graphite-tools.js";

const guard = await GraphiteGuard.create({
  // or GRAPHITE_MAX_TRANSFER_LAMPORTS / GRAPHITE_ALLOWED_DESTINATIONS
  spendPolicy: { maxTransferLamports: 100_000_000n }, // required: 0.1 SOL per call
  reporter: "vercel-ai",
});

const result = await generateText({
  model, // any AI SDK model
  tools: graphiteTools(guard), // fund-moving tools carry needsApproval: true
  // Approvals come back in the message history the client sends. With a
  // secret, the SDK signs the approval requests it issues and refuses an
  // approval it did not issue (one a client wrote into replayed history).
  experimental_toolApprovalSecret: process.env.TOOL_APPROVAL_SECRET, // 32+ random bytes, server-side only
  prompt: "Send 0.05 SOL to <address>",
});
```

Approval is the default (Round 29, audit 2026-10-20, M7): `graphite_transfer_sol` and
`graphite_swap` are defined with `needsApproval: true`, so the AI SDK returns a
`tool-approval-request` instead of running them until a person approves. An application
that configures approval centrally can pass `toolApproval: GRAPHITE_TOOL_APPROVAL` (the
same policy, with reasons shown to the approver). The SDK lets an application's own
`toolApproval` override a tool's setting — a generic approval function decides every
tool, and a per-tool entry decides that tool — so switching approval off for these tools
takes an explicit entry naming them. Keep `experimental_toolApprovalSecret` set whenever
approvals round-trip through a client.

| Tool | What it does |
|---|---|
| `graphite_wallet` | The wallet's address and the operator's limits. Moves nothing. |
| `graphite_transfer_sol` | `{ request }`: the user's request in their own words. |
| `graphite_swap` | `{ request, route }`: the request and the EXACT route instruction (program, accounts with signer/writable flags, data, lookup tables) from a route API. Without a route the swap is refused. |

Every tool returns a structured result (`GraphiteToolResult`): `executed`, and when it did
not, `refusedBy` — `spend-policy`, `request-grounding`, `swap-route`, `residual-policy`, `person`,
`graphite`, `submission-unknown` (signed and handed to the RPC with an unknown outcome:
`signature` is set, and must be checked before any retry) or `error` — with the reason.
Reasons are bounded and have URLs, bearer tokens and key-like values redacted before the
model sees them. When the Core was asked, the result carries its verdict: what the approval
covers (`scope`: the exact bytes, or only a description), the transaction's SHA-256, the
checks that did not run (residuals) and the manifest version it was judged against.

## What the model controls, and what bounds it

The model writes the tool input. It does not build, sign or submit anything, and three
bounds hold whatever it writes:

- **Graphite's verdict** on the exact bytes, as in every integration.
- **A per-transaction cap is required.** The guard itself refuses to start without one
  (unless `GRAPHITE_ALLOW_UNCAPPED=1`), and `graphiteTools` refuses a guard without one. A
  transfer's grounded amount is checked before anything is built. A swap's outflow is
  measured by simulating the exact transaction (lamports out of the wallet, fee and wrapped
  SOL included) before it is signed; over the cap is refused, and so is a swap that spends
  any other token, which a lamport cap cannot price. A destination allowlist bounds
  transfers only, so with an allowlist and no cap every swap is refused.
- **The swap must be the one the user asked for.** The amount and both tokens are read
  from the request's own text, and the simulated transaction must spend no more than that
  amount of that token, spend nothing else, and deliver the requested token. A request that
  negates or cancels what it names ("don't swap …") is refused. The request must be one
  of the accepted forms ("swap <amount> <token> for <token>", optionally "for at least
  <amount> <token>" and "with <n>% slippage"); a question or a condition is refused.
- **The route must be worth what was asked** (Round 29, H2/H4). Only exact-in
  instructions the guard decodes are built (Jupiter v6 `route`/`shared_accounts_route`,
  Orca Whirlpools, Raydium CPMM/CLMM/AMM v4, Meteora DLMM); the route's own minimum
  output must be within the allowed slippage of the simulated output and meet a price
  floor — the request's stated minimum or the operator's `GRAPHITE_SWAP_MIN_RATES`.
  With neither, the swap is refused unless `GRAPHITE_SWAP_ALLOW_UNPRICED=1`.
- **A person approves every fund-moving call by default** (`needsApproval: true`, above).

## Installation and tests

The tools import the guard's sources, so install both:

```bash
(cd integrations/agent-guard && npm ci --ignore-scripts)
(cd integrations/vercel-ai && npm ci --ignore-scripts)
cd integrations/vercel-ai && npm run typecheck && npm test
```

The tests run the tools inside the AI SDK's own tool loop (`generateText`), with the SDK's
scripted test model (`ai/test`) standing in for a hosted model and loopback stand-ins for
the RPC, the Core and the AI layer (9 tests): execution through the guard, approval holding
the call by default and under `GRAPHITE_TOOL_APPROVAL`, an approved transfer executing end
to end against a loopback Core that approves with the real digests, the cap, a request the
user never wrote, a malformed input, and the refusal of a guard without a cap.
