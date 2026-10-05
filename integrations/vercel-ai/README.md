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
  tools: graphiteTools(guard),
  toolApproval: GRAPHITE_TOOL_APPROVAL, // a person approves every fund movement
  prompt: "Send 0.05 SOL to <address>",
});
```

| Tool | What it does |
|---|---|
| `graphite_wallet` | The wallet's address and the operator's limits. Moves nothing. |
| `graphite_transfer_sol` | `{ request }`: the user's request in their own words. |
| `graphite_swap` | `{ request, route }`: the request and the EXACT route instruction (program, accounts with signer/writable flags, data, lookup tables) from a route API. Without a route the swap is refused. |

Every tool returns a structured result (`GraphiteToolResult`): `executed`, and when it did
not, `refusedBy` — `spend-policy`, `request-grounding`, `residual-policy`, `graphite` or `error` —
with the reason. When the Core was asked, the result carries its verdict: what the approval
covers (`scope`: the exact bytes, or only a description), the transaction's SHA-256, the
checks that did not run (residuals) and the manifest version it was judged against.

## What the model controls, and what bounds it

The model writes the tool input. It does not build, sign or submit anything, and three
bounds hold whatever it writes:

- **Graphite's verdict** on the exact bytes, as in every integration.
- **A per-transaction cap is required.** `graphiteTools` refuses a guard without one. A
  transfer's grounded amount is checked before anything is built. A swap's outflow is
  measured by simulating the exact transaction (lamports out of the wallet, fee and wrapped
  SOL included) before it is signed; over the cap is refused, and so is a swap that spends
  any other token, which a lamport cap cannot price. A destination allowlist bounds
  transfers only, so with an allowlist and no cap every swap is refused.
- **`GRAPHITE_TOOL_APPROVAL`** marks every fund-moving tool `user-approval`, so the AI SDK
  asks a person before the tool runs. The SDK enforces it where the application passes it
  to `generateText`/`streamText`; a tool cannot force its caller to, which is why the cap
  does not depend on it.

## Installation and tests

The tools import the guard's sources, so install both:

```bash
(cd integrations/agent-guard && npm ci --ignore-scripts)
(cd integrations/vercel-ai && npm ci --ignore-scripts)
cd integrations/vercel-ai && npm run typecheck && npm test
```

The tests run the tools inside the AI SDK's own tool loop (`generateText`), with the SDK's
scripted test model (`ai/test`) standing in for a hosted model and loopback stand-ins for
the RPC, the Core and the AI layer: execution through the guard, approval holding the
call, the cap, a request the user never wrote, a malformed input, and the refusal of a
guard without a cap.
