# Graphite for Solana Agent Kit

The Solana Agent Kit adapter. Status is the project's: security-hardened alpha, no
independent third-party audit yet ([docs/CURRENT.md](../../docs/CURRENT.md)).

`VerifiedSakAgent` is a thin layer over [`GraphiteGuard`](../agent-guard/README.md):
`executeTransfer`, `executeSwap` and `parseIntent` are the guard's, and every guarantee
in the guard's README holds for them. (`verifyTransaction` is gone since Round 34: it wrote
to the audit trail under the deployment's Core key for whoever held the adapter. A caller
that wants a verdict without executing builds its own `GraphiteClient` with its own key.)
What the adapter adds is the wallet a caller builds its own SAK agent on, for
**read-only** use (balances, prices, lookups):

- **The adapter does not load SAK (Round 36, F-001).** It used to build a `SolanaAgentKit`
  agent with no plugins — an agent with no actions — and importing SAK put LangChain, the
  OpenAI agents SDK, the Vercel AI SDK and two Zod lines (`zod/v3` among them, with the
  collection-validation advisory GHSA-mrhx-c7xc-m3w5) in the process that holds the wallet
  key. Now `getGatedWallet()` returns the wallet, and the caller builds its agent in its own
  code: `new SolanaAgentKit(agent.getGatedWallet(), rpcUrl, config)`. `openAiApiKey` is
  refused by name: the adapter holds no OpenAI key. A test pins that importing the adapter
  loads no SAK and no Zod. The development tree (where SAK is a dev dependency for those
  tests) forces Zod 4.6.7, which SAK 2.x (`zod ^3`) is not written for: SAK's own
  `createOpenAITools` throws in this tree (Round 39, R39-CLIENTS-2, `zod-override.test.ts`).
  An agent you build installs SAK with its own Zod; this tree's override does not reach it.
- **SAK never holds the key (Round 19, F-19-C2).** A `SolanaAgentKit` agent on
  `VerificationGatedWallet` (`gated-wallet.ts`) gets a public key whose every signing method
  (`signTransaction`, `signAllTransactions`, `sendTransaction`,
  `signAndSendTransaction`, `signMessage`) throws `UngatedSigningRefused`, naming the
  verified path. Every SAK plugin method and LLM-driven SAK tool that would sign is
  refused; funds move only through the guard.
- **No SAK plugins are loaded.** Importing one runs its whole dependency tree in the
  process that holds the key; `@solana-agent-kit/plugin-defi` alone brought 25 of the
  tree's 36 high/critical npm advisories (2026-09-30).
- **The key is not reachable** through the adapter, the guard or a SAK agent built on the
  wallet: the tests walk all three for the secret key's bytes, and for the Core API key
  (Round 29, M8: `getGraphiteClient()` returns the Core's read-only endpoints, not the
  client). `SOLANA_PRIVATE_KEY` is deleted from `process.env` once the guard has read it.
- **A per-transaction cap is required** (Round 29, M6): the guard refuses to start without
  `GRAPHITE_MAX_TRANSFER_LAMPORTS` (or `spendPolicy.maxTransferLamports`) unless the
  operator sets `GRAPHITE_ALLOW_UNCAPPED=1`. This adapter used to start without one.
  `.env.example` lists every variable the adapter and the guard read, and a test keeps it
  that way.
- The audit trail's `reported_by` names this adapter (`sak-bridge:<key prefix>`).

`solana-agent-kit` is a development dependency of this package only (its tests drive SAK's
own signing helpers against the gated wallet), and with it its gated `bigint-buffer`
advisory (through `@solana/spl-token` 0.4; never built, every install runs with
`--ignore-scripts`). The development tree's Zod is forced to 4.6.7. See
`.github/npm-audit/solana-agent-kit.allow`.

## Installation

The adapter imports the guard's sources, so install both:

```bash
(cd integrations/agent-guard && npm ci --ignore-scripts)
(cd integrations/solana-agent-kit && npm ci --ignore-scripts)
```

## Usage

```typescript
import { VerifiedSakAgent } from "./graphite-sak-bridge.js";

const agent = await VerifiedSakAgent.create({
  // every GraphiteGuard option:
  spendPolicy: { maxTransferLamports: 100_000_000n }, // or GRAPHITE_MAX_TRANSFER_LAMPORTS
});

const outcome = await agent.executeTransfer("Transfer 0.05 SOL to <address>");

// Your own SAK agent, in your own code, on a wallet that cannot sign:
import { SolanaAgentKit } from "solana-agent-kit";
const sak = new SolanaAgentKit(agent.getGatedWallet(), process.env.SOLANA_RPC_URL!, {
  OPENAI_API_KEY: process.env.OPENAI_API_KEY,
});
```

To run one request from a terminal, use the guard's runner
(`../agent-guard/cli.ts`); it moves real funds when the Core approves, on whatever
cluster `SOLANA_RPC_URL` names.

## Tests

```bash
npm run typecheck
npm test                 # the SAK-specific tests (counts: docs/CURRENT.md): the gated wallet, a SAK agent on it
                         # and the keys' reachability, no SAK or Zod in the adapter's
                         # module graph, delegation to the guard, the cap, and
                         # .env.example naming every variable read
```

The verified paths are tested in the guard (`../agent-guard`).
