# Graphite for Solana Agent Kit

The Solana Agent Kit adapter. Status is the project's: security-hardened alpha, no
independent third-party audit yet ([docs/CURRENT.md](../../docs/CURRENT.md)).

`VerifiedSakAgent` is a thin layer over [`GraphiteGuard`](../agent-guard/README.md):
`executeTransfer`, `executeSwap`, `parseIntent` and `verifyTransaction` are the
guard's, and every guarantee in the guard's README holds for them. What the adapter adds
is SAK's own agent, for a caller's **read-only** use (balances, prices, lookups):

- **SAK never holds the key (Round 19, F-19-C2).** `SolanaAgentKit` is built on
  `VerificationGatedWallet` (`gated-wallet.ts`): a public key whose every signing method
  (`signTransaction`, `signAllTransactions`, `sendTransaction`,
  `signAndSendTransaction`, `signMessage`) throws `UngatedSigningRefused`, naming the
  verified path. Every SAK plugin method and LLM-driven SAK tool that would sign is
  refused; funds move only through the guard.
- **No SAK plugins are loaded.** Importing one runs its whole dependency tree in the
  process that holds the key; `@solana-agent-kit/plugin-defi` alone brought 25 of the
  tree's 36 high/critical npm advisories (2026-09-30).
- **The key is not reachable** through the adapter, the guard or the SAK agent at
  runtime: the tests walk all three for the secret key's bytes. Since Round 29 (audit
  2026-10-20, M8) they also look for the Core API key and the OpenAI key: neither is
  reachable through the adapter or the guard (`getGraphiteClient()` returns the Core's
  read-only endpoints, not the client). `SolanaAgentKit` keeps the OpenAI key in its own
  config because it calls a model with it — SAK's design, and the only secret the SAK agent
  holds. `SOLANA_PRIVATE_KEY` is deleted from `process.env` once the guard has read it.
- **A per-transaction cap is required** (Round 29, M6): the guard refuses to start without
  `GRAPHITE_MAX_TRANSFER_LAMPORTS` (or `spendPolicy.maxTransferLamports`) unless the
  operator sets `GRAPHITE_ALLOW_UNCAPPED=1`. This adapter used to start without one.
  `.env.example` lists every variable the adapter and the guard read, and a test keeps it
  that way.
- The audit trail's `reported_by` names this adapter (`sak-bridge:<key prefix>`).

This is the only package in the repository that depends on the `solana-agent-kit` npm
package, and so the only one carrying its gated `bigint-buffer` advisory (through
`@solana/spl-token` 0.4; the native addon is never built, every install runs with
`--ignore-scripts`). See `.github/npm-audit/solana-agent-kit.allow`.

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
  // every GraphiteGuard option, plus the key SAK itself needs:
  spendPolicy: { maxTransferLamports: 100_000_000n }, // or GRAPHITE_MAX_TRANSFER_LAMPORTS
  openAiApiKey: process.env.OPENAI_API_KEY,
});

const outcome = await agent.executeTransfer("Transfer 0.05 SOL to <address>");
const sak = agent.getSakAgent(); // read-only; it cannot sign
```

To run one request from a terminal, use the guard's runner
(`../agent-guard/cli.ts`); it moves real funds when the Core approves, on whatever
cluster `SOLANA_RPC_URL` names.

## Tests

```bash
npm run typecheck
npm test                 # the SAK-specific tests (counts: docs/CURRENT.md): the gated wallet, the SAK agent and
                         # the keys' reachability, delegation to the guard, the cap,
                         # and .env.example naming every variable read
```

The verified paths are tested in the guard (`../agent-guard`).
