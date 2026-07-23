# Graphite × Solana Agent Kit Integration

**Phase 1.5 Exit Criterion (ROADMAP.md §3.19)**

This integration demonstrates one real, working end-to-end agent flow:

```
User: "Swap 0.5 SOL for USDC"
  → AI Layer (Python) parses natural language → ProposedIntent
  → Graphite Core (Rust) verifies the transaction → VerificationResult
  → If approved: Solana Agent Kit executes via Jupiter
  → If blocked: Agent REFUSES to execute (Graphite is a hard gate)
```

## What This Proves

1. **Graphite sits between the agent and the wallet.** The transaction never reaches the wallet until Graphite verifies it.
2. **The AI Layer is advisory-only (Constitution P1).** It parses intent; it does not approve or execute. The Rust Core makes all security decisions.
3. **A blocked transaction is never sent.** If Graphite says "blocked," the agent refuses to execute — this is a hard gate, not a scoring signal.
4. **Process isolation is structural.** The AI Layer (Python) and Core (Rust) are separate processes communicating over HTTP. There is zero call-graph overlap.

## Quick Start

### Prerequisites

1. **Graphite Core server** running on `:7331`:
   ```bash
   cd graphite-core
   cargo run --bin graphite server
   ```

2. **Graphite AI Layer** running on `:8081`:
   ```bash
   cd python-ai-layer
   python3 intent_parser.py --serve
   ```

### Run the Demo (Dry-Run)

```bash
cd integrations/solana-agent-kit
npx tsx demo.ts "Swap 0.5 SOL for USDC"
```

This shows the full flow: AI parsing → Graphite verification → simulated execution. No on-chain transaction is sent.

### Run with Live Execution

Requires a funded Solana wallet and the Solana Agent Kit package:

```bash
npm install solana-agent-kit @solana-agent-kit/plugin-defi

GRAPHITE_RPC_URL=https://api.devnet.solana.com \
GRAPHITE_PRIVATE_KEY=your_base58_private_key \
npx tsx demo.ts "Swap 0.5 SOL for USDC" --execute
```

## Architecture

```
┌─────────────┐     HTTP/JSON      ┌──────────────────┐     HTTP/JSON      ┌─────────────────┐
│  User NL    │ ────────────────→ │  AI Layer (:8081) │ ────────────────→ │  Graphite Core  │
│  "Swap..."  │                   │  Python            │                   │  Rust (:7331)    │
└─────────────┘                   │  parse_intent()    │                   │  verify()         │
                                  └──────────────────┘                   └────────┬────────┘
                                                                                  │
                                                                        ┌─────────▼─────────┐
                                                                        │  VerificationResult │
                                                                        │  approved / blocked │
                                                                        └─────────┬─────────┘
                                                                                  │
                                                                         approved │ blocked → STOP
                                                                        ┌─────────▼─────────┐
                                                                        │  Solana Agent Kit  │
                                                                        │  agent.methods.trade│
                                                                        │  → Jupiter → Wallet │
                                                                        └───────────────────┘
```

## Integration Pattern

For teams integrating Graphite into their own Solana agents:

```typescript
import { GraphiteClient } from "../../sdk/typescript";

const graphite = new GraphiteClient({ baseUrl: "http://localhost:7331" });

// 1. Parse intent (your AI layer — any NLP/LLM you choose)
const intent = await parseIntentWithYourAI("Swap 0.5 SOL for USDC");

// 2. Build the transaction (using Solana Agent Kit or @solana/web3.js)
const tx = await buildTransaction(intent); // your code

// 3. Verify with Graphite BEFORE sending to wallet
const result = await graphite.verify({
  proposed_intent: intent,
  program_id: tx.programId,
  instruction_discriminator: tx.discriminator,
  account_addresses: tx.accountAddresses,
  cpi_targets: tx.cpiTargets,
  wallet_profile: "Standard",
  behavior_evidence: { /* ... */ },
  compute_units: tx.computeBudget,
  account_writes: tx.writableAccounts,
  cpi_hops: tx.cpiDepth,
});

// 4. Hard gate: only execute if Graphite approves
if (result.approved) {
  const signature = await agent.methods.trade(/* ... */);
  console.log("Executed:", signature);
} else {
  console.log("BLOCKED by Graphite:", result.risk_verdict.findings);
  // DO NOT send the transaction — Graphite is a hard gate
}
```

## Constitution Compliance

- **P1 (AI assists, never decides):** The AI Layer only parses intent. The Rust Core makes all verification decisions. They are separate processes.
- **P3 (confidence scored, never boolean):** Every verification result includes a numeric confidence score (0.0-1.0) with a full breakdown.
- **P12 (degrades gracefully):** Unknown protocols get a hard confidence ceiling, not a panic.
- **P16 (reproducible benchmarks):** The verification numbers in the demo are from real Core runs, not estimates.

## License

MIT (same as Graphite Core)
