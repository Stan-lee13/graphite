# Graphite + Solana Agent Kit Integration

Real, production-ready integration that verifies every SAK transaction through Graphite Core before execution.

## Architecture

```
Natural Language → Python AI Layer (parse intent) → SAK (construct tx) → Graphite Core (verify) → SAK (execute if approved)
```

Constitution P1 (AI assists, never decides): The AI Layer only parses intent — it does not verify or approve. Graphite Core's deterministic verification engine makes all security decisions. SAK only executes if Graphite approves.

## Prerequisites

1. **Graphite Core** running:
   ```bash
   cd graphite-core
   cargo run --release -- server
   ```

2. **Python AI Layer** running:
   ```bash
   cd python-ai-layer
   python3 intent_parser.py --serve
   ```

3. **Environment variables**:
   ```bash
   export SOLANA_PRIVATE_KEY="your_base58_private_key"
   export SOLANA_RPC_URL="https://api.devnet.solana.com"
   export OPENAI_API_KEY="your_openai_api_key"
   ```

## Installation

```bash
cd integrations/solana-agent-kit
npm install
```

## Usage

### Run the end-to-end demo:

```bash
# Swap demo
npx tsx demo.ts "Swap 0.1 SOL for USDC"

# Transfer demo
npx tsx demo.ts "Transfer 0.05 SOL to 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
```

### Use the bridge in your own code:

```typescript
import { VerifiedSakAgent } from "./graphite-sak-bridge.js";

const agent = await VerifiedSakAgent.create();

// Every transaction is verified by Graphite before execution
const result = await agent.executeSwap("Swap 1 SOL for USDC");

if (!result.executed) {
  console.log("Blocked by Graphite:", result.verification.risk_verdict.findings);
} else {
  console.log("Executed:", result.result);
}
```

## What Graphite Verifies

Before SAK submits any transaction, Graphite checks:

- **L1 Account Resolution**: Are all accounts resolved correctly for the protocol?
- **L2 Instruction Verification**: Does the instruction match the protocol manifest?
- **L3 Simulation Integrity**: Is the compute usage consistent with historical baselines?
- **L4 State Verification**: Are writable/signer accounts consistent with declared state changes?
- **L5 Semantic Verification**: Does the intent match the instruction semantics?
- **L6 Policy Verification**: Does the confidence score meet the wallet profile threshold?
- **L7 Risk Verification**: Are there any risk patterns (drainers, authority hijacks, fake swaps, etc.)?

If any layer fails, the transaction is NOT submitted.

## Wallet Profiles

Graphite enforces different confidence thresholds per wallet profile:

| Profile | Min Confidence | Min Trust Tier |
|---------|---------------|----------------|
| Treasury | 95% | CommunityVerified |
| TradingBot | 80% | SimulationValidated |
| Gaming | 60% | HeuristicInferred |
| Enterprise | 99% | BattleTested |

Set via `GRAPHITE_WALLET_PROFILE` environment variable.
