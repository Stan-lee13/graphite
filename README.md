# Graphite

Transaction verification for Solana AI agents. Graphite sits between an AI agent and the wallet, verifying that a constructed transaction actually does what was declared — with a transparent, falsifiable confidence score.

## What Graphite Does

```
AI Agent → Graphite → Wallet → Blockchain
```

Nothing reaches the wallet before Graphite understands it.

## Phase 1 MVP

### Core (Rust)

```bash
cd graphite-core

# Run tests (264 tests across unit, integration, adversarial, red-team, confidence, self-healing)
cargo test

# Run the benchmark
cargo run --bin graphite benchmark

# Start the HTTP server
cargo run --bin graphite server --port 7331

# Verify a transaction from file
cargo run --bin graphite verify --file examples/verify-input.json

# List loaded protocol manifests
cargo run --bin graphite manifests
```

### API Endpoints

- `POST /verify` — Verify a transaction
- `GET /health` — Health check
- `GET /manifests` — List loaded protocol manifests

### Protocol Manifests

Graphite ships with built-in manifests for 10 Solana protocols:
- **System Program** (Transfer, CreateAccount, Assign, Allocate)
- **SPL Token Program** (Transfer, InitializeMint, MintTo, Burn, Approve, SetAuthority, CloseAccount)
- **Token-2022** (Transfer, SetAuthority, CloseAccount)
- **Stake Program** (DelegateStake, Deactivate, Withdraw)
- **Raydium AMM V4** (Swap, AddLiquidity)
- **Squads V4 Multisig** (multisigCreateV2, vaultTransactionCreate)
- **Jupiter V6** (Swap via route)
- **Orca Whirlpools** (Swap)
- **Meteora DLMM** (Swap)
- **Memo Program** (Memo)

Custom manifests can be loaded at runtime via the `GraphiteCore::load_manifest()` API.

### TypeScript SDK

```typescript
import { GraphiteClient } from "@graphite/sdk";

const client = new GraphiteClient({ baseUrl: "http://localhost:7331" });

const result = await client.verify({
  proposed_intent: {
    intent_type: "transfer",
    raw_natural_language: "Transfer 1 SOL to friend",
    confidence_of_parse: 0.95,
  },
  program_id: "11111111111111111111111111111111",
  instruction_discriminator: "02000000",
  account_addresses: ["7xKXtg..."],
});

console.log(result.approved);     // true
console.log(result.confidence);   // 1.0
console.log(result.summary);      // "APPROVED | confidence=1.00 | ..."
```

### Benchmark Results

```
Total cases:      13
Scored cases:     11 (safe + malicious only)
Accuracy:         100.0%
Precision:        100.0%
Recall:           100.0%
Avg Latency:      ~97μs
```

## Architecture

Graphite Core is organized around an 8-layer verification pipeline:
1. Account Resolution
2. Transaction Construction
3. Simulation
4. Protocol Intelligence
5. Semantic Verification
6. Policy Engine
7. Risk Verification
8. Confidence Engine

Key principles (Constitution):
- AI proposes, deterministic code verifies (P1)
- Confidence is always scored, never boolean (P3)
- Unknown protocols get capped confidence (P6/P12)
- Risk engine blocks override confidence (hard gate)
- Everything is deterministic and reproducible (P2)

## License

MIT
