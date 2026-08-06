<div align="center">

# Graphite

**Transaction intent verification for Solana AI agents.**

Graphite sits between an AI agent's intent and the wallet's execution. It verifies that a constructed transaction actually does what was declared — with a falsifiable confidence score, not a binary safe/unsafe.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![Rust Tests](https://img.shields.io/badge/Rust_Tests-649_passing-brightgreen?style=flat-square)](graphite-core/tests/)
[![Clippy](https://img.shields.io/badge/Clippy-0_warnings-brightgreen?style=flat-square)](graphite-core/)
[![Protocols](https://img.shields.io/badge/Protocol_Manifests-11-blue?style=flat-square)](graphite-core/protocols/)
[![Risk Patterns](https://img.shields.io/badge/Risk_Patterns-8-red?style=flat-square)](graphite-core/src/risk_engine.rs)
[![Version](https://img.shields.io/badge/Version-v0.1.1--alpha-orange?style=flat-square)](https://github.com/Stan-lee13/graphite/releases)

</div>

---

## The Problem This Solves

AI agents on Solana can construct and submit transactions autonomously. But nothing verifies that the transaction they *say* they're building is the transaction they *actually* build.

```
WITHOUT GRAPHITE:

  AI Agent → "Swap 1 SOL for USDC" → Construct Transaction → Wallet → Blockchain
                                         ↑
                                    No one checks if the
                                    transaction actually
                                    does what was declared

WITH GRAPHITE:

  AI Agent → "Swap 1 SOL for USDC" → Graphite verifies → Wallet → Blockchain
                                         ↓
                                    8-layer pipeline checks:
                                    • Accounts match the protocol
                                    • Instruction matches the intent
                                    • No drainer patterns
                                    • No authority hijacks
                                    • No hidden transfers
                                    • Confidence score is honest
                                    • Policy threshold is met

                                    If any check fails → BLOCKED. Period.
```

This is not a simulation. This is not advisory. Graphite is a **deterministic verification gate** — if Graphite blocks, the transaction is not submitted.

---

## What Ships Ready to Run

```bash
# Clone
git clone https://github.com/Stan-lee13/graphite.git
cd graphite

# Build the core engine
cd graphite-core
cargo build --release

# Run 635 tests — zero setup
cargo test --release

# Output:
# running 635 tests
# test result: ok. 635 passed; 0 failed; 0 ignored

# Run the benchmark (18 cases, P16 compliant)
cargo run --release --bin graphite -- benchmark
```

---

## Architecture — 8-Layer Verification Pipeline

Each layer can only **reduce** confidence or **block**. No layer can invent confidence that lower layers didn't earn.

| Layer | Name | Responsibility | Failure Mode |
|-------|------|---------------|--------------|
| L1 | Account Resolution | Resolve all required accounts/PDAs | Missing/ambiguous → block |
| L2 | Instruction Verification | Confirm discriminator + args match known shape | Unknown → Unknown Protocol Mode |
| L3 | Simulation Verification | Run `simulateTransaction`, confirm it succeeds | Simulation failure → block |
| L4 | State Verification | Diff pre/post account state vs declared intent | Mismatch → block or flag |
| L5 | Semantic Verification | Compare diff against Semantic Graph expectations | Deviation → confidence penalty |
| L6 | Policy Verification | Apply wallet's policy profile thresholds | Policy violation → block |
| L7 | Risk Verification | Run Risk Engine — forbidden patterns, compositional risk | Forbidden pattern → block |
| L8 | Execution Verification | Post-submission: confirm on-chain result matches prediction | Mismatch → audit trail flag |

**Phase 1.5 status:** L1-L2, L4-L7 active. L3 requires RPC (Phase 2). L8 requires live execution (Phase 2).

---

## Risk Engine — 8 Attack Patterns

| Pattern | What It Catches |
|--------|----------------|
| **Drainer** | High account-to-change ratio — multi-transfer drain |
| **AuthorityHijack** | SetAuthority/CloseAccount via CPI from untrusted root |
| **HiddenTransfer** | Transaction touches accounts not in declared state changes |
| **UnexpectedCpi** | CPI target not in manifest's allowed list (fail-closed) |
| **FakeSwap** | Swap intent on a non-swap program |
| **PermissionEscalation** | SPL Token Approve instruction when intent is "transfer" |
| **MaliciousAccountChange** | CloseAccount/Allocate when intent is not "close" |
| **CompositionalDrainPattern** | Deep CPI chains (5+) from untrusted roots, or repeated program revisits |

All 8 patterns are real detection logic — not stubs, not placeholders.

---

## Supported Protocols (11 Manifests)

| Protocol | Program ID | Trust Tier |
|----------|-----------|------------|
| System Program | `11111111111111111111111111111111` | Battle Tested |
| SPL Token | `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` | Battle Tested |
| Token-2022 | `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb` | Official Manifest |
| Stake Program | `Stake11111111111111111111111111111111111111` | Battle Tested |
| Memo (p-memo) | `Memo4c2pN8afCj432Lb7RMVKi9PbQnnW7ewFFaV3oAH` | Official Manifest |
| Memo (legacy SPL) | `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr` | Official Manifest |
| Jupiter V6 | `JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4` | Battle Tested |
| Orca Whirlpools | `whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc` | Battle Tested |
| Meteora DLMM | `LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo` | Battle Tested |
| Raydium AMM V4 | `675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8` | Battle Tested |
| Squads V4 | `SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf` | Battle Tested |

---

## What's in the Box

```
graphite/
│
├── graphite-core/              ← Rust verification engine (the heart)
│   ├── src/
│   │   ├── verification.rs      ← 8-layer pipeline orchestrator
│   │   ├── account_resolution.rs← L1: PDA derivation, account matching
│   │   ├── risk_engine.rs       ← L7: 8 attack pattern detectors
│   │   ├── confidence_engine.rs ← Weighted signal scoring + tier ceilings
│   │   ├── policy_engine.rs     ← L6: Per-wallet policy profiles
│   │   ├── simulation_integrity.rs ← L3: Compute/write/CPI z-score
│   │   ├── semantic_graph_store.rs ← Trust tier computation
│   │   ├── transaction_builder.rs  ← Canonical serialization
│   │   ├── unknown_protocol_mode.rs ← 0.55 confidence cap (P6/P12)
│   │   ├── server.rs            ← HTTP API (axum)
│   │   ├── benchmark.rs         ← P16-compliant benchmark suite
│   │   └── cli.rs               ← CLI (clap)
│   ├── protocols/               ← 11 JSON protocol manifests
│   └── tests/                   ← 635 tests (unit + adversarial + exploit)
│
├── sdk/
│   ├── typescript/              ← TS SDK (GraphiteClient)
│   └── go/                      ← Go SDK (full VerificationResult parity)
│
├── integrations/
│   └── solana-agent-kit/        ← SAK v2 integration (verified execution gate)
│       ├── graphite-sak-bridge.ts ← Pre-flight verification before SAK executes
│       └── demo.ts              ← End-to-end demo
│
├── python-ai-layer/            ← Advisory intent parser (P1: AI never decides)
│   ├── intent_parser.py
│   └── test_intent_parser.py
│
├── examples/                   ← Sample verification inputs/outputs
├── schemas/                    ← JSON schemas for API contracts
├── docs/                       ← Audit reports, Phase 2 plans
│
├── ARCHITECTURE.md             ← System design specification
├── ROADMAP.md                  ← Phase 1 (done) → Phase 2 (planned) → Phase 3+
├── SECURITY.md                 ← Security policy + known limitations
├── CONTRIBUTING.md             ← How to contribute
└── README.md                   ← You are here
```

---

## Quick Start

### 1. Run the verification engine

```bash
cd graphite-core
cargo run --release --bin graphite -- server --port 7331
# Graphite Core running on port 7331
```

### Production server configuration (all optional env vars)

| Env var | Default | Purpose |
|---------|---------|---------|
| `GRAPHITE_API_KEY` | *(unset = open)* | **Set this in production.** Bearer token required on `/verify` and `/manifests` (constant-time compared). `/health` stays open for load balancers. |
| `GRAPHITE_RATE_LIMIT` | `30` | Per-IP token bucket, requests/second. Returns `429` when exceeded. |
| `GRAPHITE_CORS_ORIGINS` | *(denied)* | Comma-separated allowed browser origins. Default denies all cross-origin browser calls; server-to-server clients are unaffected. |
| `GRAPHITE_DATA_DIR` | `./graphite-data` | Durability: semantic-graph snapshot (trust tiers + earned simulation baselines) and append-only `audit.jsonl` written after every verification, reloaded on restart. |
| `GRAPHITE_RPC_URL` | *(off)* | Attaches a Solana RPC client — live L3: `simulateTransaction` runs and real compute usage feeds the trusted baseline accumulator. |

```bash
# Minimal production launch (auth + rate limit + durability)
GRAPHITE_API_KEY=$(openssl rand -hex 32) GRAPHITE_RATE_LIMIT=100 \
  GRAPHITE_DATA_DIR=/var/lib/graphite GRAPHITE_CORS_ORIGINS= \
  cargo run --release --bin graphite -- server --port 7331
```

### 2. Verify a transaction

```bash
curl -X POST http://localhost:7331/verify \
  -H "Content-Type: application/json" \
  -d @../examples/verify-input.json | jq .
```

> ⚠️ The example input uses the `TradingBot` profile (0.80 threshold). In Phase 1 the achievable confidence for a known protocol is ~0.44 (see *Honest Status* below), so this example returns **BLOCKED** — that is the engine being honest, not a bug. To see an approval, set a Phase-1-calibrated profile:
>
> ```bash
> jq '.wallet_profile = {"Custom": {"min_confidence": 0.40, "min_trust_tier": "OfficialManifest"}}' ../examples/verify-input.json | curl -X POST http://localhost:7331/verify -H "Content-Type: application/json" -d @- | jq .approved
> ```

### 3. Run the SAK integration demo

```bash
# Start AI Layer (separate process, P1 compliance)
cd python-ai-layer
python3 intent_parser.py --serve --port 8081

# Run the demo
cd ../integrations/solana-agent-kit
npx tsx demo.ts "Swap 0.5 SOL for USDC"
```

The demo shows the full flow:
1. AI Layer parses "Swap 0.5 SOL for USDC" → `ProposedIntent`
2. SAK constructs the Jupiter V6 swap transaction
3. Graphite verifies the transaction → `VerificationResult`
4. If approved → SAK executes. If blocked → transaction is NOT submitted.

---

## Security Properties

| Property | How It's Enforced |
|----------|-------------------|
| **Unknown protocol cap** | Hard 0.55 confidence ceiling — no caller evidence can override (P6/P12) |
| **Fail-closed on unknown** | Unknown discriminator on known protocol → BLOCKED (confidence 0.0) |
| **NaN bypass prevention** | Explicit NaN/Infinity rejection in confidence engine |
| **AI never decides** | Python AI layer is advisory only — Core verification is deterministic (P1) |
| **Deterministic** | `content_hash` = SHA-256 of transaction config — same input, same output (P2) |
| **Compositional drain detection** | Both duplicate AND unique-program deep CPI chains caught |
| **Trusted simulation baselines** | Baselines live in the semantic-graph accumulator (earned via RPC-verified usage or operator-seeded) — the request body **cannot** supply one (anti-poisoning) |
| **API auth** | Optional Bearer API key, constant-time compared; `429` per-IP rate limiting; CORS allowlist (denied by default) |
| **Durability** | Semantic-graph snapshot + append-only audit trail (`audit.jsonl`) persisted to `GRAPHITE_DATA_DIR`, reloaded on restart |

---

## Honest Status (Phase 1.5)

What we **do not** claim:

- The benchmark is 18 handcrafted test cases — NOT a statistical evaluation on unseen data. "100% pass rate on handcrafted tests" is the honest claim.
- 5 exploit reconstructions use real program IDs but fabricated account structures. They are labeled "SYNTHETIC" per P16, not "real mainnet data."
- L3 (Simulation) and L8 (Execution Verification) are not yet active — they require live RPC and execution infrastructure (Phase 2).
- No instruction data semantic parsing beyond discriminator matching (Phase 2).

What we **do** claim:

- **Phase 1 confidence is calibrated honestly.** The three evidence-derived signals (`SimulationMatch`, `HistoricalVolume`, `CommunityVerification`) are intentionally ZEROED in Phase 1 — they'd come from caller-controlled request JSON, which an attacker could fabricate to mint confidence (Constitution G4). Trust tiers are capped at `OfficialManifest` (P7: tiers 3+ must be earned via the Semantic Graph, not self-asserted). The achievable confidence for a known, clean, intent-aligned protocol is therefore **~0.44**. The built-in wallet profiles (TradingBot 0.80, Treasury 0.95, …) were calibrated for the Phase 2 signal set and will block everything in Phase 1 — the benchmark, and the SAK demo, therefore default to a `Custom { min_confidence: 0.40, min_trust_tier: OfficialManifest }` profile. Raise or lower the profile to change policy; the engine's score itself is the honest number.
- 649 Rust tests, 0 failures, 0 clippy warnings — every test has real assertions.
- 8 risk patterns are real detection logic, not stubs.
- 11 protocol manifests with program IDs verified against official on-chain sources.
- Confidence engine uses real weighted computation with tier ceilings and NaN rejection.
- Simulation integrity uses 3-signal z-score (compute, writes, CPI hops) with Welford's algorithm.
- The SAK integration imports real `solana-agent-kit` v2 and calls real SAK methods.

---

## Documentation

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | System design, 8-layer pipeline, subsystem specs |
| [ROADMAP.md](ROADMAP.md) | Phase 1 (done) → Phase 2 (planned) → Phase 3+ |
| [SECURITY.md](SECURITY.md) | Security policy, known limitations, reporting |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup, PR checklist, Constitution principles |
| [Engineering Skill](https://github.com/Stan-lee13/graphite-engineering-skill) | The skill that builds Graphite — Constitution, personas, checklists |

---

## License

MIT — Copyright (c) 2026 Victor Stanley

---

<div align="center">

*If an AI agent is going to submit transactions on your behalf, something should verify those transactions first. That's what Graphite does.*

</div>
