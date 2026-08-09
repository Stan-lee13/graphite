<div align="center">

# Graphite

**Transaction intent verification for Solana AI agents.**

Graphite sits between an AI agent's intent and the wallet's execution. It verifies that a constructed transaction actually does what was declared — with a falsifiable confidence score, not a binary safe/unsafe.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![Rust Tests](https://img.shields.io/badge/Rust_Tests-861_passing-brightgreen?style=flat-square)](graphite-core/tests/)
[![Clippy](https://img.shields.io/badge/Clippy-0_warnings-brightgreen?style=flat-square)](graphite-core/)
[![Protocols](https://img.shields.io/badge/Protocol_Manifests-20-blue?style=flat-square)](graphite-core/protocols/)
[![Risk Patterns](https://img.shields.io/badge/Risk_Patterns-9-red?style=flat-square)](graphite-core/src/risk_engine.rs)
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

# Run 861 tests — zero setup
cargo test --release

# Output:
# running 861 tests
# test result: ok. 861 passed; 0 failed; 3 ignored

# Run the benchmark (16 scored cases + 2 baseline comparisons, P16 compliant)
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

**Phase 1.5 status:** L1-L2, L4-L7 active. L3 is active whenever an RPC client is attached (`GRAPHITE_RPC_URL`) — verified end-to-end on Solana devnet. L8 reports an honest **"not yet verified"** state until live execution is wired (Phase 2).

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

## Supported Protocols (20 Manifests)

| Protocol | Program ID | Trust Tier |
|----------|-----------|------------|
| System Program | `11111111111111111111111111111111` | Battle Tested |
| SPL Token | `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` | Battle Tested |
| Token-2022 | `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb` | Official Manifest |
| Stake Program | `Stake11111111111111111111111111111111111111` | Battle Tested |
| Memo (v4.0.0, upgradeable) | `Memo4c2pN8afCj432Lb7RMVKi9PbQnnW7ewFFaV3oAH` | Official Manifest |
| Memo (classic SPL, restored 2026-08-08) | `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr` | Official Manifest |
| Memo (legacy SPL, superseded) | `Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo` | Official Manifest |
| Associated Token Account | `ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL` | Official Manifest |
| Compute Budget | `ComputeBudget111111111111111111111111111111` | Official Manifest |
| BPF Loader (classic) | `BPFLoader2111111111111111111111111111111111` | Official Manifest |
| BPF Loader Upgradeable | `BPFLoaderUpgradeab1e11111111111111111111111` | Official Manifest |
| Jupiter V6 | `JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4` | Battle Tested |
| Orca Whirlpools | `whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc` | Battle Tested |
| Meteora DLMM | `LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo` | Battle Tested |
| Raydium AMM V4 | `675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8` | Battle Tested |
| Squads V4 | `SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf` | Battle Tested |
| Pump.fun | `6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P` | Official Manifest |
| Jupiter DCA | `DCA265Vj8a9CEuX1eb1LWRnDT7uK6q1xMipnNyatn23M` | Official Manifest |
| Wormhole Core | `worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth` | Official Manifest |
| Metaplex Token Metadata | `metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s` | Official Manifest |

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
│   │   ├── regression_engine.rs ← P10 promotion gate + fixture corpus
│   │   ├── manifest_registry.rs ← Signed community manifests (G5/P7/P10/P11)
│   │   ├── plugin_orchestrator.rs ← P8 plugin framework (sole plugin caller)
│   │   ├── plugins/             ← Built-in plugins: FakeRewardsDrainer (L7),
│   │   │                          VerificationEventLogger (analytics)
│   │   ├── benchmark.rs         ← P16-compliant benchmark suite
│   │   └── cli.rs               ← CLI (clap)
│   ├── protocols/               ← 20 JSON protocol manifests
│   └── tests/                   ← 861 tests (unit + adversarial + exploit)
│
├── dashboard/                   ← React + TS dashboard (5 views, polls /api/*)
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
```> ⚠️ The example input uses the `TradingBot` profile (0.80 threshold). On a fresh Core (no earned evidence) the achievable confidence for a known protocol is ~0.44, so this example returns **BLOCKED** — that is the engine being honest, not a bug. The confidence signals are *earned*, not asserted: `SimulationMatch`, `HistoricalVolume`, and `CommunityVerification` read from the Semantic Graph's internal accumulator (RPC-verified baselines and Behavior evidence), so the presets become satisfiable as the graph accumulates verified history. To see an immediate approval on a fresh core, set a calibrated profile:
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

## Dashboard

The read-only dashboard (`dashboard/`) visualizes live Core state — protocol
overview with trust tiers, a Semantic Graph view with directed CPI edges, a
confidence time series, policy violations, and the Manifest Registry.

```bash
cd dashboard
npm install
npm run dev          # dev: proxies /api to http://localhost:7331
npm run build        # production build → dist/
```

It polls the read-only endpoints (`/api/graph`, `/api/confidence-history`,
`/api/policy-violations`, `/api/protocols/top`, `/api/registry`) that the
Core server exposes behind the same Bearer auth and rate limiting as
`/verify`. Point a browser at the dev server (or serve `dist/` statically)
and set `VITE_GRAPHITE_API` if Core lives elsewhere. Read-only by
construction (Constitution P4) — the dashboard never mutates graph state.

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

- The benchmark is 16 scored cases (safe + malicious) plus 2 baseline comparisons — NOT a statistical evaluation on unseen data. "100% precision / 100% recall on the scored benchmark cases" is the honest claim.
- 5 exploit reconstructions use real program IDs but fabricated account structures. They are labeled "SYNTHETIC" per P16, not "real mainnet data."
- L3 (Simulation) is active when an RPC client is attached and was verified against real Solana devnet transactions (Aug 7, 2026). L8 (Execution Verification) still requires live execution infrastructure and honestly reports **"not yet verified"** until then (Phase 2).
- No instruction data semantic parsing beyond discriminator matching (Phase 2).

What we **do** claim:

- **Confidence is calibrated honestly and earned, never asserted (G4).** The three evidence-derived signals (`SimulationMatch`, `HistoricalVolume`, `CommunityVerification`) read from the Semantic Graph's **internal accumulator** — the program's RPC-verified simulation baseline (`sample_count`) and its earned Behavior evidence — never from request-body JSON, which an attacker could fabricate to mint confidence. Trust tiers are capped at `OfficialManifest` (P7: tiers 3+ must be earned via the Semantic Graph, not self-asserted). A fresh Core therefore scores a known, clean, intent-aligned protocol at **~0.44** and the built-in presets (TradingBot 0.80, Treasury 0.95, Gaming 0.60, Enterprise 0.99) block everything until evidence is earned — e.g. Gaming unlocks at simulation-validated evidence (≈ 0.66), Treasury at battle-tested evidence (≈ 0.98). The benchmark and SAK demo default to a `Custom { min_confidence: 0.40, min_trust_tier: OfficialManifest }` profile; `graphite verify --profile <preset>` or `graphite profiles` drives the presets from the CLI. Raise or lower the profile to change policy; the engine's score itself is the honest number.
- 844 Rust tests, 0 failures, 0 clippy warnings — every test has real assertions.
- 8 risk patterns are real detection logic, not stubs.
- 15 protocol manifests with program IDs verified against official on-chain sources (11 seed + Pump.fun, Jupiter DCA, Wormhole Core, Metaplex Token Metadata — all confirmed executable on mainnet 2026-08-07).
- Confidence engine uses real weighted computation with tier ceilings and NaN rejection.
- Simulation integrity uses 3-signal z-score (compute, writes, CPI hops) with Welford's algorithm.
- The SAK integration imports real `solana-agent-kit` v2 and calls real SAK methods — **verified on Solana devnet** (wallet `CWb8MciizembLV66kisYcXo3Cb91hdszxw74QHpEJKZR`, 5 finalized transactions: 2 faucet airdrops + 3 SAK test transfers; latest signature `xHa4dyuFS6JmSaTsmhcMpEtwbWnPjBoUGwk3wNixD2uw2Wmeui6GhnSmmdzNVkv85zXSd6g7QYhHymAjciwP3jJ` confirmed and finalized).

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
