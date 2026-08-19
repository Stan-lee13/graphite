# graphite-core

The Rust verification engine — the heart of Graphite.

## Modules (Phase 2 — all active production modules)

| Module | Responsibility | Layer |
|--------|---------------|-------|
| `account_resolution` | PDA derivation (Solana hash-chain algorithm), account role validation | L1 |
| `verification` | 8-layer pipeline orchestrator (L1–L8) — implements L2 Instruction Verification and L4 State Verification inline | L2/L4 |
| `transaction_builder` | Canonical serialization, compute budget estimate | — |
| `risk_engine` | 11 attack pattern detectors (13 risk checks, hard gate) | L7 |
| `confidence_engine` | Weighted signal scoring + trust tier ceilings | L6 |
| `policy_engine` | Per-wallet profile thresholds (Treasury, TradingBot, Gaming, Enterprise) | L6 |
| `simulation_integrity` | 3-signal z-score (compute, writes, CPI hops) with Welford's algorithm + MAD baseline | L3 |
| `semantic_graph_store` | Trust tier computation, append-only storage | L5 |
| `unknown_protocol_mode` | 0.55 confidence ceiling for unknown protocols (P6/P12) | — |
| `server` | HTTP API (axum) on port 7331 | — |
| `regression_engine` | P10 promotion gate: fixture corpus + deterministic replay (99.5%) | — |
| `manifest_registry` | Signed community manifest submissions (G5/P7/P10/P11) | — |
| `plugin_orchestrator` | P8 plugin framework: 6 traits, review gate, panic-isolated execution | — |
| `plugins` | Built-in plugins: FakeRewardsDrainer (L7 risk), VerificationEventLogger (analytics) | L7/L8 |
| `benchmark` | P16-compliant benchmark suite (16 scored cases + 2 baseline comparisons + plugin overhead) | — |
| `cli` | CLI interface (clap) | — |
| `durable` | Append-only audit trail (P4) | — |
| `live_corpus` | Pinned real on-chain transaction corpus for regression testing | — |
| `manifest` | Runtime manifest loader (compile-time include_str! baking) | — |
| `rpc_client` | Solana RPC client for live L3/L8 verification | — |
| `tx_pattern_analysis` | Multi-instruction + CPI trace analysis (C29) | — |

## Build

```bash
cargo build --release    # 3.1MB binary
cargo test --release     # 1,014 tests (0 failures, 10 network-dependent ignored)
cargo clippy --release -- -D warnings  # 0 warnings
```

## Run

```bash
# HTTP server
cargo run --release --bin graphite -- server --port 7331

# CLI
cargo run --release --bin graphite -- verify --input examples/verify-input.json

# Benchmark
cargo run --release --bin graphite -- benchmark
```

## Protocol Manifests

33 JSON manifests in `protocols/` covering all major Solana programs. Each contains the program ID, trust tier, instructions with discriminators, expected accounts, and allowed CPI targets. 803 instructions total.

All program IDs verified against official on-chain sources (pinned by `test_all_seed_manifest_program_ids_are_canonical`). See `CONTRIBUTING.md` for how to add a new manifest.

## Server Features

When run via `cargo run --release --bin graphite -- server --port 7331`, the HTTP server includes:

- **Bearer API key auth** (constant-time SHA-256 comparison) via `GRAPHITE_API_KEY` — required on `/verify` and `/manifests` when set; `/health` stays open
- **Per-IP token-bucket rate limiting** (`GRAPHITE_RATE_LIMIT`, returns 429, FIFO eviction)
- **CORS denied by default**, allowlist via `GRAPHITE_CORS_ORIGINS`
- **Audit log** — append-only JSONL (`audit.jsonl` in `GRAPHITE_DATA_DIR`) covering approved/blocked/400/500 paths
- **Graceful shutdown**; `X-Forwarded-For` only honored behind an explicit trusted-proxy flag
- **Live L3** when `GRAPHITE_RPC_URL` is set — `simulateTransaction` runs with real compute feeding the trusted baseline accumulator (live-validated on Solana devnet, C40)
- **Live L8** — execution verification reports honest on-chain status (Confirmed/Unknown/Unavailable), live-validated against mainnet RPC (C40)
