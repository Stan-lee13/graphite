# graphite-core

The Rust verification engine — the heart of Graphite.

## Modules (Phase 1.5 — all active production modules)

| Module | Responsibility | Layer |
|--------|---------------|-------|
| `account_resolution` | PDA derivation, account role validation | L1 |
| `transaction_builder` | Canonical serialization, compute budget estimate | — |
| `risk_engine` | 8 attack pattern detectors (hard gate) | L7 |
| `confidence_engine` | Weighted signal scoring + trust tier ceilings | L6 |
| `policy_engine` | Per-wallet profile thresholds (Treasury, TradingBot, Gaming, Enterprise) | L6 |
| `simulation_integrity` | 3-signal z-score (compute, writes, CPI hops) with Welford's algorithm | L3 |
| `semantic_graph_store` | Trust tier computation, append-only storage | L5 |
| `unknown_protocol_mode` | 0.55 confidence ceiling for unknown protocols (P6/P12) | — |
| `server` | HTTP API (axum) on port 7331 | — |
| `benchmark` | P16-compliant benchmark suite (18 cases) | — |
| `cli` | CLI interface (clap) | — |

## Build

```bash
cargo build --release    # 3.1MB binary
cargo test --release     # 635 tests
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

11 JSON manifests in `protocols/`. Each contains the program ID, trust tier, instructions with discriminators, expected accounts, and allowed CPI targets.

All program IDs verified against official on-chain sources. See `CONTRIBUTING.md` for how to add a new manifest.
