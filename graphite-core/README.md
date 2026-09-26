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
| `semantic_graph_store` | Trust tier computation, append-only storage, earned baselines with an exact per-program observation memory (Round 19) | L5 |
| `unknown_protocol_mode` | 0.55 confidence ceiling for unknown protocols (P6/P12) | — |
| `server` | HTTP API (axum) on port 7331 | — |
| `regression_engine` | P10 promotion gate: fixture corpus + deterministic replay (99.5%) | — |
| `manifest_registry` | Signed community manifest submissions (G5/P7/P10/P11) | — |
| `plugin_orchestrator` | P8 plugin framework: 6 traits, review gate, panic-isolated execution | — |
| `plugins` | Built-in plugins: FakeRewardsDrainer (L7 risk), VerificationEventLogger (analytics) | L7/L8 |
| `benchmark` | P16-compliant benchmark suite (18 scored cases + 2 baseline comparisons + plugin overhead) | — |
| `cli` | CLI interface (clap) | — |
| `durable` | Append-only audit trail (P4/P9): `sync_data` per record, rotation by rename, archives read by every consumer, health counters | — |
| `tx_artifact` | Wire-format parser (legacy, v0 and — since Round 19 — v1): canonical compact-u16, header privileges, lookup-table resolution, runtime account numbering, durable-nonce detection, `message_bytes`, `simulation_identity` (the baseline's observation key: signatures and blockhash zeroed) | L1/L2 |
| `state_diff` | Pre/post account diff; SPL Token / Token-2022 decoding; Token-2022 extension classification (fail-closed on unreadable regions) | L4 |
| `solana_types` | PDA derivation, base58, 32-byte pubkeys — no `solana-sdk` dependency | — |
| `live_corpus` | Pinned real on-chain transaction corpus for regression testing | — |
| `manifest` | Seed manifest loader (one compile-time `include_str!` list) + the trust-tier evidence gate | — |
| `rpc_client` | Solana RPC client for live L3/L8 verification | — |
| `tx_pattern_analysis` | Multi-instruction + CPI trace analysis (C29), run on the call tree the simulator reports (Round 19) | — |

## Build

```bash
cargo build --release    # 3.1MB binary
cargo test --release     # 1,652 tests (0 failures, 15 network- or sample-dependent ignored)
cargo test --release --no-default-features --lib            # 327 — the featureless library
cargo test --release --no-default-features --features cli   # 1,436 — cli without the server
cargo clippy --release -- -D warnings  # 0 warnings
```

## Run

```bash
# HTTP server (authenticated by default; GRAPHITE_DEV_MODE=1 for a keyless loopback-only instance)
GRAPHITE_API_KEY=$(openssl rand -hex 32) cargo run --release --bin graphite -- server --port 7331

# CLI
cargo run --release --bin graphite -- verify --input examples/verify-input.json

# Benchmark
cargo run --release --bin graphite -- benchmark
```

## Protocol Manifests

129 JSON manifests in `protocols/`, 3,192 instructions. Each carries the program
ID, trust tier, instructions with discriminators, expected accounts and allowed
CPI targets. Ninety-six of them were generated in Round 18 from each program's
**own on-chain Anchor IDL** — the account the program itself owns — after the
programs were ranked by real usage over a sample of finalized mainnet blocks.

All program IDs are verified against on-chain sources and pinned in both
directions by `test_all_seed_manifest_program_ids_are_canonical`;
`test_every_protocol_file_is_a_seed_manifest` additionally fails if a file in
`protocols/` is never loaded.

`protocols/battle_tested_evidence.json` holds a mainnet measurement for every
manifest — executable account, successful-transaction count over a stated
window, and the share of really-observed instructions the manifest can name.
**A manifest may not award itself a tier**: `load_seed_manifests` lowers a
declared `BattleTested` to `OfficialManifest` unless that record clears the bar
in `manifest::battle_tested_bar`. Reproduce the measurements with
`scripts/battle_tested_census.py`; see `docs/protocol-coverage.md` for the
rendered table and `CONTRIBUTING.md` for how to add a manifest.

## Server Features

When run via `cargo run --release --bin graphite -- server --port 7331`, the HTTP server includes:

- **Bearer API key auth** (constant-time SHA-256 comparison) via `GRAPHITE_API_KEY` — required by default on every route except `/health`; the server refuses to start without a key unless `GRAPHITE_DEV_MODE=1` (loopback only)
- **Per-IP token-bucket rate limiting** (`GRAPHITE_RATE_LIMIT`, returns 429, FIFO eviction)
- **CORS denied by default**, allowlist via `GRAPHITE_CORS_ORIGINS`
- **Audit trail** — append-only JSONL (`audit.jsonl` in `GRAPHITE_DATA_DIR`), every record synced to the device before the response; a verdict that cannot be recorded is refused with `503`; rotation is a rename and every reader covers the archives
- **Health and metrics** — `/health` (open) reports `degraded_reasons`, audit and rotation counters and snapshot health; `/metrics` (keyed) exports Prometheus counters
- **L8 and lifecycle** — `POST /verify/execution` reconciles a signature against the recorded verdict across the whole trail; `POST /audit/event` records caller-reported signing/submission/confirmation/finalization as attestations
- **Operator switches** — `/admin/quarantine` (the separate operator key `GRAPHITE_ADMIN_API_KEY`; disabled without it — Round 19), `GRAPHITE_WALLET_PROFILE`, `GRAPHITE_ALLOW_PERMISSIVE_PROFILES`, `GRAPHITE_ALLOW_DURABLE_NONCE`; all default closed
- **Graceful shutdown**; `X-Forwarded-For` only honored behind an explicit trusted-proxy flag
- **Live L3** when `GRAPHITE_RPC_URL` is set — `simulateTransaction` runs with real compute feeding the trusted baseline accumulator (live-validated on Solana devnet, C40)
- **Live L8** — execution verification reports honest on-chain status (Confirmed/Unknown/Unavailable), live-validated against mainnet RPC (C40)
