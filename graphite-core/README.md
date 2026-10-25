# graphite-core

The Rust verification engine — the heart of Graphite.

## Modules (Phase 2 — all active production modules)

| Module | Responsibility | Layer |
|--------|---------------|-------|
| `account_resolution` | PDA derivation (Solana hash-chain algorithm), account role validation | L1 |
| `verification` | 8-layer pipeline orchestrator (L1–L8) — implements L2 Instruction Verification and L4 State Verification inline | L2/L4 |
| `transaction_builder` | `InstructionPlan` / `InstructionSummary`: a validated summary of one instruction and a compute-unit ESTIMATE, not wire bytes (renamed in Round 30; the old names are deprecated aliases) | — |
| `risk_engine` | 10 of the 13 detection patterns in 16 checks, hard gate (two more come from `tx_pattern_analysis` and `UnboundedWithdrawal` from `intent_grants`; the 14th `RiskPattern`, `PluginBlock`, names a plugin veto) | L7 |
| `confidence_engine` | Weighted signal scoring + trust tier ceilings | L6 |
| `policy_engine` | Per-wallet profile thresholds (Treasury, TradingBot, Gaming, Enterprise) | L6 |
| `simulation_integrity` | 3-signal z-score (compute, writes, CPI hops) with Welford's algorithm + MAD baseline | L3 |
| `semantic_graph_store` | Trust tier computation, append-only storage, earned baselines with an exact per-program observation memory (Round 19) | L5 |
| `unknown_protocol_mode` | 0.55 confidence ceiling for unknown protocols (P6/P12) | — |
| `server` | HTTP API (axum) on port 7331 | — |
| `regression_engine` | P10 promotion gate: fixture corpus + deterministic replay (99.5%) | — |
| `manifest_registry` | Signed community manifest submissions (G5/P7/P10/P11): the registry owns its regression corpus, enforces version lineage, verifies a domain-tagged signature, and can revoke a reviewer | — |
| `plugin_orchestrator` | P8 plugin framework: 6 traits, review gate, panic-isolated execution | — |
| `plugins` | Built-in plugins: FakeRewardsDrainer (L7 risk), VerificationEventLogger (analytics) | L7/L8 |
| `benchmark` | P16-compliant benchmark suite (24 cases, 22 scored; an approve-all comparison row; plugin overhead) | — |
| `cli` | CLI interface (clap) | — |
| `operator_boundary` | The trust-boundary rules the server and the CLI share: profile pin, weak-`Custom` clamp, permissive opt-out, plugins directory, durable nonces, upgrade quarantine, the three Round 32 relaxations (unreadable value declarations, W19, unbounded withdrawals; each strict-parsed and logged); the retired learning variable refuses to start (Round 30) | — |
| `durable` | Append-only audit trail (P4/P9): `sync_data` per record, rotation by rename, archives read by every consumer through persisted, checked indexes (`src/durable/archive_index.rs`), the lifecycle emission table, health counters; since Round 30 a hash chain across rotation with an optional HMAC key, `graphite audit verify` / `checkpoint`, and one writer per trail (`src/durable/chain.rs`) | — |
| `tx_artifact` | Wire-format parser (legacy, v0 and — since Round 19 — v1): canonical compact-u16, header privileges, lookup-table resolution, runtime account numbering, durable-nonce detection, `message_bytes`, `simulation_identity` (the baseline's observation key: signatures and blockhash zeroed) | L1/L2 |
| `state_diff` | Pre/post account diff; SPL Token / Token-2022 decoding; Token-2022 extension classification (fail-closed on unreadable regions) | L4 |
| `solana_types` | PDA derivation, base58, 32-byte pubkeys — no `solana-sdk` dependency | — |
| `live_corpus` | Pinned real on-chain transaction corpus for regression testing | — |
| `intent_grants` | Round 30: the 21 named instructions a `withdraw` / `claim` / `close` / `burn` / `configure` intent may clear, each only when the transaction's own accounts show the proceeds or rent go to the signer | L5/L7 |
| `manifest` | Seed manifest loader (one compile-time `include_str!` list) + the trust-tier evidence gate | — |
| `rpc_client` | Solana RPC client for live L3/L8 verification | — |
| `tx_pattern_analysis` | Multi-instruction + CPI trace analysis (C29), run on the call tree the simulator reports (Round 19) | — |

## Build

```bash
cargo build --release    # 3.1MB binary
cargo test --release --all-features                        # the full suite; counts: ../docs/CURRENT.md
cargo test --release --no-default-features --lib            # the featureless library
cargo test --release --no-default-features --features cli   # cli without the server
cargo clippy --release -- -D warnings  # 0 warnings
```

## Run

```bash
# HTTP server (authenticated by default; GRAPHITE_DEV_MODE=1 for a keyless loopback-only instance)
GRAPHITE_API_KEY=$(openssl rand -hex 32) cargo run --release --bin graphite -- server --port 7331

# CLI
cargo run --release --bin graphite -- verify --file ../examples/verify-input.json

# Benchmark
cargo run --release --bin graphite -- benchmark
```

## Protocol Manifests

137 JSON manifests in `protocols/`, 3,541 instructions. Each carries the program
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
- **Health and metrics** — `/health` (open, exempt from rate limiting and load shedding) reports `degraded_reasons`, audit and rotation counters, `frozen_baseline_count` and snapshot health; `/metrics` (keyed; also the read-only key since Round 30) exports 30 Prometheus series (Round 30 added `graphite_audit_tamper_evident` and `graphite_audit_anchor_writes_failed_total`); `GET /api/frozen-baselines` (keyed) lists the frozen programs
- **L8 and lifecycle** — `POST /verify/execution` reconciles a signature against the recorded verdict across the whole trail; `POST /audit/event` records caller-reported signing/submission/confirmation/finalization as attestations
- **Operator switches** — `/admin/quarantine` (the separate operator key `GRAPHITE_ADMIN_API_KEY`; disabled without it — Round 19), `GRAPHITE_WALLET_PROFILE`, `GRAPHITE_ALLOW_PERMISSIVE_PROFILES`, `GRAPHITE_ALLOW_DURABLE_NONCE`, `GRAPHITE_QUARANTINE_ON_UPGRADE` (quarantine a program found redeployed since last seen; detection itself is always on with an RPC, and since Round 30 an upgrade withdraws the program's evidence), `GRAPHITE_L8_HIGH_ASSURANCE` (Round 30), the read-only `GRAPHITE_READ_API_KEY` (Round 30), and the Round 32 relaxations `GRAPHITE_ALLOW_UNREADABLE_VALUE_DECLARATIONS`, `GRAPHITE_ALLOW_SIGNER_LAMPORTS_OUTSIDE_DECLARED_DEBIT` and `GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS` (each off: the refusal is the default); all default closed, every variable refuses to start on a value it cannot parse, and the retired `GRAPHITE_LEARN_FROM_POLICY_REFUSALS` refuses to start with any value
- **Graceful shutdown**; `X-Forwarded-For` only honored behind an explicit trusted-proxy flag
- **Live L3** when `GRAPHITE_RPC_URL` is set — `simulateTransaction` runs with real compute feeding the trusted baseline accumulator (checked by hand on Solana devnet through an ignored live test, C40); a failed or incomplete simulation refuses the verdict (Round 29). Without it, L3 is Inconclusive, the verdict carries `not_simulated`, and every approval is `decision: analysis_only` — never permission to sign (Round 30)
- **Live L8** — execution verification reports honest on-chain status (Confirmed/Unknown/Unavailable), checked by hand against mainnet RPC through an ignored live test (C40); since Round 30 each reconciliation states its `inclusion_assurance`
