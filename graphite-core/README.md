# graphite-core

Rust core starter for Graphite.

## Modules (Phase 1 + 1.5 — active production modules)

- `account_resolution` — PDA derivation and account role validation
- `transaction_builder` — Canonical serialization and compute budget estimation
- `risk_engine` — 5 P0 risk patterns (Drainer, AuthorityHijack, HiddenTransfer, UnexpectedCpi, FakeSwap)
- `confidence_engine` — Weighted signal scoring with trust tier ceilings
- `policy_engine` — Wallet profile enforcement (Risk → Confidence → TrustTier ordering)
- `unknown_protocol_mode` — Hard 0.55 ceiling on unknown protocols (Constitution P12)
- `semantic_graph_store` — Append-only behavior ledger with quarantine support (Constitution P4)
- `simulation_integrity` — 3-signal z-score baseline comparison (Welford's algorithm)
- `manifest` — Protocol manifest registry (10 seed protocols, baked at compile time)
- `verification` — 8-layer pipeline coordinator (L1–L7 active, L8 deferred to Phase 2)

## Primary entry point

Use `GraphiteVerifier::verify(...)` from `src/verification.rs`.

## Quick start

```bash
cargo test --release          # 630 tests, 0 failures, 0 clippy warnings
cargo run --release -- benchmark   # 18 cases, 100% precision/recall, ~25μs avg latency
cargo run --release -- server      # HTTP server on :7331 (requires --features server)
cargo run --release --no-default-features --features cli -- verify <tx.json>
```
