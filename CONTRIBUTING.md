# Contributing to Graphite

Graphite is a transaction verification engine for Solana AI agents. Every contribution must maintain the security and honesty guarantees defined in the [Constitution](https://github.com/Stan-lee13/graphite-engineering-skill/blob/main/CONSTITUTION.md).

## Before You Contribute

1. Read the [Architecture Specification](ARCHITECTURE.md) — understand the 8-layer pipeline and subsystem design
2. Read the [Roadmap](ROADMAP.md) — understand what's in scope for the current phase
3. Check the [Engineering Skill](https://github.com/Stan-lee13/graphite-engineering-skill) — the canonical source for layer names, personas, and checklists

## Branch Rules

- `main` is the integration branch. Every commit on it must have a green GitHub Actions run — the run for the exact SHA, read from the Actions runs endpoint, not a commit message claiming it.
- Branch protection is not yet enabled (owner decision, tracked in `ROADMAP.md`), so the CI gate is a discipline rather than a mechanism today. Treat it as mandatory anyway: a red run is fixed before anything else lands.
- Security fixes ship with a reproduction test, and the fix is reverted once locally to show that test fails without it. Record the result in the round report under `docs/`.
- Historical phase branches (`phase2-development`) are closed; do not target them.

## Development Setup

```bash
# Clone
git clone https://github.com/Stan-lee13/graphite.git
cd graphite

# Rust core
cd graphite-core
cargo build --release
cargo test --release
cargo clippy --release -- -D warnings

# Python AI layer
cd ../python-ai-layer
python3 -m pytest test_intent_parser.py

# TypeScript SDK
cd ../sdk/typescript
npm ci && npm run build && npm test

# SAK integration (the execution boundary) — also regenerates the cross-language corpus
cd ../../integrations/solana-agent-kit
npm ci && npm run typecheck && npm test && npm run emit:corpus
git diff --exit-code -- ../../graphite-core/fixtures/artifacts/   # CI fails on drift

# Run the server locally without a key (loopback only)
cd ../../graphite-core
GRAPHITE_DEV_MODE=1 cargo run --release --bin graphite -- server
```

## Constitution Principles (Non-Negotiable)

Every PR must satisfy all 16 Constitution principles. The most commonly violated:

- **P1**: AI assists, never decides. No LLM output is the final authority on a transaction's safety.
- **P2**: Deterministic verification. Same inputs → same outputs. No timestamps, random numbers, or non-deterministic operations in the verification path.
- **P6**: Unknown protocol confidence cap (0.55). No evidence can override this.
- **P12**: Fail-closed on unknown. Unknown instructions on known protocols return BLOCKED, not an error. Anything Graphite cannot observe is disclosed in `scope.unobserved`, never assumed.
- **P5**: Simulation is evidence, not truth. RPC-derived values come only from canonical response fields and can lower or fail a verdict, never manufacture one.
- **P9**: The audit trail is append-only and synced before the response; a verdict that cannot be recorded is refused.
- **P16**: No public performance claim without a linked, reproducible benchmark run backing the exact number.

## PR Checklist

Every commit to `main` must pass the full CI gate (`.github/workflows/ci.yml`), which runs on every push:

- [ ] `cargo fmt --all -- --check` clean (0 diffs)
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes (0 warnings)
- [ ] `cargo test --release` passes (0 failures — currently 1,444 tests, 10 ignored; `--include-ignored` for the live RPC corpus)
- [ ] `cargo test --release --no-default-features --lib` (301) and `--no-default-features --features cli` (1,281) pass — the feature matrix is tested, not just checked
- [ ] `cargo audit --deny warnings` clean
- [ ] Container builds, boots, `/health` answers, `/data` is writable, unauthenticated `/verify` is `401`, and a keyless container refuses to start
- [ ] TypeScript SDK `npm run build` + `npm test`; SAK integration `npm run typecheck` + `npm test` (73) and the regenerated artifact fixture + corpus show no diff
- [ ] Go SDK `gofmt` / `go vet` / `go test ./...` pass
- [ ] Python AI layer `pytest` passes (27)
- [ ] Dashboard `npm run typecheck` + `npm run build`
- [ ] No new `unwrap()` or `panic!()` in the verification hot path
- [ ] Constitution principles checked (P1-P16)
- [ ] No public performance claim without reproducible benchmark (P16)
- [ ] Layer names match `graphite-engineering-skill/ARCHITECTURE.md` section 3.12
- [ ] Test count and metrics updated in README.md, `docs/CURRENT.md` and the round report if changed
- [ ] A security fix carries its reproduction as a test and a deliberate-break note (fix reverted → test fails)
- [ ] No new credential, RPC URL or key in source, fixtures, logs or reports; no attack against a public RPC — mock it on loopback

## Adding a Protocol Manifest

1. Copy `graphite-core/protocols/` template (use an existing manifest as reference)
2. Verify the program ID against official on-chain sources (not explorer — use official docs/GitHub)
3. Add the program ID to `TRUSTED_COMPOSABILITY_PROGRAMS` in `risk_engine.rs` if it's a DEX/aggregator/multisig (one canonical list; `TRUSTED_CPI_ROOTS` and `DEX_PROGRAMS` are aliases of it) and pin fixed account roles with `expected_address` (`scripts/populate_expected_addresses.py`)
4. Add a test case in the appropriate test file
5. Run the Python cross-check test to validate base58 charset and pubkey length

## Reporting Issues

Use the appropriate issue template:
- [Bug Report](.github/ISSUE_TEMPLATE/bug_report.md)
- [Protocol Manifest Request](.github/ISSUE_TEMPLATE/protocol_manifest.md)
- [Security Report](.github/ISSUE_TEMPLATE/security_report.md) — or see [SECURITY.md](SECURITY.md) for private disclosure
