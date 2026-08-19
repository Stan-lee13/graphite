# Contributing to Graphite

Graphite is a transaction verification engine for Solana AI agents. Every contribution must maintain the security and honesty guarantees defined in the [Constitution](https://github.com/Stan-lee13/graphite-engineering-skill/blob/main/CONSTITUTION.md).

## Before You Contribute

1. Read the [Architecture Specification](ARCHITECTURE.md) — understand the 8-layer pipeline and subsystem design
2. Read the [Roadmap](ROADMAP.md) — understand what's in scope for the current phase
3. Check the [Engineering Skill](https://github.com/Stan-lee13/graphite-engineering-skill) — the canonical source for layer names, personas, and checklists

## Branch Rules

- **Phase 1 / 1.5 maintenance:** fixes go to `main` only via `hotfix/*` branches (critical bugs).
- **All Phase 2 work goes to `phase2-development`** (feature branches `feature/*` merge into it). **No direct pushes to `main` during Phase 2** — `main` receives Phase 2 work only via PR after Phase 2 certification.
- Start from `phase2-development` (`git checkout phase2-development && git pull origin phase2-development`); if it is behind `main`, rebase first.

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
npx tsc --noEmit
```

## Constitution Principles (Non-Negotiable)

Every PR must satisfy all 16 Constitution principles. The most commonly violated:

- **P1**: AI assists, never decides. No LLM output is the final authority on a transaction's safety.
- **P2**: Deterministic verification. Same inputs → same outputs. No timestamps, random numbers, or non-deterministic operations in the verification path.
- **P6**: Unknown protocol confidence cap (0.55). No evidence can override this.
- **P12**: Fail-closed on unknown. Unknown instructions on known protocols return BLOCKED, not an error.
- **P16**: No public performance claim without a linked, reproducible benchmark run backing the exact number.

## PR Checklist

Every merge to `phase2-development` (and every `hotfix/*` to `main`) must pass the full CI gate. CI runs these on every push — a red CI blocks the merge:

- [ ] `cargo fmt --all -- --check` clean (0 diffs)
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes (0 warnings)
- [ ] `cargo test --release` passes (0 failures — currently 1,014 tests; `--include-ignored` for the live devnet corpus)
- [ ] `cargo check --no-default-features` builds (embedded-use contract; async code is gated behind `--features rpc`)
- [ ] TypeScript SDK `npm run build` / `tsc --noEmit` clean
- [ ] Go SDK `go test ./...` passes
- [ ] Python AI layer `pytest` passes
- [ ] No new `unwrap()` or `panic!()` in the verification hot path
- [ ] Constitution principles checked (P1-P16)
- [ ] No public performance claim without reproducible benchmark (P16)
- [ ] Layer names match `graphite-engineering-skill/ARCHITECTURE.md` section 3.12
- [ ] Test count and metrics updated in README.md and ROADMAP.md if changed

## Adding a Protocol Manifest

1. Copy `graphite-core/protocols/` template (use an existing manifest as reference)
2. Verify the program ID against official on-chain sources (not explorer — use official docs/GitHub)
3. Add the program ID to `TRUSTED_CPI_ROOTS` and `SWAP_PROGRAMS` in `risk_engine.rs` if it's a DEX
4. Add a test case in the appropriate test file
5. Run the Python cross-check test to validate base58 charset and pubkey length

## Reporting Issues

Use the appropriate issue template:
- [Bug Report](.github/ISSUE_TEMPLATE/bug_report.md)
- [Protocol Manifest Request](.github/ISSUE_TEMPLATE/protocol_manifest.md)
- [Security Report](.github/ISSUE_TEMPLATE/security_report.md) — or see [SECURITY.md](SECURITY.md) for private disclosure
