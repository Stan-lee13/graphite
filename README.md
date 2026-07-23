# Graphite

Transaction intent verification for Solana AI agents.

Graphite sits between an AI agent's intent and the wallet's execution. It verifies that a constructed transaction actually does what was declared — with a falsifiable confidence score, staying accurate as protocols evolve.

## Phase 1 + 1.5 — COMPLETE (v0.1.0-alpha)

**Core verification engine** (Rust):
- 8-layer verification pipeline: Account Resolution → Transaction Construction → Risk → Confidence → Policy → Unknown Protocol Mode
- 10 seed protocol manifests (System, SPL Token, Token-2022, Stake, Raydium AMM V4, Squads V4, Jupiter V6, Orca Whirlpools, Meteora DLMM, Memo)
- Risk Engine: 5 P0 patterns (Drainer, AuthorityHijack, HiddenTransfer, UnexpectedCpi, FakeSwap)
- Unknown Protocol Mode with hard confidence ceiling
- Benchmark: 13 cases, 100% precision/recall, ~25-66μs avg latency

**Consumer surfaces:**
- TypeScript SDK + Go SDK (full VerificationResult round-trip)
- CLI (Rust, feature-gated)
- Python AI Layer (advisory-only, separate process — P1 compliance)
- **Solana Agent Kit integration** — end-to-end demo: NL → AI Layer → Graphite Core → SAK execution

**279 tests passing** (266 Rust + 7 Go + 6 Python), 0 clippy warnings.

## Quick Start

### Run the Solana Agent Kit demo

```bash
# 1. Start Graphite Core
cd graphite-core && cargo run --release --bin graphite -- server --port 7331

# 2. Start AI Layer (separate process)
cd python-ai-layer && python3 intent_parser.py --serve --port 8081

# 3. Run the demo (dry-run)
cd integrations/solana-agent-kit
npx tsx demo.ts "Swap 0.5 SOL for USDC"
```

The demo shows the full flow:
1. AI Layer parses "Swap 0.5 SOL for USDC" → ProposedIntent
2. Graphite Core verifies the Jupiter V6 swap → VerificationResult (approved)
3. Agent would execute via `agent.methods.trade()` (dry-run shows the path)

It also demonstrates the security property — a malicious CPI route is **blocked** by Graphite (fail-closed per Constitution P12).

### Run the benchmark

```bash
cd graphite-core
cargo run --release --bin graphite -- benchmark
```

## Documentation

- [Release Evaluation Report](RELEASE_EVALUATION_REPORT.md) — P16 compliant, reproducible
- [Architecture](https://github.com/Stan-lee13/graphite/blob/main/ARCHITECTURE.md) — full system design
- [Engineering Skill](https://github.com/Stan-lee13/graphite-engineering-skill) — the skill that builds Graphite

## License

MIT — Copyright Victor Stanley
