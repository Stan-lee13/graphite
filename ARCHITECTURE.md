# Graphite — Architecture

## Overview

Graphite is a structural transaction verification engine for Solana. It verifies
that transactions constructed by AI agents match their declared intent by checking
program IDs, CPI chains, account structures, and risk patterns against a curated
knowledge base of protocol manifests.

**Honest framing:** Graphite performs deterministic pattern matching on program
identity, CPI chains, and account structures — not semantic AI-based intent
verification. The AI layer (Python, separate process) parses natural language
into a JSON label; the Rust core makes all security decisions deterministically.

## Language Split

| Component | Language | Why |
|---|---|---|
| Core engine | Rust | Deterministic, no GC, auditable, fast |
| AI layer (advisory) | Python | Separate process — enforces P1 (AI assists, never decides) |
| SDK | TypeScript + Go | Consumer-facing, typed |

## 8-Layer Verification Pipeline

1. **Account Resolution** — Resolves all accounts, verifies PDAs against protocol manifests
2. **Transaction Construction** — Reconstructs the transaction from instruction data
3. **Risk Engine** — Pattern-matches against 8 known attack patterns
4. **Confidence Engine** — Computes 0.0–1.0 confidence from multiple signals
5. **Protocol Intelligence** — Matches against protocol manifests (10 seed protocols)
6. **Simulation Integrity** — Compares expected vs simulated state changes
7. **Policy Engine** — Applies risk profiles (Conservative, Standard, Permissive, Enterprise)
8. **Emit Verdict** — Returns Verified/Blocked/Unknown with full breakdown

## Security Boundaries (Constitution)

- **P1:** AI assists, never decides — separate process, no override capability
- **P2:** Deterministic/reproducible — same input → same output, always
- **P3:** Confidence scored (0.0–1.0), never bare boolean
- **P12:** Unknown protocols capped at 0.55 confidence — hard-coded, not overridable
- **P16:** No public performance claim without reproducible benchmark

## What Graphite Does NOT Do (Honest)

- Does NOT parse instruction data semantics (instruction bytes are not analyzed)
- Does NOT detect novel attack patterns (only known patterns are matched)
- Does NOT use AI/ML in the verification path (deterministic pattern matching only)
- Does NOT verify intent semantically (intent is a label, not a semantic constraint)
- Does NOT work on chains other than Solana (SVM-specific, complete rewrite needed)

## Repository Structure

```
graphite/
├── graphite-core/          # Rust verification engine
│   ├── src/
│   ├── protocols/          # Protocol manifests (JSON)
│   ├── tests/              # Test suite
│   └── Cargo.toml
├── sdk/
│   ├── typescript/         # TypeScript SDK
│   └── go/                 # Go SDK
├── python-ai-layer/        # Advisory intent parser (separate process)
├── integrations/
│   └── solana-agent-kit/   # SAK integration adapter
├── schemas/                # JSON schemas (proposed-intent, verification-result)
├── examples/               # Usage examples
├── Dockerfile              # Multi-stage container build
└── .github/                # CI workflows + issue templates
```
