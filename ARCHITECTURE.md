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

The pipeline executes in order. Each layer is tracked in the verification result with pass/fail status and a human-readable reason.

1. **L1 Account Resolution** — Resolves all accounts, verifies PDAs against protocol manifests
2. **L2 Instruction Verification** — Confirms the instruction discriminator and account count match the manifest's declared shape
3. **L3 Risk Engine** — Pattern-matches against 8 known attack patterns (hard gate, independent of confidence)
4. **L4 State Verification** — Diffs pre/post account state against the manifest's expected state changes
5. **L5 Semantic Verification** — Compares the proposed intent against the Semantic Graph's expected behavior for this program
6. **L6 Confidence Engine** — Computes 0.0–1.0 confidence from weighted signals (manifest match, simulation, historical volume, community verification) plus penalties for failed layers
7. **L7 Policy Engine** — Applies wallet profile thresholds (TradingBot 80%, Treasury 95%, Enterprise 100%, Unrestricted 0%) and trust tier requirements
8. **L8 Emit Verdict** — Returns Approved/Blocked with full breakdown, audit ID, and summary

### Key Properties
- **L3 Risk Engine is a hard gate** — it blocks independently of confidence score. A malicious pattern blocks the transaction even if confidence is high.
- **L6 Confidence Engine applies tier ceilings** — Unknown/Heuristic protocols are capped at 0.55 (hard-coded, not overridable per P12).
- **L7 Policy Engine is the final gate** — it checks both confidence threshold and minimum trust tier for the wallet's profile.
- **L3 runs before L4/L5** — risk patterns are checked before expensive state/semantic verification.
- **Simulation (L3 in original spec) is deferred to Phase 2** — the current pipeline does not include RPC simulation.

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
├── schemas/                # JSON schemas (proposed-intent, verification-result)
├── examples/               # Usage examples
├── Dockerfile              # Multi-stage container build
└── .github/                # CI workflows + issue templates
```
