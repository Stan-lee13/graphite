# Graphite — Architecture

## Overview

Graphite is a deterministic semantic verification engine for Solana. It verifies
that transactions constructed by AI agents match their declared intent by checking
program IDs, CPI chains, account structures, cross-instruction patterns, and risk
patterns against a curated knowledge base of 22 protocol manifests covering 561
instructions.

**Honest framing:** Graphite performs deterministic pattern matching on program
identity, CPI chains, and account structures. The AI layer (Python, separate process)
parses natural language into a JSON label; the Rust core makes all security decisions
deterministically. The semantic layer (L5) verifies intent↔program alignment —
intent is a label, not a semantic constraint, but the alignment check is real and
fail-closed.

## Language Split

| Component | Language | Why |
|---|---|---|
| Core engine | Rust | Deterministic, no GC, auditable, fast |
| AI layer (advisory) | Python | Separate process — enforces P1 (AI assists, never decides) |
| SDK | TypeScript + Go | Consumer-facing, typed |

## 8-Layer Verification Pipeline

The pipeline executes in order. Each layer is tracked in the verification result with pass/fail status and a human-readable reason.

1. **L1 Account Resolution** — Resolves all accounts, verifies PDAs against protocol manifests (PDA derivation uses Solana's actual `create_program_address` hash-chain algorithm)
2. **L2 Instruction Verification** — Confirms the instruction discriminator and account count match the manifest's declared shape (exact-match, no prefix bypass since C33)
3. **L3 Simulation Verification** — Runs `simulateTransaction` and checks compute/account-write/CPI divergence. Active whenever an RPC client is attached (`GRAPHITE_RPC_URL`); the simulation-integrity module runs a 3-signal z-score (compute, writes, CPI hops) with Welford's algorithm against earned baselines, plus median/MAD baseline (C28) for poisoning resistance. Live-validated against real Solana devnet transactions (C40). Without an RPC client the layer reports an honest `Inconclusive` state, never a phantom pass.
4. **L4 State Verification** — Diffs pre/post account state against the manifest's expected state changes
5. **L5 Semantic Verification** — Compares the proposed intent against the Semantic Graph's expected behavior for this program. The intent vocabulary is exactly: `swap|trade|exchange`, `transfer|send`, `stake|delegate`, `close|close_account`, `create|create_account`, `approve|revoke` (anything else fails closed). The advisory labeler (v2, C21) emits only this vocabulary.
6. **L6 Policy Verification** — Computes confidence (0.0–1.0 from weighted signals + tier ceilings) and applies wallet profile thresholds (TradingBot 80%, Treasury 95%, Gaming 60%, Enterprise 99%) and trust tier requirements
7. **L7 Risk Verification** — Pattern-matches against 11 known attack patterns (14 risk checks, hard gate, independent of confidence): Drainer, HiddenTransfer, AuthorityHijack, FakeSwap, UnexpectedCpi, PermissionEscalation, MaliciousAccountChange, CompositionalDrainPattern, Impersonation (system-account impersonation — SolPhishHunter arXiv:2505.04094), MultiInstructionDrain (C29), and CpiTraceAnomaly (C29). Runs early for fail-fast but is reported at L7 per architecture spec.
8. **L8 Execution Verification** — Post-submission: confirm finalized on-chain result matches prediction. Live-validated against real mainnet RPC (C40) — reports honest execution status (Confirmed / Unknown / Unavailable). Production default-on wiring pending public deployment.

### Key Properties
- **L7 Risk Verification is a hard gate** — it blocks independently of confidence score. A malicious pattern blocks the transaction even if confidence is high. The Risk Engine executes early in the pipeline (before L4/L5) for fail-fast performance, but is reported at L7 per this spec.
- **L6 Policy Verification applies tier ceilings** — Unknown/Heuristic protocols are capped at 0.55 (hard-coded, not overridable per P12). Confidence computation is included in L6.
- **L6 Policy Verification is the final gate** — it checks both confidence threshold and minimum trust tier for the wallet's profile.
- **L3 Simulation Verification is active when an RPC client is attached** — `GRAPHITE_RPC_URL` wires a live `simulateTransaction` call into the pipeline, live-validated against real Solana devnet transactions (C40). Without an RPC client, L3 reports `Inconclusive` (honest tri-state: `Passed` / `Failed` / `Inconclusive`) rather than a phantom pass.

## Security Boundaries (Constitution)

- **P1:** AI assists, never decides — separate process, no override capability
- **P2:** Deterministic/reproducible — same input → same output, always (`content_hash` = SHA-256)
- **P3:** Confidence scored (0.0–1.0), never bare boolean
- **P12:** Unknown protocols capped at 0.55 confidence — hard-coded, not overridable
- **P16:** No public performance claim without reproducible benchmark

## Server (HTTP API)

The axum-based HTTP server exposes `POST /verify`, `GET /manifests` (listing), `GET /health`, and the read-only dashboard API (`/api/graph`, `/api/confidence-history`, `/api/policy-violations`, `/api/protocols/top`, `/api/registry`).

| Concern | Implementation |
|---|---|
| **Authentication** | Optional Bearer API key (`GRAPHITE_API_KEY`), compared in constant time (SHA-256). `/verify` and `/manifests` require it when set; `/health` stays open for load balancers. |
| **Rate limiting** | Per-IP token bucket (`GRAPHITE_RATE_LIMIT`, default 30 req/s), FIFO eviction, returns `429` on exhaustion. |
| **CORS** | Denied by default; `GRAPHITE_CORS_ORIGINS` (comma-separated) enables specific browser origins. Server-to-server clients are unaffected. |
| **Audit log** | Append-only JSONL (`audit.jsonl` under `GRAPHITE_DATA_DIR`) written after every verification — covers all four outcomes: approved, blocked, HTTP 400, HTTP 500. |
| **Durability** | Semantic-graph snapshot (trust tiers + earned simulation baselines) and the audit log are reloaded on restart. |
| **Graceful shutdown** | SIGINT/SIGTERM drain in-flight requests before exit. |
| **Trusted proxy** | `X-Forwarded-For` is honored only when the server is explicitly configured behind a trusted proxy. |

## What Graphite Does NOT Do (Honest)

- Does NOT parse instruction data semantics beyond the discriminator (instruction bytes are not analyzed for meaning)
- Does NOT detect novel attack patterns (only the 11 known patterns / 14 checks are matched)
- Does NOT use AI/ML in the verification path (deterministic pattern matching only; the Python layer is an advisory labeler)
- Does NOT treat the advisory labeler's suggestions as decisions — a wrong suggestion simply fails to match and the verification blocks (P1)
- Does NOT work on chains other than Solana (SVM-specific, complete rewrite needed)
- Does NOT hold wallet private keys — the Rust core never receives signing material; keys live at the wallet/SAK boundary (the integration bridge holds them to execute, like any self-custody agent wallet)

## Known Boundary Limitations (honest)

- **SAK swap-path TOCTOU residual:** AuditBind can bind the EXACT instruction the caller supplies (`verifyInstruction`), but the SAK `methods.swap` path rebuilds the swap instruction internally — so a bound payload is not guaranteed to be the executed instruction. `GRAPHITE_SWAP_STRICT=1` requires a payload but does not by itself force the executor to submit it. Operators who need full TOCTOU closure must execute the bound payload directly (build + sign the verified instruction themselves) rather than delegating to SAK's internal builder. The transfer path is fully bound (same instruction object is verified and executed).

## Repository Structure

```
graphite/
├── graphite-core/          # Rust verification engine
│   ├── src/                # core modules + plugins/ + feature-gated server/cli/rpc
│   ├── protocols/          # 22 JSON protocol manifests (561 instructions)
│   ├── tests/              # 984 tests (unit + adversarial + exploit + pinned real corpus)
│   └── Cargo.toml
├── sdk/
│   ├── typescript/         # TypeScript SDK (GraphiteClient)
│   └── go/                 # Go SDK (16-field VerificationResult parity)
├── integrations/
│   └── solana-agent-kit/   # SAK v2 integration (verified execution gate)
├── python-ai-layer/        # Advisory intent parser (separate process, P1)
├── schemas/                # JSON schemas (proposed-intent, verification-result)
├── examples/               # Sample verification inputs/outputs
├── docs/                   # Audit reports, certification, grant proposal
├── .github/                # CI workflow + issue templates
├── ARCHITECTURE.md          # This file
├── ROADMAP.md              # Phase 1 (done) → Phase 2 (in progress) → Phase 3+
├── SECURITY.md             # Security policy + known limitations
├── CONTRIBUTING.md         # Development setup + PR checklist
├── Dockerfile              # Multi-stage container build
└── LICENSE                 # MIT
```
