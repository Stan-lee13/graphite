# Graphite — Solana Foundation Developer Tooling Grant Proposal

## 1. Applicant Information

**Project / Tool Name:** Graphite

**Applicant / Organization:** Victor Stanley

**Primary Contact:** Victor Stanley — Stanleyvic13@gmail.com

**Total Amount Requested (USD):** $120,000

**Relevant Experience & Track Record:**

Graphite is a Rust transaction-verification engine that has been built iteratively through 1,014 tests, two independent adversarial security audits (findings C33–C44), and live validation against real Solana mainnet and devnet transactions. The codebase has grown from a Phase 1 MVP (account resolution + risk engine) through a Phase 2 expansion (multi-instruction pattern analysis, CPI trace analysis, live corpus collection, regression engine) to a Phase 3 production-ready system with an HTTP server, TypeScript/Go SDKs, Python advisory layer, React dashboard, Dockerfile, and a SolanaAgentKit integration verified end-to-end on devnet with 5 finalized transactions.

Key technical artifacts delivered:
- 33 protocol manifests covering 803 verified instructions across Solana's core programs (System, SPL Token, Token-2022, Stake), DeFi (Jupiter V6, Orca Whirlpools, Raydium AMM/CLMM/CPMM, Meteora DLMM, Phoenix, OpenBook, Squads, Drift, Kamino, Solend, MarginFi), NFT infrastructure (Metaplex), oracle (Switchboard), memecoin (Pump.fun), and bridging (Wormhole)
- A 2,747-fixture regression corpus with 0 false negatives on a holdout of 38 independently labeled real mainnet exploit signatures (from the peer-reviewed SolPhishHunter dataset arXiv:2505.04094) plus pinned real transactions
- A deterministic P10 promotion gate: no protocol version may be promoted without ≥99.5% of non-deprecated regression fixtures passing
- A community Manifest Registry with signed submissions, reviewer attestation, reputation tracking, and seed-wins policy (compile-time seed manifests are never overridden)

## 2. Overview of Ecosystem Impact

### How is this project a public good for the Solana community?

Graphite is a security verification layer that sits between an AI agent's intent and the wallet's signing operation. It deterministically checks that a constructed transaction actually does what was declared — with a falsifiable confidence score, not a binary safe/unsafe.

The problem it solves is concrete and measured: $494M was stolen by wallet drainers in 2024 (Scam Sniffer), $2.17B across crypto in H1 2025 (Chainalysis), and the first AI-package-drainer attacks on Solana wallets were observed in mid-2025. Solana phishing specifically "exploits weaknesses in transaction simulations" (Scam Sniffer). AI agents that hold signing keys are the exact attack surface these drainers target — an agent will approve whatever it is instructed to approve.

Graphite is not a wallet UI or a simulation tool. It is a deterministic verification gate: if Graphite blocks, the transaction is not submitted. The system is fully open-source (MIT), has no token, no fee, no rent extraction. Every component — the Rust core, 33 protocol manifests, TypeScript SDK, Go SDK, Python advisory layer, React dashboard — is public.

### Specific benefits to Solana developers

1. **Drop-in verification for agent frameworks.** SolanaAgentKit and any framework that constructs transactions can add a single HTTP call (`POST /verify`) before signing. The TypeScript SDK wraps this in typed `verify()` / `verifyExecution()` methods. The Go SDK provides the same for Go-based agents.

2. **Deterministic, auditable security decisions.** Every verification produces an itemized breakdown (which signals contributed, which risk patterns were checked, which layers passed/failed/inconclusive) and a content-hash for replay. No LLM is in the decision path — the Python layer is advisory only (Constitution P1: AI assists, never decides).

3. **Protocol manifests as a public registry.** The 33 JSON manifests define the trusted instruction surface for each program: discriminators, account roles, PDA seeds, expected state changes, allowed CPIs, and risk rules. Any developer can author a manifest for their program, sign it, and submit it through the Manifest Registry — the community review gate (reputation + regression replay) prevents bad manifests from entering the verification path.

4. **Regression corpus as an open benchmark.** The 2,747-fixture corpus (dev, regression, holdout) is deterministic — same fixtures, same verdicts, byte-identical across runs. Other teams can run `graphite regression` against their own verification implementations and compare results.

5. **Zero-friction integration.** The HTTP server exposes `/verify`, `/health`, `/manifests`, `/api/graph`, `/api/confidence-history`, `/api/policy-violations`, `/api/protocols/top`, and `/api/registry` — all read-only dashboard endpoints. Docker support (`Dockerfile` included), configurable auth (`GRAPHITE_API_KEY`), per-IP rate limiting, CORS, and audit logging are built in.

## 3. Product Design

### Architecture & how it works

Graphite Core is an 8-layer deterministic verification pipeline written in Rust:

```
LLM / Agent intent
        │  (advisory — never authoritative)
        ▼
┌─────────────────────────────────────────────────────┐
│ Graphite Core (Rust, 8 layers, all deterministic)   │
│                                                      │
│  L1  Account Resolution                             │
│      Resolve program ID + discriminator → manifest   │
│      → account roles (signer/writable/readonly/pda)  │
│      → PDA derivation verification                   │
│                                                      │
│  L2  Instruction Verification                       │
│      Discriminator match against manifest            │
│      Account count check (surplus = routing,         │
│        shortfall = limitation, not spoofing)         │
│                                                      │
│  L3  Simulation Integrity                           │
│      z-score vs historical baseline (compute units,  │
│      account writes, CPI hops)                       │
│      C28: robust median/MAD anti-poisoning           │
│                                                      │
│  L4  State Verification                             │
│      Expected state changes vs account roles         │
│      (debit/credit → ≥2 writable; approve → ≥1       │
│       signer; close → ≥1 writable)                   │
│                                                      │
│  L5  Semantic Verification                          │
│      Intent type ↔ instruction name ↔ state changes  │
│      FakeSwap detection (swap programs need          │
│        credit output wording in state changes)       │
│                                                      │
│  L6  Policy Evaluation                              │
│      Wallet profile thresholds (Treasury 0.95 /      │
│        TradingBot 0.80 / Gaming 0.55 / Enterprise    │
│        0.99 / Custom)                                │
│      Risk Engine blocks override confidence (G4)     │
│                                                      │
│  L7  Risk Engine (13 checks, 11 pattern types)      │
│      Drainer, HiddenTransfer, AuthorityHijack,       │
│      FakeSwap, UnexpectedCpi, PermissionEscalation,  │
│      MaliciousAccountChange, CompositionalDrain,     │
│      Impersonation, MultiInstructionDrain,           │
│      CpiTraceAnomaly                                 │
│      All findings are HARD GATES                     │
│                                                      │
│  L8  Execution Verification (post-submission)        │
│      Confirmed / Unknown / Unavailable (honest)      │
└─────────────────────────────────────────────────────┘
        │  Approved / Blocked / Inconclusive (audit trail)
        ▼
Signing (only on Approved)
```

Key architectural decisions:

- **Deterministic (Constitution P2):** same transaction → same verdict. The `VerificationInput` is flat data (Strings, Vecs, Options); the `VerificationResult` is flat data with a SHA-256 content hash. No random state, no LLM calls, no network in the core path.

- **Fail-closed (Constitution P12):** unknown program → reduced confidence ceiling (0.55). Unknown instruction on a high-risk protocol → blocked. Risk-class instruction without declared intent → blocked. An empty corpus always blocks promotion.

- **Manifest-anchored:** 33 curated manifests define the trusted instruction surface. The registry uses `BTreeMap` (not `HashMap`) for deterministic iteration order — the regression corpus derives fixture addresses from the manifest index, and any index drift would silently change every generated fixture.

- **Layered (GAP-2026-08-06-3):** every layer reports one of three states: `Passed`, `Failed`, or `Inconclusive`. A skipped check is never reported as a pass. The `passed` boolean (kept for SDK backward compatibility) is derived from `status` at construction — the phantom-pass class where L3/L8 hardcoded `true` while the real verdict lived elsewhere is structurally eliminated.

### Key features

1. **33 protocol manifests / 803 verified instructions.** Each manifest declares discriminators, account roles with PDA seeds, expected state changes, allowed CPIs, risk rules, and a machine-readable risk class. PDA seeds support dynamic templates (`{instruction_data:8:10}`, `{account_0}`, `{program_id}`) — verified against real mainnet accounts for Drift, Kamino, Jupiter DCA, and Squads V4.

2. **Multi-instruction pattern analysis.** Detects coordinated mass-drain patterns across multiple instructions in one transaction: Approve-then-Transfer (AAT), SetAuthority-then-Transfer (authority hijack), CloseAccount-then-Transfer (close-and-sweep), mass multi-transfer sweep (≥3 destinations or ≥4 sources), and Approve-then-System-assign (SlowMist AAT ownership theft). Ordering matters — the Approve must precede the Transfer.

3. **Hierarchical CPI trace analysis.** Walks the CPI tree of the primary instruction: unknown program at depth ≥1 (blocked), repeated revisit along one path ≥3 times (compositional drain, blocked), vanity-impersonated program (blocked), excessive depth ≥6 (warning).

4. **Simulation integrity with anti-poisoning.** Classic mean/std z-score plus C28 robust median/MAD z-score. A 256-sample bounded window so poisoned samples age out. Both statistics are checked — an attacker who poisons the baseline targets whichever the check uses.

5. **Regression engine (P10 gate).** Append-only corpus, content-hash dedup, deterministic replay. Promotion requires ≥99.5% pass rate. `replay_corpus_for_program` enables per-program promotion decisions.

6. **Community Manifest Registry.** Signed submissions with ed25519, reviewer attestation with reputation tracking, schema validation, seed-wins policy. Accepted manifests merge into the runtime verification registry (C53).

7. **Plugin framework (Constitution P8).** Layer-scoped plugins (VerifierPlugin, RiskPlugin, PolicyPlugin, ProtocolPlugin, SimulationPlugin) fold into their own layer's result. Analytics plugins observe completed results. Built-in: FakeRewardsDrainer risk plugin, verification event logger with JSON-lines file sink.

8. **Production HTTP server.** Axum-based with optional Bearer auth (`GRAPHITE_API_KEY`, constant-time comparison via SHA-256 hash), per-IP rate limiting (GCRA token bucket, bounded at 1M IPs with FIFO eviction), CORS, 1MB body limit, 10s timeout, CatchPanicLayer, graceful SIGTERM/SIGINT shutdown, append-only audit trail.

### Integration into existing developer workflows

- **TypeScript SDK:** `import { GraphiteClient } from '@graphite/sdk'; const result = await client.verify(input);`
- **Go SDK:** `client := graphite.NewClientWithAPIKey(url, key); result, err := client.Verify(input);`
- **Python advisory layer:** `python3 intent_parser.py "Swap 1 SOL for USDC"` — deterministic regex-based intent labeling, manifest-grounded protocol candidates, advisory risk hints. Runs as HTTP server on :8081 or CLI.
- **CLI:** `graphite verify --input tx.json --profile treasury`, `graphite regression --corpus-dir ./corpus`, `graphite registry submit --manifest m.json --corpus-dir ./corpus`
- **Docker:** `docker build -t graphite . && docker run -p 8080:8080 -e GRAPHITE_API_KEY=... graphite`

### Technology stack

- **Core:** Rust (axum, tokio, serde, sha2, ed25519-dalek, bs58, hex, thiserror)
- **SDKs:** TypeScript (fetch-based client), Go (net/http client)
- **Python layer:** Python 3 stdlib only (no dependencies — zero network, zero LLM)
- **Dashboard:** React (TypeScript), Vite, fetch-based API client
- **Infrastructure:** Docker, HTTP/JSON API, append-only JSONL audit log

### Proof-of-Concept

The full working system is available at https://github.com/Stan-lee13/graphite — 1,014 Rust tests, 33 protocol manifests, TypeScript/Go SDKs, Python layer, React dashboard, HTTP server, Dockerfile, and a SolanaAgentKit integration verified end-to-end on devnet with 5 finalized transactions.

## 4. Budget Breakdown (Milestones)

### 4a. Completed First Version (Beta) — per component

**Component 1: Public Deployment + Production Hardening — $30,000**

Scope: Deploy Graphite Core to a production public endpoint with TLS, auth, rate limiting, health monitoring, secrets management, and a documented security posture. Harden the server for sustained public traffic (connection pooling, graceful degradation under load, structured logging). Publish a live public demo endpoint.

Testing plan:
- Load testing with `wrk`/`hey` to validate throughput targets (>100 req/s sustained, <10ms p99 latency)
- Adversarial penetration testing (malformed payloads, oversized bodies, auth bypass attempts, rate limit rotation)
- Graceful shutdown testing (SIGTERM under load — no dropped in-flight requests)
- Audit log integrity testing (append-only semantics, crash recovery)

Amount: $30,000

**Component 2: Professional Security Audit — $30,000**

Scope: Commission an independent professional security audit of the core verification engine, risk engine, confidence engine, policy engine, server, and SDKs. Fix all findings at the root with regression tests. Publish the audit report.

Testing plan:
- Red-team exercise against the full 8-layer pipeline with fresh attack variants
- Regression test for every audit finding (the existing C33–C44 pattern: find → root-fix → regression test → re-attack with fresh variant)
- Clippy `-D warnings` + fmt clean, full test suite green

Amount: $30,000

**Component 3: Manifest Expansion to 50+ Protocols — $15,000**

Scope: Onboard 17+ additional protocol manifests covering the top agent-facing programs (Jito, Marinade, Sanctum, Claynosaurz, Tensor, Magic Eden, Lifinity, OpenBook DEX, Symmetry, Drift Perp, GooseFX, etc.). Each manifest: IDL-verified instruction layout, account roles with PDA seeds, expected state changes, allowed CPIs, risk rules, risk class. Ground discriminators against real mainnet transactions.

Testing plan:
- Live mainnet verification of every new manifest's discriminator against real transactions
- PDA derivation verification against pinned known-answer addresses (the Drift/Kamino/Jupiter DCA/Squads V4 pattern)
- Regression corpus expansion with real mainnet fixtures for each new protocol
- P10 gate pass on the expanded corpus

Amount: $15,000

### 4b. Maintenance — minimum 6 months

Total maintenance budget: $24,000 ($4,000/month × 6 months)

Monthly maintenance includes:
- Managing issues and bug reports
- Dependency updates (Rust crate ecosystem, TypeScript/Go SDK dependencies)
- Protocol manifest maintenance (updating discriminators, account layouts, PDA seeds when upstream programs upgrade)
- Regression corpus maintenance (replaying against updated manifests, fixing false positives/negatives)
- Server maintenance (monitoring, log rotation, security patches)
- Documentation updates (API changes, new protocol onboarding guides)
- Clippy/fmt/test suite maintenance

Amount: $24,000

### 4c. User Adoption

**Metric 1: Agent framework integrations — $15,000**

Target: 3+ Solana agent frameworks (SolanaAgentKit + 2 others, e.g. ElizaOS, Rig) routing transactions through Graphite for verification before signing.

Tracking method: Merged PRs in upstream repositories, integration documentation, and verification traffic from distinct framework user-agents on the public endpoint.

Milestones:
- 25% (1 framework merged): $3,750
- 50% (2 frameworks merged): $3,750
- 75% (3 frameworks merged): $3,750
- 100% (documentation + traffic validation): $3,750

Amount: $15,000

**Metric 2: Developer adoption via SDKs — $6,000**

Target: 50+ distinct developers using the TypeScript or Go SDK (measured by unique npm/Go module downloads or GitHub Stars on the SDK repos).

Tracking method: npm download counts, Go module proxy stats, GitHub Stars.

Milestones:
- 25% (13+ developers): $1,500
- 50% (25+ developers): $1,500
- 75% (38+ developers): $1,500
- 100% (50+ developers): $1,500

Amount: $6,000

**Metric 3: Live verification volume — $0 (included in M1 deployment)**

Target: 1,000+ real verifications served through the public endpoint within 6 months of launch.

Tracking method: Audit log line count on the public endpoint.

This metric is tracked but carries no separate budget — it validates that the public endpoint (M1) is actually being used.

### Milestone Summary Table

| # | Milestone / Deliverable | Success Criteria | Amount (USD) |
|---|---|---|---|
| 1 | Public deployment + production hardening | Live endpoint serving real verification traffic with TLS, auth, rate limiting, audit log; load-tested >100 req/s | $30,000 |
| 2 | Professional security audit | Published audit report; all findings closed with regression tests; full suite green | $30,000 |
| 3 | Manifest expansion to 50+ protocols | 17+ new manifests with IDL-verified layouts, PDA seeds, real mainnet discriminator grounding; P10 gate pass | $15,000 |
| 4 | 6 months maintenance | Monthly dependency updates, manifest maintenance, corpus replay, issue management, documentation | $24,000 |
| 5 | 3+ agent framework integrations | Merged PRs in 3+ frameworks (SolanaAgentKit + 2 others) with verification traffic | $15,000 |
| 6 | 50+ developer SDK adoption | npm/Go module downloads from 50+ distinct developers | $6,000 |

**Total: $120,000**

## 5. Acknowledgements

[✔] The project will release a published production version by the end of the grant agreement.
[✔] The project will be completely public and open-source.
[✔] The team agrees to at least 6 months of maintenance.
[✔] The team agrees to meet quantifiable user-adoption metrics.

---

## Why You?

1. **The code exists and works.** This is not a proposal to build a verification engine — it is a proposal to deploy, audit, expand, and integrate one that already runs 1,014 tests with 0 failures, covers 33 protocols with 803 verified instructions, and has been validated against real Solana mainnet exploit transactions. The $120k is for the final mile, not the research.

2. **Two adversarial audits already found and fixed the hard bugs.** The C33–C44 audit series found 4 P0 and 1 P1 vulnerabilities — including a real discriminator bug that would have let SetAuthority hijacks bypass detection entirely. Every finding was root-fixed with a regression test and re-attacked with fresh variants. The codebase has been adversarially tested by independent reviewers, not just by the author.

3. **The architecture is purpose-built for Solana.** Graphite is not an EVM security tool ported to Solana. Every detection rule, every manifest layout, every PDA derivation, every CPI trace analysis, every multi-instruction pattern is Solana-specific — grounded against real mainnet transactions, IDL-verified account layouts, and pinned known-answer PDA addresses from official SDKs (Drift, Kamino, Jupiter DCA, Squads V4).

4. **The security model is honest.** Every limitation is documented in the code, not hidden. L3/L8 report `Inconclusive` when they cannot produce a verdict (never phantom passes). Unknown protocols get a 0.55 confidence ceiling, not a fake pass. The regression corpus holds out real exploit signatures and reports 0 false negatives — not 0 false negatives on synthetic data. The simulation integrity layer uses robust median/MAD statistics specifically to resist baseline poisoning. The rate limiter bounds its bucket map to prevent O(n) sweeps. Constant-time API key comparison hashes both inputs to fixed-length digests before comparing to prevent length leaking.

5. **The ecosystem integration is real.** The SolanaAgentKit integration has 5 finalized devnet transactions proving end-to-end flow: intent parse → verification → signing → submission → confirmation. The TypeScript SDK, Go SDK, and Python advisory layer are tested and working. The React dashboard reads from the live server. The Dockerfile builds and runs. The CLI serves as a CI gate (`exit 1` on reject). This is not a library that needs wrappers — it is a deployed system that needs to be turned on.
