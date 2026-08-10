# Graphite — Solana Foundation Grant Proposal

**Project:** Graphite — a deterministic transaction-verification and anti-drain layer for AI agents on Solana
**Requested funding:** $120,000 (milestone-based, 3 milestones over ~9 months)
**Grant type:** Open-source public good / security infrastructure (Foundation funding range $10k–$400k, milestone-based, ~30-day evaluation)

---

## 1. Executive Summary

Graphite is a security layer that sits between an AI agent and the Solana network. It
deterministically verifies **what a transaction will do** — program, instruction,
accounts, CPI structure, cross-instruction patterns, and intent — **before** the agent
signs and submits it. It exists because the fastest-growing attack class on Solana —
wallet drainers, approval abuse, authority hijack, and compositional phishing — is
exactly the failure mode an autonomous agent cannot afford: an agent with a signing key
will approve whatever it is instructed to approve, and drainers are built to exploit
weak or absent transaction simulation.

The problem is measured in billions, not millions: **$494M was stolen by wallet drainers
in 2024** (Scam Sniffer); **$2.17B was stolen across crypto in the first half of 2025**
(Chainalysis); Google Cloud's threat-intel team tracked CLINKSINK drainer campaigns
stealing at least $900k on Solana alone; and **malicious AI-generated packages began
draining Solana wallets in mid-2025** — the exact convergence Graphite targets. Solana
phishing specifically "exploits weaknesses in transaction simulations" (Scam Sniffer).

Graphite is not a research prototype. It is a working, tested, and live-validated system:

- **976 tests / 0 failures / 0 clippy warnings / 0 compiler warnings**, fmt clean.
- **22 protocol manifests / 561 verified instructions**, every program ID verified
  executable on mainnet.
- **A 2,181-fixture regression corpus** — dev, regression, and a real holdout of 38
  independently labeled transactions (35 real mainnet exploit signatures from a
  peer-reviewed arXiv dataset + 3 real mainnet transactions) with **0 false negatives**.
- **Real on-chain validation**: 3 real mainnet exploits scored in the benchmark
  (Wormhole $320M hack, CLINKSINK STMT drainer, SlowMist AAT drainer — all blocked);
  L3 simulation validated against real devnet RPC; L8 execution verification validated
  against real mainnet RPC (Confirmed / Unknown / Unavailable, honestly reported).
- **Working integrations**: TypeScript SDK, Go SDK, Python advisory layer, React
  dashboard, HTTP server (auth, rate limiting, CORS, audit log), Dockerfile, and a
  SolanaAgentKit integration verified end-to-end on devnet with 5 finalized transactions.
- **Two independent adversarial security audits** (C33–C44) that found and root-fixed
  four P0 and one P1 class of vulnerabilities — including a real discriminator bug that
  would have let SetAuthority hijacks bypass detection entirely.

We are asking the Solana Foundation to fund the final mile: public deployment with a
professional security audit, expansion of the real-exploit corpus and protocol coverage,
and enterprise integration so that every AI agent framework on Solana can be protected
by default.

---

## 2. The Problem

### 2.1 Autonomous agents are a new, unsolved attack surface

AI agents that transact on Solana hold signing keys. Their "intent" comes from an LLM —
which is prompt-injectable — and the transaction they build is what gets signed. The
industry's current defenses assume a human reviews the transaction:

- **Wallet UIs** show simulation summaries — but simulation can lie (or be absent),
  and an agent has no eyes to read the summary.
- **Existing security tools** scan for known malicious *programs* or *addresses*. They
  do not verify *behavior*: a known-good program (SPL Token, Jupiter, System) is exactly
  what drainers route their theft through.
- **"Just check the simulation"** is the standard advice, and it is precisely the
  mechanism Solana drainers are built to exploit.

### 2.2 The attack classes (all demonstrated against Graphite, all blocked)

1. **Approval abuse / AAT**: Approve a delegate, then transfer out. Mass-approve + System
   assign to steal ownership (SlowMist-documented $3M+ drainer pattern).
2. **Authority hijack**: SetAuthority / CloseAccount smuggled inside a CPI from an
   untrusted contract.
3. **Compositional drains**: many transfers, many destinations, one transaction; or a
   custom program re-entered repeatedly along one CPI path.
4. **ISA / phishing**: fund movement to vanity addresses impersonating system accounts
   (the dominant SolPhishHunter class on mainnet).
5. **Fake swaps**: a "swap" intent executed by a non-swap program, or a swap whose
   state changes establish no output credit.
6. **Baseline poisoning**: inflating the simulation baseline so divergence goes
   unnoticed — defended by a robust median/MAD statistic.

### 2.3 Why now

Solana is the leading chain for AI agents by transaction volume and framework adoption
(SolanaAgentKit, ElizaOS, and others), and agent wallets are increasingly funded. The
first AI-package-drainer attacks on Solana wallets were observed in July 2025. Every
framework that gives an agent a key is a drainer target. The window to build
"verification by default" into the agent stack is now.

---

## 3. The Solution

Graphite is a deterministic, multi-layer verification pipeline:

```
LLM / Agent intent
        │  (advisory — never authoritative)
        ▼
┌─────────────────────────────────────────────────────┐
│ Graphite (Rust core, 8 layers, all deterministic)    │
│  L1 Account resolution  (PDA derivation, roles)      │
│  L2 Instruction verification (discriminator match)   │
│  L3 Simulation integrity (median/MAD, anti-poison)   │
│  L4 State verification (writable/signer vs layout)   │
│  L5 Semantic verification (intent ↔ program)         │
│  L6 Policy (wallet profile thresholds)               │
│  L7 Risk engine (attack-pattern gates)               │
│  L8 Execution verification (post-submission status)  │
│  + Phase 2 gates: multi-instruction + CPI-trace      │
└─────────────────────────────────────────────────────┘
        │  Approved / Blocked / Inconclusive (audit trail)
        ▼
Signing (only on Approved)
```

Key properties:

- **Deterministic** (P2): same transaction → same verdict, cryptographically hashed.
  No LLM in the decision path — the Python layer is an advisory pattern matcher that
  can never override a Rust security decision (P1).
- **Fail-closed** (P12): unknown program, unknown instruction on a high-risk protocol,
  or a risk-class instruction without declared intent → blocked.
- **Manifest-anchored**: 22 curated manifests (program IDs verified on mainnet) define
  the trusted instruction surface; everything else is unverified code.
- **Layered**: if one gate misses, the next catches it — proven by the P0/P1 audit
  history where each layer closed the previous layer's gap.
- **Auditable**: every decision has an itemized breakdown and an append-only audit
  trail; AuditBind middleware re-hashes the signed transaction against the approved
  content hash (TOCTOU prevention).

---

## 4. Traction & Evidence (all measured, all real)

| Claim | Evidence |
|---|---|
| Correctness | 976 tests / 0 failures / 0 clippy / 0 warnings; benchmark 100% precision & recall on 16 scored cases |
| Real data | 3 real mainnet exploits blocked in benchmark (Wormhole $320M, CLINKSINK, SlowMist AAT); 35 real exploit signatures in holdout, 0 false negatives |
| Live validation | L3 on real devnet RPC; L8 on real mainnet RPC; SAK integration = 5 finalized devnet transactions |
| Corpus | 2,181 deterministic fixtures (dev / regression / holdout), byte-identical across runs |
| Manifests | 22 protocols, 561 instructions, program IDs verified executable on mainnet |
| Security | Two independent adversarial audits; 4 P0 + 1 P1 classes root-fixed and re-attacked with fresh variants |
| Performance | ~1.8ms p50 / ~2.8ms p95 / ~3.0ms p99 verification — 0.5% of Solana's 400ms block budget |
| Integrations | TypeScript SDK, Go SDK, Python advisory layer, React dashboard, HTTP server, Dockerfile, SolanaAgentKit integration |

---

## 5. Milestones & Budget

**Total request: $120,000** — milestone-based, disbursed on verified completion (per the
Foundation's milestone model). Rationale in §8.

### Milestone 1 — Public Deployment + Professional Security Audit — $45,000 (months 1–3)

- Deploy Graphite to a production public endpoint (TLS, auth, rate limiting, health,
  monitoring, secrets management) with a documented security posture.
- Commission an independent professional security audit of the core verification engine,
  risk engine, and server; fix all findings at the root with regression tests.
- Publish a live public demo endpoint so anyone can verify a transaction.
- **Deliverable:** live endpoint + audit report + remediation commit set.
- **Exit check:** audit findings closed; endpoint passes the adversarial test matrix.

### Milestone 2 — Real-Exploit Corpus Expansion + Protocol Coverage — $40,000 (months 4–6)

- Expand the real on-chain corpus: fetch and pin 100+ additional real mainnet exploit
  and benign transactions (raw instruction bytes) across a wider attack-class and
  protocol distribution; grow the holdout to a statistically meaningful evaluation.
- Onboard 10–15 additional protocol manifests (IDL/source-verified layouts, PDA seed
  templates) covering the top agent-facing programs.
- Publish the corpus and evaluation methodology as an open benchmark other teams can
  run against.
- **Deliverable:** expanded corpus + expanded manifests + published benchmark.

### Milestone 3 — Agent-Framework Integration + Ecosystem Adoption — $35,000 (months 7–9)

- Production integration with the major Solana agent frameworks (SolanaAgentKit and at
  least one more, e.g. ElizaOS) so verification is default-on for agent wallets.
- SDK hardening: typed verdicts, plugin surface, dashboard observability, docs.
- Outreach: developer guides, security write-ups, and a "verify before you sign" public
  campaign with the Foundation.
- **Deliverable:** framework integrations merged upstream / published + adoption
  metrics.
- **Exit check:** N real agent frameworks routing transactions through Graphite; public
  documentation.

---

## 6. Team

> (Complete with real names/links before submission. For the application, the honest
> framing: this is currently a solo/small-team open-source effort with a strong audit
> trail — the plan below shows where grant funding goes to build out review capacity.)

- **Maintainer / core engineer** — full ownership of the Rust core, risk engine, and
  manifests; authored the C33–C44 audit-and-fix series.
- **Security reviewer (M2 funded)** — independent audit lead.
- **Integration engineer (M3 funded)** — framework integrations.

---

## 7. Why the Solana Foundation

1. **Public good, not a token project**: Graphite is verification infrastructure. It has
   no token, no fee, no rent extraction — it is exactly the "open-source public good"
   the Foundation's grant program funds.
2. **Network-level security value**: every protected agent wallet protects the Solana
   ecosystem's reputation and reduces the drainer tax on Solana users.
3. **Complements existing Foundation investments**: agent frameworks (SolanaAgentKit
   ecosystem), security tooling, and AI x Solana programs. Graphite is the missing
   verification layer those investments need.
4. **Proven delivery**: the project has already shipped what most grants fund — the
   request is for the final mile, de-risked by a working, tested, live-validated codebase.

---

## 8. Funding Amount — Rationale

We request **$120,000 over three milestones**. Reasoning:

- **What remains is not research risk — it is delivery cost.** The core is built and
  tested (976 tests, two audits, live RPC validation). The remaining work — deployment,
  professional audit, corpus expansion, integrations — is well-scoped execution.
- **Professional security audit** of a Rust verification engine of this surface area
  realistically costs $30k–$60k; our M1 allocates ~$30k toward it (rest internal).
- **Benchmarked against the Foundation's range**: $10k–$400k, milestone-based. $120k is
  mid-range — appropriate for a working system with a public-good mandate, not an
  idea-stage microgrant ($10k) and not a large strategic grant.
- **A higher ask ($250k+) is not yet justified** because the project is not yet
  deployed at ecosystem scale; a lower ask would not cover a real audit + deployment +
  integrations.
- **The grant is milestone-gated by the Foundation**: each tranche is disbursed on
  verified deliverables, so the amount scales with demonstrated progress.

---

## 9. Risks & Honest Limitations

- **Corpus-scoped validation**: 0 false negatives on 38 holdout transactions is strong
  but not a mainnet-wide statistical claim. M2 grows this explicitly.
- **Manifest maintenance**: protocol correctness depends on curated manifests; the
  registry's signed-submission gate (G5) addresses community growth, and M2 expands
  coverage.
- **Agent adoption**: verification is only effective if frameworks route through it —
  the exact problem M3 tackles.
- **L3/L8 production activation**: live-validated but not yet default-on in production;
  M1 makes them production-activated.

---

## 10. Success Metrics

- **Security**: 0 verified-exploit false negatives on the expanded holdout; audit
  findings closed.
- **Adoption**: 2+ agent frameworks routing transactions through Graphite; public
  endpoint serving real verification traffic.
- **Ecosystem**: published open benchmark; documentation; measurable reduction in
  drainer success on integrated wallets (reported, not overclaimed).
- **Sustainability**: a hosted verification API and SDK that any Solana team can adopt
  free for public-good use, with paid tier options for enterprise (future, post-grant).

---

## 11. Contact / Links

> (Insert before submission.)
- GitHub: https://github.com/Stan-lee13/graphite
- Docs / architecture: `ARCHITECTURE.md`, `docs/phase2-certification-report.md`
- Demo endpoint: (M1 deliverable — currently no public endpoint, honestly stated)
