# Graphite — Developer Tooling Grant Proposal

Solana Foundation, Developer Tooling. Draft of 2026-10-26, prepared from the repository at the head
of PR #55. Every figure below is taken from a file in the repository, named next to it, and can
be reproduced from that file or command (Constitution P16). Items marked **[OWNER]** are yours to
fill or confirm; items marked **[LIVE]** are filled from the live-mainnet measurement run
(`.github/workflows/live-mainnet.yml`) once it finishes.

---

## 1. Applicant Information

**Project / Tool Name**
Graphite — a deterministic pre-signature verification gate for Solana transactions built by AI
agents.

**Applicant / Organization**
**[OWNER: individual or organization name]**

**Primary Contact (name, email, Telegram/X)**
**[OWNER: Victor Stanley — email — handle]**

**Total Amount Requested (USD)**
$120,000

**Relevant Experience & Track Record**

- **Graphite itself, built in the open:** https://github.com/Stan-lee13/graphite (MIT). It contains:
  - a Rust core with an eight-layer verification pipeline;
  - an HTTP server with a hash-chained, keyed audit trail;
  - a CLI;
  - a manifest registry with signed submissions and a replay gate;
  - TypeScript and Go SDKs;
  - an agent signing guard;
  - integrations for SolanaAgentKit, the Vercel AI SDK and the Model Context Protocol;
  - an operator dashboard;
  - a deployment kit.
- **Engineering discipline you can check:**
  - 40 recorded rounds of adversarial review and repair, including three internal deep audits, each
    answered in the round after (`AUDIT/01-findings.md`, `docs/audit/`).
  - Every security fix has a test that fails before the fix. Fixes are reverted one at a time to
    show the test catches the reversal (break log B01–B244 in `AUDIT/01-findings.md`).
  - CI holds every test suite to a floor, per test binary for the security suites
    (`.github/test-floors/`).
- **Solana-specific depth:**
  - a parser checked against the Anza SDK's own decoder on generated frames (`tools/runtime-oracle`);
  - a rebuild of Agave's parsed inner instructions checked against Agave's parser
    (`tools/inner-instruction-oracle`);
  - Token-2022 fee and extension modelling;
  - address-lookup-table resolution;
  - v0 and v1 transaction formats;
  - 137 protocol manifests covering 3,518 instructions, built from programs' own IDLs and measured
    on mainnet (`docs/protocol-coverage.md`, `graphite-core/protocols/battle_tested_evidence.json`).
- **[OWNER: prior work, hackathon placements — e.g. the Superteam Solana AI Kit bounty placement
  recorded in the engineering skill's Constitution history — employers, other Solana projects.]**

---

## 2. Overview of Ecosystem Impact

**How is this project a public good for the Solana community?**

An AI agent that holds a Solana key signs whatever its tool call builds, and that tool call comes
from a model that reads untrusted text: a prompt injection, a malicious API response or a
poisoned document can steer it. A drainer has to talk a person into signing; an agent signs
without being asked. Address and program blocklists do not help, because drains route through
programs everyone trusts (System, SPL Token, Token-2022, the major DEXs), and a simulation summary
does not help either, because the agent has nobody to read it.

Graphite is the missing check: before the agent's key signs, it verifies the exact transaction
bytes against what the agent says it is doing, and against what each instruction is allowed to
do, and answers with a deterministic, explained verdict. Only `executable_approved` permits signing.
It is MIT-licensed, self-hostable, has no token, and no model in the decision path — the same
input always gives the same verdict, which anyone can reproduce.

**Specific benefits to Solana developers**

- **Agent framework authors** route signing through one guard (`integrations/agent-guard`) instead
  of writing their own safety checks. The guard:
  - binds the approved bytes to the signed bytes;
  - verifies every signature;
  - refuses residual risks the operator has not accepted;
  - enforces a spend cap measured by simulating the exact transaction;
  - records each lifecycle step.
- **Wallet and backend developers** call one HTTP endpoint or the TypeScript/Go SDK and get, for
  any transaction:
  - which accounts it touches and with what privileges;
  - what the simulation changed;
  - whether that matches the declared intent;
  - why it was refused.
- **Protocol teams** publish a manifest, generated from their IDL, so agents can use their
  program safely. A manifest upgrade is replayed against recorded history before it is accepted
  (the P10 gate).
- **Security researchers** get an open, reproducible corpus and benchmark of real exploit
  transactions to test against.

---

## 3. Product Design

**Architecture & how it works**

```
agent / app ── intent + exact tx bytes ──▶ Graphite Core ──▶ verdict (decision, confidence, reasons)
                                              │
                    L1 account resolution  ── PDA seeds re-derived, pinned addresses
                    L2 instruction identity ── discriminator, accounts, runtime privileges
                    L3 simulation          ── RPC simulation vs the program's anchored baseline
                    L4 state diff          ── every account change must be declared
                    L5 intent              ── the declared intent can describe this instruction
                    L6 policy              ── confidence and trust tier meet the wallet profile
                    L7 risk                ── drainer, hand-over, impersonation, CPI-tree patterns
                    L8 execution           ── after submission, the chain's bytes match the approval
```

- **Decision.** The verdict's `decision` is one of `executable_approved`, `analysis_only`,
  `inconclusive` or `blocked`. It is computed once in the Core, and every client recomputes it and
  refuses a disagreement.
- **Binding.** The approval is bound to the exact bytes by SHA-256 and to the request's amount,
  recipient and asset.
- **Fail-closed.** Anything Graphite cannot observe is named in the verdict and is never
  executable. That covers an unreadable account, an undescribed instruction, an unparsed CPI and
  a missing simulation.
- **Confidence.** Confidence is a weighted, itemised score. Its trust tier is computed from
  evidence, never asserted.

**Key features**
- Byte-level verification of legacy, v0 (address lookup tables) and v1 transactions.
- Account-state diffing with a Token-2022 model (transfer fees, hooks, permanent delegates,
  extensions).
- Intent binding for transfers, swaps, withdrawals, claims, closes and creations.
- 137 protocol manifests generated from IDLs, each with a recorded mainnet measurement.
- A hash-chained, HMAC-keyed audit trail with `graphite audit verify`, checkpoints, rotation and
  pruning records.
- A manifest registry with signed submissions and a regression gate.
- Upgrade detection: a redeployed program loses its earned evidence.
- An explicit, audited bootstrap from the committed mainnet census
  (`graphite evidence import-census --cluster mainnet-beta`).
- An agent signing guard, TypeScript and Go SDKs, an MCP server, and SolanaAgentKit and Vercel AI
  SDK adapters.
- An operator dashboard, Prometheus metrics, and a deployment kit (Docker Compose and systemd
  behind Caddy).

**Integration into existing developer workflows**
- **Agents:** replace the framework's signer with `agent-guard`, or call the MCP tool, so that
  every transaction is verified before signing.
- **Backends:** `POST /verify` with the intent and the serialized transaction, then sign only on
  `executable: true`. The SDKs do this in one call.
- **CI and protocol teams:**
  - `graphite protocol diff` shows every field the runtime judges a manifest by;
  - `graphite verify` exits 0 only for an executable approval, so it gates scripts;
  - the registry replays a manifest change before accepting it.

**Technology stack**
- **Core:** Rust (axum, tokio, reqwest with a guarded resolver).
- **Clients:** TypeScript SDK, agent guard and adapters on `@solana/kit`; a Go SDK; a Python
  advisory layer that cannot override the Core; a React dashboard.
- **Verification of the verifier:** cargo-fuzz, a runtime-decoder oracle (the Anza SDK), an
  inner-instruction oracle (Agave's parser), and mutation testing.
- **Deployment:** Docker Compose, systemd and Caddy, with reproducible builds and signed
  provenance in the release workflow.

**Proof-of-Concept**
- The whole system: https://github.com/Stan-lee13/graphite.
- Five-minute reviewer path: README, "For Judges and Reviewers".
- Current state with every number and known limitation: `docs/CURRENT.md`.
- This round's evidence: `docs/audit/`.

---

## 4. Budget Breakdown (Milestones)

Graphite's beta exists today. The grant funds the production version, kept running and adopted.
**[OWNER: the amounts and adoption targets below are a proposal — adjust them to what you can
commit to.]**

### 4a. Completed versions (per component)

| # | Component | Scope | How it is tested | Amount |
|---|---|---|---|---|
| 1 | Independently audited core | A third-party security audit of the Core, server and agent guard; every finding fixed at its root with a test; report published | each fix's test fails before the fix and is reverted once to prove it (the repo's existing practice); the auditor re-checks the fixes | $35,000 |
| 2 | Public verification endpoint | Hosted `/verify` (TLS, API keys, rate limits, monitoring, status page), deployed from the signed release by digest, with branch protection and immutable release tags applied | the deployment kit's tests (`deploy/tests/run.sh`) on the shipped configuration; synthetic probes every minute; a published uptime record | $15,000 |
| 3 | Coverage where agents transact | Swap and lending decoders for the venues agents use most, so honest swaps through them can be bound and become executable (today `decode_swap` reads 6 programs); manifests for the top unmanifested programs in measured agent traffic, each from its IDL with a mainnet measurement | the live-mainnet workflow's measured approval and refusal rates before and after, published; an attack test per new venue | $15,000 |
| 4 | Agent-stack integrations upstreamed | The guarded signer offered upstream to SolanaAgentKit, the Vercel AI SDK and MCP, plus an ElizaOS plugin, each with docs and an example agent | each integration's test suite in CI plus an end-to-end run on devnet through the guard | $10,000 |

Subtotal: $75,000.

### 4b. Maintenance (6 months)

- **Budget:** $24,000 in total, $4,000 a month for 6 months.
- **What maintenance covers:**
  - triaging and fixing reported issues and security reports;
  - keeping manifests current when programs upgrade (upgrade detection already flags them);
  - dependency updates through the repository's gated update process;
  - keeping the hosted endpoint patched;
  - monthly CI evidence (test floors, fuzzing, mutation scores).
- **Reporting:** a monthly public report listing issues closed, manifests updated and the
  endpoint's uptime.

### 4c. User adoption

- **Budget:** $21,000 in total, split across three metrics.
- **Paid pro rata:** each 25% of a target reached releases 25% of that metric's amount.

| Metric | Target by the end of the grant | How it is tracked | Amount |
|---|---|---|---|
| A. Projects routing real transactions through Graphite | 5 projects (agent frameworks, wallets or agent products) | public integration PRs or written confirmation; each named in the monthly report | $7,000 |
| B. Transactions verified on the public endpoint | 50,000 `/verify` requests from external API keys | the endpoint's Prometheus counters (`graphite_*_total`), published monthly | $7,000 |
| C. Developers / teams with active API keys | 25 distinct teams with at least one verified transaction in the last 30 days | API-key registry on the hosted endpoint (counts only, no transaction content) | $7,000 |

### Milestone Summary Table

| # | Milestone / Deliverable | Success Criteria | Amount (USD) |
|---|---|---|---|
| 1 | Independent audit, all findings fixed | published audit report; every finding closed with a test, or explained | $35,000 |
| 2 | Public verification endpoint | live endpoint deployed from a signed release; uptime published; repository protections applied | $15,000 |
| 3 | Coverage where agents transact | new decoders and manifests merged; measured approval rate on honest mainnet traffic published before and after | $15,000 |
| 4 | Upstream agent integrations | SolanaAgentKit, Vercel AI SDK, MCP and ElizaOS integrations released with docs and examples | $10,000 |
| 5–10 | Maintenance, months 1–6 | monthly report: issues and security reports handled, manifests current, endpoint patched | $24,000 ($4,000 / month) |
| 11 | Adoption A | 5 projects routing real transactions | $7,000 |
| 12 | Adoption B | 50,000 external `/verify` requests | $7,000 |
| 13 | Adoption C | 25 active teams | $7,000 |

**Total: $120,000**

---

## 5. Acknowledgements

- [✔] The project will release a published production version by the end of the grant agreement.
- [✔] The project will be completely public and open-source (MIT, already).
- [✔] The team agrees to at least 6 months of maintenance.
- [✔] The team agrees to meet quantifiable user-adoption metrics.

---

## What a reviewer should know (stated, not hidden)

These come from `docs/CURRENT.md` and `docs/audit/RESIDUAL_RISK_AND_OWNER_GATES.md`.

- **Not independently audited yet.** Every review so far is internal engineering work by the
  maintainer with AI engineering agents, plus two external reviews answered item by item.
  Milestone 1 pays for the independent audit.
- **Not publicly deployed yet.** It runs locally, in Docker and in CI. Milestone 2 deploys it.
- **Confidence is earned.** A fresh instance approves nothing until it has evidence.
  - One audited command imports the measured mainnet census. After it, a manifested program
    reaches the Gaming profile.
  - Every recorded attack was re-run in that state and is still refused.
  - The stricter profiles need evidence earned from traffic.
- **Coverage is partial.**
  - Most mainnet transactions touch at least one unmanifested program. There Graphite refuses
    rather than approves.
  - Swaps through venues it cannot yet decode are analysis-only, never executable.
  - **[LIVE: the measured approval and refusal rates on recent mainnet traffic, from the run on
    PR #55.]**
- **Real exploits.** 35 mainnet exploit transactions from the public SolPhishHunter dataset
  (arXiv:2505.04094), labelled outside Graphite, are all refused.
- **Real traffic.**
  - Whole mainnet blocks (48,855 executed transactions) go through the full pipeline with 0 parse
    failures and 0 verify errors (`tools/mainnet-sample/SAMPLES.md`).
  - Two of those blocks are committed, and their verdict file's hash is pinned in CI.
