# Graphite — Developer Tooling Grant Proposal

Solana Foundation, Developer Tooling. Draft of 2026-10-26, prepared from the repository at the head
of PR #55. Every figure below is taken from a file in the repository, named next to it, and can
be reproduced from that file or command (Constitution P16). Items marked **[OWNER]** are yours to
fill or confirm. Live figures come from one run of `.github/workflows/live-mainnet.yml`, whose report
is committed under `docs/evidence/live-mainnet/`; a live run measures that moment's chain.

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
$18,000

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

Graphite's beta exists today: the verification core, SDKs, agent guard, integrations, dashboard and
deployment kit are built and tested. This grant funds the step from beta to a published production
version that people can use without running it themselves, plus six months of maintenance and
measured adoption. The scope is sized for one maintainer over about six months.

**Not funded here, stated plainly:** an independent third-party security audit. A credible audit of
a verifier this size costs more than this whole grant, so it is pursued separately (an audit
subsidy or a dedicated audit grant). Until it happens, every public page says Graphite is not
independently audited. **[OWNER: the amounts and targets below are a proposal — adjust to what
you can commit to.]**

### 4a. Completed production version (per component)

| # | Component | Scope | How it is tested | Amount |
|---|---|---|---|---|
| 1 | Public verification endpoint | Hosted `/verify` for anyone: TLS, API keys, rate limits, monitoring, a status page; deployed from the signed release by digest, with branch protection and immutable release tags applied on the repository | the deployment kit's tests (`deploy/tests/run.sh`) on the shipped configuration; a synthetic probe every minute; the uptime published monthly | $3,500 |
| 2 | Honest swaps on more venues | Swap decoders for the most-used venues Graphite cannot bind yet (`decode_swap` reads 6 programs today; Pump AMM and Meteora DAMM v2 are the first two), so an honest swap through them can become `executable_approved` instead of analysis-only | an honest-swap and four attack tests per venue (the Round 40 harness); the live-mainnet workflow's approval rate before and after, published | $3,000 |
| 3 | Agent-stack integrations upstreamed | The guarded signer offered upstream to SolanaAgentKit and the Vercel AI SDK, the MCP server published, and an ElizaOS plugin, each with docs and an example agent | each integration's test suite in CI, plus an end-to-end devnet run through the guard | $2,500 |

Subtotal: $9,000.

### 4b. Maintenance (6 months)

$4,500 in total: $750 a month for 6 months, each month one milestone. It covers:
- triaging and fixing reported issues and security reports;
- keeping manifests current when programs upgrade (upgrade detection already flags them);
- dependency updates through the repository's gated process;
- keeping the hosted endpoint patched, including its hosting cost;
- monthly CI evidence (test floors, fuzzing, mutation scores).

Each month ends with a short public report: issues closed, manifests updated, endpoint uptime.

### 4c. User adoption

$4,500 in total, split over three metrics. For every 25% of a target reached, 25% of that metric's
amount is paid at the end of the period.

| Metric | Target by the end of the grant | How it is tracked | Amount |
|---|---|---|---|
| A. Projects routing real transactions through Graphite | 3 projects (agent frameworks, wallets or agent products) | public integration PRs or written confirmation, each named in the monthly report | $1,500 |
| B. Transactions verified on the public endpoint | 10,000 `/verify` requests from external API keys | the endpoint's Prometheus counters, published monthly | $1,500 |
| C. Teams with active API keys | 10 distinct teams with at least one verified transaction in the last 30 days | the hosted endpoint's API-key registry (counts only, no transaction content) | $1,500 |

### Milestone Summary Table

| # | Milestone / Deliverable | Success Criteria | Amount (USD) |
|---|---|---|---|
| 1 | Public verification endpoint | live endpoint deployed from a signed release; uptime published; repository protections applied | $3,500 |
| 2 | Honest swaps on more venues | decoders for at least 2 more venues merged with honest and attack tests; live approval rate published before and after | $3,000 |
| 3 | Upstream agent integrations | SolanaAgentKit and Vercel AI SDK integrations offered upstream, MCP server published, ElizaOS plugin released, each with docs and an example | $2,500 |
| 4–9 | Maintenance, months 1–6 | monthly report: issues and security reports handled, manifests current, endpoint patched | $4,500 ($750 / month) |
| 10 | Adoption A | 3 projects routing real transactions | $1,500 |
| 11 | Adoption B | 10,000 external `/verify` requests | $1,500 |
| 12 | Adoption C | 10 active teams | $1,500 |

**Total: $18,000**

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
  maintainer with AI engineering agents, plus two external reviews answered item by item. The
  audit is pursued separately from this grant (§4).
- **Not publicly deployed yet.** It runs locally, in Docker and in CI. Milestone 1 deploys it.
- **Confidence is earned.** A fresh instance approves nothing until it has evidence.
  - One audited command imports the measured mainnet census. After it, a manifested program
    reaches the Gaming profile.
  - Every recorded attack was re-run in that state and is still refused.
  - The stricter profiles need evidence earned from traffic.
- **Coverage is partial.**
  - Most mainnet transactions touch at least one unmanifested program. There Graphite refuses
    rather than approves.
  - Swaps through venues it cannot yet decode are analysis-only, never executable.
  - **Measured live (2026-10-29, PR #55 run 40839253280; report committed as
    `docs/evidence/live-mainnet/run-40839253280.md`):** after `graphite evidence import-census`, a
    Core with a mainnet RPC verified 28 new, never-signed honest transfers built from accounts that
    had just transferred on mainnet (1 lamport or 1 base unit each): **27 were
    `executable_approved`** (21 of 21 System, 6 of 7 SPL Token), and the one refusal was a transfer
    the simulator showed would fail on chain. In the same run, 200 recent mainnet transactions
    replayed through `/verify` gave 0 server errors and p50 / p99 latency of 208 / 430 ms; none of
    those replays was executable (most fail simulation against later state, and 155 call programs
    the census does not cover), which is why the replay is not an approval rate.
  - **Measured live again (2026-10-31, PR #61 run 41155961160; report committed as
    `docs/evidence/live-mainnet/run-41155961160.md`):** after the false refusals Round 41's own
    live runs found were fixed (decisions D-19 to D-26) and the six swap venues' census was
    re-measured, **36 of 36** honest transfers and **2 of 2** honest Jupiter v6 swaps were
    `executable_approved`. Each swap was an executed mainnet swap rebuilt unsigned (same wallet,
    route and amount, a fresh blockhash) with its minimum output re-quoted by simulation. Two
    swaps is a small sample; an earlier run's four Jupiter routes through Pump AMM are still
    refused with the route unbound, which Milestone 2's venue work addresses.
- **Real exploits.** 35 mainnet exploit transactions from the public SolPhishHunter dataset
  (arXiv:2505.04094), labelled outside Graphite, are all refused.
- **Real traffic.**
  - Whole mainnet blocks (48,855 executed transactions) go through the full pipeline with 0 parse
    failures and 0 verify errors (`tools/mainnet-sample/SAMPLES.md`).
  - Two of those blocks are committed, and their verdict file's hash is pinned in CI.
