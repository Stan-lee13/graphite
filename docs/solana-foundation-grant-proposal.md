# Graphite — Solana Foundation grant proposal

> **Revised 2026-10-03, after Round 24.** Every figure about Graphite below is measured in this
> repository and named with where it comes from. [`CURRENT.md`](CURRENT.md) is authoritative
> for anything that has moved since.

**Project:** Graphite — deterministic verification of a Solana transaction's bytes against what
the agent says it is doing, before the agent's key signs it.
**License:** MIT. The whole system is open source.
**Requested funding:** $120,000, milestone-based, three milestones over about nine months.
**Grant type:** open-source public good / security infrastructure.

---

## 1. Summary

An AI agent that holds a Solana key signs what it builds, and what it builds comes from a model
that can be talked into things. Graphite sits between the agent and the key. It parses the exact
transaction bytes, resolves every account, simulates the transaction when an RPC is attached,
diffs the account state it would change, and compares all of that with the agent's declared
intent and with a manifest of what each instruction is allowed to do. It then answers approved or
refused, with the reason. Nothing is signed on a refusal, and no model is in the decision path.

What exists today, all in the repository:

- **A Rust core** with an eight-layer pipeline, an HTTP server with an append-only audit trail,
  a CLI, and a manifest registry with signed submissions and a replay gate.
- **137 protocol manifests covering 3,504 instructions.** Every program id is verified
  executable on mainnet. 113 carry a `BattleTested` tier backed by a recorded mainnet
  measurement, which the loader checks and lowers when the evidence does not support it
  ([`protocol-coverage.md`](protocol-coverage.md)).
- **Three agent-framework integrations behind one signing boundary:** SolanaAgentKit, the
  Vercel AI SDK, and a Model Context Protocol server. All three sign only through
  `integrations/agent-guard`. The guard binds the approved bytes to the signed bytes, refuses
  residual risks the operator has not accepted, records each lifecycle step on the audit trail,
  and enforces the operator's spend cap. For a swap, the cap is checked against the wallet
  outflow measured by simulating the exact transaction.
- **SDKs** for TypeScript and Go, a Python advisory layer that cannot override the core, and
  a React dashboard.
- **Tests:** 1,908 Rust tests in the all-features suite, plus 183 in the agent guard, 34 in the
  TypeScript SDK, 15 across the Vercel AI and MCP adapters, 6 in the SolanaAgentKit adapter,
  Go and Python suites, and 7 in the dashboard. A runtime oracle compares Graphite's parser
  with the validator's own decoder on about 628,500 generated frames per CI seed.

## 2. The problem

The losses are documented. Wallet drainers stole about $494M from more than 300,000 addresses
in 2024, according to Scam Sniffer's annual report. Chainalysis counted $2.17B stolen across
crypto in the first half of 2025, with personal-wallet compromises rising. Google Cloud's
Mandiant traced at least $900,000 stolen from Solana users by CLINKSINK drainer affiliates.

Agents make this worse in a specific way. A drainer has to persuade a person to sign. An agent
signs whatever its tool call produces, and its tool call is produced by a model that reads
untrusted text. Address and program blocklists do not help, because drains route through
programs everyone trusts: System, SPL Token, Token-2022, the major DEXs. A simulation summary
does not help either, because the agent has no one to read it. What is missing is a check of
behaviour, done on the bytes, that fails closed.

## 3. What Graphite checks

| Layer | What it establishes |
|---|---|
| L1 Account resolution | Each account is what the manifest says the slot holds: PDA seeds re-derived, pinned addresses compared |
| L2 Instruction identity | The described instruction is in the bytes: discriminator, account count, the runtime's privileges |
| L3 Simulation | The simulator's report is consistent with the program's earned baseline (median/MAD, anti-poisoning) |
| L4 State diff | Every account change in the simulation is declared: closures, owner changes, delegate grants, token debits, Token-2022 extension authorities, native authorities |
| L5 Intent | The declared intent can describe this instruction's security class (one table, `manifest::INTENT_DECLARES`) |
| L6 Policy | Confidence and trust tier meet the wallet profile |
| L7 Risk | Drainer, hand-over, impersonation, multi-instruction and CPI-tree patterns, on the call tree the simulator actually executed |
| L8 Execution | After submission, the chain's own bytes for the signature match the approved transaction |

Properties: deterministic (the same input gives the same verdict, which is hashed); fail-closed
(an unknown program, an undescribed instruction, an unreadable answer or a missing observation
refuses rather than passes); the AI layer is advisory only; every verdict says what it did *not*
observe, and the guard refuses to sign over any such gap the operator has not accepted by name.

## 4. Evidence, and how it was produced

- **Adversarial rounds.** The repository records 24 rounds of internal review and repair. Each
  finding has a class, a root cause, a fix, and a test that fails before the fix
  ([`AUDIT/01-findings.md`](../AUDIT/01-findings.md)). Every fix in the last two rounds was then
  reverted once, alone, to show its test catches the reversal. The latest round answered an
  external review. Its two most serious items (R2 and R3) showed that a `transfer` label could
  clear a multisig drain or a delegate hand-over at the intent and risk layers. Both were
  reproduced on the previous commit and fixed at the root.
- **Real traffic.** Whole finalized mainnet blocks from four days, 48,855 executed transactions,
  are pushed through the full pipeline bound to their real bytes. Graphite records 0 parse
  failures and 0 verify errors, and every verdict that changes between rounds is attributed to
  the finding that changed it ([`round24-the-intent-is-the-class-2026-10-03.md`](round24-the-intent-is-the-class-2026-10-03.md)).
  The samples are fetched by slot list, with their SHA-256 recorded, so anyone can re-measure
  them ([`../tools/mainnet-sample/SAMPLES.md`](../tools/mainnet-sample/SAMPLES.md)).
- **Real exploits.** 35 mainnet exploit transactions from the public SolPhishHunter dataset
  (arXiv:2505.04094), labelled outside Graphite, are all refused.

What this evidence is not:

- **It is not an independent audit.** Every review in the repository is internal engineering
  work, done by the maintainer with AI engineering agents, apart from one external review whose
  items are verified and answered in `AUDIT/01-findings.md`. No third party has certified
  Graphite. Milestone 1 pays for one to try.
- **There is no public deployment.** Graphite runs locally, in Docker, and in CI.
- **Coverage is partial.** On the measured mainnet sample, most executed transactions call at
  least one program with no manifest. There, Graphite falls back to its drainer heuristics,
  and it refuses rather than approves what it cannot describe.
- **Approval is earned.** A fresh deployment approves nothing until it has simulation evidence
  from an RPC, by design. The known limitations are listed in
  [`../SECURITY.md`](../SECURITY.md#known-limitations).

## 5. Milestones and budget

**Total: $120,000**, each tranche released on verified delivery.

### Milestone 1: independent audit and public endpoint ($45,000; months 1–3)

- Commission an independent security audit of the core, the server, and the agent guard. Fix
  every finding at its root, with a test for each, and publish the report.
- Deploy a public verification endpoint (TLS, auth, rate limits, monitoring) that anyone can
  send a transaction to. Turn on branch protection and signed releases.
- **Exit:** a published audit report with every finding closed or explained; a live endpoint.

### Milestone 2: coverage where agents transact ($40,000; months 4–6)

- Onboard the programs that dominate the unmanifested share of agent and mainnet traffic,
  each from its program's own interface. Each gets a mainnet measurement before it earns a tier.
- Watch for protocol upgrades (ProgramData and upgrade authority), so a manifest cannot
  silently outlive the program it describes (roadmap R-M1).
- Grow the labelled real-exploit set and publish the corpus and method as an open benchmark.
- **Exit:** the measured share of mainnet transactions with a manifested program rises, and the
  measurement is published with its samples.

### Milestone 3: verification on by default in agent stacks ($35,000; months 7–9)

- Upstream the integrations: SolanaAgentKit, the Vercel AI SDK and MCP exist today; add ElizaOS.
  Make the guarded path the default for agent wallets in each.
- Ship a hosted tier of the same MIT code for teams that do not want to run it, with the
  self-hosted path kept first-class.
- Write developer guides and a public "verify before you sign" write-up with the Foundation.
- **Exit:** frameworks route real agent transactions through Graphite, with numbers reported.

## 6. Why fund it

1. **It is a public good.** Graphite is MIT-licensed infrastructure with no token. The hosted
   tier pays for operations, while the code, manifests, corpus and benchmark stay open.
2. **The hard part exists.** The verification engine, the manifests and the signing boundary
   are built and tested. The grant pays for what one maintainer cannot do alone: an independent
   audit, a public deployment, and coverage measured against real traffic.
3. **It is honest about itself.** Every claim in the repository names its evidence, every
   limitation is written down, and every fix is tested against its own reversal. A reviewer
   can check the work.

## 7. Team

- **Victor Stanley:** maintainer and core engineer. Owns the Rust core, manifests, agent guard
  and integrations.
- **Independent auditor (Milestone 1):** contracted security firm.
- **Integration engineer (Milestone 3):** framework integrations and the hosted tier.

## 8. Risks

- **The audit may find serious issues.** That is the point of Milestone 1. The budget assumes
  fixes at the root, each with a test.
- **Manifest upkeep.** Programs upgrade. Milestone 2's upgrade watch and the registry's replay
  gate exist for this, and a stale manifest refuses rather than approves.
- **Adoption.** Verification protects only the agents that route through it, which is what
  Milestone 3 is for.

## 9. Success metrics

- The independent audit is published, and every finding is closed or explained.
- A public endpoint serves real verification traffic.
- The manifested share of mainnet transactions rises, measured on published samples.
- Real-exploit false negatives stay at 0 on the expanded set.
- Agent frameworks route transactions through Graphite by default.

## 10. Links

- Repository: https://github.com/Stan-lee13/graphite
- Current status: [`CURRENT.md`](CURRENT.md); architecture: [`../ARCHITECTURE.md`](../ARCHITECTURE.md);
  audit trail: [`../AUDIT/`](../AUDIT/)
- Sources for §2: Scam Sniffer 2024 drainer report (reported by BleepingComputer, "Cryptocurrency
  wallet drainers stole $494 million in 2024"); Chainalysis 2025 mid-year crypto crime update
  (reported by The Record, "$2.17 billion in crypto stolen in first half of 2025"); Google Cloud
  Mandiant, "Solana cryptocurrency stolen in CLINKSINK drainer campaigns".
