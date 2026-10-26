<div align="center">

<img src="assets/brand/graphite-logo-256.png" alt="Graphite logo" width="140" />

# Graphite

**Deterministic semantic verification for Solana AI agents.**

Graphite sits between an AI agent's intent and the wallet's execution. It verifies that a constructed transaction actually does what was declared — with a falsifiable confidence score, not a binary safe/unsafe — and, when given the exact transaction bytes, binds its verdict to those bytes so that what gets signed is what was verified.

**Current status, in one place: [docs/CURRENT.md](docs/CURRENT.md).** Every dated report under `docs/` is a historical record and points there.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![Rust Tests](https://img.shields.io/badge/Rust_Tests-counts_in_CURRENT.md-brightgreen?style=flat-square)](docs/CURRENT.md#numbers-as-of-this-pages-commit)
[![Status](https://img.shields.io/badge/Status-security--hardened_alpha-orange?style=flat-square)](docs/CURRENT.md)
[![Clippy](https://img.shields.io/badge/Clippy-0_warnings-brightgreen?style=flat-square)](graphite-core/)
[![Protocols](https://img.shields.io/badge/Protocol_Manifests-137-blue?style=flat-square)](docs/protocol-coverage.md)
[![Risk Patterns](https://img.shields.io/badge/Risk_Patterns-13-red?style=flat-square)](graphite-core/src/risk_engine.rs)
[![Version](https://img.shields.io/badge/Version-0.3.0--beta%20(unreleased)-orange?style=flat-square)](graphite-core/CHANGELOG.md)

</div>

---

## For Judges and Reviewers: Graphite in Five Minutes

**What it is.** A verification gate between an AI agent and its Solana key. The agent says what it is
doing ("Swap 1 SOL for USDC"); Graphite parses the exact transaction bytes, simulates them, diffs the
account state they change, and approves only if the transaction does what the request said, with
the reason for every refusal. No model is in the decision path.

**See it refuse something (about two minutes, after one build):**

```bash
cd graphite-core
cargo build --release --bin graphite
# A token transfer that also calls an unverified program: refused, layer by layer, with reasons.
./target/release/graphite explain --file ../examples/verify-malicious.json
# Real mainnet exploit transactions and benign ones, scored.
./target/release/graphite benchmark
```

**See an agent get talked into it and stopped** (the agent guard, the signing boundary every
integration uses; loopback mocks, no network, no keys):

```bash
cd integrations/agent-guard
npm ci --ignore-scripts
npm test
```

Among its tests: "Swap 1 SOL for USDC" handed a route that spends 2 SOL, 100 SOL, USDT, or
delivers BONK is refused before Graphite is asked; "Don't send 1.5 SOL to …" is refused, not
executed; a model's reading of the request that disagrees with the user's own words is refused;
nothing is ever signed before the verdict.

**Why you can believe the numbers:**

| Claim | Evidence |
|---|---|
| It behaves on real traffic | 48,855 executed mainnet transactions from four days, run through the whole pipeline on their real bytes: 0 parse failures, 0 verify errors, every changed verdict attributed ([round report](docs/round24-the-intent-is-the-class-2026-10-03.md); samples by slot list and SHA-256 in [`tools/mainnet-sample/SAMPLES.md`](tools/mainnet-sample/SAMPLES.md)). Live replays on a real RPC approved **0 of 200** in each of the two runs on the Round 35 head (seeded and unseeded; most of the 200 fail simulation against later state), so the approval path on live traffic is not yet measured ([Round 35 report, §I](docs/round35-live-mainnet-and-the-parsed-cpi-report-2026-10-23.md)) |
| You can rerun it, offline | two of those blocks (2,284 transactions) are committed and run on every `cargo test`: the verdict file's SHA-256 is pinned and equals the full measurement's for the same rows, so the same input gives the same output on your machine (`tests/mainnet_conformance.rs`, [`SAMPLES.md`](tools/mainnet-sample/SAMPLES.md)) |
| Its fixes are real | every security fix has a test that fails without it; through Round 28 each fix was also reverted once to prove its test catches it ([`AUDIT/01-findings.md`](AUDIT/01-findings.md), break log). Round 29's fixes were not all reverted that way, and [its report](docs/round29-the-audit-remediated-2026-10-21.md) says which were |
| It parses what the network runs | a runtime oracle compares Graphite's parser with the Anza SDK's decoder and `sanitize` on ~628,500 frames per CI seed: never looser |
| Agents can use it today | SolanaAgentKit, the Vercel AI SDK and an MCP server, all signing through [`integrations/agent-guard`](integrations/agent-guard/README.md) |
| It covers real protocols | 137 manifests, 3,518 instructions, 113 with a measured `BattleTested` tier ([coverage](docs/protocol-coverage.md)) |

**What it is not, yet:** independently audited (every review here is internal engineering work
plus two external reviews and one full-repository audit, answered item by item), or publicly
deployed. A fresh instance approves nothing on the built-in profiles until it has evidence —
seeded by the operator, or earned from approved, simulated traffic; that is deliberate. Open
items are listed, with their measured cost, in [`AUDIT/FINAL.md`](AUDIT/FINAL.md).

---

## The Problem This Solves

AI agents on Solana can construct and submit transactions autonomously. But nothing verifies that the transaction they *say* they're building is the transaction they *actually* build.

```
WITHOUT GRAPHITE:

  AI Agent → "Swap 1 SOL for USDC" → Construct Transaction → Wallet → Blockchain
                                         ↑
                                    No one checks if the
                                    transaction actually
                                    does what was declared

WITH GRAPHITE:

  AI Agent → "Swap 1 SOL for USDC" → Graphite verifies → Wallet → Blockchain
                                         ↓
                                    8-layer pipeline checks:
                                    • Accounts match the protocol
                                    • Instruction matches the intent
                                    • No drainer patterns
                                    • No authority hijacks
                                    • No hidden transfers
                                    • Confidence score is honest
                                    • Policy threshold is met

                                    If any check fails → BLOCKED. Period.
```

This is not a simulation. This is not advisory. Graphite is a **deterministic verification gate** — if Graphite blocks, the transaction is not submitted.

---

## What Ships Ready to Run

```bash
# Clone
git clone https://github.com/Stan-lee13/graphite.git
cd graphite

# Build the core engine
cd graphite-core
cargo build --release

# Run the test suite — zero setup. The ignored tests are network- or
# sample-dependent, plus two soak benchmarks (run them with --ignored).
# Current counts, for this and every other suite: docs/CURRENT.md, "Numbers".
cargo test --release --all-features

# The same gate CI runs on the feature matrix: the library with no features
# and the cli-only build must pass too.
cargo test --release --no-default-features --lib
cargo test --release --no-default-features --features cli

# Run the benchmark: 24 hand-built cases (7 safe, 15 malicious, 2 unscored
# unknown-protocol), 22 scored; REAL-RECONSTRUCTED and SYNTHETIC cases labeled
cargo run --release --bin graphite -- benchmark
```

---

## Architecture — 8-Layer Verification Pipeline

Each layer can only **reduce** confidence or **block**. No layer can invent confidence that lower layers didn't earn.

| Layer | Name | Responsibility | Failure Mode |
|-------|------|---------------|--------------|
| L1 | Account Resolution | Resolve all required accounts/PDAs | Missing/ambiguous → block |
| L2 | Instruction Verification | Confirm discriminator + args match known shape | Unknown → Unknown Protocol Mode |
| L3 | Simulation Verification | Run `simulateTransaction` on the exact bytes, confirm it succeeds | With an RPC: failed → block (`SimulationFailed`); not obtained or incomplete → block (`VerificationIncomplete`). Without an RPC: `Inconclusive` and the `not_simulated` residual — not a block |
| L4 | State Verification | Diff pre/post account state vs declared intent | Mismatch → block or flag |
| L5 | Semantic Verification | Compare diff against Semantic Graph expectations | Deviation → confidence penalty |
| L6 | Policy Verification | Apply wallet's policy profile thresholds | Policy violation → block |
| L7 | Risk Verification | Run Risk Engine — forbidden patterns, compositional risk | Forbidden pattern → block |
| L8 | Execution Verification | Post-submission: confirm on-chain result matches prediction | Mismatch → audit trail flag |

**Current status:** L1–L7 run inside every `/verify` call. L3 and L4 are live against real Solana RPC when `GRAPHITE_RPC_URL` is set — L3 simulates and accumulates its own baseline, L4 builds a real pre/post account diff. With an RPC attached and the bytes supplied, a simulation that errored refuses the verdict (`SimulationFailed`), and one that could not be obtained or came back incomplete — an RPC error, a timeout, the budget, an implausible answer, a CPI tree that cannot be rebuilt, a missing pre/post diff — refuses it too (`VerificationIncomplete`; Round 29). **Without an RPC nothing is simulated:** L3 is `Inconclusive`, the verdict carries the `not_simulated` residual, and since Round 30 every approval is `decision: "analysis_only"`, `executable: false`. **Only `executable: true` (`decision: "executable_approved"`) permits signing** — `approved` alone never did; the TS and Go SDKs' `isExecutable` / `IsExecutable` and the agent guard recompute the decision and refuse a disagreement, and `graphite verify` exits 3 on an analysis-only approval. The server logs `ANALYSIS-ONLY MODE` at startup and reports `verification_mode` on `/health`. L8 runs after submission, because that is when there is an execution to verify: call `POST /verify/execution` (or `graphite execution`) with the `content_hash` and the signature, and it reconciles the chain against the verdict Graphite recorded — across the whole audit trail, rotated archives included. The outcome that matters is `BlockedButExecuted` — a transaction Graphite refused that was submitted anyway, which no layer inside a verification request can detect. Run by hand against mainnet through the ignored live tests (`graphite-core/tests/l8_live_mainnet.rs`); no run artifact is kept in the repository. Since Round 30 every reconciliation states `inclusion_assurance`.

**The transaction itself, not a description of it.** When the caller supplies `signed_transaction` (the serialized bytes, signature slots empty), Graphite parses the wire format itself — legacy, v0 and (since Round 19) v1, address lookup tables fetched and resolved, privileges read from the header rather than from the caller — and returns `scope.kind = "artifact_bound"` with `transaction_sha256` over those exact bytes. L2 then requires that the described instruction is *in* the bytes, positionally, and that every sibling instruction is declared. Without the bytes the verdict is `descriptive`: an honest statement about what the caller said, constraining nothing about what gets signed.

---

## Risk Engine — 13 Detection Patterns (+ plugin veto)

| Pattern | What It Catches |
|--------|----------------|
| **Drainer** | High account-to-change ratio — multi-transfer drain (Checks 3, 3b); also SPL / Token-2022 `CloseAccount`, which the known-risky table (Check 2) refuses under any intent |
| **AuthorityHijack** | SetAuthority/CloseAccount via CPI from an untrusted root (Check 1b); any manifested instruction whose manifest class is an authority change (`set_admin`, `transferOwnership`, …), with or without a declared intent (Check 2b) |
| **HiddenTransfer** | Transaction touches far more accounts than its declared state changes name (Check 5) |
| **UnexpectedCpi** | CPI target not in the manifest's allowed list (fail-closed, Check 1) |
| **FakeSwap** | A swap/trade/exchange intent on a swap-category program whose non-empty state changes mention no credit or output (Check 8). A swap intent on a program that is not a swap program is Check 9 (`PermissionEscalation`) |
| **PermissionEscalation** | SPL Token / Token-2022 `Approve` and `ApproveChecked` under **any** intent (Check 2: a delegate grant is an authority change); an intent the program does not serve (Check 9), or one that cannot declare the instruction's security class (Check 9b) |
| **MaliciousAccountChange** | A token `CloseAccount` that Check 2 exempted as a verified self-refund, declared as anything but a close (Check 6a); a System account creation declared as anything but a create (Check 6b); a high-risk class with no declared intent (Check 10) |
| **CompositionalDrainPattern** | A repeated security-relevant CPI target, or five or more targets from an untrusted root (Check 4) — also judged on the callees the Core's own simulation reports executing, repeats counted |
| **Impersonation** | A fund movement whose **destination** ends in four or more `1`s or starts with `Compu`, or whose **source** does so at five or more `1`s — address-poisoning sends from a ground vanity address (SolPhishHunter class, Check 10a). The signing authority of an SPL transfer is never judged |
| **MultiInstructionDrain** | Coordinated mass-drain across multiple instructions in one tx (approve-then-transfer, authority-hijack-then-drain, close-and-sweep, mass multi-transfer sweep) |
| **UnspendableDestination** | Value sent to an address nobody can spend from — the native programs, the loaders, every sysvar, the lookup-table, Config, Feature and ZK programs and the precompiles (Check 10b; distinct from `Impersonation`, which is about addresses that only *look* official) |
| **CpiTraceAnomaly** | Malicious shape in hierarchical CPI trace — unknown program, repeated revisits, a same-instruction sweep across many account sets, or vanity-impersonated program in the tree. Judged on the call tree the Core's own simulation reports (`innerInstructions`), not only on one a caller declares (Round 19) |
| **UnboundedWithdrawal** | A granted withdrawal (Raydium CLMM `decrease_liquidity_v2`, Raydium CPMM `withdraw`, Pump AMM `withdraw`) with any minimum output at zero, or one too short to read, loses its grant (Round 32; any zero since Round 34). Emitted by the grounded-intent grants (`intent_grants.rs`), not by `assess`; `GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS=1` keeps the grant |

All 13 patterns are real detection logic — not stubs, not placeholders. Ten are emitted by the single-instruction risk engine (`risk_engine.rs`), whose `assess` runs 16 checks — 1, 1b, 2, 2b, 3, 3b, 4, 5, 6a, 6b, 8, 9, 9b, 10a, 10b and 10, the table on `risk_engine::CHECKED_PATTERNS` (Round 29 removed Check 7, which no input could reach: Check 2 refuses every `Approve` first); `MultiInstructionDrain` and `CpiTraceAnomaly` are emitted by the transaction-level and CPI-trace analyzers (`tx_pattern_analysis.rs`) and mapped onto the same `RiskPattern` enum in the orchestrator; `UnboundedWithdrawal` (Round 32) is emitted by the grounded-intent grants (`intent_grants.rs`) when a granted withdrawal leaves a minimum output at zero. The enum's fourteenth variant, `PluginBlock`, is not a detector: it names a registered plugin's veto as a plugin veto. Separately, the pipeline bounds the priority fee (`ExcessivePriorityFee`, Round 21), and refuses a failed or incomplete simulation (`SimulationFailed`, `VerificationIncomplete`, Round 29). A CPI outside the manifest from a manifested root program is a warning, not a block, by design: the manifest vouches for the root.

---

## Supported Protocols (137 Manifests / 3,518 Instructions)

The full table — every program, its instruction count, the tier the loader
actually applied, and the mainnet measurement behind it — is
**[docs/protocol-coverage.md](docs/protocol-coverage.md)**, which is generated
from the manifests and compared against the loaded registry in CI, so it cannot
drift from the code the way a hand-maintained table does (it had: four rows of
the old table named the wrong tier).

Of those, **113 carry a BattleTested tier that a mainnet measurement supports** — up from 8 that merely declared one.

**A manifest does not get to award itself a trust tier.** `load_seed_manifests`
lowers a declared `BattleTested` to `OfficialManifest` unless
`protocols/battle_tested_evidence.json` shows that the program account is
executable on mainnet, that at least 1,000 successful transactions *carry* its
address over a stated window (carry, not necessarily invoke:
`getSignaturesForAddress` returns every transaction whose account list names
it), and that of at least 20 instructions really observed on chain the manifest
names at least 90%. Measurements are read-only and reproducible
(`graphite-core/scripts/battle_tested_census.py`); since Round 29 each record's
decode rate is recomputed at load against the manifest actually loaded.

**What that measured tier does, and does not do.** On the verdict path it does
nothing: every manifest's tier is capped at `OfficialManifest` when a verdict is
computed (Constitution P7), so the measured `BattleTested` tier is registry and
display information — the protocol table, `graphite protocol status`, the
dashboard. A verdict reaches `BattleTested` only through the Semantic Graph,
whose transaction volume comes from the operator (`graphite evidence seed`):
asserted, not earned at runtime. The bar itself is thin, and the numbers say so:
across the 113 records that carry the tier, the observed-instruction sample is
21 at the least and 54 at the median (82 records observed fewer than 100);
70 records name three or fewer distinct instructions; 30 sit at exactly 1,000
successes from a single page of signatures. Measured 2026-09-22 to 2026-10-03.

That tier is a statement about usage and description accuracy, **not about
safety**: a heavily used malicious program would clear the same bar. What judges
safety is L4, L5 and L7, which run identically at every tier.

Ninety-six of these manifests were onboarded in Round 18 from each program's
**own on-chain Anchor IDL** — the account the program itself owns — after
ranking the Solana program inventory by real usage over 80 finalized mainnet
blocks. On a 10,617-transaction sample, the share of non-vote transactions whose
primary program Graphite can name went from 20.8% to 44.0%
(`tools/mainnet-sample`; measured on a sample fetched on 2026-09-22, which is
not in the repo — `mainnet_sample.json` is gitignored, so a re-run measures a
fresh sample); counted per program invocation over an 80-block
census, 64.5% to 79.5% ([docs/protocol-coverage.md](docs/protocol-coverage.md)).

## What's in the Box

```
graphite/
│
├── graphite-core/                  ← Rust verification engine (the heart)
│   ├── src/
│   │   ├── verification.rs         ← 8-layer pipeline orchestrator
│   │   ├── account_resolution.rs  ← L1: PDA derivation (Solana hash-chain), account matching
│   │   ├── risk_engine.rs         ← L7: 10 of the 13 detection patterns (16 checks)
│   │   ├── confidence_engine.rs   ← L6: Weighted signal scoring + tier ceilings
│   │   ├── policy_engine.rs       ← L6: Per-wallet policy profiles
│   │   ├── simulation_integrity.rs← L3: 3-signal z-score (compute/writes/CPI) + MAD baseline
│   │   ├── semantic_graph_store.rs← L5: Trust tier computation, append-only storage
│   │   ├── transaction_builder.rs ← A validated transaction summary (not wire bytes), compute budget estimate
│   │   ├── unknown_protocol_mode.rs← 0.55 confidence cap (P6/P12)
│   │   ├── tx_pattern_analysis.rs ← Multi-instruction drain + CPI trace analysis (C29)
│   │   ├── manifest.rs            ← Protocol manifest loading + registry
│   │   ├── manifest_registry.rs   ← Signed community manifest submissions (G5/P7/P10/P11)
│   │   ├── regression_engine.rs   ← P10 promotion gate + fixture corpus replay
│   │   ├── plugin_orchestrator.rs ← P8 plugin framework (sole plugin caller)
│   │   ├── plugins/               ← Built-in: FakeRewardsDrainer (L7), EventLogger (analytics)
│   │   ├── live_corpus.rs         ← Live RPC fixture seeding + devnet verification
│   │   ├── rpc_client.rs          ← Solana RPC client (L3 simulation + L8 execution)
│   │   ├── tx_artifact.rs         ← Wire-format parser (legacy, v0, v1), ALT resolution, durable-nonce detection, simulation identity
│   │   ├── state_diff.rs          ← L4 pre/post diff, SPL Token / Token-2022 decoding + extension classification
│   │   ├── durable.rs             ← Append-only audit trail: fdatasync per record, rotation, whole-trail reads
│   │   ├── solana_types.rs        ← PDA derivation, base58, type primitives
│   │   ├── server.rs              ← HTTP API (axum): /verify, /verify/execution, /audit/event, /admin/quarantine, /metrics, /health, /api/*
│   │   ├── operator_boundary.rs   ← The trust-boundary rules the server and the CLI share (profile pin, permissive clamp, nonce, upgrade quarantine, learning opt-in)
│   │   ├── benchmark.rs           ← Benchmark (24 cases, 22 scored; REAL-RECONSTRUCTED and SYNTHETIC cases labeled; approve-all comparison row)
│   │   ├── bin/graphite.rs        ← Binary entry point (server + CLI)
│   │   └── cli.rs                 ← CLI command handlers (the clap tree is in bin/graphite.rs; `graphite --help` lists every command)
│   ├── protocols/                 ← 137 JSON protocol manifests (3,518 instructions)
│   │                                 + battle_tested_evidence.json: the mainnet measurement behind each tier
│   └── tests/                     ← integration suites (adversarial + exploit + RPC trust boundary + live RPC + real mainnet); counts in docs/CURRENT.md
│
├── dashboard/                     ← React + TS dashboard (8 views, polls /api/* and /metrics)
│
├── sdk/
│   ├── typescript/                ← TS SDK (GraphiteClient + AuditBind TOCTOU binding)
│   └── go/                        ← Go SDK (same client + AuditBind; VerificationResult's 21 fields, full parity)
│
├── integrations/
│   ├── agent-guard/               ← The verification gate every integration signs through (no framework dependency)
│   │   ├── guard.ts               ← GraphiteGuard: builds ONE BoundTransaction, verifies it, signs only on artifact_bound approval
│   │   ├── cli.ts                 ← Runs one request through the guard from a terminal (real path; exit 0/2/1)
│   │   ├── artifact.ts            ← BoundTransaction: deep-copied, digest-rechecked, signer-set-checked signing gate; messageOf
│   │   ├── kit-artifact.ts        ← Compiles legacy, v0 and v1 (SIMD-0385) messages through @solana/kit
│   │   ├── auditbind.ts           ← Secondary instruction-level binding (content_hash); the digest is authoritative
│   │   ├── bound-instruction.ts   ← Builds the swap instruction from the verified payload, never from a framework's builder
│   │   ├── emit-corpus.ts         ← Cross-language corpus: 15 shapes + 2,897 byte-level mutations, diffed in CI
│   │   ├── residual-policy.ts     ← Which unobserved residuals a deployment accepts; refuses the rest before signing
│   │   ├── execution-lifecycle.ts ← The one path from verdict to network: policy → sign → record → submit → record → confirm → L8
│   │   ├── devnet-test.ts         ← Live devnet test (BoundTransaction → signApproved → sendRawTransaction)
│   │   ├── spend-policy.ts        ← The operator's per-transfer cap and destination allowlist, enforced before anything is built
│   │   └── mainnet-benchmark.ts   ← Real mainnet exploit benchmark runner
│   ├── vercel-ai/                 ← Vercel AI SDK tools over the guard (cap required; approval config for every fund movement)
│   ├── mcp-server/                ← MCP server over the guard (cap required; a person confirms through elicitation)
│   └── solana-agent-kit/          ← SAK adapter: VerifiedSakAgent over the guard; SAK gets a wallet that cannot sign
│
├── python-ai-layer/               ← Advisory intent parser (P1: AI never decides)
│   ├── intent_parser.py
│   └── test_intent_parser.py
│
├── tools/
│   ├── mainnet-sample/            ← Fetches and pins real mainnet blocks; the conformance samples (SAMPLES.md)
│   └── runtime-oracle/            ← Graphite's parser against the Anza SDK decoder + sanitize, in CI
│
├── examples/                      ← Sample verification inputs/outputs
├── schemas/                       ← JSON schemas (proposed-intent, verification-result)
├── docs/                          ← CURRENT.md (status now) + dated campaign reports (historical, banner-linked)
├── .github/                       ← CI workflow + issue/PR templates
│
├── ARCHITECTURE.md                ← System design specification
├── ROADMAP.md                     ← Phases 1–2 complete; hardening rounds; Phase 3 gates
├── SECURITY.md                    ← Security policy + known limitations
├── CONTRIBUTING.md                 ← How to contribute
├── Dockerfile                     ← Multi-stage container build
├── docker-compose.yml             ← One-command deploy
└── README.md                      ← You are here
```
---

## Agent Framework Integrations

Every integration signs through one framework-independent package,
[`integrations/agent-guard`](integrations/agent-guard/README.md) (`GraphiteGuard`): the
request is grounded in the user's own words, ONE transaction is built (legacy, v0 or v1),
Graphite Core verifies those exact bytes, and the guard signs only on an artifact-bound
approval whose digest matches, after a confirmation hook shows the resolved transaction.
The operator's spend policy — a per-transaction cap the guard itself requires (every
adapter; `GRAPHITE_ALLOW_UNCAPPED=1` is the named opt-out), an optional rolling aggregate
(`GRAPHITE_MAX_TOTAL_LAMPORTS` per `GRAPHITE_SPEND_WINDOW_SECONDS`, in memory, per process)
and an optional destination allowlist — is enforced on a transfer before anything is built,
and on a swap against the wallet outflow measured by simulating the exact transaction. A
transfer request must match one grammar (`[please] send|transfer|pay <amount> SOL to
<address>`); a swap runs only on six decoded programs, exact-in, and its route's own minimum
output is read and held to the simulated delivery, a slippage bound and a price floor.

| Integration | Framework | What the model can do | Bounds that hold whatever the model writes |
|---|---|---|---|
| [`integrations/vercel-ai`](integrations/vercel-ai/README.md) | Vercel AI SDK 7 (`ai`) | call `graphite_transfer_sol` / `graphite_swap` / `graphite_wallet` | Graphite's verdict; a required per-transaction cap (a swap is bounded by the outflow its simulation measures); the fund-moving tools carry `needsApproval: true` by default, so a person approves each call |
| [`integrations/mcp-server`](integrations/mcp-server/README.md) | Model Context Protocol (Claude, Cursor, ElizaOS's MCP plugin, LangChain's MCP adapters, the AI SDK's MCP client) | the same three tools over stdio | Graphite's verdict; a required cap; a person confirms every fund movement through MCP elicitation — after the verdict, shown the resolved destination, amounts and measured wallet effect — and a client that cannot ask is refused |
| [`integrations/solana-agent-kit`](integrations/solana-agent-kit/README.md) | Solana Agent Kit 2.x | `executeTransfer` / `executeSwap`; SAK's own agent for read-only use | Graphite's verdict; a required cap; SAK is given a wallet that cannot sign |

CI's npm advisory gate covers six lockfiles and fails on any moderate, high or critical
advisory that is not listed, with its reachability reasoning, in `.github/npm-audit/`;
low advisories are not gated. The SAK adapter is the only package that depends on
`solana-agent-kit`, and the only one carrying its listed `bigint-buffer` advisory.

## Quick Start

### 1. Run the verification engine

```bash
cd graphite-core
export GRAPHITE_API_KEY=$(openssl rand -hex 32)   # every call below sends it
cargo run --release --bin graphite -- server --port 7331
# Graphite Core running on port 7331
```

The server is **authenticated by default** and refuses to start without
`GRAPHITE_API_KEY`. For local development only, `GRAPHITE_DEV_MODE=1` runs an
unauthenticated instance — and even then only on a loopback address.

### Production server configuration

| Env var | Default | Purpose |
|---------|---------|---------|
| `GRAPHITE_API_KEY` | *(required)* | Bearer token required on every route except `/health` (constant-time compared). **Startup refuses without it** unless `GRAPHITE_DEV_MODE=1`. |
| `GRAPHITE_ADMIN_API_KEY` | *(unset: `/admin/*` disabled)* | Operator key for `/admin/quarantine` (Round 19). Must be at least 32 characters and **different from `GRAPHITE_API_KEY`** — startup refuses otherwise. The verify key is never accepted on `/admin/*`, so an agent (or a prompt-injected one) holding the verify key cannot lift a quarantine. Unset, `/admin/*` answers `403`. Audit rows name the key id that acted. |
| `GRAPHITE_DEV_MODE` | `0` | `1` permits an **unauthenticated** instance for local development, and only when bound to loopback (`127.0.0.1` / `::1`). Never set this on a reachable address; the server refuses the combination. |
| `GRAPHITE_MAX_CONCURRENT` | `32` | Verifications allowed in flight at once. Excess is shed immediately with `503` + `Retry-After` rather than accepted and left to expire at the 10s request timeout — a request that dies at the timeout carries no verdict and no audit record. Distinct from the per-IP `429`: `429` means one caller is asking too often, `503` means the instance is saturated. Both are counted separately at `/metrics`. Raise it when the upstream RPC can sustain more. |
| `GRAPHITE_MAX_CONNECTIONS` | `1024` | TCP connections held open at once. A connection past the cap is closed at accept, before a byte is read, so descriptor exhaustion cannot take `accept` down for everyone. Must be a positive integer; anything else refuses to start. |
| `GRAPHITE_MAX_CONNECTIONS_PER_IP` | `64` (no limit behind `GRAPHITE_TRUST_PROXY`) | Connections one peer may hold open at once (IPv6 counted per /64, and a /48 may hold at most four times that), so one client cannot hold every slot of `GRAPHITE_MAX_CONNECTIONS`. Behind a trusted proxy every connection comes from the proxy, so the default there is no per-peer limit and the proxy should enforce one. `0` = no limit; a negative or non-integer value refuses to start. |
| `GRAPHITE_CONNECTION_LIFETIME_SECS` | `120` | The longest one connection may stay open, keep-alive included. Must be greater than `0`. |
| `GRAPHITE_RATE_LIMIT` | `30` | Per-IP token bucket, requests/second. Returns `429` when exceeded. |
| `GRAPHITE_CORS_ORIGINS` | *(denied)* | Comma-separated allowed browser origins. Default denies all cross-origin browser calls; server-to-server clients are unaffected. `*`, and anything that is not an origin, refuses to start. |
| `GRAPHITE_DATA_DIR` | `./graphite-data` | Durability: semantic-graph snapshot (trust tiers + earned simulation baselines) and append-only `audit.jsonl` written after every verification, reloaded on restart. **The server probes this directory for writability at startup and refuses to boot if it cannot write** — it never serves traffic with no audit trail (P9) — and holds an exclusive lock on `graphite.lock` so a second server on the same directory refuses to start (Round 12). |
| `GRAPHITE_RPC_URL` | *(off)* | Attaches a Solana RPC client — live L3: `simulateTransaction` runs and real compute usage feeds the trusted baseline accumulator. Validated at startup (http/https only, no fragment; a plaintext non-loopback endpoint is warned about; link-local, cloud-metadata, unspecified, multicast and broadcast addresses refuse to start, and since Round 30 a host name is re-checked against them each time it resolves) and redirects are never followed. Usually embeds a provider API key; Graphite redacts endpoint URLs from every error and log line it surfaces, but treat the value as a secret. |
| `GRAPHITE_RPC_WITNESS_URL` | *(off)* | A second, independent RPC that L8 asks about inclusion (Round 12). An approved transaction is reported `ApprovedAndExecuted` only when both endpoints place the signature in the same slot with the same outcome; either endpoint's sighting of a BLOCKED transaction raises `BlockedButExecuted`. Must differ from `GRAPHITE_RPC_URL`. Without it, `/health` says `inclusion_witness: false` and every reconciliation carries `inclusion_witness: null`. |
| `GRAPHITE_TRUST_PROXY` | `0` | Number of **trusted reverse-proxy hops** in front of the server, for per-IP rate limiting: `0`–`255`, or `true` (= 1) / `false`; anything else refuses to start. `0` ignores `X-Forwarded-For` entirely (correct whenever clients can reach the server directly). Set it to the real number of proxies you control — the client IP is counted that many entries from the *right*, because proxies append the peer they observed and the left end is whatever the caller claimed. Over-counting re-opens the spoofing bypass. A header too short for the hop count, or malformed at the client's position, puts the request in one shared "unattributed" bucket — never the proxy's own. |
| `GRAPHITE_WALLET_PROFILE` | *(unset)* | **Pins the wallet policy profile server-side; the request body's profile is ignored.** Set this whenever the caller is not the wallet operator — the body is written by the agent, so a caller-supplied threshold is one the attacker gets to choose. Accepts `treasury`/`trading`/`gaming`/`enterprise`/`custom:<min_confidence>:<TrustTier>`. An unparseable value fails startup rather than silently falling back. |
| `GRAPHITE_ALLOW_PERMISSIVE_PROFILES` | `0` | Allow a caller-supplied `Custom` profile weaker than the weakest built-in (Gaming, 0.55). Off by default: otherwise a caller can disable the confidence/trust-tier gate outright. |
| `GRAPHITE_LEARN_FROM_POLICY_REFUSALS` | *(retired)* | **Removed in Round 30; any non-empty value refuses to start.** It let a request refused only by the threshold train evidence, so any verify-key holder could raise a program's confidence for every caller. Evidence now trains only when a verdict clears the weakest built-in bar on its own, whatever profile the request named; stand a program up with `graphite evidence seed` / `graphite evidence baseline`. |
| `GRAPHITE_READ_API_KEY` | *(unset)* | Optional read-only key (Round 30): opens only `GET /metrics`, `/manifests` and `/api/*` — give it to the dashboard instead of the verify key. At least 32 characters, different from both other keys, and only with `GRAPHITE_API_KEY` set; startup refuses otherwise. |
| `GRAPHITE_L8_HIGH_ASSURANCE` | `0` | `1` (Round 30): L8 states nothing about what the chain holds unless an independent witness agrees (reported `Unavailable` with the reason; the `BlockedButExecuted` alarm is never withheld). Startup refuses unless both RPC URLs are https, the witness is judged independent of the primary (host, registrable domain, resolved addresses), and the two provider names below are set and differ. |
| `GRAPHITE_RPC_PROVIDER`, `GRAPHITE_RPC_WITNESS_PROVIDER` | *(unset)* | The operator's attestation of who runs each RPC (e.g. the company names), required and compared under `GRAPHITE_L8_HIGH_ASSURANCE=1`; logged at startup, never compared to the URLs. |
| `GRAPHITE_AUDIT_KEY_FILE` | *(unset: corruption-evident)* | Round 30. A file holding at least 32 bytes as hex, mode 600 or stricter, outside `GRAPHITE_DATA_DIR`: every audit record's chain link then carries an HMAC-SHA256 under it, and the trail is tamper-evident against anyone without the key. A keyed trail refuses to continue without a key. Rotation: `docs/ops/keys.md`. |
| `GRAPHITE_AUDIT_ANCHOR_DIR` | *(unset)* | Round 30. A directory outside `GRAPHITE_DATA_DIR` where a checkpoint of the chain's head is written at every rotation; kept on storage the server cannot rewrite, a checkpoint is what shows a dropped tail or a restored older backup (`graphite audit verify --checkpoint`). Failed writes are counted on `/health` and `/metrics`. |
| `GRAPHITE_LOG_FORMAT` | *(text)* | `json` emits structured logs for aggregators. Level via `RUST_LOG` (default `info`). |
| `GRAPHITE_AUDIT_ROTATE_BYTES` | `67108864` (64 MiB) | Rotate the active audit file at this size, bounding disk growth and the dashboard's per-poll scan cost. `0` disables rotation, which leaves the active file and its in-memory indexes unbounded (a startup warning says so). |
| `GRAPHITE_AUDIT_MAX_ARCHIVES` | `0` (keep all) | Rotated archives to retain. The default keeps the complete audit trail (P9); set a limit only if you accept that the oldest history is deleted. |
| `GRAPHITE_ALLOW_DURABLE_NONCE` | `0` | `1` permits durable-nonce transactions, which never expire, and only after the nonce account is verified on-chain. Refused at L2 by default. Process-wide. A legacy (version 0) nonce account is refused either way, as the runtime refuses it. |
| `GRAPHITE_ALLOW_UNREADABLE_VALUE_DECLARATIONS` | `0` | A signer's loss under a protocol declaration Graphite cannot read is refused whatever the instruction's class (Round 32). `1` turns it back into a warning for the classes that move value (swap, deposit, withdrawal and the like). Process-wide; logged at startup. |
| `GRAPHITE_ALLOW_SIGNER_LAMPORTS_OUTSIDE_DECLARED_DEBIT` | `0` | W19: lamports leaving a signer's wallet through an instruction whose declared debit names other accounts only are refused (Round 32), net of created accounts' rent and wrapped SOL. This also refuses a tip or a plain SOL transfer beside such an instruction; `1` restores the warning. Process-wide; logged at startup. |
| `GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS` | `0` | A granted Raydium CLMM, Raydium CPMM or Pump AMM withdrawal whose every minimum output is zero loses its grant (`UnboundedWithdrawal`, Round 32). `1` keeps the grant. Process-wide; logged at startup. |
| `GRAPHITE_QUARANTINE_ON_UPGRADE` | `0` | With an RPC attached, Graphite always notices when a manifested program is redeployed or handed to a new upgrade authority (reported on the verdict as `program_upgrades`, on `/health`, and as `graphite_program_upgrades_detected_total`). `1` also quarantines the program until the operator reviews the manifest and lifts it. Any value other than `0`/`1`/`true`/`false` refuses to start. |
| `GRAPHITE_PLUGINS_DIR` | *(unset)* | Directory of plugin manifests to activate (the review gate: pending or rejected manifests are skipped). A directory that fails to load is a startup error, never a silent removal of the checks it carried. The in-tree built-in plugins are active regardless. |
| `GRAPHITE_PLUGIN_EVENTS_FILE` | *(unset)* | Append every verification event to this JSON-lines file, for observability. A file that cannot be opened for append refuses to start. |
| `GRAPHITE_REGISTRY_STATE` | `registry_state.json` (the container image sets it on the `/data` volume) | Manifest Registry state (reviewers, accepted community submissions, the registry's own regression corpus), shared by the server and `graphite registry` / `graphite verify`. Accepted community manifests are merged into the verifying core at startup. A missing file is a fresh registry; a corrupt or unreadable one refuses to start. |
| `GRAPHITE_GRAPH_STATE` | `graph_state.json` | CLI only: the Semantic Graph state `graphite registry submit` records submissions into (`--graph-state` overrides). |
| `GRAPHITE_SIGNER_KEY_FILE` | *(unset)* | CLI only: file holding the ed25519 key (64 hex chars) that signs a `graphite registry submit`. Preferred over the deprecated `--signer-key`, which exposes the key in shell history and the process list. |

**Every variable is parsed strictly.** `GRAPHITE_MAX_CONCURRENT` and
`GRAPHITE_MAX_CONNECTIONS` must be greater than `0`; `GRAPHITE_MAX_CONNECTIONS_PER_IP`,
`GRAPHITE_AUDIT_ROTATE_BYTES` and `GRAPHITE_AUDIT_MAX_ARCHIVES` at least `0`;
`GRAPHITE_ALLOW_PERMISSIVE_PROFILES`, `GRAPHITE_ALLOW_DURABLE_NONCE`, the three
Round 32 opt-outs (`GRAPHITE_ALLOW_UNREADABLE_VALUE_DECLARATIONS`,
`GRAPHITE_ALLOW_SIGNER_LAMPORTS_OUTSIDE_DECLARED_DEBIT`, `GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS`),
`GRAPHITE_QUARANTINE_ON_UPGRADE` and `GRAPHITE_L8_HIGH_ASSURANCE` accept
`1`/`true`/`0`/`false`, trimmed and in any case; the retired
`GRAPHITE_LEARN_FROM_POLICY_REFUSALS` refuses to start with any value. A value that does not parse refuses to
start; nothing falls back to a default silently. A keyless `GRAPHITE_DEV_MODE=1` instance
answers `421` to a request whose `Host` is not loopback (DNS rebinding).

**Transport limits.** The server speaks HTTP/1.1 only (no HTTP/2, no
upgrade). A client has 5 s to send a complete request head, and an idle
keep-alive connection is closed after the same 5 s; the body then has 2 s to
arrive (`408` otherwise, before any verification permit is taken); the 10 s
request timeout covers the body and the verification together, and no
connection lives longer than `GRAPHITE_CONNECTION_LIFETIME_SECS` (120 s).
Verifications (`/verify`, `/verify/execution`) draw on the
`GRAPHITE_MAX_CONCURRENT` permits; every other route shares a separate, fixed
pool of 16, so a slow dashboard cannot starve verification; `/health` draws on
neither and is exempt from rate limiting. With the
connection cap above, these are what stop a slow-loris client, which the
request timeout alone could not, because it only starts once a request head
exists.

**Observability.** `GET /metrics` serves Prometheus text format (behind the API
key, like every endpoint except `/health`), 28 series: verification request/approve/block/
error counts (a `422` on `/verify` counts as a request and an error), auth failures,
rate-limit rejections, request rejections by kind (`graphite_request_rejections_total`),
load shedding of the non-verification pool (`graphite_auxiliary_load_shed_total`), audit-log write and
rotation success/failure counters, active log size and archive count,
semantic-graph snapshot success/failure counters, lifecycle reports against
blocked or unverified hashes, and the L8 counters — `graphite_execution_checks_total`,
`graphite_execution_discrepancies_total` (a blocked transaction executed: page
on this) and `graphite_execution_chain_bytes_rejected_total` (the RPC returned
bytes that are not the signature's: a faulty or hostile RPC). `GET /health` is open for
load balancers, exempt from rate limiting and load shedding, and reports `degraded` with a
`degraded_reasons` list (`audit_writes_failed`, `audit_rotation_failed`, `audit_disabled`,
`graph_snapshot_failed`, `simulation_baseline_frozen`) and `frozen_baseline_count`; the
frozen programs themselves are listed at the authenticated `GET /api/frozen-baselines`
— a verdict that cannot be recorded is refused with
`503`, and every other durability failure is counted here so a node quietly
losing its trail or its earned state is alertable rather than invisible.
`graphite healthcheck` (the container's `HEALTHCHECK`) passes on any `2xx`
from `/health`, degraded or not: a degraded node already refuses what it
cannot record. `graphite healthcheck --strict` also fails when `/health`
reports `degraded: true` (or carries no `degraded` flag), for an orchestrator
that should replace such a node. The image keeps the default.

**Audit durability.** Every audit record is `fdatasync`'d to the device before
the response is sent (≈1.5 ms per record measured on an NTFS SSD; `File::flush`
is a no-op for an unbuffered file and was what the code called before
2026-09-12). Rotation renames the active file; the read APIs and L8
reconciliation cover every archive plus the active file, so a verdict never
disappears from Graphite's own view by rotating out. Each archive has a
persisted index, checked against the archive's SHA-256, so a lookup into the
archives is a few seeks rather than a pass over each (2.2 ms against 822 ms
for three 64 MiB archives). Every append runs on
tokio's blocking pool, so a slow disk flush holds a blocking thread, not one of
the async workers that serve other requests.

```bash
# Minimal production launch (auth + rate limit + durability)
GRAPHITE_API_KEY=$(openssl rand -hex 32) GRAPHITE_RATE_LIMIT=100 \
  GRAPHITE_DATA_DIR=/var/lib/graphite GRAPHITE_CORS_ORIGINS= \
  cargo run --release --bin graphite -- server --port 7331 --host 0.0.0.0
```

> **Bind address.** `--host` defaults to `127.0.0.1` so running the server on a
> laptop, shared box, or cloud VM does not silently publish the API to every
> reachable network. Pass `--host 0.0.0.0` to expose it deliberately. Without
> `GRAPHITE_API_KEY` the server does not start at all; with `GRAPHITE_DEV_MODE=1`
> and no key it starts **only** on loopback.

### Integrating safely (read this before writing the integration)

Graphite verifies **before** the transaction is signed. Four rules make that
protection real; skipping any one of them produces an integration that looks
correct and protects nothing.

**1. Send the bytes, and require `artifact_bound`.** Build the transaction
first, serialize it with empty signature slots, and send it as
`signed_transaction`. The verdict then carries `scope.kind = "artifact_bound"`
and `scope.transaction_sha256`, the SHA-256 of those exact bytes. A verdict
without the bytes is `descriptive`: it describes what you *said*, and nothing
in it constrains what is signed.

| `scope.kind` | What the verdict covers | Safe to execute on `approved` alone? |
|---|---|---|
| `artifact_bound` | The exact transaction bytes you supplied, subject to `scope.unobserved` | Only if you sign and submit those exact bytes (rule 2) |
| `descriptive` | Only the metadata you described. Nothing constrains what is actually signed | **No** |
| *(absent)* | Not a v1 verdict: the schema requires `scope`, and both SDKs refuse a verdict without it | **No** — refuse it |

Read `scope.unobserved` in both modes: it lists, in words, the security-relevant
properties Graphite did *not* establish. It is never empty — a verdict claiming
to have observed everything would be a strong assertion, and one Graphite does
not make. Decide on `scope.unobserved_codes`, not on the prose (rule 3).

Always send `instruction_data` with the bytes. An artifact-bound verdict
identifies the described instruction in the message by its program, its exact
data and its accounts at one position; without the data L2 fails, because
Graphite will not bind a verdict to bytes it could not compare (Round 9: a
100 SOL transfer was approved under a 0.002 SOL description by omitting it).

A transport error, timeout, or non-200 means *verification did not happen*:
that is a hard stop, never an implicit pass.

**2. Sign exactly the bytes that were verified.** Between approval and the
chain, a transaction object can still be mutated — a compromised RPC proxy, a
malicious wallet adapter, a helper that "refreshes" the blockhash, a race in
your own pipeline. The SAK bridge's `BoundTransaction` is the reference shape:
it deep-copies the instructions at build time, exposes no mutable handle,
recomputes the digest against the approved `transaction_sha256` inside
`signApproved`, derives the required signer set from the compiled message
rather than from the caller, and returns the only bytes meant for submission.
A rebuilt or refreshed transaction is a different digest and is refused.

```ts
import { GraphiteClient, isArtifactBound, isExecutable } from "@graphite/sdk";
import { BoundTransaction } from "./artifact.js"; // integrations/agent-guard
import { ResidualPolicy } from "./residual-policy.js";

const graphite = new GraphiteClient({ baseUrl, apiKey });
const bound = BoundTransaction.build({ instructions, feePayer, recentBlockhash, lastValidBlockHeight });

let result;
try {
  result = await graphite.verify({ ...input, signed_transaction: bound.artifact() });
} catch (e) {
  throw new Error(`verification did not happen: ${e}`); // never proceed
}

if (!result.approved) throw new Error(`blocked: ${result.summary}`);
if (!isArtifactBound(result)) throw new Error("verdict is descriptive; nothing is bound");
// Rule 3 (Round 30): `approved` is not permission to sign. Without the guard,
// `isExecutable` recomputes the decision and requires the Core's to agree:
if (!isExecutable(result)) throw new Error(`not executable: ${result.decision}`);
// With the guard's policy, the same check plus operator-accepted residuals:
// it throws unless the verdict is executable_approved, or analysis_only only
// because of a residual named in GRAPHITE_ACCEPT_UNOBSERVED.
// new ResidualPolicy(process.env.GRAPHITE_ACCEPT_UNOBSERVED?.split(",") ?? []).assertExecutableVerdict(result, "transfer");

// Throws unless the digest of these exact bytes equals the approved one and
// the supplied signers are exactly the message's required signers.
const raw = bound.signApproved(result.scope.transaction_sha256, [walletKeypair]);
// Rule 4: the signing is on the trail before anything leaves the process.
const keys = { content_hash: result.content_hash, audit_trail_id: result.audit_trail_id, transaction_sha256: result.scope.transaction_sha256 };
const receipt = await graphite.recordLifecycleEvent({ event_type: "signing", ...keys });
if (receipt.verdict_on_record !== "approved" || receipt.verdict_on_record_key !== "audit_trail_id") {
  throw new Error("the approval in hand is not the approval on record");
}
const signature = await connection.sendRawTransaction(raw);
await graphite.recordLifecycleEvent({ event_type: "submission", ...keys, transaction_signature: signature });
const l8 = await graphite.verifyExecution({ signature, ...keys });
if (l8.discrepancy) throw new Error("BlockedButExecuted: the gate did not govern");
```

**3. Refuse any residual you have not accepted by name.** Every verdict carries
`scope.unobserved_codes`, one stable code per `unobserved` entry. Two codes are
inherent to every artifact-bound verdict — `program_semantics` and
`inner_instructions` — and a policy that accepts only those accepts nothing
Graphite could have observed and did not. Every other code (`no_state_diff`,
`simulation_failed`, `not_simulated`, `privileges_from_caller`, `privileges_absent`,
`lookup_tables_unresolved`, `artifact_unparsed`, `account_identity_unparsed`,
`instruction_not_located`) names an observation that was possible and did not
happen. The SAK bridge's `ResidualPolicy` refuses execution on any of them
unless the operator lists it in `GRAPHITE_ACCEPT_UNOBSERVED`, validates that
list at startup, refuses a server that reports prose only, and records the
accepted codes on the execution outcome. A verdict is a description of what was
checked; the policy is where a deployment says what it is willing to sign
without.

**4. Put your signing and submission on the trail, then reconcile — under the
exact keys.** Graphite records what it verifies; only you can record what you
sign and send. `recordLifecycleEvent({ event_type: "signing", content_hash,
audit_trail_id, transaction_sha256 })` *before* submission — and do not submit
if it is not recorded, if its `verdict_on_record` is not `approved`, or if
`verdict_on_record_key` is not `audit_trail_id` — then `submission` with the
signature, then `verifyExecution({ signature, content_hash, transaction_sha256,
audit_trail_id })` for L8. `content_hash` alone names every transaction
carrying that instruction; the exact keys name yours. L8 itself joins on the
chain's bytes when it can fetch them and reports which key it used
(`attribution`). The reference sequence is `executeBoundTransaction` in
`integrations/agent-guard/execution-lifecycle.ts`; no irreversible step
proceeds unless the step before it is on the trail.

**`content_hash` is the audit key, not the binding.** `content_hash` is a
64-bit identifier over one instruction's projection — program, discriminator,
accounts, data, CPI targets. It links the verdict to the audit trail and to L8
reconciliation, and the SDKs' `verifyInstruction` / `VerifyInstruction`
(TypeScript, Go) re-hash an instruction against it as a secondary,
instruction-level check. It cannot see the fee payer, the blockhash, the
signer set, or any other instruction in the transaction; `transaction_sha256`
can, and is the authoritative binding whenever the bytes were supplied.

**Durable nonces are refused.** A transaction whose first instruction is a
System `AdvanceNonceAccount` does not expire, so every state-based conclusion
in a verdict holds only at verification time. L2 refuses them by default;
`GRAPHITE_ALLOW_DURABLE_NONCE=1` permits them only after the nonce account is
verified on-chain, and the bridge will not build one.

### Deployment, TLS, and scaling

- **TLS is terminated upstream.** The server speaks plain HTTP by design; run it
  behind a reverse proxy or load balancer that terminates TLS. Do not expose it
  directly to the internet. Set `GRAPHITE_TRUST_PROXY` to the number of proxy
  hops you control, and make sure that proxy *overwrites* rather than trusts any
  client-supplied `X-Forwarded-For`.
- **Single replica today.** Durable state (the append-only audit log and the
  semantic-graph snapshot) lives on a local volume with no cross-process
  coordination, so this stack is **not** currently safe to scale horizontally:
  two replicas sharing a volume would race, and two replicas with separate
  volumes would fragment the earned-trust history that the confidence model
  depends on. Run one replica (Kubernetes: `strategy: Recreate` with a PVC)
  until a shared-state backend lands. This is a known limitation, tracked in
  `SECURITY.md`, not an oversight.
- **Container hardening.** The shipped `docker-compose.yml` runs the image as a
  fixed non-root UID with a read-only root filesystem, all capabilities dropped,
  `no-new-privileges`, CPU/memory/PID limits, log rotation, and the host port
  bound to loopback. Change the port binding deliberately when putting a proxy
  in front of it.

### 2. Verify a transaction

```bash
curl -X POST http://localhost:7331/verify \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $GRAPHITE_API_KEY" \
  -d @../examples/verify-input.json | jq .
```
> ⚠️ The example input uses the `TradingBot` profile (0.80 threshold) and sends no transaction bytes, so its verdict is `descriptive`. On a fresh Core (no earned evidence) the achievable confidence for a known protocol is ~0.44, so this example returns **BLOCKED** — that is the engine being honest, not a bug. The confidence signals are *earned*, not asserted: `SimulationMatch`, `HistoricalVolume`, and `CommunityVerification` read from the Semantic Graph's internal accumulator (simulation baselines from approved traffic or the operator, and Behavior evidence the operator seeds), so the presets become satisfiable as the graph accumulates history. A `Custom` profile below Gaming (0.55) is raised to Gaming unless the server was started with `GRAPHITE_ALLOW_PERMISSIVE_PROFILES=1` — a development setting that disables the confidence gate. With it, this shows the pipeline approving the descriptive example (which is still not executable: nothing is bound):
> 
> ```bash
> jq '.wallet_profile = {"Custom": {"min_confidence": 0.40, "min_trust_tier": "OfficialManifest"}}' ../examples/verify-input.json | curl -X POST http://localhost:7331/verify -H "Content-Type: application/json" -H "Authorization: Bearer $GRAPHITE_API_KEY" -d @- | jq .approved
> ```

### 3. After submission: reconcile what happened (L8)

`/verify` answers "should this be signed?". It cannot answer "did my decision
govern the wallet?", because that happens after the request is over. L8 is the
call that closes the loop, and it is caller-driven by design — Graphite does not
watch the chain, so someone has to report the signature.

```bash
curl -X POST http://localhost:7331/verify/execution   -H "Content-Type: application/json"   -H "Authorization: Bearer $GRAPHITE_API_KEY"   -d '{"signature":"<base58 signature>","audit_trail_id":"<from the /verify response>","transaction_sha256":"<scope.transaction_sha256>","content_hash":"<content_hash>"}' | jq .
```

```bash
# Same reconciliation from the CLI, usable as a monitoring check. Exit codes:
# 0 clean, 1 discrepancy (BlockedButExecuted), 3 unavailable or misconfigured,
# 4 the chain's bytes were rejected, 5 the RPC contradicted itself, 6 the
# witness disagreed.
graphite execution --signature <base58 signature> --audit-trail-id <id> --transaction-sha256 <digest>
```

With an RPC that serves `getTransaction`, L8 does not need the keys at all: it
fetches the bytes behind the signature, checks that they are that signature's
— the first slot holds it and it verifies (ed25519) over the message under the
fee payer's key — zeroes the signature slots (which gives back exactly the
artifact that was verified) and joins on their digest — `attribution:
"chain"`. Bytes that fail that binding are refused: `chain_bytes_rejected`
says why, the reconciliation is `Unavailable`, and the keys you supplied are
*not* consulted in their place (an RPC that can substitute bytes must not also
choose the join). The keys are cross-checked against the chain's answer and
any disagreement is reported in `caller_keys_disagree` — a record you cite
whose bytes the chain contradicts is `NoVerificationOnRecord` plus a
`caller_keys_disagree` entry, never a discrepancy (only `BlockedButExecuted`
is). `getTransaction` is asked at the configured commitment (`confirmed` at
least), so chain-byte attribution works once a transaction is confirmed. Without the chain's
bytes the most exact key you supplied decides, and `content_hash` alone is
ambiguous by construction: it names every transaction carrying that
instruction.

The SAK bridge makes this call itself after every verified execution, and
records its `signing` and `submission` on the trail around it (`POST
/audit/event`); each such row carries `verdict_on_record`, what the trail said
about the hash when the report arrived, and a report against a blocked verdict
is counted at `/metrics` and logged at ERROR.

The field to watch is `reconciliation`. `ApprovedAndExecuted` and
`BlockedAndNotExecuted` are the gate being obeyed. `ApprovedButFailedOnChain` is
not a security failure — Graphite verifies intent and structure, not that a
transaction will succeed. **`BlockedButExecuted` is the one worth paging on:**
Graphite refused the transaction and it landed anyway, so the gate was bypassed
rather than obeyed — an integration ignoring the verdict, a key used out of
band, or an override. It sets `discrepancy: true`, logs at ERROR, and goes on
the append-only trail. Nothing inside a verification request can ever detect it,
because it happens entirely outside one.

Without an RPC endpoint, or with one that will not answer, the result is
`Unavailable` with the endpoint redacted. An unavailable check reports that it
is unavailable; it never reports a confirmation: an L8 check that did not see
the transaction included at a cluster-backed commitment writes an
`execution_check` row to the trail, never a Graphite-attested `confirmation`.
Without `GRAPHITE_RPC_WITNESS_URL`, a hostile or broken primary RPC can turn a
`BlockedButExecuted` into `BlockedAndNotExecuted`, `NotFound` or `Unavailable`;
the witness is what stops one endpoint deciding that alone.

### Operator CLI

`graphite verify` answers "what does the gate decide?" as JSON. These answer the questions an operator actually asks around it. All of them read the same durable semantic graph the server does (`GRAPHITE_DATA_DIR`, default `./graphite-data`), so the CLI and the server never disagree about a program's earned trust.

```bash
# WHY did the gate decide that? Layer by layer, with the confidence breakdown,
# the risk findings, and the accounts. Same pipeline as `verify` — a renderer,
# not a second decision path. Exits as `verify` does (Round 30): 0 only for
# executable_approved, 1 when refused, 3 for an analysis-only approval — and
# the CLI attaches no RPC, so every approval it gives exits 3.
graphite explain --file examples/verify-input.json
```

```bash
# Is the audit trail what was written? Walks every archive and the active file
# along the hash chain (never trusting an index) and checks every MAC under the
# key files given (old keys after a rotation too). Exit 0 nothing failed,
# 1 a break or a checkpoint that does not hold, 2 not provable as asked (a MAC
# under a key not supplied, no chained record, a pruned checkpoint),
# 3 unreadable. Then export a checkpoint of the head to anchor elsewhere.
graphite audit verify --key-file /etc/graphite/audit.key --checkpoint ./last-checkpoint.json
graphite audit checkpoint --out ./checkpoint-2026-10-22.json
```

```bash
# What does the gate know about this program? Manifest, EARNED trust tier and
# the evidence behind it, simulation baseline, declared CPI targets, quarantine
# state. A declared tier is labelled as declared — a manifest claiming
# BattleTested with no evidence must not read as fact.
graphite protocol status --program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
```

```bash
# What am I signing off on? Compares a candidate manifest against the one
# currently in force: instructions added and removed, renames (identified by an
# unchanged discriminator, so a rename never reads as a breaking removal),
# account privilege changes, each slot's role, PDA seeds, expected addresses
# and optional flag (alternative layouts too), new CPI targets, changed risk
# classes and risk rules.
# The reviewer's missing tool — their attestation is what earns the tier.
graphite protocol diff --manifest ./candidate.json
```

```bash
# Would the loader accept this? Run before signing, not after.
graphite manifest-verify --manifest ./candidate.json
```

```bash
# Bootstrap: a fresh graph has no earned evidence, and the evidence-derived
# confidence signals are half the total weight -- so an instance with an empty
# graph and no GRAPHITE_RPC_URL blocks 100% of traffic (max reachable
# confidence 0.44 against a 0.55 floor). These restore an exported graph or
# stand an instance up before that history exists. CLI-only: request-body
# evidence would let any caller mint an earned-looking tier.
# Both take a base58 program id and write an operator_action row to the audit trail.
graphite evidence seed --program <id> --signed-manifest --community-verified 2   --battle-tested 1500 --simulation-matches 100
graphite evidence baseline --program <id> --mean-compute-units 150   --std-compute-units 12 --samples 50
graphite evidence show --program <id>
```

```bash
# Withdraw a program from trust immediately, restore it, or see what is withdrawn.
graphite quarantine add --program <id> --reason "GHSA-2026-0001 authority takeover"
graphite quarantine list
graphite quarantine lift --program <id>
```

```bash
# Onboarding a new program: the P10 gate needs a regression baseline, and one
# cannot be recorded the ordinary way because the manifest is not installed yet.
graphite registry record-fixture --corpus-dir ./corpus   --manifest ./candidate.json --input ./tx.json
graphite registry submit --manifest ./candidate.json   --signer-key-file ./key.hex --corpus-dir ./corpus
# The registry owns its regression corpus: a submission adds fixtures and cannot
# remove them. Retiring a fixture, and a reviewer, are operator actions.
graphite registry deprecate-fixture --help
graphite registry revoke-reviewer --help
```

There is deliberately no `build --simulate`. `verify` already simulates when an RPC client is attached, and a separate build-and-simulate command would need its own transaction-plan input format — inventing one to round out a list is the kind of surface that exists to be listed rather than used.

### 3. Run one request through the guard

```bash
# Start the AI layer (separate process, P1 compliance)
cd python-ai-layer
python3 intent_parser.py --serve --port 8081

# One transfer, end to end (SOLANA_PRIVATE_KEY, SOLANA_RPC_URL, GRAPHITE_CORE_URL set)
cd ../integrations/agent-guard
npm ci --ignore-scripts
npx tsx cli.ts transfer "Transfer 0.05 SOL to <address>"
```

The flow:
1. The AI layer parses the request → `ProposedIntent` (advisory)
2. The guard re-derives amount and destination from the user's own text and refuses a parse that disagrees
3. The guard builds ONE transaction and Graphite verifies those exact bytes → `VerificationResult`
4. Approved and artifact-bound → the guard signs those bytes and submits them. Blocked → nothing is signed (exit status 2).

This is the real path: an approval moves funds on whatever cluster `SOLANA_RPC_URL`
names. A swap needs the exact route instruction (`cli.ts swap "<request>" route.json`).

---

## Dashboard

The read-only dashboard (`dashboard/`) visualizes live Core state — protocol
overview with trust tiers, a Semantic Graph view with directed CPI edges, a
confidence time series, policy violations, and the Manifest Registry.

```bash
cd dashboard
npm ci
npm run dev          # dev: proxies /api to http://localhost:7331
npm run build        # production build → dist/
```

It polls the read-only endpoints (`/api/graph`, `/api/confidence-history`,
`/api/policy-violations`, `/api/protocols/top`, `/api/registry`, `/manifests`, `/health`
and `/metrics`) that the Core server exposes behind the same Bearer auth and rate limiting as
`/verify` (`/health` excepted). Totals are the server's whole-trail counts; figures
computed from a returned window say "last N"; a failed `/metrics` read is shown as
"unknown", never as zero. Point a browser at the dev server (or serve `dist/` statically)
and set `VITE_GRAPHITE_API` if Core lives elsewhere. Read-only by
construction (Constitution P4) — the dashboard never mutates graph state.

## Security Properties

| Property | How It's Enforced |
|----------|-------------------|
| **Unknown protocol cap** | Hard 0.55 confidence ceiling — no caller evidence can override (P6/P12) |
| **Fail-closed on unknown** | Unknown discriminator on known protocol → BLOCKED (confidence 0.0) |
| **NaN bypass prevention** | Explicit NaN/Infinity rejection in confidence engine |
| **AI never decides** | Python AI layer is advisory only — Core verification is deterministic (P1) |
| **Deterministic** | Same input, same output (P2). `content_hash` is the first 8 bytes of a framed SHA-256 over one instruction's projection — a 64-bit audit identifier; `scope.transaction_sha256` is the full digest of the transaction bytes |
| **Compositional drain detection** | Both duplicate AND unique-program deep CPI chains caught |
| **Trusted simulation baselines** | Baselines live in the semantic-graph accumulator (earned via RPC-verified usage or operator-seeded) — the request body **cannot** supply one (anti-poisoning) An observation is one distinct execution: keyed on the frame with its signatures and blockhash zeroed, remembered exactly per program, and recorded only from the transaction artifact itself — a fresh blockhash or a repeated descriptive request earns nothing (Round 19). |
| **Transaction identity** | With `signed_transaction` supplied: wire format parsed (legacy, v0 and v1 — never looser than agave's decoder), `transaction_sha256` over the exact bytes, L2 requires the described instruction to be in the bytes positionally and every sibling declared, privileges read from the header and resolved lookup tables — never from the caller |
| **Address lookup tables** | Fetched, owner-checked, decoded; runtime account numbering rebuilt (static ++ writable ++ readonly); all-or-nothing — an unresolved table is disclosed as unobserved, never treated as empty |
| **Token-2022** | Extensions classified; the **transfer fee is modelled** (Round 20) and **replayed** (Round 21) — every Token-2022 instruction the simulator executed is replayed from the pre-state against the mint's schedule for the epoch Graphite reads, and must end exactly at the post-state; withdrawals, several transfers into one account and send-and-receive included; the fee and what arrives stated, a fee larger than the arrival blocked. A hook naming no program, untouched confidential state and an issuer's unchanged standing powers are inert; a hook that runs a program is inert when the bytes bound it — nothing Token-2022 can hand it signs the transaction and every writable account among them is its own (Round 22); a pending fee schedule is always judged (Round 22); a permanent delegate moving someone else's tokens is Critical. Anything it cannot account for exactly, and every unknown or unreadable extension, blocks; informational extensions warn |
| **Durable nonces** | Detected by the runtime's rule; refused at L2 by default; opt-in only after on-chain nonce verification |
| **Wire-format bounds** | Canonical compact-u16 (≤ 65,535, minimal encoding), trailing bytes refused, indexes bounds-checked, nothing over the format's size bound (1232-byte packet for legacy/v0, 4,096 bytes for v1) — the same rules on the TypeScript side, asserted equal across 2,897 byte-level mutations in CI |
| **The described instruction is located, or L2 fails** | An artifact without `instruction_data`, or one that does not parse, fails L2; `artifact_bound` never claims a comparison L2 did not make (Round 9: a 100 SOL transfer was approved under a 0.002 SOL description by omitting the optional field) |
| **Residuals are gated at execution** | `scope.unobserved_codes` names each residual; the bridge's `ResidualPolicy` refuses any non-inherent one the operator has not accepted in `GRAPHITE_ACCEPT_UNOBSERVED` |
| **Lifecycle on the trail** | The bridge records signing before it submits (and aborts if it cannot), submission after, and runs L8 at the end; every caller-reported row carries the server's `verdict_on_record` and is bounded on disk |
| **L8 attribution is exact** | An execution is joined to the verification of *those bytes* — the chain's transaction with signature slots zeroed digests to `scope.transaction_sha256` — never to a same-instruction sibling by `content_hash` (Round 10: a blocked B executed after an approved A read as `ApprovedAndExecuted`). The bytes are the signature's, not merely the RPC's: first slot equal to it and verifying under the fee payer's key, or refused with nothing attributed (Round 11). Without the chain's bytes a caller's key can find the record, but an approval found that way is never reported as executed: `Unavailable` (R1, 2026-10-01); a blocked record still alarms on any sighting |
| **L8 does not take one RPC's word for inclusion** | A status at `processed` commitment is one node's view and draws no positive conclusion; an RPC whose `getTransaction` contradicts its `getSignatureStatuses` (slot or outcome) draws none; a malformed status is `Unavailable`, never "included and failed"; redirects are not followed; with `GRAPHITE_RPC_WITNESS_URL` both endpoints must agree before an approval is reported executed. The alarm on a BLOCKED transaction fires on any sighting by either endpoint, at any commitment (Round 12). Every reconciliation states its `inclusion_assurance`, a witness on the same provider is labelled not independent, and `GRAPHITE_L8_HIGH_ASSURANCE=1` withholds what one provider alone says (Round 30). Two providers agreeing is not a light-client proof |
| **The parser is never looser than the runtime** | `tools/runtime-oracle` decodes the corpus, its 2,897 mutations and ~628,500 frames per CI seed (300,000 legacy/v0, 300,000 v1, a systematic pass and the corpus) with the Anza SDK crates (`solana-transaction`, `solana-message`) as a validator's packet path does — plus frames either side of the 64-instruction, 64-lock and 256-account limits, and a cross-check of the 32 reserved ids; Graphite parses nothing the runtime's `sanitize` refuses (program index 0, out-of-range account indexes, empty lookups, > 256 accounts — all found and closed in Round 12) and reads every accepted transaction identically. Runs in CI on every push |
| **The lifecycle trail knows its own order** | Every caller-reported row is checked against the rows already on record for the same transaction: a retry is named `duplicate`, a stage out of order or without its predecessor is named, and a second signature for one transaction is a `signature conflict` logged as loudly as a discrepancy. Recorded, never refused (Round 12) |
| **RPC evidence provenance** | Simulation writes/CPI hops derived only from canonical response fields; non-standard provider fields that disagree are reported as anomalies, never used |
| **API auth** | Bearer API key required by default — the server refuses to start without one, or with one shorter than 32 characters; `GRAPHITE_DEV_MODE=1` permits keyless on loopback only. Constant-time compared; `429` per-IP rate limiting with `Retry-After`; `503` load shedding; refusals drain the request body so the status is readable, never a reset; CORS allowlist (denied by default) The operator surface (`/admin/*`) takes a second, distinct key, `GRAPHITE_ADMIN_API_KEY`, and is disabled without one (Round 19). An optional third, `GRAPHITE_READ_API_KEY`, opens only the read routes the dashboard uses (Round 30). |
| **Durability** | Every audit record `fdatasync`'d before the response; a verdict that cannot be recorded is refused with `503`; a failed append is truncated away, and appends are refused until that succeeds; rotation is a rename, archives retained, and every reader (dashboard, L8) covers the whole trail; snapshot and rotation failures surface on `/health` as `degraded_reasons`. Since Round 30 every record is hash-chained to the one before it, across rotation, and one process writes a trail (an exclusive lock). With `GRAPHITE_AUDIT_KEY_FILE` each link also carries an HMAC-SHA256: **tamper-evident** against anyone without the key; without one the chain is **corruption-evident** only. A dropped tail or a restored older backup shows only against a checkpoint kept where the server cannot rewrite it (`graphite audit checkpoint`, `GRAPHITE_AUDIT_ANCHOR_DIR`, `graphite audit verify --checkpoint`) |

---

## Honest Status

The single authoritative statement of what is enforced today, what is not, and
what remains undone is [docs/CURRENT.md](docs/CURRENT.md). The dated reports in
`docs/` are evidence of the work as it happened and are not edited afterwards.

What we **do not** claim:

- The benchmark is 24 hand-built cases — 7 safe, 15 malicious and 2 unscored "unknown" (no manifest: their refusal is documented policy, not a detection) — so 22 are scored. It is NOT a statistical evaluation on unseen data, and every case is a hand-written `VerificationInput` verified in descriptive scope. Its comparison row is an approve-all baseline (it approves whatever simulates, and every case does), named as such; it is degenerate and is there to show what "no gate" scores. Five exploit cases are **REAL-RECONSTRUCTED** from real mainnet transactions (STMT drainer 64tsGGe, AAT drainer 524t8LW, Wormhole $320M hack 5fKWY7X, fresh Aug-2026 drainer chain 2AWwL6dk, AAT mass drain 3PbK87): the program ids, account addresses and CPI targets are the transaction's; the intent, profile, compute numbers, hex discriminator and the instruction and CPI slices are reconstructed by hand (`benchmark.rs` says which, per case). The Wormhole case is refused by Risk Check 3 (the drainer ratio: nine accounts against a manifest instruction that declares two) — `wormhole-core.json` is a seed manifest and its `08` is `PostMessageUnreliable` — so it is not evidence that Graphite detects the Wormhole exploit's mechanism. Two more are SYNTHETIC (real program ids, fabricated accounts), labeled so per P16. Avg latency ~2.1ms (release build, measured locally at C52; no run artifact is in the repo — a figure, not a claim).
- L3 (Simulation) and L4 (State) are active when an RPC client is attached, and were validated end to end against live devnet on 2026-09-07 — including a transaction whose primary instruction is an ordinary transfer and whose second instruction reassigns the payer's account, which L1, L2 and L5 all pass and only L4's observed post-state catches. L8 (Execution Verification) is reachable in production as `POST /verify/execution` and `graphite execution`, and was checked by hand against mainnet through the ignored live tests (no run artifact in the repository). It is caller-driven by design: Graphite does not watch the chain, so someone must report the signature after submission. Until that call is made, L8 reports `Inconclusive` and says which endpoint completes it. The RPC endpoint is inside the trust boundary — see SECURITY.md for what a hostile one can and cannot do.
- No LLM-based intent parsing in the verification path (P1: AI assists, never decides). Intent alignment is structural — the declared intent type is matched against the manifest's supported intents (L5, Check 9), and high-risk instruction classes with no declared intent fail closed (Check 10, C38).

What we **do** claim:

- **Confidence is calibrated honestly and never read from the request (G4).** The three evidence-derived signals (`SimulationMatch`, `HistoricalVolume`, `CommunityVerification`) read from the Semantic Graph's **internal accumulator** — the program's RPC-verified simulation baseline (`sample_count`, counting DISTINCT sound transactions: the same bytes re-verified are one observation; a request refused at L2 or by the Risk Engine is none; and since Round 29 a request refused only by the policy threshold is none either; the Round 29 opt-in `GRAPHITE_LEARN_FROM_POLICY_REFUSALS` was retired in Round 30, since it let a verify-key holder train evidence, and now refuses to start) and the Behavior evidence the operator seeds — never from request-body JSON, which an attacker could fabricate to mint confidence. Manifest trust tiers are capped at `OfficialManifest` (P7), and the verdict's tier is the lowest over every top-level program the transaction invokes: an unmanifested sibling makes it `Unknown`, refused on every built-in profile. A fresh Core therefore scores a known, clean, intent-aligned `OfficialManifest` protocol at **~0.44** (0.20 + 0.14 + 0.10) and the built-in presets (TradingBot 0.80, Treasury 0.95, Gaming 0.55, Enterprise 0.99) block everything until evidence exists — e.g. Gaming (0.55) is exactly satisfiable by a HeuristicInferred manifest-backed program (the P6 ceiling), or by an `OfficialManifest` program with three simulation observations (0.64), which now accrue only from approved verdicts at the built-in floor or from the operator (Round 30). The benchmark and the agent guard default to a `Custom { min_confidence: 0.40, min_trust_tier: OfficialManifest }` profile (which the Core clamps to Gaming unless the operator allows permissive profiles); `graphite verify --profile <preset>` or `graphite profiles` drives the presets from the CLI. Raise or lower the profile to change policy; the engine's score itself is the honest number.
- The Rust, TypeScript, Go and Python suites pass with 0 failures and 0 clippy warnings; their counts are in [docs/CURRENT.md](docs/CURRENT.md#numbers-as-of-this-pages-commit). Every security fix from 2026-09-08 to Round 28 had its fix reverted once to show its test fails without it (the "deliberate break" logs in the round reports); Round 29's report says which of its fixes were and were not.
- 13 detection patterns (14 `RiskPattern` variants counting the `PluginBlock` plugin veto) and the Risk Engine's 16 checks, plus the priority-fee bound, are real detection logic, not stubs. Multi-instruction drain, CPI trace analysis (C29), and manifest-declared high-risk class gating (C38) shipped.
- 137 protocol manifests / 3,518 instructions (Round 18; Token-2022's transfer-fee instructions added in Round 20; Stake and the BPF Upgradeable Loader rebuilt from their interfaces in Round 22; eight programs added and the instructions that move nothing classed `inert` in Round 24), program IDs verified against on-chain sources and pinned both ways by test; 104 generated from each program's own on-chain Anchor IDL; every `BattleTested` tier backed by a mainnet measurement in `protocols/battle_tested_evidence.json` or lowered at load.
- Confidence engine uses real weighted computation with tier ceilings and NaN rejection.
- Simulation integrity uses 3-signal z-score (compute, writes, CPI hops) with Welford's algorithm and median/MAD baseline (C28).
- The SAK integration imports real `solana-agent-kit` v2 and calls real SAK methods — **verified on Solana devnet** (wallet `CWb8MciizembLV66kisYcXo3Cb91hdszxw74QHpEJKZR`, 5 finalized transactions: 2 faucet airdrops + 3 SAK test transfers; latest signature `xHa4dyuFS6JmSaTsmhcMpEtwbWnPjBoUGwk3wNixD2uw2Wmeui6GhnSmmdzNVkv85zXSd6g7QYhHymAjciwP3jJ` confirmed and finalized).
- A 12,967-fixture committed regression corpus (`graphite-core/fixtures/corpus`): 12,897 dev fixtures synthesised from the manifests, 32 synthetic regression attack shapes, and a 38-fixture holdout — 37 real mainnet exploit signatures (35 SolPhishHunter + 2 live-fetched from mainnet RPC) and 1 real, successful mainnet Jupiter swap. Only the holdout carries labels independent of Graphite: all 37 exploits are refused (0 false negatives, recall 1.0), and the Jupiter swap is refused too (1 false positive, precision 0.974 on n=38), because offline its address lookup tables cannot be resolved and the gate fails closed. Two more real transactions the holdout used to score as benign had in fact failed on chain, and are no longer scored. The exploits run descriptively, on hand-supplied evidence the engine ignores. The synthetic fixtures are labeled by Graphite's own documented rules (`tests/regression_corpus.rs`), so they measure consistency, not accuracy.

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/CURRENT.md](docs/CURRENT.md) | **The current security status** — what is enforced, what is not, what is still undone. Every dated report in `docs/` is historical and points here. |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System design, 8-layer pipeline, subsystem specs |
| [ROADMAP.md](ROADMAP.md) | Phases 1–2 complete; the 2026-09 hardening rounds; what gates Phase 3 |
| [SECURITY.md](SECURITY.md) | Security policy, known limitations, reporting |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup, PR checklist, Constitution principles |
| [Engineering Skill](https://github.com/Stan-lee13/graphite-engineering-skill) | The skill that builds Graphite — Constitution, personas, checklists |

---

## License

MIT — Copyright (c) 2026 Victor Stanley

---

<div align="center">

*If an AI agent is going to submit transactions on your behalf, something should verify those transactions first. That's what Graphite does.*

</div>
