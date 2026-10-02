# AUDIT 00 — Map of Graphite at `3327fcf` (2026-09-29)

This is the map the audit worked from: what exists, where it lives, what it is supposed to do, and the checklist every audit area was measured against. It describes the repository as it stands. It is not a claim that anything works: the evidence is in `01-findings.md`, `02-roadmap-gap.md` and `FINAL.md`.

Sources read: this repository (every top-level doc, `docs/CURRENT.md`, the Round 8–22 reports, `graphite-core/src/**`, `.github/workflows/ci.yml`), and the engineering-skills repository `graphite-engineering-skill-main` (README, ROADMAP, FEATURES, CONSTITUTION, ARCHITECTURE, SECURITY, TESTING, BENCHMARK, SEED_PROTOCOLS, SKILL, checklists, personas, memory logs, `reference/`).

## 1. What Graphite is

Graphite is a transaction-intent verification layer for Solana. An agent (or wallet) proposes an intent and a serialized transaction; the Rust Core decides, deterministically, whether the bytes do what the intent says and nothing it should not. The constitution's first principle is **"AI assists, AI never decides"** (P1): no model output may create or raise an approval. Everything that decides a verdict is deterministic Rust; the Python AI layer is a separate process whose output is advisory text.

## 2. Components

| Component | Path | Language | Size | Role |
|---|---|---|---|---|
| Core library | `graphite-core/src/` | Rust 1.98.1 | 48.4k lines, 28 files | The verifier |
| Pipeline | `src/verification.rs` | Rust | 9.2k | `GraphiteCore::verify`: L1–L7 per request, L8 post-submission |
| Wire parser | `src/tx_artifact.rs` | Rust | 2.0k | legacy / v0 / v1 messages, ALTs, runtime writability (agave demotion) |
| State diff | `src/state_diff.rs` | Rust | 4.5k | L4: pre/post diff, Token-2022 fee replay, extension judgement |
| Risk engine | `src/risk_engine.rs`, `src/tx_pattern_analysis.rs` | Rust | 3.6k | L7: drainer, hijack, fake swap, CPI-tree and multi-instruction patterns |
| Manifests | `src/manifest.rs`, `src/manifest_registry.rs`, `protocols/*.json` (131) | Rust / JSON | 4.0k | L2/L5 identity: discriminators, account layouts, PDA templates, trust tiers |
| Account resolution | `src/account_resolution.rs` | Rust | 1.4k | L1: PDA/AccountMeta resolution with provenance |
| Simulation integrity | `src/simulation_integrity.rs` | Rust | 1.1k | L3: compute baselines, shadow baselines, spoofing checks |
| Confidence / policy | `src/confidence_engine.rs`, `src/policy_engine.rs`, `src/unknown_protocol_mode.rs` | Rust | 0.9k | L6/L7: weighted signals, 0.55 unknown-protocol ceiling, 4 profiles |
| Semantic graph | `src/semantic_graph_store.rs` | Rust | 1.2k | Append-only evidence store, tier computation |
| Audit trail (L8) | `src/durable.rs` | Rust | 3.2k | JSONL audit log, fdatasync, rotation, active index, lifecycle rows |
| RPC client | `src/rpc_client.rs` (feature `rpc`) | Rust | 1.9k | simulate, getAccountInfo, ALTs, epoch, witness RPC; bounded bodies/timeouts |
| Plugins | `src/plugin_orchestrator.rs`, `src/plugins/` | Rust | 1.9k | 6 plugin interfaces, 2 reference plugins; veto/annotate only |
| Regression / benchmark | `src/regression_engine.rs`, `src/benchmark.rs`, `src/live_corpus.rs` | Rust | 3.1k | Corpus replay, P10 promotion gate, P16 benchmark |
| HTTP server | `src/server.rs` (feature `server`) | Rust / axum 0.8 | 6.3k | `/verify`, `/verify/execution`, `/audit/event`, `/health`, `/metrics`, `/manifests`, `/admin/*`, `/api/*` |
| CLI | `src/cli.rs`, `src/bin/graphite.rs` (feature `cli`) | Rust / clap | 3.2k | verify, server, regression, registry, evidence, execution, … |
| Runtime oracle | `tools/runtime-oracle/` | Rust + agave 5.0 | — | Parser never looser than agave; 2×300k generated frames in CI |
| Mainnet sampler | `tools/mainnet-sample/` | Python | — | Paced public-RPC block fetch for conformance runs |
| TypeScript SDK | `sdk/typescript/` | TS | — | Thin client, AuditBind, content_hash parity |
| Go SDK | `sdk/go/` | Go 1.26 (`go.mod`; CI tests 1.26.8 and 1.27.1) | — | Thin client, VerificationResult parity |
| SAK integration | `integrations/solana-agent-kit/` | TS | — | Bridge: BoundTransaction, signs only after an approved artifact-bound verdict |
| Python AI layer | `python-ai-layer/` | Python 3.11 | — | Advisory intent parsing, separate process |
| Dashboard | `dashboard/` | React / Vite | — | Read-only views over `/api/*` |
| Deploy | `Dockerfile`, `docker-compose.yml` | — | — | Non-root image, keyless start refused, loopback default |
| CI | `.github/workflows/ci.yml` | — | 8 jobs | rust (fmt, 2 no-feature checks, clippy, 3 test legs), cargo-audit, runtime-oracle, container smoke + TS live conformance, TS/SAK, Go, dashboard, Python |

## 3. The pipeline

`POST /verify` (or `graphite verify`) runs L1–L7 on one request; L8 runs after submission.

| Layer | Name | What decides it |
|---|---|---|
| L1 | Account resolution | Manifest layouts and PDA templates resolve every account, with provenance |
| L2 | Instruction verification | The wire bytes are parsed (never looser than agave); the instruction's leading bytes decide identity; the description is bound to the bytes (`artifact_bound`); ALTs are fetched, owner-checked, and decoded; durable nonces are refused unless verified |
| L3 | Simulation verification | `simulateTransaction` over the artifact only; its compute is judged against an earned baseline (±25% band); a failed simulation is `simulation_failed` |
| L4 | State verification | Graphite's own pre/post diff from simulation. Token-2022 fees are replayed exactly; every writable account is diffed |
| L5 | Semantic verification | The diff must match the manifest's expected behaviour; unknown programs are capped at 0.55 |
| L6 | Policy verification | Profile thresholds (Treasury, TradingBot, Gaming, Enterprise); policy plugins may only veto |
| L7 | Risk verification | Risk engine patterns (drainer, authority hijack, fake swap, hidden transfer, CPI tricks, permanent delegate, …). Any hard gate blocks. Risk plugins may only veto |
| L8 | Execution verification | `POST /verify/execution`: reads the chain's bytes (signature-bound), reconciles them against the audit record, and alarms when a refusal was executed |

Invariants the whole design rests on:

- **Fail closed.** No approval without every required layer passing. An unreadable account, a missing RPC, a panic, or an unparseable artifact refuses; it never approves.
- **Determinism (P2).** The same bytes, intent and state give the same verdict.
- **AI non-authority (P1).** No path from the Python layer, an LLM plugin or any model output raises a verdict.
- **Plugins only veto or annotate (P8).**
- **Evidence is earned.** Baselines record only sound, risk-clear, successfully simulated artifacts.

## 4. Goals extracted from the engineering-skills repository

- The **Constitution** has 15+ principles, each with a mechanical check. The load-bearing ones:
  - P1: AI never decides.
  - P2: determinism.
  - P3: explainability.
  - P6 and P12: the unknown-protocol ceiling.
  - P8: plugins bounded.
  - P9: an audit trail.
  - P10: the regression promotion gate.
  - P16: a published evaluation against a real benchmark.
- **Skills ROADMAP phase exit criteria** (these are the bar used in `02-roadmap-gap.md`):
  - **Phase 1:**
    - resolution verified against real mainnet history;
    - the 8-layer pipeline runs end to end;
    - the confidence ceiling passes;
    - the Risk Engine catches all 8 `RiskPattern` categories against an adversarial fixture set;
    - the TS SDK round-trips `VerificationResult`;
    - a published Release Evaluation Report on a real corpus.
  - **Phase 1.5:**
    - Go SDK and CLI parity;
    - a SAK end-to-end demo;
    - the Python layer proven process-separate.
  - **Phase 2:**
    - a signed community registry with an independence check;
    - 2 or more third-party plugins in production;
    - 4 profiles in use by a real integration each;
    - a corpus of at least 1,000 real fixtures;
    - a dashboard over live state.
  - **Phase 3:**
    - baselines of at least 20 samples for every Tier 3+ protocol;
    - automated upgrade detection within 1 hour;
    - one real self-healing quarantine;
    - a load test at a 10k-fixture corpus.
  - **Phase 4:** ISL, Finalis and FlowForge, all gated on external convergence and not in scope.
- **Repository ROADMAP "Phase 3 — what gates it"** open items:
  - an independent audit (owner);
  - branch protection (owner);
  - manifest coverage for programs with no IDL;
  - the `content_hash` rename;
  - a persisted archive index;
  - mainnet deployment.

## 5. Audit checklist (one row per component; each audit area ticks its rows in `01-findings.md`)

Legend for every row: reviewed end to end · existing tests run · new tests for untested paths · stubs/mocks/hardcoded data in production paths · TODO/FIXME · swallowed errors · RPC failure/timeouts · races · unvalidated input · AI influence on a verdict · adversarial inputs.

- [ ] A1 Wire parser and identity (`tx_artifact.rs`, L2 in `verification.rs`, ALTs, durable nonce, v1)
- [ ] A2 Simulation and state (`simulation_integrity.rs`, `state_diff.rs`, L3/L4, Token-2022)
- [ ] A3 Manifests, resolution, semantic and risk (`manifest*.rs`, `account_resolution.rs`, `risk_engine.rs`, `tx_pattern_analysis.rs`, `protocols/*.json`, L1/L5/L7)
- [ ] A4 Confidence, policy, unknown-protocol ceiling, plugins (`confidence_engine.rs`, `policy_engine.rs`, `plugin_orchestrator.rs`, `plugins/`)
- [ ] A5 RPC integration and failure modes (`rpc_client.rs`, witness RPC, L8 chain reads)
- [ ] A6 HTTP/API surface, auth, limits, audit trail (`server.rs`, `durable.rs`, `/admin/*`, `/api/*`)
- [ ] A7 AI-assist boundary and consumers (`python-ai-layer/`, `sdk/typescript`, `sdk/go`, `integrations/solana-agent-kit`, `dashboard/`)
- [ ] A8 CI, supply chain, container, deploy (`ci.yml`, `Dockerfile`, `docker-compose.yml`, lockfiles)
- [ ] A9 Docs and DX (every `.md`, badges, counts, CLI help against the docs)
- [ ] A10 Performance and reliability (request-path cost, load shedding, rotation, restart, disk-full)
