# AUDIT 02 — Roadmap gap: what the roadmap asks for vs. what the code does (2026-09-30)

This compares the goals in the engineering-skill repository (ROADMAP phase exit criteria, FEATURES rows, CONSTITUTION checks, TESTING, BENCHMARK) and this repository's own `ROADMAP.md` and `docs/CURRENT.md` against the code at `3327fcf`. It then records what this round implemented. The full evidence table from the audit is in `graphite-audit-work/a6/roadmap_gap.md`, outside the repository.

Legend:
- **NOW:** implementable in this repository with tests.
- **OWNER:** needs an owner decision.
- **SPEND:** needs money or infrastructure.
- **EXT:** needs an outside party.

## Implemented and verified (before this round)

The 8-layer pipeline, account and PDA resolution with provenance, the confidence engine with tier ceilings, and deterministic verdicts (P2) are in place. So are:
- the risk engine patterns and trust tiers computed rather than asserted (P7);
- the append-only semantic graph (P4) and a durable audit trail with lifecycle rows (P9);
- the policy presets and the plugin framework (P8);
- the regression engine with the P10 promotion gate, and signed manifest submissions;
- simulation integrity (robust baselines and a shadow accumulator);
- the runtime oracle (never looser than agave);
- v1 messages, Token-2022 fees and hooks;
- both SDKs, the CLI, the advisory Python layer, the dashboard and the SAK bridge.

Each has named tests; see the audit table.

## Closed or advanced this round

| # | Goal | Status now | Proof |
|---|---|---|---|
| A6-01 | The SDK↔server wire gate must fail when its tests fail | **Done.** pipefail plus a TAP summary assertion | CI container job |
| R-P4 / A6-02 | Go SDK live conformance; whole-response schema validation | **Done.** Go `liveserver` tests run in CI; real results are validated against the schema in both directions | `tests/verification_result_schema_contract.rs`, CI |
| R-P5 | P1 separation of the AI layer "verified, not asserted" | **Done.** A mechanical scan of `src/` and `Cargo.toml` | `tests/ai_layer_isolation.rs` |
| R-P13 | Every public number linked to its source (P16) | **Done** for mutation, risk-check, residual-code and dashboard-view counts, alongside the existing manifest counts | `tests/docs_numbers_match_the_code.rs`, `tests/docs_match_the_registry.rs` |
| A6-04 / R-M3 (part) | Corpus drift check | **Done.** CI fails if the test run changes `fixtures/corpus` | CI rust job |
| A6-05 | Supply-chain coverage | **Done.** cargo-audit on both lockfiles, an npm advisory gate on all three npm lockfiles, Dependabot, `--ignore-scripts`, `persist-credentials: false`, job timeouts | CI; `.github/npm-audit/` |
| — | Scalability of the request path | **Advanced.** Audit-trail appends (each ending in a disk flush) run on the blocking pool, and the three dashboard scans do too. There is a connection cap (`GRAPHITE_MAX_CONNECTIONS`) and a header-read timeout against slow-loris | `tests/audit_a4_*`, `server.rs` |
| — | A strict container healthcheck | **Done.** `graphite healthcheck --strict` | `cli::tests::strict_healthcheck_fails_a_degraded_node` |

## Still partial (what is missing)

| # | Goal | What is missing | Class |
|---|---|---|---|
| R-P1 | A current release-evaluation report (P16) | `graphite benchmark --json` and a generated, test-pinned report for v0.2.0 | NOW |
| R-P2 / R-P3 / A6-35 | Reproducible mainnet numbers; ≥1,000 real regression fixtures | A committed, fixed mainnet subset (~2–3 MB), gated in CI without `#[ignore]`, recorded as real fixtures. Today the samples are gitignored and the published numbers name their sample dates | NOW |
| R-P6 | Community submissions with reviewer independence (G5) | A PR-based workflow and the independence design | NOW (CI part) / OWNER |
| R-P7 | `sample_count ≥ 20` for every tier-3+ protocol | Real accumulated baselines from a running deployment | SPEND |
| R-P8 | Building v1 transactions in the bridge | Migrating the bridge's transaction path to `@solana/kit` (8.x builds legacy, v0 and v1), byte-for-byte on legacy and v0 against the cross-language corpus, then v1. The last gated npm advisory (`bigint-buffer`) does NOT go with it: it arrives through the `solana-agent-kit` package's `@solana/spl-token` 0.4, so it goes when the bridge drops that dependency (see `01-findings.md`, A6-05) | NOW. **Phase 1 done (2026-10-02):** `BoundTransaction` compiles and signs through `@solana/kit` 8.4.0; legacy bytes are identical to web3.js's, v0 is the same transaction with accounts sorted within each privilege class (`kit-artifact.test.ts` against the old web3.js path); the transaction is an ES private field, signing is async and happens once; the cross-language corpus carries a v0 entry compiled by the bridge itself in kit's order, read by the Rust Core. **Phase 2 done (2026-10-02):** the bridge builds v1 (`transactionVersion: 1`); both v1 limits are measured by an unsigned v1 simulation before the verified message is built; ComputeBudget instructions and lookup tables are refused in v1; `messageOf` and the empty-slot check read v1's trailing signatures by a port of the Core's `parse_v1`; the transaction id is read from the signed bytes, not the RPC's answer; two bridge-built v1 shapes in the corpus. Phase 3 (the `solana-agent-kit` dependency) and phase 4 (tools) open |
| R-P10 | Self-healing automatic quarantine | An operator-flagged threshold with an audit row; the plumbing exists | OWNER |
| R-P11 / R-P12 / R-P15 | Mutation testing, coverage-guided fuzzing, coverage floors | Scheduled non-gating workflows (`cargo mutants`, `cargo fuzz`, `cargo llvm-cov`). Coverage tooling was not installed on the build machine by the owner's choice, so Rust coverage is unmeasured | NOW / OWNER |
| R-P14 | P9: a lifecycle transition without an audit emission fails the build | An exhaustive `match` over `LifecycleEvent` for emissions | NOW |
| R-P16 / R-P17 | Manifest coverage of IDL-less traffic; five manifests below the decode bar | Protocol teams' data, or reverse engineering with RPC data | EXT |
| R-P18 | Second-source inclusion proof for L8 | A light-client proof | EXT |
| A2-08 | L3 baselines per instruction, not per program | Keying compute baselines by (program, instruction) and by the transaction's composition | NOW |

## Missing

| # | Goal | Recommendation | Class |
|---|---|---|---|
| R-M1 | Protocol upgrade detection (a ProgramData slot watch) | Read the loader's ProgramData `slot`, persist `last_deploy_slot` per manifested program, and add an audit row, a `/health` entry and a metric. Quarantine only behind an operator flag | NOW |
| R-M2 | P13 schema and version gate between releases | A snapshot of the result's field set plus the schema; a change requires a version bump and a CHANGELOG entry. The whole-response contract test added this round is the first half | NOW |
| R-M4 | Independent third-party audit | — | OWNER + SPEND + EXT |
| R-M5 | Branch protection on `main` | Until then every CI gate is advisory | OWNER |
| R-M6 | Mainnet deployment, TLS, DNS, monitoring | — | OWNER + SPEND |
| R-M7 / R-M8 | Third-party plugins; GOAT/ElizaOS; LLM advisory parsing | — | EXT / OWNER |
| R-M9 | Constitution P12 ("never fails closed on the unknown") vs. the drainer heuristic refusing unmanifested multi-account calls | A deliberate, documented divergence. Amend the Constitution or add a graceful path; do not change it silently | OWNER |
| R-M10 | Rename `content_hash` to say it is instruction-level | A serde alias for one version, across Rust, TypeScript, Go and SAK | NOW (API change) |
| R-M11 | Persisted archive index (scalability of L8 lookups into rotated archives) | `<archive>.idx` written at rotation, verified on use, rebuilt when invalid | NOW, planned for the next round |
| R-M12 | A shared rate limiter for horizontal scale | A shared store such as Redis | OWNER + SPEND |
| R-M13 | Owner configuration vs. protocol administration (2026-10-01) | The IDL onboarding tags every `set_*`/`update*`/`change*`/`configure*` instruction `authority`, and since F3 that blocks under any intent, so an owner configuring its own object (Magic Eden MMM `updatePool`, a marketplace's `update_offer`) is refused like protocol administration. Measured: 9 newly refused of 48,855 executed mainnet transactions. Classify by the IDL's signer account and the configured object's owner field, grounded in each program's traffic, into a class that needs a declared intent | NOW |

## Order of work after this round

1. **Supply chain.** Cut the SAK bridge's npm advisories where it is in our control:
   - stop loading the plugin trees the bridge does not use;
   - force patched transitive versions where they exist;
   - re-audit, and shrink the allowlist.
2. **The `@solana/kit` migration (R-P8)**, and the persisted archive index (R-M11).
3. **Real-traffic reproducibility.** The committed mainnet subset gated in CI, with real regression fixtures (R-P2, R-P3), and the release-evaluation report (R-P1).
4. **Detection breadth.** Protocol upgrade detection (R-M1) and per-instruction L3 baselines (A2-08).
5. **Continuous assurance.** Scheduled mutation, fuzz and coverage workflows (R-P11, R-P12, R-P15); the P9 emission lint (R-P14); and the P13 version gate (R-M2).
