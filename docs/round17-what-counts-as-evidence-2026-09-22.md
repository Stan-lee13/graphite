# Round 17 — what counts as evidence

> **Historical record.** This report describes the codebase at commit
> `453dd01` on 2026-09-22, and the fixes made on top of `e95857d`. For the
> current state of Graphite see [`CURRENT.md`](CURRENT.md).

**Date:** 2026-09-22
**Trigger:** "fix every single issue mentioned" — every finding of the Round 15
(`round15-earned-by-asking-2026-09-20.md`) and Round 16
(`round16-signed-before-it-was-shown-2026-09-21.md`) forensic re-audits.
**Base:** `af8faca` (the Round 16 report commit; code identical to `e95857d`
and `21c0a7b`).
**Method:** each finding fixed at the line the audit named, each with a
regression test that fails on the audited code; the full Rust matrix CI runs
(all-features, featureless library, cli-only), clippy `-D warnings`, fmt, the
bridge, TS SDK and Go SDK suites, and the console build were run locally; the
remediated Core was then live-probed on a loopback Core behind the Round 16
mock RPC with the same requests that produced Round 16's measurements. No
public RPC, no wallet, no funds, no key. Internal work; not an independent
certification.

> This file is a dated record. `docs/CURRENT.md` describes the codebase as it
> is now; `SECURITY.md` carries the running list of what was fixed and why.

---

## 1. What changed, by finding

| Finding | Severity (as audited) | Fix | Where | Regression test |
|---|---|---|---|---|
| **F-16-01** pre-signed artifact approved; L8 unjoinable | Medium | Any non-zero signature slot is a 400 at `/verify`; `scope.transaction_sha256` is the digest of the unsigned frame; L8 answers `RecordedForDifferentBytes` when the chain digest resolves nothing but the caller cites an `audit_trail_id` for other bytes — a discrepancy when that verdict was a refusal | `tx_artifact::filled_signature_slots`; `verification.rs` input validation, `verification_scope`, `audit_execution`; `cli.rs` rendering | `round17_remediations::a_presigned_artifact_is_refused_at_verify`, `::a_cited_verdict_about_other_bytes_is_reported_and_a_cited_refusal_alarms` |
| **F-16-11** L8 last-wins attribution | Low | `recorded_verdicts {approved, refused}` for the chain digest on every L8 answer (`AuditLog::count_verifications`) | `durable.rs`, `verification.rs`, `server.rs` | `::l8_reports_every_verdict_recorded_for_the_chain_digest` |
| **F-16-03** refused requests train the baseline; **F-15-02** errored simulations are evidence; **F-15-01** identical requests pump confidence | Medium / P2 / P2 | `rpc_sim_ok` requires `err == null`; recording moved after the verdict, gated on no structural failure and risk Clear; every observation keyed on the artifact digest (`record_simulation_keyed`) so the same bytes are one observation | `verification.rs`, `semantic_graph_store.rs`, `simulation_integrity::ComputeBaseline.recent_observation_keys` | `::an_l2_refused_request_does_not_grow_the_baseline`, `::an_errored_simulation_is_not_evidence_and_is_named`, `::identical_approved_bytes_are_one_observation`, `::the_same_request_is_not_approved_on_the_second_call` |
| **F-16-04** failed simulation folded into `no_state_diff` | Low | `UnobservedCode::SimulationFailed` (15th code, mirrored in TS types, Go constants, schema, bridge policy list); L3 reports "Simulation FAILED", never "clean" | `verification.rs`, `sdk/typescript/src/types.ts`, `sdk/go/graphite.go`, `schemas/verification-result-v1.json` | `::an_errored_simulation_is_not_evidence_and_is_named` |
| **F-16-02** ten identical samples freeze the baseline | Medium | Variance floor: spread = max(measured, 25% of centre, 1.0) on the mean/std and robust paths; shadow accumulator for flagged-but-clean executions (same identity rule); `/health.frozen_baselines` + `degraded_reasons: simulation_baseline_frozen`; `graphite evidence promote-shadow` | `simulation_integrity.rs`, `semantic_graph_store.rs`, `server.rs`, `cli.rs`, `bin/graphite.rs` | `::ten_identical_samples_do_not_refuse_the_eleventh_at_plus_one_cu`, `simulation_integrity::tests::test_zero_variance_baseline_is_a_band_not_a_point` |
| **F-15-05** approval not conditioned on ALT resolution | P2 design | Unresolved primary positions fail L2; `SiblingCoverage.unresolved_positions` fails L2; deactivating tables still refused, by name | `verification.rs`, `tx_artifact.rs` | existing `tests/alt_*.rs` (all green under the stricter rule) |
| **F-15-03** empty label switches Check 10 off | P2 partial | Manifest risk metadata keyed on `effective_discriminator` | `verification.rs` | `tests/mislabelled_discriminator.rs`, `tests/truncated_discriminator.rs` (green) |
| **F-16-05** CPI targets declared, not measured | Low–Medium | `SimulationResult.inner_program_indexes` from `innerInstructions[*].programIdIndex`, mapped through static keys + loaded addresses, fed to `assess_with_warnings` like a declaration; undeclared observed targets named in the warnings | `rpc_client.rs`, `verification.rs` | `::an_observed_cpi_target_the_caller_omitted_is_judged_like_a_declared_one` |
| **F-16-06 / F-15-08** PDA templates fall back silently | Low | Closed grammar; resolver returns `Result`; `validate_seed_template` at manifest load AND registry submission (indexes vs declared slots, ranges vs 32 bytes); a well-formed template this request cannot satisfy flags the slot (`unresolvable_seed_templates`) and refuses | `account_resolution.rs`, `manifest.rs`, `manifest_registry.rs` | `manifest::tests::test_unsupported_seed_templates_are_refused_at_load` |
| **F-16-14** mismatches collected by address | Info | By slot | `account_resolution.rs` | covered by the identity suites |
| **F-16-07** Risk plugin panic loses its block | Low | Risk / Verifier / Policy panic → `Block { "<name>:panicked" }`; Simulation keeps the Note; `GRAPHITE_PLUGINS_DIR` load failure is a startup error | `plugin_orchestrator.rs`, `server.rs` | `plugin_orchestrator::tests::test_panicking_blocking_plugin_fails_closed`, `plugin_framework::test_panicking_plugin_never_wedges_verification_and_fails_closed` |
| **F-16-08** `min_confidence > 1` is a 500; **F-15-07** one-axis clamp | Low / P3 | `enforce_wallet_profile` returns `Err` (400) before the pipeline; `WEAKEST_BUILTIN_MIN_TRUST_TIER` clamps the tier axis with disclosure | `server.rs`, `policy_engine.rs` | `server::tests::min_confidence_above_one_is_refused_up_front`, `::unknown_tier_floor_is_raised_to_the_weakest_builtin` |
| **F-16-15** non-finite rate limit | Info | `GRAPHITE_RATE_LIMIT` must be finite and > 0 | `server.rs` | startup validation |
| **F-16-09** unframed `content_hash` | Low | Domain tag + u32 LE length prefixes + list counts, in Rust, TS SDK, SAK AuditBind and Go; vectors re-pinned (`48c65c638aceb5de`, `dd8569c46af7e6c0`, `6d302e018b2b91ce`) in all four suites and the sample result | `verification.rs`, `sdk/typescript/src/auditbind.ts`, `integrations/solana-agent-kit/auditbind.ts`, `sdk/go/auditbind.go` | `verification::tests::test_content_hash_is_injective_across_field_boundaries` + the four pinned-vector suites |
| **F-16-10** console renders manifest URLs unchecked | Low | http(s) only at manifest load, at registry submission, and at render (`httpUrl()`) | `manifest.rs`, `manifest_registry.rs`, `dashboard/src/views/ProgramsView.tsx` | `manifest::tests::test_manifest_url_fields_must_be_http` |
| **F-15-09** lifecycle across a rotation | P3 | Newest archive merged whenever the active file rotated within `ROTATION_STRADDLE_WINDOW` (10 min) | `durable.rs` | existing lifecycle suites |
| **F-16-12 / F-15-06** demo without residual policy; permissive profile | Low | `devnet-test.ts` executes through `executeBoundTransaction` with `ResidualPolicy.fromEnv()` under Gaming; Go package doc includes the residual check | `integrations/solana-agent-kit/devnet-test.ts`, `sdk/go/graphite.go` | bridge typecheck; the demo is live-only |
| **F-16-13** CI without `--locked`; **F-16-16** Go version | Info | `--locked` on every cargo step; `go.mod` → 1.22 | `.github/workflows/ci.yml`, `sdk/go/go.mod` | CI |

Wire-visible changes: `unobserved_codes` gains `simulation_failed`; `/verify`
refuses filled signature slots (400) and `min_confidence > 1` (400);
`/verify/execution` gains `recorded_verdicts` and the
`RecordedForDifferentBytes` reconciliation; `/health` gains
`frozen_baselines`; `content_hash` values change encoding (a trail written
before this round will not match new hashes — the coarsest L8 key resolves
nothing across the upgrade, and says so). The bridge's `ResidualPolicy`
already refuses unknown codes, so an older bridge against a newer Core
refuses `simulation_failed` verdicts — the right direction.

---

## 2. Design decisions worth recording

**Eligibility, not approval.** The first cut gated baseline recording on
`approved`. That recreated the dead bootstrap Round 2026-09-05 fixed: a
manifested program with no history scores 0.44, below every built-in floor,
so nothing would ever be approved and nothing would ever be recorded. The
rule is *sound and risk-clear*: no structural layer failed, the Risk Engine
found nothing, the simulation completed without error. A policy-threshold
refusal alone still trains — and F-15-01 is closed by identity, not by
eligibility: the same bytes re-verified are one observation, so the identical
refused request cannot become approved by repetition. Measured (§4): three
identical honest calls stayed at 1 sample and 0.507; four distinct
transactions of the same instruction earned 0.573, 0.64, 0.64.

**A band, not a point.** The zero-variance rule was itself a fix (a uniform
history used to skip the check). Keeping the check and flooring the spread at
25% of the centre keeps that fix — a doubling still flags — while a program
whose first ten observations happened to be identical no longer refuses every
other shape it has. The floor is a judgement; the report that named the
finding asked for one. Flagged-but-clean executions are kept where an operator
can see them and promote them.

**Unresolvable-for-this-request templates flag, they do not error.** A
template outside the grammar is refused at load and can never reach the
runtime; a well-formed template the request cannot satisfy (a descriptive
request with no `instruction_data` against `{instruction_data:8:16}`) flags
the slot as an identity mismatch and the verdict refuses. A 400 would have
been an explicit rejection too, but it would have hidden every other layer's
answer about the same request; the first cut did that and
`test_all_protocols_verifiable` said so.

**Deactivating tables stay refused.** F-15-05 noted the runtime honours a
deactivating table for ~512 more slots. A verdict about identities read from
a table being retired is true for minutes; refusing is the conservative side,
and the refusal now names the discrepancy instead of reading as a parse
failure.

**Blocking plugins fail closed; report-only plugins do not.** A Policy
plugin's Block is a veto, so it joins Risk and Verifier in the fail-closed
set. Simulation-family verdicts never blocked, so a crashing one becomes a
note rather than wedging traffic.

---

## 3. Tests

| Suite | Result |
|---|---|
| Rust, all features (`cargo test --all-features`) | **1,549 passed, 0 failed** (11 network-gated ignored) |
| Rust, featureless library (`--no-default-features --lib`) | **319 passed** |
| Rust, cli-only (`--no-default-features --features cli`) | **1,353 passed** |
| `cargo clippy --all-targets --all-features -- -D warnings`, `cargo fmt --check` | clean |
| `cargo check --no-default-features`, `--features cli` | clean |
| SAK bridge (`npm test`, `npm run typecheck`) | **100 passed** |
| TS SDK (`npm test`, `npm run check`) | 13 passed, 4 live-server tests skipped locally (run in CI's container job) |
| Go SDK (`gofmt`, `go vet`, `go test`) | passed |
| Console (`npm run typecheck`, `npm run build`) | clean |
| Python (`pytest`) | 26 passed; `test_performance_smoke` fails on this machine at 7,589 parses/s against a 10,000 threshold **before and after** this round (verified on the stashed tree) — a wall-clock assertion on a loaded workstation, not a change here |

New this round: `tests/round17_remediations.rs` (9 end-to-end tests on a
controllable mock cluster: simulation `err`, compute units, inner-instruction
program indexes, chain bytes per signature) and unit tests in `manifest.rs`
(URL scheme; template grammar — 8 accepted, 13 refused forms),
`simulation_integrity.rs` (band), `verification.rs` (content-hash injectivity
across three boundaries plus the second cross-language vector), `server.rs`
(profile above 1.0; tier axis), `plugin_orchestrator.rs` (fail-closed panic,
advisory note).

Tests changed because they encoded the old semantics — earning a baseline by
verifying ONE transaction repeatedly, or handing the Core an unparseable blob
to switch the simulation path on: `round9_identity_requires_data.rs`,
`round10_attribution.rs` (warm-up now uses distinct blockhashes),
`evading_the_fixes.rs`, `rpc_trust_boundary.rs`, `rpc_influence_bounds.rs`
(a real corpus artifact, distinct per call), `plugin_framework.rs` (panic now
fails closed), `mainnet_conformance.rs` (chain bytes replayed with slots
zeroed, as the bridge would have presented them). Every one of those changes
is the test catching up with the invariant it now protects; none weakened an
assertion.

---

## 4. Live probe (loopback Core, debug build of this tree, mock RPC)

Same harness as Round 16 (`mock_rpc.py`, `txlib.py`), fresh data dir.

| Probe | Round 16 measured | Round 17 measured |
|---|---|---|
| Pre-signed artifact at `/verify` | 200, approved, `artifact_bound`, raw-bytes digest | **400** "carries 1 non-zero signature slot(s)" |
| Three L2-refused requests (wrong label) | baseline "3 of 10" | baseline unchanged (1, from the one honest call) |
| Same honest bytes ×3 | +1 sample each; refused→approved on the 2nd | 1 sample, confidence 0.507 all three, refused all three |
| Four distinct transactions of the same instruction | — | samples 1→2→3→4; confidence 0.507, 0.573, 0.64, 0.64; approved from the second |
| Simulation `err: InstructionError` | approved, `no_state_diff`, L3 "clean (RPC-verified)", sample recorded | approved with **`simulation_failed`**, L3 "Simulation FAILED …", **not recorded** |
| `min_confidence: 2.0` | 500 `PolicyEvaluation` | **400** `InvalidInput` |
| Uniform 450 CU history, then 451 / 460 / 600 / 150 / 1200 CU | 451, 460, 600, 150 all Blocked `SimulationSpoofing` | 451, 460, 600 **clean and approved**; 150 (−67%) and 1200 (+167%) flagged |
| `/health` | — | `frozen_baselines: []` with 2 shadow observations (< `MIN_SAMPLES`); `evidence promote-shadow` refuses with "2 observation(s); at least 10 are needed" |
| Y executed, L8 cites X's REFUSED `audit_trail_id` | `NoVerificationOnRecord`, `discrepancy: false` | **`RecordedForDifferentBytes { recorded_approved: false }`, `discrepancy: true`** |
| Y executed, L8 cites X's APPROVED id | `NoVerificationOnRecord` | `RecordedForDifferentBytes { recorded_approved: true }`, `discrepancy: false` |
| X executed (refused once under Treasury, approved once under Gaming), no keys | `ApprovedAndExecuted` | `ApprovedAndExecuted`, **`recorded_verdicts: {approved: 1, refused: 1}`** |

---

## 5. What is still open, and what this round did not do

- The Python `test_performance_smoke` threshold is machine-dependent
  (pre-existing); left as is.
- The baseline is still keyed per program while compute is per transaction
  (`SECURITY.md` "Known Limitations", 2026-09-08). The band makes a narrow
  history tolerant of nearby shapes; it does not make a per-program baseline a
  per-instruction one, and re-keying is still the evasion-prone change it was.
- `inner_instructions` remains an inherent residual. Observed callees are now
  judged; what those calls do inside is not, and the prose says so.
- Version-1 transactions: unchanged (refused by name).
- Independent audit: not performed. Everything here was written and tested by
  the same party that wrote the findings.

---

## Appendix — probe scripts

`p17_live.py` (pre-signed, eligibility, identity, errored simulation, profile
edge), `p17_freeze.py` (band and shadow), `p17_l8.py` (different-bytes
attribution, verdict counts), against `mock_rpc.py` on `127.0.0.1:7660` and a
dev-mode Core on `127.0.0.1:7661`, in the session scratchpad.
