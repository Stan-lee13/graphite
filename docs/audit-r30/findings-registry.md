# Round 30 findings registry

Every finding of the Round 30 forensic audit (2026-10-21/22) against `29e4356`, with its
status at the end of the round. Round 30 is internal engineering work, not an independent
audit. The round report is
[round30-forensic-audit-and-remediation-2026-10-22.md](../round30-forensic-audit-and-remediation-2026-10-22.md);
the current state is [CURRENT.md](../CURRENT.md).

**IDs.** `R30-<workstream>-<n>` for a finding a workstream reproduced and fixed or dispositioned;
`K-nn` for a defect the ledger pass (WS-K) found and handed on (full write-up:
[new-defects.md](new-defects.md)); `G-nn` for the twelve leads the brief named, mapped to the
findings that answer them. Where a K item was fixed under a workstream ID, both are given.

**Severity** follows the brief: P0 stop-ship (unauthorised signing, a false approval from
untrusted input, trust poisoning past a mandatory gate, a forged audit outcome); P1 high
stop-ship; P2 medium; P3 low; Info. **Class** is one of: confirmed vulnerability; functional
bug; design weakness; integration footgun; operational/governance blocker; data/coverage gap;
visual/accessibility; documentation/claim mismatch; suspected/unconfirmed.

**Status**: *fixed* (in code, with a regression test that fails on the old behaviour — the
"break" column names the deliberate revert that showed it); *fixed (docs)*; *open (owner)* —
needs a repository owner, money or an external party; *residual* — narrowed and stated, not
eliminated.

## The twelve leads

| Lead | Disposition at the end of Round 30 | Findings |
|---|---|---|
| G-01 approved without simulation | **Fixed.** Every verdict carries `decision` / `executable`; only `executable_approved` permits signing; the SDKs, the guard and the dashboard recompute it and require agreement | R30-A-1, A-2, H-1, I-1 |
| G-02 learning opt-in lets a verify key raise confidence | **Fixed, and wider than the lead.** The opt-in is retired (setting it refuses startup), and a second path — a request-named permissive profile — is closed: evidence counts only at the built-in floor | R30-B-1 |
| G-03 program-level baselines | **Fixed (residual stated).** Per-shape baselines, fixed anchors at maturity, versioned snapshot migration | R30-B-2 |
| G-04 upgrades keep evidence | **Fixed (residual stated).** An upgrade withdraws the program's evidence; first sighting checks the deployment slot | R30-B-3 |
| G-05 manifest coverage | **Revalidated; residual.** Counts recomputed (137 / 3,541 / 46 unclassed); the 13 low-decode manifests refuse their undescribed instructions under every built-in profile; no manifest data invented | R30-F-3, F-6, the G-05 row below |
| G-06 whole operation classes refused | **Fixed for 21 grounded instructions** (withdraw, claim, close, burn, configure); the rest stays refused | R30-G-1, G-2, G-3 |
| G-07 audit trail not tamper-evident | **Fixed when keyed** (hash chain + HMAC, verify, checkpoint, anchor directory); unkeyed stays corruption-evident; truncation and stale restore need an anchored checkpoint | R30-C-1, C-2, C-3 |
| G-08 single-provider L8 | **Narrowed.** `inclusion_assurance` on every reconciliation, provider-independence checks, a high-assurance mode; no light-client proof | R30-D-1 |
| G-09 release evaluation | <!-- WS-E --> Pending the WS-E merge. | — |
| G-10 fuzzing / mutation / coverage | <!-- WS-E --> Pending the WS-E merge. | — |
| G-11 branch protection | **Open (owner, STOP-SHIP).** Rulesets, CODEOWNERS and the `CI gate` job are prepared; nothing is enforced until an owner applies them | R30-J-2 |
| G-12 operations and external items | **Open (owner/external)** — the owner gate in the round report | — |

## Findings

### Execution decision and API contract (WS-A)

| ID | Sev | Class | Location | Finding | Status | Regression test | Break | Residual / owner |
|---|---|---|---|---|---|---|---|---|
| R30-A-1 | P1 | design weakness / integration footgun | `verification.rs` result construction; every SDK | `approved: true` was returned for bytes nothing had simulated (no RPC) or for no bytes at all, and a client gating on `approved` would sign it | fixed | `tests/round30_execution_decision.rs`, `tests/round30_decision_fixtures.rs`, `sdk/typescript/src/execution-decision.test.ts`, Go `TestAnAnalysisOnlyApprovalEditedIntoPermissionIsRefused` | B1 (rule without the `simulated` / inherent-code checks: 6 of 8 failed), B2 (TS), B3 (Go) | `approved` kept for compatibility, documented as not permission to sign |
| R30-A-2 | P2 | documentation/claim mismatch | `cli.rs` verify/explain | `graphite verify && sign` saw exit 0 on an unsimulated approval | fixed: exit 0 only for `executable_approved`, 1 refusal, 3 `analysis_only` | `round30_execution_decision.rs` | the mapping itself was not broken on its own | — |
| R30-A-3 | P3 | documentation/claim mismatch | `transaction_builder.rs` | `build_transaction` / `BuiltTransaction` implied wire-byte construction; it is a summary | fixed: `InstructionPlan` / `InstructionSummary` / `summarize_instruction`, deprecated aliases; `compute_units_estimate` | existing suites | — | wire field name `compute_budget_units` kept |
| R30-A-4 | P3 | design weakness | `GraphiteCore::with_data_dir` | panics on a bad data directory | fixed: deprecated; no server or CLI path uses it | — | — | — |
| R30-A-5 | P3 | documentation/claim mismatch | `content_hash` (R-M10) | the name read as the transaction's identity | fixed: `instruction_bind_key` added, `content_hash` deprecated | schema contract test | — | lifecycle request bodies keep the `content_hash` wire name |
| R30-A-6 / K-03 | P3 | availability | `sdk/typescript/src/client.ts` | the TS client read bodies with no size bound | fixed: `readJsonBounded` (16 MiB / 64 KiB) | "K-03: a body over the bound is refused" | B4 | — |

### Trust learning, baselines, upgrades (WS-B)

| ID | Sev | Class | Location | Finding | Status | Regression test | Break | Residual / owner |
|---|---|---|---|---|---|---|---|---|
| R30-B-1 | P1 | confirmed vulnerability | observation path, `verification.rs` | beyond the opt-in, a verdict approved under a profile the request named (`Custom{0.40}` in the library or CLI, or on a server with `GRAPHITE_ALLOW_PERMISSIVE_PROFILES`) trained evidence for every caller: three self-approved transfers took a fresh program from 0.44 to 0.64 | fixed: `ObservationPolicy::BuiltinFloor`; the opt-in variable refuses startup | `tests/round30_trust_learning.rs` (`a_verify_key_holder_cannot_raise_a_programs_evidence`, `concurrent_self_approvals_teach_nothing`) | one build with eight reversions: all 11 targeted tests failed | a program no built-in profile admits learns nothing from traffic and needs operator seeding |
| R30-B-2 | P2 | design weakness | `simulation_integrity.rs`, `semantic_graph_store.rs` | one baseline per program; adaptive bands with no fixed bound (a drip reached 153,409 CU past a 150,000 first band) | fixed: shape baselines, `BaselineAnchor`, schema-versioned snapshot | `a_slow_drip_cannot_walk_an_anchored_baseline` and five more | in the eight reversions | false-positive impact on real RPC traffic not measured |
| R30-B-3 | P2 | design weakness | `retire_program_evidence` | an upgrade kept earned and operator evidence; first sighting was the baseline | fixed | `an_upgrade_withdraws_the_programs_evidence`, `a_deployment_newer_than_the_evidence_at_first_sighting_withdraws_it`, `a_simulation_of_replaced_code_is_not_recorded` | in the eight reversions | after an upgrade the program sits near 0.44 until re-seeded (de facto quarantine); a lying RPC can reset evidence (availability, inside the RPC trust boundary); loader-v4 untracked |
| R30-B-4 | Info | covered by test | refusal classes | no table proved every refusal class trains nothing | covered | `no_refusal_class_trains_any_accumulator` | — | — |
| K-13 | Info | hardening | `policy_engine.rs` | a NaN confidence passed the threshold comparison (unreachable) | fixed | `a_nan_on_either_side_of_the_threshold_refuses` | in the eight reversions | — |
| K-16 | P3 | documentation/claim mismatch | `confidence_engine.rs` header | "reference implementation", a nonexistent log, a "signature-verified" tier | fixed (docs in code) | — | — | — |

### Audit trail (WS-C)

| ID | Sev | Class | Location | Finding | Status | Regression test | Break | Residual / owner |
|---|---|---|---|---|---|---|---|---|
| R30-C-1 | P1 | design weakness | `durable.rs`, `durable/chain.rs` | anyone able to write the data directory could rewrite the trail coherently | fixed when keyed: a chain link per record, HMAC-SHA256 under `GRAPHITE_AUDIT_KEY_FILE`; an open refuses a tampered head or a keyed trail without a key | `durable/chain_trail_tests.rs` (15), `tests/round30_audit_chain.rs` (3) | B1 (any MAC accepted), B3, B4 caught | unkeyed: corruption-evident only; truncation and stale restore need an anchored checkpoint |
| R30-C-2 | P2 | operational gap | CLI, server | no way to verify or anchor the trail | fixed: `graphite audit verify`, `graphite audit checkpoint`, `GRAPHITE_AUDIT_ANCHOR_DIR`, `/health` and `/metrics` fields | as above | — | immutability of the anchor storage is the operator's |
| R30-C-3 | P2 | concurrency bug | `AuditLog` | nothing stopped a second process writing the same trail | fixed: exclusive `.audit.jsonl.lock`; `open_read_only` for `graphite execution` | `a_second_writer_is_refused…` | B2 | — |
| R30-C-4 | P3 | claim mismatch | `persist_json_atomic` | no directory sync after the rename | fixed by inspection | — | needs power-loss injection | — |
| R30-C-5 / K-12 | P3 | test quality | `durable.rs` rotation-failure test | passed vacuously as root | fixed: `FAULT_ROTATE_RENAME` seam | `rotation_failure_is_counted_and_never_drops_a_record` | B5 | ignored live tests still pass vacuously without network when forced |

### RPC, L8 and the server surface (WS-D)

| ID | Sev | Class | Location | Finding | Status | Regression test | Break | Residual / owner |
|---|---|---|---|---|---|---|---|---|
| R30-D-1 | P2 | design weakness | `verification.rs` `audit_execution`, `same_endpoint`; server startup | L8 did not say what its answer rested on; the same provider under a second API key counted as an independent witness | fixed: `inclusion_assurance`, URL and DNS independence, `GRAPHITE_L8_HIGH_ASSURANCE` | `tests/round30_l8_assurance.rs` (11), `route_surface::high_assurance_needs_an_independent_attested_https_witness` | gate off; same-host rule off | no light-client proof; independence is a heuristic plus operator attestation; behind an HTTPS proxy the resolver sees only the proxy |
| R30-D-2 | P3 | design weakness | `rpc_client::validate_endpoint` | cloud-metadata and unroutable addresses not refused | fixed, plus a `GuardedResolver` at connect time | `metadata_link_local_and_unroutable_hosts_are_refused`, `a_name_is_judged_when_it_resolves` | range check skipped; resolver filter removed | private ranges allowed and logged |
| R30-D-3 | P3 | defence in depth | server auth | auth followed the raw path and the first header | fixed: the matched route, exactly one `Authorization`, two `Host` headers → 421 in dev mode | `tests/round30_server_wire.rs`, `two_authorization_headers_are_refused`, `dev_mode_refuses_two_host_headers` | both checks removed | — |
| R30-D-4 / K-11 | P3 | design weakness | server keys; dashboard | the dashboard's key could submit verifications and lifecycle events | fixed: `GRAPHITE_READ_API_KEY` | `each_route_answers_only_to_its_privilege`, `the_read_key_cannot_verify_record_or_act` | read key allowed everywhere | — |

### Detectors, manifests, registry (WS-F)

| ID | Sev | Class | Location | Finding | Status | Regression test | Break | Residual / owner |
|---|---|---|---|---|---|---|---|---|
| R30-F-1 | P1 | confirmed vulnerability | `state_diff.rs` `check_state_diff` | a signer's token debit or lamport loss under a silent or unreadable declaration was at most a warning (5 SOL under "frobnicate the widget" passed L4) | fixed: Critical unless the instruction's class moves value; `graphite:`-prefixed manifest lines refused | `tests/r30_declared_effects.rs` (15), `tests/r30_declared_effects_census.rs` | signer rule off: 6 failed; class ignored: 1; prefix allowed: 1 | **owner decision:** 155 unreadable declarations of value-moving classes (Orca `swapV2`, Phoenix `Swap`, Solend deposits) keep the warning; so does the W19 rule |
| R30-F-2 | Info | non-finding | `DeclaredEffects::parse` | the pre-audit mixed-declaration lead | not a bypass: mixed declarations are judged more strictly — proven by test | `r30_declared_effects` | — | — |
| R30-F-3 | P3 | test-coverage gap | risk engine, registry, manifest validator | nine checks caught by no test or almost none (Check 6b, A3-07 replay, submitted-corpus integrity, empty discriminator, low-reputation attester, `from_json` integrity, program id as a pubkey; Checks 6a and 9 thin) | fixed: isolated tests | `tests/r30_detector_isolation.rs`, `tests/r30_registry_manifest_breaks.rs` | each broken and caught | — |
| R30-F-4 / K-17 | P3 | integrity downgrade | `regression_engine.rs` | an unsealed fixture loaded and was resealed | fixed: an unsealed fixture is a load error | `r30_registry_manifest_breaks` | caught | — |
| R30-F-5 | Info | test gap | `solana_types.rs` | "bump 0 is never tried" had no test | fixed: `first_off_curve_bump`, tested 255 → 1 | — | caught | — |
| R30-F-6 | P3 | test anti-pattern | attack suites | 30 cases claimed "APPROVED with earned evidence" without asserting it | fixed: `assert_approved_with_earned_evidence` | `extreme_adversarial` | 4 caught | 44 cases are blocked only by the policy ceiling; `hell_mode_tests` and `adversarial_tests` still accept any `Err` |
| R30-F-7 | Info | dead code | manifest validator | the 32-byte seed check is unreachable (the grammar refuses first) | pinned by a test | — | — | — |
| G-05 | Info | data/coverage gap | protocols | 13 manifests below 90% decode | revalidated: undescribed instructions refused under all four built-in profiles | `tests/r30_low_decode_manifests.rs` | — | an operator `Custom{min_tier: Unknown}` profile would bypass this; untested |

### Intent classes (WS-G)

| ID | Sev | Class | Location | Finding | Status | Regression test | Break | Residual / owner |
|---|---|---|---|---|---|---|---|---|
| R30-G-1 | P2 | design weakness (R-M14) | `src/intent_grants.rs` | withdrawals, claims, protocol closes and burns were refused under any intent | fixed for 21 named instructions, each grounded on the transaction's own accounts | `tests/round30_grounded_intents.rs` (9), `intent_grants` unit tests (7) | grants off: 7 of 9 failed; facts unchecked: 5 failed | the Core does not judge withdrawal minimum outputs (a direct `/verify` caller's sandwich risk); R-M14's 219 not re-measured |
| R30-G-2 | P3 | design weakness (R-M13) | `intent_grants.rs` | an owner configuring its own object was refused as administration | fixed for CcmRKTuZ `update_offer` | as above | as above | MMM `updatePool` stays refused (no IDL in the repository) |
| R30-G-3 | P3 | test defect | `tests/mainnet_conformance.rs` harness | the harness took a durable-nonce advance as the primary | fixed: inert instructions skipped; pin `3a75d3b2…` → `bda80e69…`, rows 442, 1272 and 1366 attributed, 0 approvals before and after | `mainnet_conformance` | the change switched off reproduces the old pin | — |

### Signing boundary and adapters (WS-H)

| ID | Sev | Class | Location | Finding | Status | Regression test | Break | Residual / owner |
|---|---|---|---|---|---|---|---|---|
| R30-H-1 | P1 | design weakness | `residual-policy.ts` `assertExecutableVerdict`; `execution-lifecycle.ts` | the guard never checked a Core `decision` that contradicted the verdict's own scope | fixed: recomputed; unknown or contradicting decisions refused | `guard-round30.test.ts` (G-01 cases); `residual-policy.test.ts` (the guard's own recomputation, held directly) | all five G-01 tests; the agreement check broken at integration: caught | — |
| R30-H-2 / K-02 | P2 | functional bug | `guard.ts`, `guard-state.ts` | a reworded or repeated transfer could be sent twice after an ambiguous send; state in memory only | fixed: effect-keyed, a `beforeSubmit` record, `RequestInFlight`, durable `GRAPHITE_GUARD_STATE_FILE` | `guard-round30.test.ts` (repeat, state) | text-keyed, memory-only, no claim, early resolve, lock | without a state file a restart forgets; one file per guard process |
| R30-H-3 / K-01 | P2 | integration footgun | `vercel-ai/graphite-tools.ts` | Vercel tools asked a person before anything was resolved | fixed: a `confirm` hook is required, or an explicit `{ confirmation: "request-only" }` | `graphite-tools.test.ts` (K-01) | caught | — |
| R30-H-4 | P2 | design weakness | `artifact.ts`, `residual-policy.ts`, `spend-policy.ts`, `rpc-simulator.ts`, `guard.ts`; `sdk/typescript/src/client.ts` | in-process code could replace the signing path's methods, add accepted codes, share the guard's connection, answer its `fetch`, or read the key bytes | fixed: frozen classes, a private accepted set, `fetch` captured at load (guard and SDK client), a separate connection, a non-extractable WebCrypto key, unknown config keys refused | `guard-round30.test.ts` (escape) | each caught; SDK fetch capture reverted → the escape test failed | code loaded before the guard, or that patches `crypto.subtle`, is out of reach |
| R30-H-5 / K-09 | P3 | integration footgun | `devnet-test.ts` | the demo called `executeBoundTransaction` directly | fixed: through `GraphiteGuard.executeTransfer` with a cap and a confirm hook | source test | — | not run live |
| R30-H-6 | P3 | design weakness | confirmation | no timeout; truthy values confirmed | fixed: `confirmTimeoutMs` (120 s), only `true`, a frozen summary carrying `transactionSha256` | consent tests | caught | — |
| R30-H-7 | P3 | design weakness | lifecycle | an RPC answering a submission with another id was not recorded | fixed: on the trail and in the tool result | anomaly test | caught | — |
| R30-H-8 | Info | capability honesty | `capabilities.ts` | wSOL wrap/unwrap unsupported without a machine-readable refusal | fixed: `GUARD_CAPABILITIES`, `UnsupportedCapability("wrap_sol")` | wSOL test | caught | the swap-output `deliveredAs` path has no end-to-end fixture |
| R-M15 | Info | dependency | agent-guard public API | web3.js 1.x | contained, not migrated: the key never touches web3.js; advisories match the allowlists | npm gate | — | migration is a breaking public-API change |

### Dashboard and AI layer (WS-I)

| ID | Sev | Class | Location | Finding | Status | Regression test | Break | Residual / owner |
|---|---|---|---|---|---|---|---|---|
| R30-I-1 | P2 | UI truthfulness | `dashboard/src/figures.ts` and views | every bound approval drawn green, analysis-only ones included | fixed: green only for `executable_approved` with `executable: true` and bytes | figures tests | 3 failed | — |
| R30-I-2 / K-18 | P3 | UI truthfulness | `dashboard/src/api.ts` | answers cast without a shape check | fixed: `shape.ts` | `shape.test.ts` | caught | — |
| R30-I-3 / K-15 | P3 | UI truthfulness | `usePolling.ts` | the previous Core's data shown after a connection change | fixed: `poll-state.ts` | `poll-state.test.ts` | caught | — |
| R30-I-4 | P3 | UI truthfulness | System view | "not recording" shown while loading | fixed | — | — | — |
| R30-I-5 | P3 | functional bug | CSP | `http://[::1]:*` invalid; `127.0.0.2+` allowed by the transport rule, blocked by the CSP | fixed | transport test | caught | — |
| R30-I-6 | P3 | security headers | `vite.config.ts` | no `frame-ancestors` (a meta CSP cannot carry it) | fixed: `securityHeaders()` | — | — | the serving proxy must send them in production |
| R30-I-7 | P3 | accessibility | every view | axe: contrast, nested-interactive, focus, ARIA | fixed: 0 axe violations on every view, desktop and mobile | browser pass | — | no screen-reader session; Chromium only |
| R30-I-8 | P3 | functional | Programs; manifest polling | top 5 only; 4.6 MB refetched every 30 s | fixed | — | — | — |
| R30-I-AI1 | P3 | advisory label | `python-ai-layer/intent_parser.py` | questions, conditionals, negation, quoted speech, several amounts, non-ASCII digits and bidi characters labelled as actions | fixed: `unknown` with a reason code | pytest | 2 failed | advisory only |
| R30-I-AI2 | P2 | confidentiality | AI layer | a pasted private key or seed phrase was echoed back | fixed: `SECRET_MATERIAL`, redacted | pytest | caught | the guard then refuses with an echo-mismatch error (safe, unhelpful message) |
| R30-I-AI3 | P3 | input validation | AI layer HTTP | a non-string `text` and duplicate keys | fixed: 400s | pytest | caught | — |

### CI, supply chain, container, operations (WS-J)

| ID | Sev | Class | Location | Finding | Status | Regression test | Break | Residual / owner |
|---|---|---|---|---|---|---|---|---|
| R30-J-1 / K-10 | P2 | design weakness | `.github/workflows/ci.yml` | CI could pass with no tests run, a new skip, or a masked pipe | fixed: `shell: bash` (pipefail), `.github/scripts/test-count.sh` floors, `.github/test-allowlists/rust-ignored.txt` | 17 hand-written log cases; real logs | — | not yet run on the hosted runners |
| R30-J-2 | P2 | operational/governance blocker (G-11) | repository settings | `main` unprotected | **open (owner, STOP-SHIP)**: `.github/rulesets/main.json`, `main-review.json`, `release-tags.json`, `.github/CODEOWNERS`, `docs/ops/branch-protection.md`, the `CI gate` job | — | — | an owner must apply the rulesets |
| R30-J-3 | P3 | functional bug | CI concurrency | rapid merges could leave a `main` commit without a finished run | fixed | — | — | — |
| R30-J-4 | P3 | design weakness | `.github/npm-audit/` | allowlist entries never expired | fixed: `review-by` at most 120 days ahead, enforced | `gate.test.mjs` (10) | 1 failed | — |
| R30-J-5 | P3 | functional bug | `docker-compose.yml` | a 10 s stop grace equal to the drain; a non-strict healthcheck | fixed: 30 s, `--strict`; CI checks a real verify, the stop and persistence | container job | — | — |
| R30-J-6 / K-20 | Info | unverified claim | `Cargo.toml` `rust-version` | the MSRV was never built | fixed: measured on 1.89.0; an `msrv` job | — | — | — |
| R30-J-7 / K-08 | P3 | claim mismatch | `.env.example` | offered the retired learning flag | fixed | — | — | — |
| R30-J-8 / K-06 | Info | claim mismatch | `.github/npm-audit/*.allow` | prose said the MCP SDK advisories were unfixed | fixed | — | — | — |
| Dependabot | Info | dependency | 18 open PRs | 7 applied with their package tests (#40, #37, #39, #25, #33, #32, #34); #24 superseded by a fresher digest; 10 deferred: #41, #12, TypeScript 7 ×6 (#14, #18, #21, #23, #27, #28), #22 React 19, #26 the rust 1.99 image | partly applied | package suites | — | **owner**: the deferred majors as their own reviewed changes |

### Documentation (coordinator)

| ID | Sev | Class | Location | Finding | Status |
|---|---|---|---|---|---|
| K-04 | P3 | claim mismatch | `docs/CURRENT.md` | Node 20.20.2 said to be pinned in CI | fixed (docs) |
| K-05 | P3 | claim mismatch | `AUDIT/02-roadmap-gap.md` | "five manifests below the decode bar"; it is 13 | fixed (docs) |
| K-07 | P3 | claim mismatch | `AUDIT/FINAL.md` | stray punctuation; a contradictory "not measured" sentence | fixed (docs) |
| K-14 | Info | repository hygiene | the hosted repository | stale unprotected branches `copilot/fix-rust-core-actions-job`, `phase2-development` | **open (owner)** |
| K-19 | P3 | claim mismatch | `ARCHITECTURE.md`, `ROADMAP.md` | an unmanifested sibling called a non-blocking warning; "live-validated" with no artifact; "Phase 2 certification GO" as a live item | fixed (docs) |

## Counts

Confirmed findings at the baseline `29e4356`, by severity (Info and non-findings not counted):

| | P0 | P1 | P2 | P3 |
|---|---|---|---|---|
| Found | 0 | 5 | 14 | 35 |
| Fixed in code (with a regression test) or in docs | 0 | 5 | 13 | 35 |
| Open | 0 | 0 | 1 (R30-J-2, owner) | 0 |

Every P1 and every fixed P2 has a regression test that a deliberate revert showed failing,
except R30-A-2 (the exit-code mapping was tested through the rule, not broken on its own) and
R30-C-2 (the commands are exercised by tests; the operational gap is not a revertible check).
"Fixed" does not mean "no residual": the residual column is part of the record.

<!-- WS-E --> WS-E's findings (fuzzing, mutation testing, coverage, the release evaluation) are
added here when it merges, and the counts with them.
