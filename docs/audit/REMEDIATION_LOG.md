# Round 39 — remediation log

Every change this round made, why, the test that holds it, the commit, and what changes for a caller.
The findings themselves are in [`PRODUCTION_READINESS_FINDINGS.md`](PRODUCTION_READINESS_FINDINGS.md);
the per-workstream reproductions in [`parts/`](parts/). Internal engineering work, not an independent
audit.

**Base:** `main` at `c087bfb`. **Branch:** `claude/admiring-archimedes-lfhr7n`, PR #55.

**Rules every change kept:** no security invariant weakened to make a test pass; no residual allowed,
floor lowered or allowlist widened; nothing unavailable reported as a pass. Every P0/P1/P2 fix has a
test that failed on `c087bfb` (or under its break) and a deliberate break, built in a copy outside the
working tree with its own target directory, showing the test catches the regression (§2). Where a fix
needed a choice only the owner can make, the fail-closed behaviour was kept and the choice is in
[`RESIDUAL_RISK_AND_OWNER_GATES.md`](RESIDUAL_RISK_AND_OWNER_GATES.md).

## 1. Changes

### 1.1 Decision pipeline (core-decision)

| Commit | Finding | Change and rationale | Test | Caller-visible impact |
|---|---|---|---|---|
| `1f62c96` | R39-CORE-DECISION-1 (P0-class) | `intent_binding::keeps_value` judged value kept when it went to any signer, or a token account whose owner field named a signer. It now asks L4's `lamports_kept_by` / the owner's keeping: the swapping wallet, the grant's owner, the fee payer. A co-signer, a `CreateAccount` for another program, or a token account the attacker can close is no longer "the owner's". | `tests/round39_decision_campaigns.rs` campaigns 1 and 3, under the defaults and `Waivers::All` | value beside a swap, a grant or a creation going to a co-signer is refused (`intent_mismatch` family); honest swaps, withdrawals and creations unchanged (benign controls in the same file) |
| `1f62c96` | R39-CORE-DECISION-2 (P0-class) | Round 38 held only withdrawals to the sibling rule; claim, close and configure grants now go through `grant_keeps_value` too. | campaign 2 (`campaign2_a_claim_close_or_configure_*`) | a transfer riding beside a DLMM `claim_fee` or a CLMM `close_position` is refused |
| `60ccde2` | R39-CORE-DECISION-3 (P2) | A Simulation-family plugin that panicked became a Note and lost its veto. The Simulation family joins the fail-closed set. `test_panicking_blocking_plugin_fails_closed` re-pinned with its reason. | campaign 12 (`round39_a_crashing_plugin_of_any_family_refuses`, 56 malformed/crash cases) | a crashing Simulation plugin refuses instead of noting |
| `60ccde2` | R39-CORE-DECISION-4 (P2, owner) | No code change: the honest-swap false refusal is measured and pinned (101 of 115 declarations) so a manifest rewrite shows up as a census change. | census test in `round39_decision_campaigns.rs` | none |
| `cc6706d` | — | workstream report `parts/core-decision.md` | — | — |

### 1.2 Transaction identity, manifests, registry (core-identity)

| Commit | Finding | Change and rationale | Test | Impact |
|---|---|---|---|---|
| `d1862b9` | R39-CORE-IDENTITY-1 (P2) | `manifest_registry.rs` `gate_decision`: a pinned refusal that the candidate approves blocks the upgrade outright, and the registry's own fixtures must meet the 99.5% rate without the submitter's (which pass by construction and could be padded). | `tests/round39_registry_gate_dilution.rs` (6), with a benign padded upgrade accepted and a retired refusal released | a loosening upgrade is `Rejected` regardless of corpus size |
| `1d48628` | R39-CORE-IDENTITY-2 (P2) | A v0 simulation that returns no readable `loadedAddresses` (absent, `null`, unreadable) is set aside exactly as a contradicting one is (S-5), instead of building privileges from the static keys alone. | `tests/round39_lookup_table_campaign.rs` (12) incl. honest-lookup controls | an RPC that strips `loadedAddresses` now yields a refusal for every v0 transaction with lookups (fail closed; Agave returns the member) |
| `d93d97f` | Round 35 re-verification | One test drives all nine documented unrebuildable parsed-CPI classes through `verify_async`; each stays Inconclusive. | `round35_parsed_inner_instructions::every_documented_unrebuildable_class_stays_inconclusive` | none |
| `4b38fe5` | R39-CORE-IDENTITY-4 (P3) | `validate_manifest` checks every `expected_address` is `{program_id}` or a base58 key. All 926 shipped values pass. | `tests/round39_manifest_expected_address.rs` (2) | a manifest with a malformed `expected_address` is refused at load |
| `3b76f95` | R39-CORE-IDENTITY-5 (P3), -6 (gap) | Fuzz targets assert what they claim (`parse_transaction` re-encodes and requires the bytes back, both directions of "exactly", contents not counts). `tools/runtime-oracle --inputs DIR` replays a cargo-fuzz corpus. | every target fuzzed 120 s (no crash); oracle 645 corpus files + 66,834 generated: 0 looser, 0 disagreements | none (tooling) |
| `1c884cf` | — | workstream report `parts/core-identity.md` | — | — |

### 1.3 System boundary (core-boundary)

| Commit | Finding | Change and rationale | Test | Impact |
|---|---|---|---|---|
| `9592c6b` | R39-CB-1 (P1) | The writer's resume and every keyed reader refuse a trail whose newest record carries another trail id under the same key ("the audit trail holds records of another trail under the same key"). Coverage sets compacted (part of R39-CB-5: 146 → 59 MiB peak at 1,000,000 records). | `durable/chain.rs` `chain_trail_tests::a_record_of_another_trail_at_the_end_does_not_become_the_trail`; `tests/round39_core_boundary.rs`; `a_copied_record_is_not_the_newest_verdict` re-pinned for one step | a server facing such a trail does not start (its log names "another trail") instead of resuming onto it; the keyed reader (`graphite execution`) refuses; `audit verify` exits 1 as before; the unkeyed reader keeps reading |
| `a800b66` | R39-CB-2, -3, -4 | Logging can no longer panic the server (`log_internal_errors(false)`); `healthcheck --strict` follows no redirect and no env proxy; 413 / 408 / caught-panic 500 are counted (`graphite_payload_too_large_total`, `graphite_request_timeouts_total`, `graphite_handler_panics_total`); a wrong doc comment corrected. | binary tests in `round39_core_boundary.rs`; `route_surface::refusals_of_the_transport_are_counted_and_never_on_the_trail` | three new `/metrics` counters (additive); `healthcheck --strict` fails on a redirect |
| `68af392` | docs | `restore.sh` names Round 38 as the round that chose the anchor by content. | `backup-keys.test.sh` 22/22 | none |
| `ede4c54` | R39-CB-6, -7 | `audit verify` of a directory with no trail exits 3; a quarantine lift whose request is cut off while its append waits is not applied. | `a_lift_cut_off_while_its_append_waits_is_still_not_applied`; binary exit-code test | exit code 2 → 3 for a directory with no trail (scripts that read 2 there should read 3) |
| `857b527` | R39-CB-12 (P2) | `protocol diff` compares role, PDA seeds, expected address, optional, alternative layouts and risk rules. | `the_diff_surfaces_every_field_the_runtime_judges_an_account_by` | more lines in the diff output (additive) |
| `7d3a33d` | R39-CB-1 docs | `docs/ops/keys.md` documents the other-trail refusal and its recovery. | — | — |
| `3de2fed` | — | workstream report `parts/core-boundary.md` | — | — |

### 1.4 Clients

| Commit | Finding | Change and rationale | Test | Impact |
|---|---|---|---|---|
| `c691370` | R39-CLIENTS-1 (P2), campaign 14 | `isExecutable` (TS) and `IsExecutable` (Go) require `decision == executable_approved`; a decision-less verdict is not executable (the Core and the guard already read it so). One shared corpus, `examples/decisions/conformance.json` (102 verdicts, 8 content hashes, 13 digests), asserted by Rust, TS, Go and the guard. | `tests/round39_conformance_corpus.rs`, `sdk/typescript/src/conformance.test.ts`, `sdk/go/conformance_test.go`, guard `conformance.test.ts` | **behaviour change**: a pre-Round-30 verdict without `decision` is no longer executable in either SDK |
| `bd0fbc6` | R39-CLIENTS-4, -6, -7 | The guard verifies every signature against the address the message names; refuses to start when its state file's directory is writable by others; keys a swap's repeat by the request's amount (`swap:v3`; `swap:v2` records still honoured). | `guard-round39.test.ts` | guard refuses an insecure state directory at start-up (documented) |
| `43b40fd` | R39-CLIENTS-2, -5 | The SAK dev tree's Zod override pinned as a test and documented; the Python burn pattern matches ASCII digits only. | `zod-override.test.ts`; pytest | none |
| `a107e8a` | R39-CLIENTS-8 | `tools/live-measure` recomputes the SDKs' full rule (missing residual codes are not "none"). | pytest (60) | none |
| `268e7a4` | campaign 13 | MCP: a prompt-injected field changes nothing; only a boolean `true` approves. | MCP tests (12) | none |
| `8aee56d` | R39-CLIENTS-9 | The guard's AuditBind refuses a non-byte value instead of hashing `256` as `0`. | guard tests | none |
| `67e5dfb` | R39-CLIENTS-3 | Both SDKs pin every enum they decide on to `schemas/verification-result-v1.json`; the TS validator refuses `215.0`, `2.15e2` and u32 values above 2^32. | SDK tests | malformed numbers in a verdict are refused (serde and Go already did) |
| `d11f1d0` | — | workstream report `parts/clients.md` | — | — |
| `598eeb9` | — | CI floors at the new counts: SDK 68, guard 343, MCP 12, SAK 11, Go 66, pytest AI 51, live-measure 60. | `ci.yml` | none |

No schema change: `schemas/verification-result-v1.json` is unchanged; the SDK enums are now tested
against it.

### 1.5 Dashboard

| Commit | Finding | Change | Test |
|---|---|---|---|
| `3384f9e` | R39-DASH-1 … -12 | Unknown `/health` fields render "unknown", never "Off" or "Writing" (-5); failed audit appends render red; a key pasted into the address field is refused and never stored or echoed (-7); modal stack for palette + pane (-2); tape edge, metrics failure, CORS blame, copy feedback, freshness, filter toggle buttons, manifest without `accounts`, phone layout. | unit 36 → 48 |
| `f190629` | R39-DASH-13 | e2e smoke measures overflow by `clientWidth` at five widths; `states.mjs` drives every new state. | smoke, states |
| `22b1e9a` | — | `parts/dashboard.md` | — |

### 1.6 Supply chain, CI, data

| Commit | Finding | Change | Test |
|---|---|---|---|
| `807d7dc` | R39-SUPPLY-CHAIN-2, -3, -4 | `ruleset-drift.py` compares an uncommitted live ruleset field by field, requires `main-review.json`, adds `--require-bypass`, accepts an admin's `current_user_can_bypass: always` when the visible list matches; the live 2026-10-25 snapshot is a test fixture (71 differences named); shellcheck in the harness. `docs/ops/branch-protection.md` and the checklist give the exact owner steps. | `ci-scripts.test.sh` |
| `be1839f` | new tooling, R39-SUPPLY-CHAIN-10 … -13 | `graphite-core/scripts/validate_corpora.py` validates 495 JSON + 2 JSONC files (schemas, semantic invariants, 63 pinned gaps) in the ci-scripts job; 13 seeded faults in its own test. | `ci-scripts.test.sh` |
| `b57b982` | R39-SUPPLY-CHAIN-15 | The live-mainnet seed exit pinned by a test; exploit fixtures named by their signature. | `ci-scripts.test.sh` |
| `b57b982` / CI | R39-SUPPLY-CHAIN-5 | `cargo audit` over `graphite-core/fuzz/Cargo.lock`. | CI step |
| `f391953` | runner shellcheck | Two `A && B \|\| C` tests rewritten as explicit `if`s (SC2015, reported by the runner's shellcheck; 0.11.0 here did not). | ci-scripts |
| `84de50a` | R39-SUPPLY-CHAIN-7 | `anyhow` removed from `graphite-core/Cargo.toml` and the lockfile (`cargo update -w --offline`). | all Rust legs (§3) |
| `655fce4` | CI on `84de50a` | The runtime oracle, inner-instruction oracle and fuzz lockfiles drop `anyhow` with graphite-core (`cargo update -p graphite-core --offline`); `rust-ignored.txt` lists the R39-CB-5 measurement (a measurement, never a gate). | oracle jobs, CVE audit |
| `9e166de` | CI on `84de50a` | The R39-CB-5 measurement takes two runs instead of re-running its own binary through `std::process::Command` (the AI-isolation scan is unchanged); `tests/round39_core_boundary.rs` is `cfg(feature = "server")`. | `ai_layer_isolation`, cli leg |
| this round's last commit | — | Rust test floors in `ci.yml` raised to the measured counts: default 2,414 → 2,464, lib 529 → 530, cli 1,967 → 1,980. | test-count gate |
| `50a7cb7`, `349fa63` | — | `parts/supply-chain.md`; one line rephrased so the repo-wide signer-pin scan does not read a partial `gh attestation verify` as a command. | ci-scripts 121 |

### 1.7 Deliverables and documentation

| Commit | What |
|---|---|
| `b72b27c` + this round's last commits | `docs/audit/build_inventory.py`, `review-map.tsv`, `EXHAUSTIVE_FILE_INVENTORY.csv` (every tracked file, 0 uncovered) |
| this round's last commits | `PRODUCTION_READINESS_FINDINGS.md`, `INVARIANT_EVIDENCE_MATRIX.md`, this log, `RESIDUAL_RISK_AND_OWNER_GATES.md`; `docs/CURRENT.md`, `SECURITY.md`, `graphite-core/CHANGELOG.md`, `AUDIT/01-findings.md` (break log B207–B244); Rust test floors in `ci.yml` raised to the measured counts (§3) |

## 2. Deliberate breaks

Each break reverted one fix in a copy outside the working tree (own `CARGO_TARGET_DIR`), ran the
fix's tests, and was deleted. Continued in `AUDIT/01-findings.md` as B207–B244.

| Log | Workstream id | Fix reverted | Caught by | Result |
|---|---|---|---|---|
| B207 | core-decision B1 | `kept_by` → `signers_own` (R39-CORE-DECISION-1) | campaigns 1 and 3 | caught (3 fail; the Round 38 suites still pass) |
| B208 | core-decision B2 | `grounded_owner_operation` forced false (-2) | campaign 2 | caught |
| B209 | core-decision B3 | Simulation out of the fail-closed set (-3) | orchestrator unit test, campaign 12 | caught (2 fail) |
| B210 | core-identity | registry loosening arm off (-1) | `a_large_registry_corpus_does_not_tolerate_one_loosened_refusal` | caught |
| B211 | core-identity | registry-only rate arm off (-1) | `padding_does_not_dilute_the_registrys_own_fixtures` | caught |
| B212 | core-identity | both arms off (pre-fix) | the padded attack test | caught |
| B213 | core-identity | pre-fix `loadedAddresses` handling (-2) | `round39_lookup_table_campaign` omission test | caught (`executable_approved`) |
| B214 | B-CB-1 | other-trail refusal in `resume_head` removed (R39-CB-1) | chain and server tests | caught |
| B215 | B-CB-1b | other-trail refusal in the keyed open removed | chain tests | caught |
| B216 | B-CB-2 | `log_internal_errors(false)` removed | binary test | caught |
| B217 | B-CB-3 | healthcheck redirect policy removed | binary test | caught |
| B218 | B-CB-4 | transport counter increment removed | `route_surface` test | caught |
| B219 | B-CB-6 | no-trail exit 3 check removed | binary test | caught (exit 2) |
| B220 | B-CB-7 | lift restore moved after the await | lift test (the benign lift still passes) | caught |
| B221 | B-CB-12 | expected-address comparison in `protocol diff` off | diff test | caught |
| B222 | clients B1 | TS `isExecutable` without `decision` (R39-CLIENTS-1) | SDK conformance | caught |
| B223 | clients B1g | Go `IsExecutable` without `decision` | Go conformance | caught |
| B224 | clients B2 | guard conformance against the old rule | guard conformance | caught |
| B225 | clients B3 | TS integer check off (-3) | SDK validator tests | caught |
| B226 | clients B3b | u32 bound off | SDK validator tests | caught |
| B227 | clients B4 | guard signature verification off (-4) | `guard-round39.test.ts` | caught |
| B228 | clients B5 | Python `\d` restored (-5) | pytest | caught |
| B229 | clients B6 | state-directory check off (-6) | guard tests | caught |
| B230 | clients B7 | swap repeat key from the route (-7) | guard tests | caught |
| B231 | clients B8 | live-measure missing codes as none (-8) | pytest | caught |
| B232 | clients B9 | AuditBind byte check off (-9) | guard tests | caught |
| B233 | supply-chain B1 | Round 38 `ruleset-drift.py` | ci-scripts drift cases | caught (18 fail) |
| B234 | supply-chain B2 | uncommitted ruleset back to a notice | ci-scripts | caught (11 fail) |
| B235 | supply-chain B3 | `main-review.json` optional | ci-scripts | caught (1 fail) |
| B236 | supply-chain B4 | `--require-bypass` ignored | ci-scripts | caught (2 fail) |
| B237 | supply-chain B5 | the original `test-count.sh` line | shellcheck in the harness | caught |
| B238 | supply-chain B6 | validator prefix check off | seeded prefix fault | caught |
| B239 | supply-chain B7 | validator medium-rewrite check off | seeded fault | caught |
| B240 | supply-chain B8 | live-mainnet seed `exit` removed | "a failed seeding is never reported as seeded" | caught |
| B241 | supply-chain B9 | `SEEDED` from the step outcome | same | caught |
| B242 | dashboard | new unit tests on the `c087bfb` source | vitest | caught (8 of 43 fail) |
| B243 | dashboard | new `smoke.mjs` on the `c087bfb` build | Playwright | caught (12 fail) |
| B244 | dashboard | new `states.mjs` on the `c087bfb` build | Playwright | caught (19 fail) |

## 3. Verification

### 3.1 Local, on the integrated branch

`CARGO_TARGET_DIR=/home/user/r39-target`, rustc 1.97.0 (CI uses 1.99.1; MSRV 1.89), 4 cores.

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo clippy -j 4 --locked --all-targets --all-features -- -D warnings` | clean |
| `cargo clippy -j 4 --locked --lib --no-default-features -- -D warnings` | clean |
| `cargo clippy -j 4 --locked --all-targets --no-default-features --features cli -- -D warnings` | clean |
| `cargo test -j 4 --locked --no-fail-fast` | 2,464 passed, 0 failed, 15 ignored (all listed), 179 targets |
| `cargo test -j 4 --locked --lib --no-default-features` | 530 passed, 0 failed, 4 ignored |
| `cargo test -j 4 --locked --no-default-features --features cli --no-fail-fast` | 1,980 passed, 0 failed, 6 ignored, 179 targets |
| `cargo build -j 4 --locked --release --all-features` | builds |
| `bash .github/scripts/ci-scripts.test.sh` | 121 passed |
| `bash .github/scripts/release-gate.test.sh` | 52 / 52 |
| `bash deploy/scripts/backup-keys.test.sh` | 22 / 22 |
| `python3 -I graphite-core/scripts/validate_corpora.py` | pass (63 pinned gaps) |
| each Rust leg through `.github/scripts/test-count.sh` with `rust-ignored.txt` | ok at the new floors (2,464 / 530 / 1,980) |
| TS SDK / guard / MCP / SAK / Vercel AI | 68 / 343 / 12 / 11 / 12 |
| Go 1.26.10 and 1.27.3 | 66 / 66 |
| pytest AI layer / mainnet-sample / live-measure | 51 / 7 / 60 |
| dashboard unit / smoke / states | 48 / pass / pass |
| `python3 -I docs/audit/build_inventory.py --commit HEAD` | every tracked file covered, 0 uncovered |

The per-workstream commands (fuzzing, the two oracles, the break copies, the campaign drivers) are in
each `parts/*.md` §6.

### 3.2 CI

PR #55's CI and Assurance runs on each pushed head are listed in the PR; the green runs on intermediate
heads: `22b1e9a` (CI 40199619665, Assurance 40199619668), `cc6706d` (40200899050 / 40200899048),
`1c884cf` (40202572519 / 40202572462). `84de50a` (CI 40204111251) was red: the oracle and fuzz lockfiles still listed `anyhow`, the new CB-5 measurement test was `#[ignore]`d without an allowlist line and spawned a process the AI-isolation scan forbids, and `round39_core_boundary` was not gated on `server`; fixed in `655fce4` and `9e166de`, which is green (CI 40205747414, Assurance 40205747377). "CI gate" runs cancelled by a later push (concurrency) are not
failures of the code. The final head's runs are recorded in the PR.

### 3.3 Not run, and why

- Real-traffic false-refusal rates (needs a public RPC: not contacted by rule).
- Caddy, promtool and Docker checks (not in this container; green in PR CI).
- Mutation testing (about 260 runner-hours for a full run).
- Windows behaviour of the guard (reasoned).

## 4. Round 40 — the open decisions implemented (2026-10-26 → 2026-10-29)

The owner delegated every open Round 39 decision; each is recorded in
[`TECHNICAL_LEAD_DECISIONS.md`](TECHNICAL_LEAD_DECISIONS.md) and implemented by one workstream, whose
report (changes, tests, breaks, Constitution check, verification answers, commands) is in
[`parts-r40/`](parts-r40/):

| Workstream | What changed | Report |
|---|---|---|
| assurance | conformance corpus through the server, CLI and dashboard; actionlint 1.7.11 pinned and run; per-binary Rust floors; a required Windows CI job for the agent guard; `publish = false`; mutation shards that fit the step; `test-count.sh` reads coloured cargo output | [`assurance.md`](parts-r40/assurance.md) |
| bootstrap | `graphite evidence import-census --cluster mainnet-beta` (measured volume, mainnet-only enforced, never re-imports an upgraded program); every Round 38/39 attack re-run in the imported and trained states | [`bootstrap.md`](parts-r40/bootstrap.md) |
| manifests | 60 swap declarations rewritten from the committed IDLs; 23 phantom instructions and the dead `update_offer` grant removed; 7 F-005 promotions with evidence; label fixes | [`manifests.md`](parts-r40/manifests.md) |
| boundary | `GRAPHITE_TRUSTED_PROXIES`; RPC clients ignore env proxies; signer-key mode check; escaped terminal output; a 250 ms per-plugin deadline; first registry manifests capped at HeuristicInferred | [`boundary.md`](parts-r40/boundary.md) |
| measure | the live runner imports the census and types no baseline; a constructed-honest-transfer pass; per-row fee detail (no Core fee defect) | [`measure.md`](parts-r40/measure.md) |

Integration fixes in the main session: the census-import and swap-rewrite tests combined
(`CONFIGS`), per-binary floors for every new suite, the inner-instruction oracle moved to Agave
4.4.0 (removes `zstd-safe` 7.3.0 and eight RUSTSEC-2026 unsound advisories; no audit exception),
and two plugin-crash tests that accept `timed-out` as well as `panicked` for a crash slower than
the deadline (both refuse). Live evidence: [`../evidence/live-mainnet/run-40839253280.md`](../evidence/live-mainnet/run-40839253280.md)
— 27 of 28 constructed honest transfers `executable_approved` after the census import.

### 4.1 Verification at the end of Round 40 (2026-10-29)

| Command | Result |
|---|---|
| `cargo test -j 4 --locked --no-fail-fast` (default leg) | 2,607 passed, 0 failed, 15 ignored (all listed), 189 targets; 48 binaries at or above their per-binary floors |
| `cargo test -j 4 --locked --no-default-features --features cli --no-fail-fast` | 2,011 passed, 0 failed, 6 ignored; 32 binaries at or above their floors |
| `cargo test -j 4 --locked --no-default-features --lib` | 533 passed, 0 failed, 4 ignored |
| `cargo fmt --check`, `cargo clippy -D warnings` (all three legs) | clean |
| `cargo audit` on `graphite-core` and both oracles | no vulnerability; only the allowed bincode-unmaintained warning in the oracles |
| agent guard / dashboard (`npm test`) | 348 / 51 passed |
| `pytest`: AI layer, mainnet-sample, live-measure | 51 / 7 / 83 passed |
| `.github/scripts/ci-scripts.test.sh` | 137 passed |
| `docs/audit/build_inventory.py` | every tracked file covered by a workstream |

Rust test floors in `ci.yml` raised to these counts: default 2,464 → 2,607, lib 530 → 533, cli
1,980 → 2,011.
