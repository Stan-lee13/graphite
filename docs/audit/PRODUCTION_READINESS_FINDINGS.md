# Round 39 — production-readiness findings register

**Target audited:** `main` at `c087bfb502f5a5c13c12755c719faf54f6c4eec6` (the Round 38 merge; 1,110
tracked files). Remediation on `claude/admiring-archimedes-lfhr7n`, PR #55. **Date:** 2026-10-25.

**What this is:** internal engineering work by the maintainer and AI engineering agents, run against
the owner's exhaustive production-readiness brief. **It is not an independent third-party audit and
not a certification.** Every finding below was found, reproduced and fixed (or dispositioned) by the
same people who wrote the code.

**How it was done:** six workstreams, each reading every production file in its scope end to end
from the public entry points and running the brief's attack campaigns through the real paths
(`verify_async` against loopback mock RPCs, the HTTP server, the CLI binary, `graphite audit verify`,
a live dashboard against a real Core). Every P0/P1/P2 fix has a reproduction test that failed before
the fix and a deliberate break (the fix reverted in a copy outside the working tree, with its own
build directory) showing the test catches the regression. The per-workstream detail — files read,
reproductions, campaigns, commands — is in [`parts/`](parts/):

| Workstream | Scope | Detail |
|---|---|---|
| core-decision | the decision pipeline: binding, L4, risk, policy, confidence, simulation integrity, plugins | [`parts/core-decision.md`](parts/core-decision.md) |
| core-boundary | the audit trail, server, CLI, RPC client, operator boundary, backup/restore | [`parts/core-boundary.md`](parts/core-boundary.md) |
| core-identity | the wire parser, lookup tables, PDAs, parsed CPIs, manifests, registry, fuzzing, oracles | [`parts/core-identity.md`](parts/core-identity.md) |
| clients | TS and Go SDKs, agent guard, SAK / MCP / Vercel AI adapters, Python layer, tools, schemas | [`parts/clients.md`](parts/clients.md) |
| dashboard | the operator console, its e2e harness | [`parts/dashboard.md`](parts/dashboard.md) |
| supply-chain | CI, release, deploy, containers, dependencies, rulesets, manifests and fixture data | [`parts/supply-chain.md`](parts/supply-chain.md) |

Every tracked file's coverage is in [`EXHAUSTIVE_FILE_INVENTORY.csv`](EXHAUSTIVE_FILE_INVENTORY.csv): 1,143 files at `833af24` (the remediated branch, the CSV's own commit aside), every one mapped to a workstream by [`review-map.tsv`](review-map.tsv); regenerate with `python3 -I docs/audit/build_inventory.py --commit HEAD`.

**Severity:** P0 signing bypass / unauthorized value movement / audit-integrity or release-provenance
bypass · P1 serious security or integrity defect, silent fail-open · P2 reliability, high-impact
correctness, parity, dangerous configuration, major false refusal, supply-chain weakness · P3 docs,
usability, diagnostics, lower-impact edge cases. "P0-class" marks a P0 whose reachability needs a
stated precondition.

## 1. Summary

| | P0-class | P1 | P2 | P3 |
|---|---|---|---|---|
| New this round | 2 | 2 | 11 | 46 |
| fixed with a test | 2 | 1 (R39-CB-1) | 8 | 32 |
| owner decision / owner gate | — | 1 (live rulesets) | 2 | 4 |
| accepted limitation / recorded / pinned | — | — | 1 (R39-CB-5, partly fixed) | 10 |

Not counted above: one evidence gap narrowed (R39-CORE-IDENTITY-6), one owner decision without a
severity (R39-CORE-IDENTITY-7, first-manifest validation), and one suspected finding not reproduced
(R39-SUPPLY-CHAIN-15, already fixed in Round 36).

**No known P0/P1 remains open in the reviewed code scope.** The open P1 is not code: the live
GitHub rulesets (R39-SUPPLY-CHAIN-1), which only the owner can change. Release remains blocked by the
gates in [`RESIDUAL_RISK_AND_OWNER_GATES.md`](RESIDUAL_RISK_AND_OWNER_GATES.md).

**Round 40 (2026-10-26 → 2026-10-29).** The owner delegated every open decision below; each was
decided and implemented (`TECHNICAL_LEAD_DECISIONS.md`, `parts-r40/`). Status changes since this
register was written: R39-CORE-DECISION-4 and -5, R39-CB-8, -13, -14, -15, R39-CORE-IDENTITY-7,
R39-SUPPLY-CHAIN-6, -11, -12 and D2-8 are **fixed**; the no-per-plugin-timeout observation is fixed
(250 ms deadline). R39-SUPPLY-CHAIN-1 (the live rulesets) remains the owner's.

## 2. New findings (Round 39)

Status words: **fixed** (with a regression test that fails without the fix, and a break that proves
it) · **owner** (needs a decision only the owner can make; fail-closed behaviour kept meanwhile) ·
**accepted** (a documented, tested fail-closed limitation) · **recorded** (noted, no change).

### 2.1 Decision pipeline

| ID | Sev | Location | Finding | Status, test, break |
|---|---|---|---|---|
| R39-CORE-DECISION-1 | P0-class | `intent_binding.rs` `keeps_value` / `signers_own` | The sibling rule beside a swap, a grant or a creation called any **signer**, and any token account whose owner field named a signer, "the owner's". 30 SOL beside a granted Stake Withdraw reached `executable_approved` under the defaults and under every waiver — to a co-signing attacker, into a `CreateAccount` for the attacker's program, or into a token account the attacker can close; a swap into SOL sent to that closable account was executable with the waivers on. | **fixed**: held to the owner's keeping (the swapping wallet, the grant's owner, the fee payer) as L4's `lamports_kept_by` judges it. `round39_decision_campaigns.rs` campaigns 1–3. Break: 3 tests fail; the Round 38 suites still passed, so they did not cover it |
| R39-CORE-DECISION-2 | P0-class | `verification.rs` binding dispatch; `intent_grants.rs` | Round 38's sibling rule held only withdrawals. A Meteora DLMM `claim_fee` beside a transfer of most of the claim to the attacker, and a Raydium CLMM `close_position` beside a transfer of its refund, were `executable_approved` under the defaults. | **fixed**: claim, close and configure grants go through `grant_keeps_value`. Campaign 2. Break: caught |
| R39-CORE-DECISION-3 | P2 | `plugin_orchestrator.rs` | A Simulation-family plugin that panicked became a Note, so the crash dropped its veto. | **fixed**: the Simulation family is fail-closed; `test_panicking_blocking_plugin_fails_closed` re-pinned with its reason. Campaign 12. Break: caught |
| R39-CORE-DECISION-4 | P2 (false refusal) | `graphite-core/protocols/*` swap declarations | 101 of 115 swap/route declarations refuse an honest swap by default (93: "…received amount for the swap" declares a debit naming no account; 8: nothing L4 can read). End to end: Raydium CPMM `swap_base_input`, Meteora DAMM v2 `swap`, Orca `swap`/`swapV2` are refused (`SignerTokenDebitUnderUnscopedDebit`). | **owner**: a rewrite from the committed IDLs (`scripts/idls/raydium_cpmm.json`, `orca-whirlpools.json`, `jupiter.json`) is possible; manifests unchanged. Census pinned |
| R39-CORE-DECISION-5 | P3 (false refusal) | marketplace `update_offer` grant | The configure grant declares no debit, so even an honest update is `UndeclaredTokenDebit`: the grant can never pass. | **owner** |

Preconditions for -1 and -2: the verdict needs confidence above the profile's floor. A fresh instance
scores 0.44, below every built-in profile; in production it takes a program with an L3 baseline or an
operator profile at 0.44 or lower. Every other gate passed both attacks.

P3 observations (recorded, no change): no per-plugin timeout; the drainer plugin echoes the request's
text into the response (not the audit row); a burn grant's `CloseAccount` rent sibling is rent-sized
only; a SOL skim up to the 0.01 SOL swap overhead into an account the owner keeps; a withdrawal's
sibling check exempts the grant's own program (a second withdraw and an `Authorize` are refused
anyway, by Check 10 and L4).

### 2.2 System boundary

| ID | Sev | Location | Finding | Status, test, break |
|---|---|---|---|---|
| R39-CB-1 | P1 | `durable/chain.rs`, `durable.rs` gate and writer | A record of **another trail under the same key**, appended at the end, took the trail over: a restarted server resumed onto it, the genuine records read as foreign, and the L8 lookup returned the foreign approval. | **fixed**: writers and keyed readers refuse ("the audit trail holds records of another trail under the same key"). `chain_trail_tests::a_record_of_another_trail_at_the_end_does_not_become_the_trail`, `round39_core_boundary.rs`; one step of `a_copied_record_is_not_the_newest_verdict` re-pinned. Breaks B-CB-1/1b: 3 tests fail |
| R39-CB-2 | P2 | `server.rs` logging | With stdout and stderr both unwritable, the server panicked at its first log line (exit 101). | **fixed** (`log_internal_errors(false)`), binary test; break caught |
| R39-CB-3 | P3 | `cli.rs` `healthcheck --strict` | Followed redirects and environment proxies, so it passed on another host's answer. | **fixed**, binary test; break caught |
| R39-CB-4 | P3 | `server.rs` transport layer | 413, 408 and caught-panic 500 responses were counted nowhere; a doc comment said oversized bodies leave an audit row. | **fixed**: `graphite_payload_too_large_total`, `graphite_request_timeouts_total`, `graphite_handler_panics_total`; comment corrected. `route_surface::refusals_of_the_transport_are_counted_and_never_on_the_trail` |
| R39-CB-5 | P2 | `durable/chain.rs` keyed reader | Reader memory grew with the adopted unkeyed history: 146 MiB peak over 1,000,000 records. | partly **fixed** (59 MiB); the rest **accepted**: adopt a key early or prune. Measurement test (ignored) |
| R39-CB-6 | P3 | `cli.rs` `audit verify` | A directory with no trail exited 2 (unproven) instead of 3 (unreadable). | **fixed**, binary test |
| R39-CB-7 | P3 | `server.rs` quarantine lift | A lift cut off while its audit write waited stayed in force with no record. | **fixed**: `a_lift_cut_off_while_its_append_waits_is_still_not_applied` |
| R39-CB-8 | P2 | `GRAPHITE_TRUST_PROXY`; `deploy/compose/docker-compose.prod.yml` | Trusts `X-Forwarded-For` from any peer; in the prod compose the `ai` service shares the backend network with Core, so it can pick its own rate-limit bucket. | **owner**: a trusted-proxy address allowlist, or a Core-only network |
| R39-CB-9 | P3 | `deploy/scripts/backup.sh` | A hot backup can copy a record whose write later failed and was truncated, so a restore over-records. | **accepted** |
| R39-CB-10 | P3 | `server.rs` | A refused connection's body is drained (≤1 MiB, ≤1 s). | **accepted** (bounded) |
| R39-CB-11 | P3 | trail start-up | A trail cut at the front, or with its first record tampered, still starts; only `audit verify` (or a checkpoint) reports it. | **accepted**, documented |
| R39-CB-12 | P2 | `cli.rs` `protocol diff` | Ignored role, PDA seeds, expected address, optional, alternative layouts and risk rules, so a reviewer saw "no instruction-level changes" for a change the runtime judges by. | **fixed**: `the_diff_surfaces_every_field_the_runtime_judges_an_account_by`; break caught |
| R39-CB-13 | P3 | `rpc_client.rs` | The RPC client honours `HTTP(S)_PROXY`; the connect-time guard then checks only the proxy's address. | **owner** |
| R39-CB-14 | P3 | `bin/graphite.rs` registry signer | The signer key file is read without the permission check the audit key file gets. | recorded |
| R39-CB-15 | P3 | `cli.rs` `explain` | Prints caller-supplied strings unescaped to the terminal. | recorded |

### 2.3 Transaction identity, manifests and registry

| ID | Sev | Location | Finding | Status, test, break |
|---|---|---|---|---|
| R39-CORE-IDENTITY-1 | P2 | `manifest_registry.rs` `submit`; `regression_engine.rs` | The P10 gate promoted at 99.5% of the registry's fixtures **plus the submitter's own**, which pass by construction and could be copied under different `source` strings: 250 padding fixtures let a loosening v2 approve a refusal v1 had pinned, and v2 was `Accepted`. Precondition: a registered reviewer signs the upgrade. | **fixed**: `gate_decision` — a pinned refusal the candidate approves blocks outright, and the registry's own fixtures must meet the rate on their own. `round39_registry_gate_dilution.rs` (6). Breaks: each rule removed alone is caught |
| R39-CORE-IDENTITY-2 | P2 | `verification.rs` `loadedAddresses` handling | A v0 transaction reaching an account through a lookup table was `executable_approved` when the simulator sent no readable `loadedAddresses` (absent, `null`, unreadable): the S-5 equality check ran only when the list was present, and privileges were built from the static keys alone. | **fixed**: such a simulation is set aside like a contradicting one. `round39_lookup_table_campaign.rs` (12). Break: `executable_approved` again |
| R39-CORE-IDENTITY-3 | P3 | `docs/CURRENT.md` K-7 | "75 = 64 Orca + 10 Kamino" adds to 74; the pinned set is 65 + 10. | fixed in CURRENT (also R39-SUPPLY-CHAIN-14) |
| R39-CORE-IDENTITY-4 | P3 | `manifest.rs` `validate_manifest` | `expected_address` values were never validated (`{program_id}` or a key), so a typo refused every call to that instruction. All 926 shipped values are valid. | **fixed**: `round39_manifest_expected_address.rs` |
| R39-CORE-IDENTITY-5 | P3 | `graphite-core/fuzz/fuzz_targets/*` | Four targets asserted less than they claimed (no injectivity, one direction of "exactly", counts only, parser only). | **fixed**: e.g. `parse_transaction` re-encodes and requires the bytes back. All six fuzzed 120 s, no crash |
| R39-CORE-IDENTITY-6 | evidence gap | `tools/runtime-oracle` | Differential against the Anza decoder and sanitizer, but not coverage-guided. | narrowed: `--inputs DIR` replays a cargo-fuzz corpus (645 files + 66,834 generated: 0 looser, 0 disagreements). Open: coverage guidance on the runtime side; execution-level differential against a bank |
| R39-CORE-IDENTITY-7 | owner | first-manifest validation | A first manifest is checked only against fixtures recorded under itself. | **owner**: the four strategies in `parts/core-identity.md` §2.7 each need a bar only the owner can set |

### 2.4 Clients

| ID | Sev | Location | Finding | Status, test, break |
|---|---|---|---|---|
| R39-CLIENTS-1 | P2 | `sdk/typescript/src/types.ts` `isExecutable`; `sdk/go/graphite.go` `IsExecutable` | A verdict with no `decision` was called executable by recomputing the rule alone; the Core reads it as blocked and the guard refuses it. | **fixed** in both SDKs; two tests re-pinned with their reason. Break caught |
| R39-CLIENTS-2 | P3 | `integrations/solana-agent-kit` dev tree | The Zod 4.6.7 override crosses a major for solana-agent-kit (`zod ^3`): its own `createOpenAITools` throws, while the allowlist said every override stayed within its major. | **accepted**, documented, pinned by `zod-override.test.ts` |
| R39-CLIENTS-3 | P3 | `sdk/typescript/src/client.ts` validator | Accepted integers written `215.0` / `2.15e2`, and u32 compute limits above 2^32 (serde and Go refuse both). | **fixed** |
| R39-CLIENTS-4 | P3 | `integrations/agent-guard/artifact.ts` | Signatures were never checked after signing: a signer whose halves came from two keys got through, and the guard recorded and sent a transaction no validator accepts (no funds could move). | **fixed**: every slot must verify against the address the message names |
| R39-CLIENTS-5 | P3 | `python-ai-layer` burn pattern | `\d` matched any Unicode digit. | **fixed** |
| R39-CLIENTS-6 | P3 | `integrations/agent-guard/guard-state.ts` | The state file's location was never checked: in a directory other users can write it could be swapped before a restart, wiping reservations and unresolved submissions. | **fixed**: refuses to start (Windows checks file kinds only) |
| R39-CLIENTS-7 | P3 | `integrations/agent-guard/guard.ts` swap repeat key | The key used the route's amount: after an outcome-unknown swap, the same request through a route spending one base unit less was sent again. | **fixed**: `swap:v3` keyed by the request's amount; `swap:v2` records still honoured |
| R39-CLIENTS-8 | P3 | `tools/live-measure` | The defect check treated missing residual codes as "none". | **fixed** |
| R39-CLIENTS-9 | P3 | `integrations/agent-guard/auditbind.ts` | Hashed `[256]` as `[0]`. | **fixed** |

Campaign 14: `examples/decisions/conformance.json` — 102 verdict vectors, 8 content-hash vectors and
13 transaction-digest vectors — is asserted identically by Rust, the TS SDK, the Go SDK and the guard.

### 2.5 Dashboard

All P3 except -5 (P2); all **fixed** with unit and/or browser tests. Unit tests 36 → 48; break: 8 of
43 fail on c087bfb; smoke 12 failures and states 19 on the c087bfb build; 0 after.

| ID | Sev | Finding |
|---|---|---|
| R39-DASH-1 | P3 | A deep link opened before the graph loaded said "Not in the graph / No manifest describes this program" |
| R39-DASH-2 | P3 | The command palette over a detail pane: one Escape closed both; both focus traps ran (now a modal stack) |
| R39-DASH-3 | P3 | The verdict tape's right edge always read "now" |
| R39-DASH-4 | P3 | A failed first `/metrics` read hid everything `/health` reported |
| R39-DASH-5 | P2 | A `/health` without `audit` / `graph_persistence` drew "Off — verdicts are not being recorded"; a trail whose appends failed drew green "Writing" (the R36-D1 class) |
| R39-DASH-6 | P3 | The connection test blamed CORS for a `/health` answering 500/429 |
| R39-DASH-7 | P3 | A key pasted into the address field was stored in localStorage, echoed in error text and the sidebar; addresses with user-info likewise. Now refused, never saved or echoed |
| R39-DASH-8 | P3 | A refused copy gave no feedback |
| R39-DASH-9 | P3 | "Updated Ns ago" only moved when a poll landed; a re-focused tab kept the slow hidden-tab wait |
| R39-DASH-10 | P3 | The page scrolled sideways on phones and tablets |
| R39-DASH-11 | P3 | The Verifications filter was radio markup without arrow keys (now toggle buttons) |
| R39-DASH-12 | P3 | A manifest instruction without `accounts` crashed Programs; unchecked fields rendered "NaN" |
| R39-DASH-13 | P3 (test gap) | The smoke test's overflow check could not fail under phone/tablet emulation — why CI never saw -10 |

### 2.6 Supply chain, CI, release, data

| ID | Sev | Location | Finding | Status |
|---|---|---|---|---|
| R39-SUPPLY-CHAIN-1 | P1 (owner gate) | live repository settings | On 2026-10-25 the only ruleset is an uncommitted `Main-review` (id 25817024): 0 approvals, an extra `copilot_code_review` rule, **26 always-bypass actors** (repository roles 2 and 5 and 24 GitHub Apps); no tag rulesets; private vulnerability reporting off; the `release` environment unreadable (not verified). Anyone holding one of those apps' tokens can push to `main`. | **owner**: rulesets applied 2026-10-30 (the four match; `Main-review` deleted); the admin read of the bypass lists and the `release` environment (`branch-protection.md` §3, checklist R5) remains |
| R39-SUPPLY-CHAIN-2 | P2 | `.github/scripts/ruleset-drift.py` | Matched by name and only noted a live ruleset with no committed file, so none of Main-review's differences was compared; `main-review.json` was optional; a hidden bypass list still read "match". | **fixed**: uncommitted rulesets compared field by field; `main-review.json` required; `--require-bypass`. 71 differences named against the live snapshot. Breaks B1–B4 caught |
| R39-SUPPLY-CHAIN-3 | P3 | same | An admin token's read of a correct state failed (`current_user_can_bypass: always`). | **fixed** |
| R39-SUPPLY-CHAIN-4 | P3 | `.github/scripts/*.sh` | Never shellchecked; `test-count.sh` SC2086/SC2116 (and SC2015 in two scripts, found by the runner's shellcheck). | **fixed**, shellcheck in the ci-scripts harness |
| R39-SUPPLY-CHAIN-5 | P3 | `graphite-core/fuzz/Cargo.lock` | The one Cargo lockfile no job audited. | **fixed** (CI step) |
| R39-SUPPLY-CHAIN-6 | P3 | CI | actionlint not run nor pinned (1.7.7 rejects `release.yml:419`; 1.7.11 clean). | recorded (recommendation) |
| R39-SUPPLY-CHAIN-7 | P3 | `graphite-core/Cargo.toml` | `anyhow` unused, shipped in the SBOM. | **fixed** (removed) |
| R39-SUPPLY-CHAIN-8 | P3 | `release-guard.yml` | Watches tag-push runs only; a branch's `release.yml` publishing on `workflow_dispatch` is outside it. | **accepted**: `--source-ref` verification refuses its attestations; the owner's rulesets are the stop |
| R39-SUPPLY-CHAIN-9 | P3 | `SECURITY.md`, issue template | Security contact is e-mail only. | **fixed 2026-10-30**: the owner enabled private vulnerability reporting; `SECURITY.md` and the issue template point at the advisory form |
| R39-SUPPLY-CHAIN-10 | P3 | checklist item 13 | Said none of the nine medium rewrites has an IDL; Marinade has one. | **fixed** |
| R39-SUPPLY-CHAIN-11 | P3 | Meteora / Jupiter / Squads manifests | A phantom `swap_2` beside the real `swap2`; 27 more discriminators in no instruction of the committed IDL. | **owner** (manifest change) |
| R39-SUPPLY-CHAIN-12 | P3 | ATA, Kamino, Solend manifests | Label problems (role `pda` with no seeds, repeated names, truncated names) no declaration references. | pinned |
| R39-SUPPLY-CHAIN-13 | P3 | two on-chain IDLs | `address` field differs from the program read. | informational, pinned |
| R39-SUPPLY-CHAIN-14 | P3 | `CURRENT.md` K-7 | 64 → 65 Orca. | fixed in CURRENT |
| R39-SUPPLY-CHAIN-15 | — | `live-mainnet.yml` | The suspected seed fail-open: already fixed in Round 36. | not reproduced; now pinned by a test |

New tooling: `graphite-core/scripts/validate_corpora.py` (495 strict JSON + 2 JSONC files, schema
and semantic invariants, 63 pinned gaps, 13 seeded faults in its own test) runs in the ci-scripts job.

## 3. Prior findings re-verified at `c087bfb`

Each was re-checked against the code, not the report that closed it. Detail in the parts files' §3.

| ID / item | Status after Round 39 | Evidence |
|---|---|---|
| R37-1 / R38-1 sibling rule (swap, withdrawal) | holds, **widened** to the owner's keeping and to claim/close/configure | R39-CORE-DECISION-1, -2 |
| R37-2 legacy line before keyed genesis | holds | campaign 9 V1 |
| R37-3 unkeyed self-hashed forgery | holds | campaign 9 V2a–c |
| R37-4 retired key extends the trail | holds | campaign 9 V3 |
| R37-5 copied record at EOF | holds; the cross-trail variant at EOF was open → R39-CB-1 | campaign 9 V4–V5 |
| R37-6 unscoped authority lines | holds | `round38_unscoped_authority` 7/7, all waivers |
| R37-7 creation beyond rent; the double count | holds | `round38_create_funding`; campaign 3 |
| R37-8 release integrity | code half holds (52/52); owner half open and worse than documented | R39-SUPPLY-CHAIN-1 |
| R37-9 relayer / co-signer swap | holds; relayed swaps refused by L4 (a false-refusal class) | `round38_sibling_skims` |
| R37-10 transfer beside an unread program | holds | `a_transfer_beside_an_unread_program…` |
| R37-11 / T-9 backup and restore under keys | holds | `backup-keys.test.sh` 22/22 |
| R37-12 index forgery | holds | campaign 9 V8 |
| R37-13 vouched-key coverage | holds | unit test; re-read with R39-CB-5 |
| R37-14 prune records | holds | campaign 9 V10 |
| R37-15 / V-2 unknown `GRAPHITE_*` names | holds, server and CLI | campaign 10 |
| R37-16 program deployments | holds | code-reviewed; residual never executable |
| R37-17 guard lock directory | holds | `guard-round38.test.ts` |
| R37-18, DOC2-* | holds; three count slips found this round (K-7, residual count, CURRENT stale lines) | `docs_numbers_match_the_code` |
| T-6, T-11 … T-15, V-3, V-5, V-6 | hold | `t14` exit-code campaign; code review |
| B-5 | accepted limitation, unchanged | code-reviewed |
| B-6 | holds (Stake Withdraw); pool / Marinade amounts not compared (limitation) | campaign 2 |
| B-7 | holds | every `expect` behind a length check |
| B-8 | fails closed; quantified | R39-CORE-DECISION-4 |
| G2-2 | held except the leftover fixed as R39-CLIENTS-7 | |
| G2-3, G2-4, G2-5 | hold | guard tests |
| G2-6 | holds (dashboard bound; Windows guard half a documented limitation) | |
| D2-3 … D2-7, D-8, D-9 | hold | ci-scripts and release-gate suites |
| D2-8 per-binary Rust floors | still open: CI prints per binary, passes no floors file | remediation candidate |
| F-001 Zod bound | holds; SAK dev-tree override documented (R39-CLIENTS-2) | |
| F-003 / F-004 binding, withdrawal minimums | hold | campaigns 1–2 |
| F-005 nine medium rewrites | hold, not promoted; validator fails if one changes | owner sign-off pending |
| F-007 / S-5 lookup freshness | held for a present list; absent list open → R39-CORE-IDENTITY-2 | |
| F-008 / MR-1 … MR-6 / A3-07 registry | hold; MR-1 did not hold against dilution → R39-CORE-IDENTITY-1 | |
| F-009, F-014, F-017, F-019, F-020 | hold | |
| F-015 mutation assurance | still incomplete (no complete module score) | gate in the residual register |
| R36-D1 dashboard unread-as-zero | held for the counters; same class in audit/snapshot → R39-DASH-5 | |
| Round 35 unrebuildable parsed CPIs | hold: nine classes, never executable | `every_documented_unrebuildable_class_stays_inconclusive` |
| §2.2 item 8 (13 low-decode manifests) | same 13 | census |
| §2.2 item 9 / K-7 (75 slot differences) | holds, 65 Orca + 10 Kamino | census |
| §2.3 ALT last-extended-slot | fails closed (the simulation errs; deactivating tables refused) | campaign 5 |
| §2.3 no cumulative value cap | confirmed limitation | `risk_engine.rs` |
| §2.3 fresh-instance confidence | confirmed: 0.44, below every built-in profile | |
| §2.3 drainer as a coverage boundary | confirmed: plugin rules never reach Check 3 | campaign 12 |
| Single Core replica | holds on one host (compose + data-dir and trail locks); not enforceable across hosts sharing a volume (documented) | |
| Ids T-7, T-8, T-10, V-4 | no record of these ids in the repository | — |

## 4. Not done, and why

- **Real-traffic false-refusal rates** need a public RPC (`GRAPHITE_MAINNET_RPC_URL`), which this round
  may not contact: BLOCKED. The committed mainnet fixtures are verified without simulation, so L4 never
  runs on them.
- **Caddy, promtool and Docker** are not in this container; those checks ran green in PR CI only.
- **Mutation scores** were not re-run (a full run is about 260 runner-hours; see the residual register).
- **Windows** behaviour of the guard was reasoned, not run.
