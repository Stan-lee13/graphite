# Round 39 — residual risk and owner gates

What still stands between this code and a release, after Round 39. Each item says who can close it,
how, and how to check that it is closed. Nothing here was changed by this round on GitHub or
anywhere outside the repository. This is internal engineering work: it is not an independent audit
and not a certification, and Graphite is not production ready until the gates in §1 are closed.

**Code remediation status:** every P0-class, P1 and P2 code finding of Round 39 is fixed with a
regression test and a deliberate break, or kept fail-closed pending an owner decision (§2).
**Release remains blocked by:** G-1 (live rulesets and `release` environment), G-2 (a release
signing key), G-3 (private vulnerability reporting), G-4 (an independent third-party audit) and G-5
(a deployment run and checked by an operator) — §1. Since 2026-10-30: G-3 is closed and G-1's rulesets are applied (its bypass lists
and the `release` environment await the admin read).

## 1. Release gates (owner or external)

| Gate | What is open | Who | How to close | How to check |
|---|---|---|---|---|
| **G-1** Live rulesets and `release` environment — R39-SUPPLY-CHAIN-1 (P1), R37-8 | **Rulesets applied 2026-10-30**: the four committed rulesets are live and `active`, and `ruleset-drift.py` reports each matching the committed files (read without admin rights); `Main-review` is deleted. **Still open**: the bypass lists and the `release` environment, which only an admin read can verify. Before: on 2026-10-25 the only ruleset is the uncommitted `Main-review` (id 25817024): 0 approvals, 26 `always` bypass actors (roles 2 and 5, 24 GitHub Apps); no tag rulesets; the `release` environment could not be read (not verified). Anyone holding one of those apps' tokens can push to `main`; anyone with write access can tag a release. | repository admin | `docs/ops/branch-protection.md` §1–3; checklist R1, R2 (import the four committed rulesets under their names, delete `Main-review`, create the environment with you as reviewer and the `v*` tag policy) | `ruleset-drift.py --live <dir> --require-bypass` as admin (`branch-protection.md` §3) exits 0; Actions → Ruleset drift is green; a write-only collaborator's `v*` tag push is rejected |
| **G-2** Release signing key | `.github/allowed_signers` is empty by design: every release fails at the gate | owner | checklist R3 (one PR adding the key line, with `valid-before`) | checklist R4: an unsigned tag, a tag off `main` and a tag older than `ad3f7ad` are each stopped |
| **G-3** Private vulnerability reporting — R39-SUPPLY-CHAIN-9 | **closed 2026-10-30**: enabled (`{"enabled": true}`, read back); `SECURITY.md` and the issue template point at the advisory form, e-mail as the fallback. Was: off; e-mail only | repository admin | checklist item 2 (enable, then one PR pointing `.github/ISSUE_TEMPLATE/config.yml` and `SECURITY.md` at the advisory form) | `gh api repos/Stan-lee13/graphite/private-vulnerability-reporting` → `{"enabled": true}` |
| **G-4** Independent third-party audit | none has been done; every round so far, this one included, is internal | owner, external auditor | checklist item 3; hand over `docs/audit-handoff/` and this round's `docs/audit/` | a published report and its fixes |
| **G-5** Deployment | not deployed anywhere; Caddy, promtool and Docker checks ran only in PR CI | operator | checklist item 9 (`deploy/tests/run.sh` on the configuration to ship; verify the release by digest, checklist 10e) | `deploy/tests/run.sh` green on that host; `graphite healthcheck --strict` |

Also on the checklist, not release-blocking by itself but owed before a public claim: item 7 (measured
mutation-score floors — F-015, still no complete module score), item 8 (benchmark wording), item 10b
(release rehearsal), item 10c (`publish = false` or not in `graphite-core/Cargo.toml`), the
Dependabot holds of item 6, and K-14 stale branches.

## 2. Owner decisions — decided in Round 40

The owner delegated every decision below to the technical lead on 2026-10-25. Each is recorded,
with its options, reason and Constitution principles, in
[`TECHNICAL_LEAD_DECISIONS.md`](TECHNICAL_LEAD_DECISIONS.md), and implemented with tests
([`parts-r40/`](parts-r40/)):

| ID | Decided | Status |
|---|---|---|
| R39-CORE-DECISION-4 | swap declarations rewritten from the committed IDLs (60); 26 left with reasons | done |
| R39-CORE-DECISION-5 | the `update_offer` grant removed (its IDL never says the USDC moves) | done |
| R39-SUPPLY-CHAIN-11 | 23 instructions no committed IDL has removed; the 5 Squads ones kept (the committed IDL has them) | done |
| F-005 | 7 of the 9 medium rewrites promoted with recorded evidence; Stake Pool `WithdrawSol*` stay medium | done |
| Fresh-instance confidence | `graphite evidence import-census --cluster mainnet-beta` (D-6) | done |
| R39-CB-8 | `GRAPHITE_TRUSTED_PROXIES`, refusing to start without it when proxy trust is on | done |
| R39-CB-13 | RPC and witness clients ignore environment proxies | done |
| R39-CORE-IDENTITY-7 | a first registry manifest capped at `HeuristicInferred` | done |
| Checklist 4, 5 | Round 32 refusal defaults kept; R-M9 kept with its reasoning; upgrade quarantine stays opt-in; no automatic self-heal quarantine | decided, no change |

## 3. Accepted limitations (tested, fail-closed or bounded)

| Item | Limitation | Why accepted | Where pinned |
|---|---|---|---|
| Fresh-instance confidence | a fresh instance scores 0.44, below every built-in profile; one explicit operator command, `graphite evidence import-census --cluster mainnet-beta`, imports the measured census and lifts a manifested program to 0.59 (Gaming only); the stricter profiles need earned simulation evidence (training tops out at 0.75 on an OfficialManifest tier) | conservative by design; every Round 38/39 attack was re-run in the imported and trained states and is refused | `parts-r40/bootstrap.md` |
| Relayed / co-signed swaps | refused by L4 | safer than inferring whose value it is | `round38_sibling_skims` |
| B-5 in-transaction price manipulation | not modelled | needs a pricing oracle Graphite does not have | CURRENT |
| No cumulative value cap across calls to an unmanifested program | per-transaction only | stateful policy is outside the verifier | `risk_engine.rs`, CURRENT |
| Plugin deadline | a plugin that overruns its 250 ms deadline is treated as crashed (a blocking family refuses, a note family notes); at most 16 overrunning runs are left behind before the orchestrator refuses outright | a thread cannot be killed safely; the bound keeps abandoned work finite | campaign 12, `plugin_orchestrator.rs` |
| R39-CB-5 reader memory | 59 MiB at 1,000,000 adopted unkeyed records | adopt a key early or prune | ignored measurement test |
| R39-CB-9 hot backup | may include a record whose write later failed | restore over-records, never under-records | `backup.sh` |
| R39-CB-10 refused-connection drain | ≤ 1 MiB, ≤ 1 s | bounded | `server.rs` |
| R39-CB-11 trail front | a trail cut at the front or with a tampered first record still starts; `audit verify` or a checkpoint reports it | detecting it needs an anchor kept elsewhere | `docs/ops/keys.md` |
| Newest tail / restored old backup | detectable only against an anchored checkpoint stored elsewhere | the immutability of that storage is the operator's | `docs/ops/keys.md` |
| Unkeyed trail | cannot tell two trails apart | no MAC to compare | `durable.rs` |
| Absent `loadedAddresses` | an RPC that strips it refuses every v0 transaction with lookups | fail closed (Agave returns it) | `round39_lookup_table_campaign.rs` |
| ALT last-extended-slot | delegated to the simulator | the simulation errs; deactivating tables refused | campaign 5 |
| Confidential Token-2022 state | refused | cannot be judged without keys | Token-2022 suites |
| Nine unrebuildable parsed-CPI classes | always Inconclusive | never executable | `round35_parsed_inner_instructions` |
| R39-CLIENTS-2 SAK dev tree | the Zod 4 override breaks SAK's own `createOpenAITools` in the dev tree | dev-only; the published adapter is unaffected | `zod-override.test.ts` |
| R39-SUPPLY-CHAIN-8 | `release-guard.yml` watches tag-push runs only | `--source-ref` refuses a branch run's attestations; G-1 is the stop | checklist |
| Single Core replica | enforced on one host (compose, data-dir and trail locks), not across hosts sharing a volume | documented | `docs/ops/install.md` |

## 4. Evidence not obtained

| Claim | Why not shown | How to obtain |
|---|---|---|
| Real-traffic approval and false-refusal rates | **measured for simple transfers in Round 40**: run 40839253280 (PR #55, census imported) built 28 honest 1-lamport / 1-base-unit transfers from real senders and gave 27 `executable_approved`; the one `blocked` was a transfer the simulator showed would fail on chain. The replay of 200 other transactions in the same run had 0 server errors, p50/p99 208/430 ms. **Round 41**: run 41155961160 (PR #61, after D-19 to D-26 and the swap venues' census re-measure): 36 of 36 honest transfers and 2 of 2 re-quoted honest Jupiter v6 swaps `executable_approved`. Still open: two swaps is a small sample; run 41154452231 refused four honest SOL → Token-2022 Jupiter routes through Pump AMM with the route unbound; a small SOL-out unwrap whose fee exceeds the slippage margin is `SwapUnderbounded`; other protocol calls are not measured | `.github/workflows/live-mainnet.yml`; [`../evidence/live-mainnet/run-40839253280.md`](../evidence/live-mainnet/run-40839253280.md); [`../evidence/live-mainnet/run-41155961160.md`](../evidence/live-mainnet/run-41155961160.md) |
| Mutation scores (F-015) | shards re-sized in Round 40 to fit the step (≤ 20 mutants each); not yet dispatched (~210–290 runner-hours) | Actions → Assurance → Run workflow; then checklist item 7 |
| Execution-level differential against a bank (R39-CORE-IDENTITY-6) | not built; the runtime oracle covers the decoder and sanitizer only | a harness replaying artifacts through a bank |
| Coverage-guided runtime side of the oracle | the generator is not coverage-guided there | cargo-fuzz harness linking the oracle |
| Windows behaviour of the guard (locks, file permissions, R39-CLIENTS-6) | **closed in Round 40**: the `agent-guard-windows` CI job runs the guard's suite on a pinned Windows image (green) | — |
| HTTP/CLI JSON and dashboard rendering over the shared conformance corpus | **closed in Round 40**: `tests/round40_surface_conformance.rs` and `dashboard/src/conformance.test.ts` | — |
| The `release` environment's configuration | the session token could not read it | G-1 check above, as admin |
| CI on the `main` push of `c087bfb` (run 40182789822) | queued during this round; the same tree was green in PR CI (40152966496) | Actions → that run |

## 5. Recorded

R39-SUPPLY-CHAIN-13 (two on-chain IDLs' `address` field differs from the program read; informational)
and the P3 observations of `PRODUCTION_READINESS_FINDINGS.md` §2.1 remain recorded. Since Round 40:
R39-SUPPLY-CHAIN-6 (actionlint pinned and run), D2-8 (per-binary floors) and R39-SUPPLY-CHAIN-12
(label fixes) are done; R39-CB-14 (registry signer key permissions) and R39-CB-15 (escaped terminal
output) are done. None lets a refusal become executable.
