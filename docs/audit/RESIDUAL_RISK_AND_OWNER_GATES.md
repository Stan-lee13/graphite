# Round 39 — residual risk and owner gates

What still stands between this code and a release, after Round 39. Each item says who can close it,
how, and how to check that it is closed. Nothing here was changed by this round on GitHub or
anywhere outside the repository. This is internal engineering work: it is not an independent audit
and not a certification, and Graphite is not production ready until the gates in §1 are closed.

**Code remediation status:** every P0-class, P1 and P2 code finding of Round 39 is fixed with a
regression test and a deliberate break, or kept fail-closed pending an owner decision (§2).
**Release remains blocked by:** G-1 (live rulesets and `release` environment), G-2 (a release
signing key), G-3 (private vulnerability reporting), G-4 (an independent third-party audit) and G-5
(a deployment run and checked by an operator) — §1.

## 1. Release gates (owner or external)

| Gate | What is open | Who | How to close | How to check |
|---|---|---|---|---|
| **G-1** Live rulesets and `release` environment — R39-SUPPLY-CHAIN-1 (P1), R37-8 | On 2026-10-25 the only ruleset is the uncommitted `Main-review` (id 25817024): 0 approvals, 26 `always` bypass actors (roles 2 and 5, 24 GitHub Apps); no tag rulesets; the `release` environment could not be read (not verified). Anyone holding one of those apps' tokens can push to `main`; anyone with write access can tag a release. | repository admin | `docs/ops/branch-protection.md` §1–3; checklist R1, R2 (import the four committed rulesets under their names, delete `Main-review`, create the environment with you as reviewer and the `v*` tag policy) | `ruleset-drift.py --live <dir> --require-bypass` as admin (`branch-protection.md` §3) exits 0; Actions → Ruleset drift is green; a write-only collaborator's `v*` tag push is rejected |
| **G-2** Release signing key | `.github/allowed_signers` is empty by design: every release fails at the gate | owner | checklist R3 (one PR adding the key line, with `valid-before`) | checklist R4: an unsigned tag, a tag off `main` and a tag older than `ad3f7ad` are each stopped |
| **G-3** Private vulnerability reporting — R39-SUPPLY-CHAIN-9 | off; security contact is e-mail only | repository admin | checklist item 2 (enable, then one PR pointing `.github/ISSUE_TEMPLATE/config.yml` and `SECURITY.md` at the advisory form) | `gh api repos/Stan-lee13/graphite/private-vulnerability-reporting` → `{"enabled": true}` |
| **G-4** Independent third-party audit | none has been done; every round so far, this one included, is internal | owner, external auditor | checklist item 3; hand over `docs/audit-handoff/` and this round's `docs/audit/` | a published report and its fixes |
| **G-5** Deployment | not deployed anywhere; Caddy, promtool and Docker checks ran only in PR CI | operator | checklist item 9 (`deploy/tests/run.sh` on the configuration to ship; verify the release by digest, checklist 10e) | `deploy/tests/run.sh` green on that host; `graphite healthcheck --strict` |

Also on the checklist, not release-blocking by itself but owed before a public claim: item 7 (measured
mutation-score floors — F-015, still no complete module score), item 8 (benchmark wording), item 10b
(release rehearsal), item 10c (`publish = false` or not in `graphite-core/Cargo.toml`), the
Dependabot holds of item 6, and K-14 stale branches.

## 2. Owner decisions (fail-closed meanwhile)

None of these was decided by this round. Each is left in its safer state.

| ID | Decision | Current behaviour | Options | What would change |
|---|---|---|---|---|
| R39-CORE-DECISION-4 | Rewrite the swap declarations that refuse honest swaps | 101 of 115 swap/route declarations refuse an honest swap (93 declare a debit naming no account; 8 declare nothing L4 can read). Raydium CPMM `swap_base_input`, Meteora DAMM v2 `swap`, Orca `swap`/`swapV2` are refused end to end. | (a) keep refusing; (b) rewrite from the committed IDLs (`scripts/idls/raydium_cpmm.json`, `orca-whirlpools.json`, `jupiter.json`) with each rewrite reviewed like the nine medium ones | the census test in `round39_decision_campaigns.rs` would change; each rewritten declaration needs a manifest review |
| R39-CORE-DECISION-5 | `update_offer` (configure grant) can never pass | `UndeclaredTokenDebit` on every call, honest or not | declare its debit, or drop the grant | one manifest change |
| R39-CB-8 | `GRAPHITE_TRUST_PROXY` trusts `X-Forwarded-For` from any peer; in the prod compose the `ai` service shares the backend network and could choose its own rate-limit bucket | as documented in `.env.example` and `docs/ops/install.md` | (a) a trusted-proxy address allowlist (code change); (b) a Core-only network between Caddy and Core (compose change) | rate-limit isolation between the AI layer and other callers |
| R39-CB-13 | The RPC client honours `HTTP(S)_PROXY`; the connect-time address guard then sees only the proxy | proxies honoured | (a) ignore env proxies (`.no_proxy()`); (b) allow them, documented as trusted infrastructure | whether a deployment behind a proxy needs a new setting |
| R39-CORE-IDENTITY-7 | First-manifest validation | a first manifest is checked only against fixtures recorded under itself | four strategies in `parts/core-identity.md` §2.7; each needs a bar only the owner sets | how a new protocol enters the registry |
| R39-SUPPLY-CHAIN-11 | Phantom discriminators | Meteora / Jupiter / Squads manifests carry `swap_2` beside the real `swap2` and 27 discriminators in no instruction of the committed IDL; harmless (never matched by real traffic) but misleading | remove them in a manifest PR, or keep and label | manifests only |
| F-005 | The nine medium-confidence rewrites | not promoted; `validate_corpora.py` fails if one changes | sign off each, or keep them medium | the confidence a call through them can reach |
| Checklist 4, 5 | Round 32 refusal defaults; R-M9; `GRAPHITE_QUARANTINE_ON_UPGRADE`; self-heal threshold | refusal defaults on | keep, or relax after measuring against real traffic | false-refusal rate vs. protection |

## 3. Accepted limitations (tested, fail-closed or bounded)

| Item | Limitation | Why accepted | Where pinned |
|---|---|---|---|
| Fresh-instance confidence | a fresh instance scores 0.44, below every built-in profile, so nothing is executable until a program has an L3 baseline (or an operator lowers the profile) | conservative by design; it is also the precondition that kept R39-CORE-DECISION-1/-2 from being reachable on a fresh instance | `PRODUCTION_READINESS_FINDINGS.md` §2.1 |
| Relayed / co-signed swaps | refused by L4 | safer than inferring whose value it is | `round38_sibling_skims` |
| B-5 in-transaction price manipulation | not modelled | needs a pricing oracle Graphite does not have | CURRENT |
| No cumulative value cap across calls to an unmanifested program | per-transaction only | stateful policy is outside the verifier | `risk_engine.rs`, CURRENT |
| No per-plugin timeout | a slow plugin delays the verdict; it never lifts one | delay, not bypass | campaign 12 |
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
| Real-traffic false-refusal rates | needs a public RPC, which this round may not contact | `GRAPHITE_MAINNET_RPC_URL=… cargo test --test mainnet_transfer_fee_live -- --ignored`; `.github/workflows/live-mainnet.yml` |
| Mutation scores (F-015) | about 260 runner-hours for a full run | the weekly mutation job; then checklist item 7 |
| Execution-level differential against a bank (R39-CORE-IDENTITY-6) | not built; the runtime oracle covers the decoder and sanitizer only | a harness replaying artifacts through a bank |
| Coverage-guided runtime side of the oracle | the generator is not coverage-guided there | cargo-fuzz harness linking the oracle |
| Windows behaviour of the guard (locks, file permissions, R39-CLIENTS-6) | no Windows runner here | a Windows CI job for `integrations/agent-guard` |
| HTTP/CLI JSON and dashboard rendering over the shared conformance corpus | only the four library implementations run it | drive `examples/decisions/conformance.json` through the server and the dashboard |
| The `release` environment's configuration | the session token could not read it | G-1 check above, as admin |
| CI on the `main` push of `c087bfb` (run 40182789822) | queued during this round; the same tree was green in PR CI (40152966496) | Actions → that run |

## 5. Recorded, no change

R39-CB-14 (the registry signer key file is read without the audit key's permission check), R39-CB-15
(`graphite explain` prints caller strings unescaped to the terminal), R39-SUPPLY-CHAIN-6 (pin and run
actionlint ≥ 1.7.11), R39-SUPPLY-CHAIN-12 and -13 (manifest labels; IDL `address` fields), D2-8
(per-binary Rust floors are printed but no floors file is passed), and the P3 observations of
`PRODUCTION_READINESS_FINDINGS.md` §2.1. Each is a candidate for a later round; none lets a refusal
become executable.
