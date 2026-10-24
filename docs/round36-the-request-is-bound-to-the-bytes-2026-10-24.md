# Round 36 — the request is bound to the bytes

> **Historical record.** This report describes the codebase at `2140427` (`main`, 2026-10-24) and
> the changes made on top of it on 2026-10-24. For the current state of Graphite see
> [`CURRENT.md`](CURRENT.md).

**Date:** 2026-10-24 · **Base:** `2140427` · **Branch:** `claude/admiring-archimedes-lfhr7n`
(PR [#53](https://github.com/Stan-lee13/graphite/pull/53)) · **Scope:** the owner's whole-repository
forensic audit, remediation and release-gate brief (findings F-001 to F-022). Internal engineering
work by the maintainer and AI engineering agents. **This is not an independent third-party audit
and not a certification.**

## Decision

**RELEASE BLOCKED** on owner and external gates. These are listed in §F, and none of them can be
closed from the code:

- `main` has no branch protection and no rulesets. The GitHub API returns `protected: false` and an
  empty rulesets list.
- Private vulnerability reporting is not enabled.
- There has been no independent audit.
- There is no production deployment, and no deployment has been operated.

The code is **conditionally ready for independent audit**. Every P0/P1 code finding in the brief
is fixed with a regression test or dispositioned below. The dependency gate that failed on the base
commit is green.

| Severity | At base `2140427` | After this round |
|---|---:|---:|
| P0 (code) | 0 | 0 |
| P1 (code) | 3: F-001 dependency DoS gate, F-003 unbound intent, F-004 dust minimum | 0 |
| P2 (code) | 8: F-005, F-008, F-009, F-013, F-014, F-017, F-019, F-020 | 0 open; the residuals are in §E |
| External / owner | F-002, private reporting, audit, deployment, live data, F-016 holdout | unchanged: STOP-SHIP |

## A. What changed for an operator

- **An approval is executable only when the request's amount, recipient and asset are the
  transaction's (F-003).**
  - What a `/verify` caller sends in `proposed_intent.extracted_parameters` is now compared with
    the bytes.
  - A disagreement is Blocked: `IntentMismatch`, or `SwapUnderbounded` when the swap's minimum is
    too low.
  - A request the Core cannot bind is `analysis_only` and carries the new residual
    `intent_parameters`. That covers a request with no parameters, a token named by symbol, a stake,
    or a route the Core does not decode.
  - `input_token` and `output_token` must be `"SOL"` or a mint address.
  - The agent guard already sends what binds. A direct API caller that sends nothing now gets
    `analysis_only` where it used to get `executable_approved`.
- **A withdrawal's minimum output is held to the simulation (F-004).**
  - A non-zero dust minimum is now `WithdrawalUnderbounded`. Before this round only a zero minimum
    was refused.
  - A Meteora DLMM remove, which carries no minimum, is never executable.
  - `GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS=1` waives both checks.
- **The server refuses to start on a misspelled `GRAPHITE_*` variable (F-020).** This applies only
  to a near-miss of a variable it reads; any other unknown `GRAPHITE_*` name is logged.
- **Deployments:**
  - **One replica.** The Core runs as one instance only: both compose files and the systemd unit
    enforce it (F-019).
  - **Image digest.** The image digest is a required, separate variable.
  - **Lost audit key.** After an audit key is lost, `backup.sh` and `restore.sh` take
    `--lost-key <id>`.
- **Agent guard:**
  - Every web3.js RPC call has a deadline, a 32 MiB body cap and no websocket
    (`GRAPHITE_RPC_TIMEOUT_MS`).
  - A verdict older than `GRAPHITE_MAX_VERDICT_AGE_MS` is not signed (default 150 s).

## B. Findings

Status vocabulary is the brief's. Each test named here fails on the base code and passes on this
branch; "fail-before" says how that was shown.

| ID | Finding | Class / severity | Status | Fix and test |
|---|---|---|---|---|
| F-001 | GHSA-mrhx-c7xc-m3w5 (Zod) failed the npm gate in the SAK adapter | availability / P1 | confirmed fixed with regression proof | The adapter no longer imports `solana-agent-kit`; it was dev-only and loaded LangChain, the OpenAI agents SDK and `zod/v3` at import. Zod is held at 4.6.7 by override everywhere, and every untrusted array was already bounded. Tests: an import trace (no Zod module loads), and a 2,000,000-element tool input refused on its bound in MCP and Vercel AI. Fail-before: Zod 4.6.5 raised "Maximum call stack size exceeded" / 2,000,001 issues. CI run [40054717819](https://github.com/Stan-lee13/graphite/actions/runs/40054717819): every job green, including the dependency audit |
| F-002 | No branch protection or rulesets on `main` | governance / STOP-SHIP | external STOP-SHIP | Owner action (§F) |
| F-003 | The Core compared no `ExtractedParameters` field: a 2,000,000-lamport transfer was `executable_approved` under a request for 0.003 SOL | confirmed vulnerability (raw API) / P1 | confirmed fixed with regression proof | `src/intent_binding.rs`. `tests/round36_intent_binding.rs` (22): wrong amount, recipient, asset or direction, TransferWithSeed, TransferChecked to the wrong ATA or program, TransferCheckedWithFee, Approve, Burn, a mixed transfer+approve, swaps (amount in, spend, other-token spend, delivery, dust minimum, slippage ceiling, exact-out, trailing bytes, two swaps), and every unbindable form. Each has its benign control |
| F-004 | A non-zero dust minimum passed a granted withdrawal | design weakness / P1 | confirmed fixed with regression proof | `intent_binding::bind_withdrawal`, `intent_grants::withdrawal_minimums`, `PRICE_EXPOSED_WITHOUT_MINIMUM`. Tests: `a_withdrawal_minimum_is_held_to_what_was_simulated`, plus the grant-table tests in `intent_grants` |
| F-005 | 18 withdrawal grants and the high-traffic swaps declared debits that name no account; honest flows were refused | false refusal / P2 | confirmed fixed with regression proof | 35 declarations rewritten from their IDLs (`docs/audit-r36/declaration-rewrites.json`). Census (3541, 1820, 1802, 1802, 18, 27) → (3541, 1780, 1767, 1767, 0, 27). The signer drains are still refused (`SignerLamportsOutsideDeclaredDebit`, same 5,000,000,000 lamports). Marinade `liquidUnstake` back to the signer is now `executable_approved`. The 9 medium-confidence rewrites (Stake Pool, Raydium AMM v4: no IDL file in the repository) need owner sign-off (§F) |
| F-006 | Unsupported CPI families | capability limitation / P2 | not changed; fails closed (verified) | `round35_parsed_inner_instructions` keeps the unrebuilt forms `Inconclusive` with the callees named; the docs list them. No new family was added this round |
| F-007 | Lookup-table freshness | design weakness / P3 | disposition: no false approval possible | Entries are append-only for a table's lifetime. Its address cannot be re-created after a close. A deactivating table is refused. Graphite's resolution must equal the simulator's `loadedAddresses` (S-5). Graphite does not apply the last-extended-slot rule itself; the simulator does |
| F-008 | Registry records kept no signatures | test/assurance gap / P2 | confirmed fixed with regression proof | `RegistryRecord::{signature_hex, attestation_signatures, signing_domain}`, `verify_offline`. Test: `an_accepted_record_verifies_offline_and_a_tampered_one_does_not`. The first-manifest self-replay limitation stands (SECURITY.md) |
| F-009 | Loader-v4 deployments were not read | coverage limitation / P2 | confirmed fixed with regression proof | `rpc_client::decode_loader_v4_header`, `ProgramDeployment::LoaderV4`. Test: `loader_v4_redeployments_withdraw_evidence` (redeploy withdraws evidence; retracted is named; an undefined status changes nothing) |
| F-010 | Witness is not a proof | claim check / P3 | verified: no overclaim found | Every surface (SECURITY, README, ARCHITECTURE, CURRENT, TS types, dashboard) says "two providers agreeing is not a light-client proof"; `inclusion_assurance` labels each case |
| F-011 | Intent coverage is 21 grants | capability limitation | unchanged; refused classes stay refused | Counts reproduced by the ledger: 137 manifests, 3,541 instructions, 46 unclassed, 13 under 90% decode |
| F-012 | Token-2022 / state-diff attribution | coverage limitation | unchanged; fail-closed paths unchanged | — |
| F-013 | Spend parity, concurrency, outcome unknown | integration footgun / P2 | confirmed fixed with regression proof | Guard: a send whose RPC never answers is now `SubmissionOutcomeUnknown` at the deadline, the reservation is kept and the identical repeat is refused (it used to hang). Parallel-reservation and swap-reserve proofs added (`guard-round35.test.ts`) |
| F-014 | web3.js `Connection` unbounded | availability / P2 | confirmed fixed with regression proof | `integrations/agent-guard/rpc-transport.ts`. 9 of the 12 new guard tests fail with enforcement reverted: hang, trickle, 33 MiB body, 429 retries, websocket, malformed timeout, stale verdict ×2, a send that never answers |
| F-015 | Mutation floors unmeasured | test/assurance gap | open | The weekly mutation job has never run on schedule. Dispatched on this branch for measurement (§D) |
| F-016 | 38-row holdout | data limitation | owner/external | No safety claim is made from it (§F) |
| F-017 | Durable nonce / verdict age | design weakness / P2 | confirmed fixed with regression proof | The guard never signs a durable-nonce transaction (existing tests). New verdict-age bound immediately before signing (`StaleVerdict`) |
| F-018 | Audit chain is not WORM | operational | owner/external | Anchors are a local directory until an operator points them at object-lock storage |
| F-019 | Single instance | operational / P2 | confirmed fixed with regression proof | `container_name` and `deploy.replicas: 1` in both compose files; a `scale: 2` or `replicas: 2` override fails to render; the systemd unit is not a template. Deploy tests 109 → 162 |
| F-020 | Environment strictness | integration footgun / P2 | confirmed fixed with regression proof | `operator_boundary::{CORE_ENV_NAMES, COMPONENT_ENV_NAMES, check_env_names}`. `tests/round36_env_names.rs` pins both lists to the repository and starts the real server with a misspelled switch |
| F-021 | Deploy rehearsal | operational | partially addressed | Rehearsed against the real binary: second Core, SIGTERM with a request in flight, full disk (tmpfs in a user namespace), lost audit key. Not rehearsed: real TLS/DNS, a Docker daemon, systemd running, WORM (§F) |
| F-022 | Stale docs | documentation mismatch | fixed | CURRENT, SECURITY, CHANGELOG and this report. Historical reports are unchanged |
| R36-L1 | `live-mainnet.yml`: a failed seed step read as success | correctness bug / P3 | fixed | The step now exits non-zero; the replay's seeded flag reads the exit code |
| R36-L2 | Dependency PRs #47/#48/#52 cannot compile | supply chain | owner decision: do not merge | Each bumps one of two crates that move in lockstep. Dependabot now ignores those majors, with the reason |
| R36-D1 | Dashboard showed unread figures as 0 / "clear" / "Operational" | false status / P2 | confirmed fixed with regression proof | `readBypass`, the em dash for "not read", "Not answering". Dashboard tests 31 → 35, plus `e2e/states.mjs` (126 failures before the fix) |

## C. Deliberate-break evidence

Every test above was run against the unfixed code. A broken implementation was built in an
isolated worktree or in a copy, never in the working tree. Where an agent did it, its report names
the reverted files and logs:

- F-001: Zod 4.6.5 reinstated in a copy.
- F-014/F-017: enforcement switched off.
- F-019/F-021: the base versions of the fixed files restored.
- Dashboard: source fixes removed.

F-003/F-004: the break run is recorded in §D.

## D. What was run

To be completed with the final run (exact SHA, counts, durations, CI URLs).

## E. Residuals, stated exactly

- The binding judges top-level instructions. A value transfer made only by CPI is judged by the
  state diff and the risk layers, as before, not compared with the request.
- The Core judges no price. A swap's minimum is held to its own simulation; a price floor is the
  guard's or the request's.
- Stake intents, unchecked token `Transfer`s without a simulated mint, and any swap outside the six
  decoded programs are `analysis_only`.
- Marinade `liquidUnstake`, Stake and Stake Pool withdrawals, and claims are not held to a minimum
  (reasons in CURRENT.md).
- The guard's subscriptions on the connection it hands out now throw. No adapter uses them.

## F. Owner and external gates (STOP-SHIP)

1. Apply the `main` and release rulesets (`docs/ops/branch-protection.md`) and confirm them through
   the API.
2. Enable private vulnerability reporting. The contact change in `2140427` does not enable it.
3. Close dependency PRs #47, #48 and #52 (they cannot compile, §B).
4. Sign off the 9 medium-confidence declaration rewrites (`declaration-rewrites.json`, `confidence:
   medium`).
5. Deploy to real infrastructure: TLS/DNS, secrets, monitoring and on-call, backups with a restore
   drill, WORM anchors.
6. Choose independent RPC providers for L8 high assurance.
7. Authorize a fresh read-only live-mainnet replay to measure the false-refusal cost of this round's
   stricter binding.
8. Build a larger independent holdout. No safety claim is made from the 38-row holdout.
9. Arrange the independent third-party audit.
10. Decide on Constitution P12 versus the drainer's refusal of unmanifested multi-account
    instructions, which is still open.
