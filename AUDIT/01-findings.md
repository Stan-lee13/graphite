# AUDIT 01 — Findings and fixes (2026-09-29 → 2026-10-03)

This file lists every finding from the six audit areas mapped in [`00-map.md`](00-map.md), how it was classified, what was changed at its root, and the test that proves the change. The audits were internal: sub-agents plus the maintainer's own passes. **They are not an independent third-party audit** (see `docs/CURRENT.md`, "Independent third-party audit: NOT PERFORMED").

Every fixed finding has a regression test that **failed on `3327fcf`** and passes on the fix. Each fix was reverted once while the tree was otherwise unchanged, and the test was re-run to show it fails again. That break log is in [§ Break log](#break-log). The before and after runs of the audit test set are in `graphite-audit-work/logs/audit_run1_BEFORE_fixes.log` and `audit_run2.log`, outside the repository.

Severity scale:

| Class | Meaning |
|---|---|
| **P0** | Funds can be lost with no precondition beyond sending a request. |
| **P1** | A harmful transaction can be approved. |
| **P2** | A security invariant or stated guarantee is broken, but the verdict is still refused, or reaching it needs a strong precondition. |
| **P3** | Correctness, robustness, or an evidence or honesty gap. |
| **NOT A FINDING** | Checked; the behaviour is correct or fails closed. |
| **DOCUMENTED LIMITATION** | Already stated in the live docs. |
| **COVERAGE GAP** | No defect shown, but nothing tests it. |

No finding was raised above what its evidence showed. Where the audit agent could not demonstrate an end-to-end approval, the finding says so.

## Summary

| Area | P0 | P1 | P2 | P3 | Fixed | Owner decision | Coverage gap |
|---|---|---|---|---|---|---|---|
| A1 Parser and identity | 0 | 1 | 1 | 2 | 4 | – | – |
| A2 Simulation and state diff | 0 | 0 | 7 | 3 | 10 | – | 1 (A2-08) |
| A3 Manifests, risk, confidence, policy, plugins, registry | 0 | 3 | 2 | 6 | 11 | – | – |
| A4 RPC, server, audit log | 0 | 0 | 4 | 8 | 12 | – | – |
| A5 AI boundary, SDKs, bridge, dashboard, Python | 0 | 0 | 2 | 5 | see § A5 | – | – |
| A6 CI, supply chain, container, docs | 0 | 0 | 4 | 30 | see § A6 | A6-15, A6-16, A6-36 | A6-02, A6-05 |

No P0 was found. The four P1 findings (A1-01, A3-01, A3-02, A3-03) were each confirmed by a test that produced `approved: true`, or a Clear risk verdict, for a harmful transaction on `3327fcf`.

---

## A1 — Wire parser and instruction identity

### A1-01 — P1 — A token-account close with a trailing data byte escaped both close checks — FIXED
- **Root cause.** `self_refund_closes` and the drainer checks recognised `CloseAccount` only when the data was exactly `[9]` (`ix.data.len() != 1`). The SPL Token and Token-2022 programs read the first byte and ignore the rest, so `[9, 0]` is a close to agave but was not a close to Graphite. A primary self-refund close plus a declared sibling close of the victim's wSOL account to the attacker came out Clear.
- **Fix.** Identity is decided by the leading byte alone, as the runtime decides it. The length condition is gone (`verification.rs`, `self_refund_closes`).
- **Test.** `tests/audit_a1_close_trailing_byte.rs`.

### A1-02 — P2 — Compute Budget instructions with trailing bytes were skipped, understating the priority fee — FIXED
- **Root cause.** agave decodes Compute Budget data with `try_from_slice_unchecked`, which ignores trailing bytes. Graphite treated any length mismatch as undecodable, so the `ExcessivePriorityFee` bound could read a fee near zero while the payer was charged about 1.4 SOL.
- **Fix.** Only data too short to decode is a problem. Trailing bytes are accepted, matching the runtime (`tx_artifact.rs`, `compute_budget_request`).
- **Test.** `tests/audit_a1_compute_budget_trailing.rs`. `tests/round21_open_list.rs` was updated for the corrected rule.

### A1-03 / A3-09 — P3 — A non-ASCII program id on a sibling or CPI-trace node panicked the pipeline — FIXED
- **Root cause.** `risk_engine.rs` and `tx_pattern_analysis.rs` sliced ids at byte 8. Sibling and trace identifiers were never validated. The panic gave a 500 with no verdict and no audit row.
- **Fix.** Two changes, both at the source:
  1. `validate_identifiers` refuses, before the pipeline runs, any identifier that is non-ASCII, contains a control character or is over 44 characters (discriminators may be up to 128). It also bounds the accounts per instruction (256), CPIs per sibling (32), and the CPI trace (depth 16, 4,096 nodes).
  2. Every display slice goes through the char-safe `risk_engine::short_id`.
- **Tests.** `tests/audit_a1_sibling_program_id_utf8_panic.rs`, `tests/audit_a3_non_ascii_program_id_panics.rs`.

### A1-04 — P3 (unverified reachability) — p-token's batch instruction (`0xff`) as a sibling met no risk check — FIXED
- **Fix.** `ff` on SPL Token and Token-2022 is in `RISKY_PATTERNS`. A batch carries arbitrary inner token instructions, so it is judged the way its most dangerous content could be.
- **Test.** `tests/audit_a1_token_batch_sibling.rs`.

### A1-05 — NOT A FINDING
- A nonce account loaded through an address lookup table cannot be a durable nonce: agave requires the nonce account to be a static key. Graphite's refusal matches that. The test `tests/audit_a1_nonce_account_from_lookup_table.rs` is kept as a pin.

---

## A2 — Simulation integrity (L3) and state diff (L4)

### A2-01 — P2 — The declared-effects parser read account NAMES as effects and applied them to the whole transaction — FIXED
- **Root cause.** `DeclaredEffects::parse` substring-matched every `expected_state_changes` string, including the generated `modifies writable accounts: pool, owner, lpmint, …` line. An account named `owner` or `authority` switched off the owner, delegate, close-authority, SPL-authority, mint-authority and freeze-authority detectors for every account in the transaction. This affected 417 instructions for authority, 232 for mint, and 133 for debit.
- **Fix.** Declared effects are rewritten as scoped declarations:
  - Effect words are matched on word boundaries.
  - The `modifies writable accounts:` list is an enumeration of names, not verbs, and is ignored as a source of effects.
  - `accounts.<name>` references scope an effect to the accounts it names (`covers(effect, names)`), and `check_state_diff` maps each delta's pubkey to its account names.
  - An authority, owner, delegate, close-authority, mint-authority or freeze-authority change on an account the declaration does not name stays Critical. Debits are scoped by the signer rule added after review (F2 below).
- **Test.** `tests/audit_a2_declared_effects_account_names.rs`.

### A2-02 — P2 — A raised allowance to an existing delegate was invisible — FIXED
- **Fix.** L4 compares `delegated_amount` as well as the delegate. An increase is `UndeclaredDelegateGrant` unless the declaration names it.
- **Test.** `tests/audit_a2_delegate_allowance_increase.rs`.

### A2-03 — P2 — A Token-2022 permanent-delegate drain was invisible when the drained account had no account-side extension — FIXED
- **Root cause.** The mint was fetched only for accounts that carried a transfer-fee extension, so a permanent delegate on the mint was never read.
- **Fix.**
  - `transfer_fee_mints_to_fetch` fetches the mint of every Token-2022 token account in the diff.
  - A mint that cannot be read is `Token2022MintUnread`, which is Critical.
- **Test.** `tests/audit_a2_permanent_delegate_unread_mint.rs`.

### A2-04 — P2 — A caller-supplied diff displaced L4's structural hard gate — FIXED
- **Root cause.** Attaching `state_diff: {deltas: []}` replaced the structural check, turning L4 from Failed into Inconclusive.
- **Fix.** L4 matches on `(observed_diff, caller_diff)`. With a caller diff and no observed diff, both the diff check and the structural check run, and a structural Failed wins.
- **Test.** `tests/audit_a2_caller_diff_displaces_structural_gate.rs`.

### A2-05 — P2 — L4 was blind to any data change on an account that is not an SPL token account or mint — FIXED
- **Root cause.** `AccountSnapshot` kept the data length and the decoded token views only, so any other data change compared equal.
- **Fix.** `AccountSnapshot` now carries three more things:
  - `data_sha256`.
  - The `executable` flag.
  - The native authorities at their fixed offsets: the Stake staker, withdrawer and lockup custodian, and the ProgramData upgrade authority.

  L4 raises three new findings: `ExecutableChanged`, `UndeclaredNativeAuthorityChange` and `AccountReallocated`. A declared-read-only account whose data hash changed is no longer "observed unchanged".
- **Test.** `tests/audit_a2_data_only_change_is_not_noop.rs`.

### A2-06 — P2 — Mature L3 baselines could be widened by un-flagged observations — FIXED
- **Root cause.** Welford updates took every in-band sample at full weight. A variance ratchet turned a 1.5× band into an 8× band in about 600 self-generated transactions.
- **Fix.** After `MIN_SAMPLES`, each observation is winsorized to the current band before it updates the baseline, so in-band noise cannot widen it.
- **Test.** `tests/audit_a2_baseline_variance_ratchet.rs`.

### A2-07 — P3 — The shadow accumulator accepted observations of refused requests — FIXED
- **Fix.** A shadow observation is recorded only when nothing failed structurally and the only thing blocking was the simulation flag itself.
- **Test.** `tests/audit_a2_shadow_takes_refused_requests.rs`.

### A2-08 — COVERAGE GAP — L3 compares whole-transaction simulations keyed by program id
- **Round 30 (R30-B-2):** closed — baselines are kept per transaction shape (program, instruction, the other top-level programs), judged once mature and anchored where they matured (`tests/round30_trust_learning.rs`).
- The baseline measures the caller's composition, not the program's own behaviour, so it cannot see the per-instruction attack its module doc names. This is recorded as a design gap in [`02-roadmap-gap.md`](02-roadmap-gap.md). No approval path was shown, because L3 can flag but never certify.

### A2-09 — P3 — An RPC diff without balance arrays reported Passed with coverage silently skipped — FIXED
- **Fix.** An `RpcSimulated` diff without full writable coverage and without artifact balances is Inconclusive.
- **Test.** The unit test `verification::tests::an_rpc_diff_without_balance_arrays_is_not_a_pass`.

### A2-10 — P3 — The fee-replay disclosure could overflow a `u64` sum in debug builds — FIXED
- **Fix.** Sums use `u128` and checked arithmetic.
- **Test.** `tests/audit_a2_fee_replay_gross_sum_overflow.rs`.

### A2-11 — P2 — Deep `stackHeight` runs in a simulation response overflowed the stack — FIXED
- **Fix.** Inner instructions beyond agave's `MAX_INSTRUCTION_TRACE_LENGTH` (64), or with a `stackHeight` outside `2..=9` (agave's maximum under SIMD-0268), are refused. The CPI tree is then not built, and the diff is not trusted.
- **Test.** `tests/audit_a2_deep_inner_instructions_abort.rs`.

---

## A3 — Manifests, risk engine, confidence, policy, plugins, registry

### A3-01 — P1 — An authority or delegate hand-over passed as the primary when its intent keyword appeared in the manifest's prose — FIXED
- **Root cause.** There were two causes.
  - The unconditional table held seven entries.
  - The intent match was a keyword search over the manifest's own text. For example, "stake" matched Stake `Authorize`, and "transfer" matched loader `SetAuthority`. `revoke` also shared a canonical class with `approve`.
- **Fix.** The fix works at three levels:
  1. **The table.** `RISKY_PATTERNS` now covers every native hand-over family, and each of them blocks under any intent:
     - SPL Token and Token-2022 `ApproveChecked` (`0d`) and batch (`ff`).
     - System `AssignWithSeed` (`0a000000`) and `AuthorizeNonceAccount` (`07000000`).
     - Stake `Authorize`, `SetLockup`, `AuthorizeWithSeed`, `AuthorizeChecked`, `AuthorizeCheckedWithSeed` and `SetLockupChecked`.
     - BPF Upgradeable `Upgrade`, `SetAuthority` and `SetAuthorityChecked` as AuthorityHijack, and `Close` as Drainer.
     - Vote authority and withdraw instructions.
  2. **The class.** Check 2b blocks any manifest instruction whose derived security class is `authority_change`. That class is not read from the manifest. It is derived from the instruction's name by `names_an_authority_change`, which splits the name into words and looks for authority, admin, owner, ownership or governance. It is a floor under the manifest's own tag, so the next onboarding cannot mistag it.
  3. **The vocabulary.** `revoke` is now its own intent class.
- **Tests.** `tests/audit_a3_authority_handover_primary.rs`, plus the revoke-versus-approve tests appended to the audit set.

### A3-02 — P1 — The same hand-over as a declared sibling was caught only if its manifest tagged it — FIXED
- **Fix.** Siblings are judged through the same `security_class()` as primaries, so the two cannot disagree.
- **Manifest validation.** Validation now refuses three things at load and at registry submission:
  - a `risk_class` outside `RISK_CLASSES`;
  - an empty discriminator, unless it is the program's only instruction;
  - a PDA seed that references its own slot.

  The seed manifests carrying out-of-vocabulary classes (`jupiter-dca`, `squads-v4`, `system-program`, `bpf-loader-upgradeable`) were retagged.
- **Tests.**
  - `tests/audit_a3_authority_handover_sibling.rs`.
  - `tests/audit_a3_manifest_lint.rs`, which covers the vocabulary, self-seeds and `every_instruction_is_addressable`.
  - The loader-refusal tests.

### A3-03 — P1 — Quarantine blocked only the primary instruction's program — FIXED
- **Fix.** `invoked_programs` collects every program the transaction reaches:
  - the primary;
  - the declared siblings;
  - the declared CPI targets and trace nodes;
  - the observed CPI callees and tree.

  The quarantine gate blocks on any of them, with the pattern `ProgramQuarantined`.
- **Test.** `tests/audit_a3_quarantine_primary_only.rs`.

### A3-04 — P2 — An instruction missing from its manifest scored like a described one — FIXED
- **Fix.** Two changes:
  - An instruction a known protocol does not describe gets the `Unknown` trust tier, which fails every built-in profile's tier floor.
  - IntentAlignment credits only a **Passed** L5 (1.0). Failed gives 0.3, and anything else gives 0.
  - This also fixes A5-06: caller or AI intent text no longer earns alignment for a check that did not run.
- **Test.** `tests/audit_a3_unknown_instruction_confidence.rs`.

### A3-05 — P2 — A protocol plugin, even a crashing one, disarmed the drainer check (fail-open) — FIXED
- **Fix.** The risk engine's view of expected state changes is taken **before** plugin rules are appended, so plugin text can annotate but never clear a block (P8).
- **Test.** `tests/audit_a3_protocol_plugin_disarms_drainer.rs`.

### A3-06 — P3 — A community manifest's self-declared tier decided its verdict tier — FIXED
- **Fix.** `ManifestRegistry::manifests_in_force` overrides each manifest's tier with the registry's computed tier, and the verdict path merges only those (P7).
- **Test.** `tests/audit_a3_community_tier_self_asserted.rs`.

### A3-07 — P3 — An old registry submission could be replayed to roll a manifest back — FIXED
- **Fix.** A content hash the registry has already accepted is refused with `VersionAlreadyAccepted`.
- **Test.** `tests/audit_a3_registry_replay_rollback.rs`.

### A3-08 — P3 — Ten PDA seed templates referenced their own slot, so every real call was refused — FIXED
- **Fix.** The self-referential seeds are removed: seven in `gmsol-store` and orao-vrf `fulfill_v2` slot 3. Those slots are now judged by position, which is honest about what is verified. Validation also refuses a self-referencing seed from now on.
- **Test.** `tests/audit_a3_manifest_lint.rs::no_pda_seed_reads_its_own_address`.

### A3-10 — P3 — L1 always reported Passed and called a mismatched slot "matched" — FIXED
- **Fix.** `account_resolution_reason` returns a status as well as the text. Any PDA, expected-address or privilege mismatch is **Failed**. The wording separates slots that were re-derived or equal to a fixed address from slots accepted by position only.
- **Test.** `tests/audit_a3_l1_report_truthfulness.rs`.

### A3-11 — P3 (documentation) — `docs/CURRENT.md` said approval is unreachable without an RPC — FIXED
- **Fix.** The sentence is corrected: without an RPC, an approval needs evidence the graph has already earned or an operator seeded, and the scope names `not_simulated`, which the bridge refuses by default.

---

## A4 — RPC client, HTTP server, audit trail, L8

### A4-01 — P2 — A blocked transaction the witness saw executed did not alarm when the primary RPC was down — FIXED
- **Fix.** A new first arm in the reconciliation: primary `Unavailable`, a record that is not approved, the witness saw the signature, and the chain bytes were not rejected gives `BlockedButExecuted`.
- **Test.** `tests/audit_a4_l8_witness_alarm_primary_unavailable.rs`.

### A4-02 — P2 (with `GRAPHITE_TRUST_PROXY`) — A second `X-Forwarded-For` line chose the rate-limit bucket — FIXED
- **Fix.** `client_ip` joins every header line with `get_all`, in order, before counting hops from the right. Entries of the form `ip:port` and `[v6]:port` parse to their client.
- **Tests.**
  - `tests/audit_a4_xff_multiple_header_lines.rs`.
  - The unit tests `a_second_xff_line_does_not_choose_the_bucket` and `an_xff_entry_with_a_port_keys_its_client`.

### A4-03 — P2 — A slow or incomplete request head held a connection forever (slow-loris) — FIXED
- **Root cause.** axum's `serve` gives hyper no timer, so hyper's header-read timeout was disabled, and nothing capped connections.
- **Fix.** The server now runs its own hyper-util accept loop, `serve_hardened`:
  - HTTP/1.1 with a `TokioTimer`.
  - `header_read_timeout` of 5 s.
  - A connection semaphore (`GRAPHITE_MAX_CONNECTIONS`, default 1,024).
  - `TCP_NODELAY`.
  - Graceful shutdown.

  The server is HTTP/1.1 only.
- **Test.** `tests/audit_a4_slow_headers_hold_connections.rs`.

### A4-04 — P2 — The dashboard's `/api/*` scans blocked the async runtime — FIXED
- **Fix.** The three scan handlers run through `off_runtime`, which is `spawn_blocking`, as F-19-18 did for the other scans.
- **Test.** `tests/audit_a4_dashboard_scan_blocks_runtime.rs`.

### A4-05 — P3 — L8 had no RPC deadline, so a reconciliation could be lost to the request timeout — FIXED
- **Fix.** `audit_execution` runs under an `RpcBudget`. The primary and witness status calls run concurrently (`tokio::join!`) within it, and `getTransaction` is budgeted as well. An exhausted budget is `RpcError::Timeout`, which gives an `Unavailable` row, never a lost one.
- **Test.** `tests/audit_a4_l8_no_deadline.rs`.

### A4-06 — P3 — The audit record did not say which wallet profile applied — FIXED
- **Fix.** `AuditRecord.wallet_profile` records the profile that applied (`serde(default)` for old rows).
- **Test.** `tests/audit_a4_profile_override_not_on_trail.rs`.

### A4-07 — P3 — A `/verify` refused for its wallet profile left no audit row — FIXED
- **Fix.** That path appends an `AuditErrorRecord`, the same as the 422 and `VerificationError` paths.
- **Test.** `tests/audit_a4_profile_400_not_audited.rs`.

### A4-08 — P3 — A witness that saw the signature only at `processed` counted as agreeing — FIXED
- **Fix.** A witness agrees only at a cluster-backed commitment. A sighting of a blocked transaction still alarms at any commitment.
- **Test.** `tests/audit_a4_l8_witness_processed_agrees.rs`.

### A4-09 — P3 — The approved-verdict counter was incremented before the audit append — FIXED
- **Fix.** The verdict metrics are counted after the append succeeds, so a 503 is never counted as an approval.
- **Test.** `server::tests::a_verdict_that_could_not_be_recorded_is_not_counted` (added 2026-10-01): a `/verify` whose verdict cannot be appended is refused with 503 and counted as neither approved nor blocked.

### A4-10 — P3 — The body-read allowance plus the RPC budget exceeded the request timeout — FIXED
- **Fix.** `BODY_READ_TIMEOUT` is now 2 s, and a compile-time assertion checks `BODY_READ_TIMEOUT + RPC_BUDGET + 2 s ≤ REQUEST_TIMEOUT`.
- **Test.** The compile-time assertion.

### A4-11 — P3 — Two concurrent `/audit/event` reports could both record conflicting signatures — FIXED
- **Fix.** A process-wide `LIFECYCLE_REPORTS` mutex makes the history lookup and the append one critical section.
- **Test.** `server::tests::concurrent_reports_of_two_signatures_cannot_both_miss_the_conflict` (added 2026-10-01): sixteen submissions under sixteen signatures, sent together, leave exactly one row without a `signature conflict`.

### A4-12 — P3 — The text log format allowed log-line injection — FIXED
- **Fix.** `log_safe` escapes control characters in every caller-derived field before it is logged.
- **Test.** The unit test `log_lines_escape_control_characters`.

### Also fixed from the A4 notes
- **Witness guard.** The witness-equals-primary guard compares normalised URLs, not trimmed strings (`same_endpoint`). The unit test is `the_same_endpoint_written_differently_is_the_same_endpoint`.

---

## A5 — AI boundary, SDKs, bridge, dashboard, Python layer

The audit found **no path** where model, LLM or parser output raises a verdict in the Core (P1 holds). For the invariants checked, see `graphite-audit-work/a5/a5_findings.md`.

| ID | Class | Finding | Status |
|---|---|---|---|
| A5-01 | P2 | The bridge's swap path forwarded the AI layer's `intent_type`, so the untrusted label chose which Core checks fire, and any program was accepted | FIXED |
| A5-02 | P2 | Transfer grounding accepted a prefix of an address the user mistyped (a burn to an unheld key) | FIXED |
| A5-03 | P3 | The `identity` enum was PascalCase in the schema and SDKs but snake_case on the wire | FIXED |
| A5-04 | P3 | Both SDKs and the dashboard followed redirects past the https base-URL check | FIXED |
| A5-05 | P3 | The Python standalone fallback crashed every modelled intent | FIXED |
| A5-06 | P3 | Caller or AI intent text earned full IntentAlignment when L5 did not run | FIXED with A3-04 |
| A5-07 | P3 | Dev scripts skipped the transport rules and logged part of the RPC URL | FIXED |

### A5-01 — P2 — The swap path let the untrusted AI label choose the Core's checks — FIXED
- **Root cause.** `executeSwap` forwarded whatever `intent_type` the AI layer returned, and it accepted a payload for any program.
  - The transfer path is grounded in the user's own text. The swap path was not.
  - A compromised or prompt-injected layer could label an SPL `Approve` as "approve" and skip the intent-mismatch checks that exist to catch it.
- **Fix.** `executeSwap` always tells the Core `swap`. The method defines the class; the model does not.
  - `groundSwapIntent` refuses before any blockhash fetch or `POST /verify` unless all three hold:
    - the user's text contains a swap verb as a whole word;
    - the AI label, if present, is in the swap class;
    - the program is a swap program.
  - The swap programs are an explicit constant (`swap-programs.ts`, 45 ids): the seed manifests tagged `category: "swap"`, which is exactly the Core's `is_swap_program` set. `swap-programs.test.ts` fails if the constant and the manifests drift apart.
  - `GRAPHITE_AI_LAYER_URL` now follows the SDK's transport rule: https, or loopback http.
  - `parseIntent` has a 5 s timeout, and redirects are refused.
- **Tests.** The A5-01 tests in `graphite-sak-bridge.test.ts`, the `groundSwapIntent` tests in `intent-grounding.test.ts`, and `swap-programs.test.ts`.

### A5-02 — P2 — An address typo grounded to its prefix — FIXED
- **Root cause.** Grounding matched base58 runs, so a trailing non-base58 character split a 44-character address into a 43-character run. The Python parser's `{32,44}` stopped at the same place, the two agreed, and about 78% of such prefixes are valid keys that nobody holds.
- **Fix.**
  - **TypeScript** tokenizes on whitespace and strips only trailing sentence punctuation. A word containing a 32+ character base58 run that is not itself address-shaped raises `IntentGroundingError`.
  - **Python** requires the address to end the word (a trailing-boundary lookahead).
- **Tests.** In TypeScript, the stray-character cases (`0`, Cyrillic `А`, `-`, `.`, `_`, 45 characters, typo followed by `.`). In Python, `test_destination_is_never_a_prefix_of_the_typed_word`.

### A5-03 — P3 — The `identity` enum drifted from the wire — FIXED
- **Fix.** Snake_case (`pda` / `constant` / `unverified`) everywhere: the schema, the TypeScript union (plus a runtime `ACCOUNT_IDENTITIES`) and the Go constants.
  - The committed example now validates against the schema.
  - The new `resolved_accounts[].name` field is declared in the schema and in both SDKs.
- **Tests.**
  - Rust: `tests/verification_result_schema_contract.rs` serializes real artifact-bound, descriptive, blocked and unknown-program results. It checks them against the schema in both directions (the schema's rules hold, and every emitted field is declared), and validates the committed example.
  - Go: `sdk/go/identity_test.go`.
  - TypeScript: `sdk/typescript/src/types.test.ts`.

### A5-04 — P3 — The SDKs and the dashboard followed redirects — FIXED
- **Fix.** Go refuses every 3xx, including through a caller-supplied `http.Client`. The TypeScript SDK and the dashboard use `redirect: "error"` on every call.
- **Tests.** Go `TestRedirectsAreRefusedAndNeverFollowed`; the TypeScript SDK and dashboard redirect tests. Each one asserts that the redirect target is never contacted.

### A5-05 — P3 — The Python standalone fallback crashed — FIXED
- **Fix.**
  - Each manifest loads in its own `try`, so one bad file costs only itself.
  - The fallback uses the registry's list shape.
  - Embedded entries report `grounded=False`, so the protocol signal is 0.7, not 1.0.
- **Tests.** `test_standalone_fallback_parses_every_modelled_intent` and `test_a_bad_manifest_costs_only_itself`.

### A5-07 — P3 — Dev scripts bypassed the transport rules — FIXED
- **Fix.**
  - `devnet-test.ts` and `mainnet-benchmark.ts` verify through `GraphiteClient`, which enforces the transport rule and checks the response shape.
  - They read `GRAPHITE_CORE_URL`, and the legacy `GRAPHITE_URL` is refused, by the bridge too.
  - They log only the RPC host.
- **Test.** `env-names.test.ts`.

---

## A6 — CI, supply chain, container, documentation

Nothing in this area is a verdict bypass. The most serious item was a CI gate that could pass without testing anything (A6-01). The source reports are `graphite-audit-work/a6/ci_findings.md` and `docs_findings.md`.

### CI, supply chain and container

| ID | Class | Finding | Status |
|---|---|---|---|
| A6-01 | P2 | The live TypeScript SDK conformance step piped `npm test` into `tee` without `pipefail`, so a failing live test passed CI | FIXED |
| A6-02 | COVERAGE GAP | The Go SDK's live-server tests never ran in CI | FIXED |
| A6-03 | P3 | The keyless-container check could hang the job for 6 h; no job had a timeout | FIXED |
| A6-04 | P3 | Tests rewrite the committed regression corpus, and CI never checked it for drift | FIXED |
| A6-05 | COVERAGE GAP | CVE scanning covered one lockfile of five; there was no Dependabot configuration | FIXED; see below for the open advisories |
| A6-06 | P3 | Clippy was gated on one feature set of three; the oracle had no fmt or clippy step | FIXED |
| A6-07 | P3 | A `workflow_dispatch` input that nothing read | FIXED |
| A6-08 | P3 | The runner image and Node versions floated | FIXED |
| A6-09 | P3 | `npm ci` ran every dependency's install scripts | FIXED |
| A6-10 | P3 | Checkout left the token in `.git/config` | FIXED |
| A6-11 | P3 | Wall-clock assertions in the gating suites | FIXED where a structural witness exists; see below |
| A6-12 | P3 | `.dockerignore` let nested build output and local data into the build context | FIXED |
| A6-13 | P3 | The container healthcheck could not see a degraded audit trail | FIXED |
| A6-14 | P3 | Runtime apt packages are not pinned | DOCUMENTED LIMITATION (accepted and documented in the Dockerfile) |
| A6-15 | P3 | The crate is publishable, and its comment about it was garbled | OWNER DECISION (comment cleaned; the flag is unchanged) |
| A6-16 | DOCUMENTED LIMITATION | No branch protection on `main` | OWNER DECISION |
| A6-18 | P2 | A public "Security Report" issue template contradicted SECURITY.md's private-disclosure rule | FIXED |

How each was fixed:

- **A6-01.**
  - The step runs under `bash` with `set -euo pipefail` and the TAP reporter.
  - The TAP summary must show 0 fail, cancelled, skipped and todo, `pass == tests`, and at least one pass.
  - Every `live("…")` test named in the source must appear as an `ok` line.
  - There is no pinned count, so a new hermetic test needs no CI edit.
- **A6-02.** In the container job, `go test -tags liveserver` runs against the running image. It fails on `--- SKIP` or `--- FAIL`, and every `TestLive*` must pass.
- **A6-03.** The keyless check runs under `timeout --kill-after=10 60`. An exit of 124 or 137 fails with a message saying the container started instead of refusing. Every job has a `timeout-minutes`.
- **A6-04.** After the tests, CI runs `git diff --exit-code` and `git status --porcelain` on `fixtures/corpus`, after both legs that run the corpus test.
- **A6-05.**
  - `cargo audit --deny warnings` now covers the oracle too. Its one ignore is RUSTSEC-2025-0141, "bincode unmaintained": a warning, not a vulnerability. bincode 1.3 is a deliberate direct dependency that mirrors the runtime's decoder.
  - A new npm gate (`.github/npm-audit/gate.mjs`) checks the three lockfiles. It fails closed on:
    - any high or critical advisory missing from its package's allowlist;
    - any allowlisted advisory that is no longer reported;
    - an npm error or an empty report.
  - `.github/dependabot.yml` covers actions, cargo ×2, npm ×3, gomod and pip, weekly and grouped.
  - **At the audit (`3327fcf`):** the SAK bridge's tree carried 36 distinct high/critical npm advisories (`@solana/web3.js` 1.x through `bigint-buffer` and `node-fetch`, the `plugin-defi` and `plugin-token` trees, the agent frameworks), and the dashboard's `vite` 5 one dev-server advisory.
  - **Now (`dd85f62` onward):** the bridge no longer loads the plugin trees and pins patched transitive versions, leaving **one** gated advisory: `GHSA-3gc7-fjrx-p6mg` in `bigint-buffer`, through `solana-agent-kit` 2.0.10 → `@solana/spl-token` 0.4.15 → `@solana/buffer-layout-utils` 0.3.0 → `bigint-buffer` 1.1.5 (`npm ls`, 2026-10-02; an earlier version of this line said it came through `@solana/web3.js`, which was wrong), allowlisted as `GHSA-3gc7-fjrx-p6mg@bigint-buffer` (package-scoped since F14). Its native addon is never built, because every install runs with `--ignore-scripts`. Moving the bridge's own code to `@solana/kit` did not remove it. **Since R-P8 phase 3 (2026-10-02)** it is confined to the SAK adapter: the guard that signs moved to `integrations/agent-guard`, which does not depend on `solana-agent-kit`, and its lockfile carries no high or critical advisory (`agent-guard.allow` is empty, so CI fails on any). The adapter keeps the advisory for as long as `solana-agent-kit` stays on `@solana/spl-token` 0.4. The dashboard is on `vite` 8 with no advisories. Verified by `npm audit` through the gate on all three lockfiles (2026-10-01).
- **A6-06.** Clippy `-D warnings` now runs on all three feature legs, and the oracle has `cargo fmt --check` and clippy.
- **A6-07.** The input is deleted; `workflow_dispatch` itself stays.
- **A6-08.** All jobs use `ubuntu-24.04`. Every Node job is on Node 22.23.3, the current LTS; Node 20 is past end of life.
- **A6-09.** Every install is `npm ci --ignore-scripts`. The one patch the SAK needs runs explicitly.
- **A6-10.** Every checkout sets `persist-credentials: false`.
- **A6-11.** Each wall-clock assertion was replaced with a structural witness where one exists, and kept where the time IS the property:
  - **`AppState` clones** assert that every clone shares the same core, registry engine and permit pool (`Arc::ptr_eq`). The 250 ms bound is gone.
  - **The indexed audit lookup** relies on its scan counters (already asserted to be 0). The 1 s bound is gone.
  - **`round9_resource_bounds`** asserts the algorithm, not the machine: under 5 s against a regression of about 6×10⁸ comparisons (minutes). It was 500 ms, which took 1.3 s under load.
  - **The Python labeler smoke test** now refuses every socket connect while it parses, which is the structural form of "no LLM, no network". Its floor is 500 parses/s, two orders of magnitude above any network or model round trip. The old 10,000/s target failed on the build box under load for the old and new parser alike.
  - **Kept, with their margins documented:**
    - `tests/rpc_budget.rs`: a 2 s budget against a stalled RPC must finish within budget + 3 s, where the defect held for 120 s+.
    - The `/health` round trip: 50 ms per request, where the regression was 100 ms.
- **A6-12.** `.dockerignore` is an allowlist of exactly the four paths the Dockerfile copies. A probe build confirmed the context is 161 files (7.4 MB).
- **A6-13.** `graphite healthcheck --strict` also fails when `/health` reports `degraded: true`. The image keeps the default check, so a load balancer keeps a node that still refuses correctly.
  - Unit test: `cli::tests::strict_healthcheck_fails_a_degraded_node`.
- **A6-18.** The public template is now "Hardening Suggestion (no exploit details)", with a banner pointing to SECURITY.md. `ISSUE_TEMPLATE/config.yml` disables blank issues and links to the private channel, and CONTRIBUTING leads with private disclosure.

### Documentation

| ID | Class | Finding | Status |
|---|---|---|---|
| A6-17 | P2 | ROADMAP claimed "CI green on every commit since `f10e4ab`"; run #155 on `58a9ad8` was red | FIXED |
| A6-19 | P2 | The SAK README called the bridge "production-ready" | FIXED ("reference integration (alpha)") |
| A6-20..A6-29 | P3 | Stale or conflicting numbers: mutation count, test counts, risk-pattern counts, residual codes, corpus split, dashboard views, onboarding count, round count | FIXED |
| A6-23 | P3 | The crate README's first CLI example used a flag that does not exist | FIXED |
| A6-30 | P3 | Two SECURITY.md limitation bullets understated what is parsed and observed | FIXED |
| A6-31 | P3 | The source-tree lines misplaced the CLI and mislabelled the test count | FIXED |
| A6-32 | P3 | Seven environment variables were undocumented | FIXED, plus `GRAPHITE_MAX_CONNECTIONS` and a transport-limits paragraph |
| A6-33 | P3 | Principle P12 was cited as "fail-closed", the opposite of what it says | FIXED; the deliberate divergence is stated as an open owner decision |
| A6-34 | P3 | Internal audit passes were headed "Independent Audit"; "P16 compliant" was self-attested | FIXED |
| A6-35 | COVERAGE GAP | Headline mainnet numbers come from samples that are not in the repo | Labelled with their sample dates; the reproducible fix is roadmap gap R-P2 |
| A6-36 | P3 | The disclosure mailbox in SECURITY.md appears nowhere else | OWNER DECISION (unchanged) |
| A6-37 | P3 | CURRENT.md's "Updated" date | FIXED |

---

## Review of the fixes (2026-09-30)

An independent read-only review of `3327fcf..HEAD` hunted for defects the fixes themselves introduced. It found real ones, and they are fixed and tested like the original findings.

| ID | Class | Finding | Fix |
|---|---|---|---|
| F1 | P2 (regression from A2-01) | The rebuilt declared-effects parser skipped name lists and one-word lines, and then called a declaration made only of those "unrecognised". That softened an undeclared token debit from Critical to a warning on 27 seed instructions (OpenBook, Raydium AMM v4, Solend, Squads, SAGE, Switchboard) and on every memo. | A name list, a bare identifier and "no state changes" are read: they declare nothing, so the declaration is interpretable and the debit is Critical. "Unrecognised" now means real prose the parser could not map. Test: `state_diff::tests::a_name_list_alone_declares_nothing_and_a_debit_under_it_is_critical`. |
| F2 | P2 | Token debits were still judged transaction-wide, so a debit declared for `accounts.vault` excused draining any other account. | A debit declared only for named accounts no longer excuses a debit of a token account a transaction **signer** owns that the declaration does not name: that is Critical. Program-owned accounts, such as a pool vault paying out a swap, keep the transaction-wide rule, so swaps are not refused. Test: `a_named_debit_does_not_excuse_draining_a_signers_other_account`. |
| F3 | P1 candidate (residual of A3-01) | The name rule missed control hand-overs: `grant_role`, `multisigAddMember`, `multisigChangeThreshold`, `setOperator`, `set_treasury`, `set_delegate`, `ChangeFeeRecipient` and others. `authority`-tagged instructions blocked only when no intent was declared. | Two changes. The manifest's own `authority` tag now raises the security class to `authority_change`, which blocks under any intent (595 seed instructions at the review, 588 after F16 and F18 corrected seven mis-tags; the rest are protocol-admin operations and real hand-overs). The name rule adds a mutating verb paired with a power noun, acronym and digit word boundaries, and does not exempt a `check_*` name that also mutates. Creating state with an authority set is still a grant and stays blocked: a wrapped-SOL account created with someone else's close authority can be closed by them, taking its SOL. Tests: `manifest::tests::authority_change_names_are_recognised`, `the_authority_tag_raises_the_security_class`; corpus labels follow `security_class()`. |
| F4 | P2 (availability) | The 128-character discriminator cap applied to declared siblings, whose "discriminator" is their whole instruction data (the bridge's `declareSiblings`). Any bridge transaction with a sibling of more than 64 data bytes was refused. | Sibling and trace discriminators are bounded by the largest frame Graphite parses (2 × 4,096 hex characters); the primary keeps its pre-existing 128. Test: `verification::tests::a_sibling_with_long_data_is_not_refused_at_the_door`. |
| F5 | P3 | `f64::clamp` in the winsorizing update panics on NaN or inverted bounds, which a corrupted persisted baseline could produce. Winsorizing also shrinks the band for heavy-tailed programs: more false `SimulationSpoofing` flags (simulated: 15% → 34% at a coefficient of variation of 0.6). | The clamp is guarded (test: `a_broken_baseline_does_not_panic_the_update`). The false-positive cost is accepted and documented: one spread is the only setting that cannot ratchet. Above it, edge observations grow the band without bound. The robust window keeps raw values and can only add a flag. Steady one-way drift over about 10,000 accepted observations remains a limitation of program-level baselines (A2-08). |
| F6 | P3 (rejected) | `create_ata_with_close_authority` (the OKX router) is blocked as an authority change, which the review called a false positive. | Kept blocked after analysis. A creation exception was tried and withdrawn: it let 9 corpus fixtures go from refused back to approved, and creating a token account with someone else's close authority grants them the power to close it and take its SOL. The mainnet comparison measures the cost on real traffic. |
| F7 | P3 | The stem `creat` matched "creator", so `SignMetadata` declared a creation. | "creator" is excluded. Test: `creator_does_not_declare_creation`. |
| F8 | P3 | The connection cap was global, so one client could hold all 1,024 slots. | A per-peer cap: 64 by default when facing clients directly, off behind a trusted proxy (the proxy enforces one), set with `GRAPHITE_MAX_CONNECTIONS_PER_IP`. Keyed like the rate limiter (IPv6 per /64). Test: `one_peer_cannot_hold_every_connection`. |
| F9 | P3 | A request cancelled by the timeout released the lifecycle lock while its append still ran, re-opening the A4-11 race. Dashboard scans were unbounded on the blocking pool that the audit appends share. | The history read, the comparison and the append run in one blocking task holding a process-wide lock, and a blocking task runs to completion. Dashboard scans are capped at 4 at a time. An append that completes after a 408 leaves a row the client never received; that fails closed for the client, and it is recorded here. Tests: `concurrent_reports_of_two_signatures_cannot_both_miss_the_conflict` (the critical section), `dashboard_scans_run_a_bounded_number_at_a_time` (the cap). The cancellation path itself is not reproduced by a test: it is closed by construction (one blocking task holds the lock until the row is written). |
| F10 | P3 | L8's `getTransaction` got only what the status calls left of the budget, so the chain's bytes were often unavailable and attribution fell back to the caller's keys. | The status calls get at most half the budget; the bytes fetch has the rest. The total is unchanged. Test: `tests/audit_review_f10_l8_bytes_keep_their_budget.rs` — a silent witness, a primary that answers at once: the chain's bound bytes are fetched and attributed. |
| F11 | P3 | The A3-07 replay refusal also refused resubmitting the manifest in force with more attestations. | The head may be resubmitted unchanged only when its evidence earns a higher tier; anything else is still a replay. Test: `the_head_may_be_resubmitted_only_to_raise_its_tier`. |
| F12 | P3 | An address in `(…)`, quotes or backticks was refused by grounding. Swap programs with control instructions get no protection from grounding. | Leading quoting is stripped like trailing punctuation (test: "F12: a quoted address is the address…"). The second point is covered in the Core by F3. Verb inflections ("swapping") stay refused, matching the Python parser. |
| F13 | Test quality | The dashboard test required a scan of at least 300 ms, which fails on fast release runners. The baseline ratchet test's `unwrap_or(true)` could pass on a check that never ran. "N checks" in any prose matched the docs test. | The dashboard test calibrates relatively (a scan ≥ 20 × an idle `/health`). The ratchet test `expect`s the check to run. The docs test reads counts only on lines about their subject. |
| F14 | NIT | The npm gate keyed its allowlist by advisory id only, so a known advisory arriving through a new package passed. A stale Node 20 comment in the workflow. | Entries are `GHSA-id@package`, and a known advisory in a new package fails CI (tested locally both ways). The comment is fixed. |
| F15 | NIT | The Python transfer pattern's base58 class ran case-insensitively, admitting `I`, `O` and `l`. | The address group is case-sensitive (`(?-i:…)`). Test: `test_a_destination_is_case_sensitive_base58`. |
| F16 | P2 (regression from F3, found by the suite) | F3 made the manifest's `authority` tag a hand-over that blocks under any intent. The hand-written Stake Program manifest tagged six routine staking operations `authority` — `DelegateStake`, `Deactivate`, `Split`, `Merge`, `MoveStake`, `MoveLamports` — so delegating or unstaking through Graphite was refused whatever the agent declared. The full suite caught it: `hell_mode_tests::h12_stake_delegate_stake_not_blocked` and `deep_extreme_tests::test_verify_stake_delegate_passes_risk` failed, and 12 Stake corpus fixtures had flipped to refused. None of the six changes who controls a stake account: Split copies the source's authorities, Merge and the Move operations require both accounts to share them, Delegate and Deactivate change only the delegation. | The data was wrong, not the rule. A `stake` class is added for a stake account's own operations under the authority that controls it; it is in Check 10's high-risk set, so it still needs a declared intent, as these did before F3. The six are retagged `stake`; `Authorize*` and `SetLockup*` (which can replace the lockup custodian) stay `authority` and still block. The high-risk set is one constant, `manifest::HIGH_RISK_CLASSES`, read by Check 10 and its tests instead of four copies. Test: `manifest::tests::staking_is_not_an_authority_change_but_authorizing_is`; the two suite tests pass again. Of the other 32 corpus flips, every one is a real control change (`grant_role`, `multisigRemoveMember`, `allowOperator`, `add_or_update_user_delegate`, `SetTransferFee`, `transferRecipient`, …) and stays refused. |
| F17 | Test fixture | Three Round 22 transfer-hook tests (`round22_remaining.rs`) declared "debits accounts.source" but gave every resolved account an empty slot name, so F2 could not see that the debited account was `source` and refused it. | The fixture names `source` and `destination` as Token-2022's `TransferChecked` layout does, which is what the resolver hands L4 in the pipeline. F2 is unchanged. |
| F18 | P3 (pre-existing; fails closed) | `GRAPHITE_ALLOW_DURABLE_NONCE=1` could never produce an approval. A durable-nonce transaction opens with System `AdvanceNonceAccount`, which the pipeline judges like every instruction after the primary, and the System manifest tagged it `authority`: refused by Check 10 (empty intent) before F3 and as a hand-over after it. The existing opt-in test checked only that L2 passed. Found while auditing every native manifest's `authority` tags after F16. | Advancing a nonce moves no value and changes no control; L2 already verifies the nonce account on-chain before it passes. `AdvanceNonceAccount` is retagged with no class; `AuthorizeNonceAccount`, which does hand the nonce over, stays `authority`. Test: `durable_nonce_rpc::a_permitted_nonce_advance_is_not_refused_as_a_hand_over`. The stale-nonce, wrong-authority, missing-account, unreachable-RPC and no-opt-in refusals are unchanged and still tested. |

## External review (2026-10-01)

A second, external review of `0921647` listed further items (R1–R26). Each is re-verified here before anything is changed; this section records only what has been verified.

| ID | Class | Finding | Fix |
|---|---|---|---|
| R1 | P2 | L8 reported `ApprovedAndExecuted` for an approved record found by a key the caller supplied (`audit_trail_id`, `transaction_sha256` or `content_hash`) when `getTransaction` returned no bytes, so a random successful signature presented with the key of any approval reconciled as "the approved transaction executed". Confirmed by code read; three existing tests asserted that answer as correct. Not an approval bypass: L8 runs after execution and moves no funds; it is the audit attestation that could be manufactured. | A positive conclusion about an approved record (executed, or failed on chain) needs `attribution == Chain`, the chain's own bytes bound to the signature; otherwise `Unavailable`, naming the caller key. A blocked record still alarms on any sighting. Tests: `tests/audit_review_r1_l8_needs_chain_bytes.rs`; the three pinned tests updated; break B59 caught. |
| R2 | P1 | A caller's intent label cleared L5 and L7 for instructions it does not describe. L5 matched intent words against the instruction name AND the manifest's prose, which is boilerplate (the create, withdraw and close templates all say "transfers"; "move" matched "remove"); the Risk Engine's Check 9 accepted `transfer` for every program. Reproduced on `eb17aa5`, built in its own target directory: under a `transfer` intent, Squads `vaultTransactionExecute` and `batchExecuteTransaction` (the registry's two `drain` instructions), Bubblegum `delegate` and SPL/Token-2022 `MintTo`, `MintToChecked`, `Burn`, `BurnChecked` got **L5 Passed and L7 Clear**. Not re-run to `approved: true` here: the probe seeded no evidence or simulation; the review's recipe, which does, reported `approved: true` for Bubblegum `delegate` under four profiles. | L5 compares the intent's canonical class with the instruction's security class through one table, `manifest::INTENT_DECLARES` (transfer→transfer; swap→transfer or unclassed; stake→stake, withdraw, transfer, create; close→close; create→create; approve→nothing; revoke→unclassed), and Check 9b reads the same table, so the two layers cannot disagree. The intent's vocabulary and the prose can only refuse. L5 also requires the program to serve the intent, as Check 9 does (`l5_refuses_an_intent_the_program_does_not_serve_even_when_the_class_and_words_fit`). SPL `Revoke` and Pump.fun `sell` retagged so their honest intents pass. The corpus oracle uses the table. Tests: `tests/audit_review_r2_r3_intent_cannot_clear_danger.rs` (every manifest instruction under every intent judged by its class; the review's cases pinned; honest labels pass; nothing the old rule refused is approved); breaks B60–B65, B72. |
| R3 | P1 | Control changes escaped `names_an_authority_change` and the sibling path: camelCase split `multisigSetTimeLock` into time + lock; executor, submitter, successor and other powers were missing; Bubblegum `delegate` was tagged `transfer`; an instruction its program's manifest does not describe was only a warning as a declared sibling. Reproduced on `eb17aa5`: beside a 0.001 SOL transfer, Phoenix `NameSuccessor`, Squads `multisigAddSpendingLimit`, `multisigSetTimeLock`, `multisigSetRentCollector`, `configTransactionExecute`, the verifier's `rotate_block_submitter` and Token-2022 CPI Guard `Disable`, `Reallocate` and `WithdrawExcessLamports` came back **L7 Clear**; the controls `multisigSetConfigAuthority` and `ClaimAuthority` were Blocked. | The name rule reads joined adjacent words (`time`+`lock` = timelock) and the missing verbs and powers; a delegation grant is a hand-over outside the `stake` class; the transfer-fee noun is not read as a verb. An undescribed instruction of a described program is refused as a sibling. W14-a below completes it for described but unclassed siblings. Tests: as R2 (`r3_*`, `the_name_rules_catch_the_review_list_and_leave_user_operations_alone`); breaks B66–B71. |

### Status of every item (verified 2026-10-01 → 2026-10-02)

"Verified" means re-checked in the code or by a test here, not taken from the review's text.

| Item | Status | Evidence / where |
|---|---|---|
| R1 | **FIXED** (P2) | above; `tests/audit_review_r1_l8_needs_chain_bytes.rs`; break B59 caught |
| R2 | **CONFIRMED on `eb17aa5`, FIXED** (P1) | above; breaks B60–B65, B72 caught |
| R3 | **CONFIRMED on `eb17aa5`, FIXED** (P1) | above, and W14-a; breaks B66–B71, B73 caught |
| R4 | **FIXED** (docs integrity) | the cited files exist; break log complete (59/59); A6-05 advisory count and the Go version corrected; `tests/docs_paths_resolve.rs` fails when a live document names a missing file (shown failing with `AUDIT/FINAL.md` moved aside) |
| R5 | **FIXED** | both schemas declare JSON Schema 2020-12 and an `$id` on the repository's host; they compile with jsonschema's `Draft202012Validator`, the committed examples validate; `the_schemas_name_a_real_metaschema_and_their_own_id` |
| R6 | **FIXED** | `confidence_of_parse` is not recorded and now says so (code and schema); it is refused outside [0, 1] or non-finite; `intent_type` is bounded and printable; `VerificationInput` refuses unknown fields (both SDKs send exactly its fields); `a_request_outside_its_schema_is_refused_at_the_door` |
| R7 | **FIXED** (comments only) | the bridge's default profile fails closed (the Core clamps Custom to Gaming's 0.55) and now says so; `GRAPHITE_URL` documented as the SDK live tests' variable in CONTRIBUTING |
| R8 | **CONFIRMED at runtime, FIXED** | a test walking the bridge object found `walletKeypair` with the secret key bytes; the key is now an ES `#private` field and the test passes; the gated wallet's claim is narrowed (the key still enters the process through its environment or config) |
| R9 | **FIXED** | the live L3 test requests version 1; since R-P8 phase 4 the two web3.js tools request version 1 too (web3.js 1.99 decodes v1; read live) and report how many v1 transactions they read, pinned by `env-names.test.ts`; `graphite-core/scripts/README.md` records which tools see v1 (nine one-off Python onboarding scripts stay at version 0 and may not be used to measure traffic) |
| R10 | **CONFIRMED, FIXED** (R-P8 phases 1-2) | the bridge compiles and signs through `@solana/kit` 8.4.0 and builds v1 (`transactionVersion: 1`), with both limits measured by an unsigned simulation; `messageOf` ports the Core's `parse_v1`; the corpus carries two bridge-built v1 shapes and 1,238 v1 mutations, read the same way by both sides (`v1-transaction.test.ts`, `tests/sak_bridge_corpus.rs`); 9/9 TypeScript breaks caught |
| R11 | **CONFIRMED, FIXED** (Round 27, roadmap R-M1) | with an RPC, each manifested program a verification invokes has its loader-v3 deployment read and compared with the last one seen; a redeploy or a new upgrade authority is reported on the verdict, `/health` and the metrics, and `GRAPHITE_QUARANTINE_ON_UPGRADE=1` quarantines it (`tests/rm1_program_upgrade_detection.rs`; breaks B109–B111). An upgrade before the first sighting is not reportable |
| R12 | **ADDRESSED** | R1, R2 and R3 are each pinned by tests that fail on `eb17aa5` |
| W1 | covered by R1 | the `Confirmed` arm was the only path from RPC or witness output to an approval-flavoured L8 answer found by reading `audit_execution`; lifecycle `verdict_on_record` is resolved and recorded with its key, never as an execution |
| W2, W4 | **FIXED** (R-P8 phases 1-3) | W2 = R10 above. W4: the signing package (`integrations/agent-guard`) no longer depends on `solana-agent-kit`, so the gated `bigint-buffer` advisory is confined to the SAK adapter's lockfile; the guard's lockfile has no high or critical advisory and an empty allowlist. Four moderate advisories (`uuid`, `stream-json`, through `@solana/web3.js` 1.x's `jayson`) remain in the guard, recorded in `agent-guard.allow` |
| W3 | **FIXED** (R-P8 phase 4) | R9 above: every tool that publishes or gates a number requests version 1 |
| W5, W6 | **FIXED** (Round 27, with R11) | the upgrade is noticed; re-measuring the manifest against the new code is not automatic. Manifest lineage is recorded as `manifest_version` on each audit row |
| W7 | **OPEN** | roadmap R-M13 (measured cost: 9 of 48,855 executed transactions) |
| W8 | **OPEN** | A2-08 (documented limitation) |
| W9 | **OWNER** | R-M9 |
| W10 | **FIXED** (Round 28, roadmap R-M11) | each rotated archive has a persisted, checked index; see the Round 28 section below |
| W13 | **OPEN** | R-M10 |
| W20 | **VERIFIED SOUND** for profile thresholds | Custom `min_confidence` that is NaN, infinite or outside [0, 1] is refused in both `server.rs` and `policy_engine.rs` |
| W26 | **FIXED** (one example) | `examples/verify-input.json` carried 50,000 "battle tested" transactions in `behavior_evidence`, which the Core ignores by design; the example no longer suggests it matters |
| W11, W12, W14–W19, W21–W25 | **VERIFIED and FIXED, or documented** (Round 24) | one row each in the table below; W18/19-f (signer lamports outside a declared debit) is disclosed, not refused, and is a documented limitation |

### Round 24: the rest of the review (2026-10-03)

Each item below was re-verified here before anything changed — by a reproduction against
`eb17aa5` (built in its own target directory) or by reading the code to a concrete input and
then a test that fails without the fix. Seven read-only verification passes covered W11–W25; their
reports were leads, not evidence: every item kept here was reproduced or traced in the code.

| ID | Class | Finding | Fix |
|---|---|---|---|
| W14-a | P1 (completes R3) | A declared sibling DESCRIBED by its manifest but given no class was judged with the empty class and the empty intent, which no check acts on. Squads `spendingLimitUse` (pays out of a vault), `batchAccountsClose` and `proposalApprove` beside a 0.001 SOL transfer came back Clear on `eb17aa5` and on the R3 fix alike. | An unclassed declared sibling must be described by the transaction's own intent through `INTENT_DECLARES`, as the primary must. The plumbing every transaction carries is classed `inert` (Compute Budget, Memo, `SyncNative`, the read-only Token queries, `AdvanceNonceAccount`) and ATA creation `create`, so it is not unclassed. |
| R3-b | P1 (found by this round's own mainnet re-measurement) | Re-measuring four days of mainnet after the R2 fix turned one refused verdict into a Clear one: Tensor AMM's `editPool`, newly manifested this round and classed `transfer` by the IDL onboarding's default, so a `transfer` label cleared it at L5 and L7. The same default had classed 52 seed instructions that switch or edit a setting (`unpause_dex`, `pause_swap_and_arbitrage`, `toggle_feature`, `editPool`) as transfers, and 391 instructions whose layout needs a signer the manifest names an admin as transfers, creations, withdrawals, closures or nothing, so the intent of that class cleared them. No approval was observed (the measurement approves nothing offline); the class gate was the only thing in the way, as in R2. | `InstructionDef::security_class` raises to an authority change any instruction whose name opens by switching something (`enable`, `disable`, `toggle`, `pause`, `unpause`, `halt`, `unhalt`, `resume`) and any whose layout needs an admin's signature, whatever its tag. The 52 generated `edit*`/`reset*`/switch instructions are retagged in the data, and the onboarding classifier tests those verbs first. Mainnet cost: the one `editPool` row; 45 already refused Coinflow admin withdrawals now name the admin reason. Tests: `a_switch_an_edit_or_an_admin_signature_is_a_control_change`, `no_seed_instruction_with_an_admin_signer_or_a_switch_name_escapes_the_control_class`, `manifest::tests::a_name_that_opens_with_a_switch_is_a_control_change`; breaks B100–B102. |
| W14-b | P2 | What a sibling EXECUTED was judged as the primary's: the simulator's callees were checked as one set against the primary's allowed CPIs and root, and the CPI-trace rules ran on the primary's tree only. Under a trusted root, a sibling's token CPI outside its own manifest passed. | Each top-level instruction's observed tree is rebuilt and judged with its own manifest's allowed CPIs (Checks 1 and 1b, now one function each) and the trace rules. |
| W15-a | P3 | A protocol plugin's rules reached the diff comparison, so a rule naming an effect excused `UndeclaredOwnerReassignment`, `UndeclaredAccountClosure` and `UndeclaredTokenDebit`. No approval path (an unmanifested program is Unknown tier), but P8 says a plugin never disarms. | A diff is compared with the manifest's own declaration; plugin rules still drive the structural check, which is never a pass. |
| W15-b | P3 | A plugin registered under a taken name was dropped with an info log and counted as registered; a Block named "warning" was recorded with a Note's suffix and fed the shadow accumulator; two comments said a panic contributes nothing (it is a block). | `register_plugin` returns whether it registered (warning otherwise); `already_registered` in the summary; a Block is never `:warning`; comments corrected. |
| W11-a | P3 | A submission's signer counted as one of its own attesters, so one other reviewer made it CommunityVerified. | The signer's attestation is not counted. |
| W11-b | P3 | A corpus fixture's `program_id` and `content_hash` were taken on trust at load. | Both are recomputed from the fixture's input; a mismatch is a load error. |
| W12-a | P2 | An upgrade that did not raise the tier skipped the P10 gate, so a second reviewer's v2 that retagged v1's control instruction `transfer` became the manifest in force with no replay. | Every upgrade of a manifest in force is replayed. |
| W12-b | P2 | The gate replayed the candidate at the tier its document declares (empty = Unknown) while the runtime applies the tier the registry computes; a loosened manifest passed a gate its runtime self fails. | The candidate is replayed at the computed tier. |
| W12-c | P3 | The CLI wrote the registry and graph with a plain write, unlocked: a torn write left a registry the server reads as empty, and two submits at once dropped one record. | Atomic write (temp + rename) and an exclusive lock around the read-modify-write. |
| W16-a | P2 | The 32 MiB response cap bounds bytes, not the parsed tree: 32 MiB of `[0,0,…]` parses to ~16.7M `Value`s (~540 MB) against a 512 MB container. | Values are counted in one pass before parsing; more than 1,000,000 is refused. |
| W16-b | P3 | A simulation result without `err` was read as success (and could train the baseline); a `getTransaction` meta without `err` as `succeeded`. | An absent `err` is an unreadable answer / an unknown outcome. |
| W17-a | P3 | An unset v1 compute-unit limit was reported as the legacy 200,000 per instruction; in v1 unset means 0. | 0, and the scope's `problems` name both unset limits. |
| W17-b | P3 | The bank's account-lock limit (64 on mainnet) was not modelled; a v0 transaction locking 65+ accounts got a bound verdict. | Refused at parse (`TooManyAccountLocks`); the oracle lists it, with `DuplicateAccountKey`, as a deliberate post-sanitize refusal. Mainnet check: the largest executed transaction across 48,946 sampled locks exactly 64. |
| W18/19-a | P2 | Token-2022 mint extension authorities (transfer hook, interest rate, metadata/group pointers, token metadata and group update authorities, scaled UI amount, pause, confidential configuration) and the pause flag changed with warnings only. | Compared before/after; an undeclared change is Critical (`UndeclaredToken2022AuthorityChange`, `UndeclaredToken2022Pause`). |
| W18/19-b | P2 | Native authorities beyond stake staker/withdrawer/custodian and the upgrade authority were not compared: a nonce authority, a program rewritten under the same authority, a stake lockup, a vote account's withdrawer, a buffer's or lookup table's authority. | All recorded in `native_authorities`; an undeclared change is `UndeclaredNativeAuthorityChange`. |
| W18/19-c | P2 | A declared effect was scoped to every `accounts.X` on its line and read without polarity: CloseAccount's prose excused a closure of its destination, InitializeAccount's an authority change on its owner slot, and Revoke's prose declared a delegation. | Role by position ("to"/"into" = recipient, credited only; "from" = source); a revoking line declares no delegation. |
| W18/19-d | P3 | The arithmetic transfer-fee path asked about a pending schedule only when a fee was withheld. | Asked on the zero-fee path too. |
| W18/19-e | P3 | A mint read but whose extensions did not decode was treated as having no permanent delegate. | Treated like an unread mint. |
| W18/19-f | P2, disclosed | Under a declaration that debits only named accounts, lamports leaving the signer's own wallet were not judged at all. | Disclosed as `SignerLamportsOutsideDeclaredDebit` (warning). Not refused: the same outflow is every tip and every rent payment for an account a sibling creates, Graphite does not bind amounts, and the cost of refusing it cannot be measured offline. An agent guard bounds it by the operator's cap on the measured outflow. Documented limitation. |
| W21-a | P3 | The dashboard scan's permit lived in the async frame and was released when a request timed out while its scan ran on; the lifecycle and L8 lookups scanned every archive with no bound. | One bound for every audit-trail scan, its permit moved into the blocking task. |
| W21-b | P3 | The simulation baseline trained before the audit append, so a verdict refused with 503 (or a request that timed out) still trained it. | The server defers each observation and commits it only once its verdict is on the trail. |
| W21-c | P3 | A quarantine LIFT took effect when the trail could not record it. | It is put back and the request answered 503. |
| W21-d | P3 | Nothing bounded a connection after its request head: a non-reading client or an idle keep-alive held its connection slot. | A connection lifetime (`GRAPHITE_CONNECTION_LIFETIME_SECS`, 120 s). |
| W22-a | P2 | The agent guard's spend cap bounded transfers only; both framework adapters expose a swap tool (introduced in this round's own adapter work, before commit). | A swap's outflow is measured by simulating the exact transaction; over the cap, or spending a token a lamport cap cannot price, is refused; a destination list alone refuses swaps. |
| W22-b | P3 | `destination` was sent by the TS SDK, the guard and the Python layer and dropped by the Core; the guard said the Core compared it. | `destination` and `account_type` are schema fields; unknown parameters are refused; the comment says what is true. |
| W22-c | P3 | A tool result left out the verdict's scope, digest, residuals and manifest version; a residual-policy refusal read as "error". | All carried; `refusedBy: "residual-policy"`. |
| W22-d | P3 | The dashboard showed an approval of a description and of bytes the same way. | The projection carries `transaction_sha256` and `manifest_version`; a descriptive approval is labelled so. |
| W23-a | P2 | Docker base images were pinned by digest but never offered updates. | Dependabot `docker` entry. |
| W23-b | P3 | The Python lockfile was not audited — and carried pytest 8.3.4 (PYSEC-2026-1845). | `pip-audit` in CI (pinned action); pytest 9.1.1 (+ pygments 2.21.0, which it requires). |
| W23-c | P3 | The npm gate accepted a bare advisory id; Python versions floated; the tree-mutation check covered `fixtures/corpus` only. | Scoped entries only; exact Python releases; the whole tree checked. |
| W25-a | P2 | A verification error counted as a blocked exploit in the benchmark and the holdout. | Counted separately; pinned at zero. |
| W25-b | P2 | The mainnet samples could not be reproduced (blocks counted back from the head; a README called an uncommitted sample committed). | `--slots`, the slot lists and file hashes in `tools/mainnet-sample/SAMPLES.md`, and the test prints the hash it measured. A refetch of one block reproduced its 1,242 rows. |
| W25-c | P2 | The conformance test passed when the sample path was set but unreadable. | It fails unless it measured something. |
| W24 | test quality | Disjunctions that passed for an approved drainer, an always-true assertion, attack tests that never asserted `approved == false`, ceiling tests comparing a constant with itself, and two loopback-only tests left `#[ignore]`. | Strengthened as listed in the round report; the loopback tests run in CI. |
| W22-e | P3 | The TypeScript SDK's result guard checked five fields and never the scope, so a verdict claiming `artifact_bound` with no digest, an unknown residual code, or `approved` beside a Blocked risk verdict reached the caller typed as a result. | `validateVerificationResult` checks the scope against the schema's two shapes, the risk verdict's status and findings, the tier, every layer's reason, and refuses an approval beside a Blocked risk verdict. Test: `sdk/typescript/src/client.test.ts`; TypeScript breaks TSB4 and TSB5 caught. |
| W22-f | P3 | A verdict did not say which message format Graphite parsed. | The artifact-bound scope carries `message_version` (`legacy`, `v0`, `v1`), read from the bytes; schema, TypeScript and Go types. Test: `round19_v1_transactions::the_verdict_names_the_message_version_it_parsed`. |

**Still open after Round 24** (recorded, not fixed):

| ID | Class | What | Where it is tracked |
|---|---|---|---|
| R11 / W5 / W6 | P2 (open) | No watch on a program's ProgramData slot or upgrade authority; a protocol upgraded under its manifest is judged by the old manifest until someone notices. | roadmap R-M1 |
| W7 | P3 (open) | Owner configuration of one's own object is refused like protocol administration (measured: 9 of 48,855 executed transactions). | roadmap R-M13 |
| W8 | documented limitation | L3 compares whole-transaction simulations keyed by program id. | A2-08; `SECURITY.md` |
| W17-c | documented limitation | A lookup table's freshness is not checked against the current slot. The direction is refusal (the runtime fails such a transaction). | `SECURITY.md` |
| W11-c | documented limitation | Registry records keep no signatures, so a registry file cannot be re-verified offline. | `SECURITY.md`; roadmap |
| W18/19-f | documented limitation | Lamports leaving the signer's wallet under a declared debit are disclosed, not refused; Graphite does not bind amounts. | `SECURITY.md` |
| W25-d | documented limitation | The holdout's benign labels are "the program is manifested", the P10 gate replays the same set, and the benchmark and holdout have no v0 or v1 rows. | `SECURITY.md` |
| R2-c | documented limitation (measured) | An honest agent has no intent for a withdrawal, a fee or reward claim, or a close on a protocol program: `stake` declares `withdraw` only on staking programs, and `close`/`create` are served only by the token programs, System, ATA, Metaplex, Pump.fun and Jupiter DCA. Under honest labels, 219 of 48,855 executed mainnet transactions are newly refused against `eb17aa5`, all with a manifested primary: 59 pump AMM `close_user_volume_accumulator`, 41 durable-nonce transactions the harness labels by their nonce advance, 29 Pyth `updatePriceFeed` keeper calls, 30 Meteora DLMM liquidity calls, and withdrawals and fee claims (Raydium CLMM `decrease_liquidity_v2`, creator-fee claims). Before R2 a `transfer` label cleared these by matching prose. | roadmap R-M14 (an intent for withdrawals and claims, and per-program `close`/`create` support from the manifest, each judged at L4 by where the funds go) |
| W9, W13 | owner / roadmap | as listed in the status table above | R-M9, R-M10 |

## Second external review (2026-10-16, Round 25)

A review of `d95d37a` (the whole tree and its CI run) listed ten items (E1–E10 here, in its order).
Each was checked against the code before anything changed; two were narrower or wider than
stated, and one was not a finding.

| ID | Class | Finding | Fix |
|---|---|---|---|
| E1 | P1 by mechanism (not shown end to end: an approval needs earned evidence the loopback harness does not seed) | The agent guard grounded only that a request asks for A swap on a swap program (`groundSwapIntent`), never the amount or the tokens, and the Core does not compare them. "Swap 1 SOL for USDC" signed whatever route the Core found well-formed: one spending 100 SOL, spending USDT, or delivering BONK. The operator's cap bounded the loss where one was set (both framework adapters require one; direct guard use does not), but did not tie it to the request. | `groundSwapRequest` reads the amount and both tokens from the user's own text (one amount; "swap <amount> <in> for <out>" or "buy <out> with <amount> <in>"; percentages are constraints, not amounts; symbols from a table checked against Jupiter's verified list, anything else by mint address) and the AI layer's reading must agree on all three. `assertSwapEffectMatches` then holds the exact transaction to it in a simulation of its bytes: no more than the requested amount of the requested token (plus `SWAP_SOL_OVERHEAD_LAMPORTS`, 0.01 SOL, for fees and rent), no other token spent, the requested token delivered. A request that names what it receives but not what it spends ("buy 5 SOL with USDT") is refused. Tests: `guard.test.ts` ("swap grounding: …", seven tests including the review's 2 SOL, 100 SOL, BONK, USDT and disagreeing-AI cases); TypeScript breaks TSB6, TSB8. |
| E2 | P2 (by mechanism; the MCP server's default confirmation would show the person the request) | Grounding established what a request names, not that the user asked for it: "Don't send 5 SOL to <address>" had one address, one amount and the word SOL, and became a 5 SOL transfer; "Don't swap 1 SOL for USDC" passed the swap grounding. | `assertAffirmative`: a request containing a negating, cancelling or withholding word (not, no, never, don't, do not, won't, cancel, stop, abort, undo, instead, any "n't") is refused, for transfers and swaps, before anything is built. Tests: `guard.test.ts` ("negation: …", nine phrasings); break TSB7. |
| E3 | P3 (narrower than stated) | The review said a blocked transaction the primary reported but whose bytes it could not return reconciled as `Unavailable`. With the caller's keys it already alarmed (the `Confirmed` arm); without keys, the bytes were asked of the primary only, so there was nothing to join the record by and the answer was "nothing to reconcile" although the witness held the bytes. | The bytes are asked of every source that reports the signature, primary first; a source with none no longer ends the search. Tests: `audit_a4_l8_witness_alarm_primary_unavailable::a_primary_without_the_bytes_does_not_hide_a_blocked_transaction_the_witness_saw` (null and failing `getTransaction`), `::an_approved_transaction_is_reconciled_from_the_witnesss_bound_bytes`; break B104. |
| E3b | P2 (found while writing E3's regression; the review's "rejected-primary-bytes variant") | A primary that served bytes not bound to the signature ended the search, and the reconciliation answered `Unavailable` whatever the record: a primary serving substituted bytes silenced a blocked transaction the witness had seen — the alarm L8 exists for (the same class as A4-01). | A rejected answer is recorded and the next source is asked; bound bytes decide, whichever endpoint served them. A blocked record then alarms; an approved one is not reconciled as executed while a source served substituted bytes (`Unavailable`, "the inclusion sources disagree about the bytes"). Test: `::substituted_bytes_from_the_primary_do_not_silence_the_witness`; breaks B105, B106. |
| E4 | P2 | The spend cap measured a swap's outflow from two reads: `getMultipleAccounts` before, the simulation's post-state after. Not one snapshot: a deposit landing between them made a 50 SOL spend look like no outflow under a 1 SOL cap. | `measureWalletEffect` reads the wallet's lamports and every wallet-owned token balance from ONE simulation's `preBalances`/`postBalances` and `preTokenBalances`/`postTokenBalances`, the same run at the same slot; no separate read remains. A simulation without both arrays, or a token balance without an owner, is refused. Tests: `swap-effect.test.ts`, the guard's spend-policy tests (no `getMultipleAccounts` call); break TSB9. |
| E5 | P3 | The guard parsed RPC answers with `response.json()`, unbounded, in the signing process. | `readJsonBounded`: the Core's 32 MiB bound, checked against `content-length` and while streaming, before parsing, on every raw JSON-RPC read. web3.js 1.x's own reads (the guard's `Connection`) are not bounded by this; that goes with R-M15. Test: `swap-effect.test.ts`; break TSB10. |
| E6 | P3 | Lamports from the RPC were a JavaScript `number`, which loses integer precision past 2^53 silently. | `exactLamports` refuses any balance that is not a safe integer; token amounts are read from their decimal strings into `bigint`. Test: `swap-effect.test.ts`; break TSB11. |
| E7 | NOT A FINDING | The review asked for the packet parser's 12-signature limit on legacy and v0. agave derives `MAX_SIGNATURES_PER_PACKET` as the packet size over a signature and its signer's key (1232 / 96 = 12), so Graphite's 1232-byte bound already refuses a thirteenth signer: the smallest 13-signer legacy frame is 1321 bytes. | Pinned: `wire_format_bounds::a_thirteenth_signer_does_not_fit_in_a_legacy_packet`. |
| E8 | P3 | v1 refused more than 64 top-level instructions; legacy and v0 did not, though the runtime's instruction trace (`MAX_INSTRUCTION_TRACE_LENGTH`, top-level and CPI together) holds 64 in every format and 65 three-byte instructions fit in a packet. Such a transaction can only fail; Graphite gave it a verdict. | `TooManyInstructions` at parse; the runtime oracle lists it as a deliberate refusal beyond sanitize. Test: `wire_format_bounds::more_top_level_instructions_than_the_trace_holds_is_refused`; break B107. |
| E9 | P3 (documented, not self-declaring) | Nine onboarding and census scripts request transaction version 0. `scripts/README.md` already classified them as one-off tools whose output excludes v1; nothing in the scripts said so. | Each prints, on every run, that its output excludes v1 and is not for measuring traffic. |
| E10 | P3 (documentation) | `docs/CURRENT.md` said the bridge builds legacy and v0, not v1, contradicting itself. | Corrected: the guard builds all three; what remains web3.js 1.x is its public API (R-M15). |

The review's list of architectural items still open (upgrade detection, per-instruction L3
baselines, the archive index, owner configuration, P12, the schema gate, reviewer independence,
committed mainnet fixtures, mutation/fuzz/coverage gates, web3.js in the guard, `bigint-buffer`,
the independent audit) matches `02-roadmap-gap.md`, where each is recorded with its class.

## Round 28: three roadmap items, and what closing them found (2026-10-17)

Three open roadmap items that need no owner decision were closed: the persisted archive index
(R-M11, external review W10), the lifecycle-emission lint (R-P14) and the P13 contract gate (R-M2).
Building them found three things.

| ID | Class | Finding | Fix |
|---|---|---|---|
| R28-1 | P3 (process; Constitution P13) | The published contract broke after the `v0.2.0-beta` tag under the same version, with no CHANGELOG entry naming the break. A caller written against the tag's `proposed-intent-v1.json` could send an `extracted_parameters` field the Core now refuses (`deny_unknown_fields`, W22, Round 24), or the intent `lend`, which the schema listed until `5fd1dc3` and the engine never accepted. Nothing compared the schemas between versions, so neither was caught. The gate written for R-M2 found both on its first run. | `tests/contract_version_gate.rs` diffs both schemas against the last release tag. Its rules depend on who writes each document: for Graphite's output, removing, widening or opening breaks; for the caller's input, removing, narrowing, requiring or closing breaks. A break needs a version bump and a CHANGELOG section naming the path. The crate is `0.3.0-beta`, and the CHANGELOG's `0.3.0-beta` section names both breaks. CI checks out the history and sets `GRAPHITE_CONTRACT_GATE_REQUIRED=1`. Breaks B124, B125. |
| R28-2 | test quality | `a_caller_cannot_forge_a_self_observed_event` named `verification`, `construction` and `simulation`, not `operator_action`. That a caller cannot write "quarantine lifted" into the trail rested on `is_self_observed` alone, with no test naming the event. | The test names all four self-observed events, written out rather than read from `LifecycleEvent::emission`, so a change to that table that makes one reportable fails. Break B121. |
| R28-3 | P3 (documentation) | `LifecycleEvent`'s documentation sent a reader to `GraphiteCore::record_lifecycle_event`, which does not exist. | The comment names `POST /audit/event` and `LifecycleEvent::emission`. |

**R-M11.** Each rotated archive has an index at `<log>-index/<archive>.idx`. It is binary,
fixed-width and sorted, and searched by seeking, so none of it is held in memory. It is checked
against the archive once per process (magic, version, length, the file's trailing SHA-256, and the
archive's length and SHA-256), and rebuilt when it does not check. A lookup still reads its record
back from the archive and matches it. An offset that does not read back discards the index and
scans. An index that cannot be written leaves its archive scanned on each lookup, without a
rebuild each time. Measured on three 64 MiB archives (144,322 records each): a count took
822 ms by scanning and takes 2.2 ms from the indexes, and a miss takes 3.5 ms. Building the three
indexes from a parse took 6.7 s and checking them after a restart 1.8 s. Rotation writes the new
archive's index from the active file's indexes without a parse, and the server checks every archive
in the background at start. The index files are about a quarter of the archives' size (49 MB for
192 MiB). Tests: seven in `durable::tests`; breaks B112–B120.

**R-P14.** `LifecycleEvent::emission` says where every event reaches the trail, in a `match` with
no wildcard, so a new event does not compile without an emitter. `is_self_observed` is read from
it. `LifecycleEvent::ALL` is checked against the variants serde derives.
`server::tests::every_lifecycle_event_reaches_the_trail` drives every emitter (`/verify`,
`/admin/quarantine`, `/audit/event`) and reads each row back. Construction and simulation are
recorded on the verification row (`content_hash`, `l3_status`), not as rows of their own. That is a
recorded choice, not a gap closed. Breaks B121–B123.

## The full-repository audit of 2026-10-20 (Round 29, 2026-10-21)

An audit of `19a2974` read every source file, re-checked its most consequential findings by hand
and ran every suite. It ranked findings HIGH / MEDIUM / LOW on the gate as shipped. All are closed in
Round 29 ([report](../docs/round29-the-audit-remediated-2026-10-21.md)): fixed, documented as a
limitation, or an owner decision.

| ID | Finding | Status | Test |
|---|---|---|---|
| H1 | The Core approved a transaction whose simulation failed or never ran | **Fixed with an RPC attached** (`SimulationFailed`, `VerificationIncomplete` refuse). Without an RPC: documented limitation (L3 Inconclusive, `not_simulated`; the guard refuses it) | `audit_2026_10_20_simulation_gate`, `audit_2026_10_20_core_gates::without_an_rpc_client_an_artifact_verdict_is_unchanged`; caught when reverted (round report §5) |
| H2 | A swap's delivered amount was never bounded; the guard's comment said the Core read the minimum | **Fixed in the guard**: six programs decoded, the route's minimum held to the simulated delivery, a slippage bound and a price floor. The Core reads no minimum; the Round 25 report's statement is corrected in `CURRENT.md` | `swap-instructions.test.ts`, `swap-economics.test.ts`, `guard-round29.test.ts` (H2) |
| H3 / M5 | Transfer grounding checked no verb or direction; units and currency ignored | **Fixed**: one positive grammar | `intent-grounding.test.ts` (H3) |
| H4 | A swap's spend was a one-simulation snapshot; exact-out forms bounded only by a caller's maximum | **Fixed**: exact-in only; amount in read from the data | `guard-round29.test.ts` (H4), `swap-instructions.test.ts` |
| M1 | Policy-refused requests trained `SimulationMatch` for every caller | **Fixed**: off unless `GRAPHITE_LEARN_FROM_POLICY_REFUSALS=1` | `audit_2026_10_20_simulation_gate::policy_refusals_teach_nothing_unless_the_operator_opts_in` |
| M2 | Confidence and tier read the primary program only | **Fixed** for the tier (the minimum over every top-level program); the evidence signals stay the primary's, by design | `audit_2026_10_20_core_gates::{an_unmanifested_sibling_sets_the_verdicts_tier, an_earned_primary_tier_is_held_to_its_siblings}` |
| M3 | The registry's promotion gate was no boundary against a malicious reviewer | **Fixed**: registry-owned corpus, lineage, domain-tagged signature, full validation, revocation; fixture integrity covers the outcome (unkeyed: evident, not prevented) | `manifest_registry::tests`, `regression_engine::tests::an_edited_outcome_or_deprecation_is_refused_and_old_fixtures_migrate` |
| M4 | `/verify/execution` wrote a Graphite-attested `confirmation` unconditionally; cited refusals could inject alarms | **Fixed**: `execution_check` unless inclusion was seen; a contradicted citation is `caller_keys_disagree` | `server::tests::an_l8_check_that_saw_nothing_is_not_a_confirmation`, `audit_2026_10_20_simulation_gate::a_cited_refusal_of_other_bytes_is_not_an_alarm` |
| M6 | Spend limits unlimited by default, not logged, per-transaction only; the SAK adapter required no cap | **Fixed**: the guard requires a cap in every adapter (`GRAPHITE_ALLOW_UNCAPPED=1` the named opt-out), logs the policy, and holds an optional rolling aggregate | `spend-policy.test.ts`, `guard-round29.test.ts` (M6), `env-example.test.ts` |
| M7 | Vercel approval opt-in; MCP elicited before resolution | **Fixed**: `needsApproval: true` by default; elicitation through `confirm(summary)` after the verdict | `guard-round29.test.ts` (M7), the Vercel and MCP suites |
| M8 | The key and the decision collaborators reachable from the same process | **Fixed** as far as JavaScript allows: key deleted from the environment, ES-private collaborators, frozen instance, read-only client. A process that rewrites the module remains out of scope | `guard-round29.test.ts` (M8) |
| M9 | L8 byte attribution only after finalization | **Fixed**: `getTransaction` at the configured commitment | `round29_rpc_client::get_transaction_asks_at_the_configured_commitment` |
| M10 | System `TransferWithSeed` layout wrong; admin setters classed `transfer`; 562 unclassed instructions | **Fixed**: layout corrected and `UpgradeNonceAccount` added; 128 setters to `authority`; 46 left unclassed by rule (3 `Revoke`s, 43 swaps) | `tests/system_program_manifest.rs`; the manifest suites |
| M11 | Token-2022 padded accounts falsely blocked | **Fixed** | `round29_state_diff::{a_mint_padded_past_the_multisig_length_reads_cleanly, short_tails_end_the_region_only_when_they_are_padding}`; B126 |
| M12 | Verification permits starved by dashboard calls | **Fixed**: a separate fixed pool of 16 for other routes; `/health` on neither | `server::tests::{non_verification_routes_cannot_hold_verification_permits, health_is_neither_shed_nor_rate_limited}` |
| M13 | Attack suites mapped errors to "blocked"; two holdout "successes" had failed on chain; no approved-path guard test; the contract gate vacuous without tags | **Fixed**: shared harness, specific causes, positive controls (30 cases marked as refused only for lack of evidence); the holdout scores 37 exploits and 1 real swap; approved paths driven through the guard; the gate runs against a committed `v0.2.0-beta` snapshot | `tests/attack_harness/mod.rs`, `tests/regression_corpus.rs`, `guard-round29.test.ts` (coverage), `tests/contract_version_gate.rs`; B127 |
| M14 | The BattleTested evidence had no effect on verdicts, contrary to the README | **Documented**: the README, ARCHITECTURE and `CURRENT.md` say it is registry and display information, with the measured thinness of the bar; decode rates recomputed at load | `tests/battle_tested_evidence.rs` |
| M15 | The dashboard showed capped windows as totals and hid a failed `/metrics` read | **Fixed** | the dashboard suite |
| M16 | No branch protection on `main` | **Owner decision**, open | — |
| LOW | Audit trail, server, CLI, Core, RPC, simulation integrity, state diff, parser, risk engine, guard, SDKs, infrastructure, the Python layer, scripts | **Fixed or documented**, area by area, in the round report's section 2 | the suites named there |
| Docs | Test counts four ways, "23 risk checks", L3 "failure → block", the BattleTested paragraph, the corpus size, "19-field parity", Quick Start without the key, missing banners | **Fixed**; `tests/docs_numbers_match_the_code.rs` now pins the registry's size and the corpus size, scans CONTRIBUTING and ROADMAP, and keeps test counts in `docs/CURRENT.md` only. Two generated figures in `docs/protocol-coverage.md` come from data files and are corrected in `CURRENT.md`, not on that page | `tests/docs_numbers_match_the_code.rs`, `tests/docs_match_the_registry.rs`, `tests/docs_paths_resolve.rs` |

**R-4, a trade-off recorded here.** The Risk Engine stopped judging the signing authority of an SPL
transfer and judges a destination at four trailing `1`s. Judging no source would have approved five
documented address-poisoning sends in the holdout, so a source is still judged at five. A user's own
wallet ending in five or more `1`s (about one random address in 656 million) is refused when it
sends.

## The forensic audit of `29e4356` (Round 30, 2026-10-22)

A whole-repository forensic audit of the Round 29 merge, worked by eleven workstreams against a
brief of twelve leads (G-01 … G-12) and every open item in these records. It found no P0, 5 P1,
14 P2 and 35 P3; every one is fixed except R30-J-2 (branch protection, an owner action). Each
finding, its test and the deliberate revert that showed the test fails without the fix are in
[`../docs/audit-r30/findings-registry.md`](../docs/audit-r30/findings-registry.md); the ledger of
every file, the architecture reconstructed from the code and the regression matrix of every
historical finding are in [`../docs/audit-r30/`](../docs/audit-r30/README.md).

| ID | Finding | Status | Test |
|---|---|---|---|
| R30-A-1 (G-01) | `approved: true` for bytes nothing had simulated, or for no bytes | **Fixed**: `decision` / `executable`; only `executable_approved` permits signing | `tests/round30_execution_decision.rs` |
| R30-B-1 (G-02) | A verdict approved under a profile the request named trained evidence for every caller | **Fixed**: evidence only at the built-in floor; the Round 29 opt-in retired | `tests/round30_trust_learning.rs` |
| R30-C-1 (G-07) | The audit trail could be rewritten coherently | **Fixed when keyed**: hash chain + HMAC; checkpoints for truncation | `tests/round30_audit_chain.rs` |
| R30-F-1 | A signer's loss under an unreadable declaration was a warning | **Fixed** for every class that does not move value; 155 that do: owner decision | `tests/r30_declared_effects.rs` |
| R30-H-1 (G-01) | The guard never checked the Core's decision against the verdict | **Fixed** | `integrations/agent-guard/guard-round30.test.ts` |
| M16 / R30-J-2 (G-11) | No branch protection on `main` | **Owner action, STOP-SHIP**: rulesets prepared, not applied | — |

The Round 29 risk-engine, registry, protocol-data and attack-suite fixes, which Round 29 did not
break-test, were broken check by check in Round 30 (R30-F-3); the nine no test caught now have
tests of their own.

## Break log

Every fix was reverted once, alone, with the tree otherwise unchanged, and its named test re-run; the fix was then restored and the tree checked clean. The harness is `graphite-audit-work/audit_breaks.py` (outside the repository): each break is an exact text edit validated against the current sources before it runs, and a break whose test still passes is reported MISSED.

**125 breaks, 125 caught** (B01–B59 in Round 23, B60–B103 in Round 24, B104–B107 in Round 25, B108 in Round 26: the committed mainnet blocks catch a verdict change, B109–B111 in Round 27: upgrade detection, B112–B125 in Round 28: the archive index, the emission table and the contract gate). Round 29 adds B126 and B127, run outside that harness and recorded below; the other areas' own revert runs are listed in the Round 29 report §5 (all caught where run; the risk engine, registry, protocol data and attack suites were not break-tested) and are not counted here, plus the TypeScript breaks TSB1–TSB11 (11 of 11 caught; TSB6–TSB11 are Round 25's swap grounding, negation, wallet-owner filter, response bound and exact lamports). One test was vacuous on its first run and is recorded as such: B54 (A4-11) still passed with the lock removed, because the audit log's own file mutex makes the race need microsecond timing. The test now holds the window between the history read and the append open for one dedicated trail id (`cfg(test)` only), and fails without the lock. In Round 24, B62 and B99 were missed on their first run, because each test did not exercise the reverted rule; B62's test was re-pointed to one that does and B99's was strengthened with cases only the reverted step decides, and both were then caught. B15 is caught by the test process aborting (a stack overflow prints no FAILED line), which the harness counts only when the test was running.

| Break | Finding | What was reverted | Test | Result |
|---|---|---|---|---|
| B01 | A1-01 | a close with a trailing byte is not counted as a close | `audit_a1_close_trailing_byte::a_draining_sibling_close_with_a_trailing_byte_is_still_blocked` | caught |
| B02 | A1-02 | a Compute Budget instruction with trailing bytes is refused as undecodable | `audit_a1_compute_budget_trailing::a_price_with_a_trailing_byte_is_the_price_the_runtime_charges` | caught |
| B03 | A1-03/A3-09 | non-ASCII ids pass the door and short_id byte-slices | `audit_a1_sibling_program_id_utf8_panic::a_non_ascii_sibling_program_id_is_refused_not_a_panic` | caught |
| B04 | A1-04 | the SPL Token batch (ff) entry removed from RISKY_PATTERNS | `audit_a1_token_batch_sibling::a_token_batch_sibling_wrapping_a_draining_close_is_blocked` | caught |
| B05 | A2-01 | the 'modifies writable accounts' name list is read as effects | `audit_a2_declared_effects_account_names::a_writable_account_named_owner_does_not_declare_an_authority_change` | caught |
| B06 | A2-01 | an effect declared about accounts.<name> excuses every account | `audit_a2_declared_effects_account_names::a_declared_owner_on_one_account_does_not_excuse_a_takeover_of_another` | caught |
| B07 | A2-02 | a raised allowance to an existing delegate is not a grant | `audit_a2_delegate_allowance_increase::raising_an_existing_delegates_allowance_is_an_undeclared_delegate_grant` | caught |
| B08 | A2-03 | a transfer under an unread Token-2022 mint is certified | `audit_a2_permanent_delegate_unread_mint::a_token2022_transfer_under_an_unread_mint_is_not_certified` | caught |
| B09 | A2-04 | a caller-supplied diff displaces the structural L4 failure | `audit_a2_caller_diff_displaces_structural_gate::an_empty_caller_diff_does_not_lift_a_structural_l4_failure` | caught |
| B10 | A2-05 | the snapshot drops the data hash and native authorities | `audit_a2_data_only_change_is_not_noop::a_rewritten_account_is_not_a_noop` | caught |
| B11 | A2-06 | mature baselines record edge observations unclamped | `audit_a2_baseline_variance_ratchet::accepted_observations_cannot_widen_the_band_eightfold` | caught |
| B12 | A2-07 | refused, flagged requests train the promotable shadow | `audit_a2_shadow_takes_refused_requests::refused_requests_do_not_fill_the_promotable_shadow` | caught |
| B13 | A2-09 | an RPC diff without balance arrays is Passed | `lib::verification::tests::an_rpc_diff_without_balance_arrays_is_not_a_pass` | caught |
| B14 | A2-10 | the replay gross is summed in u64 | `audit_a2_fee_replay_gross_sum_overflow::a_gross_above_u64_into_one_account_does_not_panic_the_diff_check` | caught |
| B15 | A2-11 | the instruction-trace and stack-height bounds lifted | `audit_a2_deep_inner_instructions_abort::a_deep_inner_instruction_report_does_not_abort_the_verifier` | caught (abort) |
| B16 | A3-01 | Stake Authorize removed from RISKY_PATTERNS | `audit_a3_authority_handover_primary::attack_stake_authorize_withdrawer_under_stake_intent_is_blocked` | caught |
| B17 | A3-01 | SPL Token ApproveChecked removed from RISKY_PATTERNS | `audit_a3_authority_handover_primary::attack_approve_checked_under_approve_intent_is_blocked_like_approve` | caught |
| B18 | A3-01 | loader SetAuthority unlisted and Check 2b off | `audit_a3_authority_handover_primary::attack_loader_set_authority_under_transfer_intent_is_blocked` | caught |
| B19 | A3-01 | Check 2b (derived authority_change) off | `audit_a3_authority_handover_sibling::attack_squads_set_config_authority_sibling_is_blocked` | caught |
| B20 | A3-01 | an instruction named Revoke no longer contradicts an approve intent | `audit_a3_authority_handover_primary::revoke_and_approve_are_opposite_declarations` | caught |
| B21 | A3-02 | siblings judged by the raw risk_class, not security_class() | `audit_a3_authority_handover_sibling::attack_squads_set_config_authority_sibling_is_blocked` | caught |
| B22 | A3-02 | the loader accepts an unknown risk_class | `audit_a3_manifest_lint::the_loader_refuses_an_unknown_risk_class` | caught |
| B23 | A3-02 | the loader accepts a self-referencing PDA seed | `audit_a3_manifest_lint::the_loader_refuses_a_seed_that_reads_its_own_slot` | caught |
| B24 | A3-02 | the loader accepts an empty discriminator beside others | `audit_a3_manifest_lint::an_empty_discriminator_describes_a_single_instruction_program_only` | caught |
| B25 | A3-03 | the quarantine gate does not see declared siblings | `audit_a3_quarantine_primary_only::attack_a_quarantined_program_as_a_sibling_is_blocked` | caught |
| B26 | A3-04 | an uncompared intent earns full alignment credit | `audit_a3_unknown_instruction_confidence::a_semantic_check_that_did_not_run_earns_no_alignment_credit` | caught |
| B27 | A3-05 | plugin rules reach the Risk Engine | `audit_a3_protocol_plugin_disarms_drainer::attack_a_protocol_plugin_rule_removes_a_risk_block` | caught |
| B28 | A3-06 | manifests_in_force keeps the document's own trust_tier | `audit_a3_community_tier_self_asserted::attack_a_self_declared_tier_outranks_the_computed_one` | caught |
| B29 | A3-07 | an accepted version can be resubmitted | `audit_a3_registry_replay_rollback::replaying_a_superseded_submission_does_not_roll_the_manifest_back` | caught |
| B30 | A3-10 | L1 is Passed with a failed identity check | `audit_a3_l1_report_truthfulness::l1_does_not_certify_an_identity_that_failed` | caught |
| B31 | A4-01 | a down primary suppresses the witness alarm | `audit_a4_l8_witness_alarm_primary_unavailable::a_witness_sighting_of_a_blocked_transaction_alarms_even_when_the_primary_is_down` | caught |
| B32 | A4-02 | only the first X-Forwarded-For line is read | `lib::server::tests::a_second_xff_line_does_not_choose_the_bucket` | caught |
| B33 | A4-02 | an XFF entry with a port is not parsed | `lib::server::tests::an_xff_entry_with_a_port_keys_its_client` | caught |
| B34 | A4-03 | the request-head read timeout is an hour | `audit_a4_slow_headers_hold_connections::a_client_that_never_finishes_its_request_head_is_disconnected` | caught |
| B35 | A4-04 | dashboard scans run on the async workers | `audit_a4_dashboard_scan_blocks_runtime::dashboard_reads_do_not_stall_the_rest_of_the_server` | caught |
| B36 | A4-05 | L8 runs without an effective RPC deadline | `audit_a4_l8_no_deadline::l8_reconciliation_finishes_inside_the_request_timeout` | caught |
| B37 | A4-06 | the audit record omits the wallet profile | `audit_a4_profile_override_not_on_trail::an_overridden_wallet_profile_is_on_the_audit_record` | caught |
| B38 | A4-07 | a wallet-profile 400 leaves no audit row | `audit_a4_profile_400_not_audited::a_refused_wallet_profile_leaves_a_trail_like_every_other_refusal` | caught |
| B39 | A4-08 | a processed-only witness counts as agreeing | `audit_a4_l8_witness_processed_agrees::a_witness_at_processed_is_not_a_second_source_of_inclusion` | caught |
| B40 | A4-12 | log lines are not escaped | `lib::server::tests::log_lines_escape_control_characters` | caught |
| B41 | A4 | same_endpoint compares trimmed strings | `lib::verification::tests::the_same_endpoint_written_differently_is_the_same_endpoint` | caught |
| B42 | A2-06 | the robust window learns the winsorized value | `lib::simulation_integrity::tests::test_window_ages_out_poison_and_recovers` | caught |
| B43 | CHECKED_PATTERNS | drifts from the labelled checks | `lib::risk_engine::tests::checked_patterns_counts_the_labelled_checks` | caught |
| B44 | F1 | name lists alone count as unrecognised | `lib::state_diff::tests::a_name_list_alone_declares_nothing_and_a_debit_under_it_is_critical` | caught |
| B45 | F2 | a named debit excuses a signer's other account | `lib::state_diff::tests::a_named_debit_does_not_excuse_draining_a_signers_other_account` | caught |
| B46 | F3 | the authority tag does not raise the security class | `lib::manifest::tests::the_authority_tag_raises_the_security_class` | caught |
| B47 | F3 | the verb + power rule is gone | `lib::manifest::tests::authority_change_names_are_recognised` | caught |
| B48 | F4 | sibling data bounded at 128 hex characters | `lib::verification::tests::a_sibling_with_long_data_is_not_refused_at_the_door` | caught |
| B49 | F5 | the winsorizing clamp is unguarded | `lib::simulation_integrity::tests::a_broken_baseline_does_not_panic_the_update` | caught |
| B50 | F7 | creator reads as creation | `lib::state_diff::tests::creator_does_not_declare_creation` | caught |
| B51 | F8 | no per-peer connection limit | `lib::server::tests::one_peer_cannot_hold_every_connection` | caught |
| B52 | F11 | the head resubmitted with nothing new is accepted | `lib::manifest_registry::tests::the_head_may_be_resubmitted_only_to_raise_its_tier` | caught |
| B53 | A4-09 | the verdict is counted before it is recorded | `lib::server::tests::a_verdict_that_could_not_be_recorded_is_not_counted` | caught |
| B54 | A4-11 | lifecycle reports are not taken one at a time | `lib::server::tests::concurrent_reports_of_two_signatures_cannot_both_miss_the_conflict` | caught; first run MISSED — test strengthened, re-run |
| B55 | F10 | the status calls may take the whole L8 budget | `audit_review_f10_l8_bytes_keep_their_budget::a_silent_witness_does_not_starve_the_bytes_fetch` | caught |
| B56 | F9 | dashboard scans are not bounded | `lib::server::tests::dashboard_scans_run_a_bounded_number_at_a_time` | caught |
| B57 | F16 | DelegateStake tagged authority again | `hell_mode_tests::h12_stake_delegate_stake_not_blocked` | caught |
| B58 | F18 | the nonce advance tagged authority again | `durable_nonce_rpc::a_permitted_nonce_advance_is_not_refused_as_a_hand_over` | caught |
| B59 | R1 | an approval named by a caller key is an execution of it | `audit_review_r1_l8_needs_chain_bytes::an_approval_named_only_by_a_caller_key_is_not_an_execution_of_it` | caught |
| B60 | R2 | L5 class gate reverted (`src/verification.rs`) | `audit_review_r2_r3_intent_cannot_clear_danger::r2_squads_drain_instructions_are_refused_as_a_transfer` | caught |
| B61 | R2 | Check 9b reverted (`src/risk_engine.rs`) | `audit_review_r2_r3_intent_cannot_clear_danger::every_manifest_instruction_under_every_intent_is_judged_by_its_class` | caught |
| B62 | R2 | L5 program serves intent reverted (`src/verification.rs`) | `l2_l4_l5_hard_gate::l5_refuses_an_intent_the_program_does_not_serve_even_when_the_class_and_words_fit` | caught; first run MISSED — test re-pointed, re-run |
| B63 | R2 | refuse only vocabulary reverted (`src/verification.rs`) | `audit_review_r2_r3_intent_cannot_clear_danger::the_class_gate_approves_nothing_the_previous_rule_refused` | caught |
| B64 | R2 | Revoke retag reverted (`protocols/spl-token.json`) | `audit_review_r2_r3_intent_cannot_clear_danger::honest_labels_pass_the_class_gate` | caught |
| B65 | R2 | PumpFun sell retag reverted (`protocols/pump-fun.json`) | `audit_review_r2_r3_intent_cannot_clear_danger::honest_labels_pass_the_class_gate` | caught |
| B66 | R3 | undescribed sibling reverted (`src/verification.rs`) | `audit_review_r2_r3_intent_cannot_clear_danger::r3_an_undescribed_instruction_of_a_described_program_is_refused_as_a_sibling` | caught |
| B67 | R3 | new verbs reverted (`src/manifest.rs`) | `audit_review_r2_r3_intent_cannot_clear_danger::the_name_rules_catch_the_review_list_and_leave_user_operations_alone` | caught |
| B68 | R3 | new powers reverted (`src/manifest.rs`) | `audit_review_r2_r3_intent_cannot_clear_danger::r3_control_changes_are_refused_as_the_primary_under_a_transfer_intent` | caught |
| B69 | R3 | compounds reverted (`src/manifest.rs`) | `audit_review_r2_r3_intent_cannot_clear_danger::r3_control_changes_are_refused_as_a_sibling` | caught |
| B70 | R3 | delegation grant reverted (`src/manifest.rs`) | `audit_review_r2_r3_intent_cannot_clear_danger::r2_bubblegum_delegate_is_refused_as_a_transfer` | caught |
| B71 | R3 | transfer fee noun reverted (`src/manifest.rs`) | `audit_review_r2_r3_intent_cannot_clear_danger::the_name_rules_catch_the_review_list_and_leave_user_operations_alone` | caught |
| B72 | R2 | corpus oracle reverted (`tests/regression_corpus.rs`) | `regression_corpus::dev_corpus_replays_with_high_pass_rate` | caught |
| B73 | W14 | unclassed sibling reverted (`src/verification.rs`) | `audit_review_r2_r3_intent_cannot_clear_danger::w14_an_unclassed_sibling_needs_an_intent_that_describes_it` | caught |
| B74 | W14 | sibling observed cpis reverted (`src/verification.rs`) | `round17_remediations::a_siblings_executed_cpis_are_judged_by_its_own_manifest` | caught |
| B75 | W15 | plugin rules in diff reverted (`src/verification.rs`) | `audit_a3_protocol_plugin_disarms_drainer::attack_a_protocol_plugin_rule_excuses_a_critical_state_change` | caught |
| B76 | W15 | duplicate plugin count reverted (`src/plugin_orchestrator.rs`) | `lib::plugin_orchestrator::tests::test_a_duplicate_registration_is_reported_not_counted` | caught |
| B77 | W15 | block named warning reverted (`src/plugin_orchestrator.rs`) | `lib::plugin_orchestrator::tests::test_a_block_named_warning_is_not_recorded_as_a_note` | caught |
| B78 | W17 | v1 unset limit is zero reverted (`src/tx_artifact.rs`) | `round19_v1_transactions::an_unset_v1_compute_limit_is_zero_not_a_default` | caught |
| B79 | W17 | account lock limit reverted (`src/tx_artifact.rs`) | `wire_format_bounds::more_accounts_than_the_bank_locks_is_refused` | caught |
| B80 | W16 | value count reverted (`src/rpc_client.rs`) | `lib::rpc_client::tests::an_rpc_answer_with_too_many_values_is_refused_before_parsing` | caught |
| B81 | W16 | sim without err reverted (`src/rpc_client.rs`) | `rpc_simulation_contract::a_simulation_without_an_err_field_is_not_a_success` | caught |
| B82 | W16 | meta without err reverted (`src/rpc_client.rs`) | `lib::rpc_client::tests::a_transaction_meta_without_err_is_not_a_success` | caught |
| B83 | W21 | scan permit held reverted (`src/verification.rs`) | `lib::server::tests::an_abandoned_scan_keeps_its_slot_until_it_ends` | caught |
| B84 | W21 | observation deferred reverted (`src/verification.rs`) | `audit_a2_shadow_takes_refused_requests::an_observation_trains_the_baseline_only_once_its_verdict_is_recorded` | caught |
| B85 | W21 | quarantine lift recorded reverted (`src/server.rs`) | `lib::server::tests::a_quarantine_lift_the_trail_cannot_record_is_not_applied` | caught |
| B86 | W21 | connection lifetime reverted (`src/server.rs`) | `audit_w21_connection_lifetime::an_idle_keep_alive_connection_is_closed_at_its_lifetime` | caught |
| B87 | W12 | upgrade gated reverted (`src/manifest_registry.rs`) | `lib::manifest_registry::tests::a_loosening_upgrade_at_the_same_tier_is_refused_by_the_replay` | caught |
| B88 | W12 | replay at computed tier reverted (`src/manifest_registry.rs`) | `lib::manifest_registry::tests::a_loosening_upgrade_at_the_same_tier_is_refused_by_the_replay` | caught |
| B89 | W11 | signer not attester reverted (`src/manifest_registry.rs`) | `lib::manifest_registry::tests::the_signer_does_not_attest_its_own_submission` | caught |
| B90 | W11 | fixture identity reverted (`src/regression_engine.rs`) | `lib::regression_engine::tests::a_fixture_that_is_not_what_its_input_says_is_refused_at_load` | caught |
| B91 | W19 | extension authorities reverted (`src/state_diff.rs`) | `lib::state_diff::w19_authority_tests::a_transfer_hook_authority_changing_hands_is_critical` | caught |
| B92 | W19 | nonce authority reverted (`src/state_diff.rs`) | `lib::state_diff::w19_authority_tests::a_nonce_authority_changing_hands_is_critical` | caught |
| B93 | W19 | recipient role reverted (`src/state_diff.rs`) | `lib::state_diff::w19_scope_tests::where_lamports_go_is_not_what_is_closed` | caught |
| B94 | W19 | revoke polarity reverted (`src/state_diff.rs`) | `lib::state_diff::w19_scope_tests::a_revoke_declares_no_delegate_grant` | caught |
| B95 | W19 | pending on zero fee reverted (`src/state_diff.rs`) | `round21_open_list::a_pending_majority_fee_blocks_on_the_arithmetic_path_too` | caught |
| B96 | W19 | unreadable delegate reverted (`src/state_diff.rs`) | `round21_open_list::extensions_judged_by_what_happened::a_mint_whose_extensions_do_not_decode_cannot_rule_out_a_permanent_delegate` | caught |
| B97 | W19 | signer lamports disclosed reverted (`src/state_diff.rs`) | `lib::state_diff::w19_scope_tests::lamports_leaving_the_signers_wallet_outside_the_declared_debit_are_disclosed` | caught |
| B98 | W22 | parameters schema reverted (`src/verification.rs`) | `lib::verification::tests::extracted_parameters_are_the_schema_every_client_sends` | caught |
| B99 | R2 | honest label by name reverted (`src/live_corpus.rs`) | `audit_review_r2_r3_intent_cannot_clear_danger::the_measurement_labels_an_instruction_by_its_name_then_its_class` | caught; first run MISSED (its cases were labelled the same without the name step) — test strengthened, re-run |
| B100 | R3 | switch names reverted (`src/manifest.rs`) | `lib::manifest::tests::a_name_that_opens_with_a_switch_is_a_control_change` | caught |
| B101 | R3 | admin signer reverted (`src/manifest.rs`) | `audit_review_r2_r3_intent_cannot_clear_danger::no_seed_instruction_with_an_admin_signer_or_a_switch_name_escapes_the_control_class` | caught |
| B102 | R3 | editPool retag reverted (`protocols/amm-program-tamm6u.json`) | `audit_review_r2_r3_intent_cannot_clear_danger::a_switch_an_edit_or_an_admin_signature_is_a_control_change` | caught |
| B103 | W22 | message version reverted (`src/verification.rs`) | `round19_v1_transactions::the_verdict_names_the_message_version_it_parsed` | caught |
| B104 | E3 | the witness is not asked for the bytes when the primary reports the signature (`src/verification.rs`) | `audit_a4_l8_witness_alarm_primary_unavailable::a_primary_without_the_bytes_does_not_hide_a_blocked_transaction_the_witness_saw` | caught |
| B105 | E3b | bytes not bound to the signature end the search (`src/verification.rs`) | `audit_a4_l8_witness_alarm_primary_unavailable::substituted_bytes_from_the_primary_do_not_silence_the_witness` | caught |
| B106 | E3b | an approval is reconciled as executed although a source served substituted bytes (`src/verification.rs`) | `audit_a4_l8_witness_alarm_primary_unavailable::substituted_bytes_from_the_primary_do_not_silence_the_witness` | caught |
| B107 | E8 | the 64-instruction trace limit off for legacy and v0 (`src/tx_artifact.rs`) | `wire_format_bounds::more_top_level_instructions_than_the_trace_holds_is_refused` | caught |
| B108 | R-P2 | the drainer heuristic (Check 3) off, so verdicts on real traffic move (`src/risk_engine.rs`) | `mainnet_conformance::the_committed_mainnet_blocks_give_the_recorded_verdicts_every_run` | caught |
| B109 | R-M1 | a redeploy is not a change (`src/semantic_graph_store.rs`) | `rm1_program_upgrade_detection::a_redeployed_program_is_reported_once_and_not_refused_by_default` | caught |
| B110 | R-M1 | the operator's quarantine-on-upgrade flag ignored (`src/verification.rs`) | `rm1_program_upgrade_detection::with_the_operator_flag_an_upgrade_quarantines_the_program` | caught |
| B111 | R-M1 | the loader reads not limited to the headers (`src/rpc_client.rs`) | `rm1_program_upgrade_detection::a_redeployed_program_is_reported_once_and_not_refused_by_default` | caught |
| B112 | R-M11 | a count no longer answered from the archive index (`src/durable.rs`) | `lib::durable::tests::archive_lookups_answer_from_a_persisted_index_across_restart` | caught |
| B113 | R-M11 | a lookup no longer answered from the archive index (`src/durable.rs`) | `lib::durable::tests::archive_lookups_answer_from_a_persisted_index_across_restart` | caught |
| B114 | R-M11 | an indexed record returned without being matched (`src/durable.rs`) | `lib::durable::tests::an_indexed_archive_offset_that_does_not_read_back_is_never_an_answer` | caught |
| B115 | R-M11 | the index not checked against the archive's SHA-256 (`src/durable/archive_index.rs`) | `lib::durable::tests::an_archive_index_that_does_not_check_is_rebuilt` | caught |
| B116 | R-M11 | the index file's trailer not checked (`src/durable/archive_index.rs`) | `lib::durable::tests::an_archive_index_that_does_not_check_is_rebuilt` | caught |
| B117 | R-M11 | rotation does not hand the active file's indexes to the archive (`src/durable.rs`) | `lib::durable::tests::a_rotated_archive_is_indexed_from_the_active_indexes_without_a_parse` | caught |
| B118 | R-M11 | an index that cannot be had is not remembered, so every lookup rebuilds (`src/durable.rs`) | `lib::durable::tests::an_unwritable_archive_index_falls_back_to_one_scan_per_lookup` | caught |
| B119 | R-M11 | pruning leaves the archive's index: the direct removal and the sweep, both reverted (`src/durable.rs`) | `lib::durable::tests::pruning_an_archive_removes_its_index` | caught |
| B120 | R-M11 | the sweep keeps a stopped write's temporary file (`src/durable.rs`) | `lib::durable::tests::warming_the_archive_indexes_checks_every_archive_and_sweeps_stale_files` | caught |
| B121 | R-P14 | an operator action made caller-reportable in the emission table (`src/durable.rs`) | `lib::server::tests::a_caller_cannot_forge_a_self_observed_event` | caught |
| B122 | R-P14 | `LifecycleEvent::ALL` missing a variant (`src/durable.rs`) | `lib::server::tests::every_lifecycle_event_reaches_the_trail` | caught |
| B123 | R-P14 | a stage recorded under a field the verification row does not fill (`src/durable.rs`) | `lib::server::tests::every_lifecycle_event_reaches_the_trail` | caught |
| B124 | R-M2 | closing an input object not counted as a break (`tests/contract_version_gate.rs`) | `contract_version_gate::the_breaking_rules_follow_who_writes_the_document` | caught |
| B125 | R-M2 | the CHANGELOG no longer names a break (`CHANGELOG.md`) | `contract_version_gate::the_contract_breaks_only_with_a_version_bump_and_a_changelog_entry` | caught |
| B126 | Round 29 (M9, M11, RPC and state-diff LOW items) | `src/state_diff.rs` and `src/rpc_client.rs` reverted together to their pre-fix versions (not one fix alone) | `round29_rpc_client` (11 of 11 failed), `round29_state_diff` (15 of 17 failed; its two controls passed), `token2022_extensions::zero_padding_shorter_than_a_header_ends_the_region`, `round20_transfer_fee::an_undeclared_change_to_the_fee_terms_blocks` | caught (28 failures) |
| B127 | Round 29 (M13, the contract gate) | `raw_natural_language` removed from `proposed-intent-v1.json` | `contract_version_gate`, in a checkout with no tags | caught |
