# AUDIT 01 — Findings and fixes (2026-09-29 → 2026-09-30)

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
  - **Open, and not claimed as fixed:**
    - The SAK bridge's dependency tree carries 36 distinct high/critical npm advisories, all in runtime dependencies:
      - `@solana/web3.js` 1.x (`bigint-buffer`, `node-fetch`);
      - the `plugin-defi` and `plugin-token` trees the bridge loads (`form-data` and `protobufjs` are critical);
      - the agent frameworks.
    - None has a non-breaking fix. `npm audit fix` without `--force` cleared none of the criticals.
    - They are allowlisted one by one with their dependency paths, so any new advisory fails CI.
    - Removing them needs the `@solana/kit` migration (roadmap gap R-P8) and upstream releases.
    - The dashboard's `vite` 5 has one high advisory affecting only the dev server; the fix is a major upgrade.
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

## Break log

In progress. B01–B19 (A1-01 through A3-01) have run: each fix reverted, its test re-run, and all 19 caught. B20–B58 run after this commit; the results replace this paragraph.
