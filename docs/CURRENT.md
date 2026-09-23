# Graphite â€” Current Status

**This is the one document that describes the codebase as it is now.** Every
other file in `docs/` is a dated record of what was true when it was written;
each carries a banner pointing here. When this file and a report disagree,
this file is current and the report is history.

Updated: 2026-09-22, after Round 18 (see `git log -1 -- docs/CURRENT.md`).
If that commit is not HEAD, later commits may have moved things;
`git log --oneline -- docs/CURRENT.md` shows when this page last changed.

---

## What Graphite is

A deterministic, pre-signature verification gate between an AI agent and a
Solana wallet. It takes a description of an intended transaction plus,
whenever possible, the exact serialized transaction bytes, runs an eight-layer
pipeline over them, and returns `approved: true | false` with a full account
of what was and was not observed. **AI never decides** (Constitution P1); the
verdict is deterministic (P2) and explainable (P3); anything Graphite cannot
observe is refused rather than assumed (P12).

## Security status

```
Overall:                         CONDITIONAL â€” security-hardened alpha
Exact transaction identity:      enforced (artifact_bound scope, transaction_sha256, message-equality at signing);
                                 an artifact without instruction_data, or one that does not parse, FAILS L2 (Round 9)
Residuals at execution:          gated â€” scope.unobserved_codes; the bridge refuses any non-inherent residual
                                 the operator has not accepted by code (GRAPHITE_ACCEPT_UNOBSERVED)
ALT / v0 account identity:       enforced (runtime numbering rebuilt; all-or-nothing resolution; owner checked)
Privilege source:                the transaction's header / tables, never the caller's description
Instruction identity for risk:   the instruction's own leading bytes, never the caller's label â€” a hex
                                 discriminator contradicting its instruction_data fails L2 for every protocol,
                                 a non-hex one never reaches a verdict, and the known-risky table is keyed on
                                 the bytes so a truncated but truthful label hides nothing (Round 13)
Authority changes in the diff:   the SPL owner field, mint authority and freeze authority are each watched;
                                 an undeclared change is Critical, so a hand-over that moves no value is seen
Measured on real mainnet:        10,669 transactions from 8 finalized blocks, 189 programs, run artifact-bound:
                                 0 parse failures, 0 false refusals from the L2 self-consistency check, and all
                                 1,087 known-risky-table blocks verified against the named instruction's own
                                 bytes. Round 13 changed 0 of 9,784 verdicts (`tools/mainnet-sample`)
Manifest coverage of the chain:  129 manifests / 3,186 instructions. On a 10,617-transaction mainnet sample,
                                 44.0% of non-vote transactions have a manifested primary program, up from 20.8%
                                 for the same sample before Round 18. The rest still meet the drainer heuristic
                                 (>=3 accounts, no declared state changes), which is the fail-closed posture at
                                 the coverage boundary, not a bug
Trust tier a manifest declares:  checked, not believed - `BattleTested` is lowered to `OfficialManifest` at load
                                 unless protocols/battle_tested_evidence.json shows an executable program, >=1,000
                                 successful transactions over a stated window, and >=90% of really-observed
                                 instructions named by the manifest (Round 18)
Message version 1:               refused by name, and no longer rare: 17.2% of the same sample. Fail-closed and
                                 honest, but roughly one mainnet transaction in six is one Graphite cannot verify
Durable-nonce transactions:      refused at L2 by default; opt-in requires on-chain nonce verification
Token-2022 extensions:           classified, not modelled â€” semantics/authority/unknown/unreadable all block
Input bounds:                    artifact â‰¤ 1232 bytes (PACKET_DATA_SIZE), â‰¤ 256 declared siblings, every
                                 audit-trail field bounded on the way to disk
Pre-signed artifacts:            refused at /verify â€” any non-zero signature slot is a 400; the bound digest is
                                 the unsigned frame's, the same one L8 recovers from the chain (Round 17)
What trains the baseline:        only a sound, risk-clear, successfully simulated transaction; err != null is
                                 not evidence; the same bytes re-verified are ONE observation; a uniform history
                                 is a Â±25% band, refused-but-clean executions accumulate in a shadow that /health
                                 reports and an operator can promote (Round 17)
Observed CPI targets:            read from the simulation's innerInstructions and judged by the same rules as a
                                 declaration; declaring nothing switches nothing off (Round 17)
Lookup-table resolution:         approval is conditioned on it â€” an unresolved position fails L2 (Round 17)
Audit trail durability:          fdatasync per record; whole-trail reads across rotated archives; indexed L8 join
L8 execution attribution:        joined on the chain's bytes (signature slots zeroed â†’ scope.transaction_sha256),
                                 accepted only when bound to the signature â€” first slot equal to it, verifying
                                 under the fee payer's key â€” else refused with nothing attributed (Round 11);
                                 caller keys audit_trail_id â†’ transaction_sha256 â†’ content_hash, most exact first,
                                 cross-checked, never falling back (Round 10); a cited audit_trail_id for OTHER
                                 bytes is named (RecordedForDifferentBytes, a discrepancy when it was a refusal)
                                 and every verdict on record for the chain digest is counted (Round 17)
L8 inclusion evidence:           commitment read (processed proves nothing); an RPC contradicting itself or answering
                                 malformed draws no conclusion; redirects refused; optional independent witness
                                 (GRAPHITE_RPC_WITNESS_URL) must agree before an approval is reported executed;
                                 a blocked transaction sighted by either endpoint alarms (Round 12)
Parser vs the runtime:           never looser than agave's decoder + sanitize, proven in CI over the corpus and
                                 600,000 generated frames (tools/runtime-oracle, Round 12)
Lifecycle sequence:              every report checked against the rows on record â€” duplicate / out of order /
                                 unpreceded / signature conflict â€” recorded, never refused (Round 12)
One server per data directory:   enforced by an exclusive lock on graphite.lock (Round 12)
Lifecycle on the trail:          the bridge records signing before submission and submission after it, and runs
                                 L8 at the end, with the exact keys; every lifecycle row carries verdict_on_record
                                 and the key that resolved it
Server authentication:           required by default, â‰¥ 32 characters; GRAPHITE_DEV_MODE=1 permits keyless on loopback only
Request path:                    no per-request deep copy of state (/health ~1 ms; 960 verifies/s in-process with
                                 fdatasync per record); refusals drain the body and are readable (Round 11)
Repository integrity:            CI token read-only; actions pinned by commit SHA; base images pinned by digest;
                                 toolchain 1.98.1 in CI and in the container; Go, cargo-audit and Python (hash-locked) pinned
Independent third-party audit:   NOT PERFORMED â€” every campaign report is internal engineering work
Branch protection on main:       ABSENT â€” an owner decision; see "Not yet done"
```

"Conditional" means: no known way to turn a blocked verdict into an executed
transaction under the stated threat model, and no external party has yet tried.

## What is enforced (and where the test lives)

| Property | Enforced by | Reproduction |
|---|---|---|
| The signed message is the verified message | `BoundTransaction.signApproved` (TS): digest re-check, signer set derived from the compiled message, message-slice equality | `integrations/solana-agent-kit/bound-transaction.test.ts`, `execution-boundary-fuzz.test.ts` |
| A descriptive verdict never reaches execution | `ResidualPolicy.assertExecutable` requires `scope.kind === "artifact_bound"` | `residual-policy.test.ts`, `toctou-signing-boundary.test.ts` |
| An approved verdict with an unaccepted residual never reaches execution | `ResidualPolicy` (bridge): every non-inherent `unobserved_codes` entry refuses unless named in `GRAPHITE_ACCEPT_UNOBSERVED` / `acceptUnobserved`; a server reporting no codes refuses | `residual-policy.test.ts` (each of the 12 non-inherent codes), `execution-lifecycle.test.ts` |
| `artifact_bound` means the described instruction was located in the bytes | L2 artifact branch: parse failure fails; missing `instruction_data` fails; exact-data match at one position under the described program and accounts | `tests/round9_identity_requires_data.rs` (100 SOL under a 0.002 SOL description, refused), `tests/artifact_binding.rs` |
| Instruction identity is positional and complete | `compare_instruction_accounts`, `sibling_coverage` | `tests/instruction_account_identity.rs`, `tests/described_siblings.rs` |
| An artifact the network would refuse is refused before it is parsed | `MAX_TRANSACTION_BYTES` = 1232 at `/verify` entry, in `parse_transaction`, and in TS `messageOf`; `MAX_TRANSACTION_INSTRUCTIONS` = 256 | `tests/round9_resource_bounds.rs` (122 s â†’ 1.6 ms) |
| ALT accounts are identified, not counted | `runtime_account_list`, `resolve_lookups`, owner check | `tests/alt_real_v0.rs` (3 real mainnet v0 txs, `meta.loadedAddresses` ground truth), `tests/alt_privilege.rs` |
| Privileges come from the bytes | `privileges_from_artifact` | `tests/privilege_from_artifact.rs` |
| A risky instruction cannot hide behind the name it was given | L2's `declared_discriminator_contradicts_data` runs first, for every protocol, manifested or not; `transaction_builder` refuses a non-hex discriminator outright; **every manifest lookup â€” account resolution, the declared-effects lookup, the risk context, the plugin rules â€” is keyed on the instruction's own first eight bytes, not on the caller's label** | `tests/mislabelled_discriminator.rs` (16), `tests/truncated_discriminator.rs` (22) |
| A label that is TRUE BUT SHORT cannot switch off the account checks | Round 14 (GFX-101): `discriminator_matches` is `input.starts_with(selector)`, so a label shorter than a selector missed the manifest, and the miss took `resolve_accounts` down the P12 path whose accounts carry `pda_mismatch`/`expected_address_mismatch`/`privilege_mismatch` all false. One `effective_discriminator`, derived from the bytes, now keys them all; an EMPTY label is covered too (GFX-108) | `tests/truncated_discriminator.rs` (Jupiter V6 route with an attacker program in the pinned token-program slot: full label and 4-byte label and empty label all produce the identity finding; the honest pinned account still clears) |
| A declared sibling is judged on its own bytes, not its label | Round 14 (GFX-106): `sibling_coverage` records which artifact instruction each declaration matched and `siblings_keyed_on_their_bytes` rewrites the discriminator from that instruction's data before the Risk Engine sees it. A declaration matching nothing is left as written â€” L2 has already failed | `tests/truncated_discriminator.rs` (a real System `Assign` declared `01`/`0100`, a real SPL `SetAuthority` declared `0`, and a Raydium CPMM `close` declared at half length, all still block) |
| A sibling's lookup-table accounts are compared, not assumed | Round 14 (GFX-107): the primary's comparison resolved ALT positions and a sibling's did not, so every lookup slot in a declared sibling accepted any address â€” and declared accounts widen the set `ArtifactAccountsNotDescribed` treats as named | `tests/sibling_lookup_accounts.rs` (mock RPC serving one table: the honest declaration is accepted, one naming a different address at the resolved position fails L2) |
| A declaration too short to identify a risky instruction is refused | Round 14: `disc_matches` fires when the input is at least as long as the selector; a strict PREFIX of one sat in the gap. Reachable only in descriptive mode, where there are no bytes to re-derive from | `tests/truncated_discriminator.rs` (a descriptive `01` on System, and a descriptive `0` sibling on SPL Token, are both refused; a complete `03` still clears) |
| The gate behaves the same on real traffic as on the fixtures | Whole finalized mainnet blocks, every transaction pushed through the full pipeline artifact-bound â€” real bytes, real data, accounts resolved from the block's own `loadedAddresses`, every sibling declared | `tests/mainnet_conformance.rs` + `tools/mainnet-sample` (10,669 transactions, 2026-09-17: 0 parse failures, 0 false refusals, 1,087/1,087 risky-table blocks confirmed against the real bytes, 0 verdicts changed by Round 13) |
| An undeclared authority change is a finding, not silence | `state_diff::AccountDelta::{token_authority_change, mint_authority_change, freeze_authority_change}` â€” the SPL `owner` field is the authority, distinct from `owner_change`'s owning program | `state_diff::tests::{a_token_account_changing_hands_is_critical, a_mint_authority_changing_hands_is_critical, a_freeze_authority_appearing_from_nothing_is_critical}` plus four controls |
| Wire-format bounds on both sides | `compact_u16` (Rust), `messageOf` / `readSignatureCount` (TS) | `tests/wire_format_bounds.rs`; 1,647-mutation cross-language corpus in `tests/sak_bridge_corpus.rs` |
| Provider fields cannot override canonical evidence | `rpc_client.rs` derives writes/hops from canonical fields only | `tests/provider_field_precedence.rs` |
| Token-2022 classification is fail-closed | `detect_token2022_extensions`, `ExtensionScan.malformed` | `tests/token2022_extensions.rs`, `tests/l4_state_diff_gate.rs` |
| Durable-nonce transactions are refused unless verified | `tx_artifact::durable_nonce`, L2 gate | `tests/durable_nonce.rs`, `tests/durable_nonce_rpc.rs` |
| Audit records are synced to the device before the response | `AuditLog::append_line` â†’ `sync_data` | Established by code reading â€” no userspace test can observe it; `durable::tests::audit_append_syncs_the_device` measures the cost (1.2 ms vs 19 Âµs for the no-op it replaced) and asserts nothing |
| L8 reconciliation sees the whole trail | `AuditLog::find_verification` by `audit_trail_id` / `transaction_sha256` / `content_hash`: indexed active file, archives newest-first | `durable::tests::read_path_covers_every_archive_after_rotation`, `last_verification_index_tracks_rotation_and_reopen`, `tests/round10_attribution.rs` |
| An executed blocked transaction is attributed to ITS verification, not to a same-instruction approval | `audit_execution`: `getTransaction` bytes â†’ `bound_artifact_sha256` â†’ digest â†’ `find_verification(TransactionSha256)`; caller keys most-exact-first with no fallback; `caller_keys_disagree` | `tests/round10_attribution.rs` (approved A newest, blocked B executed â†’ `BlockedButExecuted`, attribution `chain`) |
| The chain's bytes are the signature's, not merely the RPC's | `tx_artifact::bound_artifact_sha256`: first slot equals the signature; ed25519 `verify_strict` over the message under the fee payer's key; rejected bytes â†’ `Unavailable`, `chain_bytes_rejected`, no fallback to caller keys | `tests/round10_attribution.rs::{chain_bytes_are_accepted_only_when_bound_to_the_signature, an_rpc_that_substitutes_bytes_cannot_attribute_the_execution}`; `tests/l8_live_mainnet.rs::l8_real_chain_bytes_are_bound_to_their_signature` (public devnet, ignored by default) |
| A frame the runtime would not sanitize is not a transaction | `parse_transaction`: `SignatureCountMismatch`, `ImpossibleHeader` (no writable signer), `ProgramIsFeePayer`, `AccountIndexOutOfRange` (legacy and v0), `EmptyLookup`, `TooManyAccounts` | `tests/round12_runtime_sanitize.rs`; `tests/sak_bridge_corpus.rs`; **`tools/runtime-oracle`** against agave's decoder + `sanitize` over the corpus and 600,000 generated frames, in CI (job `runtime-oracle`) |
| L8 draws no positive conclusion from one node's view, a self-contradicting RPC, or a malformed status | `rpc_client::InclusionCommitment`; `get_signature_status` strict; `ChainTransaction` slot/outcome held against the status â†’ `chain_inconsistent` | `tests/round12_rpc_equivocation.rs::{a_processed_status_is_not_a_positive_conclusion, an_rpc_that_contradicts_itself_gets_no_positive_conclusion, a_malformed_status_is_never_a_conclusion, a_status_without_bytes_is_disclosed_as_caller_attributed}` |
| Redirects from an RPC are never followed | `SolanaRpcClient::new` â†’ `Policy::none()` | `tests/round12_rpc_equivocation.rs::a_redirecting_rpc_is_not_followed` (the target records zero hits) |
| An approval is reported executed only when two independent RPCs agree; a blocked transaction seen by either alarms | `GraphiteCore::attach_inclusion_witness`, `compare_witness`, `ExecutionAudit.inclusion_witness` | `tests/round12_rpc_equivocation.rs::{a_positive_conclusion_needs_the_witness_to_agree, either_endpoint_seeing_a_blocked_transaction_alarms, a_witness_that_is_the_primary_is_refused}`; the probe with a mock witness |
| The RPC endpoint is validated before the process claims to simulate | `rpc_client::validate_endpoint` at server startup and in the CLI | `tests/round12_rpc_equivocation.rs::endpoints_are_validated_before_a_client_exists`; the probe's startup refusals |
| One server per data directory | `server::lock_data_dir` (`graphite.lock`, exclusive advisory lock) | `server::tests::a_data_directory_is_held_by_one_process`; the probe (a second server refuses while the first runs) |
| A lifecycle report is checked against the rows on record for its transaction | `AuditLog::lifecycle_history` (per-transaction index), `lifecycle_sequence_anomalies` | `server::tests::{lifecycle_reports_in_order_carry_no_anomaly_and_a_retry_is_a_duplicate, lifecycle_reports_out_of_sequence_are_named_and_a_second_signature_is_loud, graphite_observed_rows_are_marked_and_are_not_duplicates_of_reports, submission_onward_requires_a_real_signature}`; `durable::tests::lifecycle_history_*` |
| An L8 row attributed by `content_hash` claims no exact identity | `execution_handler` writes exact keys only for exact attributions | `server::tests::an_l8_row_attributed_by_content_hash_carries_no_exact_keys` |
| The bridge's submission report survives a lost answer | `executeBoundTransaction` retries (3 Ã— doubling backoff); a repeat is a `duplicate` on the trail | `execution-lifecycle.test.ts` (fails once â†’ recorded on the second try; lost answer â†’ duplicate, counted as recorded) |
| The request path does not deep-copy state | `AppState.core: Arc<GraphiteCore>`, `registry_engine: Arc<â€¦>` | `server::request_path_cost::{app_state_clone_is_a_reference_count_not_a_deep_copy, health_answers_in_milliseconds_on_loopback}` |
| A refusal is readable, never a reset | `refuse_after_draining` on 401 / 429 / 503 | `server::request_path_cost::early_refusals_drain_the_body_so_the_status_is_readable` |
| The API key is not guessable by length | `server::MIN_API_KEY_CHARS` = 32 in `auth_posture` | `server::tests::auth_is_required_unless_dev_mode_is_named_and_the_bind_is_loopback` |
| The SDK and the server agree on the wire | `sdk/typescript/src/live-server.test.ts` against the CI container, failing if skipped | `.github/workflows/ci.yml` container job |
| A lifecycle `verdict_on_record` is about the transaction the event names | `/audit/event` resolves by `audit_trail_id`, else `transaction_sha256`, else `content_hash`; contradicting keys â†’ 400 | `server::tests::lifecycle_verdict_resolves_by_the_most_exact_key_and_refuses_contradiction` |
| A compressed RPC response cannot outgrow the cap | `read_body_capped` bounds decompressed chunks | `tests/round10_rpc_decompression.rs` (65 KB â†’ 64 MiB refused in 35 ms) |
| Caller-reported lifecycle rows are bounded and carry what the trail knows | `LifecycleEventRecord::bounded`, `/audit/event` shape and length checks, `verdict_on_record` computed server-side | `durable::tests::lifecycle_event_fields_are_bounded_on_disk`, `server::tests::lifecycle_events_carry_the_verdict_on_record` |
| The bridge's signing and submission are on the trail, in order | `executeBoundTransaction`: policy â†’ sign â†’ record signing (abort if not recorded or not `approved` on record) â†’ submit â†’ record submission â†’ confirm â†’ L8 | `execution-lifecycle.test.ts` |
| Keyless server cannot start on a reachable address | `server::auth_posture` | `server::tests::auth_is_required_unless_dev_mode_is_named_and_the_bind_is_loopback` |
| L8 rows on the trail carry the whole reconciliation detail | `durable::MAX_LIFECYCLE_DETAIL_CHARS` (1024) at the boundary and on disk | `durable::tests::lifecycle_event_fields_are_bounded_on_disk` |
| An artifact signed before it was shown is refused | Round 17 (F-16-01): `tx_artifact::filled_signature_slots` at `/verify` entry â€” any non-zero slot is a 400; `scope.transaction_sha256` is the digest of the unsigned frame by construction | `tests/round17_remediations.rs::a_presigned_artifact_is_refused_at_verify` |
| L8 names a cited verdict about OTHER bytes, and alarms when it was a refusal | Round 17 (F-16-01): `ExecutionReconciliation::RecordedForDifferentBytes { recorded_approved, .. }`, a discrepancy when `!recorded_approved`; `recorded_verdicts {approved, refused}` for the chain digest (F-16-11) | `round17_remediations::a_cited_verdict_about_other_bytes_is_reported_and_a_cited_refusal_alarms`, `::l8_reports_every_verdict_recorded_for_the_chain_digest` |
| Only a SOUND transaction trains the baseline, and the same bytes are one observation | Round 17 (F-16-03 / F-15-01 / F-15-02): recording after the verdict, gated on `rpc_sim_ok` (now `err == null`), no structural failure, risk Clear; keyed on the artifact digest (`record_simulation_keyed`) | `round17_remediations::an_l2_refused_request_does_not_grow_the_baseline`, `::an_errored_simulation_is_not_evidence_and_is_named`, `::identical_approved_bytes_are_one_observation`, `::the_same_request_is_not_approved_on_the_second_call` |
| A failed simulation is named, never "clean" | Round 17 (F-16-04): `UnobservedCode::SimulationFailed`; L3 reports "FAILED" | `round17_remediations::an_errored_simulation_is_not_evidence_and_is_named` |
| A uniform history is a band, not a point | Round 17 (F-16-02): `simulation_integrity::effective_spread` (25% of centre, floor 1.0) on both the mean/std and robust paths; flagged-but-clean executions go to the shadow accumulator; `/health.frozen_baselines`; `graphite evidence promote-shadow` | `round17_remediations::ten_identical_samples_do_not_refuse_the_eleventh_at_plus_one_cu`, `simulation_integrity::tests::test_zero_variance_baseline_is_a_band_not_a_point` |
| Approval is conditioned on lookup-table resolution | Round 17 (F-15-05): an unresolved primary position fails L2; `SiblingCoverage.unresolved_positions` fails L2 | existing ALT tests; `tests/alt_*.rs` |
| Manifest risk metadata is keyed on the bytes | Round 17 (F-15-03): `manifest_risk_class` / expected count / variable flag looked up with `effective_discriminator` | `tests/mislabelled_discriminator.rs`, `tests/truncated_discriminator.rs` |
| Observed CPI targets are judged like declared ones | Round 17 (F-16-05): `rpc_client::SimulationResult.inner_program_indexes` â†’ `observed_cpi_callees` â†’ `assess_with_warnings` | `round17_remediations::an_observed_cpi_target_the_caller_omitted_is_judged_like_a_declared_one` |
| The PDA seed template grammar is closed | Round 17 (F-16-06): `resolve_pda_seed_template` returns `Result`; `validate_seed_template` at manifest load and registry submission; an unresolvable-for-this-request template flags the slot | `manifest::tests::test_unsupported_seed_templates_are_refused_at_load` |
| A panicking blocking plugin fails closed | Round 17 (F-16-07): Risk/Verifier/Policy panic â†’ `Block { pattern: "<name>:panicked" }`; plugin-dir load failure is a startup error | `plugin_orchestrator::tests::test_panicking_blocking_plugin_fails_closed`, `tests/plugin_framework.rs` |
| Malformed policy input is a 400 before the pipeline; both profile axes are clamped | Round 17 (F-16-08 / F-15-07): `enforce_wallet_profile` returns `Err` for `min_confidence > 1`; `WEAKEST_BUILTIN_MIN_TRUST_TIER` | `server::tests::min_confidence_above_one_is_refused_up_front`, `::unknown_tier_floor_is_raised_to_the_weakest_builtin` |
| `content_hash` is framed | Round 17 (F-16-09): domain tag + u32 LE length prefixes + list counts, mirrored in TS SDK, SAK AuditBind, Go | `verification::tests::test_content_hash_is_injective_across_field_boundaries`; pinned vectors `48c65c638aceb5de` / `dd8569c46af7e6c0` in all four suites |
| Manifest URLs are links only when http(s) | Round 17 (F-16-10): `manifest::validate`, `manifest_registry::validate_manifest`, console `httpUrl()` | `manifest::tests::test_manifest_url_fields_must_be_http` |
| A manifest may not award itself a trust tier | Round 18: `load_seed_manifests` lowers a declared `BattleTested` unless `protocols/battle_tested_evidence.json` clears `manifest::battle_tested_bar` on all three axes; the gate reads the raw measurements, never the file's own verdict field | `tests/battle_tested_evidence.rs` (8 tests, one per axis and one proving the verdict field is ignored) |
| Every seed manifest has a mainnet measurement on record | Round 18: identity, volume over a stated window, and the share of really-observed instructions the manifest can name; reproducible with `scripts/battle_tested_census.py` | `battle_tested_evidence::every_seed_manifest_has_a_measurement_on_record` |
| The manifest list and the manifest directory agree | Round 18: one `SEED_MANIFESTS` list produces both the name and the baked-in contents (the `include_str!` match arms are gone), and the list is compared to `protocols/` in both directions | `manifest::tests::test_every_protocol_file_is_a_seed_manifest` |
| The documented protocol table is the loaded registry | Round 18: `docs/protocol-coverage.md` is generated; the test compares every row's program id, name, instruction count and APPLIED tier against `load_seed_manifests()`, and the README's headline counts too | `tests/docs_match_the_registry.rs` |
| An account the manifest never declared has no privilege to mismatch | Round 18: an `extra` slot past the declared list is `remaining_accounts`; comparing the real `AccountMeta` against the placeholder blocked 1,036 real mainnet transactions across four programs | `privilege_mismatch::an_undeclared_extra_account_has_no_privilege_to_mismatch`, `::extras_do_not_mask_a_real_privilege_mismatch_on_a_declared_slot` |
| A swap program is one whose manifest says so | Round 18: `is_swap_program` reads `"category": "swap"` from the loaded manifests instead of a second hand-kept list; the trusted-CPI list stays hand-curated, because it RELAXES checks | `manifest::tests::manifest_category_aligns_with_swap_set` |

## What is NOT enforced (documented limitations)

- **Token-2022 `TransferFee` is refused, not modelled.** Fee-bearing mints
  block. Modelling the fee is the path to accepting them.
- **An accepted residual is the operator's decision.** Every `artifact_bound`
  verdict carries the two inherent residuals (`program_semantics`,
  `inner_instructions`); every other code refuses execution unless the
  operator names it in `GRAPHITE_ACCEPT_UNOBSERVED`. The bridge enforces the
  configuration; it does not second-guess it, and the outcome records what
  was accepted.
- **Pre-signature verification has a window.** The chain moves between
  verification and execution; the blockhash bounds that window to about a
  minute for ordinary transactions, and a permitted durable nonce removes the
  bound.
- **The manifest set covers a small slice of the chain.** Measured
  2026-09-17: 92.5% of mainnet transactions sampled call a program with no
  manifest, and 189 distinct programs appeared in eight blocks against 33
  shipped manifests. An unmanifested program declares no state changes, so
  the drainer heuristic blocks every call to one that touches three or more
  accounts. That is the intended fail-closed direction â€” it refuses rather
  than guesses â€” but it means an agent working outside the manifested set
  is refused, not merely scored lower, and the honest description of
  today's coverage is "the protocols Graphite knows", not "Solana".
- **Single-tenant.** One API key, one profile pin, one trail, one semantic
  graph per process. Tenant isolation is process isolation.
- **Archive lookups are scans.** The L8 / lifecycle join is indexed for the
  active file; a key older than the last rotation costs one pass over each
  archive.
- **L8's inclusion evidence is as independent as the RPCs it is given.** A
  `processed` status, a self-contradicting RPC or a malformed status draws no
  positive conclusion; with `GRAPHITE_RPC_WITNESS_URL` two independent
  endpoints must agree before an approval is reported executed, and either
  endpoint's sighting of a blocked transaction alarms (Round 12). Two RPCs
  behind one provider are two views of one answer; a light-client inclusion
  proof is not built. Without a witness the reconciliation says
  `inclusion_witness: null`.
- **The runtime oracle covers what it generates.** Agave's `wincode` decode
  path is not a second oracle; the generator is seeded and structure-aware,
  not coverage-guided.
- **Version-1 transactions are refused, not understood.** They are live on
  devnet (2026-09). The parser refuses them by name, L8 reports the RPC's
  refusal as `Unavailable`, the live corpus skips them; nothing fails open,
  and nothing v1 can be verified until the format is implemented.
- **The lifecycle-sequence check sees the active file and the newest
  archive.** A lifecycle across two rotations is checked against what it saw.
- **One server per data directory, enforced by a lock.** Two servers on one
  directory would each see half a trail; the second now refuses to start.
- **A body over the 1 MiB limit may be answered with a reset** rather than a
  readable 413; refusals below the limit are drained and readable.
- **Without the chain's bytes, L8 is only as exact as the caller's keys.** An
  RPC without `getTransaction`, a pruned ledger, or no RPC leaves attribution
  on `audit_trail_id` â†’ `transaction_sha256` â†’ `content_hash`; the last names
  every transaction carrying that instruction and the answer says so.
- **Rows written before Round 10 carry no `transaction_sha256`**; they are
  reachable by id and `content_hash` only.
- **A compromised process is out of scope.** Deep copies, private fields and
  digest checks defend against callers and plugins that behave like
  JavaScript; not against code that rewrites the bridge module.
- **Without RPC, L3 is Inconclusive** and confidence is capped below every
  built-in profile's threshold; `approved` is unreachable. This is the intended
  fail-closed shape, not a degraded mode.
- **Lifecycle events reported by callers are attestations.** `POST
  /audit/event` records what the caller said with `reported_by`; Graphite
  cannot witness a signing it did not perform and does not claim to. What it
  does establish, on every row, is `verdict_on_record` â€” what its own trail
  said about the hash when the report arrived â€” and it counts and logs a
  report against a blocked verdict as the gate being bypassed.

## Not yet done

| Item | Status | Whose decision |
|---|---|---|
| Independent third-party audit | Not performed | Owner |
| Rounds 15â€“16 findings | **Closed in Round 17** (every item, each with a regression test; see the Round 17 report and `SECURITY.md`) | â€” |
| Identity mismatches on declared signer slots | **Open — measured, not diagnosed** (Round 18): 544 `AccountIdentityMismatch` blocks remain over a 10,617-transaction mainnet sample, most `kind=privilege` on slots the manifest DOES declare as signers. The shape suggests instructions reached through CPI, where a PDA signs via `invoke_signed`; that is a hypothesis, and a blocking control is not loosened on one. Reproduce with `GRAPHITE_MAINNET_REASONS` | Engineering |
| Manifests for the traffic that publishes no on-chain IDL | Open (Round 18): the programs that dominate the remaining unmanifested share do not publish an Anchor IDL account, so they need a per-protocol source rather than a sweep | Engineering |
| Five manifests below the decode bar | Open (Round 18): Metaplex Token Metadata (0.67 — the unified V2 instruction set is not modelled), Bubblegum, Light System Program, Coinflow and Pump Fees. Each is recorded in `battle_tested_evidence.json` with the unnamed leading bytes | Engineering |
| Branch protection on `main` (required CI, no force-push) | Absent; conflicts with the standing push-to-main workflow | Owner |
| **Version-1 transaction format** — **on MAINNET and growing**: 1,829 of 10,617 transactions (17.2%) across eight finalized blocks on 2026-09-22, up from 8.2% five days earlier; an 80-block census the same day put it at 15.8% of 95,181 (`tools/mainnet-sample`, `scripts/solana_inventory_census.py`). Refused by name, so nothing fails open — but roughly one mainnet transaction in six is one Graphite cannot verify at all, and a client capped at `maxSupportedTransactionVersion: 0` is refused the WHOLE BLOCK (`-32015`). Must be parsed, bound and simulated | **Open — the largest single gap in coverage of the chain** | Engineering |
| Token-2022 `TransferFee` modelling | Open | Engineering |
| `content_hash` â†’ a name that says it is an instruction-level identifier | Open (it is the 64-bit AuditBind key, not the authoritative binding) | Engineering |
| Runtime-decoder oracle over the mutation corpus | Done (Round 12: `tools/runtime-oracle`, in CI) | â€” |
| Coverage-guided fuzzing of `parse_transaction`; a `wincode` second oracle; the V1 message format | Open | Engineering |
| Persisted archive index for the L8 / lifecycle join | Open | Engineering |
| Shared rate limiter for a horizontally deployed Graphite (single-instance today; 452 ns/check at one million buckets) | Open | Engineering |
| Second-source inclusion check for L8 | Done for an independent RPC (Round 12: `GRAPHITE_RPC_WITNESS_URL`); light-client proof open | Engineering |

## Numbers (as of this page's commit)

1,562 Rust tests passing in the all-features build (12 network-dependent
ignored, all of which were run against public devnet for Round 12, plus the
mainnet-sample probe run for Round 18); 320 in
the featureless library build; 1,366 in the cli-only build; 100 TypeScript
tests in the SAK integration; 17 in the TypeScript SDK (13 hermetic, 4 against a
live server â€” run in the Round 12 probe and in CI's container job); 20 Go; 27
Python; 110 live-probe checks of the release binary; the runtime oracle over
the corpus, 1,659 mutations and 600,000 generated frames. Clippy `-D warnings`
and fmt clean on rustc 1.98.1. Reproduced from `cargo test` / `npm test` output
in the Round 18 report, not estimated. CI for the
commit is the GitHub Actions run for that SHA â€” the runs endpoint, not the
combined-status endpoint.

## Report index (newest first)

| Date | Report | What it records |
|---|---|---|
| 2026-09-23 | [round18-the-registry-is-measured-2026-09-23.md](round18-the-registry-is-measured-2026-09-23.md) | `trust_tier` was a string nothing checked: eight manifests declared `BattleTested` and the engine believed all eight. A mainnet measurement now backs every seed manifest (executable account; >=1,000 successful transactions over a stated window; >=90% of >=20 really-observed instructions named), and `load_seed_manifests` lowers an unsupported declaration. The registry went from 33 manifests / 803 instructions to 129 / 3,186 (106 of them battle-tested on the evidence), ranked by what mainnet runs and generated from each program's own on-chain Anchor IDL; 216 instructions merged into six manifests that had fallen behind. Running that registry against real blocks found two pre-existing defects blocking legitimate traffic — an undeclared extra account had a privilege to mismatch (1,036 blocks across four programs), and the Wormhole manifest named the wrong instruction for two bytes — plus one introduced and fixed in the round (PDAs grounded under the wrong program). Non-vote mainnet transactions whose primary program Graphite can name: 20.8% -> 44.0% on the same sample. 544 identity mismatches remain, measured and left open rather than loosened |
| 2026-09-22 | [round17-what-counts-as-evidence-2026-09-22.md](round17-what-counts-as-evidence-2026-09-22.md) | Every Round 15 and Round 16 finding closed, each with a regression test that fails on `e95857d`: pre-signed artifacts refused at `/verify` and L8 reporting `RecordedForDifferentBytes` (F-16-01) and `recorded_verdicts` (F-16-11); baseline eligibility â€” sound and risk-clear only, `err == null` part of completeness, one observation per artifact digest (F-16-03, F-15-01, F-15-02) â€” with a `simulation_failed` residual (F-16-04); a variance floor, a shadow accumulator, `/health.frozen_baselines` and `graphite evidence promote-shadow` (F-16-02); L2 fails on unresolved lookup positions (F-15-05); Check 10 keyed on the bytes (F-15-03); observed CPI targets judged (F-16-05); the PDA template grammar closed at load and at verify (F-16-06); blocking plugins fail closed on panic (F-16-07); `min_confidence > 1` a 400 and the tier axis clamped (F-16-08, F-15-07); framed `content_hash` v2 in all four implementations (F-16-09); http(s)-only manifest links (F-16-10); lifecycle merged across a rotation (F-15-09); the devnet demo through `executeBoundTransaction` and the Go doc with the residual check (F-16-12); `--locked` in CI, `go.mod` pinned (F-16-13/16); finite rate limit (F-16-15); mismatches by slot (F-16-14). Live-probed on a loopback Core; CI green |
| 2026-09-21 | [round16-signed-before-it-was-shown-2026-09-21.md](round16-signed-before-it-was-shown-2026-09-21.md) | The full 43-section forensic brief run against `e95857d` (code identical to `21c0a7b`), report only. The exact-byte boundary held under every mutation tried, and 2 of 2 deliberate breaks (L8 signature binding, sibling coverage) were caught. New: a pre-signed artifact is approved as `artifact_bound` but its refusal cannot be found by L8 when the chain's bytes are available â€” the stronger evidence path yields the weaker alarm (F-16-01); ten identical-CU requests, none of which need to be approved, freeze a program's baseline and refuse every honest transaction at any other CU (F-16-02/03); plus measured CPI targets, PDA template grammar, Risk-plugin panic semantics, a 500 on `min_confidence > 1`, unframed `content_hash`, console link schemes, last-wins L8 attribution, and `--locked` in CI. Round 15's three P2 findings re-measured and still open; twelve historical classes CONFIRMED CLOSED; 14 missing tests named |
| 2026-09-20 | [round15-earned-by-asking-2026-09-20.md](round15-earned-by-asking-2026-09-20.md) | A full forensic re-audit of `21c0a7b`, report only. The exact-byte boundary and all twelve historical classes re-checked and confirmed closed. Three new confirmed defects, none an approval bypass through the reference bridge: confidence is earned by repetition â€” the same refused request is approved under Gaming on its second call because the `SimulationMatch` signal is the baseline sample count (F-15-01); a failed simulation with non-zero compute units is recorded as trusted evidence and certified "integrity clean" by L3 (F-15-02); an empty caller label switches the manifest risk-class hard gate off for non-native programs while the confidence floor still refuses (F-15-03). Plus the unresolved-ALT approval path and the deactivating-table discrepancy (F-15-05), two digests for one artifact (F-15-04), two in-repo executors without the residual policy (F-15-06), and three hardening items. 1 of 1 deliberate break caught; 11 missing tests named |
| 2026-09-20 | [round14-the-prefix-and-the-pin-2026-09-20.md](round14-the-prefix-and-the-pin-2026-09-20.md) | A forensic re-audit of Round 13 found that re-keying the Risk Engine on the instruction's bytes while leaving every OTHER manifest lookup on the caller's label was itself a bypass (GFX-101, HIGH): a truthful four-byte PREFIX of a discriminator switched off PDA re-derivation, the fixed-address comparison and the privilege comparison together, taking an attacker's program in Jupiter route's pinned slot from Blocked to `approved: true, artifact_bound, inherent residuals only`. Four more of the same shape: the declared-effects lookup (GFX-102), declared siblings judged on their labels (GFX-106), sibling lookup-table positions as wildcards (GFX-107), and the empty-label spelling of the first fix (GFX-108). One `effective_discriminator` now keys every manifest lookup; 5 of 5 deliberate breaks caught |
| 2026-09-17 | [round13-the-label-and-the-bytes-2026-09-17.md](round13-the-label-and-the-bytes-2026-09-17.md) | The Risk Engine judged the caller's label rather than the instruction (GFX-001, HIGH): a real SetAuthority declared `ff` was approved where the same bytes declared `06` were Blocked; the self-consistency check now runs first for every protocol and the table is keyed on the instruction's own bytes, which also closes the truthful-but-truncated variant. L4 was blind to the SPL `owner` field, so a token account changing hands produced no findings (GFX-002, MEDIUM); three authority fields now watched. AuditBind refuses a mismatched declaration by rule rather than by accident |
| 2026-09-16 | [round12-runtime-truth-2026-09-16.md](round12-runtime-truth-2026-09-16.md) | The runtime oracle (parser accepted five frame classes the runtime refuses, R12-01); L8 commitment, self-consistency, malformed statuses, redirects, the inclusion witness (R12-02â€¦05); one server per data directory (R12-06); RPC URL validation (R12-07); lifecycle sequence findings and signature shape (R12-08â€¦10); the bridge's submission-report retry (R12-11) |
| 2026-09-15 | [round11-full-run-2026-09-15.md](round11-full-run-2026-09-15.md) | The full run: L8 chain bytes unbound to the signature (R11-01, P1) fixed; request path deep-copying state (100 ms â†’ 1 ms); refusals reset the connection; parser signer-count rule; 32-character keys; L8 metrics; SDK live conformance in CI |
| 2026-09-13 | [round10-exact-attribution-2026-09-13.md](round10-exact-attribution-2026-09-13.md) | L8 and lifecycle joined on `content_hash` (R10-01, P1): now joined on the chain's bytes / exact keys; supply-chain pins; decompression and limiter measured |
| 2026-09-12 | [round9-next-surface-2026-09-12.md](round9-next-surface-2026-09-12.md) | Artifact without data bound uncompared (R9-01, P1); unparseable artifact fails L2; residual codes and the bridge's residual policy; packet-size bound; lifecycle bounds, `verdict_on_record`, the bridge's lifecycle reporting; CI/image pinning |
| 2026-09-12 | [round8-remaining-assumptions-2026-09-12.md](round8-remaining-assumptions-2026-09-12.md) | Audit durability, archive visibility, durable nonces, auth default, byte-level parser corpus |
| 2026-09-11 | [round7-adversarial-assurance-2026-09-11.md](round7-adversarial-assurance-2026-09-11.md) | BoundTransaction aliasing, Token-2022 malformed TLV fail-open (R7-01), ALT owner, cross-language corpus |
| 2026-09-11 | [round6-execution-boundary-2026-09-11.md](round6-execution-boundary-2026-09-11.md) | Exact final transaction binding; signing gate made unskippable |
| 2026-09-11 | [identity-boundary-campaign-2026-09-11.md](identity-boundary-campaign-2026-09-11.md) | ALT identity, privileges from the artifact, instruction-account identity |
| 2026-09-08 | [production-readiness-audit-2026-09-08.md](production-readiness-audit-2026-09-08.md) | Server, audit trail, CI, deployment |
| 2026-09-08 | [rpc-validation-campaign-2026-09-08.md](rpc-validation-campaign-2026-09-08.md) | RPC trust boundary, budget, provider precedence |
| 2026-09-06 | [adversarial-campaign-2026-09-06.md](adversarial-campaign-2026-09-06.md) | Early adversarial hardening |
| earlier | `final-forensic-report.md`, `forensic-audit-report.md`, `clean-room-revalidation-C26.md`, `phase2-certification-report.md`, `release-evaluation-report.md`, `independent-gap-audit.md`, `p16-mainnet-benchmark.md`, `drift-kamino-onboarding-C27.md` | Phase 1/2 milestones. Their descriptions of L8, benchmark sizes, test counts and protocol counts are **historical** and superseded here. |

`phase2-plan.md`, `phase2-branch-strategy.md` and the two grant proposals are
plans and proposals, not status.

## Language discipline

"Certified" in any report means: that commit's GitHub Actions run completed
successfully. It never means an external party certified anything. "Passed
N tests" is evidence that N specific reproductions run; it is not evidence of
security.
