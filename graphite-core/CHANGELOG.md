# Changelog

All notable changes to Graphite Core are documented here.
Layer names follow `graphite-engineering-skill/ARCHITECTURE.md` section 3.12 as the canonical source.

## [Round 19 — what one observation is] — 2026-09-24

Report: `docs/round19-what-one-observation-is-2026-09-24.md`. An external review
of `453dd01` checked, confirmed and widened; every layer run live; version-1
transactions parsed. Every fix below was reverted once and its regression test
failed without it (13 of 13).

- **A fresh blockhash is not a new observation (P1, F-19-01 — F-15-01 re-opened)**: the baseline key was the artifact digest, which covers the recent blockhash `simulateTransaction` replaces, so one transfer re-asked under fresh blockhashes grew its program's baseline on every ask. Reproduced live on the `a1db51f` release binary: refused at 0.44, **approved at 0.573 on the third ask**. Keyed now on `tx_artifact::simulation_identity` (signature slots and blockhash zeroed, domain-tagged SHA-256). `tests/round19_what_one_observation_is.rs`.
- **Only the artifact is simulated (P1, F-19-02)**: a descriptive request had its `instruction_data` simulated as a transaction and recorded with no key (12 identical requests took a baseline from 5 to 16 samples, L3 "passed"). A sample is recorded only when the described instruction was located in the artifact.
- **Exact observation memory (P2, F-19-03 — the review's finding)**: the 256-key window forgot, so a counted key counted again after 256 others. `ObservationMemory` (64-bit fingerprints, bound 16,384 per program, persisted, malformed memory refused at load); a full memory routes to the shadow accumulator instead of forgetting.
- **The CPI-trace rules run on what the simulator executed (P1, F-19-22)**: they ran only on a caller-declared `cpi_trace`, which the bridge never sends. The tree is rebuilt from `innerInstructions` by stack height; a Blocked finding refuses. `tests/round19_observed_execution.rs`.
- **Undescribed instructions (P1, F-19-04; P2, F-19-05; P3, F-19-06)**: L4 diffed only account 0 of an instruction the manifest does not describe, and its effects were prose L4 could not read, so a token debit was a warning. Every writable account is diffed; `UNDESCRIBED_INSTRUCTION_EFFECTS` promises nothing, interpretably. An unknown program's accounts are no longer all read-only; privileges and the L4 fee payer come from the artifact.
- **Operator key (P1, F-19-13)**: `/admin/*` requires `GRAPHITE_ADMIN_API_KEY` (≥ 32 characters, not the verify key) and is disabled without it; quarantine input validated, idempotent, `persisted` real, the acting key id on the trail (F-19-15).
- **Concurrency (P1, F-19-14)**: rate → auth → body within 5 s → permit; refusals drain ≤ 1 s and close. IPv6 rate-limited by /64; a sub-1 rate still admits (F-19-16).
- **One writer per data directory (P1, F-19-12)**: `GraphiteCore::open_data_dir` (lock, temp cleanup, strict load) and `open_data_dir_read_only`; snapshot generations so an older snapshot never overwrites a newer one; a corrupt snapshot refuses to start instead of lifting every quarantine; the CLI's writing commands take the lock.
- **Wire and lookup identity (P2, F-19-08)**: a frame naming one account twice, a lookup resolving an already-named address, and a lookup account that is not an initialized table are refused. PDA seeds past the runtime's limits derive nothing (F-19-09); a read-only nonce account is not a nonce transaction.
- **Smaller**: empty `instruction_data` under a label is a contradiction (F-19-07); caller `cpi_targets` count as described only when observed (F-19-10); community/candidate manifests cannot declare a tier above `OfficialManifest` (F-19-11); L8 rows index only chain-derived keys (F-19-17); audit scans off the async runtime (F-19-18); `/health` redacts paths (F-19-19); lifecycle history keeps the first and the latest rows (F-19-20); an all-zero signal history is observed, not skipped (F-19-21); a torn audit line no longer swallows the next record, and a non-UTF-8 line skips only itself (F-19-23); `TransferCheckedWithFee` and `TransferWithSeed` count in sweeps (F-19-24); a panicking protocol plugin declares no effects instead of unwinding (F-19-25).
- **Two false-refusal classes on real traffic (P2, F-19-28)**: found by running the conformance probe over the 19,458-transaction mainnet sample. Two same-program, same-data instructions are now told apart by their static account positions (fully identical copies are still refused, with a reason that says so instead of "not in the transaction"), and an empty discriminator describes a sibling whose data is empty — the legacy associated-token-account `create` — and nothing else. 104 real transactions went from refused to L2-passed; no risk verdict and no approval changed. `tests/round19_real_traffic_shapes.rs`.
- **Thresholds outside [0, 1] (P3, F-19-27)**: a negative, NaN or infinite `Custom` `min_confidence` is a 400 in every mode; it used to pass through under `GRAPHITE_ALLOW_PERMISSIVE_PROFILES`.
- **Version-1 transactions (SIMD-0385) parsed**: `parse_v1`, every frame helper v1-aware, `max_frame_bytes` (4,096 for v1) at the `/verify` entry, "versioned" meaning v0 or v1, L8 and `getTransaction` at `maxSupportedTransactionVersion: 1`. The runtime oracle now decodes with agave's `wincode` reader too, with a v1 generator and a systematic v1 pass: zero frames Graphite accepts that the runtime refuses on both CI seeds; 3,302 of 3,302 real mainnet v1 transactions parse and bind. `tests/round19_v1_transactions.rs`.
- **Client side**: the SAK bridge's pre-verdict simulation is unsigned by construction (P0, F-19-C1 — web3.js signed it on a live blockhash and sent it to the RPC); SolanaAgentKit gets `VerificationGatedWallet`, and the unverified swap opt-out is retired (P1, F-19-C2); `verifyTransactionDigest` in the TS and Go SDKs, v1-aware, with a cross-language v1 vector (F-19-C3); intent grounded in the user's text (F-19-C5); the AI layer binds 127.0.0.1, threaded, with socket timeouts; https-or-loopback transport in the SDKs and the console (F-19-C6).

## [Round 18 — the registry is measured] — 2026-09-23

Report: `docs/round18-the-registry-is-measured-2026-09-23.md`.

- **A manifest may no longer award itself a trust tier (P1, fixed)**: `trust_tier` was a string nothing checked, and eight manifests declared `BattleTested` — the tier reserved for 1,000+ verified transactions — with no evidence behind any of them. `protocols/battle_tested_evidence.json` now carries a mainnet measurement for every seed manifest (executable account; ≥1,000 successful transactions carrying the address over a stated window; ≥90% of ≥20 really-observed instructions named by the manifest), and `load_seed_manifests` lowers an unsupported declaration to `OfficialManifest`. The gate reads the raw measurements, never the file's own verdict field. `tests/battle_tested_evidence.rs` (8).
- **The registry grew from 33 manifests / 803 instructions to 129 / 3,186**, ranked by what mainnet actually runs (80 finalized blocks, 77,589 successful transactions, 569 distinct programs) and generated from each program's **own on-chain Anchor IDL** — 108 of the 569 publish one. 216 instructions were merged into six manifests that had fallen behind their deployed programs (Marginfi v2 4 → 91, Meteora DLMM 17 → 84, Pump.fun 9 → 47). Every auto-onboarded manifest is named `<IDL name> (<address prefix>)`: the IDL names are not unique, and a name alone would let an unrecognised address present itself as the protocol whose name it copied.
- **An undeclared extra account had a privilege to mismatch (P1, pre-existing, fixed)**: a slot past the end of a manifest's declared list is `remaining_accounts`, but `resolve_accounts` compared the real `AccountMeta` against the `("extra", is_writable: false)` placeholder, so every legitimate writable remaining-account became a blocking `AccountIdentityMismatch` — 429 on Pump AMM, 336 on Pump.fun, 199 on the System Program and 72 on SPL Token over 10,617 real mainnet transactions. `privilege_mismatch::an_undeclared_extra_account_has_no_privilege_to_mismatch`.
- **The Wormhole manifest named the wrong instruction for two bytes (P2, pre-existing, fixed)**: 29 observed instructions carried tag `08` that nothing could name while the manifest declared `PostMessageUnreliable` at `09` and `VerifySignatures` at `03`. Against the program's own dispatch order `03` is `SetFees` and `09` is `ClosePostedMessage`. Corrected to `07`/`08`.
- **PDA seeds are grounded only where they can be derived exactly**: a seed whose byte offset sits after an argument of unknown width, and a PDA the IDL says is derived under a DIFFERENT program (an associated token account is derived under the ATA program), now ground nothing rather than something wrong — the C26 rule. Grounded slots 1,571 → 1,140; `AccountIdentityMismatch` over the sample 1,022 → 544.
- **One list, not two**: `SEED_MANIFESTS` produces both the manifest name and its baked-in contents, replacing the `seed_paths` array plus one `include_str!` match arm per path that aborted the process at startup if they disagreed; `manifest::tests::test_every_protocol_file_is_a_seed_manifest` fails if a file in `protocols/` is never loaded. `is_swap_program` reads `"category": "swap"` from the manifests instead of a second hand-kept list (the trusted-CPI list stays hand-curated, because it RELAXES checks).
- **The documented protocol table is generated and compared in CI**: `docs/protocol-coverage.md` plus `tests/docs_match_the_registry.rs`. The previous hand-maintained README table named the wrong tier for four programs.
- **Measured coverage**: on the same 10,617-transaction mainnet sample, the share of non-vote transactions whose primary program Graphite can name went from 20.8% to 44.0%. Message version 1 — refused by name — is 17.2% of that sample.

## [Round 17 — what counts as evidence] — 2026-09-22

Report: `docs/round17-what-counts-as-evidence-2026-09-22.md`. Every finding of
the Round 15 and Round 16 forensic re-audits closed, each with a regression
test that fails on the audited commit.

- **A pre-signed artifact is refused at `/verify`** (F-16-01): any non-zero signature slot is a 400, and `scope.transaction_sha256` is the digest of the unsigned frame by construction. L8 answers `RecordedForDifferentBytes` for a cited verdict about other bytes — a discrepancy when that verdict was a refusal — and reports `recorded_verdicts {approved, refused}` for the chain digest (F-16-11).
- **Only a sound transaction trains the baseline** (F-16-03, F-15-01, F-15-02): recording moved below the verdict and gated on a successful simulation (`err == null` is now part of completeness), no structural-layer failure and a Clear risk summary; keyed on the artifact digest, so the same bytes re-verified are ONE observation. A failed simulation carries `UnobservedCode::SimulationFailed` and L3 never reports it clean (F-16-04).
- **A uniform history is a band, not a point** (F-16-02): a 25% relative / 1.0 absolute variance floor on both the mean-std and robust paths; flagged-but-clean executions accumulate in a shadow baseline that `/health.frozen_baselines` reports and `graphite evidence promote-shadow` promotes.
- L2 fails on an unresolved lookup-table position (F-15-05); Check 10's manifest risk metadata is keyed on the instruction's bytes (F-15-03); observed CPI targets from `innerInstructions` are judged like declared ones (F-16-05); the PDA seed-template grammar is closed at manifest load, at registry submission and at verify (F-16-06, F-16-14); a panicking Risk/Verifier/Policy plugin blocks (F-16-07); `min_confidence > 1` is a 400 before the pipeline and the tier axis is clamped (F-16-08, F-15-07); `content_hash` is framed with a domain tag and length prefixes in all four implementations (F-16-09); manifest links are http(s) only (F-16-10); lifecycle history is merged across a rotation (F-15-09).

## [Round 16 — signed before it was shown] — 2026-09-21

Report: `docs/round16-signed-before-it-was-shown-2026-09-21.md`. A full forensic
audit run against `e95857d`. **No production code changed in this round** — it
is the measurement that Round 17 acted on. Sixteen findings, two deliberate
breaks caught, fourteen missing tests named.

## [Round 15 — earned by asking] — 2026-09-20

Report: `docs/round15-earned-by-asking-2026-09-20.md`. A forensic re-audit of
`21c0a7b`, **report only**: three confirmed defects in how evidence was earned
(confidence rising by repetition, a failed simulation recorded as trusted
evidence, an empty label switching off a hard gate), plus the unresolved-ALT
approval path and two in-repo executors without the residual policy. All closed
in Round 17.

## [Round 14 — the prefix and the pin] — 2026-09-20

Report: `docs/round14-the-prefix-and-the-pin-2026-09-20.md`. Found by a forensic
re-audit commissioned as an adversarial review of Round 13 rather than a
continuation of it.

- **A truthful PREFIX of the discriminator switched off every manifest-grounded account check (P1, fixed)**: Round 13 re-keyed the Risk Engine on the instruction's bytes and left `resolve_accounts`, the declared-effects lookup, `verify_instruction`'s manifest lookup and the plugin rules keyed on the caller's label. `manifest::discriminator_matches` is `input.starts_with(selector)`, so a label SHORTER than a selector misses — and a short label contradicts nothing, so Round 13's self-consistency check passes it. On the miss, `resolve_accounts` returns `InstructionNotFound` and the P12 arm synthesises accounts with `pda_mismatch`, `expected_address_mismatch` and `privilege_mismatch` ALL false, so `MaliciousAccountChange` cannot fire. Measured against a running server, identical artifact and identical described accounts: an attacker-controlled program in Jupiter V6 `route`'s account 0 — pinned by the manifest to the two token programs — went from `Blocked [AccountIdentityMismatch]` under `e517cb977ae3ad2a` to `approved: true`, `Clear`, `artifact_bound`, residuals `[program_semantics, inner_instructions]` under `e517cb97`; that verdict passes the reference bridge's DEFAULT residual policy. 312 of 803 shipped manifest instructions, across 13 of 33 manifests, have both a truncatable discriminator and a pinned account slot. One `effective_discriminator`, derived from the instruction's own first eight bytes, now keys every manifest lookup. The substitution cannot refuse anything it did not refuse before: L2 has already established that the label is a prefix of the data, so every selector the label matched is also a prefix of these bytes, and manifest discriminator ambiguity is rejected at load on both paths. `tests/truncated_discriminator.rs` (22).
- **The same miss replaced the manifest's declared effects (P2, fixed by the same regrounding)**: `expected_state_changes` fell back to the generic "Protocol-level state changes", which `DeclaredEffects::parse` cannot interpret — and an uninterpretable declaration downgrades every undeclared value-movement finding in L4 from Critical to Warning. `allowed_cpis` widened to the protocol-wide union at the same time. Both were caller-selectable by shortening a string.
- **Declared SIBLINGS were judged under the caller's label (P1, fixed)**: `assess_secondary_instructions` fed `ix.instruction_discriminator` straight into the Risk Engine, and `declaration_describes` only requires that label to be a hex-STRING prefix of the sibling's data. Measured: a real System `Assign` declared `01` or `0100`, and a real SPL `SetAuthority` declared `0` — a single hex nibble — all drew `Clear`. `tx_pattern_analysis::disc_matches` is the same relation, so the AAT correlation rules were evaded by the same move. `sibling_coverage` now records which artifact instruction each declaration matched and `siblings_keyed_on_their_bytes` rewrites the discriminator from that instruction's own data; a declaration matching nothing is left as written, because L2 has already failed the verification and rewriting it would be inventing evidence.
- **A declared sibling's lookup-table positions were wildcards (P2, fixed)**: the PRIMARY's account comparison resolves ALT positions; a sibling's compared against the UNRESOLVED list, and `compare_instruction_accounts` reads an unresolved position as neither match nor mismatch. Declared accounts widen the set `ArtifactAccountsNotDescribed` treats as named, so a fabricated address at a lookup position could mask a real account from a Critical finding. `sibling_coverage` now takes the resolved lookups. `tests/sibling_lookup_accounts.rs` (mock RPC serving one table).
- **The first cut of the fix kept the bypass under an EMPTY label (P1, fixed)**: it inherited the Risk Engine's `!is_empty()` gate, and `discriminator_matches` refuses an empty input, so the lookup missed exactly as before — `e517cb97` Blocked, `""` Clear. The two values are now split: manifest lookups always use the bytes; `risk_discriminator` keeps the empty-label gate, because Check 2's fail-closed arm refuses a request that named no instruction on a known-risky program and deriving one would turn "refused because you did not say" into "allowed because we worked it out".
- **A declaration too short to identify a risky instruction is refused (descriptive mode)**: `disc_matches` fires when the input is at least as long as the selector; a strict PREFIX of one sat in the gap between Check 2's two arms. Unreachable artifact-bound (the discriminator is re-derived from the bytes), so this covers the descriptive path, where there is nothing to re-derive from. A complete selector is unaffected.
- **Deliberate-break log**: 5 of 5 controls caught. The FIRST run caught only 3 — two of the new tests were vacuous (one was being caught by a different new control, the other covered a fix that had never been reproduced), and both were replaced with isolating tests before the campaign was re-run.
- **Unchanged**: `content_hash` is still computed over the DECLARED discriminator, which is what keeps the Rust/TypeScript/Go projections byte-identical; `transaction_builder` still applies its hex check to the caller's label; L2's contradiction check still compares the LABEL against the bytes, because that is its entire purpose.

## [Round 13 — the label and the bytes] — 2026-09-17

Report: `docs/round13-the-label-and-the-bytes-2026-09-17.md`.

- **The Risk Engine judged the caller's label, not the instruction (P1, fixed)**: `RiskAssessmentInput.instruction_discriminator` was the request's own `instruction_discriminator`, and L2's `instruction_data`/discriminator comparison sat below the manifest lookup, so it ran only on a manifest HIT — a discriminator matching no manifest entry took the unknown-instruction P12 soft pass before the comparison was reached, and `manifest_risk_class` was empty on that path so Check 10 could not back the table up. Same bytes, same `instruction_data`, `WalletProfile::Gaming`: SPL-Token `SetAuthority` declared `06` → `Blocked [AuthorityHijack]`; declared `ff` → `approved: true`, `Clear`, confidence 0.640, `scope: artifact_bound`. `CloseAccount` (`09`→`ff`) and System `Assign` (`01000000`→`ffffffff`) identical. Two independent closures: `verification::declared_discriminator_contradicts_data` runs at the TOP of L2 for every protocol, manifested or not (and data shorter than the declared discriminator is now a contradiction — the old `data.len() >= disc_bytes.len()` guard skipped exactly the padding shape `disc_matches` warns about); and the Risk Engine plus the manifest risk-context lookup are keyed on `risk_discriminator`, the hex of the instruction's own first eight bytes. An empty declared discriminator is left untouched so Check 2's fail-closed arm is unaffected. `tests/mislabelled_discriminator.rs` (16).
- **A truthful but truncated discriminator hid the instruction too (P1, fixed by the same regrounding)**: System `Assign` is `01000000` and `"01".starts_with("01000000")` is false, so declaring `01` over `01 00 00 00 …` contradicts nothing, matches no pattern and misses the manifest. The contradiction check cannot reach this; keying on the bytes does. `a_truthful_but_truncated_discriminator_does_not_hide_the_instruction`.
- **L4 could not see a token account change hands (P2, fixed)**: `AccountDelta::{token_authority_change, mint_authority_change, freeze_authority_change}` and the Critical findings `UndeclaredTokenAuthorityChange`, `UndeclaredMintAuthorityChange`, `UndeclaredFreezeAuthorityChange`, each excused by a manifest that declares an authority change (freeze authority also by a declared freeze). `owner_change` watches the owning PROGRAM; the SPL `owner` field is the AUTHORITY, and `SetAuthority(AccountOwner)` changes only the latter — a diff whose sole change was `ALICE → MALLORY` previously returned `findings: []`, `blocked: false`. Mint authorities compared as `Option`s (absence is a real on-chain value); an uninitialized "before" does not decode, so initialization is a creation, not a hand-over. Seven tests in `state_diff::tests`.
- **SAK bridge**: `AuditBind.projectionFromInstruction` refuses an explicit `discriminator` that is not a prefix of its `data` instead of building the projection around the label — the swap path's protection was previously incidental (`executeSwap` passes none, so the projection was rebuilt from the bytes and the hash diverged). `auditbind.test.ts`.
- **Unchanged and re-pinned**: a discriminator that is not hex never reaches a verdict (`transaction_builder::InvalidDiscriminator`); `content_hash` is still computed over the DECLARED discriminator, which is what keeps the Rust, TypeScript and Go projections byte-identical.

## [Round 12 — runtime truth] — 2026-09-16

Report: `docs/round12-runtime-truth-2026-09-16.md`.

- **Parser accepted frames the runtime's `sanitize` refuses (P2, fixed)**: `ArtifactParseError::{ProgramIsFeePayer, EmptyLookup, TooManyAccounts}` and `AccountIndexOutOfRange` for any index at or past the static-plus-loaded universe (legacy and v0, checked once the lookups are known). Found by the new runtime oracle: 3,382 / 200,000 generated frames and 8 recorded corpus mutations; a legacy frame with account index 255 had passed L2 as lookup-derived.
- **Runtime oracle** (`tools/runtime-oracle`, its own workspace): the agave crates (`solana-transaction` / `solana-message` 5.0) decode the corpus, its 1,659 mutations and 300,000 seeded frames as a validator's packet path does; fails on any byte string Graphite parses that the runtime refuses or reads differently. CI job `runtime-oracle`, two seeds.
- **L8 took one RPC at its word for inclusion (P2, fixed)**: `rpc_client::InclusionCommitment` parsed from `confirmationStatus` (missing/unknown → invalid response), on `SignatureStatus` and `ExecutionVerification::Confirmed`; a `processed` sighting withholds `ApprovedAndExecuted` and still alarms on a blocked verdict; a status without `slot` or with a `status` that is neither `Ok` nor `Err` is `InvalidResponse`, not "included and failed". `ChainTransaction { bytes, slot, succeeded }` from `get_chain_transaction`; a slot or outcome that contradicts the status is `ExecutionAudit.chain_inconsistent` and withholds every positive conclusion. `chain_bytes_unavailable` names why the caller's keys stood in.
- **Inclusion witness (design, built)**: `GraphiteCore::attach_inclusion_witness` (refuses the primary's endpoint), `GRAPHITE_RPC_WITNESS_URL`, CLI `--witness-url`; `ExecutionAudit.inclusion_witness: InclusionWitness { agrees, seen, commitment, detail }`; both endpoints must agree before an approval is reported executed; a blocked transaction seen by either alarms, with the bytes fetched from the endpoint that saw it and bound to the signature; `/health.inclusion_witness`; `graphite_execution_witness_disagreements_total`, `graphite_execution_chain_inconsistent_total`.
- **RPC client**: redirects never followed (`Policy::none()`; a 3xx is a named `RequestFailed`); `validate_endpoint` / `EndpointError` / `EndpointFacts` (http/https, host, no fragment) applied at server startup and in the CLI; plaintext-to-non-loopback warned; the startup log names the scheme, never the URL; `SolanaRpcClient::endpoint()`.
- **One server per data directory (P2 operational, fixed)**: exclusive advisory lock on `<data_dir>/graphite.lock` (`server::DATA_DIR_LOCK`, `File::try_lock`); a second server refuses to start.
- **Lifecycle sequence (P3, fixed)**: `durable::LifecycleKey`, `AuditLog::lifecycle_history` over a per-transaction index (`lc:id:` / `lc:tx:` / `lc:sig:`, `MAX_LIFECYCLE_HISTORY = 64`, cleared on rotation, newest archive on a miss); `LifecycleEventRecord::{observed_by_graphite, sequence_anomalies}`; `/audit/event` returns `sequence_anomalies` (`duplicate` / `out of order` / `unpreceded` / `signature conflict`) and `prior_events_on_record`, counts `graphite_lifecycle_sequence_anomalies_total`, logs a conflict at ERROR; submission onward requires `transaction_signature`; signatures must decode to 64 bytes on both endpoints (`signature_shape`), refused before any RPC call.
- **L8 row keys (P3, fixed)**: a `content_hash`-attributed reconciliation row no longer writes the resolved record's `audit_trail_id` / `transaction_sha256` onto the signature's row.
- **SDK / bridge**: TS `ExecutionCheckResult.{chain_bytes_unavailable, chain_inconsistent, inclusion_witness}`, `InclusionCommitment`, `InclusionWitness`, `LifecycleEventReceipt.{sequence_anomalies, prior_events_on_record}`; the bridge retries the submission report (`submissionRecordAttempts`, `submissionRecordBackoffMs`; default 3 × 500 ms doubling) and reports `submissionRecordAttempts`.
- **Version-1 transactions on devnet (external change, discovery fixed)**: `get_block` requests `maxSupportedTransactionVersion: 1` (an RPC refuses a whole block to a version-0 client once it holds one v1 transaction; the live corpus test found nothing for 17 minutes); `live_corpus::tx_to_input` skips `"version": 1`; the `UnsupportedVersion` error names the v1 format. Parsing v1 is open and time-sensitive.
- **Build hygiene**: the featureless library build is warning-free (`state_diff` imports and `deltas_lamport_changed` gated on `rpc`).

## [Round 11 — the full run] — 2026-09-15

Report: `docs/round11-full-run-2026-09-15.md`.

- **L8 chain bytes not bound to the signature (P1, fixed)**: `tx_artifact::bound_artifact_sha256(bytes, signature)` — the first slot must hold the signature and it must verify (`ed25519_dalek::verify_strict`) over the message under the fee payer's key; `SignatureBindingError`. `audit_execution` refuses bytes that fail (`ExecutionAudit.chain_bytes_rejected`, reconciliation `Unavailable`, `attribution: none`, caller keys not consulted); the server counts (`graphite_execution_chain_bytes_rejected_total`), logs at ERROR and writes the reason on the trail row; the CLI prints `REJECTED`; the bridge logs `L8 REFUSED`. Live test against public devnet: real bytes bind, the same bytes refuse another signature.
- **Request path deep-copied the state (P2, fixed)**: `AppState.core: Arc<GraphiteCore>`, `registry_engine: Arc<…>`; `/manifests` serializes from references. `/health` 100 ms → 1 ms; in-process storm 21 → 960 verifies/s. Regression tests `app_state_clone_is_a_reference_count_not_a_deep_copy`, `health_answers_in_milliseconds_on_loopback`.
- **Early refusals reset the connection (P2, fixed)**: `refuse_after_draining` — 401/429/503 drain the (size-capped) body before answering; 429 carries `Retry-After: 1`. Test `early_refusals_drain_the_body_so_the_status_is_readable`.
- **Parser accepted frames the runtime refuses (P2, fixed)**: `ArtifactParseError::SignatureCountMismatch` (signature array length ≠ header signer count); `ImpossibleHeader` when no signer is writable. Corpus `slots` mutation (12 cases, 1,659 total); web3.js agrees.
- **Any-length API key (P2, fixed)**: `MIN_API_KEY_CHARS = 32`; shorter refuses to start.
- **L8 trail rows truncated (P3, fixed)**: `durable::MAX_LIFECYCLE_DETAIL_CHARS = 1024` shared by the boundary and the disk.
- **Metrics**: `graphite_execution_checks_total`, `graphite_execution_discrepancies_total`, `graphite_execution_chain_bytes_rejected_total`.
- **CLI**: a `--profile custom` bar below the weakest built-in profile warns on stderr (`policy_engine::WEAKEST_BUILTIN_MIN_CONFIDENCE`, `WalletProfile::is_weaker_than_any_builtin`).
- **CI**: the container job runs the TypeScript SDK's live conformance tests against the container and fails if any was skipped; the smoke key is 34 characters.
- **Supply chain**: `rustls` 0.23.43 → 0.23.45 (RUSTSEC-2026-0285).

## [Round 10 — exact execution attribution] — 2026-09-13

Report: `docs/round10-exact-attribution-2026-09-13.md`.

- **L8 and the lifecycle join keyed on `content_hash` (P1, fixed)**: an instruction-level key shared by every transaction carrying that instruction; the newest such record answered, so a blocked B's execution resolved to a later approved A. `AuditRecord.transaction_sha256`; `AuditLog::find_verification(VerificationKey::{AuditTrailId, TransactionSha256, ContentHash})` with the active-file index keyed all three ways; `tx_artifact::unsigned_artifact` / `artifact_sha256_of_signed`; `rpc_client::get_transaction_bytes`; `audit_execution(signature, ExecutionKeys, audit)` joins on the chain's bytes first, then the caller's keys most-exact-first with no fallback, reporting `attribution`, `chain_transaction_sha256`, `caller_keys_disagree`; `/audit/event` resolves `verdict_on_record` the same way, refuses contradicting keys (400 `InconsistentKeys`), records `verdict_on_record_key`; CLI `--transaction-sha256` / `--audit-trail-id`.
- **SDK / bridge**: `LifecycleEventInput.transaction_sha256`, `ExecutionCheckInput.{transaction_sha256, audit_trail_id}`, `ExecutionAttribution`, `VerificationKeyKind`; the bridge sends the exact keys on every call and refuses to submit unless its signing was resolved by `audit_trail_id`.
- **Supply chain**: toolchain `1.98.1` in CI and `rust:1.98.1-bookworm@sha256:…` in the container; Go `1.22.12`; `cargo-audit 0.22.2`; `python-ai-layer/requirements-lock.txt` with `--require-hashes`.
- **Measured**: a 65 KB gzip body inflating to 64 MiB is refused at the 32 MiB cap in 35 ms; 100,000-deep nesting is a parse error; the rate limiter at one million buckets costs 452 ns per check (`flate2` added as a dev-dependency, already in the tree via reqwest).

## [Round 9 — the next surface] — 2026-09-12

Report: `docs/round9-next-surface-2026-09-12.md`.

- **Artifact without `instruction_data` bound without comparison (P1, fixed)**: L2's artifact branch ran only when the data was present and ≥ 8 bytes; omitting the optional field skipped the positional/sibling check while `scope` still reported `artifact_bound`. A 100 SOL transfer was approved under a "0.002 SOL" description through a mock cluster. Now the branch runs for every artifact: no data → L2 fails; no parse → L2 fails (substring fallback deleted); `correspond` matches exact data at any length.
- **`UnobservedCode`** (14 codes) and `scope.unobserved_codes`, parallel to `unobserved`; `inherent()` for `program_semantics` / `inner_instructions`; schema enum pinned to `UnobservedCode::ALL`. New code `instruction_not_located`.
- **Packet-size bound**: `MAX_TRANSACTION_BYTES` = 1232 (`ArtifactParseError::TooLarge`) in `parse_transaction`, `message_bytes` and the `/verify` entry; `MAX_TRANSACTION_INSTRUCTIONS` = 256. Measured 122 s → 1.6 ms for one request.
- **Lifecycle rows**: `LifecycleEventRecord::bounded()`; `/audit/event` shape and length checks (16-hex `content_hash`, signature ≤ 90, ids ≤ 128, detail ≤ 1024); `VerdictOnRecord` (`approved` / `blocked` / `not_found`) computed server-side and written on every row; `graphite_lifecycle_events_on_blocked_total`, `graphite_lifecycle_events_unverified_total`.
- **Active-file index** for `last_verification_for`: `content_hash → offset`, built at open, maintained per append under the file lock, cleared on rotation. 953 ms → 0.5 ms per lookup over 64 MB.
- **Slot capture**: `SimulationResult.slot`, `get_multiple_accounts_at`; L4's reason names the pre-state and simulation slots when they differ.
- **SDKs**: TS `UnobservedCode`, `unobservedCodes()`, `recordLifecycleEvent`, `verifyExecution`; Go residual constants and `NonInherentUnobserved()`.
- **Bridge**: `residual-policy.ts` (refuses non-inherent residuals unless accepted by code; refuses servers without codes), `execution-lifecycle.ts` (policy → sign → record signing → submit → record submission → confirm → L8), `ExecutionOutcome.lifecycle`; `messageOf` packet bound with `readSignatureCount` factored out; corpus `pad` mutations (1,647 total).
- **CI / image**: workflow token `contents: read`; every action pinned to a commit SHA; Docker base images pinned by digest.

## [Round 8 — remaining assumptions] — 2026-09-12

Full report: `docs/round8-remaining-assumptions-2026-09-12.md`. Current status
lives in `docs/CURRENT.md`; the entry below and every earlier one are history.

- **Audit durability (P2, fixed)**: `AuditLog::append_line` called `File::flush()`, which is a no-op for an unbuffered `std::fs::File`, and then reported the record as "durably on disk". It now calls `sync_data()`; measured 1.5 ms per record on NTFS. The semantic-graph snapshot syncs its temp file before the rename for the same reason; rotation syncs the directory on Unix.
- **Archive visibility (P2, fixed)**: `read_tail_filtered` and `observations_by_program` opened only the active file, so after a rotation the dashboard totals fell to what had been written since and L8 reconciliation could not find a verdict that had rotated out — a BLOCKED transaction submitted anyway reconciled as `NoVerificationOnRecord`. Both now cover every archive; `last_verification_for` is the L8 join. Per-archive statistics are cached (archives are immutable) so a poll costs the active file, not the history. Selector is a closed enum (`AuditSelector`) to make that cache possible.
- **Rotation failure visibility (P3, fixed)**: a failed rename was retried silently on every append. Now counted (`rotations_failed`), surfaced on `/health` (`degraded_reasons`) and `/metrics`. Windows rename-while-open is NOT a finding: Rust's handles carry `FILE_SHARE_DELETE`; a foreign handle without it is reproduced in `rotation_failure_is_counted_and_never_drops_a_record`.
- **Semantic-graph persistence (fixed)**: snapshot failures were a `warn!`. Now counted and surfaced (`graph_persistence` on `/health`, `graphite_graph_snapshots_failed_total`).
- **Handler panics on audit failure (P3, fixed)**: `assert!(log.append_…)` in four handlers became structured responses: `/audit/event` and `/verify/execution` answer 503 "NOT recorded"; error-path records and operator actions report the outcome.
- **Authentication default inverted (P2, fixed)**: an absent `GRAPHITE_API_KEY` used to mean dev mode. The server now refuses to start without a key unless `GRAPHITE_DEV_MODE=1`, and then only on loopback (`server::auth_posture`).
- **Durable-nonce transactions (P1 gap, closed)**: detected from the bytes by the runtime's rule (`tx_artifact::durable_nonce`); refused at L2 by default; `GRAPHITE_ALLOW_DURABLE_NONCE=1` permits them only after the nonce account is fetched and matches (value, authority, authority signs). The bridge refuses to build one. Corpus entries emitted by `SystemProgram.nonceAdvance`.
- **Byte-level cross-language corpus**: 1,641 mutations (every truncation, every single-byte flip, 14 signature-count prefixes, trailing bytes) of three transactions; Graphite's `message_bytes` — now the parser's own signature skip, exported — must agree with the bridge's `messageOf` exactly, and Graphite must never accept bytes `@solana/web3.js` refuses. `web3.js` is measured lenient where the runtime is not (non-minimal shortvec, over-long declared lengths, trailing bytes); Graphite refuses those.
- **Documentation provenance**: `docs/CURRENT.md` is the single current-status page; every dated report carries a historical banner.

## [Rounds 3–7 — the transaction identity boundary] — 2026-09-08 → 2026-09-11

Reports: `docs/identity-boundary-campaign-2026-09-11.md`, `docs/round6-execution-boundary-2026-09-11.md`, `docs/round7-adversarial-assurance-2026-09-11.md`.

- **Wire-format parser** (`tx_artifact.rs`): legacy + v0, canonical compact-u16 (≤ 65,535, minimal), trailing bytes and out-of-range indexes refused. `VerificationScope::{ArtifactBound, Descriptive}` as a schema `oneOf`, `transaction_sha256` over the supplied bytes.
- **Instruction identity**: L2 requires the described instruction to be present positionally (`compare_instruction_accounts`) and every sibling declared (`sibling_coverage`, bijective). Account universe checked by address (`artifact_accounts_undescribed`).
- **Lookup tables** resolved before account resolution, owner-checked, all-or-nothing; `runtime_account_list` rebuilds the runtime's numbering; ground-truthed against three real mainnet v0 transactions (`tests/alt_real_v0.rs`).
- **Privileges from the artifact** (`privileges_from_artifact`, `PrivilegeSource` reported in L1); a contradicting caller is reported and overridden.
- **Provider field precedence**: `account_writes` / `cpi_hops` from canonical fields only; `provider_anomalies` surfaced.
- **Token-2022 extensions classified** (`ExtensionImpact`), unreadable region fail-closed (R7-01, a fail-open in the Round-6 fix).
- **SAK bridge**: `BoundTransaction` (deep copy, private signing path `signApproved`, signer set from the message, message-slice equality), `artifact_bound` required to execute, swap opt-out phrase + `ExecutionOutcome.verifiedExecution`, AuditBind partial-metas refused, `messageOf` with the Rust acceptance language.
- **CI**: `cargo test` on the feature matrix (28 previously-untested failures found), corpus and fixture drift checks, `npm ci` everywhere.
- Test count 1,014 → 1,399 across these rounds.

## [Historical — C58 state, 2026-08-19: 1,014 tests, 33 manifests, 803 instructions, 13 risk checks, 37-entry exploit corpus, deployment verified, full-stack auth, v0.2.0-beta]

The entries from here down describe the codebase as it was when each was written. Current status: `docs/CURRENT.md`.

### Summary of all changes C28–C55

- **C55**: Production-readiness pass — closed the auth gap across the whole client stack and synced every connected file. Live-verified end-to-end against a secured Core (Bearer auth on, rate limit on, registry loaded):
  - **Dashboard (FIXED — was unusable against a secured Core)**: the read-only UI sent NO Authorization header, so with `GRAPHITE_API_KEY` set (required by docker-compose) every `/api/*` poll got 401 and the dashboard showed nothing. Added a header API-key field (persisted in localStorage) that sends `Authorization: Bearer` on all `/api/*` requests; `/health` stays open. Verified live in the browser: without the key → 401 error card; with the key → 29 programs (28 seed + community) render, Manifest Registry shows the accepted submission.
  - **TypeScript SDK (FIXED)**: `GraphiteClient` now accepts `apiKey` and sends the Bearer header on `/verify` and `/manifests`; also added Phase 2 input parity (`signed_transaction`, `transaction_instructions`, `cpi_trace`) and manifest `category`. Runtime-verified against the secured Core: anon → 401, keyed → reaches verification logic.
  - **Go SDK (FIXED)**: `NewClientWithAPIKey` + `Client.APIKey` with the Bearer header on `Verify`/`ListManifests`; Phase 2 input parity (`SignedTransaction`, `TransactionInstructions`, `CpiTrace`) and `category`. Runtime-verified against the secured Core with the local Go toolchain (vet clean, tests pass).
  - **SAK bridge (FIXED)**: `graphiteApiKey` config/env passthrough into the SDK client — the flagship integration can now talk to a secured Core.
  - **JSON schema (FIXED — was stale)**: `schemas/verification-result-v1.json` covered only 6 of the 19 fields and didn't even require `approved`. Rewritten to the full 19-field VerificationResult contract.
  - **Docs synced**: README badges 987 → 999, Version badge v0.1.1-alpha → v0.2.0-beta, example output 987/8 → 999/9, Gaming threshold 0.60 → 0.55 (C53 change) with the corrected unlock explanation; ARCHITECTURE Gaming 60% → 55%; cert report matrix 987 → 999 tests.
  - Full re-verification: 999 Rust tests / 0 failures (incl. 9 live-RPC tests: L3 real mainnet simulate, L8 Confirmed/Unknown/Unavailable), 0 clippy, fmt clean, benchmark 18/18 (4 safe→approved, 0 FP/FN), 27 Python tests, dashboard typecheck+build, TS SDK check+build, Go vet+tests, SAK typecheck + 9 AuditBind tests, e2e registry→verification session (signed submission ACCEPTED, resolves at CLI + server + dashboard).
- **C54**: Deployment verification — Phase 2's last exit item closed with runtime evidence. Three real Dockerfile defects found and fixed: (1) toolchain pinned at `rust:1.82` could not build the locked dependency tree (`clap_lex 1.1.0` requires Cargo's `edition2024`, stabilized in 1.85) → `rust:1.97-bookworm`; (2) `--features server` never built the `graphite` binary (`required-features = ["cli"]`) → both build steps use `--features server,cli`; (3) cargo's `target/` lands under the manifest's workspace root, so the `COPY` path was always wrong → `CARGO_TARGET_DIR` pinned in the builder stage. Image now builds (185MB), container runs non-root (uid 999), HEALTHCHECK healthy. Live security tests against the deployed container: auth 401s, rate limiting 429 on a concurrent burst, CORS default-deny + allowlist, audit log append-only JSONL, malformed/oversized bodies → 422/413 with the server surviving. Certification report upgraded CONDITIONAL GO → GO (§7/§10/§11); ROADMAP Phase 2 marked COMPLETE; Cargo.toml 0.1.1 → 0.2.0-beta and tagged `v0.2.0-beta`.
- **C53**: Independent-audit remediation — 3 real logic bugs fixed, the Manifest Registry wired into verification, docs synced.
  - **Gaming profile was unsatisfiable for its own minimum tier (FIXED)**: Gaming required `min_confidence 0.60` but the HeuristicInferred P6 ceiling is 0.55 — the profile could never approve the very tier it names as its minimum. Lowered Gaming to 0.55 (exactly the ceiling); the P6 security bound is untouched (the ceiling itself was NOT raised). New tests: `test_gaming_approves_heuristic_inferred_at_ceiling` + `test_gaming_still_rejects_below_threshold_and_unknown_tier`.
  - **`TrustTier::from_manifest_str` promoted malformed manifests (FIXED)**: empty/unrecognized `trust_tier` strings defaulted to `HeuristicInferred` (Tier 1) — a manifest declaring no (or a garbage) trust level cleared profiles requiring HeuristicInferred. Now fail-closed to `Unknown` (Tier 0). New test: `test_from_manifest_str_empty_and_unrecognized_default_to_unknown`.
  - **Spurious `ceiling_triggered` from float accumulation (FIXED)**: the production signal weights (0.20×3 + 0.15×2 + 0.10) sum to 1.0000000000000002 in f64, so a perfect signal set produced confidence 1.0000000000000002 — flagged as `ceiling_triggered = true` against the 1.0 BattleTested ceiling even though nothing was ever capped. Confidence is now clamped to [0,1] before the ceiling comparison. New test: `test_battle_tested_ceiling_not_flagged_by_float_accumulation`.
  - **Manifest Registry NOT wired into verification (FIXED)**: community-accepted manifests lived only in the registry engine/dashboard and never reached the runtime registry, so accepted community protocols still resolved as unknown at verification time. Accepted submissions now persist their full manifest; `ManifestRegistry::merge_community` merges them into the runtime registry **seed-wins** (a compile-time seed manifest can never be overridden; each community manifest is re-validated before insertion); `GraphiteCore::merge_community_manifests` exposes it; the server and `graphite verify` both load the shared registry state (`registry_state.json` / `GRAPHITE_REGISTRY_STATE`) at startup. New tests: `accepted_manifest_survives_snapshot_roundtrip` + `accepted_community_manifest_reaches_verification_registry` (end-to-end).
  - **Docs synced**: ROADMAP protocol count 22 → 28, Go SDK parity 16 → 19 fields, cert report CatchPanicLayer marked FIXED (installed at server.rs), README risk-pattern provenance clarified (9 risk-engine + 2 pattern-analysis).
  - Suite: **999 passed / 0 failed / 9 ignored**, 0 clippy, fmt clean.

- **C52**: Dynamic PDA grounding for Squads V4 + Jupiter DCA + live-RPC exploit corpus expansion.
  - **Jupiter DCA manifest rebuilt from the official DCA SDK IDL**: real defects fixed — account order now matches on-chain (`dca` FIRST, then user/inputMint/outputMint; previously `user` was first), account lists completed (openDca has 12 accounts; the manifest carried only 5), and the `dca` PDA now declares `pda_seeds: ["dca", user, inputMint, outputMint, uid]` where `uid` = `{instruction_data:8:16}` (u64 LE applicationIdx). PDA derivation **verified against live mainnet**: `findProgramAddressSync` with the real seed tuple derives exactly the live account `Ck1Ct3vsMfzxeEM2RmKmTS4FVXoCB3YAUunKVFyNsFiq` from real tx data. Raw evidence: `scripts/dca_idl.json` + `scripts/dca_real_account.json`.
  - **Squads V4 manifest rebuilt from the official v4 IDL**: seed template `["multisig", "multisig", createKey]` verified against the official `getMultisigPda` and **confirmed against live mainnet** — the derivation reproduces the real multisig `DDV1BEtsu…` from its own stored `create_key`. Role defects fixed (create_key/config_authority/creator/member are SIGNERS per the IDL, were marked readonly). Unverifiable vault-seed offsets rejected rather than kept (they would have false-blocked); only `multisigCreateV2` gets grounded seeds. Raw evidence: `scripts/squads_v4_idl.json` + `scripts/squads_real_pair.json`.
  - **Live-RPC exploit corpus expansion (35 → 37)**: 2 new real mainnet exploit transactions fetched live from `api.mainnet-beta.solana.com` and pinned with full fidelity — TX `2AWwL6dk` (slot 438712938, Aug 2026): fresh drainer chain unknown program `8MjG72…` → `GieMfa5…` (19 accts, real Token-2022 `mintTo` of 660,854 tokens, mintAuthority `3H5qEiP…`) → 2 calls to the KNOWN malicious HELPER program `L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95`; TX `3PbK87` (slot 382864866, Dec 2025): 20 top-level calls to the SlowMist AAT drainer (real disc `0e00000000000000`) across 23 unique accounts. Both wired as REAL scored benchmark cases (benchmark: 5 REAL + 2 SYNTHETIC, 20 total) with real account addresses/CPI structure, pinning tests in `tests/real_onchain_exploits.rs`, and raw evidence under `scripts/real_exploit_*.json`. Benchmark remains 100% precision/recall on 18 scored cases.
  - `test_new_protocol_manifests_are_grounded` + 4 new PDA known-answer tests; regression-engine seed pin updated 16 → 18.
- **C50**: Independent audit sync — regression_engine SetAuthority discriminator corrected `0b` (ThawAccount) → `06` (SetAuthority): the test was passing for the wrong reason (account-count error on ThawAccount, not the AuthorityHijack pattern). Now genuinely exercises the SetAuthority authority-hijack path. Cargo.toml version 0.1.0 → 0.1.1 (matches v0.1.1-alpha tag). README protocol table gained the 6 C46 protocols.
- **C51**: Audit-correction pass — corrected the C50 test count (1012 → 987 passed / 995 running, 8 network-dependent ignored; the 1012 figure was not reproducible) and the README Protocol_Manifests badge (22 → 28, missed by C50).

- **C46**: Six new protocol manifests grounded in official sources — **Phoenix** (28 ix, native shank 1-byte tags verified from live mainnet), **OpenBook V2** (29 ix, Anchor snake_case discriminators verified on-chain), **Switchboard** (48 ix), **Jupiter Limit Order** (9 ix), **Solend** (16 ix, layouts from official SDK doc comments with full readonly accounts; tags from official `unpack()`), **Marginfi** (4 ix, real mainnet shapes observed on-chain). All 6 program IDs verified executable on mainnet and pinned in `verified_program_ids.json`; discriminator derivation mode per program asserted by `test_new_protocol_manifests_are_grounded`. Drift + Kamino PDA seeds verified against official sources (IDLs + SDK codegen) and pinned with JS-SDK known answers in `account_resolution.rs`.

- **C28**: MAD (median absolute deviation) baseline for simulation integrity — replaces mean/stddev with robust statistics resistant to poisoning. Simulation z-score now uses MAD-based outlier detection.
- **C29**: Multi-instruction transaction analysis + CPI instruction trace analysis — 2 new RiskPattern variants (MultiInstructionDrain, CpiTraceAnomaly). Coordinated mass-drain detection across instructions in one tx (approve-then-transfer, authority-hijack-then-drain, close-and-sweep, mass multi-transfer sweep). Hierarchical CPI tree analysis for unknown, re-entered, or vanity-impersonated programs.
- **C30**: Real mainnet exploit data pinned in benchmark — 3 REAL mainnet exploit cases (STMT drainer 64tsGGe, AAT drainer 524t8LW, Wormhole $320M hack 5fKWY7X) replace 3 of 5 SYNTHETIC reconstructions. 2 SYNTHETIC remain, honestly labeled. Avg latency ~2.1ms (up from sub-ms, due to real-data cases).
- **C33**: Risk-engine discriminator-width bypass fix (CVE-class) — prefix-matching allowed short discriminators to match longer ones, bypassing detection. Now exact-match only.
- **C36**: P1 remediation — CPI flattening, instruction ordering, hidden-transfer semantics, swap classification.
- **C37**: CatchPanicLayer added to production router; formal discriminator-length decision (exact match, no prefix).
- **C38**: Phase 2 gates — real L8 execution verification (reports Confirmed/Unknown/Unavailable from mainnet RPC) + manifest-declared risk-class engine expansion.
- **C39**: Certification revalidation — fresh adversarial pass + malformed-discriminator fail-closed.
- **C40**: Live mainnet/devnet validation — L3 simulateTransaction on real devnet RPC; L8 execution verification on real mainnet RPC (Confirmed/UnknownSignature/Unavailable, honestly reported).
- **C41**: 2,181-fixture regression corpus — dev ~2,112 + regression 31 + holdout 38 (35 real SolPhishHunter mainnet exploit signatures from arXiv:2505.04094 + 3 real mainnet txs). 0 false negatives on holdout. Root fixes surfaced by the corpus.
- **C42**: Kamino V2 real layouts from live on-chain decoded streams; registry determinism fix; universal-CPI audit test.
- **C43**: Phase 2 certification report + ROADMAP sync.
- **C44**: Encoding-explicit manifest reads in Python test (Windows-locale fix — `encoding="utf-8"` on all `open()` calls).
- **C45**: Solana Foundation grant proposal ($120k, 3 milestones over 9 months).

### Current numbers (C54)
- **1,014 Rust tests passing** (1004 passed; 10 network-dependent ignored), 0 failures, 0 clippy warnings, fmt clean
- **33 protocol manifests**, 803 instructions, all program IDs verified executable on mainnet
- **11 risk patterns / 13 risk checks** (was 9/9)
- **2,747-fixture corpus**: 0 false negatives on 40-fixture holdout (38 real-exploit + real txs)
- **37-entry exploit corpus** (35 SolPhishHunter + 2 live-fetched from mainnet RPC)
- **5 REAL mainnet exploits** scored in benchmark (Wormhole $320M, CLINKSINK STMT, SlowMist AAT, fresh Aug-2026 drainer chain 2AWwL6dk, AAT mass drain 3PbK87); 18 scored cases, 100% precision/recall
- **L3 live-validated** on devnet RPC; **L8 live-validated** on mainnet RPC
- **SAK integration verified** on devnet (5 finalized transactions)
- **Go SDK**: 10 tests, 16-field parity; **Python AI layer**: 27 tests; **TS SDK**: compiles clean

Layer names follow `graphite-engineering-skill/ARCHITECTURE.md` section 3.12 as the canonical source.

## [Round Six — C27: Drift + Kamino Lending on-boarded from official IDLs with live-verified discriminators and source-scoped PDA grounding] — 2026-08-09

### Two new BattleTested manifests: Drift Perpetuals (249 ix) + Kamino Lending (51 ix)
- **Official IDL ground truth**: Drift built from velocity-exchange/protocol-v2 `sdk/src/idl/drift.json` (program `dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH` — the SDK's DRIFT_PROGRAM_ID; the repo is the moved drift-labs/protocol-v2), Kamino from Kamino-Finance/klend-sdk `src/idl/klend.json` (program `KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD` — codegen PROGRAM_ID). Both confirmed executable on mainnet via getAccountInfo. IDLs committed as `scripts/drift_idl.json` / `scripts/klend_idl.json`; `scripts/rebuild_drift_kamino_manifest.py` regenerates both manifests.
- **Discriminators derived + verified LIVE**: neither IDL embeds discriminator bytes, so all 300 are derived as `sha256("global:"+snake_case)[0..8]` and then proven on the deployed binaries by on-chain census (`scripts/census_drift_kamino.py`, base58-correct decode): 14/300 observed on mainnet — Drift placePerpOrder ×128, cancelOrdersByIds ×41, placeOrders ×41; Kamino flashBorrow ×136, flashRepay ×136, refreshReserve ×19, refreshReservesBatch ×13, refreshObligation ×8, depositReserveLiquidityAndObligationCollateralV2 ×5, borrowObligationLiquidityV2 ×3, redeemReserveCollateral ×3, depositReserveLiquidity ×2, initUserMetadata ×1, initObligation ×1 — all matched the derived values, zero unmatched. Kamino's deployed `InitObligationArgs` carries only tag+id (no seed1/seed2), matching the observed 10-byte instruction data.
- **PDA grounding scoped to what the deployed program actually seed-constrains (C26 principle)**: `scripts/verify_dk_pdas.py` re-derives every grounded PDA from real txs (manifest-driven acceptance test) — all 5 live-observable grounds MATCH (Drift n/a in recent surface; Kamino lma in deposit/flashBorrow/flashRepay, obligation in initObligation, userMetadata in initUserMetadata). Notably: Kamino runtime ixs (deposit/borrow/flashBorrow/etc.) constrain vaults by `address = reserve.state.vault`, NOT by PDA — grounding them as `[const, reserve]` would false-flag legitimate txs, so vaults are grounded ONLY in initReserve. Drift user_stats is PDA-derived ONLY in initializeUserStats (elsewhere the program uses `has_one`/`is_stats_for_user` consistency checks), and spot_market_vault is grounded in deposit/withdraw/transferDeposit where the program seed-constrains it.
- **variable_accounts**: Kamino refreshReservesBatch reads (reserve, market) pairs from `remaining_accounts` (deployed handler) — marked variable so drainer heuristics don't false-flag legitimate batch refreshes.
- **Regression protection**: C27 test module pins the full 300-instruction surface against the snake_case convention (C18 bug class), 9 chain-observed discriminators, the exact PDA-grounding scope per instruction, and an end-to-end initObligation obligation-PDA derivation (correct key passes, spoofed key flagged as PDA mismatch). Verified program IDs added to `protocols/verified_program_ids.json` (bidirectional pin test: 22 programs). Manifest count assertions updated (Rust + Python AI layer).
- Validation: full Rust suite green (869 tests, 0 failures), Python AI-layer green (22 manifests), AuditBind 9/9, TS typecheck clean, fmt + clippy clean.

## [Round-Five Clean-Room Revalidation — C26: Orca 66/66 On-Chain Proof + Manifest-Spoofing Defense Repair] — 2026-08-09

### Orca Whirlpools: all 66 discriminators verified against the DEPLOYED program, not just the census (C26.1)
- **On-chain dispatch proof**: every one of the 66 manifest discriminators was simulated against the live mainnet binary (programdata fetched via the ELF-loader stub, `sigVerify:false`, real fee-payer) — each dispatches to its named handler; a garbage discriminator returns `InstructionFallbackNotFound`. The 6 entries without explicit handler logs failed AFTER dispatch with Anchor account-validation errors (3006/3007/3010). The `idl_include` entry (suspected as a non-dispatchable Anchor artifact) is a real handler on the deployed binary.
- **Anchor-convention cross-check**: all 66 discriminators re-derive as `sha256("global:"+snake_case)[0..8]`; the IDL is internally consistent.
- **2022-era continuity**: earliest program-source tree (v0.1.1) through latest 0.1.x (v0.1.19) — all 2022-era instruction names are a strict subset of the current 66; the 6 fabricated C23-era names appear in NO program-source tree at any tag.
- Full report: `docs/clean-room-revalidation-C26.md`.

### Manifest-spoofing defense: the H6 test was vacuous and is repaired (C26.2)
- H6's malicious manifest used the OLD string-array account schema, so `load_manifest` rejected it and the injected manifest NEVER entered the registry — the test passed because the transfer intent mismatched SetAuthority (L5) against the bundled manifest, not because any spoofing defense fired.
- H6 rewritten with a schema-valid malicious manifest (self-asserted `OfficialManifest`, real SetAuthority discriminator `06` renamed "SafeTransfer"): it now asserts the manifest loads AND the risk engine's P0 Check 2 blocks with an `AuthorityHijack` finding. H6b pins the residual boundary: non-pattern-covered discriminators on fabricated manifests follow the manifest (the risky-pattern list is the defense).
- Benchmark correction: both "SetAuthority hijack" cases used discriminator `0b` (ThawAccount, blocked by L5 intent mismatch) — corrected to the real `06` so the suite actually exercises SetAuthority-hijack detection.
- Audit honesty: `BuiltTransaction.instruction_count` was a fabricated `1 + state_changes + allowed_cpis`; now `1` (the plan verifies exactly one instruction). The compute-budget estimate and data-hex projection are documented as what they are.
- Validation: full suite green (all 24 test binaries, 0 failures), clippy clean, fmt clean.

## [Round-Four Independent Audit — C25: Orca Full-Surface Rebuild + Fabricated-Instruction Removal] — 2026-08-09

### Orca Whirlpools: 6 FABRICATED instructions removed; manifest rebuilt to the full deployed surface (C25.1/C25.2)
- **6 of 24 manifest entries were fabricated** — `updateFeeRate`, `transferPositionDelegate`, `applyDelta`, `syncTickArray`, `closeAccount`, `closeConfigExtension` appear in NEITHER the 2022-era deployed IDL (v0.1.0, 25 instructions) NOR the current deployed IDL (66 instructions), and the orca-so/whirlpools git history has zero occurrences. The C24 note's claim that these were "corrected to the snake_case convention" was itself built on the false premise that they existed; this round supersedes it.
- The manifest previously covered only 24 of the 66 deployed instructions — every legitimate Orca txn using any other instruction fell to unknown-protocol mode (0.55 confidence ceiling). The manifest now covers the FULL deployed surface: all 66 discriminators are the explicit byte arrays from the official deployed-program IDL (npm `@orca-so/whirlpools`, program v0.9.0; the repo's Anchor.toml maps `whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc` to this source), NOT re-derived hashes. The IDL is committed as `scripts/whirlpool_idl.json` for reproducibility; `scripts/rebuild_orca_manifest.py` regenerates the manifest.
- **3 discriminators corroborated by live on-chain census** (base58-correct decode, 528 Orca txs): `swap = f8c69e91e17587c8` (×153), `swap_v2 = 2b04ed0b1ac91e62` (×342), `increase_liquidity_by_token_amounts_v2 = effb097cd2c6352b` (×7 — an instruction that exists only in the current IDL, proving the IDL is the deployment's instruction set). Census script: `scripts/census_orca.py` (progress cache gitignored).
- Regression: `orca_discriminators_pin_onchain_verified_values` now asserts the manifest covers all 66 instructions, pins the 3 live-observed values, and asserts all 6 fabricated names are ABSENT from the table.

### Instruction-surface total updated
- 219 → **261 instructions** across 20 manifests (Orca 24 → 66); manifest version bumped 1.0.0 → 2.0.0 with `previous_version_ref`.
- Validation: **864 Rust tests / 0 failed**, clippy `-D warnings` clean, fmt clean.

## [Round-Two Sub-Agent Verification — C23: Manifest Discriminator Ground Truth] — 2026-08-09

### Jupiter V6: 16 legacy camelCase hashes corrected to the deployed program's snake_case convention (C23.1)
- `route` (`e517cb977ae3ad2a`) and `route_v2` (`bb64facc31c4af14`) are CONFIRMED on-chain (C19/C21 claim stood; an early base64-vs-base58 decode artifact was caught and reverted before any claim was made).
- 16 old-era entries (`sharedAccountsRoute`, `setTokenLedger`, `routeWithTokenLedger`, all account-compression/check variants) carried `sha256("global:"+camelCase)` hashes that never match the deployed program — the C18 bug class. Corrected to snake_case; `sharedAccountsRoute=c1209b3341d69c81`, `setTokenLedger=e455b9704e4f4d02`, `routeWithTokenLedger=96564774a75d0e68` verified on-chain, the rest follow the program's confirmed convention.
- Manifest `note` documents the correction methodology and the internal `e445a52e51cb9a1d` route (1-account CPI under `shared_accounts_route_v2`) as non-top-level provenance.
- Regression: `jupiter_discriminators_pin_onchain_verified_values` pins verified values AND asserts the old camelCase hashes must NOT resolve; `jupiter_pinned_fixture_discriminator_resolves_in_manifest` asserts the pinned fixture carries `bb64facc31c4af14` under base58 decode.

### Jupiter DCA: corrupted discriminator table replaced + live fill path declared (C23.2)
- The previous 7-value table was never observed on-chain (stale/contaminated values; `verification.notes` falsely claimed live observation). On-chain census with base58-correct decode shows the deployed program is STANDARD ANCHOR: `initiate_flash_fill=8fcd03bfa2d7f531`, `fulfill_flash_fill=7340e24e21d369a2`, `transfer=a334c8e78c0345ba` observed live; remaining instructions follow `sha256("global:"+snake_case)[:8]`.
- The 3 fill-path instructions were MISSING entirely — the dominant real DCA traffic (keeper fills) was falling to unknown-protocol mode (0.55 ceiling). Added with accounts, expected state changes, and risk rules (flash-loan repayment must match borrow; diverted swap output = compositional drain; transfer recipient must be the owner's ATA).
- All 7 stale discriminators updated to confirmed values; `verification.notes` corrected; `probe_dca_pda.py` and tests referencing the stale `131cb5dbd74f7e19` updated to `16072162a8b722f3`.
- Regression: `jupiter_dca_discriminators_pin_onchain_verified_values` pins all 10 values, asserts the 7 stale values must NOT resolve, and verifies the fill path resolves as known protocol.

### Docs-vs-reality synced
- README/ARCHITECTURE/ROADMAP/release-evaluation/phase2-plan/branch-strategy/gap-audit updated: 861 tests (was 844), 20 manifests (was 15), 219 instructions (was 216), 9 risk patterns (was 8).

## [Round-Three Independent Audit — C24: Orca + Metaplex Discriminator Ground Truth] — 2026-08-09

### Orca Whirlpools: 23 camelCase hashes corrected to the deployed program's snake_case convention (C24.1)
- Only `swap` was correct. On-chain census with base58-correct decode observed `swap_v2 = 2b04ed0b1ac91e62` (×17) and `swap = f8c69e91e17587c8` (×4) — both equal `sha256("global:" + snake_case)[:8]`, proving the deployed program is standard Anchor.
- All 23 camelCase-hashed entries (`increaseLiquidity`, `initializePool`, `collectFees`, `openPosition`, …) corrected to snake_case; provenance note added to the manifest.
- Regression: `orca_discriminators_pin_onchain_verified_values` pins `swap`/`swapV2` (directly observed), pins the convention for 3 more, asserts the stale camelCase values are absent from the table, and proves a verified swap passes the pipeline as Clear.

### Metaplex Token Metadata: Shank u8 discriminators replace fabricated 8-byte values (C24.2)
- The deployed program (metaqbxx…) is Shank-derived, NOT Anchor. On-chain census observed instruction data starting `0x21` (=33, CreateMetadataAccountV3) and `0x0f` (=15, UpdateMetadataAccountV2). Per the enum order in mpl-token-metadata program/src/instruction/mod.rs: SignMetadata=07, VerifyCollection=12, BurnNft=1d.
- The old 8-byte values (0fd902b83e0f4ee4, …) were never observed on-chain — the previous verification note claiming live observation was fabricated (same artifact class as C22.4/DCA).
- Manifest rewritten to u8 discriminators; `verification.notes` corrected; `metaplex_discriminators.txt` regenerated with the full Shank enum order; `test_metaplex_token_metadata_manifest_has_create` and the pipeline test updated.
- Regression: `metaplex_discriminators_are_shank_u8_values` pins all 5 values, asserts fabricated values are absent, and proves real u8-prefixed data resolves via the registry's prefix match.

### Systemic guard: the C18 camelCase disease can no longer re-enter any manifest (C24.3)
- New `no_manifest_discriminator_is_a_camelcase_anchor_hash` scans every loaded manifest and fails on any camelCase-named instruction storing `sha256("global:" + camelCaseName)` — the bug class that recurred in Squads (C18), Jupiter V6 (C22.3), DCA (C22.4), and Orca (C24.1) is now structurally impossible.

## [Clean-Room Revalidation — C22: Live-Corpus Selection + Transfer TOCTOU Binding] — 2026-08-09

### Live-corpus selection records the protocol call, not the fee payment (C22.1)
- `live_corpus::tx_to_input` prefer-selection was first-match over the prefer-set. The production `seed-live` path passes EVERY manifest program ID (including System and ComputeBudget), so first-match degenerated to the System fee payment (2–3 accounts) that real blocks front-load — the corpus recorded fee payments instead of protocol interactions.
- Selection now ranks prefer-matching instructions by **account count** AND **excludes infrastructure programs** (System, ComputeBudget, ATA, Memo×3) from prefer-matching: set membership alone cannot mean "the interesting program" when the set contains the boilerplate. The actual invocation wins (Jupiter route: 40 accounts), or the max-accounts fallback for CPI-only protocols (pump.fun: 20-account router). Deterministic (ties → last maximal).
- **ALT placeholders fixed:** ALT-resolved account positions (`alt:{table}:{entry}`) are not valid base58 and silently failed verification, dropping transactions from the corpus. They are now skipped; an instruction whose accounts are ALL ALT-resolved yields no input (fail-closed).
- Regression protection: `full_pipeline_over_real_mainnet_transactions` now pins the selected program per pinned fixture (pump → router, jup → Jupiter, system → AMM) under the PRODUCTION prefer-set; new `production_prefer_set_never_selects_fee_payment` and `alt_placeholder_accounts_are_skipped_not_recorded`.

### Transfer-path AuditBind binds the amount (C22.2)
- `executeTransfer` (SAK bridge) verified and AuditBind-bound only `programId + discriminator + accounts` — the transfer amount (u64 LE lamports in the instruction data) was UNBOUND, so mutating the amount between verification and execution passed the TOCTOU check.
- Fix is two-sided by contract (Rust `content_hash` includes `instruction_data` only when present): the bridge now sends `instructionData` to verification AND to the AuditBind projection (4-byte `02000000` discriminator shape). Amount mutation now changes the hash and ABORTS.
- Regression protection: pinned TS test `C22 transfer binding: amount is bound via instructionData` (1 SOL vs 100 SOL differ; old no-data projection differs; bound projection verifies).

### Validation
- **858 Rust tests / 0 failed** (+2), clippy `-D warnings`, fmt clean, no-default-features + cli + rpc gates green, 27/27 Python, **9/9 AuditBind** (+1), TS SDK + SAK typecheck clean, dashboard builds.

## [Final Forensic Re-run — C21: Advisory Labeler v2 + Intent-Vocabulary Alignment] — 2026-08-08

### Advisory labeler expanded without an LLM (C21.2)
- `python-ai-layer/intent_parser.py` v2: emits the FULL Core semantic vocabulary (`swap|trade|exchange`, `transfer|send`, `stake|delegate`, `close|close_account`, `create|create_account`, `approve|revoke`) instead of 4 hardcoded classes. `mint`/`bridge`/`lend` are detected and surfaced as advisory warnings but labeled `unknown` (fail-closed) because the Core has no semantic class for them.
- `suggested_program_id`/`suggested_discriminator`/`protocol_candidates` are now **derived from the verified manifest registry** at load time (embedded fallback for standalone deployments) — swap → Jupiter `route_v2` `bb64facc31c4af14` (deployed entrypoint), transfer → System `02000000`, stake → `DelegateStake`, close → SPL Token `09`, create → ATA `00`, approve → `04`, revoke → `05`.
- Risk-hint warnings (advisory): impersonation-vanity destinations (`…11111`, `Compu…` — validated against the real exploit corpus), authority changes, approve-delegate escalation, close rent recovery, unknown token symbols, large amounts.
- Per-signal confidence (`confidence_components`: phrase/parameters/token/protocol) replaces the hardcoded 0.9. Deterministic, pure stdlib, no network — **~47k parses/sec, p50 ~21 µs** (50k-parse benchmark). 27 Python tests (was 8).

### Root-level risk-engine contradiction fixed (C21.1)
- `program_supports_intent` (P0 Check 9) returned `false` for `create`/`approve`/`revoke` — the L5 semantic layer's own vocabulary — so every legitimate create/approve/revoke transaction was blocked as `PermissionEscalation` even when the instruction matched the intent, contradicting Check 6b/7. Expanded to the full L5 vocabulary with correct program sets (create → System/ATA/Token/Token-2022/Metaplex/Pump.fun; approve/revoke → Token/Token-2022; aliases trade/exchange/send/delegate/close_account). Unknown intents remain fail-closed. 4 regression tests (`protocol_expansion_tests.rs`).

### Integration-surface fixes
- **Bridge default discriminator corrected (C21.3):** `executeSwap` defaulted to the LEGACY `route` (`e517cb97…`); live txs carry `route_v2` (`bb64facc…`) — default now `bb64facc31c4af14`.
- **TS SDK `IntentType` aligned (C21.4):** removed `lend` (no Core semantic class — would fail closed), added close/create/approve/revoke + aliases to match L5.

### Validation
- **856 Rust tests / 0 failed** (was 852), clippy `-D warnings`, fmt clean, no-default-features + cli gates green, 27/27 Python, 8/8 AuditBind, TS SDK + SAK typecheck clean.
- Live-server probes: create/revoke intents now pass the risk engine (Clear); approve still hard-blocks by design (risky-pattern PermissionEscalation); 2 MB body → 413; malformed Content-Length → 413; trailing-JSON → 422.
- On-chain: all manifest IDs involved (Jupiter V6, System, SPL Token, ATA, Stake) re-verified executable on mainnet.

## [P16 Real-Mainnet Benchmark — C19: Real Exploit Corpus + Two Real Defects Fixed] — 2026-08-08

### First P16 run on unseen real data
- **Real pinned exploit corpus (35 entries):** `tests/fixtures/exploit_corpus.json` — transactions pinned by signature from documented phishing accounts (SolPhishHunter arXiv:2505.04094; STMT/AAT/ISA attack classes), reproducible via `integrations/solana-agent-kit/build_exploit_corpus.mts`. `tests/exploit_corpus_tests.rs` enforces: every entry blocked, ISA blocks principled (`Impersonation` pattern).
- **`mainnet-benchmark.ts` rewritten honestly:** per-protocol real intents (DEX → swap; Squads → empty intent, reported honestly), real pinned corpus for the malicious half, JSON report output. Old fake "drainer" section (two invalid addresses rejected by the RPC: fabricated Marinade/Drift IDs) removed.
- **Result (fresh node):** malicious recall **100%** (35/35 blocked, 0 missed); legitimate 0/7 — all root-caused: cold-start confidence ceiling (0.44 < 0.80 TradingBot threshold, P7 earned evidence by design; steady-state approval proven by a seeded regression test) and Raydium CLMM unknown-protocol.

### Two real defects found and fixed
- **64-account input cap rejected legitimate modern transactions (C19.1):** a real 72-account Jupiter V6 route tx was rejected with `Account count mismatch: expected 64, got 72`. Cap raised to Solana's protocol limit (**256**); regression test proves the exact 72-account route verifies and approves with earned evidence.
- **ISA (system-account impersonation) not detected (C19.2):** added **P0 Check 10** — fund movement (System transfer 0x02, Token transfer 0x03 / transferChecked 0x0c) to/from an address impersonating an official system account (vanity `…11111` suffix or `Compu` prefix) is blocked with the new `Impersonation` risk pattern. Grounded in the paper's own detection criteria; corpus test asserts the blocks are principled (risk = Impersonation), not incidental low-confidence rejections.

### Honest cold-start finding (documented, by design)
- On a fresh node, earned-evidence signals (HistoricalVolume, CommunityVerification) are zero (P7), so max confidence for a manifest-matched tx is 0.44 — below every production profile threshold. Not a regression; a live deployment accrues evidence and attaches an RPC client for L3 simulation. Full numbers and reproducibility in `docs/p16-mainnet-benchmark.md`.

## [Independent Gap Audit — C18 Squads Rebuild + Dynamic PDA Grounded] — 2026-08-08

### Squads V4 Manifest Rebuilt from the Official IDL (C18)
- **The Squads manifest was fabricated.** Its discriminators were computed by hashing the camelCase IDL display names (`sha256("global:multisigCreateV2")`); Anchor actually hashes the snake_case Rust fn name (`sha256("global:multisig_create_v2")`). It also carried 18 v1-era instructions (`add_member`, `create_proposal`, `execute_transaction`, …) that do not exist in the deployed program. Only 3 of 21 instructions were real, and 2 had wrong discriminators.
- **Chain evidence:** official `squads_multisig_program` IDL v2.1.0 + live mainnet txs — `vaultTransactionCreate` = `30fa4ea8d0e2dad3` (observed in a live tx; manifest said `ed3256172ab558fc`), `multisigCreateV2` = `32ddc75d28f58be9` (manifest said `8faecbbfaecf93c5`), `proposalCreate` = `dc3c49e01e6c4f9f` and `proposalApprove` = `9025a488bcd82af8` (both observed live, neither in the manifest).
- **Fix:** `squads-v4.json` rebuilt from the IDL — all **36 deployed instructions** with correct discriminators, IDL account lists, honest risk rules (execute/approve/threshold/rent-collector flagged).
- **Dynamic PDA grounded in a real manifest (finally):** `multisigCreateV2`'s multisig account now has `pda_seeds: ["multisig", "multisig", "{account_3}"]` (create_key) — official SDK `pda.ts` layout, IDL-confirmed ("createKey … used as a seed for the Multisig PDA"). New tests: snake_case-hash discriminator guard (bug class cannot recur), 4 chain-verified discriminator constants, and an end-to-end resolver test proving correct derivation + spoofed-multisig flagging. Transaction/vault PDAs need account-state seeds beyond the template engine — documented, not faked.
- **Honest caveat:** a direct chain reproduction of the multisig PDA from a create tx was attempted but not completed (create-tx scans timed out on the public RPC; the multisig whose account data was parsed predates the current struct layout). The layout is grounded in the program's own SDK + IDL; the deployed program version was proven current via the 4 chain-verified discriminators.

## [Independent Gap Audit — C17 Tier-0 Protocol Surface] — 2026-08-08

### Tier-0 Foundational Programs Added (C17)
- **4 new seed manifests** (16 → 20): Associated Token Account (`ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL`), Compute Budget (`ComputeBudget111111111111111111111111111111`), BPF Loader classic (`BPFLoader2111…`), BPF Loader Upgradeable (`BPFLoaderUpgradeab1e…`). All four IDs verified executable on mainnet 2026-08-08 and added to `verified_program_ids.json`, the blessed-canonical-set test, `load_seed_manifests`, and the Python cross-check.
- **Grounded, not self-referential:** `test_tier0_manifest_discriminators_match_real_mainnet_fixtures` parses the pinned real mainnet fixtures and asserts every observed ComputeBudget/ATA instruction byte resolves to a manifest discriminator with an EQUAL value (0x02/0x03/0x04 ComputeBudget and 0x01 ATA observed live). Compute Budget instructions take zero accounts by design (Solana source) — documented, and the pipeline's rejection of a standalone empty plan is asserted as correct behavior.
- **`scripts/live_revalidate.py` retry+backoff** for 429/5xx: a transient public-RPC rate limit is retried (1.5s/3s) instead of being misreported as "program absent". Run result: registry 20/20 EXEC, manifests 20/20 EXEC, SAK Ok, exit 0.
- **Instruction surface total: 216 across 20 manifests** (Squads rebuilt to the full 36-instruction IDL surface by C18).

## [Independent Gap Audit — C16 Memo Restoration] — 2026-08-08

### Classic SPL Memo Restored (C16)
- **`MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr` restored as the 16th seed manifest** (`spl-memo-program.json`) and 16th entry in `protocols/verified_program_ids.json`. The earlier C1 conclusion that this ID "never existed on any cluster" was **itself wrong**: `getAccountInfo` on `api.mainnet-beta.solana.com` returns an executable account (99,736 B ELF, owner BPFLoader2111, actively used) — it is the classic SPL memo from solana-program-library, used in countless SPL token transfers.
- **Registry completeness now guarded three ways:** the new blessed-canonical-set test (`manifest.rs test_registry_contains_blessed_canonical_programs`) anchors the non-negotiable core IDs (System, SPL Token, Token-2022, Stake, and all three memo programs) so the registry cannot be silently corrupted by edit again; the bidirectional pin test (Rust + Python) checks manifests↔registry consistency; `scripts/live_revalidate.py` is fixed to skip non-manifest JSON files and to verify the registry's own IDs on-chain (non-zero exit on any absence) — it previously crashed with `KeyError: 'protocol'` on `verified_program_ids.json`.
- **Docs corrected** across `docs/forensic-audit-report.md`, `docs/independent-gap-audit.md`, `docs/release-evaluation-report.md`, and this changelog — every "never existed" claim replaced with the verified fact.

## [Phase 1.5 Completion — Devnet Verified] — 2026-08-07

### RPC Client (live-verified against Helius mainnet + devnet)
- **`get_slot` u64 parse fix** — the live `getSlot` response is a plain `u64`; the client parsed `result.value`, so every call failed `InvalidResponse`. This silently broke the live-corpus test and L3 wiring.
- **`get_account` null check** — a `value: null` response now returns `AccountNotFound` instead of fabricating a zeroed account that flowed through typed as real state.
- **`get_oracle_price` placeholder removed** — was a hardcoded zeroed `OraclePrice` fake (dead code, unused repo-wide).
- **`is_account_frozen` byte 108 fix** — the SPL token account `state` field sits at byte **108**; the client read byte 46 (the mint field), so freeze state was read from the wrong offset.
- **`post_rpc` exponential backoff** — retry-aware RPC helper with exponential backoff on `429`/`5xx`; `max_retries` config is now actually honored. New `RpcError::RateLimited` surfaced correctly.
- **9 new unit tests** for the RPC client (mock server, no network dependency).

### Server Hardening
- **Bearer API key auth** — constant-time SHA-256 comparison; `/verify` and `/manifests` protected, `/health` open for load balancers.
- **Per-IP token-bucket rate limiting** — configurable (`GRAPHITE_RATE_LIMIT`), FIFO eviction, returns `429`.
- **CORS denied by default** — configurable allowlist (`GRAPHITE_CORS_ORIGINS`); server-to-server clients unaffected.
- **Audit log persistence** — append-only JSONL (`audit.jsonl`) covering all 4 paths: approved / blocked / 400 / 500.
- **Graceful shutdown** and **`X-Forwarded-For` trusted only behind an explicit proxy flag**.

### L3/L8 Honest Layer States
- **L3 provenance-aware tri-state** — `Passed` / `Failed` / `Inconclusive`; the real simulation verdict is now reported (no more phantom `passed: true`).
- **L8 honestly reports "not yet verified"** with an audit-trail event until live execution is wired (Phase 2).
- Audit trail records `l3_status` / `l8_status`; verdict math unchanged (penalties key off `Failed` only) — 671 → 680 tests all green.

### Novel Instruction Fail-Closed (P12)
- **Unknown discriminator on a known protocol with a high-risk intent → BLOCKED**; a non-blocking warning is surfaced in the L7 layer report and the summary for novel instructions on known protocols (GAP-1).

### Validation & Determinism
- **Whitespace-only `program_id` rejection** in `seed_simulation_baseline` (GAP-9) — empty check extended to whitespace-only strings (poison key that survives snapshot restore).
- **Proptest invariant suite** — `proptest_engine.rs`: 512 cases, pinned regression.
- **PDA known-answer tests** — cross-validated against `@solana/web3.js` (Raydium AMM V4 `amm_authority`, CPMM `vault_and_lp_mint_auth_seed`), pinned 2026-08-06.
- **Manifest ID regression test** — `test_all_seed_manifest_program_ids_are_canonical` pins all 11 program IDs.

### Integration & CI
- **SAK integration verified on Solana devnet** — 5 finalized transactions (2 faucet airdrops + 3 SAK test transfers), wallet `CWb8MciizembLV66kisYcXo3Cb91hdszxw74QHpEJKZR`; latest signature `xHa4dyuFS6JmSaTsmhcMpEtwbWnPjBoUGwk3wNixD2uw2Wmeui6GhnSmmdzNVkv85zXSd6g7QYhHymAjciwP3jJ` confirmed and finalized.
- **CI: 4/4 jobs green** — Rust (fmt/clippy/tests + no-default-features gates), TypeScript SDK + SAK, Go SDK, Python AI layer.
- **Final state: 680 tests, 0 failures, 0 clippy warnings, fmt clean, ~850μs avg benchmark latency** (16 scored cases, 100% precision/recall).

## [Production Readiness Pass] — 2026-08-06

### Security Fixes
- **G4: caller evidence can no longer raise the trust tier above the manifest's declared tier.** `behavior_evidence` is request-body JSON; fabricated `has_signed_manifest`/community/battle counts could previously mint `OfficialManifest` on a low-tier manifest, escaping that tier's 0.55 P6 ceiling and inflating the `TrustTierLevel` signal. The manifest-found path now ignores caller evidence entirely (the Semantic Graph's internally-earned tier is still honored). Regression test: `test_caller_evidence_cannot_raise_tier_above_manifest_declared`.
- **TS AuditBind TOCTOU check fixed.** `AuditBind.computeHash` encoded fields with `|`/`,` separators, which never matched the Rust `content_hash` byte stream — the check always aborted. It now mirrors the Core byte-for-byte (SHA-256 over programId, discriminator, account addresses, raw data bytes, CPI targets, truncated to 16 hex chars) with cross-language pinned vectors in `integrations/solana-agent-kit/auditbind.test.ts`.
- **Out-of-manifest CPI warnings are no longer silently dropped.** `assess()` computed CPI warnings for known protocols then discarded them. New `assess_with_warnings()` returns `RiskAssessmentDetail { verdict, warnings }`; the orchestrator surfaces warnings in the L7 layer report and the result summary (Constitution P3), while keeping the binary verdict fail-open (P12 response 2).

### Correctness / Compile Fixes
- **`--features rpc` now compiles.** Two non-`mut` bindings (`l3_rpc_account_info`, `usage`) were assigned inside `#[cfg(feature = "rpc")]` blocks — a hard compile error for the RPC feature.
- **G7: `VerificationResult.manifest_version` added** — the version label of the manifest the result was checked against (`None` for unknown protocols), letting consumers detect cross-version replay confusion. Populated in the result and mirrored in the TS + Go SDKs.
- **Input size caps added** — `instruction_data` ≤ 64 KiB and `cpi_targets` ≤ 32, via new `VerificationError::InvalidInput` (HTTP 400). Prevents unbounded CPU/memory from in-process callers.
- **Server no longer spawns a Tokio runtime per request.** The axum handler now calls `verify_async` directly instead of the synchronous `verify()` wrapper (which created a full runtime + threads per request).
- **Removed dead code** in `manifest::load_seed_manifests` (orphan `include_str!` binding).

### Integration / Docs
- **SAK bridge defaults fixed** — AI layer URL default `7332` → `8081` (matches `intent_parser.py --serve`); default wallet profile is now a Phase-1-calibrated `Custom { min_confidence: 0.40, min_trust_tier: OfficialManifest }` (the built-in profiles — TradingBot 0.80 etc. — were tuned for the Phase 2 signal set and block everything in Phase 1); misleading "simulation raises confidence" comments corrected.
- **TS SDK `WalletProfile` now models the `Custom` object form** the Rust serde enum expects (`{ "Custom": { ... } }`).
- **CI added** — `.github/workflows/ci.yml` runs Rust fmt/clippy (all features)/tests, TS SDK typecheck + SAK typecheck + AuditBind cross-language tests, Go vet/tests, Python pytest.

## [Phase 1.5 — Audit Fixes Round 4] — 2026-07-30

### SAK Bridge
- **Pre-flight account reconstruction.** `executeSwap` and `executeTransfer` now pass the wallet public key (extracted from keypair at construction) and program IDs to Graphite. Previously passed empty `accountAddresses: []`, meaning L1 and L4 could not detect authority hijack or PDA mismatch.
- **TOCTOU documentation.** Added explicit comment and `content_hash` logging before SAK execution. Full TOCTOU prevention (re-hash signed tx vs approved hash) is Phase 2 AuditBind middleware.

### Intent Parser
- **Case-sensitive parsing.** Removed `.lower()` from `parse_intent()` — Solana base58 addresses are case-sensitive and lowercasing corrupts them. The regex already uses `re.IGNORECASE` for keyword matching.
- **Destination extraction.** Transfer intents now extract the destination address from natural language input and pass it through to the SAK bridge.

### TypeScript SDK
- **`content_hash` field added** to `VerificationResult` interface in `sdk/typescript/src/types.ts`.

### Compositional Drain
- **Pattern 2 added.** `detect_compositional_drain` now catches 5+ deep CPI chains with all-unique program IDs from untrusted roots (previously only caught duplicate program revisits). Trusted DEXs whitelisted. 3 new tests added.

### Test Suite
- Tests: 635 (630 Rust + 3 new compositional drain + 2 from SAK bridge updates)
- Python: 7 tests (destination extraction + 11 manifest cross-check)
- Go SDK: 9 tests
- Clippy warnings: 0

## [Phase 1.5 — Audit Fixes Round 3] — 2026-07-26

### Program ID Fixes
- **5 fake program IDs in `extreme_adversarial.rs`** corrected: Jupiter V6, Orca Whirlpools, Raydium AMM V4, Squads V4, Memo. Tests were unknowingly exercising the unknown-protocol path (0.55 ceiling) instead of manifest matching.
- **Legacy Memo program added as 11th manifest.** Both `Memo4c2pN8afCj432Lb7RMVKi9PbQnnW7ewFFaV3oAH` (p-memo) and `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr` (legacy SPL) are real on-chain programs.
  - ⚠️ **Superseded correction (2026-08-08):** the C1 conclusion that `MemoSq4gq…` "never existed on any cluster" was **itself wrong** — independent re-verification (same day, C16) shows it IS executable on mainnet (99,736 B ELF, owner BPFLoader2111) and it was restored as the classic SPL memo. The real story: all three memo programs exist on-chain — `MemoSq4gq…` (classic SPL), `Memo4c2pN8afCj…` (memo v4.0.0, upgradeable), `Memo1UhkJRfHyv…` (legacy, superseded). Since 2026-08-08 the program-ID single source of truth is `graphite-core/protocols/verified_program_ids.json`, guarded by the blessed-set test, the bidirectional pin tests (Rust + Python), and the fixed `scripts/live_revalidate.py` on-chain gate.

### Content Hash (P2)
- **`content_hash` field added to `VerificationResult`.** `audit_trail_id` includes an AtomicU64 counter (unique per call) — not deterministic. Added separate `content_hash` field — pure SHA-256 of transaction config, fully deterministic.

### SAK Integration
- **Port fixed.** SAK bridge was defaulting to `localhost:8080` but Rust server uses `7331`.
- **bs58 shim fixed.** Bare function → object with `decode`/`encode` methods.
- **TypeScript type errors fixed.** Re-exported `VerificationResult` from `graphite-sak-bridge.ts`.

## [Phase 1.5 — Audit Fixes Round 2] — 2026-07-26

### Trust Tier Fix
- **`TrustTierCeiling` breakdown bug (P3 violation).** Ceiling cap was never shown in verification breakdown because code compared two already-capped values. Fixed by using `ceiling_triggered` flag and reconstructing raw confidence. Added floating-point noise filter (>0.001).

### Benchmark Honesty (P16)
- **Benchmark labels corrected.** 5 cases labeled "REAL: ... (mainnet)" changed to "SYNTHETIC: ... (real program ID, synthetic accounts)".
- **Baseline comparison added.** Simulation-only baseline (approve if compute_units > 0) shows 0% recall — Graphite catches all 12 malicious cases.

### SAK Integration Rebuild
- **Previous fake integration removed.** Was an HTTP wrapper that did NOT import `solana-agent-kit`.
- **Real SAK v2 integration built.** Imports real `solana-agent-kit`, `@solana-agent-kit/plugin-token`, `@solana-agent-kit/plugin-defi`. Uses real SAK API.

## [Phase 1.5 — Audit Fixes Round 1] — 2026-07-24

### Architecture Fixes
- **8-layer pipeline tracking fixed.** The `layers` vec in `VerificationResult` now matches the architecture spec exactly: L1_AccountResolution → L2_InstructionVerification → L3_SimulationVerification → L4_StateVerification → L5_SemanticVerification → L6_PolicyVerification → L7_RiskVerification → L8_ExecutionVerification. Previously tracked 7 layers with wrong names and order.
- **L2/L4/L5 verification layers implemented.** Instruction verification (discriminator + arg structure check), state verification (expected state changes vs transaction structure), and semantic verification (intent-behavior matching) are now real checks, not stubs.

### Dead Code Removed
- **cpi_chain.rs** — CPI chain checking is done inline in risk_engine.rs.
- **self_healing.rs** — Phase 2+ reference implementation, never called.
- **Fake SAK integration** — HTTP wrapper that did NOT import solana-agent-kit.

### Later Re-Integrated
- **regression_engine.rs** — Was initially removed, later re-implemented as an active module (P10 promotion gate, fixture corpus replay, `graphite regression` CLI gate, 12 tests).
- **plugin_orchestrator.rs** — Was initially removed, later re-implemented as an active module (6 plugin traits, panic-isolated execution, 2 real plugins, 56 tests).

### Test Quality
- **35 zero-assertion tests fixed.** Every test now has real assertions.
- **Layer tracking test added.** Dedicated test verifies 8 layers with correct names and order.

### Risk Engine Strengthened
- **PermissionEscalation** — Detects SPL Token Approve (discriminator 04) when intent is "transfer".
- **MaliciousAccountChange** — Detects CloseAccount/Allocate when intent is not "close".

## [Phase 1 — OMEGA RED TEAM Hardening] — 2026-07-22

### P0 CRITICAL Fixes
- **Corrected SPL Token and Token-2022 program IDs.** Case-sensitive base58 — `GKPfx` vs `GKPFX`.
- **NaN confidence bypass.** NaN passed range check → NaN < threshold is false → policy APPROVES. Fixed: explicit NaN/Infinity rejection.
- **Drainer ratio bypass.** 100 accounts + 1 declared change bypassed both drainer and hidden transfer detection. Fixed: ratio-based detection.

### P1 Fixes
- Drainer threshold: >5 → >=5
- Hidden transfer threshold: >12 → >=12
- Compositional drain threshold: >4 → >=3
- NaN/Infinity in simulation baseline values now rejected
- Empty discriminator on known risky programs now fails closed (P12)
- Account deduplication added to drainer detection

## [Phase 1.5 — Initial] — 2026-07-22

### Added
- FakeSwap detection — blocks swap intent on non-swap programs
- Simulation integrity check (3-signal z-score with Welford's algorithm)
- 4 additional seed protocols: Jupiter V6, Orca Whirlpools, Meteora DLMM, Memo
- TypeScript SDK with full type definitions
- Go SDK with integration tests

## [Phase 1 — MVP] — 2026-07-22

### Added
- Full Rust crate with real Solana types (curve25519-dalek, AccountMeta, Instruction, PDA derivation)
- 5 verified seed protocol manifests: System, SPL Token, Stake, Raydium AMM V4, Squads V4
- Risk Engine: 5 P0 patterns (Drainer, AuthorityHijack, HiddenTransfer, UnexpectedCpi, CompositionalDrain)
- 8-layer verification pipeline
- HTTP server (axum) + CLI (clap)
- Benchmark: 9 cases, 100% pass rate
- Release Evaluation Report (P16 compliant)
