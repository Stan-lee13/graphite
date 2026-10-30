# Round 39 — core-identity: transaction identity and manifests

Workstream `core-identity` of Round 39, at `c087bfb` (the Round 38 merge). Internal engineering
evidence, not an independent audit. Scope: `graphite-core/src/{tx_artifact, solana_types,
account_resolution, parsed_inner, transaction_builder, manifest, manifest_registry}.rs`, the
fuzz targets in `graphite-core/fuzz/`, `tools/runtime-oracle`, `tools/inner-instruction-oracle`,
attack campaigns 4, 5 and 13, and brief §2.2 items 8, 9, 13 and the §2.3 items on lookup tables,
parsed inner instructions and the first manifest.

## 1. Scope read

| File | Read | Disposition |
|---|---|---|
| `graphite-core/src/tx_artifact.rs` (2,744 lines) | fully, production and unit tests | No defect found in the parser; panics classified in §7. |
| `graphite-core/src/solana_types.rs` (499) | fully | No defect; PDA derivation matches `create_program_address`/`try_find_program_address` (seed limits, bump 255..1, on-curve refusal). |
| `graphite-core/src/account_resolution.rs` (1,598) | production fully (1–718); unit tests by name | No defect; wrong-program PDA, malicious seed grammar and aliasing reviewed (campaign 4). |
| `graphite-core/src/parsed_inner.rs` (854) | fully | No defect; every unrebuilt class now tested end to end (§3, §4). |
| `graphite-core/src/transaction_builder.rs` (339) | fully | No defect; summary only, nothing signs or binds to it. |
| `graphite-core/src/manifest.rs` (3,635) | production fully (1–1675); tests by name and the census tests | P3 R39-CORE-IDENTITY-4 fixed (an `expected_address` was never validated at load). |
| `graphite-core/src/manifest_registry.rs` (2,863) | production fully (1–1151); unit tests 1151–2863 fully | **R39-CORE-IDENTITY-1 fixed.** |
| `graphite-core/src/regression_engine.rs` | 1–512 (the corpus and the gate the registry calls) | Read for R39-CORE-IDENTITY-1. |
| `graphite-core/src/verification.rs` | in part: lookup resolution (6250–6400), L2 lookup positions (6690–6840), residuals (1960–2330), `execution_decision`, the simulation's `loadedAddresses` handling (8130–8420, 8630–8720) | **R39-CORE-IDENTITY-2 fixed.** The rest of the file is other workstreams'. |
| `graphite-core/src/rpc_client.rs` | in part: `loadedAddresses` and inner-instruction parsing (470–690, 1075–1140), `get_multiple_accounts` (2038–2110) | No defect in scope. |
| `graphite-core/fuzz/fuzz_targets/*.rs` (6 targets), `make_seeds.py`, seeds | fully | Assertions strengthened in four targets (R39-CORE-IDENTITY-5). |
| `tools/runtime-oracle/src/main.rs` (1,809) | header, verdict model, tally, corpus runner and `main` fully; generators by structure | Differential, not coverage-guided; `--inputs` added (§3, R39-CORE-IDENTITY-6). |
| `tools/inner-instruction-oracle/src/main.rs` (661) | header, type lists, case generators by structure | Differential against Agave's parser; no change. |
| `graphite-core/tests/{simulator_loaded_addresses, alt_*, sibling_lookup_accounts, round35_parsed_inner_instructions, r30_low_decode_manifests, r30_declared_effects_census, audit_a3_registry_replay_rollback, r30_registry_manifest_breaks, audit_a3_community_tier_self_asserted}.rs` | fully or the parts named | Harness models for the new tests. |

## 2. Findings

| Id | Sev | Where | One line | Status |
|---|---|---|---|---|
| R39-CORE-IDENTITY-1 | P2 | `manifest_registry.rs` `ManifestRegistryEngine::submit` → `gate_decision` | The P10 gate's 99.5% was over the registry's fixtures plus the submitter's, which pass by construction and multiply by provenance string; 250 padding fixtures let a loosening upgrade approve a refusal the registry had pinned. | Fixed with tests; break-tested |
| R39-CORE-IDENTITY-2 | P2 | `verification.rs` `mismatched_lookups` (~8157) | A v0 transaction reaching accounts through a lookup table was `executable_approved` when the simulator returned no readable `loadedAddresses`; the S-5 equality check ran only when the list was present. | Fixed with tests; break-tested |
| R39-CORE-IDENTITY-3 | P3 | `docs/CURRENT.md` K-7 | "75 instructions (64 Orca, 10 Kamino)" adds to 74; the pinned set is 65 Orca + 10 Kamino, and includes the IDL-only `idlInclude` and `idlMissingTypes`. | Doc fix for the main session |
| R39-CORE-IDENTITY-4 | P3 | `manifest.rs` `validate_manifest` | An `expected_address` value was never checked to be `{program_id}` or a base58 32-byte key; a typo made the slot refuse every call (fail closed). All 926 shipped values are valid. | Fixed with test |
| R39-CORE-IDENTITY-5 | P3 | `graphite-core/fuzz/fuzz_targets/` | Four targets asserted less than they claim: `parse_transaction` had no injectivity check; `manifest_json` asserted one direction of "exactly"; `lookup_table` compared counts, not identities; `rpc_json` only ran the simulation parser. | Strengthened; run |
| R39-CORE-IDENTITY-6 | P3 / evidence gap | `tools/runtime-oracle` | The oracle is differential against the Anza decoder and sanitizer, but its generator is seeded, not coverage-guided (brief §2.2 item 13). | `--inputs DIR` added; a coverage-guided corpus was run through it; gap narrowed, not closed |
| R39-CORE-IDENTITY-7 | owner decision | `manifest_registry.rs` first submission | A first manifest's fixtures are recorded under the candidate itself, so its replay is self-consistent by construction. | Owner decision (§2.7) |

### R39-CORE-IDENTITY-1 — the P10 gate could be diluted (P2, fixed)

- **Where.** `ManifestRegistryEngine::submit` replays `self.corpus.fixtures_for(program)` together
  with the submitter's `submitted.fixtures_for(program)` and called `decide_promotion(&run)`:
  promote at ≥ 99.5% of the whole run (`regression_engine::PROMOTION_PASS_RATE`).
- **Preconditions.** A submission that earns evidence: a registered reviewer's signature or
  attestation (reputation ≥ 100). That is the party the gate exists to hold to the pinned
  behaviour (MR-1: "a submission can add fixtures but never remove one").
- **Attack.** The submitter's fixtures are recorded under the candidate, so they pass by
  construction, and a fixture's identity covers its `source` string, so one input can be pinned
  any number of times. 250 such fixtures beside the registry's one refusal fixture make 250 / 251
  = 99.6%, so the candidate may fail the refusal — approve what v1 pinned as refused — and be
  promoted. The same holds without padding once the registry's own corpus passes ~200 fixtures:
  one pinned refusal could be flipped.
- **Impact.** A loosened manifest becomes the manifest in force for a non-seed program
  (`manifests_in_force`, merged into the verification core). Seed manifests are unaffected
  (seed-wins).
- **Reproduction.** `tests/round39_registry_gate_dilution.rs`
  `padding_the_submitted_corpus_does_not_let_an_upgrade_approve_a_pinned_refusal`: pre-fix
  `Ok(Accepted { trust_tier: OfficialManifest, version_label: "v2.0" })`.
- **Fix.** `ManifestRegistryEngine::gate_decision`: a fixture pinned as refused that the candidate
  approves blocks outright, whatever the pass rate; the registry's own non-deprecated fixtures are
  held to the pass rate on their own; then the whole run as before. A correction that legitimately
  changes a pinned outcome uses the existing operator escape hatch,
  `deprecate_regression_fixture`.
- **Tests.** Attack: the padded upgrade; `a_large_registry_corpus_does_not_tolerate_one_loosened_refusal`
  (251 registry fixtures, one flipped); `padding_does_not_dilute_the_registrys_own_fixtures`.
  Controls: `the_same_upgrade_without_padding_is_blocked`;
  benign `an_upgrade_that_keeps_the_pinned_refusal_is_accepted` (padded, accepted);
  escape hatch `a_retired_refusal_no_longer_holds_the_upgrade_back`.
- **Break.** In a copy (`/home/user/brk-core-identity-1`, own target dir): the loosening arm
  disabled → `a_large_registry_corpus_does_not_tolerate_one_loosened_refusal` fails (the padded
  case is still caught by the second arm); the registry-only rate arm disabled →
  `padding_does_not_dilute_the_registrys_own_fixtures` fails; both disabled (pre-fix) → the padded
  attack test fails. Every registry unit test (38) and the four registry integration files pass.
- **Confidence.** High; reproduced.

### R39-CORE-IDENTITY-2 — a v0 simulation that does not say what it loaded (P2, fixed)

- **Where.** `verification.rs`, `mismatched_lookups`: compared Graphite's resolution with
  `sim_res.loaded_addresses` only when the RPC returned a readable list. `rpc_client.rs` reads an
  absent, `null` or partly unreadable `loadedAddresses` as `None` (Round 29, R3: never a shorter
  list), and `None` fell through to "no mismatch".
- **Preconditions.** A v0 transaction reaching an account through a lookup table, and an RPC whose
  simulation omits `loadedAddresses` (or sends it unreadable). Graphite resolved the tables itself.
- **Impact.** The simulation was used although the accounts it executed against were never
  confirmed to be the ones Graphite resolved (the Round 34 S-5 rule says it must equal them or be
  set aside). With no list, the transaction's account list (`diff.transaction_accounts`) and
  privileges (`diff.transaction_privileges`) were built from the static keys alone, so a writable
  account loaded through a table read as not writable to `transfer_hook_reach` (code-reviewed;
  the reproduction shows the executable approval itself).
- **Reproduction.** `tests/round39_lookup_table_campaign.rs`
  `a_simulator_that_omits_or_nulls_its_loaded_addresses_is_not_believed` (absent, `null`,
  unreadable): pre-fix the absent case was `executable_approved`.
- **Fix.** A message with lookups whose simulation has no readable `loadedAddresses` is set aside
  exactly as a contradicting list is ("reports no readable loadedAddresses").
- **Controls.** `the_honest_lookup_is_executable` (`executable_approved`),
  `one_table_looked_up_twice_for_two_entries_resolves` (`executable_approved`).
- **Break.** Pre-fix `verification.rs` in the copy: the omission test fails
  (`absent: executable_approved`); every other campaign test passes.
- **False-refusal cost.** An RPC that omits `loadedAddresses` now refuses every v0 transaction with
  lookups. Agave's `simulateTransaction` returns the member; a provider that strips it is the
  case this closes. Not measured live (no live RPC in this round).
- **Confidence.** High for the approval (reproduced); medium for the hook-reach consequence
  (code-reviewed).

### R39-CORE-IDENTITY-3 — the K-7 count in `CURRENT.md` (P3, doc)

`tests/r30_declared_effects_census.rs::every_instruction_with_an_onchain_idl_has_the_idls_slot_count`
pins 75 entries: 65 Orca Whirlpools (64 instructions plus the IDL-only `idlInclude`) and 10 Kamino
Lending (9 plus the IDL-only `idlMissingTypes`). `CURRENT.md` says "64 Orca … 10 Kamino", which is
74. The test passes at this commit (census unchanged). Manifests were not changed.

### R39-CORE-IDENTITY-4 — `expected_address` values were not validated (P3, fixed)

`manifest::validate_manifest` checked PDA seed templates, discriminators and classes, and not the
`expected_address` constants of a pinned slot. A value that is neither `{program_id}` nor a
base58 public key matches no account, so every call of that instruction was refused as an
`expected_address_mismatch` — fail closed, found only when a verification reached it, and
reachable through `load_from_json` and community submissions as well as seeds. The validator now
refuses such a value at load. All 926 shipped values are keys or `{program_id}` (scratch
`expected_addr.py`), and the seed set still loads. Test:
`tests/round39_manifest_expected_address.rs` (four malformed values refused; two token programs,
the sentinel and an empty list load). No break run (P3; the test refuses inputs the pre-fix
validator accepted by construction). Confidence: high; code-reviewed and tested.

### R39-CORE-IDENTITY-5 — fuzz targets assert less than they say (P3, strengthened)

- `parse_transaction`: now re-encodes the parse (legacy, v0 and v1, from the parse alone) and
  requires the input's message bytes exactly, inside exactly the signature array the header
  requires — injectivity, the property the binding rests on. "Internally consistent" could not
  see a second spelling of a transaction.
- `manifest_json`: "a registry must accept exactly the documents `validate_manifest` accepts" was
  asserted one way; now both. And every validated instruction's own selector, and longer data
  starting with it, resolves to that instruction (`instruction_for`) — the discriminator-collision
  property.
- `lookup_table`: each resolved address is the table entry at the named index, in the runtime's
  order; it compared counts.
- `rpc_json`: an accepted simulation's `loadedAddresses` is exactly the provider's two lists, and a
  list with any unreadable entry is `None`; the simulation parser was only run.
- `state_diff` and `token_extensions` already assert meaningful properties; unchanged.

Run results: §6.

### R39-CORE-IDENTITY-6 — differential fuzzing against Agave (evidence gap, narrowed)

The runtime oracle is differential testing: every frame is decoded by the Anza SDK's own decoder
(bincode packet path and wincode) and `sanitize`, and Graphite must never accept a frame the runtime
refuses, must read every frame both accept identically (header, keys, instructions, lookups,
writability and demotion), and must not panic. Its inputs are the recorded corpus, systematic
limit and v1 passes and a seeded structure-aware generator — not coverage-guided. Round 39 adds
`--inputs DIR` (repeatable): every file of a directory goes through the same check, so the corpus
`cargo fuzz run parse_transaction` grows, guided by Graphite's parser coverage, is judged against
the runtime. What stays open: coverage guidance over the runtime's side, and execution-level
differential testing (lookup-table loading, account locks, the bank's writability) against a real
bank; both need an Agave runtime harness beyond this workstream.

### R39-CORE-IDENTITY-7 — an independent first-manifest validation (owner decision)

A first submission has no prior behaviour to regress against; its fixtures are recorded under the
candidate and replay against it by construction (documented in `manifest_registry.rs` and
`SECURITY.md`). Strategies that would make the first replay independent, each of which is a
policy choice:

1. require first-submission fixtures to be real executed transactions — signed bytes bound to their
   signature (`tx_artifact::bound_artifact_sha256`) and to an independent RPC's
   `getTransaction` — so the submitter cannot invent the inputs, only choose them;
2. require a minimum decode rate of the new manifest over an independent sample of the program's
   mainnet instructions (the `battle_tested_evidence.json` census method) before a first acceptance;
3. require two independent attesters for a first submission rather than one signature;
4. accept a first manifest only at `HeuristicInferred` until an upgrade or a measured census lifts
   it.

None is implementable without the owner choosing the bar (which RPC is independent, which
sample, how many attesters, what tier). The refusal and the documented limitation stay as they are.

## 3. Prior findings re-verified

| Id | What | Status at this commit | Evidence |
|---|---|---|---|
| F-007 (R36) / S-5 (R34) | Lookup freshness is the simulator's; Graphite's resolution must equal `loadedAddresses` | Holds for a present list (reorder, substitution, privilege move all refused); **did not hold for an absent list** → R39-CORE-IDENTITY-2 | `round39_lookup_table_campaign.rs`, `simulator_loaded_addresses.rs` |
| §2.3 last-extended-slot | Not applied by the Core; relies on the simulator and fails closed | Holds: such a transaction's simulation errs (`InvalidAddressLookupTableIndex`) and the verdict is not executable; deactivating tables are refused (`TableDeactivating`) | `last_extended_slot_and_stale_simulations_are_refused`, `a_deactivating_table_is_refused` |
| F-15-05 (R17) | Unresolved lookup positions fail L2 | Holds (`LookupTablesUnresolved` is not an inherent residual, `execution_decision` requires inherent-only) | `a_missing_table_is_refused`, `an_index_past_the_table_is_refused` |
| F-19-08 (R19) | Accounts loaded twice refused | Holds for static duplicates (parser) and static/loaded or loaded/loaded duplicates (`resolve_lookups`) | `one_table_looked_up_twice_for_one_entry_loads_it_twice_and_is_refused` |
| Round 35 | Unrebuildable parsed inner instructions stay incomplete | Holds for every documented class (Memo, `assignWithSeed`, `transferCheckedWithFee`, a Token-2022 extension, token metadata, Stake, Vote, lookup table, loader): `Inconclusive`, never executable | `round35_parsed_inner_instructions.rs::every_documented_unrebuildable_class_stays_inconclusive` |
| §2.2 item 8 / G-05 | 13 manifests below 90% decode | Census re-run: exactly the same 13 (recomputed against the shipped manifests: Light System, Ocr2, Account Compression, Oridion, Pump Fees 0.000; Rush 0.025; Bubblegum 0.057; Merkle Distributor 0.489; Coinflow 0.500; Zeta 0.670; Doorcash 0.675; Main 0.725; Timelock 0.776). Five records have no rate (three Memo programs, Switchboard v2 and Drift with 0 observed). Unknown bytes stay refused. Manifests unchanged | scratch `decode_census.py`; `r30_low_decode_manifests.rs` |
| §2.2 item 9 / K-7 | 75 account-count differences | Census unchanged (the pinning test passes); count wording in CURRENT is off by one (R39-CORE-IDENTITY-3). Manifests unchanged | `r30_declared_effects_census.rs` |
| A3-07, MR-1..MR-6, F-008, V-5 | Registry rollback, lineage, refused versions, signing domain, revocation, offline verification | Hold; MR-1's "never remove a fixture" did not hold against dilution → R39-CORE-IDENTITY-1 | registry unit and integration tests |
| F-16-06, M-3, M-4, A-1 (seed grammar) | Malicious seed grammar refused at load and at verification | Holds (code-reviewed; unit tests in `account_resolution.rs`, `r30_registry_manifest_breaks.rs`) | — |
| Discriminator ambiguity (2026-09-05) | Prefix-related discriminators refused in both validators | Holds; now also a fuzz property | `manifest_json` target |

## 4. Attack campaigns

All end to end through `verify_async` against a loopback mock RPC unless noted.

### Campaign 4 — discriminators, accounts, PDAs (code-reviewed; existing tests re-run)

| Attack | Preconditions | Expected | Observed | Test |
|---|---|---|---|---|
| Discriminator prefix/truncation | input shorter than a selector, or a prefix of it | no match | `discriminator_matches` requires the full selector and well-formed hex | `manifest.rs` tests; `manifest_json` fuzz (selector self-resolution) |
| Two prefix-related selectors | manifest declares `01` and `0100` | refused at load | refused by both validators | `ambiguous_prefix_discriminators_are_rejected` |
| Wrong-program PDA | an address derived under another program for the same seeds | `pda_mismatch` | derivation is always under the instruction's own program id; a mismatch flags the slot (the grammar cannot name another program — a manifest that needs one cannot be expressed and fails closed) | `account_resolution.rs` tests |
| Malicious seed grammar | `{account_99}`, `{account_+1}`, `0xZZ`, reversed range, 33-byte literal, 16 seeds | refused at load | refused | `validate_seed_templates` tests, `r30_registry_manifest_breaks.rs` |
| Duplicate / reordered accounts | same address in two slots; slots swapped | judged by position and by L4 | resolution is positional and does not refuse aliasing (an honest transfer to itself is legal); identity and effects are L2/L4's | code-reviewed |
| Absent optional account | the program's own id in an optional slot | constant, never a signer, writable flag compared | as expected | `account_resolution.rs` tests |

### Campaign 5 — frames and lookup tables

Fixture: `tests/round39_lookup_table_campaign.rs` (a v0 System transfer to an account reached only
through a table; a loopback RPC serving the table and a simulation). Frame-level malformations
(legacy/v0/v1 framing, signer counts, truncated signatures) are covered by `tx_artifact.rs` unit
tests, the runtime oracle and the strengthened `parse_transaction` fuzz target.

| Case | Expected | Pre-fix | Observed (post-fix) |
|---|---|---|---|
| Honest control | `executable_approved` | `executable_approved` | `executable_approved` |
| Table owned by System | refused, names the owner | refused | refused |
| Deactivating table | refused (`TableDeactivating`) | refused | refused |
| Table account missing | refused | refused | refused |
| Index past the table | refused | refused | refused |
| One table, same entry twice | refused (loaded twice) | refused | refused |
| One table listed twice, two entries | resolves (runtime accepts) | `executable_approved` | `executable_approved` |
| `loadedAddresses` substituted | set aside (S-5) | refused | refused |
| `loadedAddresses` entry moved to readonly | set aside | refused | refused |
| `loadedAddresses` absent / `null` / unreadable | set aside | **`executable_approved`** | refused (R39-CORE-IDENTITY-2) |
| Last-extended-slot / stale simulator (`InvalidAddressLookupTableIndex`) | not executable | refused | refused |
| Loads reported for a legacy message | set aside | refused | refused |
| Table changed after verification | cannot change a resolved index (append-only; recreation at the same address impossible) | — | `alt_real_v0.rs::extending_a_table_cannot_change_an_index_that_already_resolved` (code-reviewed for deactivation: the transaction then fails to land) |

### Campaign 13 — registry

| Attack | Expected | Observed | Test |
|---|---|---|---|
| Rollback (old accepted version again) | refused | `VersionAlreadyAccepted` | `audit_a3_registry_replay_rollback.rs` |
| Stale lineage (signed against v1, handed in after v2) | refused | `StaleLineage` | `lineage_is_enforced_and_a_refused_version_stays_refused` |
| Refused version retried after a fixture is retired | refused | `VersionPreviouslyRefused` | same |
| Fake standing (unregistered key, low reputation, self-attestation) | no evidence | as expected | `anonymous_signature_earns_nothing`, `low_reputation_registered_reviewer_is_rejected`, `the_signer_does_not_attest_its_own_submission`, `an_attestation_below_the_reputation_bar_earns_nothing` |
| Key revocation | stops counting; tier recomputed; never re-registered | as expected | `a_revoked_reviewer_stops_counting` |
| Wrong signing domain (bare hash) | does not verify | as expected | `a_signature_over_the_bare_hash_does_not_verify` |
| Content substitution | signature does not verify; offline check fails | as expected | `tampered_manifest_is_rejected`, `an_accepted_record_verifies_offline_and_a_tampered_one_does_not` |
| First-manifest self-replay | documented limitation | self-consistent by construction | R39-CORE-IDENTITY-7 (owner decision) |
| Upgrade with poisoned / padded fixtures | blocked | **accepted pre-fix** | R39-CORE-IDENTITY-1 tests |
| Edited fixture outcome | refused | refused (integrity hash) | `a_submitted_corpus_with_an_edited_outcome_is_refused` |

## 5. Invariant evidence

| Invariant | Implementation | Tests | Gap |
|---|---|---|---|
| Exact artifact binding | `tx_artifact::parse_transaction` (canonical compact-u16, trailing bytes, signature count = header, duplicate keys, limits), `unsigned_artifact`, `simulation_identity`, `bound_artifact_sha256` | unit tests; runtime oracle; `parse_transaction` fuzz now asserts injectivity | coverage-guided over Graphite only (R39-CORE-IDENTITY-6) |
| Lookup identities, not counts | `resolve_lookups`, `runtime_account_list` (shape check), owner check in `verification.rs`, S-5 equality incl. absence | campaign 5 tests, `alt_*`, `lookup_table` fuzz | last-extended-slot delegated to the simulator (documented) |
| Privileges from the bytes | `runtime_writable` (agave reserved keys, invoked-program demotion unless the loader may be loaded) | runtime oracle `run_reserved_keys` | feature-gated reserved keys left writable on purpose (stricter) |
| Fail closed on unrebuilt CPIs | `parsed_inner::rebuild` → `None` → incomplete | `every_documented_unrebuildable_class_stays_inconclusive`; inner-instruction oracle | each class needs an oracle case to be added |
| Evidence integrity (registry) | computed tier, lineage, refused list, registry-owned corpus, `gate_decision` | registry tests, `round39_registry_gate_dilution.rs` | first manifest (owner decision) |
| Manifest strictness | `deny_unknown_fields`, closed `RISK_CLASSES`, prefix ambiguity, seed grammar, layout lengths, `expected_address` values (Round 39) | manifest tests, `round39_manifest_expected_address.rs`, `manifest_json` fuzz | a slot's `role` string is free-form and not validated (its consumers were not examined this round) |

## 6. Commands run

All with `CARGO_TARGET_DIR=/home/user/core-identity-target CARGO_INCREMENTAL=0
CARGO_PROFILE_DEV_DEBUG=0`, `-j 2`.

| Command | Result |
|---|---|
| `cargo test --test round39_registry_gate_dilution` before the fix | 3 passed, 1 failed (the padded upgrade `Accepted`) |
| `cargo test --test round39_lookup_table_campaign` before the fix | 11 passed, 1 failed (absent `loadedAddresses` → `executable_approved`) |
| same two, and `round39_manifest_expected_address`, after the fixes | 6 / 12 / 2 passed |
| `cargo test --lib manifest_registry` | 38 passed |
| `cargo test --no-fail-fast` (graphite-core, default features), final | **2,435 passed, 0 failed, 14 ignored**, 176 test binaries (Round 38 floor 2,414; +21 new tests) |
| `cargo clippy --lib --test <the four touched test files> -- -D warnings`; `cargo fmt -- --check` | clean |
| `cargo +nightly fuzz build -O` (cargo-fuzz 0.13.2, nightly 2026-10-12) | all six targets build |
| `cargo +nightly fuzz run -O <t> <fresh corpus> seeds/<t> -- -max_total_time=120 -rss_limit_mb=2048` | parse_transaction 611,941 runs, corpus 645; lookup_table 1,225,084 runs (after the harness fix below), corpus 259+; manifest_json 739,478 runs, corpus 1,359; rpc_json 4,038,469 runs, corpus 1,723; state_diff 288,464 runs, corpus 862; token_extensions 2,104,341 runs, corpus 385. 0 crashes in the shipped code |
| lookup_table first run | 1 crash in the NEW harness assertion (a message with no lookups reads no table, so "the table decodes" does not follow); harness corrected, crash input replayed clean, rerun clean |
| `tools/runtime-oracle`: `cargo fmt -- --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo run --release --locked -- --iterations 20000 --inputs <the parse_transaction corpus above> --inputs graphite-core/fuzz/seeds/parse_transaction` | clean; corpus 15 shapes / 2,897 mutations; coverage-guided inputs 645 files (98 well-formed by both), seeds 24 (24); generated 20,000 + 20,000 v1 + 26,834 systematic; both accept 25,161, both reject 45,015, Graphite looser 0, disagreements 0, stricter-undeclared 0: `OK` |
| `tools/inner-instruction-oracle`: `cargo +1.99.1 run --release --locked -- --iterations 200000` | parsed 174,401, partially decoded 25,599; `PASS` (stable 1.97.0 cannot build it: solana-vote 4.3.2 requires 1.97.1; CI uses 1.99.1) |
| `python3 -I scratch/decode_census.py graphite-core` | 137 records; 13 below 0.90 (§3); 5 without a rate |
| `python3 -I scratch/expected_addr.py graphite-core` | 926 `expected_address` values, 0 invalid |
| Break copies (`/home/user/brk-core-identity-1`, `CARGO_TARGET_DIR=/home/user/brk-core-identity-target`) | §2; deleted afterwards |

Nothing in scope was BLOCKED. Not run: the 300,000-iteration CI oracle seeds (20,000 here, plus
the coverage-guided corpus), long fuzz campaigns, any live RPC.

## 7. `unwrap` / `expect` / `panic` / indexing / arithmetic in the production files

| Site | Kind | Classification |
|---|---|---|
| `tx_artifact.rs` `v1_u32`, the v1 priority fee | `try_into().expect` on `take(4)` / `take(8)` | invariant: `take(n)` returns exactly n bytes |
| `tx_artifact.rs` `decode_lookup_table` `data[0..4]`, `data[4..12]` + `expect` | slice + expect | guarded by `data.len() >= 56` above |
| `tx_artifact.rs` `decode_nonce_account` `data[0..8]`, `[8..40]`, `[40..72]` + `expect` | slice + expect | guarded by `data.len() >= 80` |
| `tx_artifact.rs` `parse_transaction` `static_keys[..n]`, `n - ro_signed`, `key_count - ro_unsigned`, `static_keys[0]` | slicing, subtraction | guarded by the `ImpossibleHeader` check (n ≤ keys, ro_signed < n, ro_unsigned ≤ keys − n, keys ≥ 1) |
| `tx_artifact.rs` `parse_v1` same, `static_keys[program_index]`, `static_keys[i]`, `num_required_signatures * 64` | indexing, arithmetic | guarded by the range checks before the map; ≤ 255 × 64 |
| `tx_artifact.rs` `Reader::take` `pos + n`, `frame_layout` `sig_count * 64`, `r.pos - sig_len` | arithmetic | `remaining() >= n` checked; `checked_mul` in `skip_signatures` |
| `tx_artifact.rs` `simulation_identity` `out[at..at+32]` | slicing | the parse read 32 bytes there |
| `tx_artifact.rs` `resolve_lookups` `decoded[table]` | HashMap index | every lookup's table inserted in the loop before (missing → error) |
| `tx_artifact.rs` `correspond` `hits[0]`, `by_accounts[0]` | indexing | after `len() == 1` |
| `tx_artifact.rs` `compute_budget_request` `seen[slot]`, `priority_fee` | indexing, u128 product | slot ∈ 1..=4 of 5; u64 × u32 fits u128, `try_from` saturates |
| `tx_artifact.rs` `durable_nonce` `ix.data[..4]` | slicing | after the length check |
| `account_resolution.rs` `real_account_metas[i]`, `metas[i]` | indexing | guarded by equal lengths (`real_metas_usable`, `grounded &&` short-circuit) |
| `parsed_inner.rs` `i as u8` / `i as u16`, `s.len() as u64` | casts | positions in 18/29-entry tables; usize → u64 |
| `transaction_builder.rs` compute estimate `200_000 + n·10_000 + c·50_000` | unchecked u64 | bounded by in-memory list lengths; cannot overflow |
| `manifest.rs` `shipped_data_unusable` `panic!` | panic | deliberate (M-5): only on a broken build's `include_str!` data; `try_*` variants return errors |
| `manifest.rs` `recomputed_decode_rate` division | f64 | `observed > 0` filtered |
| `manifest_registry.rs` `canonical_manifest_json` `expect` | expect | plain data with no floats or non-string keys; cannot fail |
| `manifest_registry.rs` `submit` `append_registry_evidence(..).expect` | expect | its only error is an empty program id, refused earlier (`EmptyProgramId`, base58 validation) |
| `manifest_registry.rs` `gate_decision` rate | arithmetic | `saturating_sub`; `pinned` non-empty |
| `solana_types.rs` | none | — |

No unchecked panic reachable from untrusted input was found.

## 8. What the main session needs to carry

- `CURRENT.md`: R39-CORE-IDENTITY-1 and -2 as fixed limitations of the registry gate and the S-5
  rule; correct K-7 to "65 Orca (64 + `idlInclude`) and 10 Kamino (9 + `idlMissingTypes`)"; the
  runtime-oracle limitation ("covers what it generates") now has `--inputs` for a coverage-guided
  corpus; the `lookup table's freshness` paragraph should say an absent `loadedAddresses` is set
  aside too.
- `SECURITY.md`: the registry paragraph on the P10 gate — a pinned refusal can no longer be
  loosened by any submission, and corrections need the operator's `deprecate_regression_fixture`.
- `CHANGELOG.md`: both fixes (behaviour change: an RPC that omits `loadedAddresses` now refuses
  v0 transactions with lookups; a registry upgrade that approves a pinned refusal is refused).
- Break log: the three registry breaks and the S-5 break (§2).
- Owner: R39-CORE-IDENTITY-7.
