# Round 19 — what one observation is

> **Historical record.** This report describes the codebase at commit `a1db51f`
> on 2026-09-23/24, and the changes made on top of it. For the current state of
> Graphite see [`CURRENT.md`](CURRENT.md).

**Date:** 2026-09-23 → 2026-09-24
**Trigger:** "run the full suite live locally, run every single part of
graphite, test it out against live mainnet data, also test the solana
integration, test graphite processing transactions, try breaking and hacking
graphite in so many ways both novel and actual mainnet data, check deeply for
root level issues and fix them, and also check if this is true and fix it" — with
an external AI review of `453dd01` attached.
**Starting state:** commit `a1db51f` (`main`).
**Constraints kept:** no credentials or RPC secrets anywhere; the mock RPC and
every attack ran on loopback; the only public endpoint touched was the public
mainnet RPC, read-only and paced; no wallet, key or fund was ever real. None of
this is independent certification — it is internal engineering work.

---

## 1. The review, checked

The review ran 1,549 tests green on `453dd01` and made one concrete finding plus
four observations. Each was checked against the code before anything changed.

| Claim | Verdict |
|---|---|
| `record_simulation_keyed` keeps only the 256 most recent keys, so a counted key counts again after 256 others (257 → 258) | **True.** Fixed as F-19-03 — and it was the smaller half of a larger defect: the key itself was wrong (F-19-01) |
| README advertises 1,455 passing / 10 ignored while `CURRENT.md` says 1,549 / 11 | **True, and worse:** the README contradicted itself (badge 1,562; three other places 1,455 / 10) and `CURRENT.md` said 1,562 / 12. Every count is now taken from one run (§7) |
| v1 transactions are refused | **True.** Now parsed (F-19-V1, §4) |
| Token-2022 `TransferFee` is not modelled | **True, still open.** Fee-bearing mints are refused, fail-closed |
| No branch protection; no third-party audit | **True, still open.** Both are owner decisions |
| The mainnet figures rest on 8 blocks | **True.** This round adds a fresh 19,458-transaction sample and a paced run of real transactions against the real mainnet RPC (§5). It is still a sample, and says so |

## 2. Findings

Severity: **P0** an approval or a signature outside the gate, **P1** a control
that does not do what it claims on real traffic, **P2** a control weaker than
stated, **P3** hygiene. Every fix was reverted once and its regression test
failed without it (§6).

| ID | Finding | Severity | Reproduced | Fix | Regression test |
|---|---|---|---|---|---|
| **F-19-01** | The baseline's observation key was the artifact digest, which covers the recent blockhash the simulator replaces: the same transfer re-asked with a fresh blockhash was a new observation each time | **P1** (F-15-01 re-opened) | Live, `a1db51f` release Core + loopback mock RPC: refused at 0.44 on ask 1, **approved at 0.573 on ask 3**, nothing changed but the blockhash | `tx_artifact::simulation_identity` — signatures and blockhash zeroed, domain-tagged SHA-256 | `round19_what_one_observation_is::a_fresh_blockhash_is_not_a_new_observation`, `::the_simulation_identity_ignores_the_blockhash_and_nothing_else` |
| **F-19-02** | A request with no artifact was simulated anyway (its `instruction_data` sent as a transaction) and recorded with no key; L3 certified "clean (RPC-verified)" bytes that were never a transaction | **P1** | Live: repeated identical descriptive requests took the System baseline from 5 to 16 samples, L3 `passed` | Only the artifact is simulated; an observation is recorded only when the described instruction was located in it and has an identity | `::a_descriptive_request_is_not_simulated_and_teaches_nothing` |
| **F-19-03** | (external review) A counted key left the 256-key window and counted again (257 → 258) | P2 | The reviewer's reproduction; confirmed by reading `record_simulation_keyed` | Exact per-accumulator memory (`ObservationMemory`, 64-bit fingerprints, bound 16,384); a full memory stops learning and routes to the shadow instead of forgetting | `::an_identity_counted_once_is_never_counted_again`, `::a_full_memory_stops_learning_instead_of_forgetting`, `::a_malformed_memory_is_refused_at_load` |
| **F-19-04** | An instruction the manifest does not describe put only account 0 in L4's diff, and its declared effects were prose L4 could not interpret, so a token debit was a warning | **P1** | Code trace; pipeline test | Privileges from the artifact (every account observed when there are no metas); `UNDESCRIBED_INSTRUCTION_EFFECTS` is interpretable and promises nothing | `round19_observed_execution::an_undescribed_instruction_has_every_writable_account_diffed`, `round19_binding_and_ownership::an_undescribed_instruction_declares_no_effects_rather_than_unreadable_ones` |
| **F-19-05** | Every account of an unknown program was read-only | P2 | Code trace | `resolve_unknown` takes the metas; without them every account is observed | `::an_unknown_programs_accounts_are_not_all_read_only` |
| **F-19-06** | `privileges_grounded` and the L4 fee payer read the caller's metas / the manifest's first signer instead of the artifact | P3 | Code trace | `effective_metas`; `message.fee_payer` | the L4 suites |
| **F-19-07** | Empty `instruction_data` under a non-empty label fell back to the label for every manifest lookup | P2 | Code trace | Empty data is a contradiction; supplied data is always the key | `::empty_data_under_a_label_is_a_contradiction` |
| **F-19-08** | A frame naming one account twice (the bank's `AccountLoadedTwice`) parsed; a lookup could resolve a static key; a lookup account's type tag was not checked | P2 | Byte level | `DuplicateAccountKey`, `LookupResolveError::DuplicateAccount`, `NotALookupTable` | `::a_frame_naming_one_account_twice_is_not_a_transaction`, `::a_lookup_that_resolves_a_static_key_is_refused`, `::an_account_that_is_not_an_initialized_table_is_refused` |
| **F-19-09** | PDA seeds past the runtime's limits (32 bytes, 16 seeds) derived an address; a read-only nonce account was accepted as a nonce transaction under the opt-in | P3 | Code trace | `SolanaTypeError::SeedLimit`; `nonce_account_writable` checked | `::pda_seeds_past_the_runtime_limits_derive_nothing`, `::a_read_only_nonce_account_is_not_a_nonce_transaction` |
| **F-19-10** | Caller-declared `cpi_targets` counted as "described" accounts | P3 (no reachable account) | Code trace | Counted only when the simulator saw the call | the L4 suites |
| **F-19-11** | Community/candidate manifests kept a declared tier above `OfficialManifest` (display only) | P3 | Code trace | `clamp_unmeasured_tier` | `::a_community_manifest_cannot_declare_its_own_tier` |
| **F-19-12** | The CLI wrote the snapshot beside a running server without its lock (and deleted the server's in-flight temp files); two snapshots could commit out of order and lose a quarantine; `persisted: true` was hard-coded; a corrupt snapshot started fresh, lifting every quarantine | **P1** | Code trace + live probe | `open_data_dir` (lock, cleanup, strict load), `open_data_dir_read_only`; snapshot generations; `quarantine_program_durably` | `::a_data_directory_has_one_writer`, `::a_corrupt_snapshot_is_refused_not_replaced`, `verification::tests::an_older_snapshot_never_overwrites_a_newer_one` |
| **F-19-13** | The verify key was also the operator key: any agent holding it could lift a quarantine | **P1** | Code trace + live probe | `GRAPHITE_ADMIN_API_KEY` (≥ 32 characters, ≠ verify key); `/admin/*` disabled without it; audit rows name the key id | `server::tests::the_verify_key_cannot_lift_or_add_a_quarantine`, `::without_an_operator_key_the_admin_surface_is_disabled`, `::the_operator_key_is_refused_when_short_or_equal_to_the_verify_key` |
| **F-19-14** | The concurrency permit was taken before rate limiting and auth, and refusals held it while draining — 32 unauthenticated trickling connections shed all traffic | **P1** | Code trace + live probe | Rate → auth → concurrency; the body is received (5 s) before a permit; refusal drain capped at 1 s + `Connection: close` | `server::tests::an_unauthenticated_slow_body_does_not_hold_a_permit` |
| **F-19-15** | `/admin/quarantine` accepted any string id and any-length reason, appending forever | P2 | Code trace | Pubkey check, 1,024-character reason cap, idempotent re-quarantine | `server::tests::quarantine_input_is_validated_and_idempotent` |
| **F-19-16** | Rate limiting keyed on the full IPv6 address; a rate below 1 req/s refused everything | P3 | Code trace | /64 keying; a burst floor of one token | `server::tests::rate_limit_keys_ipv6_by_slash_64`, `::a_sub_one_rate_still_admits_requests` |
| **F-19-17** | L8 rows marked `observed_by_graphite` carried caller-asserted `audit_trail_id` / `transaction_sha256` | P2 | Code trace | Only chain-derived keys are indexed; caller claims go to the detail, labelled | code review (row construction) |
| **F-19-18** | Audit-trail scans ran on the async runtime | P2 | Code trace | `spawn_blocking` for the L8 and `/audit/event` lookups | the L8 and lifecycle suites |
| **F-19-19** | `/health` (unauthenticated) returned the snapshot error text with absolute paths | P3 | Code trace | Redacted; the text stays in the log | — |
| **F-19-20** | Lifecycle history kept only the FIRST 64 rows per key and per merged view | P2 | Code trace | First half + latest half, per key and after the merge | `durable::tests::bound_history_keeps_the_first_and_the_latest_rows` |
| **F-19-21** | A signal whose history was all zeros (0 CPI hops) was treated as never observed and skipped | P2 | Code trace | Observed when the robust window holds ≥ `MIN_SAMPLES` samples | `simulation_integrity::tests::an_observed_zero_is_judged_not_skipped` |
| **F-19-22** | The CPI-trace rules ran only on a caller-declared trace, which the bridge never sends | **P1** | Code trace | The tree is rebuilt from `innerInstructions` (program, accounts, data, `stackHeight`); the structural rules always run on it | `round19_observed_execution::a_sweep_the_simulator_executed_is_refused_without_a_declared_trace`, `verification::tests::the_observed_cpi_tree_is_rebuilt_from_stack_heights`, `tx_pattern_analysis::tests::observed_trace_weighs_unknown_callees_by_the_root` |
| **F-19-23** | A torn final line swallowed the next record after a restart; three readers stopped at the first non-UTF-8 line | P2 | Code trace | A newline before a torn tail; byte-wise readers | `durable::tests::a_record_after_a_torn_line_survives_a_restart`, `::an_invalid_utf8_line_does_not_hide_the_records_after_it` |
| **F-19-24** | Token-2022 `TransferCheckedWithFee` and System `TransferWithSeed` did not count toward a sweep | P2 | Code trace | Recognised; destination index 2 | `tx_pattern_analysis::tests::with_fee_and_with_seed_transfers_are_transfers` |
| **F-19-25** | A panicking protocol plugin unwound through the request | P3 | Code trace | `catch_unwind`; judged as declaring no effects | — |
| **F-19-26** | The plugin log said a rejected manifest was "skipped" while the built-in stayed active | P3 | Code trace | The log says built-ins are not governed by manifests | — |
| **F-19-27** | A `Custom` wallet-profile threshold below 0.0, NaN or infinite was clamped by default but passed straight through under `GRAPHITE_ALLOW_PERMISSIVE_PROFILES` (a NaN reached the policy comparison); only `> 1` was refused as malformed | P3 | Live probe of the release binary (a `-1` threshold answered 200) + code read | Any threshold outside [0, 1] is a 400 in every mode, as the operator's `custom:<x>:<tier>` pin already required | `server::tests::non_finite_or_negative_custom_thresholds_are_refused_in_every_mode` |
| **F-19-28** | Two false-refusal classes on real mainnet traffic: two same-program, same-data instructions (two same-amount transfers to different destinations) could not be located even when the described accounts single one out — and the refusal said the instruction was absent; and a sibling carrying NO data (the legacy associated-token-account `create`) could not be declared at all | P2 (false refusals, fail-closed) | Conformance over the 19,458-transaction mainnet sample: 71 + 41 refusals of transactions the chain executed | Candidates disambiguated by their static account positions (two fully identical copies are still refused, with an honest reason); an empty discriminator describes an instruction whose data is empty, and nothing else | `round19_real_traffic_shapes` (4) |
| **F-19-V1** | Message version 1 (SIMD-0385) was refused by name — 3,302 of the 19,458 transactions (17.0%) in the 2026-09-23 mainnet sample | Coverage (fail-closed) | Measured on the sample | `parse_v1`, v1-aware frame helpers, `max_frame_bytes` at `/verify`, "versioned" = v0 or v1, `maxSupportedTransactionVersion: 1` at L8 | `round19_v1_transactions` (27, one of them the 3,302-transaction mainnet check, ignored by default); `tools/runtime-oracle` |
| **F-19-C1** | The reference SAK bridge signed the transfer and sent the signed bytes to the RPC (web3.js `simulateTransaction` with signers) BEFORE Graphite's verdict | **P0** | Confirmed in `@solana/web3.js` 1.98.4 source; bridge test on loopback | Unsigned `VersionedTransaction`, `sigVerify: false`, `replaceRecentBlockhash: true`; refuses any filled slot | `rpc-simulator.test.ts`, `graphite-sak-bridge.test.ts` |
| **F-19-C2** | The wallet key was handed to SolanaAgentKit ungated (`getSakAgent`, every SAK action) | **P1** | Code trace | `VerificationGatedWallet` refuses every signing method; the unverified-swap opt-out is retired | `gated-wallet.test.ts`, the bridge test |
| **F-19-C3** | No whole-transaction binding helper in the SDKs; stale Go docs | P2 | Code trace | `verifyTransactionDigest` (TS), `VerifyTransactionDigest` (Go), both v1-aware, one pinned cross-language v1 vector | `transaction-digest.test.ts`, `digest_test.go`, `round19_v1_transactions::the_cross_language_v1_digest_vector_is_the_cores_answer` |
| **F-19-C4** | SDK `projectionFromInstruction` could not express native discriminators | P2 | Code trace | Explicit discriminator + prefix check | the SDK suites |
| **F-19-C5** | The intent check was circular (AI output on both sides); the AI layer bound 0.0.0.0, single-threaded, with no socket timeout | P2 | Code trace | Deterministic grounding in the user's text; echo check; 127.0.0.1; threaded + timeouts | `intent-grounding.test.ts`, pytest |
| **F-19-C6** | Env-name mismatch; plain-HTTP keys to non-loopback hosts; router crash on a malformed `%`; vector pinning; Go status check | P3 | Code trace | Each fixed | the SDK and dashboard suites |
| F-19-X1 | `wire_format_bounds`' non-canonical `0x81 0x00` case now reads as a v1 marker; the no-default-features build broke on an ungated `rpc_client` type; the featureless `--all-targets` clippy had pre-existing warnings (never linted by CI) | P3 (build hygiene) | CI mirror | The case moved to a compact-u16 position that is still one; `#[cfg(feature = "rpc")]`; gated test helpers | `wire_format_bounds::the_u16_bound_holds_at_a_non_leading_length` |

### How F-19-01 was found

Round 17 made "the same bytes re-verified are ONE observation" by keying the
baseline on the artifact digest. The live probe asked the next question — what
are "the same bytes"? The digest covers the recent blockhash, and
`simulateTransaction` is called with `replaceRecentBlockhash: true` to overwrite
it. Two frames that differ only there are one execution to the simulator and
two observations to the baseline.

Reproduced on the `a1db51f` release binary, loopback mock RPC, fresh data
directory, re-run on 2026-09-24 for this report (`r19_evidence.py`):

```
ask #1 (blockhash 1) -> approved False conf 0.440  samples before: 0
ask #2 (blockhash 2) -> approved False conf 0.507  samples before: 1
ask #3 (blockhash 3) -> approved True  conf 0.573  samples before: 2
ask #4 (blockhash 4) -> approved True  conf 0.640  samples before: 3
descriptive #6       -> approved True  scope descriptive
                        L3 passed "Simulation integrity clean (RPC-verified): 450 CU / 2 writes / 0 hops"
```

The fix does not loosen what Round 17 established; it tightens what an
observation is. `simulation_identity` hashes the frame with its signatures and
its blockhash zeroed (a v1 frame's lifetime at bytes 8..40) under a domain tag,
so everything the simulator executes — instructions, accounts, amounts, the
header, a v1 frame's compute-budget config — stays in the identity. Honest
traffic still earns: a different amount is a different execution. Twelve
existing tests failed after the fix because they had earned their baselines by
varying only the blockhash; they were moved to genuinely distinct transfers, and
the identity rule was not relaxed to keep them passing. A thirteenth,
`rpc_influence_bounds`, stayed green while measuring less than its name claimed
(its twelve "distinct" transactions had become one observation) and was
corrected rather than left passing.

### The reference bridge signed before the verdict (F-19-C1)

`@solana/web3.js` 1.98.4 `Connection.simulateTransaction(transaction, signers)`
on a legacy `Transaction` fetches a LIVE blockhash, signs the transaction with
the signers and sends the SIGNED wire bytes to the RPC. The bridge called it
from `verifyTransaction` with the wallet keypair — before Graphite had
answered. The RPC therefore held a valid, broadcastable transfer that Graphite
might go on to refuse. The simulator now takes a public key and nothing else,
compiles an unsigned `VersionedTransaction`, simulates with `sigVerify: false`
and `replaceRecentBlockhash: true`, and reads every signature slot back out of
the serialized bytes before sending: any non-zero byte and nothing leaves.

## 3. What changed where

- `tx_artifact.rs` — `simulation_identity`; duplicate static keys; lookup
  duplicates and the table type tag; the read-only nonce account; the v1 frame
  (`parse_v1`, `V1Config`, `V1Violation`, `frame_layout`, `max_frame_bytes`).
- `semantic_graph_store.rs` — `ObservationMemory` and `OBSERVATION_MEMORY`;
  `record_simulation_keyed` and `record_shadow_simulation` never re-count;
  `promote_shadow_baseline` carries the memory.
- `verification.rs` — only the artifact is simulated; recording requires a
  located instruction and an identity; the observed CPI tree
  (`observed_cpi_tree_of`) judged by `analyze_observed_cpi_trace`; L4 from the
  artifact's privileges and fee payer; the empty-data contradiction; snapshot
  generations, `open_data_dir`, `open_data_dir_read_only`, strict snapshot load,
  `quarantine_program_durably`; the frame bound and "versioned" for v1.
- `rpc_client.rs` — `innerInstructions` with accounts, data and stack height;
  `maxSupportedTransactionVersion: 1` for `getTransaction`.
- `server.rs` — the operator key; layer order rate → auth → body → permit; the
  bounded refusal drain; `/admin/quarantine` validation and idempotency; IPv6
  /64 rate-limit keys; `/health` redaction; chain-only keys on L8 rows; audit
  scans on `spawn_blocking`.
- `durable.rs` — the torn-tail newline; the byte-wise line reader; the
  first-and-latest history bound.
- `simulation_integrity.rs`, `state_diff.rs`, `account_resolution.rs`,
  `solana_types.rs`, `manifest.rs`, `plugin_orchestrator.rs`,
  `tx_pattern_analysis.rs`, `cli.rs` — as in the table.
- Client side — `integrations/solana-agent-kit/{rpc-simulator,gated-wallet,intent-grounding,loopback-mocks}.ts`
  and the bridge; `sdk/typescript/src/transaction-digest.ts`; `sdk/go/digest.go`;
  `dashboard/src/transport.ts` and the router; `python-ai-layer/intent_parser.py`.
- `tools/runtime-oracle` — agave's `wincode` reader alongside bincode; the v1
  generator and the systematic v1 pass.

## 4. Version 1

v1 moves the signatures to the END of the frame with no count in front of them,
puts the compute-budget settings in the message as config values selected by a
u32 mask, drops lookup tables and raises the size bound to 4,096 bytes. The
parser implements the layout from `solana-message` 5.0 `v1/` and the frame from
`solana-transaction` 5.0 `SchemaRead for VersionedTransaction`, and refuses
everything the runtime refuses: unknown mask bits, more than 12 signatures, 64
addresses or 64 instructions, duplicate addresses, a heap size that is not
1 KiB-aligned within 32–256 KiB, the header arithmetic, a short or long
trailing signature array. Every frame helper finds the signatures at the end;
the signed-over bytes are the frame minus its trailing signatures, `0x81`
included, and a real ed25519 signature over them verifies.

The runtime oracle now decodes every frame with agave's own `wincode` reader
(and legacy/v0 with bincode as well, which can only make its model stricter),
sanitizes, and for every frame both sides accept also compares the signed
message bytes, the unsigned artifact, the filled slot count, the simulation
identity and the v1 config:

| Seed | Frames compared | Both accept | Graphite looser | Disagreements | Graphite stricter |
|---|---|---|---|---|---|
| default | 628,505 | 317,255 | 0 | 0 | 0 |
| 20260916 | 628,461 | 317,177 | 0 | 0 | 0 |

About 27,500 accepted v1 frames per seed are larger than a packet, and each of
the six v1-only refusals was hit between 1,179 and 19,976 times per run.
Against real traffic, 3,302 of 3,302 mainnet v1 transactions in the sample
parse (2,399 of them larger than 1,232 bytes) and every fee-payer signature
verifies through `bound_artifact_sha256`.

Two callers still assumed the packet bound and "versioned means v0"; both were
fixed and both fixes were deliberately broken (§6). The TypeScript and Go
digest helpers find a v1 frame's slots at its end, and one signed 232-byte v1
frame and its digest are pinned in the Core, the TS SDK and the Go SDK.

**Not done:** the v1 config values are parsed and bounded but not surfaced in
the verdict (the fee the simulator reports is still held to
`MAX_PLAUSIBLE_FEE_LAMPORTS`); the bridge builds legacy and v0 only (web3.js 1.x
cannot build v1); the JSON-shaped `live_corpus::tx_to_input` still skips v1,
because its v1 JSON layout has not been checked against a real response.

## 5. Live: every part run, against real data

### 5.1 The release binary, attacked over HTTP

`r19_live.py` starts the release `graphite` binary as a real server on
loopback — authenticated, with a separate operator key, a real data directory
and a loopback mock RPC — and attacks it: the blockhash replay, descriptive
repetition, the verify key on `/admin/*`, 40 unauthenticated connections
trickling bodies, the CLI writing beside the running server, hostile bodies,
out-of-range thresholds, 400 random mutations of a real artifact, a pre-signed
artifact, a corrupt snapshot, an operator key equal to the verify key. Every
approved mutation is re-parsed by an independent minimal legacy-frame parser
and must still carry exactly the described transfer.

| Binary | Checks passed |
|---|---|
| `a1db51f` (before this round) | 5 of 22 — the blockhash replay approves on the third ask; descriptive requests are simulated; the verify key quarantines and lifts; the CLI writes beside the server; 40 trickling connections turn a real request and `/health` into `503`; a `-1` threshold is accepted; a corrupt snapshot and an operator key equal to the verify key both start |
| this round's release build | **22 of 22** |

The artifact fuzz approved 8 of 400 mutations on both builds; all 8 changed
only bytes outside the instruction, the keys and the header (the blockhash,
the empty signature slot), and all 8 still carry exactly the described
transfer. No mutation produced a 5xx.

One probe check was wrong, not the gate: it expected a request with a
`Custom` threshold of `-1` never to be approved, and the release build approved
it — because the threshold was raised to the weakest built-in (0.55) and the
honest transfer had earned 0.64. Reading why found F-19-27: the same input
passed straight through under `GRAPHITE_ALLOW_PERMISSIVE_PROFILES`. The probe
now requires a 400, which the fixed build gives.

### 5.2 19,458 real mainnet transactions through the whole pipeline

`tests/mainnet_conformance.rs` over a fresh sample fetched on 2026-09-23 —
every transaction of a set of finalized blocks, pushed through the full
pipeline artifact-bound, with no RPC attached:

| | Before this round (`a1db51f`, v1 skipped) | After |
|---|---|---|
| transactions | 16,156 (legacy 12,134, v0 4,022) | 19,458 (+ 3,302 v1) |
| parse failures | 0 | **0** (v1 included) |
| verify errors | 0 | 0 |
| L2 passed | 13,701 | **16,900** |
| L2 failed — lookup tables unresolved (no RPC in the harness) | 1,581 (then labelled "other") | 1,589 |
| L2 failed — durable nonce refused | 762 | 951 |
| L2 failed — described instruction not located | 67 | **0** |
| L2 failed — sibling coverage incomplete | 38 | **0** |
| risk Clear | 11,458 | 11,802 |
| approved (no RPC: unreachable by design) | 0 | 0 |

**Every fix up to F-19-27 changed 0 of 16,149 verdicts** on the v1-free rows
— the verdict files of both builds are byte-identical over the same input. The
simulation-identity, observation, CPI-tree, L4, persistence and server changes
move nothing for honest traffic. F-19-28 then changed L2 on 112 transactions
of the full sample, all transactions the chain had executed: 104 from refused
to passed, 8 from a misleading reason to the honest one (unresolved lookup
tables); no risk verdict and no approval changed. The 1,581 "other" refusals
were read before being relabelled: every one is a v0 transaction whose lookup
tables this harness cannot fetch, which fails L2 by design since Round 17.

### 5.3 Real transactions against the real mainnet RPC

`tests/mainnet_live_rpc.rs` (new, ignored by default) verifies the newest
successfully executed transactions of the sample whose primary program has a
manifest, one at a time, 1.5 s apart, against the public mainnet RPC — the
Core's own simulation, pre- and post-state reads, lookup tables and all.
Nothing is signed or sent.

| | Result (40 transactions) |
|---|---|
| versions | 14 legacy, 24 v0, 2 v1 |
| L2 passed | 39 |
| simulated by the RPC | 40 attempted; 2 succeeded, 35 `simulation_failed`, 3 not simulated |
| risk Clear / Blocked | 3 / 37 |
| approved | 0 |
| invariant violations (an approval resting on a failed L2/L3/L4/L5 or a non-Clear risk) | **0** |

Why 35 of 40 failed to simulate was checked rather than assumed
(`sim_diag.py`, the same bytes and config sent to the same RPC by hand): the
runtime's own errors — a vote for a slot already past, an SPL `InsufficientFunds`,
`AccountNotFound`, `IncorrectProgramId` on an account since closed. These are
day-old transactions against today's state; Graphite reports them as
`simulation_failed`, names the residual, and records nothing. A real v1
transaction simulated successfully through the public RPC.

### 5.4 The Solana integration

The SolanaAgentKit bridge's 119 tests run the whole path — intent grounding,
the unsigned pre-verdict simulation, the gated wallet, `BoundTransaction`, the
residual policy, the lifecycle on the trail, L8 — against loopback mocks of the
RPC, the Core and the AI layer. The bridge's corpus regenerates with no drift
against the Rust fixtures. The TS and Go SDKs carry the same v1 digest vector
the Core asserts.

## 6. Deliberate breaks

Each fix was reverted in place (from a copy, restored byte for byte) and its
regression test run: **13 of 13 failed with the fix reverted.**

| Fix reverted | Test that failed |
|---|---|
| F-19-01 identity ignores the blockhash | `a_fresh_blockhash_is_not_a_new_observation` |
| F-19-02 only the artifact is simulated | `a_descriptive_request_is_not_simulated_and_teaches_nothing` |
| F-19-03 exact observation memory | `an_identity_counted_once_is_never_counted_again` |
| F-19-12 snapshot generations | `an_older_snapshot_never_overwrites_a_newer_one` |
| F-19-13 separate operator key | `the_verify_key_cannot_lift_or_add_a_quarantine` |
| F-19-20 history keeps the latest rows | `bound_history_keeps_the_first_and_the_latest_rows` |
| F-19-22 observed CPI tree judged | `a_sweep_the_simulator_executed_is_refused_without_a_declared_trace` |
| F-19-23 torn tail | `a_record_after_a_torn_line_survives_a_restart` |
| F-19-V1 frame bound at `/verify` | `a_v1_transaction_larger_than_a_packet_reaches_the_pipeline` |
| F-19-V1 "versioned" is v0 or v1 | `a_v1_transfer_is_verified_bound_to_its_bytes` |
| F-19-27 thresholds outside [0, 1] | `non_finite_or_negative_custom_thresholds_are_refused_in_every_mode` |
| F-19-28 accounts single out a copy | `same_amount_transfers_to_different_destinations_are_told_apart_by_their_accounts` |
| F-19-28 empty label, empty data | `an_empty_data_sibling_is_declared_by_its_program_and_accounts` |

## 7. What was verified

| Suite | Result |
|---|---|
| Rust, all features (`cargo test --all-features`; = the default features) | **1,628 passed**, 0 failed, 14 ignored (network- or sample-dependent, one soak benchmark) |
| Rust, featureless library (`--no-default-features --lib`) | 327 passed, 1 ignored |
| Rust, cli only (`--no-default-features --features cli`) | 1,415 passed, 3 ignored |
| `cargo fmt --check`; `clippy --all-targets -D warnings` in all three feature legs | clean |
| SAK bridge (`npm test`, `tsc --noEmit`) | 119 / 119; typecheck clean; corpus regenerates with no drift |
| TypeScript SDK | 28 passed, 4 skipped (the live-server tests, run in CI's container job) |
| Go SDK | 34 passed; `go vet` clean |
| Dashboard | 6 / 6; typecheck and production build clean |
| Python AI layer | 30 passed; the 10,000-parses/s smoke test runs at 4,800–12,100/s on this 8 GB machine for both `a1db51f` and this round, interleaved — not a regression, left to CI's runner rather than lowered |
| Runtime oracle | both CI seeds: 0 frames Graphite accepts that the runtime refuses, 0 disagreements |
| Live probe of the release binary | 22 / 22 (`a1db51f`: 5 / 22) |

Two test-harness defects surfaced in the final runs and were fixed rather than
retried past: three tests simulated an unreachable RPC by binding a port and
dropping it, and another test's mock server in the same binary could take the
freed port and answer (`durable_nonce_rpc` failed once that way — still refusing,
for a different reason); each now owns its port for the life of the test and
closes every connection unanswered. And `round9_resource_bounds`' 500 ms timing
bound on an O(1) refusal failed once at 1.5 s during a full parallel run on a
machine with ~500 MB free; alone it passes 3 of 3 at 36–87 ms in a debug build,
and nothing ahead of the size check changed this round.

## 8. Still open

- **Independent third-party audit** and **branch protection on `main`** —
  owner decisions; neither exists.
- **Token-2022 `TransferFee`** — refused, not modelled.
- **v1 config values** are parsed and bounded but not surfaced in verdicts;
  the bridge builds legacy and v0 only; the JSON corpus builder skips v1.
- **Identity mismatches on declared signer slots** (Round 18) — 938
  `AccountIdentityMismatch` blocks over the full sample, measured and not
  loosened.
- **The mainnet run is a sample.** 19,458 transactions from one day and 40
  against the live RPC is broader than 8 blocks, and still a sample.
- **L4's structural fallback reports `Passed`** when the simulation failed
  and no diff exists; approval is gated by the `simulation_failed` residual
  and the bridge refuses it, but the layer's word is weaker than its status.

## 9. Files

New: `docs/round19-what-one-observation-is-2026-09-24.md`;
`graphite-core/tests/{round19_what_one_observation_is,round19_binding_and_ownership,round19_observed_execution,round19_v1_transactions,round19_real_traffic_shapes,mainnet_live_rpc}.rs`;
`integrations/solana-agent-kit/{rpc-simulator,gated-wallet,intent-grounding,loopback-mocks}.ts` and their tests;
`sdk/typescript/src/transaction-digest.ts` and test; `sdk/go/digest.go` and test;
`dashboard/src/transport.ts` and tests. Every live document was brought to
this state: `README.md`, `ARCHITECTURE.md`, `SECURITY.md`, `ROADMAP.md`,
`CONTRIBUTING.md`, `docs/CURRENT.md`, `graphite-core/{README,CHANGELOG}.md`,
the SAK, TS SDK, dashboard, AI-layer and mainnet-sample READMEs,
`.env.example` and `docker-compose.yml`.
