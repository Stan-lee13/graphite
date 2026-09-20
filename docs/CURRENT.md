# Graphite — Current Status

**This is the one document that describes the codebase as it is now.** Every
other file in `docs/` is a dated record of what was true when it was written;
each carries a banner pointing here. When this file and a report disagree,
this file is current and the report is history.

Updated: 2026-09-20, after Round 15 (see `git log -1 -- docs/CURRENT.md`).
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
Overall:                         CONDITIONAL — security-hardened alpha
Exact transaction identity:      enforced (artifact_bound scope, transaction_sha256, message-equality at signing);
                                 an artifact without instruction_data, or one that does not parse, FAILS L2 (Round 9)
Residuals at execution:          gated — scope.unobserved_codes; the bridge refuses any non-inherent residual
                                 the operator has not accepted by code (GRAPHITE_ACCEPT_UNOBSERVED)
ALT / v0 account identity:       enforced (runtime numbering rebuilt; all-or-nothing resolution; owner checked)
Privilege source:                the transaction's header / tables, never the caller's description
Instruction identity for risk:   the instruction's own leading bytes, never the caller's label — a hex
                                 discriminator contradicting its instruction_data fails L2 for every protocol,
                                 a non-hex one never reaches a verdict, and the known-risky table is keyed on
                                 the bytes so a truncated but truthful label hides nothing (Round 13)
Authority changes in the diff:   the SPL owner field, mint authority and freeze authority are each watched;
                                 an undeclared change is Critical, so a hand-over that moves no value is seen
Measured on real mainnet:        10,669 transactions from 8 finalized blocks, 189 programs, run artifact-bound:
                                 0 parse failures, 0 false refusals from the L2 self-consistency check, and all
                                 1,087 known-risky-table blocks verified against the named instruction's own
                                 bytes. Round 13 changed 0 of 9,784 verdicts (`tools/mainnet-sample`)
Manifest coverage of the chain:  92.5% of sampled mainnet transactions call a program with NO manifest; the
                                 drainer heuristic blocks them (>=3 accounts, no declared state changes), which
                                 is the fail-closed posture meeting the coverage boundary, not a bug
Durable-nonce transactions:      refused at L2 by default; opt-in requires on-chain nonce verification
Token-2022 extensions:           classified, not modelled — semantics/authority/unknown/unreadable all block
Input bounds:                    artifact ≤ 1232 bytes (PACKET_DATA_SIZE), ≤ 256 declared siblings, every
                                 audit-trail field bounded on the way to disk
Audit trail durability:          fdatasync per record; whole-trail reads across rotated archives; indexed L8 join
L8 execution attribution:        joined on the chain's bytes (signature slots zeroed → scope.transaction_sha256),
                                 accepted only when bound to the signature — first slot equal to it, verifying
                                 under the fee payer's key — else refused with nothing attributed (Round 11);
                                 caller keys audit_trail_id → transaction_sha256 → content_hash, most exact first,
                                 cross-checked, never falling back (Round 10)
L8 inclusion evidence:           commitment read (processed proves nothing); an RPC contradicting itself or answering
                                 malformed draws no conclusion; redirects refused; optional independent witness
                                 (GRAPHITE_RPC_WITNESS_URL) must agree before an approval is reported executed;
                                 a blocked transaction sighted by either endpoint alarms (Round 12)
Parser vs the runtime:           never looser than agave's decoder + sanitize, proven in CI over the corpus and
                                 600,000 generated frames (tools/runtime-oracle, Round 12)
Lifecycle sequence:              every report checked against the rows on record — duplicate / out of order /
                                 unpreceded / signature conflict — recorded, never refused (Round 12)
One server per data directory:   enforced by an exclusive lock on graphite.lock (Round 12)
Lifecycle on the trail:          the bridge records signing before submission and submission after it, and runs
                                 L8 at the end, with the exact keys; every lifecycle row carries verdict_on_record
                                 and the key that resolved it
Server authentication:           required by default, ≥ 32 characters; GRAPHITE_DEV_MODE=1 permits keyless on loopback only
Request path:                    no per-request deep copy of state (/health ~1 ms; 960 verifies/s in-process with
                                 fdatasync per record); refusals drain the body and are readable (Round 11)
Repository integrity:            CI token read-only; actions pinned by commit SHA; base images pinned by digest;
                                 toolchain 1.98.1 in CI and in the container; Go, cargo-audit and Python (hash-locked) pinned
Independent third-party audit:   NOT PERFORMED — every campaign report is internal engineering work
Branch protection on main:       ABSENT — an owner decision; see "Not yet done"
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
| An artifact the network would refuse is refused before it is parsed | `MAX_TRANSACTION_BYTES` = 1232 at `/verify` entry, in `parse_transaction`, and in TS `messageOf`; `MAX_TRANSACTION_INSTRUCTIONS` = 256 | `tests/round9_resource_bounds.rs` (122 s → 1.6 ms) |
| ALT accounts are identified, not counted | `runtime_account_list`, `resolve_lookups`, owner check | `tests/alt_real_v0.rs` (3 real mainnet v0 txs, `meta.loadedAddresses` ground truth), `tests/alt_privilege.rs` |
| Privileges come from the bytes | `privileges_from_artifact` | `tests/privilege_from_artifact.rs` |
| A risky instruction cannot hide behind the name it was given | L2's `declared_discriminator_contradicts_data` runs first, for every protocol, manifested or not; `transaction_builder` refuses a non-hex discriminator outright; **every manifest lookup — account resolution, the declared-effects lookup, the risk context, the plugin rules — is keyed on the instruction's own first eight bytes, not on the caller's label** | `tests/mislabelled_discriminator.rs` (16), `tests/truncated_discriminator.rs` (22) |
| A label that is TRUE BUT SHORT cannot switch off the account checks | Round 14 (GFX-101): `discriminator_matches` is `input.starts_with(selector)`, so a label shorter than a selector missed the manifest, and the miss took `resolve_accounts` down the P12 path whose accounts carry `pda_mismatch`/`expected_address_mismatch`/`privilege_mismatch` all false. One `effective_discriminator`, derived from the bytes, now keys them all; an EMPTY label is covered too (GFX-108) | `tests/truncated_discriminator.rs` (Jupiter V6 route with an attacker program in the pinned token-program slot: full label and 4-byte label and empty label all produce the identity finding; the honest pinned account still clears) |
| A declared sibling is judged on its own bytes, not its label | Round 14 (GFX-106): `sibling_coverage` records which artifact instruction each declaration matched and `siblings_keyed_on_their_bytes` rewrites the discriminator from that instruction's data before the Risk Engine sees it. A declaration matching nothing is left as written — L2 has already failed | `tests/truncated_discriminator.rs` (a real System `Assign` declared `01`/`0100`, a real SPL `SetAuthority` declared `0`, and a Raydium CPMM `close` declared at half length, all still block) |
| A sibling's lookup-table accounts are compared, not assumed | Round 14 (GFX-107): the primary's comparison resolved ALT positions and a sibling's did not, so every lookup slot in a declared sibling accepted any address — and declared accounts widen the set `ArtifactAccountsNotDescribed` treats as named | `tests/sibling_lookup_accounts.rs` (mock RPC serving one table: the honest declaration is accepted, one naming a different address at the resolved position fails L2) |
| A declaration too short to identify a risky instruction is refused | Round 14: `disc_matches` fires when the input is at least as long as the selector; a strict PREFIX of one sat in the gap. Reachable only in descriptive mode, where there are no bytes to re-derive from | `tests/truncated_discriminator.rs` (a descriptive `01` on System, and a descriptive `0` sibling on SPL Token, are both refused; a complete `03` still clears) |
| The gate behaves the same on real traffic as on the fixtures | Whole finalized mainnet blocks, every transaction pushed through the full pipeline artifact-bound — real bytes, real data, accounts resolved from the block's own `loadedAddresses`, every sibling declared | `tests/mainnet_conformance.rs` + `tools/mainnet-sample` (10,669 transactions, 2026-09-17: 0 parse failures, 0 false refusals, 1,087/1,087 risky-table blocks confirmed against the real bytes, 0 verdicts changed by Round 13) |
| An undeclared authority change is a finding, not silence | `state_diff::AccountDelta::{token_authority_change, mint_authority_change, freeze_authority_change}` — the SPL `owner` field is the authority, distinct from `owner_change`'s owning program | `state_diff::tests::{a_token_account_changing_hands_is_critical, a_mint_authority_changing_hands_is_critical, a_freeze_authority_appearing_from_nothing_is_critical}` plus four controls |
| Wire-format bounds on both sides | `compact_u16` (Rust), `messageOf` / `readSignatureCount` (TS) | `tests/wire_format_bounds.rs`; 1,647-mutation cross-language corpus in `tests/sak_bridge_corpus.rs` |
| Provider fields cannot override canonical evidence | `rpc_client.rs` derives writes/hops from canonical fields only | `tests/provider_field_precedence.rs` |
| Token-2022 classification is fail-closed | `detect_token2022_extensions`, `ExtensionScan.malformed` | `tests/token2022_extensions.rs`, `tests/l4_state_diff_gate.rs` |
| Durable-nonce transactions are refused unless verified | `tx_artifact::durable_nonce`, L2 gate | `tests/durable_nonce.rs`, `tests/durable_nonce_rpc.rs` |
| Audit records are synced to the device before the response | `AuditLog::append_line` → `sync_data` | Established by code reading — no userspace test can observe it; `durable::tests::audit_append_syncs_the_device` measures the cost (1.2 ms vs 19 µs for the no-op it replaced) and asserts nothing |
| L8 reconciliation sees the whole trail | `AuditLog::find_verification` by `audit_trail_id` / `transaction_sha256` / `content_hash`: indexed active file, archives newest-first | `durable::tests::read_path_covers_every_archive_after_rotation`, `last_verification_index_tracks_rotation_and_reopen`, `tests/round10_attribution.rs` |
| An executed blocked transaction is attributed to ITS verification, not to a same-instruction approval | `audit_execution`: `getTransaction` bytes → `bound_artifact_sha256` → digest → `find_verification(TransactionSha256)`; caller keys most-exact-first with no fallback; `caller_keys_disagree` | `tests/round10_attribution.rs` (approved A newest, blocked B executed → `BlockedButExecuted`, attribution `chain`) |
| The chain's bytes are the signature's, not merely the RPC's | `tx_artifact::bound_artifact_sha256`: first slot equals the signature; ed25519 `verify_strict` over the message under the fee payer's key; rejected bytes → `Unavailable`, `chain_bytes_rejected`, no fallback to caller keys | `tests/round10_attribution.rs::{chain_bytes_are_accepted_only_when_bound_to_the_signature, an_rpc_that_substitutes_bytes_cannot_attribute_the_execution}`; `tests/l8_live_mainnet.rs::l8_real_chain_bytes_are_bound_to_their_signature` (public devnet, ignored by default) |
| A frame the runtime would not sanitize is not a transaction | `parse_transaction`: `SignatureCountMismatch`, `ImpossibleHeader` (no writable signer), `ProgramIsFeePayer`, `AccountIndexOutOfRange` (legacy and v0), `EmptyLookup`, `TooManyAccounts` | `tests/round12_runtime_sanitize.rs`; `tests/sak_bridge_corpus.rs`; **`tools/runtime-oracle`** against agave's decoder + `sanitize` over the corpus and 600,000 generated frames, in CI (job `runtime-oracle`) |
| L8 draws no positive conclusion from one node's view, a self-contradicting RPC, or a malformed status | `rpc_client::InclusionCommitment`; `get_signature_status` strict; `ChainTransaction` slot/outcome held against the status → `chain_inconsistent` | `tests/round12_rpc_equivocation.rs::{a_processed_status_is_not_a_positive_conclusion, an_rpc_that_contradicts_itself_gets_no_positive_conclusion, a_malformed_status_is_never_a_conclusion, a_status_without_bytes_is_disclosed_as_caller_attributed}` |
| Redirects from an RPC are never followed | `SolanaRpcClient::new` → `Policy::none()` | `tests/round12_rpc_equivocation.rs::a_redirecting_rpc_is_not_followed` (the target records zero hits) |
| An approval is reported executed only when two independent RPCs agree; a blocked transaction seen by either alarms | `GraphiteCore::attach_inclusion_witness`, `compare_witness`, `ExecutionAudit.inclusion_witness` | `tests/round12_rpc_equivocation.rs::{a_positive_conclusion_needs_the_witness_to_agree, either_endpoint_seeing_a_blocked_transaction_alarms, a_witness_that_is_the_primary_is_refused}`; the probe with a mock witness |
| The RPC endpoint is validated before the process claims to simulate | `rpc_client::validate_endpoint` at server startup and in the CLI | `tests/round12_rpc_equivocation.rs::endpoints_are_validated_before_a_client_exists`; the probe's startup refusals |
| One server per data directory | `server::lock_data_dir` (`graphite.lock`, exclusive advisory lock) | `server::tests::a_data_directory_is_held_by_one_process`; the probe (a second server refuses while the first runs) |
| A lifecycle report is checked against the rows on record for its transaction | `AuditLog::lifecycle_history` (per-transaction index), `lifecycle_sequence_anomalies` | `server::tests::{lifecycle_reports_in_order_carry_no_anomaly_and_a_retry_is_a_duplicate, lifecycle_reports_out_of_sequence_are_named_and_a_second_signature_is_loud, graphite_observed_rows_are_marked_and_are_not_duplicates_of_reports, submission_onward_requires_a_real_signature}`; `durable::tests::lifecycle_history_*` |
| An L8 row attributed by `content_hash` claims no exact identity | `execution_handler` writes exact keys only for exact attributions | `server::tests::an_l8_row_attributed_by_content_hash_carries_no_exact_keys` |
| The bridge's submission report survives a lost answer | `executeBoundTransaction` retries (3 × doubling backoff); a repeat is a `duplicate` on the trail | `execution-lifecycle.test.ts` (fails once → recorded on the second try; lost answer → duplicate, counted as recorded) |
| The request path does not deep-copy state | `AppState.core: Arc<GraphiteCore>`, `registry_engine: Arc<…>` | `server::request_path_cost::{app_state_clone_is_a_reference_count_not_a_deep_copy, health_answers_in_milliseconds_on_loopback}` |
| A refusal is readable, never a reset | `refuse_after_draining` on 401 / 429 / 503 | `server::request_path_cost::early_refusals_drain_the_body_so_the_status_is_readable` |
| The API key is not guessable by length | `server::MIN_API_KEY_CHARS` = 32 in `auth_posture` | `server::tests::auth_is_required_unless_dev_mode_is_named_and_the_bind_is_loopback` |
| The SDK and the server agree on the wire | `sdk/typescript/src/live-server.test.ts` against the CI container, failing if skipped | `.github/workflows/ci.yml` container job |
| A lifecycle `verdict_on_record` is about the transaction the event names | `/audit/event` resolves by `audit_trail_id`, else `transaction_sha256`, else `content_hash`; contradicting keys → 400 | `server::tests::lifecycle_verdict_resolves_by_the_most_exact_key_and_refuses_contradiction` |
| A compressed RPC response cannot outgrow the cap | `read_body_capped` bounds decompressed chunks | `tests/round10_rpc_decompression.rs` (65 KB → 64 MiB refused in 35 ms) |
| Caller-reported lifecycle rows are bounded and carry what the trail knows | `LifecycleEventRecord::bounded`, `/audit/event` shape and length checks, `verdict_on_record` computed server-side | `durable::tests::lifecycle_event_fields_are_bounded_on_disk`, `server::tests::lifecycle_events_carry_the_verdict_on_record` |
| The bridge's signing and submission are on the trail, in order | `executeBoundTransaction`: policy → sign → record signing (abort if not recorded or not `approved` on record) → submit → record submission → confirm → L8 | `execution-lifecycle.test.ts` |
| Keyless server cannot start on a reachable address | `server::auth_posture` | `server::tests::auth_is_required_unless_dev_mode_is_named_and_the_bind_is_loopback` |
| L8 rows on the trail carry the whole reconciliation detail | `durable::MAX_LIFECYCLE_DETAIL_CHARS` (1024) at the boundary and on disk | `durable::tests::lifecycle_event_fields_are_bounded_on_disk` |

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
  accounts. That is the intended fail-closed direction — it refuses rather
  than guesses — but it means an agent working outside the manifested set
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
  on `audit_trail_id` → `transaction_sha256` → `content_hash`; the last names
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
  does establish, on every row, is `verdict_on_record` — what its own trail
  said about the hash when the report arrived — and it counts and logs a
  report against a blocked verdict as the gate being bypassed.

## Not yet done

| Item | Status | Whose decision |
|---|---|---|
| Independent third-party audit | Not performed | Owner |
| **Round 15 open findings (audit only, no code changed):** `SimulationMatch` confidence is the baseline `sample_count`, so an identical refused request becomes approved under Gaming on its second call (F-15-01, P2); a FAILED simulation with non-zero units enters the baseline and is certified "integrity clean" by L3 (F-15-02, P2); an empty caller label switches Risk Check 10 / 3b off for manifested non-native programs (F-15-03, P2, partial — the confidence floor still refuses); `approved` is not conditioned on lookup-table resolution and a deactivating table the runtime still honours is one Graphite always refuses to read (F-15-05, P2 design); verify-time `transaction_sha256` hashes raw bytes while L8 hashes zeroed slots (F-15-04, P3); the Go SDK doc pattern and `devnet-test.ts` execute without the residual policy (F-15-06, P3). See the Round 15 report | **Open** | Engineering |
| Branch protection on `main` (required CI, no force-push) | Absent; conflicts with the standing push-to-main workflow | Owner |
| **Version-1 transaction format** — **on MAINNET as of 2026-09-17**: 875 of 10,669 transactions (8.2%) across eight sampled finalized blocks, every block carrying some (`tools/mainnet-sample`). Refused by name today, so nothing fails open — but an agent building one is refused, and a client capped at `maxSupportedTransactionVersion: 0` is refused the WHOLE BLOCK (`-32015`), not just the v1 transactions in it. Must be parsed, bound and simulated | **Open — now overdue, not merely time-sensitive** | Engineering |
| Token-2022 `TransferFee` modelling | Open | Engineering |
| `content_hash` → a name that says it is an instruction-level identifier | Open (it is the 64-bit AuditBind key, not the authoritative binding) | Engineering |
| Runtime-decoder oracle over the mutation corpus | Done (Round 12: `tools/runtime-oracle`, in CI) | — |
| Coverage-guided fuzzing of `parse_transaction`; a `wincode` second oracle; the V1 message format | Open | Engineering |
| Persisted archive index for the L8 / lifecycle join | Open | Engineering |
| Shared rate limiter for a horizontally deployed Graphite (single-instance today; 452 ns/check at one million buckets) | Open | Engineering |
| Second-source inclusion check for L8 | Done for an independent RPC (Round 12: `GRAPHITE_RPC_WITNESS_URL`); light-client proof open | Engineering |

## Numbers (as of this page's commit)

1,486 Rust tests passing in the default build (11 network-dependent
ignored, all of which were run against public devnet for Round 12); 308 in
the featureless library build; 1,304 in the cli-only build; 99 TypeScript
tests in the SAK integration; 17 in the TypeScript SDK (13 hermetic, 4 against a
live server — run in the Round 12 probe and in CI's container job); 20 Go; 27
Python; 110 live-probe checks of the release binary; the runtime oracle over
the corpus, 1,659 mutations and 600,000 generated frames. Clippy `-D warnings`
and fmt clean on rustc 1.98.1. Reproduced from `cargo test` / `npm test` output
in the Round 12 report, not estimated. CI for the
commit is the GitHub Actions run for that SHA — the runs endpoint, not the
combined-status endpoint.

## Report index (newest first)

| Date | Report | What it records |
|---|---|---|
| 2026-09-20 | [round15-earned-by-asking-2026-09-20.md](round15-earned-by-asking-2026-09-20.md) | A full forensic re-audit of `21c0a7b`, report only. The exact-byte boundary and all twelve historical classes re-checked and confirmed closed. Three new confirmed defects, none an approval bypass through the reference bridge: confidence is earned by repetition — the same refused request is approved under Gaming on its second call because the `SimulationMatch` signal is the baseline sample count (F-15-01); a failed simulation with non-zero compute units is recorded as trusted evidence and certified "integrity clean" by L3 (F-15-02); an empty caller label switches the manifest risk-class hard gate off for non-native programs while the confidence floor still refuses (F-15-03). Plus the unresolved-ALT approval path and the deactivating-table discrepancy (F-15-05), two digests for one artifact (F-15-04), two in-repo executors without the residual policy (F-15-06), and three hardening items. 1 of 1 deliberate break caught; 11 missing tests named |
| 2026-09-20 | [round14-the-prefix-and-the-pin-2026-09-20.md](round14-the-prefix-and-the-pin-2026-09-20.md) | A forensic re-audit of Round 13 found that re-keying the Risk Engine on the instruction's bytes while leaving every OTHER manifest lookup on the caller's label was itself a bypass (GFX-101, HIGH): a truthful four-byte PREFIX of a discriminator switched off PDA re-derivation, the fixed-address comparison and the privilege comparison together, taking an attacker's program in Jupiter route's pinned slot from Blocked to `approved: true, artifact_bound, inherent residuals only`. Four more of the same shape: the declared-effects lookup (GFX-102), declared siblings judged on their labels (GFX-106), sibling lookup-table positions as wildcards (GFX-107), and the empty-label spelling of the first fix (GFX-108). One `effective_discriminator` now keys every manifest lookup; 5 of 5 deliberate breaks caught |
| 2026-09-17 | [round13-the-label-and-the-bytes-2026-09-17.md](round13-the-label-and-the-bytes-2026-09-17.md) | The Risk Engine judged the caller's label rather than the instruction (GFX-001, HIGH): a real SetAuthority declared `ff` was approved where the same bytes declared `06` were Blocked; the self-consistency check now runs first for every protocol and the table is keyed on the instruction's own bytes, which also closes the truthful-but-truncated variant. L4 was blind to the SPL `owner` field, so a token account changing hands produced no findings (GFX-002, MEDIUM); three authority fields now watched. AuditBind refuses a mismatched declaration by rule rather than by accident |
| 2026-09-16 | [round12-runtime-truth-2026-09-16.md](round12-runtime-truth-2026-09-16.md) | The runtime oracle (parser accepted five frame classes the runtime refuses, R12-01); L8 commitment, self-consistency, malformed statuses, redirects, the inclusion witness (R12-02…05); one server per data directory (R12-06); RPC URL validation (R12-07); lifecycle sequence findings and signature shape (R12-08…10); the bridge's submission-report retry (R12-11) |
| 2026-09-15 | [round11-full-run-2026-09-15.md](round11-full-run-2026-09-15.md) | The full run: L8 chain bytes unbound to the signature (R11-01, P1) fixed; request path deep-copying state (100 ms → 1 ms); refusals reset the connection; parser signer-count rule; 32-character keys; L8 metrics; SDK live conformance in CI |
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
