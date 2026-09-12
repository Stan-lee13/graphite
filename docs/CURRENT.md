# Graphite — Current Status

**This is the one document that describes the codebase as it is now.** Every
other file in `docs/` is a dated record of what was true when it was written;
each carries a banner pointing here. When this file and a report disagree,
this file is current and the report is history.

Updated: 2026-09-12, after Round 9 (see `git log -1 -- docs/CURRENT.md`).
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
Durable-nonce transactions:      refused at L2 by default; opt-in requires on-chain nonce verification
Token-2022 extensions:           classified, not modelled — semantics/authority/unknown/unreadable all block
Input bounds:                    artifact ≤ 1232 bytes (PACKET_DATA_SIZE), ≤ 256 declared siblings, every
                                 audit-trail field bounded on the way to disk
Audit trail durability:          fdatasync per record; whole-trail reads across rotated archives; indexed L8 join
Lifecycle on the trail:          the bridge records signing before submission and submission after it, and runs
                                 L8 at the end; every lifecycle row carries verdict_on_record
Server authentication:           required by default; GRAPHITE_DEV_MODE=1 permits keyless on loopback only
Repository integrity:            CI token read-only; actions pinned by commit SHA; base images pinned by digest
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
| Wire-format bounds on both sides | `compact_u16` (Rust), `messageOf` / `readSignatureCount` (TS) | `tests/wire_format_bounds.rs`; 1,647-mutation cross-language corpus in `tests/sak_bridge_corpus.rs` |
| Provider fields cannot override canonical evidence | `rpc_client.rs` derives writes/hops from canonical fields only | `tests/provider_field_precedence.rs` |
| Token-2022 classification is fail-closed | `detect_token2022_extensions`, `ExtensionScan.malformed` | `tests/token2022_extensions.rs`, `tests/l4_state_diff_gate.rs` |
| Durable-nonce transactions are refused unless verified | `tx_artifact::durable_nonce`, L2 gate | `tests/durable_nonce.rs`, `tests/durable_nonce_rpc.rs` |
| Audit records are synced to the device before the response | `AuditLog::append_line` → `sync_data` | Established by code reading — no userspace test can observe it; `durable::tests::audit_append_syncs_the_device` measures the cost (1.2 ms vs 19 µs for the no-op it replaced) and asserts nothing |
| L8 reconciliation sees the whole trail | `AuditLog::last_verification_for`: indexed active file, archives newest-first | `durable::tests::read_path_covers_every_archive_after_rotation`, `last_verification_index_tracks_rotation_and_reopen` |
| Caller-reported lifecycle rows are bounded and carry what the trail knows | `LifecycleEventRecord::bounded`, `/audit/event` shape and length checks, `verdict_on_record` computed server-side | `durable::tests::lifecycle_event_fields_are_bounded_on_disk`, `server::tests::lifecycle_events_carry_the_verdict_on_record` |
| The bridge's signing and submission are on the trail, in order | `executeBoundTransaction`: policy → sign → record signing (abort if not recorded or not `approved` on record) → submit → record submission → confirm → L8 | `execution-lifecycle.test.ts` |
| Keyless server cannot start on a reachable address | `server::auth_posture` | `server::tests::auth_is_required_unless_dev_mode_is_named_and_the_bind_is_loopback` |

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
- **Single-tenant.** One API key, one profile pin, one trail, one semantic
  graph per process. Tenant isolation is process isolation.
- **Archive lookups are scans.** The L8 / lifecycle join is indexed for the
  active file; a hash older than the last rotation costs one pass over each
  archive.
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
| Branch protection on `main` (required CI, no force-push) | Absent; conflicts with the standing push-to-main workflow | Owner |
| Token-2022 `TransferFee` modelling | Open | Engineering |
| `content_hash` → a name that says it is an instruction-level identifier | Open (it is the 64-bit AuditBind key, not the authoritative binding) | Engineering |
| Runtime-decoder oracle over the mutation corpus; continuous fuzzing of `parse_transaction` | Open | Engineering |
| Persisted archive index for the L8 / lifecycle join | Open | Engineering |

## Numbers (as of this page's commit)

1,444 Rust tests passing (1,454 total; 10 network-dependent ignored); 305 in
the featureless library build; 1,293 in the cli-only build; 95 TypeScript
tests in the SAK integration; 13 in the TypeScript SDK (4 live-server tests
skip without a server); 27 Python. Clippy `-D warnings` and fmt clean on
rustc 1.98.1. Reproduced from `cargo test` / `npm test` output in the Round 9
report, not estimated. CI for the
commit is the GitHub Actions run for that SHA — the runs endpoint, not the
combined-status endpoint.

## Report index (newest first)

| Date | Report | What it records |
|---|---|---|
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
