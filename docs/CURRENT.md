# Graphite — Current Status

**This is the one document that describes the codebase as it is now.** Every
other file in `docs/` is a dated record of what was true when it was written;
each carries a banner pointing here. When this file and a report disagree,
this file is current and the report is history.

Updated: 2026-09-12, for the commit that introduced it (see `git log -1 --
docs/CURRENT.md`). If that commit is not HEAD, later commits may have moved
things; `git log --oneline -- docs/CURRENT.md` shows when this page last
changed.

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
Exact transaction identity:      enforced (artifact_bound scope, transaction_sha256, message-equality at signing)
ALT / v0 account identity:       enforced (runtime numbering rebuilt; all-or-nothing resolution; owner checked)
Privilege source:                the transaction's header / tables, never the caller's description
Durable-nonce transactions:      refused at L2 by default; opt-in requires on-chain nonce verification
Token-2022 extensions:           classified, not modelled — semantics/authority/unknown/unreadable all block
Audit trail durability:          fdatasync per record; whole-trail reads across rotated archives
Server authentication:           required by default; GRAPHITE_DEV_MODE=1 permits keyless on loopback only
Independent third-party audit:   NOT PERFORMED — every campaign report is internal engineering work
Branch protection on main:       ABSENT — an owner decision; see "Not yet done"
```

"Conditional" means: no known way to turn a blocked verdict into an executed
transaction under the stated threat model, and no external party has yet tried.

## What is enforced (and where the test lives)

| Property | Enforced by | Reproduction |
|---|---|---|
| The signed message is the verified message | `BoundTransaction.signApproved` (TS): digest re-check, signer set derived from the compiled message, message-slice equality | `integrations/solana-agent-kit/bound-transaction.test.ts`, `execution-boundary-fuzz.test.ts` |
| A descriptive verdict never reaches execution | bridge requires `scope.kind === "artifact_bound"` | `toctou-signing-boundary.test.ts` |
| Instruction identity is positional and complete | `compare_instruction_accounts`, `sibling_coverage` | `tests/instruction_account_identity.rs`, `tests/described_siblings.rs` |
| ALT accounts are identified, not counted | `runtime_account_list`, `resolve_lookups`, owner check | `tests/alt_real_v0.rs` (3 real mainnet v0 txs, `meta.loadedAddresses` ground truth), `tests/alt_privilege.rs` |
| Privileges come from the bytes | `privileges_from_artifact` | `tests/privilege_from_artifact.rs` |
| Wire-format bounds on both sides | `compact_u16` (Rust), `messageOf` (TS) | `tests/wire_format_bounds.rs`; 1,641-mutation cross-language corpus in `tests/sak_bridge_corpus.rs` |
| Provider fields cannot override canonical evidence | `rpc_client.rs` derives writes/hops from canonical fields only | `tests/provider_field_precedence.rs` |
| Token-2022 classification is fail-closed | `detect_token2022_extensions`, `ExtensionScan.malformed` | `tests/token2022_extensions.rs`, `tests/l4_state_diff_gate.rs` |
| Durable-nonce transactions are refused unless verified | `tx_artifact::durable_nonce`, L2 gate | `tests/durable_nonce.rs`, `tests/durable_nonce_rpc.rs` |
| Audit records are synced to the device before the response | `AuditLog::append_line` → `sync_data` | Established by code reading — no userspace test can observe it; `durable::tests::audit_append_syncs_the_device` measures the cost (1.2 ms vs 19 µs for the no-op it replaced) and asserts nothing |
| L8 reconciliation sees the whole trail | `AuditLog::last_verification_for` across archives | `durable::tests::read_path_covers_every_archive_after_rotation` |
| Keyless server cannot start on a reachable address | `server::auth_posture` | `server::tests::auth_is_required_unless_dev_mode_is_named_and_the_bind_is_loopback` |

## What is NOT enforced (documented limitations)

- **Token-2022 `TransferFee` is refused, not modelled.** Fee-bearing mints
  block. Modelling the fee is the path to accepting them.
- **`unobserved` is surfaced, not gated.** Every `artifact_bound` verdict
  carries a non-empty residual by design; which residuals a deployment accepts
  is a deployment decision. The bridge prints them and does not decide.
- **A compromised process is out of scope.** Deep copies, private fields and
  digest checks defend against callers and plugins that behave like
  JavaScript; not against code that rewrites the bridge module.
- **Without RPC, L3 is Inconclusive** and confidence is capped below every
  built-in profile's threshold; `approved` is unreachable. This is the intended
  fail-closed shape, not a degraded mode.
- **Lifecycle events reported by callers are attestations.** `POST
  /audit/event` records what the caller said with `reported_by`; Graphite
  cannot witness a signing it did not perform and does not claim to.

## Not yet done

| Item | Status | Whose decision |
|---|---|---|
| Independent third-party audit | Not performed | Owner |
| Branch protection on `main` (required CI, no force-push) | Absent; conflicts with the standing push-to-main workflow | Owner |
| Token-2022 `TransferFee` modelling | Open | Engineering |
| `content_hash` → a name that says it is an instruction-level identifier | Open (it is the 64-bit AuditBind key, not the authoritative binding) | Engineering |

## Numbers (as of this page's commit)

1,422 Rust tests passing (1,432 total; 10 network-dependent ignored); 301 in
the featureless library build; 1,281 in the cli-only build; 73 TypeScript
tests in the SAK integration; 13 in the TypeScript SDK (4 live-server tests
skip without a server); 27 Python. Clippy `-D warnings` and fmt clean on
rustc 1.98.1. Reproduced from `cargo test` / `npm test` output in the Round 8
report, not estimated. CI for the
commit is the GitHub Actions run for that SHA — the runs endpoint, not the
combined-status endpoint.

## Report index (newest first)

| Date | Report | What it records |
|---|---|---|
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
