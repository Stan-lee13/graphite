# Round 9 — The Next Surface

**Ground truth at the start of the round.** HEAD `2416cb4` (documentation);
the substantive parent `0a36712` has a GitHub Actions run that completed
**success** (Actions run 34691034415). rustc 1.98.1 (CI's `stable`), Node
24.1.0, `@solana/web3.js` 1.98.4, TypeScript 5.9.3, Go 1.x per `go.mod`.
Windows 11 / NTFS for every measurement below that names a filesystem.

**Method.** Internal engineering work by Anthropic's Claude acting as this
project's engineering agent. **Not an independent third-party audit, not a
certification, not a penetration test by an external firm.** Every confirmed
finding was reproduced against running code before it was changed, with a
valid serialized Solana transaction where the finding is about one, and the
reproduction is committed as a test. Every fix was then reverted once and
the test re-run, to show the test fails without it (the deliberate-break log
at the end).

**Boundaries observed.** No credentials in source, commits, logs or this
report. No network beyond loopback mocks and read-only public APIs (GitHub
and Docker Hub metadata, for the pins in R9-08). Nothing signed, sent, or
submitted; no live user, wallet, protocol or funds touched.

**Scope.** The review of `2416cb4` named seven areas to attack next:
(A) lifecycle-event forgery and ordering, (B) whether any consumer executes
on an approved verdict with unaccepted `unobserved` residuals, (C) approval
freshness, (D) multi-tenant isolation, (E) resource exhaustion, (F)
adversarial RPC behaviour, (G) release and repository integrity. Each was
attacked; what was found is below, in severity order rather than review
order. One finding (R9-01) was not on the list.

---

## Findings

Classification: P0 = approve-A / execute-B or equivalent; P1 = a security
invariant is unenforced; P2 = a documented guarantee is weaker than its text;
P3 = operational or hygiene.

### R9-01 — An artifact without `instruction_data` was bound without being compared — **P1, fixed**

**Where.** `graphite-core/src/verification.rs`, the L2 artifact branch
(`match (&input.signed_transaction, &input.instruction_data)`).

**What.** The correspondence check that makes `artifact_bound` mean
something — "the described instruction is IN these bytes, at one position,
with these accounts and this exact data, and every sibling is declared" —
was keyed on `instruction_data` being present and at least eight bytes long.
`instruction_data` is optional on `/verify` and in every SDK type. With it
absent, or four bytes long, the branch did not run: L2 was the plain
manifest check, `scope` still said `artifact_bound` with a real
`transaction_sha256`, and the scope's own prose said L2 had established the
correspondence.

This is the 2026-09-09 amount finding — "0.002 SOL described, 0.9 SOL in
the bytes, approved" — reopened by omitting one optional field. That fix
compared the data when it was there. It did not require it to be there.

**Reproduction** (`tests/round9_identity_requires_data.rs`, mock cluster
serving a plausible three-account transfer; baseline warmed with three
honest verifications so an L2 pass would be an approval). A well-formed
legacy transaction on the corpus's own keys transferring **100 SOL** to the
described destination, submitted under the description "System transfer,
`02000000`, [payer, destination]", intent text "send 0.002 SOL", with
`instruction_data` omitted:

```
approved=true  confidence=0.64  L2=Passed  scope.kind=artifact_bound
L2: "Instruction Transfer verified against manifest"
```

L4 saw two described accounts change, which is what a transfer does. Nothing
in the pipeline held the amount, because the amount lives in the data and
the data was not supplied. The verdict binds, by SHA-256, to the 100 SOL
bytes; `signApproved` and `isArtifactBound` would have treated it as a
verdict about them.

Also reproduced: the corpus's `legacy_other_destination` (a transfer to an
account the request never names) with no data — L2 `Passed`, scope
`artifact_bound`; here L4's account-universe check still blocked the
approval, a second line that held, but a verdict whose layers contradict its
scope is not one anyone can rely on. And bytes that are not a Solana message
at all (`deadbeef` + the transfer data + padding) *with* the data: L2
`Passed` through the substring fallback, `approved=true` through the mock
cluster — see R9-02.

**Reachability in practice.** The SAK bridge always sends the data (AuditBind
requires it), so the reference integration was not exposed. Any integration
using the HTTP API or an SDK directly, omitting an optional field, was. A
real cluster would refuse to simulate the `deadbeef` case; it would simulate
the 100 SOL case without complaint.

**Fix.** The L2 artifact branch now runs for every non-empty artifact.
`instruction_data` absent → L2 `Failed` ("a transaction was supplied but
instruction_data was not, so the described instruction cannot be located in
it"). The eight-byte minimum is gone: `correspond` matches on exact data
equality at one position under the described program and accounts, so a
one-byte `CloseAccount` is identified as precisely as a 12-byte transfer, and
a four-byte prefix of a 12-byte instruction matches nothing. The scope
carries a new residual code, `instruction_not_located`, whenever L2 did not
locate the instruction, so `artifact_bound` never again reads as a claim L2
did not make. Six tests in the new file; `tests/artifact_binding.rs`
rewritten from the substring model to the parsed one (a prefix does not
locate; a message without data fails; unreadable bytes fail whatever they
contain).

### R9-02 — An unparseable artifact took a weaker L2 path — **P1 (documented limitation closed), fixed**

**Where.** Same branch. Round 8 recorded this as a documented limitation:
"cannot reach `approved` under any built-in profile (L3 stays Inconclusive
→ confidence ≤ 0.44)". That argument assumed no RPC. With an RPC attached
the simulation runs on whatever bytes were supplied, and the reproduction
above shows `approved=true, 0.64` for bytes that are not a message, through
a mock that simulated them. A real cluster refuses to deserialize such
bytes, so the practical requirement was "bytes the runtime decodes and
Graphite's parser refuses" — measured at zero across 1,641 mutations and
never proven impossible. The substring fallback also made L2 `Passed` on an
artifact of 150,000 instructions whose count overflowed compact-u16 (the
parser refused it; the fallback found the data bytes; see R9-04).

**Fix.** Parse failure is an L2 failure with the parser's error in the
reason. The substring search (`artifact_contains_instruction_data`) and its
constant are deleted; nothing calls them. The scope names
`artifact_unparsed`, `account_identity_unparsed` and
`instruction_not_located`. The Round 8 limitation entry is withdrawn.

### R9-03 — `unobserved` was prose, and the bridge executed on any of it — **P1 (product gap), closed**

**Where.** `integrations/solana-agent-kit/graphite-sak-bridge.ts`
(`reportVerificationScope`, `signSubmitAndConfirm`); every SDK.

**What.** The review's biggest remaining concern, confirmed by tracing every
consumer: the bridge gated on `approved` and `artifact_bound`, printed each
`unobserved` line with `console.warn`, and signed. The TypeScript SDK's
`unobserved()` returned strings; the Go SDK's `Unobserved()` returned
strings; nothing could *decide* on them because there was nothing stable to
decide on. "Surfaced, not gated" was accurate and was the gap.

**Fix, core.** `UnobservedCode` (`verification.rs`): fourteen snake_case
codes, `unobserved_codes[i]` naming `unobserved[i]` — built through one
`Residuals::push(code, prose)` so the two lists cannot drift. Two codes are
`inherent()` to every artifact-bound verdict (`program_semantics`,
`inner_instructions`: what programs without manifests do beyond simulated
effects, and CPI callees visible only through simulation); the other twelve
name an observation that was possible and did not happen. The schema
(`schemas/verification-result-v1.json`) requires the field on both branches,
and `tests/scope_schema_contract.rs` pins its enum to `UnobservedCode::ALL`
in both directions and to the serde names.

**Fix, bridge.** `residual-policy.ts`: `ResidualPolicy` refuses execution on
any code that is neither inherent nor explicitly accepted by the operator —
`GRAPHITE_ACCEPT_UNOBSERVED=code,code` or
`VerifiedSakAgent.create({ acceptUnobserved })` — and validates the accepted
list at construction (a typo is a startup error, not a silent no-op). A
server that reports no codes is refused ("prose is not a decision"); a
length mismatch between codes and prose is refused; a code the bridge does
not know is refused under any policy. The decision runs *before* signing and
the accepted codes are recorded on the execution outcome (P14).
`execution-lifecycle.ts` is the only path from verdict to network and calls
the policy first. Twelve tests in `residual-policy.test.ts`; every
non-inherent code is checked to refuse by default.

**SDKs.** TypeScript: `UnobservedCode`, `UNOBSERVED_CODES`,
`INHERENT_UNOBSERVED`, `unobservedCodes(result)` (undefined, not empty, for
an old server). Go: the fourteen constants, `IsInherentUnobserved`,
`(*VerificationResult).NonInherentUnobserved() (codes, ok)` with `ok ==
false` for a server that reported none.

### R9-04 — The artifact and the declaration list had no bound — **P2, fixed**

**Where.** `verification.rs` entry caps; `tx_artifact.rs`; `artifact.ts`.

**What.** Every `/verify` input was bounded — 256 accounts, 64 KiB of
instruction data, 44-character identifiers, 32 CPI targets — except the two
Round 3 introduced: `signed_transaction` and `transaction_instructions`.
Sibling coverage compares every artifact instruction against every
declaration (O(n·m), one hex allocation per pair); the parser allocates per
instruction; the 1 MiB body limit leaves room for hundreds of thousands of
three-byte instructions.

**Measured** (`tests/round9_resource_bounds.rs`, test profile, this
machine) before the bound, through `GraphiteCore::verify`:

```
 40 KB artifact,  10,000 siblings,   500 declarations:   6.5 s
200 KB artifact,  50,000 siblings, 2,000 declarations: 122.3 s   (one request; REQUEST_TIMEOUT is 10 s)
600 KB artifact, 150,000 siblings, 4,000 declarations:  73 ms, L2=Passed  (count overflowed compact-u16 → unparseable → substring fallback; R9-02)
```

The 122-second case is a CPU-bound section inside an async handler: the
timeout layer drops the future at the next `await`, and there is none inside
L2, so one authenticated request pinned a worker thread for two minutes.
Thirty-two of them (the concurrency limit) pin the server.

**Fix.** The runtime settles the bound: `PACKET_DATA_SIZE` = 1280 − 40 − 8 =
**1232 bytes**, and `sendTransaction` refuses anything larger, so bytes past
it describe a transaction that can never execute. `MAX_TRANSACTION_BYTES`
in `tx_artifact.rs`, checked in `parse_transaction` and `message_bytes`
before a byte is read (`ArtifactParseError::TooLarge`), and at the `/verify`
entry point as `InvalidInput` (400); `MAX_TRANSACTION_INSTRUCTIONS` = 256
for the declaration list (a packet holds at most ~400 three-byte
instructions; a real transaction holds a handful). The same bound in
TypeScript's `messageOf`, with the compact-u16 reader factored out as
`readSignatureCount` so its acceptance language is still tested at counts
no packet holds. The corpus gained a `pad` mutation to exactly 1232 and
1233 bytes on each base: **1,647 mutations, prefix agreement 1,647/1,647,
Graphite looser than web3.js 0, stricter 51** (the 6 new ones are
"larger than a packet" ×3 and "trailing bytes" ×3 on the 1232-byte pads).

After: the 600 KB request is refused in **1.6 ms**; the worst case that
fits — a 1232-byte artifact of 254 siblings against 256 unmatched
declarations — completes in **27 ms**.

### R9-05 — `/audit/event` fields were unbounded on the way to disk — **P2, fixed**

**Where.** `durable.rs::append_lifecycle`; `server.rs::lifecycle_event_handler`.

**What.** The 2026-09-06 fix bounded `AuditErrorRecord` (`bounded()`) and
the `/verify` identifiers after a 100,000-character `program_id` was echoed
into the trail. `LifecycleEventRecord` was added after that fix and was not
covered: `content_hash`, `audit_trail_id`, `transaction_signature`,
`reported_by` and `detail` were written verbatim. One request under the
1 MiB body limit put ~1 MiB of chosen bytes on the audit volume; 64 forced a
rotation; with `GRAPHITE_AUDIT_MAX_ARCHIVES` set, a rotation prunes the
oldest archive of real verifications. Authenticated, so P2 rather than P1 —
but the trail is the one file the system must not lose, and the API key is
held by the same integration a prompt-injected agent drives.

**Fix.** Two layers. At the boundary (`server.rs`): `content_hash` must be
16 lowercase hex characters (the shape `hex::encode(&hash[..8])` produces);
`transaction_signature` ≤ 90; `audit_trail_id` and `reported_by` ≤ 128;
`detail` ≤ 1024; rejections report lengths, never values; the same shape
check now applies to `content_hash` and `reported_by` on
`/verify/execution`. Beneath it (`durable.rs`): `LifecycleEventRecord::
bounded()` truncates every caller-supplied field to 256 characters with the
truncation recorded, exactly as the error record does, so no future handler
can reopen the path. `durable::tests::lifecycle_event_fields_are_bounded_on_disk`
(five 1 MiB fields → under 5 KB on disk) and
`server::tests::lifecycle_event_fields_are_bounded_at_the_boundary` (each
oversize field → 400; malformed hashes → 400; nothing written).

### R9-06 — Lifecycle events carried no server-established fact — **P2, fixed**

**Where.** `durable.rs`, `server.rs`, `/metrics`.

**What.** Round 8 established that a lifecycle row can never read as a
verdict (still true: `scan_file` and `build_active_index` parse
`AuditRecord` only). What it could not do was say anything about the row
beyond "the caller said so". A `signing` reported for a hash Graphite had
BLOCKED, and a `signing` for a hash Graphite had never seen, were recorded
identically to a signing of an approval, and the only way to learn the
difference was to run L8 later, by hand, with a signature.

**Fix.** `VerdictOnRecord { Approved, Blocked, NotFound }`, computed by the
server from `last_verification_for(content_hash)` at the moment the event is
recorded — never reported by the caller — written on the row
(`verdict_on_record`), returned in the response, and counted:
`graphite_lifecycle_events_on_blocked_total` (page on it: the caller has
just reported acting on a transaction Graphite refused, and it is logged as
loudly as an L8 discrepancy) and `graphite_lifecycle_events_unverified_total`.
The event is still recorded either way — the trail records what was
reported — but the row now carries the one fact Graphite can establish.
`server::tests::lifecycle_events_carry_the_verdict_on_record` (approved,
blocked, re-verified-then-blocked, never verified; counters; the four
verification rows untouched).

### R9-07 — The bridge never told Graphite it had signed or submitted — **P2, fixed**

**Where.** `graphite-sak-bridge.ts`; new `execution-lifecycle.ts`; SDK
client.

**What.** The reference integration — the component that actually performs
signing and submission — made no call to `POST /audit/event` and no call to
`POST /verify/execution`. The trail held verifications and nothing after
them for every bridge execution; L8 ran only when an operator ran it. P9
asks for the whole lifecycle; the party that performs a stage is the only
one that can put it on the trail. (A stale comment on the transfer path
still said the artifact gate was "reported rather than enforced here",
contradicting `signSubmitAndConfirm` two calls below it.)

**Fix.** `executeBoundTransaction` is now the only path from verdict to
network, in this order: residual policy → `signApproved` → record `signing`
→ submit → record `submission` → confirm → L8 `verifyExecution`. The
ordering rule: no irreversible step proceeds unless the step before it is
on the trail. A signing that cannot be recorded aborts before submission
(the bytes exist only in the process; refusing is free); a `signing`
receipt whose `verdict_on_record` is not `approved` aborts (the approval in
hand is not the approval on record); after submission every failure is
reported on the `ExecutionLifecycle` and none is hidden; L8 runs whether or
not confirmation completed. The opt-out swap path records its submission as
what it is — `UNVERIFIED`, with the opt-in phrase in `detail`. The SDK client
gained `recordLifecycleEvent` (resolves only on `recorded: true`) and
`verifyExecution`. `ExecutionOutcome.lifecycle` carries all of it. Eleven
tests in `execution-lifecycle.test.ts` against fakes that record call
order.

### R9-08 — Repository and release integrity — **P3, fixed** (review area G)

**What.** The workflow had no `permissions:` block (the token held whatever
the repository default grants), every action was pinned to a mutable tag
(`actions/checkout@v4`, `dtolnay/rust-toolchain@stable` — a branch), and the
container's base images were pinned to mutable tags.

**Fix.** `permissions: contents: read` at workflow level (no job writes
anything). Every `uses:` pinned to a full commit SHA with the version it
resolves to in a comment — resolved through the GitHub refs API, annotated
tags dereferenced (`Swatinem/rust-cache@v2` → `v2.9.2` →
`6323deb1…`); `dtolnay/rust-toolchain` pinned to a `stable`-branch commit
with `toolchain: stable` made explicit, since the action used to read the
toolchain from the ref name. `Dockerfile` base images pinned by manifest
digest, the tag kept beside it; both digests read from Docker Hub and
verified against the registry's `Docker-Content-Digest` for the same tags.
`cargo audit --deny warnings` was already in CI. Branch protection remains
an owner decision (see Not-yet-done).

### R9-09 — Pre-state and simulation slots were not compared — **P3, fixed** (review area F)

**What.** The state diff is two RPC calls — `simulateTransaction`, then
`getMultipleAccounts` for the pre-state — and neither's `context.slot` was
read. A diff spanning two slots attributes every change other transactions
made in between to this one. Not exploitable for approval (the skew can only
*add* changes the manifest then has to explain, and hiding a real effect
would require its exact inverse, deposited by the attacker at their own
expense), but a reader of the L4 detail could not tell a one-slot skew from
a measurement of this transaction alone.

**Fix.** `SimulationResult.slot` and `get_multiple_accounts_at` capture the
slots; when they differ and a diff was built, the L4 reason ends with the
two slot numbers and the gap. `tests/round9_snapshot_slots.rs` (skewed
cluster → note present; same slot → absent).

### R9-10 — `last_verification_for` scanned the whole active file — **P3, fixed** (review area E)

**What.** Every `/verify/execution` — and, after R9-06, every `/audit/event`
— parsed every line of the active file as JSON. Measured on a 64 MB active
file (the rotation threshold): **953 ms per lookup**, caller-driven, under a
30 rps per-IP rate limit and a 32-request concurrency limit. A miss (a hash
with no verification on record) is the case a caller can force at will.

**Fix.** An in-memory index `content_hash → offset of the last verification
line`, built by one scan at open (808 ms for 64 MB, once), maintained on
every append under the file lock, cleared on rotation; a lookup is a seek
and one line. Archives are still scanned newest-first on an active-file
miss (they are immutable and the case is rare: a hash verified before the
last rotation, or one that never existed). Measured after: **hit 0.5 ms,
miss 1.1 ms**. `durable::tests::last_verification_scans_a_full_active_file`
(both numbers), `last_verification_index_tracks_rotation_and_reopen`, and
`last_verification_index_never_answers_from_a_broken_entry`: the index is
built from bytes (one invalid-UTF-8 line skips one line rather than ending
the scan and leaving every later hash "not on record"), and an entry whose
line does not read back falls back to a full scan of the active file rather
than answering from a broken index.

---

## NOT A FINDING

- **Lifecycle events as forged verdicts (area A).** Unchanged from Round 8
  and re-verified after R9-05/06: a lifecycle row is `LifecycleEventRecord`,
  serialized from a fixed struct (a `detail` containing verdict-shaped JSON
  is a JSON string, not fields); `scan_file`, `build_active_index` and
  `last_verification_for` parse `AuditRecord` only. Self-observed types are
  rejected at the endpoint. `lifecycle_events_carry_the_verdict_on_record`
  writes four events and re-reads four verifications with two approvals.
- **Event reordering, caller-controlled timestamps, duplicate event ids
  (area A).** The timestamp on every lifecycle row is
  `now_utc_rfc3339()` on the server; the body has no timestamp field to
  supply. Receipt order is file order under one append lock. There are no
  event ids to duplicate — the row is the identity. A caller can report
  `confirmed` before `signed`; both rows say when Graphite received them,
  and the reconciliation that matters (L8) joins the signature to the
  verification row, not to the caller's sequence.
- **Same signature attached to multiple verdicts (area A).** An attestation
  can say anything; `/verify/execution` reconciles the signature against
  the verification on record for the `content_hash` it was called with,
  and `verdict_on_record` now says on each row what that record was.
- **Duplicate submission / retry (area C).** A signed transaction's identity
  on-chain is its signature; resubmitting the same bytes is idempotent. A
  rebuilt transaction (new blockhash) is a new digest and fails
  `signApproved` against the old approval — unchanged since Round 6, and
  `executeBoundTransaction` has one `sendRawTransaction` call and no retry.
- **Blockhash freshness (area C).** A legacy transaction is bounded by its
  blockhash (~150 slots); the bridge confirms against the
  `lastValidBlockHeight` it was built with and refuses to build durable-nonce
  transactions (Round 8). A verdict signed after expiry cannot land; a
  verdict signed inside the window executes against state up to a minute
  newer than what was simulated, which is the inherent shape of every
  pre-signature check and is stated under limitations.
- **RPC result misalignment (area F).** `get_multiple_accounts` and
  `simulate_transaction_with_accounts` already refuse a response whose entry
  count differs from the request's; response size is capped
  (`MAX_RPC_RESPONSE_BYTES`); provider-supplied fields cannot displace
  canonical ones (Round 7).
- **Multi-tenant isolation (area D).** Graphite has one API key, one wallet
  profile pin, one audit trail and one semantic graph per process; it is
  single-tenant by construction and no document claims otherwise. Tenant
  isolation is process isolation. Recorded as a limitation, not a finding.

## DOCUMENTED LIMITATIONS

- **Pre-signature verification has a window.** Between verification and
  execution the chain moves; nothing signed in advance can be verified
  against the state it will execute in. The blockhash bounds the window to
  about a minute for ordinary transactions; a permitted durable nonce
  removes the bound (Round 8, opt-in).
- **Single-tenant.** One key, one policy, one trail per process (above).
- **A permitted residual is the operator's decision.** `ResidualPolicy`
  refuses everything non-inherent by default; an operator who accepts
  `no_state_diff` or `lookup_tables_unresolved` has decided to execute
  without that observation, and the outcome records it. The bridge does not
  second-guess configuration (P1: the policy is not a judgement call at
  execution time).
- **Archive lookups are scans.** R9-10 indexes the active file only; a
  content hash older than the last rotation costs one pass over each
  archive, newest first. A persisted archive index remains open.
- **An authenticated client can still grow the trail.** Every row is now
  bounded (≤ ~2 KB for a lifecycle row, ~500 B for a verification), so the
  growth rate is the per-IP rate limit times the row bound: on the order of
  200 MB per hour from one hostile key at 30 rps. That is the append-only
  guarantee (P9) meeting finite disk; `GRAPHITE_AUDIT_MAX_ARCHIVES` is the
  operator's lever, and choosing it is choosing which rows to lose.
- **`fdatasync` proves the device acknowledged, not the platter.**
  Unchanged.
- **Token-2022 `TransferFee` is refused, not modelled.** Unchanged.

## COVERAGE GAPS (open)

- **Graphite's parser vs the runtime's decoder.** Still argued from the
  runtime's documented rules; a Rust-SDK-backed oracle over the 1,647
  mutations would close it.
- **Continuous fuzzing.** The corpus is fixed; there is no long-running
  mutation campaign (AFL/libFuzzer) over `parse_transaction`. The 1232-byte
  bound makes the input space small enough that one is cheap to run.
- **The container smoke job is the only place the digest-pinned base images
  are exercised.** Docker Desktop was not running on this machine; the
  digests were verified against the registry, and then by CI's container
  job on `a56c7e8` (success).

---

## Regression audit of this round's own changes

- **Behaviour change, deliberate:** an artifact supplied without
  `instruction_data` now fails L2 instead of passing it. Six in-repo tests
  supplied `[1, 2, 3, 4]` as an artifact with no data
  (`alt_measured_not_declared`, `artifact_coverage`, `evading_the_fixes`,
  `rpc_budget`, `rpc_influence_bounds`, `rpc_trust_boundary`); all still
  pass because none asserted L2 or `approved` on that input. Their
  artifacts are still not real transactions; that is a coverage-quality
  note, not a defect.
- **Behaviour change, deliberate:** `messageOf` and `parse_transaction`
  refuse inputs over 1232 bytes. Two TypeScript tests that exercised the
  compact-u16 reader with 128–16,384 signature slots (8 KB–1 MB frames) now
  assert the size refusal on `messageOf` and the decoding on
  `readSignatureCount`; the sweep of 36,864 prefixes over a 200-byte body is
  unaffected.
- **Wire change, additive:** `unobserved_codes` on both scope branches
  (schema `required`; `#[serde(default)]` on the Rust side so recorded
  results without it still deserialize); `verdict_on_record` on lifecycle
  rows (`skip_serializing_if` None; old rows read back with `None`).
- **Deployment change:** a bridge against a pre-Round-9 server refuses to
  execute ("prose only"). The bridge and server ship from one repository.
- **`content_hash` shape enforced on `/audit/event` and
  `/verify/execution`.** One in-repo test used `"abc123"` and was updated;
  no SDK or bridge code sent anything but the 16-hex form.

## Evidence

Exact commands, this HEAD:

```
cargo fmt --all -- --check                                  clean
cargo clippy --all-targets --all-features -- -D warnings    clean (rustc 1.98.1)
cargo test --release                                        1,444 passed, 0 failed, 10 ignored
cargo test --release --no-default-features --lib            305 passed, 0 failed, 1 ignored
cargo test --release --no-default-features --features cli   1,293 passed, 0 failed, 1 ignored
npm test  (integrations/solana-agent-kit)                   95 passed, 0 failed
npm run check + npm test  (sdk/typescript)                  checked, built; 13 passed, 4 skipped (live-server), 0 failed
gofmt / go vet / go test  (sdk/go)                          clean; ok
npm run emit:corpus, twice                                  identical sha256 f5d8259c… (deterministic; CI diffs it)
cross-language mutations                                    1,647; prefix agreement 1,647/1,647;
                                                            Graphite-looser-than-SDK 0; Graphite-stricter 51
```

Measurements quoted above, all from `--nocapture` output on this machine:
122.3 s / 6.5 s / 73 ms before the artifact bound; 1.6 ms / 27 ms after;
953 ms full-scan lookup vs 0.5 ms hit / 1.1 ms miss indexed, 808 ms index
build, over a 64 MB active file.

Test count movement: 1,422 → 1,444 Rust (+22: 6 identity-requires-data, 5
resource bounds, 2 snapshot slots, 4 durable.rs, 2 server.rs, 1 schema
contract, +2 net in `artifact_binding.rs` where four substring-model tests
became six parsed-model ones); featureless core 301 → 305; cli-only 1,281 →
1,293; TypeScript SAK 73 → 95 (+12 residual policy, +11 execution lifecycle,
−1 folded); Go +1; Python 27 unchanged. Ten ignored tests are the same ten
network-dependent ones as before.

Live probes against the release binary on loopback (`GRAPHITE_DEV_MODE=1`,
no key, no RPC): an artifact without `instruction_data` → 200, `approved:
false`, L2 failed naming the field, `unobserved_codes` = `[not_simulated,
instruction_not_located, program_semantics, inner_instructions]`; a
1,515-byte artifact → 400 naming 1232; a 1 MiB `detail` → 400, trail grew by
0 bytes; a `signing` against that blocked hash → `verdict_on_record:
"blocked"`, `graphite_lifecycle_events_on_blocked_total 1`; a never-verified
hash → `not_found`, `…_unverified_total 1`; `abc123` and uppercase hex → 400
on both `/audit/event` and `/verify/execution`; the trail holds the two
lifecycle rows with their verdicts and the verification rows untouched

Deliberate-break log, each fix reverted alone and the tree restored after:
(1) the "no `instruction_data`" L2 arm disabled → caught by
`an_artifact_without_identifying_data_fails_l2…` (reason string); the
100 SOL reproduction **still refused** under that break, because the
fallback `correspond(Some(&[]))` matches no 12-byte instruction — the
explicit arm exists to name the missing field rather than to be the only
thing standing, and this is recorded as defence in depth, not as a vacuous
test. (2) parse failure passed through → caught by 1. (3) artifact entry
cap removed → caught by 1. (4) lifecycle `bounded()` bypassed → caught by
1. (5) index not updated on append → caught by 1. (6) `verdict_on_record`
forced to `approved` → caught by 1. (7) slot skew never captured → caught
by 1. (8) `/audit/event` length caps disabled → caught by 1. TypeScript:
(9) `ResidualPolicy` accepting everything → caught by 3; (10) submission
moved ahead of the signing record → caught by 4. `git status` clean on
`src/` after each; fmt and clippy re-run green.

CI for `a56c7e8`, the commit carrying this round: **completed success**,
all seven jobs — Rust core (fmt, clippy, tests, both feature-matrix legs),
container build + live smoke (the only check that exercises the
digest-pinned base images, which Docker Desktop could not build locally),
TypeScript SDK + SAK integration including the corpus drift check, Go,
Python, dashboard, dependency CVE audit. Actions run `34720050898`, read
from the runs endpoint for the full SHA.

---

## Verdict

```
Graphite Security Status:       CONDITIONAL — security-hardened alpha
Final Transaction Identity:     PASS — and now requires the data that locates the instruction (R9-01)
Unparseable Artifact:           L2 FAILS (R9-02); the Round 8 limitation is withdrawn
Residual Policy at Execution:   ENFORCED — non-inherent residuals refuse unless accepted by code (R9-03)
Resource Bounds:                PASS — 1232-byte packet bound, 256 declarations, bounded lifecycle rows, indexed L8 join
Lifecycle on the Trail:         RECORDED — signing before submission, submission after, L8 at the end (R9-07)
Repository Integrity:           token read-only; actions and base images pinned by SHA/digest (R9-08)
CI Certification:               CERTIFIED — a56c7e8 completed success, all seven jobs (Actions run 34720050898)

P0: none
P1: R9-01, R9-02, R9-03 (fixed / closed)
P2: R9-04, R9-05, R9-06, R9-07 (fixed)
P3: R9-08, R9-09, R9-10 (fixed)
NOT A FINDING: lifecycle forgery/ordering, duplicate submission, blockhash freshness, RPC alignment, tenancy
COVERAGE GAP: runtime oracle, continuous fuzzing, local container build (open)
```

**What stays outside the guarantee.** No independent party has attempted to
break Graphite; `main` has no branch protection, so the CI that certifies
each commit is advisory until the owner makes it mandatory; a compromised
process, a lying storage device, a lying RPC, and a residual the operator
chose to accept are each outside what the code can enforce and are stated as
such. R9-01 is a reminder of the shape every finding in this codebase has
taken: a property the pipeline could check, keyed on a field the caller
could omit. The fix in each case is the same — the check runs, or the verdict
says it did not.
