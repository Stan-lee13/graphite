# Round 8 — Attacking the Remaining Assumptions

**Ground truth at the start of the round.** HEAD `7f414e5`; the substantive
parent `1830e7b` has a GitHub Actions run that completed **success** (Actions
API). rustc 1.98.1 (CI's `stable`), Node 24.1.0, `@solana/web3.js` 1.98.4,
TypeScript 5.9.3. Windows 11 / NTFS for every measurement below that names a
filesystem.

**Method.** Internal engineering work by Anthropic's Claude acting as this
project's engineering agent. **Not an independent third-party audit, not a
certification, not a penetration test by an external firm.** Every confirmed
finding was reproduced against running code before it was changed, and the
reproduction is committed as a test. Every fix was then reverted once and the
test re-run, to show the test fails without it ("deliberate break" column).

**Boundaries observed.** No credentials in source, commits, logs or this report.
No network beyond loopback mocks. Nothing signed, sent, or submitted; no live
user, wallet, protocol or funds touched. The only on-chain data used is the
read-only mainnet lookup-table capture already in the repository.

**Scope.** The review of `7f414e5` named nine assumptions that earlier rounds
had not attacked: audit durability, Windows rotation, archive visibility,
durable nonces, lifecycle-event authenticity, parser byte-level mutation,
crash consistency, no-vacuity of the tests themselves, and documentation
truth. Two earlier items still open from the 2026-09-08 review — best-effort
graph persistence (#11) and the unauthenticated-by-default server (#12) — were
taken in the same round because they sit in the same subsystems.

---

## Findings

Classification: P0 = approve-A / execute-B or equivalent; P1 = a security
invariant is unenforced; P2 = a documented guarantee is weaker than its text;
P3 = operational or hygiene.

### R8-01 — `File::flush()` was the durability primitive — **P2, fixed**

**Where.** `graphite-core/src/durable.rs`, `AuditLog::append_line`; also
`verification.rs::persist_json_atomic`.

**What.** `writeln!(file, …).and_then(|_| file.flush())` and then `return
true`, documented as "durably on disk" and, in the verify handler, the
condition for returning an approval at all. `std::fs::File` is unbuffered;
its `Write::flush` is `Ok(())` with no system call. The claim was therefore
true of the page cache and nothing beyond it. A process crash would not have
lost the record; a power loss or kernel panic between the write and the next
write-back would, after the caller had been told the approval was recorded.

**Reproduction.** Not reproducible as a behaviour from userspace — nothing
observable distinguishes a synced write from an unsynced one until the
machine dies. This finding is established by reading `append_line`, not by a
test, and the report says so rather than pretending otherwise.

**Fix.** `sync_data()` per record (`fdatasync` / `FlushFileBuffers`). The
semantic-graph snapshot now syncs its temp file before the rename, and
rotation syncs the parent directory on Unix so the archive's *name* survives
a crash as well as its bytes.

**Measured** by `durable::tests::audit_append_syncs_the_device` on this
machine's NTFS SSD, 200 iterations each: audit append **0.75 ms**; bare
write + `sync_data` **1.22 ms**; bare write + `flush` **0.019 ms**. A 65×
gap, printed for the record and asserted nowhere.

**A vacuous test of my own, found by the deliberate break.** The first
version of that test asserted "at least 2 µs per append" as proof the sync
was happening. Reverting `sync_data` to `flush` and re-running it: **it
passed.** A plain write syscall already costs more than 2 µs, so the
assertion could never fail — the exact shape of test this round's
no-vacuity pass exists to catch, in code written for this round. No
threshold is honest across machines (on tmpfs `fdatasync` is microseconds
too), so the test now measures and prints and asserts nothing about timing.
The guarantee rests on the code and on a reviewer checking that the
`and_then` still names `sync_data`.

**What this does not establish.** That the bytes reached the platter.
`fdatasync` returns when the device acknowledges; a device with a lying
write cache is outside what any userspace program can verify.

### R8-02 — The read path saw only the active file — **P2, fixed**

**Where.** `durable.rs`, `read_tail_filtered`, `observations_by_program`;
consumer `verification.rs::audit_execution`.

**What.** Both readers opened `self.path` — `audit.jsonl` — and nothing else.
Rotation renames that file. So after the first rotation: the dashboard's
totals fell to whatever had been appended since; `/api/protocols/top` forgot
every program not seen since; and **L8 reconciliation, which joins a
submitted signature to the verdict Graphite recorded for it, could not find
any verdict older than the active file.** A transaction Graphite BLOCKED that
was submitted anyway would, once its record rotated, reconcile as
`NoVerificationOnRecord` rather than `BlockedButExecuted` — the one outcome
the L8 endpoint exists to page on.

**Reproduction.** `read_path_covers_every_archive_after_rotation`: 120
records at a 512-byte rotation threshold produce ≥3 archives; the test first
asserts the active file holds fewer than 120 (so agreement with 120 is
agreement with the archives), then checks totals, the tail across the file
boundary, per-program sums, and that `last_verification_for("hash-0")` finds
the very first record in the oldest archive.

**Fix.** Every reader walks the archives plus the active file. The snapshot
of (archive list, active handle) is taken under the append lock so a rotation
cannot land between the two steps (`concurrent_reads_during_rotation_never_over_or_under_count`
runs a writer and a poller concurrently). Per-archive statistics are cached —
an archive is immutable by construction — so a dashboard poll costs the
active file plus, occasionally, the newest archive, never the history; the
selector became a closed enum (`AuditSelector::{All, Approved, Blocked}`)
to make the cache possible. L8 uses a dedicated newest-first
`last_verification_for`.

**A defect in the fix, caught by its own test.** The first version decided
whether to rescan an archive from `errors.len() < tail`, which is always true
in a trail with no error records — so every archive was rescanned on every
poll and the cache was never consulted. `archive_statistics_are_cached_and_track_pruning`
corrupts one record in the oldest archive *without changing its length* and
requires the cached count; it failed (59 ≠ 60). The decision now comes from
the cached statistics themselves.

**Deliberate break.** Skip the archive loops (`.take(0)`): five tests fail —
`read_path_covers_every_archive_after_rotation` (total 0 ≠ 120),
`last_verification_is_the_newest_across_files` (`None`),
`archive_statistics_are_cached_and_track_pruning`,
`concurrent_reads_during_rotation_never_over_or_under_count`, and the
rotation-failure test's final accounting.

### R8-03 — Windows rotation with an open handle — **NOT A FINDING**, with one adjacent P3 fixed

**The claim.** "On Windows, renaming an open file can fail because of
file-sharing semantics; rotation is effectively disabled."

**Invariant that makes it not a finding.** Rust's `std::fs::OpenOptions` on
Windows opens every file with `FILE_SHARE_READ | FILE_SHARE_WRITE |
FILE_SHARE_DELETE`. `MoveFileExW` succeeds on a file whose open handles all
carry `FILE_SHARE_DELETE`. The log's own append handle therefore never
blocks its own rotation. Verified empirically, not by reasoning: the existing
`active_audit_file_is_bounded_by_rotation` produces archives on this
machine's NTFS with the append handle open, and the concurrent-reader test
above rotates 400 records' worth while a reader holds the file.

**What was real underneath it.** A *foreign* handle without
`FILE_SHARE_DELETE` — a log shipper, an antivirus scanner, PowerShell's
`Get-Content -Wait` — does make the rename fail, and the failure was retried
silently on every append with no counter. An operator saw only a file that
never stopped growing. **P3, fixed:** `rotations_failed` is counted, appears
on `/health` as `degraded_reasons: ["audit_rotation_failed"]` and on
`/metrics` as `graphite_audit_rotations_failed_total`; the record is still
appended (the documented, correct fallback).
`rotation_failure_is_counted_and_never_drops_a_record` opens the file the
way a foreign program would (`share_mode(READ|WRITE)`), drives 40 appends
past the threshold, asserts no archive, no dropped record and a non-zero
counter, then drops the handle and asserts the next append rotates. A Unix
twin makes the directory read-only.

### R8-04 — Handlers panicked on audit-append failure — **P3, fixed**

**Where.** `server.rs`: four `assert!(log.append_…(…))` sites in
`/verify` (two error-record paths), `/verify/execution`, `/audit/event` and
the quarantine handler.

**What.** A full or failing audit disk turned into a panic, caught by
`CatchPanicLayer` as an opaque 500 — which for `/audit/event` hid the one
fact the caller needed (the event was not recorded), and for
`/verify/execution` hid the reconciliation result, discrepancy included.
Not fail-open: nothing false was returned. Fail-closed in the wrong shape.

**Fix.** `/audit/event` and `/verify/execution` answer **503** with
`error_type: "AuditUnavailable"` and the words "NOT recorded"; the execution
handler still carries the reconciliation in the error body so a discrepancy
is never hidden by a disk. Error-path records on `/verify` log the failure
and return the original 4xx/5xx (nothing false is claimed by a rejection).
The quarantine handler reports `audit_recorded: false` rather than reverting
an action that already took effect — un-quarantining a program because the
log is full would be failing open on the gate to protect the log.
`lifecycle_event_reports_an_unrecorded_event_instead_of_panicking` swaps a
read-only handle into the log and asserts the 503.

### R8-05 — Durable-nonce transactions were not modelled — **P1 gap, closed**

**Where.** New: `tx_artifact::{durable_nonce, decode_nonce_account,
check_durable_nonce}`; `verification.rs` L2; `GraphiteCore::set_allow_durable_nonce`;
`GRAPHITE_ALLOW_DURABLE_NONCE`; bridge `BoundTransaction.build`.

**What.** Every state-based conclusion Graphite reaches — balances,
token-account state, simulation — is true at verification time, and a normal
transaction is bounded to roughly a minute after that by its blockhash. A
durable-nonce transaction replaces the blockhash with a nonce value that
does not expire: once signed it stays valid until the nonce account
advances, and can be submitted an hour or a month later, by whoever holds
the bytes, against state that no longer resembles what was verified. The
bridge's `lastValidBlockHeight` — its only bound on the verify → sign → send
window — does not apply. Nothing in Graphite distinguished one from an
ordinary transaction.

**Is it approve-A / execute-B?** No: the bytes executed are the bytes
approved. It is approve-A-*then*, execute-A-*whenever*. Classified P1 because
the verdict's implicit freshness guarantee was unenforced, not because a
different transaction could run.

**Detection.** The runtime's own rule (`Message::get_durable_nonce`):
instruction 0 is a System `AdvanceNonceAccount` (bincode u32 LE `4`),
trailing bytes tolerated as the runtime tolerates them. Position 1 is an
ordinary instruction and is treated as one (`the_same_instructions_with_the_advance_second_are_not_refused_for_it`).

**Posture.** Refused at L2 by default; the reason names the nonce account,
authority and value and says why the expiry assumption fails. An operator
whose flow genuinely needs them (offline / hardware-wallet signing) sets
`GRAPHITE_ALLOW_DURABLE_NONCE=1`, and then the nonce account is fetched
under the RPC budget and must be System-owned, initialized, holding this
exact nonce value under the instruction's named authority, which must be a
required signer. Every mismatch is one the runtime refuses at load (or, for
a stale value, a transaction that already executed), and fails L2 with the
mismatch named. No RPC, or an unreachable one, also fails: the opt-in is
"permitted once verified", not "permitted". The bridge refuses to build the
shape at all.

**Evidence.** Two corpus entries serialized by `SystemProgram.nonceAdvance`
(shape from the SDK, not the test); 8 tests in `durable_nonce.rs` (parse,
runtime layout decode incl. legacy version tag, every mismatch named,
default refusal, opt-in-without-RPC refusal, position-1 control); 6 in
`durable_nonce_rpc.rs` against a loopback mock serving the nonce account
(verified pass, no-opt-in refusal, stale value, foreign authority, missing
account, unreachable RPC); 4 in `bound-transaction.test.ts`.

**Deliberate break.** Disable the L2 override: `a_durable_nonce_transaction_fails_l2_by_default`
and `the_operator_opt_in_without_rpc_still_refuses` fail (L2 Passed).
Disable the `authority_is_signer` check:
`every_mismatch_between_message_and_nonce_account_is_named` fails. Three
failures observed, tree restored, re-run green.

**What this does not establish.** That a nonce transaction whose account
*passes* the check is safe to sign — only that it will execute as verified
*if submitted before the nonce advances*, and that the operator chose to
accept the missing clock. The report says so in the L2 text.

### R8-06 — Server unauthenticated by default — **P2, fixed** (review item #12)

**What.** An absent `GRAPHITE_API_KEY` meant "dev mode" and the server
started with every route open. The CLI refused keyless + non-loopback;
keyless + loopback started with a log line. A security gate whose safe
configuration is the one you must remember to set is not fail-closed.

**Fix.** `server::auth_posture(addr, key, dev_mode)`, decided before the
data directory is touched: a key wins everywhere; no key and no
`GRAPHITE_DEV_MODE=1` refuses to start on every address including loopback;
`GRAPHITE_DEV_MODE=1` without a key is permitted only on `127.0.0.1` / `::1`.
The CLI and `run_server` both call it (embedders that never pass through the
CLI get the same refusal). Documented in README, SECURITY, ARCHITECTURE,
`.env.example`, Dockerfile, and the SAK integration README.
`auth_is_required_unless_dev_mode_is_named_and_the_bind_is_loopback` covers
the matrix. CI's container smoke test already sets a key and asserts 401 on
an unauthenticated `/verify`; unchanged.

### R8-07 — Semantic-graph snapshot failures were a `warn!` — **P3, fixed** (review item #11)

`persist_json_atomic` returns `Result` now; `GraphiteCore` counts outcomes
across clones (`PersistenceCounters`), `persistence_health()` reports them,
`/health` adds `graph_snapshot_failed` to `degraded_reasons` and `/metrics`
adds `graphite_graph_snapshots_{ok,failed}_total`. Earned trust tiers and
baselines that exist only in memory are now something an operator can alert
on before the restart that loses them.

### R8-08 — Byte-level parser corpus — **COVERAGE GAP, closed**

**What was missing.** The ten-shape corpus proved the two parsers agree on
well-formed transactions. Nothing proved they agree on damaged ones.

**What was added.** `emit-corpus.ts` records **1,641 mutations** of three
transactions (one-signer legacy, two-signer legacy, real-table v0): every
truncation length, every single-byte flip, fourteen signature-count
prefixes (including `0xFF 0xFF 0x03` = 65,535 valid, `0x80 0x80 0x04` =
65,536 refused, non-minimal aliases, never-terminating), and trailing
bytes. Each records what `messageOf` concluded and whether
`VersionedTransaction.deserialize` accepts the bytes. Stored as operations
on named bases, not as bytes: 535 KB rather than megabytes.
`every_byte_level_mutation_is_read_the_same_way_on_both_sides` replays them
against Graphite's `message_bytes` — **now the parser's own signature skip,
exported**, so the comparison is Graphite's actual acceptance language and
not a test-local reimplementation of it.

**Required and observed.**
- Prefix agreement with `messageOf`: **1,641 / 1,641** (accept ⇔ accept, same slice).
- No panics.
- Graphite accepts bytes web3.js refuses: **0 / 1,641**.
- Both accept 762; both reject 834.
- Graphite refuses bytes web3.js accepts: **45**, by reason — truncated
  field 12, non-canonical compact-u16 11, impossible header 9, trailing
  bytes 9, program index out of range 4.

**Why the 45 are the right direction.** The SDK is not the authority; the
runtime is. `web3.js`'s shortvec decoder does not check minimality
(`0x81 0x00` decodes as 1), it slices a declared length past the end of the
buffer instead of failing, it does not sanitize header counts or program
indexes, and it ignores trailing bytes. The RPC's wire decoder rejects every
one of those (`reject_trailing_bytes`; the `ShortU16` alias check; the
sanitizer's index and header bounds). Graphite refuses what the runtime
refuses and accepts what the SDK accepts otherwise.

**Deliberate break.** Loosen `compact_u16` to accept a zero continuation
group: `every_byte_level_mutation_is_read_the_same_way_on_both_sides` fails
at the first `0x81 0x00` prefix (messageOf rejects, Graphite sliced a
message), and the pre-existing `non_minimal_encodings_are_still_refused_as_non_canonical`
fails alongside it. Two independent tests, one rule.

### R8-09 — Documentation provenance — **P3, fixed**

`docs/CURRENT.md` is now the one page that describes the codebase as it is:
security status, what is enforced (with the test that proves each line),
what is not, what is still undone and whose decision it is, and a dated
report index. Fourteen dated reports carry a banner: historical record, kept
unedited, read CURRENT.md for what is true now. README's status section and
documentation table point there. `CHANGELOG.md` gained a Round 8 entry; its
older "Current State" heading is itself now history.

---

## NOT A FINDING

- **Lifecycle-event poisoning.** `POST /audit/event` accepts caller-reported
  signing/submission/confirmation/finalization for any `content_hash`.
  Invariant: those rows are `LifecycleEventRecord`, a different type from
  `AuditRecord`, and **no reader treats them as a verdict** —
  `read_tail_filtered`, `observations_by_program` and
  `last_verification_for` parse `AuditRecord` only and skip the rest; L8
  reconciliation joins on the verification row and never on a lifecycle
  row; self-observed event types (`verification`, `construction`,
  `simulation`, `operator_action`) are rejected at the endpoint. A caller
  can write "I signed X" into the trail; it cannot make Graphite say it
  approved X. The rows are labelled attestations with `reported_by`, which
  is the honest thing to record for events Graphite cannot witness.
- **Windows rotation with the log's own handle open.** See R8-03.
- **Crash between verification and audit.** Order in `/verify` is verify →
  append → respond, and a failed append refuses the response with 503. A
  crash after the append and before the response loses the response, not
  the record; the caller retries and gets a second verdict (idempotent — the
  verdict is deterministic, P2). A crash before the append loses nothing
  that was ever claimed.
- **Retry / rebuild substitution.** Unchanged from Round 7: the bridge has
  no retry code path, and a rebuilt transaction is a new `BoundTransaction`
  with a new digest that fails `signApproved` against the old approval.

## DOCUMENTED LIMITATIONS

- **An unparseable artifact takes a weaker L2 path, not a failed one.** When
  `parse_transaction` fails, L2 falls back to "the described instruction's
  bytes appear somewhere in the artifact", and the scope discloses the
  downgrade in `unobserved`. This cannot reach `approved` under any built-in
  profile (L3 stays Inconclusive → confidence ≤ 0.44 < Gaming's 0.55), and
  a `Custom` profile below 0.55 requires the operator flag
  `GRAPHITE_ALLOW_PERMISSIVE_PROFILES`. It would additionally require bytes
  the runtime accepts and Graphite's parser refuses, which R8-08 measured
  at zero across 1,641 mutations but did not prove impossible. Left as is
  this round because `tests/artifact_binding.rs` pins the fallback
  behaviour deliberately; a hard L2 failure on parse error is the
  recommended follow-up.
- **`fdatasync` proves the device acknowledged, not the platter.** See R8-01.
- **Token-2022 `TransferFee` still blocks.** Unchanged.
- **The dashboard reads are bounded by the active file plus cached archive
  statistics, but the first read after startup scans every archive once.**
  On a node with years of archives that first poll is slow; a persisted
  archive index would remove it. Not done this round.
- **Nonce opt-in is process-wide.** `GRAPHITE_ALLOW_DURABLE_NONCE` applies
  to every caller of the instance; there is no per-wallet-profile grain.

## COVERAGE GAPS (open)

- **Graphite's parser vs the runtime's decoder.** R8-08 compares against
  `messageOf` and against `web3.js`. It does not run Solana's own
  `bincode` + sanitizer over the same 1,641 mutations. The 45 Graphite-strict
  cases are argued from the runtime's documented rules, not observed against
  it. A Rust-SDK-backed oracle would close this.
- **No mutation of a nonce transaction's account list.** The nonce corpus
  entries are well-formed. Mutations that move the nonce account into a
  lookup table (the runtime requires it static) are not exercised.

---

## Regression audit of this round's own changes

- `read_tail_filtered` selector change touched every caller (`server.rs` ×3,
  `verification.rs`, in-crate tests); the existing
  `read_tail_filtered_caps_memory_and_reports_totals` still passes unchanged
  in its assertions.
- `persist_json_atomic` now creates the temp file with `File::create` +
  `write_all` + `sync_data` instead of `fs::write`; failure still removes
  the temp file; the rename is unchanged.
- The auth inversion is a **deployment-breaking change by design**: any
  environment that ran keyless will refuse to start until it sets a key or
  `GRAPHITE_DEV_MODE=1`. docker-compose already required the key; CI's
  container smoke sets one; SDK live tests require one.
- `parse_transaction` now delegates its first two steps to `skip_signatures`;
  error offsets are unchanged (the same `Reader` continues).

## Evidence

Exact commands, this HEAD plus the working tree of this round:

```
cargo fmt --all -- --check                                  clean
cargo clippy --release --all-targets -- -D warnings         clean (rustc 1.98.1)
cargo test --release                                        1,422 passed, 0 failed, 10 ignored
cargo test --release --no-default-features --lib            301 passed, 0 failed, 1 ignored
cargo test --release --no-default-features --features cli   1,281 passed, 0 failed
npm test  (integrations/solana-agent-kit)                   73 passed, 0 failed
npm run build + npm test  (sdk/typescript)                  built; 13 passed, 4 skipped (live-server), 0 failed
gofmt / go vet / go test  (sdk/go)                          clean; ok
pytest  (python-ai-layer)                                   27 passed
npm run typecheck + build  (dashboard)                      built
npm run emit:corpus, twice                                  identical sha256 (deterministic; CI diffs it)
graphite server, keyless, loopback                          exit 1: "refusing to start without GRAPHITE_API_KEY"
graphite server, GRAPHITE_DEV_MODE=1, 0.0.0.0               exit 1: "refusing to bind 0.0.0.0:7399 unauthenticated"
graphite server, GRAPHITE_DEV_MODE=1, 127.0.0.1             serves; /health carries degraded_reasons, rotation
                                                            counters, graph_persistence; /metrics carries the
                                                            six new series; POST /audit/event -> recorded:true
cross-language mutations                                    1,641; prefix agreement 1,641/1,641;
                                                            Graphite-looser-than-SDK 0; Graphite-stricter 45
```

Test count movement: 1,399 → 1,422 Rust (+23: 8 durable-nonce, 6 durable-nonce-rpc,
1 mutation corpus, 6 durable.rs, 2 server.rs); featureless core 295 → 301;
TypeScript 69 → 73. Ten ignored tests are the same ten network-dependent
ones as before.

CI added one step: a keyless container must refuse to start, with and
without `GRAPHITE_DEV_MODE=1` (0.0.0.0 is not loopback), and name the refusal
in its logs.

The deliberate-break log, in order: (1) `sync_data` → `flush`: **not caught**
— the timing assertion was vacuous and has been replaced by a measurement
(R8-01). (2) archive loops skipped: caught by 5 tests. (3) nonce L2 override
disabled: caught by 2. (4) nonce signer check disabled: caught by 1.
(5) compact-u16 alias accepted: caught by 2. Tree restored after each;
`grep` for the break markers returns zero; fmt, clippy and the touched
targets re-run green.

---

## Verdict

```
Graphite Security Status:       CONDITIONAL — security-hardened alpha
Final Transaction Identity:     PASS (unchanged)
ALT / v0:                       PASS (unchanged)
Audit Durability:               PASS — fdatasync per record; whole-trail reads; failures counted
Durable-Nonce Semantics:        ENFORCED — refused by default, verified on opt-in
Server Auth Default:            FAIL-CLOSED — key required; dev mode named and loopback-only
Parser / Wire Safety:           PASS — 1,641-mutation corpus, zero looser-than-SDK cases
Documentation Provenance:       ONE CURRENT PAGE; reports marked historical
CI Certification:               PENDING — recorded below once the Actions run for this commit completes

P0: none
P1: R8-05 (closed)
P2: R8-01, R8-02, R8-06 (fixed)
P3: R8-03 (adjacent), R8-04, R8-07, R8-09 (fixed)
COVERAGE GAP: R8-08 (closed); runtime-oracle and nonce-ALT mutation (open)
```

**What stays outside the guarantee** and why Graphite is still
"conditional": no independent party has attempted to break it; `main` has no
branch protection, so the CI that certifies each commit is advisory until
the owner makes it mandatory; and a compromised process, a lying storage
device, and a nonce transaction the operator chose to permit are each outside
what the code can enforce and are stated as such rather than claimed.
