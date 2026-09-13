# Round 10 — Exact Execution Attribution

**Ground truth at the start of the round.** HEAD `25e2306`; the substantive
parent `a56c7e8` has a GitHub Actions run that completed **success** (Actions
run 34720050898). rustc 1.98.1, Node 24.1.0, `@solana/web3.js` 1.98.4,
TypeScript 5.9.3. Windows 11 / NTFS for every measurement below.

**Method.** Internal engineering work by Anthropic's Claude acting as this
project's engineering agent. **Not an independent third-party audit, not a
certification, not a penetration test by an external firm.** Every finding
was reproduced against running code before it was changed, with valid
serialized Solana transactions, and the reproduction is committed as a test.
Every fix was reverted once and its test re-run (deliberate-break log at the
end).

**Boundaries observed.** No credentials anywhere. No network beyond loopback
mocks and read-only public metadata (GitHub, Docker Hub, PyPI, go.dev) for
the pins in R10-02. Nothing signed, sent or submitted; no live user, wallet,
protocol or funds touched.

**Scope.** The review of `25e2306` found one thing the Round 9 report had
missed and asked for a round focused on it: L8 and the lifecycle rows joined
an execution to a verification on `content_hash`, an instruction-level key
that different transactions share. The review's fourteen attacks (same
instruction with a different sibling / fee payer / signer set / blockhash;
approve-A-then-block-B and the reverse; rotation between the records;
duplicate projections; concurrent identical verifications; reconciliation
against the wrong historical verdict; `verdict_on_record` against the wrong
transaction; `audit_trail_id` spoofing; signature and content hash naming
different transactions) are each exercised below. Its three P2s — supply
chain, tested-vs-shipped compiler, and two "should be load-tested" items —
were taken in the same round.

---

## Findings

### R10-01 — L8 and the lifecycle join were keyed on `content_hash` — **P1, fixed**

**Where.** `verification.rs::audit_execution`, `durable.rs::last_verification_for`,
`server.rs::lifecycle_event_handler`; every SDK and the bridge.

**What.** `content_hash` is `hex(sha256(program ‖ discriminator ‖ accounts ‖
data ‖ cpi_targets)[..8])` — one instruction's projection. The same transfer
beside a malicious sibling, under another fee payer, signer set or blockhash,
is a different transaction with the same `content_hash`. Round 3 made
`transaction_sha256` the authoritative identity for *signing* and left
`content_hash` as the audit-trail join key, and Round 9 built
`verdict_on_record` and the bridge's lifecycle reporting on that key.
`last_verification_for(content_hash)` returned the *newest* record under it,
so:

```
verify B (transfer + undeclared 100 SOL sibling)   → BLOCKED   content_hash H
verify A (the transfer alone)                       → APPROVED  content_hash H
execute B; POST /verify/execution {content_hash: H} → ApprovedAndExecuted
```

The one guarantee L8 exists for — a blocked transaction that executed is
reported as `BlockedButExecuted` — did not hold whenever an approved
transaction carrying the same instruction had been verified more recently.
The same lookup made `verdict_on_record: "approved"` on a `signing` reported
for B.

**Reproduction** (`tests/round10_attribution.rs`). A is the corpus's own
`legacy_single_transfer`; B is the same transfer on the same keys followed by
an undeclared 100 SOL transfer to a fourth key, encoded field by field. Both
verified through the mock cluster under the same description; A approved, B
blocked at L2 ("does not describe"); `content_hash` equal, digests and ids
distinct. Also shown: the corpus's `legacy_other_blockhash` — same
`content_hash` as A, different digest. The pre-fix answer is preserved in
`without_chain_bytes_…`: with only `content_hash` to go on, the execution of
B resolves to A's approval, and the attribution now *says* `content_hash`.

**Fix — the chain decides.** The bytes behind a signature, with their
signature slots zeroed, are byte-for-byte the artifact the bridge sent
(`Transaction.serialize({requireAllSignatures:false})` leaves 64 zero bytes
per slot; signing changes nothing else), so their SHA-256 *is*
`scope.transaction_sha256` of the verification of those bytes.
`tx_artifact::unsigned_artifact` / `artifact_sha256_of_signed` recover it;
`rpc_client::get_transaction_bytes` fetches it (`getTransaction`, base64);
`audit_execution` looks the digest up. That join is independent of anything
the caller said. With A newest and B executed: `attribution: chain`,
`chain_transaction_sha256` = B's digest, `BlockedButExecuted`. Bytes that
were never verified (the same transfer under an unsubmitted blockhash) are
`NoVerificationOnRecord` even though a same-`content_hash` approval exists.
Pinned cross-language: `execution-lifecycle.test.ts` zeroes the slot of the
bytes the bridge submitted and gets `bound.artifactBytes` back, digesting to
the verdict's `transaction_sha256`.

**Fix — the trail carries the exact keys.** `AuditRecord.transaction_sha256`
(the artifact digest, `None` for descriptive verdicts and pre-Round-10 rows).
`AuditLog::find_verification(VerificationKey::{AuditTrailId, TransactionSha256,
ContentHash})` replaces the single-key lookup; the Round 9 active-file index
now holds all three keys per record (`id:`, `tx:`, `ch:` prefixes), rebuilt
at open, maintained per append, cleared on rotation, with the archives
scanned by the same key. `last_verification_for` survives as the
`ContentHash` case, documented as the coarsest key.

**Fix — caller keys, most exact first, no fallback.** When the chain's bytes
cannot be fetched (an RPC without `getTransaction`, a pruned ledger, no
RPC), `/verify/execution` and `/audit/event` resolve by `audit_trail_id`,
else `transaction_sha256`, else `content_hash` — and a more exact key that
finds nothing is *not* rescued by a coarser one beside it, because that
fallback would let a caller pick the verification an execution is attributed
to by naming a fake id and a real hash. L8 reports which key decided
(`attribution`) and cross-checks every supplied key against the record
resolved (`caller_keys_disagree`, reported and never believed). `/audit/event`
refuses (400 `InconsistentKeys`) an event whose keys name two different
verifications, records `verdict_on_record_key` on every row, and returns it.

**Fix — the bridge sends the exact keys and insists on them.**
`recordLifecycleEvent` and `verifyExecution` carry `audit_trail_id` and
`transaction_sha256` on every call; `executeBoundTransaction` refuses to
submit unless the signing receipt was resolved by `audit_trail_id` (a server
answering by a coarser key — or an older server — is not the one this bridge
is written for). CLI: `graphite execution --transaction-sha256 …
--audit-trail-id …`, printing attribution and disagreements.

Attack list, item by item: (1–5) same instruction, different
sibling/fee-payer/signers/blockhash → different digest, same `content_hash`,
joined on the digest; (6) approved A then blocked B, B executed →
`BlockedButExecuted` by chain; (7) blocked A then approved B, A executed →
by chain, A's block; (8) rotation between the records → `every_key_is_exact_
across_rotation_and_concurrency` (rotate every 2 KB, eleven records across
archives, every key exact after reopen); (9) duplicate projections → the
shared `content_hash` is the premise of every test here; (10) ten concurrent
verifications of A → ten ids, each exact; (11) reconciliation against the
wrong historical verdict → the headline test; (12) `verdict_on_record`
against the wrong transaction → `lifecycle_verdict_resolves_by_the_most_
exact_key_and_refuses_contradiction`; (13) `audit_trail_id` spoofing →
`not_found` by that key, never rescued; (14) signature and content hash
naming different transactions → `caller_keys_disagree`, chain wins.

### R10-02 — Supply chain: floating Python, Go and cargo-audit; shipped compiler ≠ tested compiler — **P2, fixed**

`python-ai-layer/requirements-lock.txt` pins pytest and its three transitive
wheels (plus Windows-only colorama) by SHA-256; CI installs with
`--require-hashes`; verified locally in a fresh venv (27 tests pass).
`go-version: "1.22.12"` (exact patch, from go.dev's release list).
`cargo install cargo-audit --locked --version 0.22.2` (the current stable on
crates.io). CI's toolchain is `1.98.1` rather than `stable`, and the
container builder is `rust:1.98.1-bookworm@sha256:9a73a508…` (digest read
from Docker Hub and verified against the registry's `Docker-Content-Digest`)
— the compiler that runs the certification is the compiler that produces the
shipped binary, and both are bumped together.

### R10-03 — Measured, not found: RPC decompression and the limiter at its bound — **NOT A FINDING**, with numbers

- **Gzip bomb.** `tests/round10_rpc_decompression.rs` serves 65,250 bytes on
  the wire that inflate 1028:1 to a 64 MiB JSON body. `read_body_capped`
  applies `MAX_RPC_RESPONSE_BYTES` to the chunks `reqwest` yields — which are
  decompressed bytes — so the body is abandoned at 32 MiB: **refused in
  35 ms**. A 100,000-deep nested body is serde_json's "recursion limit
  exceeded", not a stack overflow.
- **Rate limiter at `MAX_BUCKETS`.** `server::tests::rate_limiter_at_its_bound_
  stays_cheap_per_check` (release): one million distinct IPs inserted through
  the one mutex in 393 ms (**393 ns/check**), one million more each evicting
  the oldest in 452 ms (**452 ns/check**); ~55 MB of entries plus map
  overhead at the cap. Single-instance, as documented; a horizontally
  deployed Graphite needs a shared limiter, which is not claimed.

## NOT A FINDING

- **Duplicate instruction projections as an attack on the trail.** Two
  verifications with equal `content_hash` are two rows with distinct ids
  and, when artifact-bound, distinct digests. The ambiguity was in the join,
  not the records; nothing was overwritten.
- **Concurrent verifications with identical `content_hash`.** Each append
  takes the file lock, each id is unique, the index stores the newest offset
  per key; ten concurrent A's resolve individually by id.
- **`audit_trail_id` spoofing.** An id is `gr-<uuid>`; a fabricated one
  resolves to nothing and, by the no-fallback rule, stays `not_found`.

## DOCUMENTED LIMITATIONS

- **Without the chain's bytes, attribution is only as exact as the caller's
  keys.** An RPC that does not serve `getTransaction`, a pruned ledger, or no
  RPC at all leaves L8 on `audit_trail_id` → `transaction_sha256` →
  `content_hash`. The last is ambiguous by construction and the answer says
  so (`attribution: content_hash`); the bridge always supplies the first two.
- **Rows written before Round 10 carry no `transaction_sha256`.** They are
  reachable by id and by `content_hash` only.
- **`content_hash` keeps its name.** It is the instruction-level key on
  every row, the AuditBind key, and the compatibility key on both endpoints;
  a rename (`instruction_content_id`) remains open work.

## Regression audit of this round's own changes

- `audit_execution(signature, content_hash, audit)` →
  `audit_execution(signature, ExecutionKeys, audit)`; nine existing L8 tests
  updated mechanically and unchanged in their assertions (their one-shot
  mock serves `getSignatureStatuses` only, so the follow-up `getTransaction`
  fails and they exercise the caller-key path, now labelled).
- `AuditRecord` gains an optional field; every existing row and fixture
  deserializes with `None`. `LifecycleEventRecord` gains two optional fields.
- The index key format changed (`ch:` prefix); it is in-memory only.
- `/audit/event` now refuses an event whose `content_hash` contradicts the
  verification its `audit_trail_id` names — a behaviour change for any caller
  that was sending a wrong id, which is the point.

## Evidence

```
cargo fmt --all -- --check                                  clean
cargo clippy --all-targets --all-features -- -D warnings    clean
cargo test --release                                        1,455 passed, 0 failed, 10 ignored
cargo test --release --no-default-features --lib            305 passed, 0 failed, 1 ignored
cargo test --release --no-default-features --features cli   1,293 passed, 0 failed, 1 ignored
npm test  (integrations/solana-agent-kit)                   96 passed, 0 failed
npm run check + npm test  (sdk/typescript)                  checked; 13 passed, 4 skipped, 0 failed
gofmt / go vet / go test  (sdk/go)                          clean; ok
pytest, hash-locked venv  (python-ai-layer)                 27 passed
```

Live probe against the release binary on loopback (`GRAPHITE_DEV_MODE=1`,
`GRAPHITE_RPC_URL` pointing at a loopback mock that approves simulations,
confirms one signature and serves B's signed bytes for `getTransaction`):
B verified (blocked, L2 undeclared sibling), then A (approved); `content_hash`
equal, digests differ. `POST /verify/execution {signature, content_hash}` →
`BlockedButExecuted`, `attribution: chain`, `recorded_audit_trail_id` = B's,
`chain_transaction_sha256` = B's digest, `caller_keys_disagree: []`. The same
call with A's `audit_trail_id` and `transaction_sha256` → still
`BlockedButExecuted`, two disagreements named. `POST /audit/event signing`:
by `content_hash` alone → `approved` / `content_hash`; with B's
`transaction_sha256` → `blocked` / `transaction_sha256`; with B's
`audit_trail_id` → `blocked` / `audit_trail_id`; A's id beside B's digest →
400 `InconsistentKeys`; a spoofed id → `not_found` / `audit_trail_id`;
`graphite_lifecycle_events_on_blocked_total 2`.

Test count movement: 1,444 → 1,455 Rust (+11: 7 attribution, 2 RPC
decompression, 1 lifecycle key-precedence, 1 rate-limiter measurement);
featureless core 305 unchanged; cli-only 1,293 unchanged; TypeScript SAK
95 → 96; SDK 13; Go and Python unchanged.

Deliberate-break log, each fix reverted alone and the tree restored after:
(1) chain attribution disabled (never fetch the bytes) → caught by the
headline test; (2) a spoofed `audit_trail_id` rescued by the `content_hash`
beside it → caught by 1; (3) `unsigned_artifact` not zeroing the slots →
caught by 1; (4) contradicting lifecycle keys accepted → caught by 1; (5)
the index keyed by `content_hash` only → caught by 1 (the newest A, in the
active file, no longer found by digest). TypeScript: (6) the bridge's
`verdict_on_record_key` check removed → caught by 1. `git status` clean on
`src/` after each; fmt and clippy re-run green.

CI for `8b7e5dc`, the commit carrying this round: **completed success**,
all seven jobs — Rust core on the pinned `1.98.1` toolchain (fmt, clippy,
tests, both feature-matrix legs), container build on
`rust:1.98.1-bookworm@sha256:9a73a508…` + live smoke, TypeScript SDK + SAK
integration including the corpus drift check, Go `1.22.12`, Python with
`--require-hashes`, dashboard, dependency CVE audit with `cargo-audit
0.22.2`. Actions run `34750271068`, read from the runs endpoint for the full
SHA.

---

## Verdict

```
Graphite Security Status:       CONDITIONAL — security-hardened alpha
Final Transaction Identity:     PASS (unchanged)
L8 Exact Attribution:           ENFORCED — joined on the chain's bytes; caller keys most-exact-first, cross-checked, never falling back
Lifecycle verdict_on_record:    EXACT — resolved by audit_trail_id / transaction_sha256; content_hash labelled as the coarse key
Supply Chain:                   hash-locked Python, exact Go and cargo-audit, tested compiler = shipped compiler
RPC Decompression / Limiter:    MEASURED — 64 MiB bomb refused at 32 MiB in 35 ms; 452 ns/check at one million buckets
CI Certification:               CERTIFIED — 8b7e5dc completed success, all seven jobs (Actions run 34750271068)

P0: none
P1: R10-01 (fixed)
P2: R10-02 (fixed)
NOT A FINDING: R10-03 (measured), duplicate projections, concurrent identical verifications, id spoofing
```

**What stays outside the guarantee.** No independent party has attempted
to break Graphite; `main` has no branch protection; a compromised process, a
lying storage device, a lying RPC, and a residual the operator chose to
accept are outside what the code can enforce. And the shape of this round's
finding is worth naming: the signing gate was keyed on the exact bytes since
Round 3, while the *forensic* path beside it kept the older, coarser key for
two more rounds because it was "only" the audit join. The join is what turns
a bypass into a page; it has to be as exact as the gate.
