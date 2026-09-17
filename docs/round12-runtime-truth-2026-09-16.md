# Round 12 — Runtime truth and the trust boundary around one RPC

> **Historical record.** This report describes the codebase at commit
> `1e521ba` on 2026-09-16. For the current state of Graphite see
> [`CURRENT.md`](CURRENT.md).

**Scope.** The owner's fresh audit after Round 11 named where the remaining
risk lives: the runtime itself as the authority on what a transaction is,
hostile or inconsistent RPC behaviour beyond byte substitution, crash and
restart consistency, the deployment boundary (RPC URL / SSRF), and the
lifecycle state machine. It also raised six implementation-level
observations. This round takes each of those into code: an oracle against the
Solana runtime's own decoder, an RPC-equivocation campaign, a sequence check on
the lifecycle trail, and the deployment questions answered one by one. This is
internal engineering work by the project's own agent; nothing here is an
independent certification.

**Standing constraints, all kept.** No credentials in source, commits, logs or
output; no attack on any public RPC (every adversarial RPC is a loopback
mock); public devnet used read-only; nothing touched a live wallet, protocol
or fund.

---

## Verdict in one paragraph

The runtime oracle found, on its first run, that Graphite's parser accepted
frames Solana's own `sanitize` refuses — five classes, 3,382 of 200,000
generated frames and eight of the recorded corpus's own mutations — and in the
legacy case explained an impossible account index as a lookup-derived account
in a message that has no lookups, with L2 *passing*. None could execute, so
none was a bypass; each was an `artifact_bound` verdict about a frame that is
not a transaction. Closed at the parser; the oracle now runs in CI over the
corpus and 600,000 seeded frames and reports Graphite exactly as strict as the
runtime on every one. On the RPC side, Round 11 stopped an RPC from lying about
*which bytes* executed; this round stops it from being believed uncritically
about *whether* they did: the commitment level is read (a `processed` sighting
proves nothing), an RPC that contradicts itself is not concluded from, a
malformed status is `Unavailable` instead of "included and failed", redirects
are refused, and an optional second, independent RPC
(`GRAPHITE_RPC_WITNESS_URL`) must agree before an approval is reported
executed — while either endpoint's sighting of a blocked transaction still
alarms. The lifecycle trail now knows its own order (duplicates, out-of-order
and unpreceded stages, and a second signature for one transaction are named on
the row), one server per data directory is enforced by a lock, and the RPC URL
is validated before the process claims to be simulating. **R12-08** is the
finding this round made for itself: the live probe showed an L8 row attributed
by `content_hash` writing the resolved record's exact keys onto a signature's
row — a false link the new sequence check then reported as a conflict against
a truthful report. And the run itself surfaced **R12-12**: version-1
transactions are live on devnet as of this week, an RPC refuses whole blocks to
a client capped at version 0, and the live corpus could see nothing — fixed
for discovery, and the format itself is now the most time-sensitive open item.

---

## The audit's questions, answered

| Audit item | What was done | Where |
|---|---|---|
| Priority 1 — runtime parser oracle | `tools/runtime-oracle`: the agave crates (`solana-transaction` 5.0, `solana-message` 5.0) decode every byte string exactly as a validator's packet path does — bincode 1, fixint, 1232-byte limit, trailing bytes refused — then `VersionedTransaction::sanitize`. Required: Graphite parses nothing the runtime refuses; where both accept, message bytes, version, header, static keys, every instruction and every lookup are equal. Inputs: the 12 corpus shapes, their 1,659 recorded mutations, and 300,000 seeded structure-aware frames per run (two seeds in CI). Its own workspace and lockfile, so the agave tree never reaches the shipped binary or the audited `Cargo.lock`. | R12-01, `tools/runtime-oracle/src/main.rs`, CI job `runtime-oracle` |
| Priority 2 — continuous parser fuzzing | The oracle's generator: half the frames legal by construction, half carrying every malformation the format allows (illegal headers, indexes, program-as-payer, empty lookups, > 256 accounts, non-canonical and over-range compact-u16, wrong version prefixes, truncation, bit flips, padding to and past the packet size). No panic, no accepted-but-unexecutable frame, no divergent read, over 600,000 frames per CI run. Not coverage-guided; recorded as such. | Same |
| Priority 3 — RPC equivocation campaign | Nine scenarios against loopback mocks: `processed` commitment; slot contradiction; outcome contradiction; "included" with `null` bytes; four malformed statuses; a 307 redirect; witness agreement, no-record, wrong-slot and unreachable; a blocked transaction seen by the witness only; the witness that is the primary. | R12-02…R12-05, `tests/round12_rpc_equivocation.rs`, probe |
| Priority 4 — restart / crash consistency | Already covered by `durable.rs` (torn final line, rotation under concurrent reads, rapid back-to-back rotation, rename failure, re-index on reopen) and by the probe's restart section. New this round: two processes on one data directory (R12-06), and the lifecycle index rebuilt at open and surviving one rotation. | R12-06, `durable::tests::lifecycle_history_*` |
| Priority 5 — deployment security review | Container: non-root fixed UID, read-only root, `cap_drop: ALL`, no-new-privileges, pinned digests, `/data` the only writable path, healthcheck via the binary — all pre-existing and re-read. Forwarded-header trust, CORS, graceful shutdown: pre-existing (Rounds 5–9). New: the RPC URL is validated at startup (scheme, host, fragment), plaintext-to-non-loopback is warned, redirects are never followed, the startup log names the scheme and never the URL, and a second server on the directory refuses. | R12-05, R12-06, R12-07 |
| §12 — RPC URL / SSRF | **NOT A FINDING** for the request path: the endpoint is read from the process environment once at startup (`GRAPHITE_RPC_URL`, `GRAPHITE_RPC_WITNESS_URL`) or from the operator's own CLI flag; no HTTP handler reads, accepts or forwards an endpoint, and `VerificationInput` has no such field — verified by reading every `rpc_client` construction site (`server.rs` `run_server`, `cli.rs` `run_execution` / `run_regression_seed_live`). What an operator-chosen URL could still do is now bounded: schemes other than http/https refused, redirects refused, response bodies capped at 32 MiB (Round 9), the URL never logged. Private-range blocking is deliberately not applied — a loopback or LAN RPC is a legitimate deployment. | R12-07 |
| §13 — audit event semantics | Sequence findings computed on every report from the rows already on record for the transaction: `duplicate`, `out of order`, `unpreceded`, `signature conflict`. Submission onward requires a real signature. Timestamps are the server's, never the caller's (no finding). Replay after rotation: the newest archive is consulted; after restart: the index is rebuilt. Same event from a different `reported_by`: recorded, named a duplicate. | R12-09, R12-10 |
| Obs. 1 — descriptive fallback | DOCUMENTED, unchanged: a descriptive verdict cannot execute (`ResidualPolicy`, `scope.kind`). | — |
| Obs. 2 — `build_transaction` is a projection | DOCUMENTED, unchanged: no document calls it wire-level construction; the bridge builds the real transaction. | — |
| Obs. 3 — positional account identity | DOCUMENTED LIMITATION, unchanged and disclosed per account (`Unverified`). | — |
| Obs. 4 — the parser does not fetch ALTs | NOT A FINDING as stated: the parser records lookups and `resolve_lookups` fetches and decodes them all-or-nothing under RPC (Round 8); without RPC the accounts are counted, disclosed as `lookup_tables_unresolved`, and refused at execution unless accepted. New this round: the parser refuses a v0 index past the loaded universe and an empty lookup (R12-01), so a frame the runtime would refuse is not "unresolved" but rejected. | R12-01 |
| Obs. 5 — the bridge | No change needed. | — |
| Obs. 6 — submission record failure only logged | Fixed: the bridge retries the submission report (3 attempts, doubling backoff); a retry the trail already took is a `duplicate` and counts as recorded; the L8 row remains the recovery path and says so in the log line. | R12-11 |

---

## Findings

| # | Class | Finding | Status |
|---|---|---|---|
| R12-01 | **P2** | `parse_transaction` accepted five classes of frame the runtime's `sanitize` refuses: program index 0 (the fee payer as a program), a legacy account index past the static keys, a v0 index past the loaded universe, a lookup loading nothing, more than 256 accounts. A legacy frame with index 255 passed L2 as "1 of its account(s) arrive through address lookup tables" — in a message with no lookups — and received an `artifact_bound` scope and digest. Found by the runtime oracle on its first run: 3,382 / 200,000 generated frames, 8 of the corpus's 1,659 recorded mutations. Not a bypass: no such frame can execute, and with an RPC the simulation fails. | **Fixed.** `ProgramIsFeePayer`, `AccountIndexOutOfRange` (legacy and v0, after lookups are known), `EmptyLookup`, `TooManyAccounts`. Oracle: 0 looser, 0 stricter, over 600,000 frames. |
| R12-02 | **P2** | `getSignatureStatuses`' `confirmationStatus` was never read: a `processed` status — one node's view of a block the cluster may still discard — produced `ApprovedAndExecuted`. A status with no `slot` read as slot 0; a `status` object with neither `Ok` nor `Err` read as "included and failed" (`ApprovedButFailedOnChain`). | **Fixed.** `InclusionCommitment` on every status and on `ExecutionVerification::Confirmed`; `processed` → `Unavailable` for an approved record, still `BlockedButExecuted` for a blocked one; missing slot / malformed status / missing or unknown commitment → `InvalidResponse` → `Unavailable`. |
| R12-03 | P2 | L8 asked one RPC two questions about one signature and never compared the answers: `getTransaction` could place it in a different slot, or report a different outcome, than `getSignatureStatuses`, and the conclusion followed the status. | **Fixed.** `ChainTransaction { bytes, slot, succeeded }`; a disagreement is `chain_inconsistent`, counted, logged, and withholds every positive conclusion; the alarm on a blocked verdict still fires. |
| R12-04 | P2 (design) | L8 had one source for inclusion. An RPC could report a signature as landed when it had not, or as unknown when it had, and nothing could show it. | **Built.** `GRAPHITE_RPC_WITNESS_URL` / `--witness-url`: a second RPC asked `getSignatureStatuses` on every reconciliation. `ApprovedAndExecuted` needs both to place the signature in the same slot with the same outcome; a witness with no record, in another slot, or unreachable withholds the conclusion (`inclusion_witness`, `graphite_execution_witness_disagreements_total`). A blocked transaction sighted by the witness alone is `BlockedButExecuted` — the bytes are fetched from the witness and bound to the signature like any other. A witness equal to the primary refuses to start. |
| R12-05 | P2 | The RPC client followed redirects (reqwest's default, ten hops): whoever answers on the RPC socket could send the request, and Graphite's trust in the answer, to any address, including a plaintext one. | **Fixed.** `Policy::none()`; a 3xx is `RequestFailed("… redirect … not followed")`. Test: the redirect target records zero hits. |
| R12-06 | P2 (operational) | Two servers on one data directory ran silently side by side, each indexing only its own appends: a verification one recorded was `NoVerificationOnRecord` to the other's L8 and lifecycle lookups, and both rewrote the semantic-graph snapshot over each other. SECURITY.md said "run one replica"; nothing enforced it. | **Fixed.** Exclusive advisory lock on `<data_dir>/graphite.lock` (`File::try_lock`) held for the life of the process; a second start refuses with the reason. |
| R12-07 | P3 | `GRAPHITE_RPC_URL=ftp://…` (or any unusable URL) started the server with "live L3/L4 enabled" in the log and every simulation Inconclusive: a misconfiguration read as a working deployment. | **Fixed.** `validate_endpoint` at startup and in the CLI: http/https only, a host, no fragment; plaintext to a non-loopback host warned; the log names the scheme and whether it is loopback, never the URL; the refusal never echoes it. |
| R12-08 | P3 | An L8 row attributed by `content_hash` wrote the resolved record's `audit_trail_id` and `transaction_sha256` onto the row keyed by the signature — a statement that this signature *is* that transaction, from an attribution that names *a* transaction carrying the instruction. Found by the Round 12 probe when the new sequence check reported the false link as a `signature conflict` against a truthful report. | **Fixed.** Exact keys are written only for `chain` / `audit_trail_id` / `transaction_sha256` attribution; the detail still says what was resolved and by which key. |
| R12-09 | P3 | `/audit/event` recorded every attestation with no view of the rows already on record for the transaction: a second submission with a different signature, a confirmation with no submission, a signing after a confirmation, or a retry all looked alike. | **Fixed.** Lifecycle rows indexed per transaction (`lc:id:` / `lc:tx:` / `lc:sig:`, at most 64 per key); `sequence_anomalies` computed and written on every row, returned with `prior_events_on_record`, counted (`graphite_lifecycle_sequence_anomalies_total`); `signature conflict` logged at ERROR. Rows Graphite writes itself are marked `observed_by_graphite` and never count as duplicates. Recorded, never refused. |
| R12-10 | P3 | A `submission`, `confirmation` or `finalization` could be reported with no `transaction_signature`, and a signature of any content up to 90 characters was accepted and forwarded to the RPC. | **Fixed.** Submission onward requires a signature; a signature must decode (base58) to 64 bytes on both `/audit/event` and `/verify/execution` — refused before any RPC call. |
| R12-11 | P3 | The bridge tried once to record the submission and then only logged the failure (audit observation 6). | **Fixed.** Three attempts with doubling backoff; a retry after a lost answer is a `duplicate` on the trail and counts as recorded; the L8 row is named as the recovery path. Two new SAK tests. |
| R12-12 | **P2 (external change)** | **Version-1 transactions are live on devnet.** The full run's `live_transactions::verify_real_devnet_transactions` failed twice (17 minutes each, "attempted 0"): every `getBlock` capped at `maxSupportedTransactionVersion: 0` is refused outright by the RPC (`-32015`) for any block holding a v1 transaction, and on 2026-09-16 that was every recent block sampled (block 499429420: 52 legacy, 1 v0, 7 v1). Round 11 ran the same test on 2026-09-15 and it passed. Graphite does not parse v1 (`UnsupportedVersion(1)`, fail-closed); the corpus discovery could not see past it. | **Fixed for discovery**: `get_block` requests version 1 and `tx_to_input` skips `"version": 1` entries by name; the test passes in 90 s (10 verified). **Open for the gate**: implementing the v1 format is now the most time-sensitive item in `CURRENT.md` — when v1 reaches mainnet, an agent that builds one is refused (an outage, not a bypass). The parse error names the format. |
| — | NOT A FINDING | SSRF through the RPC URL from a request. No handler reads an endpoint; the URL is process configuration. See the table above. | — |
| — | DOCUMENTED LIMITATION | Two RPCs behind one provider, or sharing an upstream, are two views of one answer; a light-client inclusion proof is not built. | Recorded below. |
| — | DOCUMENTED LIMITATION | The runtime oracle covers agave's bincode decode path, not its newer `wincode` path (same wire format), and the generator is seeded, not coverage-guided. The agave 5.0 crates define a **V1 message format** (4096-byte transactions, a config mask); Graphite refuses it as `UnsupportedVersion`, the fail-closed direction, and must implement it before the format activates on mainnet. | Recorded below. |
| — | DOCUMENTED LIMITATION | The lifecycle-sequence check consults the active file and, on a miss, the newest archive only. | Recorded below. |

---

## R12-01 — the runtime is the authority, and it was not being asked

**What the corpus proved and did not.** `sak_bridge_corpus.rs` requires
Graphite to agree with `@solana/web3.js` about 1,659 mutations, and it does.
web3.js is a client library: it does not apply `Message::sanitize`. Eight of
those 1,659 mutations flip an instruction's account-index byte to a value past
the key list; web3.js deserializes them, Graphite parsed them, and the
runtime refuses them. They sat in the corpus for three rounds under "both
accept".

**The oracle.** `tools/runtime-oracle` is a separate Cargo workspace depending
on `graphite-core` (featureless) and on `solana-transaction` / `solana-message`
5.0.0. For each byte string it runs the validator's packet decoder —
`bincode::DefaultOptions::new().with_limit(1232).with_fixint_encoding().reject_trailing_bytes()`
into `VersionedTransaction`, then `sanitize()` — and Graphite's
`parse_transaction`, and requires: (1) Graphite Ok ⟹ runtime Ok; (2) where
both are Ok, the message bytes (`bincode::serialize(&tx.message)` against
`message_bytes`), version, header, static keys, writable set, fee payer,
blockhash, every instruction's program, account indexes, static resolution
and data, and every lookup are equal; (3) nothing panics; (4) where Graphite
refuses what the runtime accepts, the reason is one of two deliberate ones
(`TooLarge`, `UnsupportedVersion`), else it fails. Inputs are the corpus, its
mutations (the `mutate` function ported byte for byte), and a seeded
xorshift generator; half its frames are legal by construction so the equality
comparison runs over ~150,000 accepted transactions per run.

**First run.** 200,000 frames: `FAIL: Graphite accepted 3382 byte string(s)
the runtime refuses`, including the eight corpus mutations
(`legacy_single_transfer` flips at 200 and 201, `legacy_two_signers` at
296–298, `v0_real_lookup_table` at 209–211). Reproduced end to end on the
Round 11 release binary before the fix: the transfer with its first account
index flipped to 255 verified as `artifact_bound` with a digest, L1 passed, and
L2 passed with the reason "1 of its account(s) arrive through address lookup
tables and carry an index rather than an address here" — a legacy message. It
was blocked only by the no-RPC confidence cap. With an RPC, `simulateTransaction`
sanitizes first and fails, so L3 would have blocked it; the verdict text would
still have been wrong.

**The fix** adds the runtime's remaining rules to `parse_transaction`, after
the lookup section so the v0 universe is known: `ProgramIsFeePayer` (index 0),
`EmptyLookup`, `TooManyAccounts` (> 256 static + loaded), and
`AccountIndexOutOfRange` for any index at or past the universe (legacy: the
static keys). `tests/round12_runtime_sanitize.rs` pins each without the agave
crates, and pins the pipeline: the same frame now fails L2 with the parse
reason and no mention of lookups. After the fix the oracle reports
`both accept 148,772 / both reject 152,899 / Graphite stricter: none /
looser: none` on 300,000 frames, under two seeds, in about seven seconds.

**Classification.** P2. An unexecutable frame cannot move funds; the harm was
a wrong identity claim (a digest bound to a non-transaction) and a wrong
explanation in a layer report a human reads.

---

## R12-02 to R12-04 — an RPC's word for inclusion

Round 11's rule: "the chain decides, and the RPC cannot substitute the
chain's bytes." What remained was everything around the bytes.

**Commitment.** `getSignatureStatuses` reports `confirmationStatus` —
`processed` (one node has the block), `confirmed` (a supermajority voted),
`finalized` (rooted). L8 ignored it. A single node, or a single RPC, can be the
only party that ever saw a `processed` transaction, and it can vanish in a
fork. Now: `InclusionCommitment` is parsed (a missing or unknown value is an
invalid response — the field has been in every release since v1.7), carried
on `ExecutionVerification::Confirmed`, and `processed` withholds
`ApprovedAndExecuted` with a reason that says why. The asymmetry is
deliberate: a *blocked* transaction sighted at `processed` is still
`BlockedButExecuted`, because a false alarm is the safe direction and a
suppressed one is not.

**Self-consistency.** `get_chain_transaction` now returns the slot and
`meta.err` beside the bytes. Slot ≠ status slot, or outcome ≠ status outcome,
is `chain_inconsistent`: counted, logged at ERROR, written on the trail row,
and every positive conclusion withheld. The bytes are still bound and
attributed — the contradiction is about inclusion, and the conclusion is what
is withheld.

**Malformed statuses.** No `slot`, a `status` with neither key, no or unknown
`confirmationStatus`: each is `InvalidResponse` → `Unavailable` naming
`getSignatureStatuses`. Before, the second of these was
`ApprovedButFailedOnChain` — a conclusion from a malformed answer.

**The witness.** `GRAPHITE_RPC_WITNESS_URL` attaches a second
`SolanaRpcClient` (refused if it is the primary's endpoint, or set without a
primary). `audit_execution` asks it `getSignatureStatuses` regardless of the
primary's answer and holds the two together (`compare_witness`): both no
record → agree; both the same slot and outcome → agree; anything else
→ `agrees: false` with the comparison in words. An approved record is
`ApprovedAndExecuted` only when the witness agrees; a witness with no record,
in another slot, with another outcome, or unreachable is
`Unavailable("the inclusion sources disagree: …")`. When the primary has no
record and the witness does, the bytes are fetched from the witness, bound to
the signature exactly as the primary's would be, and a blocked verdict alarms.
`/health` reports `inclusion_witness`; every reconciliation carries the
witness's report or `null`; the CLI prints it; the SDK types carry it.

**What this does not do.** Two URLs at one provider are one answer. The
witness raises the cost of a false inclusion from one endpoint to two
independent ones; a light-client proof would raise it to the cluster.

---

## R12-06 — one directory, one server

`AuditLog` builds its index of the active file at open and maintains it from
its own appends. A second process on the same directory sees a consistent
file — appends are single `writeln!` calls in append mode — but its index
never learns the other process's rows, and `find_verification` consults
archives on a miss, not the active file. So: process A verifies, process B is
asked about the execution, B answers `NoVerificationOnRecord`. Both also
rewrite `graph_state.json`. Nothing failed loudly. The server now opens
`graphite.lock` in the data directory and takes an exclusive advisory lock
(`std::fs::File::try_lock`, `flock` / `LockFileEx`) for its lifetime; the OS
releases it on any exit, including a crash. The CLI does not take it: CLI
reads build a fresh index at open and are correct, and the CLI's writes
(`evidence seed`) are operator actions that predate the lock.

---

## What was run

| Suite | Result |
|---|---|
| `cargo fmt --check`, `cargo check` (featureless, cli), `cargo clippy --all-targets --all-features -D warnings` | clean (two pre-existing featureless-build warnings gated on `rpc`) |
| `cargo test --release` | 1,486 passed, 0 failed, 11 ignored (network), 79 binaries — run three times: the first stopped at two in-module `rpc_client` mocks that lacked `confirmationStatus` (now invalid by design; the mocks were corrected), the last on the final tree |
| `cargo test --release --no-default-features --lib` | 308 passed, 0 failed |
| `cargo test --release --no-default-features --features cli` | 1,304 passed, 0 failed (one run hit a Windows linker `LNK1104` on a locked object file under `target/`; removed and rerun clean) |
| `cargo audit --deny warnings` (graphite-core) | clean, 243 crate dependencies |
| `cargo audit` (tools/runtime-oracle, informational) | 1 warning: `bincode 1.3.3` unmaintained (RUSTSEC-2025-0141) — deliberate: bincode 1 *is* the runtime decoder the oracle compares against; the crate is never shipped |
| Ignored network tests against public devnet (read-only): `live_transactions` (2), `l3_live_simulation` (3), `l8_live_mainnet` (4, now asserting the fetched signature is cluster-backed), `rpc_client` live (1) | `verify_real_devnet_transactions` **failed twice** (17 min each, "attempted 0") — R12-12, v1 transactions on devnet; after the discovery fix 10 / 10 passed, the corpus test in 90 s with 10 real transactions verified |
| Runtime oracle: corpus (12 shapes, 1,659 mutations) + 300,000 generated frames, seeds `0x5eed20260916` and `20260916` | both: `OK: Graphite is never looser than the runtime, and reads every accepted transaction the same way`; ~148,000 accepted and compared per seed |
| TypeScript SDK: build, `npm test` | 17 tests (13 hermetic + 4 live; the live ones run in the probe and in CI) |
| SAK integration: typecheck, `npm test`, corpus regeneration, drift diff | 99 tests (2 new); corpus unchanged (the Round 12 parser rules are runtime rules web3.js does not apply, so the recorded SDK verdicts stand) |
| Go SDK: gofmt, vet, `go test -count=1` | 20 tests |
| Dashboard: typecheck, production build | clean |
| Python AI layer: `pytest` (hash-locked deps) | 27 tests (one timing test failed once under the Rust matrix's load, 9,119 parses/s against a 10,000 floor; 27 / 27 on the idle machine) |
| Live probe of the release binary (`r12_probe.py`, loopback, mock primary + mock witness RPC) | 110 / 110 |
| Deliberate breaks (below) | 13 / 13 caught |

### The live probe, in outline

Everything the Round 11 probe checked (73 checks), plus: startup refusals for
an `ftp://` RPC URL, a URL with a fragment (the refusal never echoing the
secret in it), a witness equal to the primary, a witness without a primary;
a plaintext non-loopback RPC starts and is warned about; `/health` reports no
witness; a second server on the same data directory refuses while the first
holds it. L8: a `processed` status for approved A is `Unavailable` naming
`processed` with the commitment in `chain_status`, and still
`BlockedButExecuted` for B; status slot 12345 against transaction slot 12346
is `chain_inconsistent`; "included" with `null` bytes is disclosed beside the
caller attribution; a 307 is not followed and its target records no hit; a
non-signature is refused before any RPC call; `inclusion_witness` is `null`.
Lifecycle: submission without a signature 400, with a non-signature 400; a
fresh verification's signing and submission carry no anomaly; a retried
submission is a `duplicate`; a confirmation under a different signature is a
`signature conflict`. Metrics: the three new counters present and counted.
Trail: L8 rows marked `observed_by_graphite`, the conflict row carries its
anomaly, the inconsistency is named, and a `content_hash`-attributed L8 row
carries no exact keys. Server log: the inconsistency and the conflict loud;
the startup line names the scheme and "redirects not followed" and never the
URL. Then, restarted with the witness: `/health` reports it; witness agrees →
`ApprovedAndExecuted` with the report; no record → `Unavailable` "disagree";
another slot → named; primary unknown + witness saw blocked B →
`BlockedButExecuted` by `chain` from the witness's bytes; disagreements
counted; the witness line in the log names the scheme only. CLI: `execution
--witness-url` agrees; `--witness-url` equal to the primary refused; an
`ftp://` `--rpc-url` refused naming the scheme.

### Deliberate breaks

Each break edits one line of production code, runs the test meant to catch it,
and restores the file from a copy (never `git checkout`, after Round 11).

| Break (one line of production code) | Caught by |
|---|---|
| `parse_transaction` no longer refuses program index 0 | `round12_runtime_sanitize::the_fee_payer_cannot_be_a_program` |
| `parse_transaction` no longer bounds account indexes | `round12_runtime_sanitize::{a_legacy_account_index_past_the_static_keys_is_refused, a_v0_account_index_past_the_loaded_universe_is_refused, the_corpus_flip_the_runtime_refuses_is_refused, a_frame_the_runtime_refuses_fails_l2_with_the_reason}` |
| The same index break, seen by the oracle | `tools/runtime-oracle`: `FAIL: Graphite accepted 208 byte string(s) the runtime refuses` (50,000 frames) |
| A status without `confirmationStatus` reads as confirmed | `round12_rpc_equivocation::a_malformed_status_is_never_a_conclusion` |
| A `processed` status is a positive conclusion again | `round12_rpc_equivocation::a_processed_status_is_not_a_positive_conclusion` |
| A self-contradicting RPC is concluded from | `round12_rpc_equivocation::an_rpc_that_contradicts_itself_gets_no_positive_conclusion` |
| Witness dissent is ignored | `round12_rpc_equivocation::a_positive_conclusion_needs_the_witness_to_agree` |
| Redirects are followed again (`Policy::limited(10)`) | `round12_rpc_equivocation::a_redirecting_rpc_is_not_followed` |
| The primary is accepted as its own witness | `round12_rpc_equivocation::a_witness_that_is_the_primary_is_refused` |
| The signature conflict is not detected | `server::tests::lifecycle_reports_out_of_sequence_are_named_and_a_second_signature_is_loud` |
| The data-directory lock is not taken | `server::tests::a_data_directory_is_held_by_one_process` |
| An L8 row attributed by `content_hash` writes the resolved id | `server::tests::an_l8_row_attributed_by_content_hash_carries_no_exact_keys` |
| The bridge tries the submission report once | SAK `execution-lifecycle.test.ts` — 3 tests fail (`retried and lands`, `duplicate … counts as recorded`, and the attempt count on the always-failing case) |

13 / 13 caught, each on the test named for it, the tree restored from file copies and byte-identical afterwards (`git diff --stat` unchanged). Two things are not one-line breaks and are covered otherwise: the startup validation of the RPC URL and the `/health` witness flag are asserted by the live probe against the release binary; the malformed-status rules are one `match` arm each and were broken as one.

---

## What was NOT tested, and what remains outside the guarantee

- **Two agreeing RPCs are two views, not a proof.** A provider behind two URLs,
  or two providers on one upstream, can agree on a false inclusion. A
  light-client inclusion proof is not built; `inclusion_witness: null` says
  when there is no second view at all.
- **The oracle's reach.** It compares against agave's bincode decode path and
  `sanitize`; agave's `wincode` path (the same wire format, a different
  decoder) is not a second oracle. The generator is seeded and
  structure-aware, not coverage-guided.
- **Version-1 transactions.** Live on devnet now (R12-12). Graphite refuses
  them by name at the parser, L8 gets an RPC error for a v1 signature
  (`Unavailable`, with the RPC's own message), and the SAK bridge builds
  legacy/v0 only — every direction is fail-closed. The format is not
  implemented; that is the next engineering item, before it reaches mainnet.
- **The sequence check's memory.** Active file plus the newest archive; a
  lifecycle across two rotations is checked against what those hold. At most
  64 rows per key are kept.
- **The lock is the server's.** The CLI does not take it; `evidence seed`
  beside a running server is an operator action that was possible before and
  still is.
- **The Python suite's timing test** (`test_performance_smoke`, > 10,000
  parses/s) failed once at 9,119/s while the Rust release matrix saturated
  this machine and passed on re-run; a load artefact, not a regression.
- **The container job was not run locally** (no Docker daemon); it runs in
  CI. **The demo (`demo.ts`) was not run** (needs an OpenAI key and a funded
  keypair).
- Everything in `CURRENT.md` under "What is NOT enforced" still holds.

---

## Evidence

CI for this commit: GitHub Actions run 35226624158 for `97c1250` — all eight jobs (Rust core, CVE audit, Parser vs the Solana runtime decoder, Container incl. the SDK live-conformance step, TypeScript SDK + SAK, Go, Dashboard, Python) completed with `success`. "Certified" here means exactly that and nothing
more.
