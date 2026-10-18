# Round 28 — the archives are indexed, the lifecycle is exhaustive, the contract is gated

**Date:** 2026-10-17 · **Base:** `365cbfd` (Round 27) · **Scope:** three open roadmap items that need
no owner decision: a persisted archive index (R-M11, external review W10), the lifecycle-emission
lint (R-P14) and the P13 contract gate (R-M2).

Internal engineering work. Not an independent audit and not a certification.

## 1. The archives are indexed (R-M11)

The active audit file's lookups were indexed in Rounds 9, 12 and 22. The rotated archives were not.
So every L8 count with a chain digest, and every lookup of a key older than the last rotation, read
every archive line by line, however many there were.

Each archive now has an index at `<log>-index/<archive>.idx` (`src/durable/archive_index.rs`). It
holds:

- for each verification key, the last record's offset and the approved and refused counts;
- for each lifecycle key, its rows' offsets;
- a header with the archive's length and SHA-256;
- a trailing SHA-256 of the whole file.

The file is fixed-width and sorted, so a lookup is a binary search by seeking: about twenty 32-byte
reads for a 64 MiB archive. None of it is held in memory, because archives are kept indefinitely
by default, and loading every index would grow memory with the trail.

**What the index is trusted for, and how.**

- It is checked against its archive once per process: magic, version, a length the header
  accounts for exactly, its own trailer, and the archive's length and SHA-256. An index that fails
  any check is rebuilt from one parse of the archive.
- A lookup reads its record back from the archive and matches it before returning it. An offset
  that does not read back discards the index, the archive is scanned, and the next lookup checks
  and rebuilds.
- An index that cannot be written (a read-only directory) is remembered as unavailable. That
  archive is scanned on each lookup, as before this round, and not rebuilt each time.

**When the work happens.**

- **Rotation.** The new archive's index is written on a background thread from the indexes the
  active file kept while it was written, so nothing is parsed. This happens only when those
  indexes account for exactly the archive's bytes.
- **Server start.** Every archive's index is checked, or built, in the background
  (`AuditLog::warm_archive_indexes_in_background`). Index files that describe no archive, and
  temporary files from a stopped write, are removed.
- **Pruning.** An archive's index is removed with it, and the same sweep runs afterwards.

**Measured** (`durable::tests::archive_index_cost_on_64_mib_archives`, release build, three
archives of 64 MiB with 144,322 records each):

| Operation | Time |
|---|---|
| A count by scanning (the path before this round) | 822 ms |
| The first count, building three indexes from a parse | 6.7 s |
| An indexed count (median of 200) | 2.2 ms |
| An indexed miss (median of 200) | 3.5 ms |
| The first count after a restart (checking three indexes) | 1.8 s |

The index files take 49 MB for 192 MiB of archives, about a quarter.

Tests, in `durable::tests`:

- lookups, counts and lifecycle history answer from the index, with no scan, before and after a
  restart;
- a flipped byte, a truncated file, another version, and an archive changed at the same length
  are each rebuilt;
- an offset that does not read back is never the answer;
- an unwritable index falls back to one scan per lookup, not one build;
- pruning removes the index;
- rotation indexes without a parse;
- the warm-up checks every archive and sweeps stale files.

Breaks B112–B120.

## 2. Every lifecycle event has an emitter (R-P14)

Constitution P9 asks for an audit event at every lifecycle stage. Nothing made a new stage name
where it is recorded.

`LifecycleEvent::emission` now does, in a `match` with no wildcard, so a new event does not compile
until it has an emitter. There are three kinds:

- **`GraphiteRow`:** Graphite performs the stage and writes the row. Verification at `/verify`;
  operator actions at `/admin/quarantine`.
- **`CallerReported`:** the caller reports the stage at `POST /audit/event`. Signing, submission
  and finalization; confirmation too, which Graphite also writes itself at `/verify/execution`.
- **`OnTheVerificationRow`:** construction and simulation have no row of their own. A verification
  is the only path that constructs or simulates, and its row records both: `content_hash` for the
  plan it judged, `l3_status` for the simulation layer. A row each would be two more device syncs
  per verdict, carrying nothing the verification row does not. This is a recorded choice, not a gap
  closed.

`is_self_observed`, which decides what a caller may report, is now read from this table.
`LifecycleEvent::ALL` is checked against the variants serde derives.

`server::tests::every_lifecycle_event_reaches_the_trail` drives every emitter and reads each row
back. It also checks that a stage on the verification row has its field there, filled.

Writing it found that `a_caller_cannot_forge_a_self_observed_event` never named `operator_action`
(R28-2). Nothing but `is_self_observed` stood between a caller and a forged "quarantine lifted" row.
The test now names all four self-observed events, written out by hand so that a change to the table
fails it.

The `LifecycleEvent` documentation pointed to a `GraphiteCore::record_lifecycle_event` that does
not exist (R28-3). It now names `POST /audit/event`.

Breaks B121–B123.

## 3. The contract is gated (R-M2)

P13: a breaking change needs a version bump and a CHANGELOG entry saying what broke.

`tests/contract_version_gate.rs` diffs both published schemas against the last release tag. What
breaks depends on who writes the document:

- **`verification-result-v1.json` (Graphite writes it):** a break is removing a field, widening a
  type or an enum, dropping a required field, loosening a bound, opening a closed object, or adding
  a field to a closed one.
- **`proposed-intent-v1.json` (the caller writes it):** a break is removing a field, narrowing a
  type or an enum, requiring a field, tightening a bound, or closing an object.

When anything breaks, the crate's version must differ from the tag's, and the CHANGELOG's section
for the crate's version must name every broken path. Descriptions do not count.

In CI the job checks out the whole history and sets `GRAPHITE_CONTRACT_GATE_REQUIRED=1`. Without
the history the gate cannot run, and there it fails rather than being skipped.

**The gate's first run failed (R28-1).** It found two breaks to the caller's input since
`v0.2.0-beta` (2026-08-12), both shipped under that same version:

- `extracted_parameters` is closed. An unknown parameter is refused, not dropped (W22, Round 24).
- `intent_type` no longer lists `lend`. The schema advertised it until `5fd1dc3`, although the
  engine never accepted it.

Neither was a mistake in the Core: W22 is a security fix, and `lend` was never served. But a caller
validating against the tag's schema could be refused, and nothing said so.

The crate is now `0.3.0-beta`, and the CHANGELOG's `0.3.0-beta` section names both breaks. On the
output side, nothing broke since the tag: every change adds a field, narrows a type, or requires a
field that was always present. Tagging the release remains the owner's decision.

`the_breaking_rules_follow_who_writes_the_document` tests each rule on schemas written for the
purpose, so the rules are checked whether or not a tag is reachable. Breaks B124, B125.

## 4. Verified

- 1,934 Rust tests pass in the all-features suite (137 binaries, 13 ignored), 363 in the
  featureless library build and 1,654 in the cli-only build.
- Clippy `-D warnings` is clean on all three feature legs, and fmt is clean.
- The runtime oracle is never looser than agave on both CI seeds.
- 14 of 14 deliberate breaks (B112–B125) were caught.

The first all-features run failed one test: `docs_paths_resolve` found
`graphite-core/README.md` naming `durable/archive_index.rs` without its `src/` prefix. The
path was corrected and the test passes.
The first clippy run failed on two lints in the new code (`unnecessary_sort_by` in
`archive_index.rs`, `manual_is_multiple_of` in a durable test). Both were rewritten, and the
durable tests were run again with clippy on all three legs.

## 5. Still open

Recorded in `AUDIT/02-roadmap-gap.md`:

- per-instruction L3 baselines (A2-08);
- owner configuration (R-M13);
- honest intents for withdrawals and claims (R-M14);
- the guard's public API on web3.js 1.x (R-M15);
- scheduled mutation, fuzz and coverage runs (R-P11/12/15);
- the release-evaluation report (R-P1);
- the owner's items: an independent audit, branch protection, deployment, and tagging `0.3.0-beta`.
