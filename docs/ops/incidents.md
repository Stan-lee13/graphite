# Incident runbooks

Each section: the signal, what it means, what to do. `/health` answers without
a key and names every reason in `degraded_reasons`; `/metrics` is behind the
verify key.

## Disk full / audit writes failing

**Signal:** `degraded_reasons` contains `audit_writes_failed` or
`audit_rotation_failed` or `graph_snapshot_failed`; the compose container turns
`unhealthy`; clients start getting `503` on `/verify`.

**Meaning:** a verdict the audit trail cannot record is refused, so the node is
failing closed: it is safe but not serving. A failed snapshot means evidence
and baselines earned since the last good snapshot exist only in memory.

1. Do not restart yet: a restart drops the in-memory state a failed snapshot
   did not save.
2. Free space on the volume's filesystem (`df -h` on the host; `docker system
   df` for images and build cache). Never delete anything under the data
   volume to make room: it is the audit trail.
3. If `GRAPHITE_AUDIT_MAX_ARCHIVES` is `0` (keep every archive, the default),
   move old `audit.jsonl.<stamp>-<seq>` archives to off-host storage
   (backup-restore.md) rather than deleting them; their indexes under
   `audit.jsonl-index/` are rebuilt when needed.
4. The failure counters do not reset while the process runs. Once writes
   succeed again, confirm new records land (`writes_ok` rising on `/health`),
   then restart during a quiet moment to clear `degraded`.
5. Record the window in which verdicts were refused.

## Audit-integrity alert

**Signal:** server log lines about an archive index that did not check out
(rebuilt), an archive that could not be read, or a record that failed to read
back; `/metrics` read errors; a dashboard total that went backwards.

**Meaning:** the audit trail is corruption-evident (lengths and SHA-256 of
archives are checked when indexed; records are read back and matched). It is
not tamper-proof against someone who can write to the volume: such a person
can rewrite a file and its index consistently.

1. Stop writes from going anywhere unexpected: snapshot the volume as it is now
   (backup-restore.md, cold backup) before touching anything.
2. Compare the affected archive with the copy in your last off-host backup
   (`sha256sum`). An archive that changed after rotation was modified: treat it
   as a security incident (below).
3. If it is disk corruption, restore the archive from backup; the index is
   rebuilt on the next read.

### `graphite audit verify` reports a `TEAR`

A line that is not JSON, that no record after it names, is a break (exit 1)
(Round 34). A writer from Round 34 on names the partial line a crash left when
it resumes past it, so this is either a crash a pre-Round-34 writer resumed
past, or bytes someone added. `verify` lists each one (`TEAR  <file> line L
(byte N, …)`) and still walks every record after it.

1. Inspect the line (`tail -c +$((N+1)) <file> | head -c 200`). A crash leaves
   the first part of a record, cut anywhere; anything else is an incident.
2. Compare with your last backup taken after that write: the same bytes in the
   same place.
3. With the server stopped, accept it:
   `graphite audit acknowledge-tear --data-dir <dir> --file <file> --offset N`
   (with `--key-file`, or `GRAPHITE_AUDIT_KEY_FILE`, on a keyed trail). It
   walks the trail first and refuses a trail broken by anything else; it
   appends a chained record (MAC'd when keyed) naming exactly those bytes at
   that place. A line that is JSON is never a tear and cannot be acknowledged.
4. `graphite audit verify` then counts it under `unparseable` and exits 0 if
   nothing else is wrong. Changing the acknowledged bytes makes it a break
   again.

## RPC degraded or down

**Signal:** verdicts with `not_simulated`, L3 `inconclusive`, refusals naming
the RPC; `graphite execution` exit code `3`; provider status page.

**Meaning:** without simulation no verdict is safe to sign on, and clients that
follow the residual policy refuse. That is the intended failure mode: an RPC
outage stops signing, it does not let unsimulated transactions through.

1. Confirm with the provider. Switching providers is a key change (keys.md,
   RPC credentials) and a restart.
2. Do not relax a client's accepted residuals to keep traffic flowing. That
   turns an outage into unverified signing.
3. If the witness (`GRAPHITE_RPC_WITNESS_URL`) is the one down, L8 checks fail
   with exit code `6`; verification itself is unaffected.

## Program upgrade detected

**Signal:** `/health` → `program_upgrades.detected` rising; the metric
`graphite_program_upgrades_detected_total`; the verdict's `program_upgrades`
field names the program and the change (redeploy or new upgrade authority).
Needs `GRAPHITE_RPC_URL`.

**Meaning:** the code behind a program changed since Graphite last saw it. With
`GRAPHITE_QUARANTINE_ON_UPGRADE=1` it is already quarantined (tier forced to
Unknown) until an operator lifts it; with `0` (default) it is reported only.

1. Identify the change: the protocol's release notes, its verified build, the
   new upgrade authority.
2. Review the manifest against it: `graphite protocol status --program <id>`,
   and `graphite protocol diff --manifest <candidate.json>` if the manifest
   needs to change.
3. To withdraw trust while you review, on a running server:
   ```sh
   curl -s -X POST -H "Authorization: Bearer $GRAPHITE_ADMIN_API_KEY" \
     -H 'content-type: application/json' \
     -d '{"program_id":"<id>","reason":"upgrade under review"}' \
     http://127.0.0.1:7331/admin/quarantine
   ```
   (or stop the server and use `graphite quarantine add --program <id>
   --reason "…"`; the CLI refuses to write while a server holds the lock).
4. Lift with `{"program_id":"<id>","lift":true}` (or `graphite quarantine
   lift --program <id>`) once reviewed. The tier is recomputed from evidence.

## Failed finalization / L8 discrepancy

Run `graphite execution --signature <sig> --transaction-sha256 <digest>
--audit-trail-id <id>` (or POST `/verify/execution`) for each signed
transaction, with the server's `GRAPHITE_AUDIT_KEY_FILE` set (Round 39: a keyed
trail is not read without its key, and the check is then unavailable, exit 3).
Exit codes:

| Code | Meaning | Action |
| --- | --- | --- |
| 0 | reconciled | none |
| 1 | **DISCREPANCY: a transaction Graphite blocked executed anyway** | security incident (below) |
| 3 | unavailable (no RPC answer, no audit trail, configuration error) | retry; RPC runbook above |
| 4 | the RPC returned bytes not bound to the signature | treat the primary RPC as faulty or hostile; switch provider |
| 5 | the primary RPC contradicted itself about the signature | same as 4 |
| 6 | the witness disagreed, or could not be asked | compare providers by hand; do not trust either alone |

A transaction that never finalizes is not a Graphite fault: check the
blockhash expiry and the fee market, and never re-submit a different build of
it without a fresh verification.

## Security incident

Triggers: L8 exit code `1`, a modified audit archive, a leaked key, a
verification you cannot explain.

1. Preserve: cold-backup the volume, copy logs (`docker compose logs`), record
   the times.
2. Contain: rotate the exposed keys (keys.md); quarantine the programs
   involved; stop the signing agents if the gate itself is in doubt.
3. Report privately per SECURITY.md, never in a public issue.
4. Reconcile every transaction signed in the window with `graphite execution`.
