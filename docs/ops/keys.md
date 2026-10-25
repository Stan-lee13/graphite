# Key and credential rotation

The server takes exactly one verify key (`GRAPHITE_API_KEY`) and at most one
operator key (`GRAPHITE_ADMIN_API_KEY`), read at startup. There is no overlap
window with two valid keys, so a rotation is a coordinated restart: the old key
stops working the moment the new process starts. Plan it as a short
maintenance window, or put an authenticating proxy in front that can hold two
keys while clients move.

Every key is at least 32 characters; the operator key must differ from the
verify key (the server refuses to start otherwise). Generate with
`openssl rand -hex 32`. Keys never belong in the image, in compose YAML, in a
shell history or in a ticket: `.env` (mode 600) or your secret store only.

## Verify key (`GRAPHITE_API_KEY`)

Held by every client: the agent guard, the SAK/MCP/Vercel adapters, the SDKs,
the dashboard.

1. Generate the new key and stage it in each client's secret store, unused.
2. Set it in `.env`, then `docker compose up -d` (recreates the container).
3. Switch each client to the new key; restart them.
4. Confirm: the old key now gets `401`; each client's next verification
   succeeds; `/metrics` shows no burst of authentication failures beyond the
   switch-over.
5. Rotate immediately, outside any schedule, if the key may have leaked: a
   verify key lets its holder submit verifications (and read the dashboard
   API), so a leaked key is a rate-limit and data-exposure problem first.

## Operator key (`GRAPHITE_ADMIN_API_KEY`)

Used only for `/admin/*` (quarantine add / lift / list). Unset disables those
routes entirely, which is the right state when nobody is using them. The CLI
(`graphite quarantine …`) works on the data directory directly and needs no
key. Rotate it the same way as the verify key; nothing but the operator's own
tooling holds it.

## RPC credentials (`GRAPHITE_RPC_URL`, `GRAPHITE_RPC_WITNESS_URL`)

These URLs usually embed a provider API key. Graphite redacts them from errors
and never logs them, but treat them as secrets. Rotate at the provider, update
`.env`, `docker compose up -d`. Keep the witness on a different provider from
the primary; after the change, `docker compose logs` shows the startup
validation of both URLs.

## Read key (`GRAPHITE_READ_API_KEY`)

Optional, Round 30. Opens only `GET /metrics`, `/manifests` and `/api/*` — the
routes the dashboard reads — and cannot submit a verification, record a
lifecycle event or reach `/admin/*`. Give it to the dashboard instead of the
verify key. It must be at least 32 characters, differ from both other keys,
and needs `GRAPHITE_API_KEY` set; the server refuses to start otherwise.
Rotate it the same way as the verify key.

## Audit MAC key (`GRAPHITE_AUDIT_KEY_FILE`)

Round 30. With this set, every audit record's chain link carries an
HMAC-SHA256 under the key, and the trail is tamper-evident against anyone who
does not hold it. The file is hex for at least 32 bytes, mode 600 or
stricter, owned by the server's user (10001 in the image), and outside
`GRAPHITE_DATA_DIR`:

```sh
openssl rand -hex 32 > audit-2026q4.key
chmod 600 audit-2026q4.key        # chown 10001:10001 for the container
```

Each record names the key it was MAC'd under (`key_id`, derived from the key),
so a rotation needs no rewrite. A key change is written INTO the chain
(Round 34): the first record under a new key is a *key-adoption record*,
MAC'd under the new key, naming the key the chain was under before. A key id
that appears with no adoption record is a break, not a rotation — that is
what a rewrite under an invented key id looks like.

1. Generate the new key file next to the old one; keep the old one.
2. Point `GRAPHITE_AUDIT_KEY_FILE` at the new file, point
   `GRAPHITE_AUDIT_PREVIOUS_KEY_FILE` at the old one, and restart. The server
   checks the newest record's MAC under the previous key, writes the
   key-adoption record, and MACs everything after it under the new key. Without
   `GRAPHITE_AUDIT_PREVIOUS_KEY_FILE` it refuses to start ("MAC'd under key …,
   not under the configured key"): it will not continue a trail whose head it
   cannot check. (`graphite quarantine` and the other writing CLI commands
   read the same two variables.)
3. **Unset `GRAPHITE_AUDIT_PREVIOUS_KEY_FILE` after that first start**
   (Round 38). It is needed for exactly one start: the one that writes the
   key-adoption record. A server started with it set while the newest record
   is not under that key logs a warning ("… is needed only for the first start
   after a key rotation"). Rotation is one-way: once the adoption record has
   moved the trail from the old key to the new one, a record under the old key
   is a break (`verify` exits 1 even with both keys), no reader reads it, and
   the server refuses to start onto one ("… which this trail retired …").
   Before Round 38 a leaked old key could keep extending the trail after the
   rotation meant to retire it, while `verify` with both keys exited 0.
4. Verify the whole trail with both keys:
   `graphite audit verify --key-file audit-2026q3.key --key-file audit-2026q4.key`.
   Exit 0 means every link and every MAC checked; with only the new key the
   older MACs cannot be checked and the walk exits 2. The text output lists
   every key id with the sequence range it covers and whether it was supplied:
   an id you never held is an incident, not a missing key file.
5. Keep retired keys for as long as you keep the records they cover, off the
   server (an attacker holding a key can rewrite what it covers; since Round 38
   it cannot add to the trail after the rotation).
6. Take a fresh backup (`deploy/scripts/backup.sh`). Since Round 38 (R37-11)
   `restore.sh` accepts an archive's `.mac` under the current key only, so a
   backup taken under the old key is refused from now on
   (backup-restore.md).

Trails rotated before Round 34 switch keys with no adoption record. They verify
(exit 0) when every key is passed; with only the new key the switch is reported
as a break (exit 1), because it cannot be told apart from an invented key id.
Since Round 38 such a switch is accepted only before the trail's first
key-adoption record (every key change since Round 34 writes one), and it
retires the key it switched away from just as an adoption does.

A lost key cannot be replaced silently: the server refuses to continue a keyed
trail without a key ("no key is configured"). With the server stopped, run
`graphite audit adopt-key --data-dir <dir> --key-file <new key>`: it walks the
trail, refuses a broken one, and writes a key-adoption record under the new key
that names the lost key as not checked. The records under the lost key then
verify as chained but not MAC'd (exit 2).

From then on that exit 2 is permanent, and `deploy/scripts/backup.sh` and
`restore.sh` refused every archive of the trail (Round 36, found by the
rehearsal in `deploy/tests/run.sh`). Pass them the lost key's id — the 16 hex
digits `graphite audit verify --key-file <new key>` prints as `NOT SUPPLIED` —
as `--lost-key <id>`. It accepts that exit 2 and nothing else: every key not
given must be named, each must be followed by a key-adoption record whose MAC
verified, the head must be under a key given, and a break, a torn write or an
unconfirmed checkpoint is still refused. A record under the lost key that was
rewritten breaks the hash chain the adoption record vouches for, so
`--lost-key` never restores one. Record the key id and the date in the
incident log; anchor a checkpoint under the new key right after the adoption
(`deploy/scripts/anchor-checkpoints.sh`).

**Adding a key to an unkeyed trail.** A server with a key refuses to resume
onto a newest record that carries no MAC: MAC'ing on top of an unkeyed history
would vouch for whatever that history holds, including a rewrite with the MACs
stripped. Check the history first (`graphite audit verify`, against a
checkpoint you anchored if you have one), then, with the server stopped, run
`graphite audit adopt-key --data-dir <dir> --key-file <key>` once. The unkeyed
records before the adoption record are then covered by its MAC (through the
hash chain) and verify; an unkeyed record after it is a break. A trail that a
pre-Round-34 server keyed without an adoption record exits 4 under its key
until `adopt-key` is run once.

**Legacy records (no chain link, written before Round 30).** Round 38 (R37-2):
a key-adoption record now lists the legacy records on disk when it is written
(a count and a SHA-256 per file). Under a key, a legacy record is covered — and
read by a server that holds the key — only when a checked adoption record
lists it; a legacy line inserted among them breaks the digest (exit 1). The
rules for `graphite audit verify` with keys:

- legacy records no checked adoption record lists: **exit 4** (not covered).
  This includes trails whose adoption was written before Round 38: run
  `graphite audit adopt-key` once more (with the same key) to list them;
- legacy records before a chain whose first record (seq 0) is MAC'd, and no
  adoption record lists them: **exit 1** — a trail keyed from genesis has no
  legacy records, so they were inserted. If you know where they came from (a
  pre-Round-30 trail a Round 30–37 server keyed at genesis), inspect them and
  run `adopt-key`, which lists them;
- a keyed server refuses to start on a trail that holds only legacy records
  ("… records without a chain link …"); `adopt-key` writes the adoption record
  at genesis that lists them.

A server that holds a key never reads a legacy record no adoption lists, so a
chain-less forgery at the top of a trail, or at the top of the oldest archive
left after a prune, is not a verdict to L8. A reader without a key reads legacy
records before the first chained record, as before.

**Run the writing CLI commands with the server's key.** `graphite evidence
seed` / `baseline`, `graphite quarantine` and the other commands that write the
trail MAC their records under `GRAPHITE_AUDIT_KEY_FILE` when it is set, and
write unkeyed records when it is not. Seeding a fresh data directory without
the key leaves an unkeyed newest record, and the keyed server then refuses to
start, as above (Round 35: the live-devnet runner did exactly this). Export
the same `GRAPHITE_AUDIT_KEY_FILE` for those commands as the server uses.

### `graphite audit verify` exit codes

| Exit | Meaning |
|---|---|
| 0 | Nothing failed: every chained record links to the one before it; every MAC under a supplied key verified; when keys are supplied, every chained record is MAC'd under one of them or covered by a key-adoption record; a `--checkpoint` is confirmed (and, when keys are supplied, MAC'd under one of them). |
| 1 | A break (an edited, inserted, deleted, reordered, copied or non-canonical line; a line that is not a record, including a torn write nothing names — `TEAR`, see incidents.md; an archive that ends without its newline; a MAC that does not verify; a key id that appears with no adoption record, or with none after the trail's first adoption record; a record under a key the chain retired at a rotation; a record of another trail (`trail` id); legacy records before a chain keyed from seq 0 that no adoption record lists, or legacy records that do not match the list an adoption record carries; since Round 38 an oldest record above seq 0 that no prune record names, and a line longer than 8 MiB), or a checkpoint that does not hold (rewritten, truncated, forged). |
| 2 | The walk could not prove what it was asked to: MACs under a key not supplied that a checked key-adoption record after them covers (an old or lost key not passed), a trail with no chained record, a checkpoint whose records were pruned. |
| 3 | The trail, a key file or the `--checkpoint` file could not be read (or the trail kept rotating under the walk on every retry). Until Round 38 an unreadable key file or checkpoint exited 1, which reads as a break. |
| 4 | Keys were supplied, but something is not covered by them: chained records with no MAC and no key-adoption record, legacy records no checked key-adoption record lists (Round 38), MACs under a key not supplied that no checked key-adoption record after them covers — a trail under none of the keys given, or a head under a key not given (Round 38, T-12; it exited 2) — or a checkpoint with no MAC or under a key not supplied. |
| 64 | A usage error (Round 38: under `graphite audit` it was clap's 2, the same as "unproven"). |

The writing `audit` commands (`adopt-key`, `acknowledge-tear`,
`acknowledge-prune`) exit 75 when another writer holds the trail (stop the
server first), 3 when a key file cannot be read, and 1 when they refuse the
trail. `graphite audit checkpoint` exits with `verify`'s code when it refuses
(see "Checkpoints" below).

**What the server reads.** Since Round 38 every reader (L8, `/audit/event`,
the dashboard, the indexes and every index read-back) walks the trail the way
`verify` does, oldest archive first, and reads a chained record only where it
continues the last record it read: the next `seq`, and `prev` that record's
hash. A genuine record copied to the end of the trail, or from another trail
under the same key, is therefore never the newest verdict and is never
counted. The server checks the MAC of every record under its own key and
`GRAPHITE_AUDIT_PREVIOUS_KEY_FILE`: once the trail is keyed, a record whose MAC
does not verify, or that carries none, is not read — a line someone forged with
a recomputed hash is not a verdict to it, even before anyone runs `verify`.
Records under an older key it does not hold are read when a key-adoption record
MAC'd under a key it holds names that key and (Round 38, R37-13) covers them
through the hash chain, as unkeyed records must be: a forgery under the old key
that replaces a record breaks the chain to the adoption, and then nothing under
the old key is read — never the forgery. (Before Round 38 such records were read
on the adoption's word alone, so a holder of the retired key could replace one
and the reader answered with the replacement.) Unkeyed
records are read only when a checked key-adoption record covers them through
the hash chain — an unkeyed line at the top of a trail keyed from genesis is
covered by nothing. A record under a key the chain retired is never read.
`graphite execution` reads with the server's keys (Round 38, T-11:
`GRAPHITE_AUDIT_KEY_FILE`, and `GRAPHITE_AUDIT_PREVIOUS_KEY_FILE` when set): run
it with the same variables as the server. A keyed trail with no key configured,
or whose newest record is under none of the keys, is refused, and the
reconciliation is unavailable (exit 3) rather than answered from a trail it
cannot check; it used to read without a key, to which a self-hashed forgery
claiming a MAC was a verdict. A reader opened without a key checks no MAC: to it
the trail is corruption-evident only. The cost is one HMAC per line read (see the delta
report / `reader_mac_check_cost_on_a_64_mib_archive`), and, once per process,
one walk of every archive: the server walks the whole trail at start, so a
start reads every archive once.

A server also refuses to start onto a newest record its readers' walk does not
reach ("… does not continue the chain the readers walk …"): a copied or
transplanted record at the end of the trail. Continuing after it would fork
the chain. Run `graphite audit verify` and move the line aside.

Since Round 39 (R39-CB-1) a server, `graphite execution` and every `graphite
audit` command that writes also refuse a trail that holds records of two
trails under one key ("… holds records of another trail under the same key
…"): a record whose trail id is not the newest record's and whose MAC
verifies, wherever it stands. The readers pin the newest record's trail id,
and a record of another trail appended at the end used to become that pin:
every genuine record then read as the other trail's, and a restarted server
resumed onto the other trail with none of its own history readable.
`graphite audit verify` names the first record of the other trail ("a record
of another trail"); move it aside, or restore the trail from a backup.

**Trail id (chain link version 2, Round 38).** Every record now carries
`chain.v = 2` and `chain.trail`, a random 16-byte id drawn when the chain
starts (at genesis, or at the first record a Round 38 writer appends to a
trail whose newest record is version 1) and repeated in every record after
it. It is hashed with the record, so the MAC binds it: a record copied from
another trail under the same key (staging and production, an HA pair) does
not fit. Version-1 records (Rounds 30–37) stay readable and verify; a
version-1 link after a version-2 one is a break. A Round 30–37 binary cannot
read version-2 records (it reports "unknown chain version 2"): upgrade every
verifier before the server. `graphite audit verify` prints the trail id. Two
data directories copied from one another share their trail id up to the copy;
give each its own key.

**Compose and systemd.** The previous key reaches the server the way the key
does: in the production compose stack, add a second secret for the old key file
and set `GRAPHITE_AUDIT_PREVIOUS_KEY_FILE: /run/secrets/audit_key_previous` for
the restart; under systemd, a second credential (`LoadCredential=audit.key.previous:…`,
`Environment=GRAPHITE_AUDIT_PREVIOUS_KEY_FILE=%d/audit.key.previous`).

Records written before Round 30 carry no chain at all ("legacy"). They are
counted and printed, accepted only before the first chained record, and, under
a key, covered only by a key-adoption record that lists them (see "Legacy
records" above).

`graphite audit verify` is safe beside a running server: a rotation or prune
during the walk is detected (the archive list changed) and the walk is
repeated.

The key file's mode is checked on Unix only. On Windows the loader does not
inspect the file's ACL: restrict it to the service account yourself
(`icacls audit.key /inheritance:r /grant:r "<service account>:R"`). The key is
wiped from memory when it is dropped.

Checkpoints (`graphite audit checkpoint --out <file>`, or automatically at
each rotation into `GRAPHITE_AUDIT_ANCHOR_DIR`) are what catch a dropped tail
or a restored older backup; ship them to storage the server cannot rewrite
(WORM, object lock) and pass one to `graphite audit verify --checkpoint`.
Since Round 38 (T-13) `graphite audit checkpoint` signs a head only when the
keys given cover it — `verify` exits 0 with them, or 2 only for MACs under a
key a checked key-adoption record closes (a lost key) — and signs it under the
key the head is MAC'd under. Otherwise it writes nothing and exits with
`verify`'s code: a head under a key not given (its MAC never checked), or a
keyed trail with no key given (an unsigned checkpoint confirms nothing under a
key). It used to sign any head the walk reached, under the first key given.

**Pruning and prune records (Round 38, R37-14).** With
`GRAPHITE_AUDIT_MAX_ARCHIVES` set, the writer deletes the oldest archives at a
rotation. It now first appends a chained *prune record* (MAC'd like any record)
naming each place the trail may start once they are gone: the first record left,
by its `seq` and its `prev` (the hash of the last record deleted). Nothing is
deleted when that record cannot be written, and deleting stops at the first
archive that cannot be removed (it used to go on past it, leaving a gap). A trail
whose oldest record on disk is above seq 0 and that no prune record names is a
break (exit 1): until Round 38 that read as "pruned", so deleting the oldest
archives, or the oldest lines of one, passed `verify` with exit 0. Readers are
unaffected: such a trail stays readable.

*Legacy rule:* a trail pruned before Round 38 has no prune record, and
`verify` reports that break (it never passes silently). Check the trail against
an anchored checkpoint or a backup that still holds the pruned records, then,
with the server stopped, run
`graphite audit acknowledge-prune --data-dir <dir> --key-file <current key>`
once: it appends a prune record (marked `acknowledged`) naming where the trail
starts now, MAC'd under the key the head is under, and refuses a trail broken by
anything else. Deleting any further archive after that is a break again. A
Round 30–38 binary cannot read a prune record ("unknown control record"):
upgrade every verifier before the server.

**Archive indexes (Round 38, R37-12).** Each archive's index
(`audit.jsonl-index/*.idx`) is now MAC'd under the trail's key (the writer's
key; a read-only reader's configured key). An index under any other key, an
unkeyed one, or one that changed after the server checked it, is not believed:
the archive is walked instead and only a writer replaces the index. They used to
carry an unkeyed SHA-256, so whoever could write the data directory could make an
index omit a transaction (the lookup fell through to an older archive's
approval), point it at another record, or change its counts, and `verify` never
reads an index. After a key rotation every index is rebuilt once, under the new
key (one parse per archive). A trail with no key keeps unkeyed indexes: to it
the index is as corruption-evident as the trail.

**A bound on a line (Round 38, T-15).** No reader, and not `verify`, holds more
than 8 MiB of one line in memory: a longer line is read past without being kept,
is never a record, and is a break (exit 1). The writer refuses to write one (the
append fails, and the verdict is not answered as recorded). No record the server
writes comes near it: a request body is at most 1 MiB.

## Registry signing keys

`graphite registry submit` signs with the ed25519 key in
`GRAPHITE_SIGNER_KEY_FILE` (or `--signer-key-file`). Keep that file mode 600 on
the reviewer's machine, never on the server. A compromised reviewer key is
revoked with `graphite registry revoke-reviewer --pubkey <base58>`; its
signatures and attestations stop counting and the tiers they helped earn are
recomputed.
