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
   cannot check. The variable may stay set; it is read only when the newest
   record is under that key. (`graphite quarantine` and the other writing CLI
   commands read the same two variables.)
3. Verify the whole trail with both keys:
   `graphite audit verify --key-file audit-2026q3.key --key-file audit-2026q4.key`.
   Exit 0 means every link and every MAC checked; with only the new key the
   older MACs cannot be checked and the walk exits 2. The text output lists
   every key id with the sequence range it covers and whether it was supplied:
   an id you never held is an incident, not a missing key file.
4. Keep retired keys for as long as you keep the records they cover, off the
   server (an attacker holding a key can rewrite what it covers).

Trails rotated before Round 34 switch keys with no adoption record. They verify
(exit 0) when every key is passed; with only the new key the switch is reported
as a break (exit 1), because it cannot be told apart from an invented key id.

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
| 1 | A break (an edited, inserted, deleted, reordered or non-canonical line; a line that is not a record, including a torn write nothing names — `TEAR`, see incidents.md; an archive that ends without its newline; a MAC that does not verify; a key id that appears with no adoption record), or a checkpoint that does not hold (rewritten, truncated, forged). |
| 2 | The walk could not prove what it was asked to: MACs under a key not supplied, a trail with no chained record, a checkpoint whose records were pruned. |
| 3 | The trail could not be read (or kept rotating under the walk on every retry). |
| 4 | Keys were supplied, but something is not covered by them: chained records with no MAC and no key-adoption record, or a checkpoint with no MAC or under a key not supplied. |

**What the server reads.** The server checks the MAC of every record it reads
under its own key and `GRAPHITE_AUDIT_PREVIOUS_KEY_FILE` (L8, `/audit/event`,
the dashboard, the indexes): once the trail is keyed, a record whose MAC does
not verify, or that carries none, is not read — a line someone forged with a
recomputed hash is not a verdict to it, even before anyone runs `verify`.
Records under an older key it does not hold are read when a key-adoption record
MAC'd under a key it holds names that key (they cannot be checked; keep the
previous key configured to have them checked). Unkeyed records before a key
adoption are read as they are. A reader without a key (`graphite execution`)
checks no MAC: to it the trail is corruption-evident only. The cost is one
HMAC per line read (see the delta report / `reader_mac_check_cost_on_a_64_mib_archive`).

**Compose and systemd.** The previous key reaches the server the way the key
does: in the production compose stack, add a second secret for the old key file
and set `GRAPHITE_AUDIT_PREVIOUS_KEY_FILE: /run/secrets/audit_key_previous` for
the restart; under systemd, a second credential (`LoadCredential=audit.key.previous:…`,
`Environment=GRAPHITE_AUDIT_PREVIOUS_KEY_FILE=%d/audit.key.previous`).

Records written before Round 30 carry no chain at all ("legacy"). They are
counted and printed, never covered by a MAC, and accepted only before the
first chained record.

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

## Registry signing keys

`graphite registry submit` signs with the ed25519 key in
`GRAPHITE_SIGNER_KEY_FILE` (or `--signer-key-file`). Keep that file mode 600 on
the reviewer's machine, never on the server. A compromised reviewer key is
revoked with `graphite registry revoke-reviewer --pubkey <base58>`; its
signatures and attestations stop counting and the tiers they helped earn are
recomputed.
