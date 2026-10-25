# Backup and restore

What to back up: the whole `graphite-data` volume (`/data`). It holds the
audit trail, the semantic-graph snapshot and `registry_state.json`. The `.env`
file and the audit MAC key hold secrets and are backed up separately, by your
secret store, never alongside the data.

Use the scripts, not a bare `tar`: `deploy/scripts/backup.sh` keeps an archive
only when `graphite audit verify` passes on the copy, and
`deploy/scripts/restore.sh` proves an archive (its checksum, its MAC, its
trail, and the newest anchored checkpoint) before anything is moved. A plain
`tar` round trip does none of that: it restores a tampered or stale archive as
readily as a good one. Both are rehearsed end to end against a real Core by
`deploy/tests/run.sh` (deploy/README.md).

The scripts take a directory path. On a compose host that is the volume's
mountpoint (run them as root, or as the volume's owner):

```sh
DATA="$(docker volume inspect graphite_graphite-data --format '{{.Mountpoint}}')"
```

The volume name is `<project>_graphite-data`; `docker volume ls` shows it
(`graphite_graphite-data` for the production compose file, whose project name
is `graphite`). With systemd the directory is `/var/lib/graphite`.

## Cold backup (consistent; the server is stopped)

```sh
STOP_CMD="docker compose -f deploy/compose/docker-compose.prod.yml stop graphite" \
START_CMD="docker compose -f deploy/compose/docker-compose.prod.yml start graphite" \
  deploy/scripts/backup.sh --key-file deploy/compose/secrets/audit_key "$DATA" /srv/graphite-backups
```

(systemd: `STOP_CMD="systemctl stop graphite" START_CMD="systemctl start graphite"`,
`--key-file /etc/graphite/audit.key`, `/var/lib/graphite`.) The script refuses
to copy while a server still holds `graphite.lock` after `STOP_CMD`, so a stop
command that did not stop it is caught. Pass every audit key the trail was
written under (`--key-file`, repeatable, in any order).

It writes `graphite-<stamp>.tar.gz`, its `.sha256` and `<archive>.mac`: an
HMAC-SHA256 over the archive's name and bytes (Round 34, R33 D-6) under the
**current** audit key — the key the copied trail's head is MAC'd under, which
the verify checked (Round 38, R37-11; it used to be the last `--key-file`
given, a retired key whenever that one was listed last). A keyed head whose key
is not among those given refuses the backup. Copy all three off the host: an
audit trail kept only on the machine it audits is lost with that machine.

`restore.sh` accepts the `.mac` under the current key only: `--current-key-file
<file>`, else `GRAPHITE_AUDIT_KEY_FILE`, else the `--key-file` when exactly one
is given; with several keys and none named current it refuses (exit 64). It
used to accept a MAC under any key it was given, so whoever still held a
retired key could forge `registry_state.json` or the graph snapshot and MAC
the archive under that key: a retired key's MAC proves nothing about when the
archive was made. A backup taken before a key rotation is therefore refused
after it: take a fresh backup after every rotation. To restore such a backup
anyway, name its key with `--current-key-file` — your explicit decision, for
the incident log. `restore.sh` also refuses an archive without a `.mac`
(`ALLOW_UNKEYED_ARCHIVE=1` for a deployment with no audit key), a `.sha256`
that names any file but the archive itself, and a run without `--anchor-dir`
(`ALLOW_NO_ANCHOR=1` to override, recorded in your drill notes). The `.sha256`
alone detects corruption, not substitution: anyone who can write the backup
store can write a matching checksum, but not a matching MAC.

## Hot backup (the server keeps running)

`deploy/scripts/backup.sh --hot --key-file <key> "$DATA" <out>`. The audit file
is append-only and each record is written whole, so a copy taken while the
server runs is a valid trail up to some record; the script cuts the active file
at its last complete line, verifies the copy and retries if a rotation raced
it. The graph snapshot is replaced atomically, so a copy is one complete
snapshot. Use it for incident preservation (incidents.md); prefer a cold
backup for anything you plan to restore from.

## Restore

1. Stop the Core (`docker compose -f deploy/compose/docker-compose.prod.yml stop graphite`,
   or `systemctl stop graphite`). `restore.sh` refuses (exit 75) while a server
   holds the directory's lock.
2. Restore, naming every audit key and the anchor directory:
   ```sh
   deploy/scripts/restore.sh --key-file <every audit key> --anchor-dir <anchors> \
     --owner 10001:10001 /srv/graphite-backups/graphite-<stamp>.tar.gz "$DATA"
   ```
   (systemd: no `--owner`; `StateDirectory=` fixes the ownership at start.)
   With more than one `--key-file`, name the current one with
   `--current-key-file` (or set `GRAPHITE_AUDIT_KEY_FILE`).
   The previous directory is kept beside it as `<dir>.pre-restore-<stamp>`.
   The newest anchored checkpoint is the one whose content has the highest
   `seq` (Round 38, T-9: never chosen by file name, which nothing
   authenticates); a checkpoint file in the anchor directory that cannot be
   read refuses the restore.
   An archive older than the newest anchored checkpoint is refused until
   `ACCEPT_STALE_RESTORE=1`: the verdicts recorded after it are lost, and that
   belongs in the incident log first. After a lost audit key, add
   `--lost-key <key id>` (keys.md).
3. Start the Core, then check `docker compose ps` (healthy) and `/health`
   (`degraded: false`).
4. Note the restore in your incident log: verdicts issued after the backup was
   taken are not in the restored trail.

## Test the restore

A backup that has never been restored is a hope. Once per release, restore the
latest backup into a scratch directory on another host (or a scratch volume
with a different project name and port), start a throwaway server on it and
confirm `/health` and the dashboard totals. Never point two servers at the same
volume: the second refuses to start (`graphite.lock`), which is the lock
working — one Core per data directory, always (production-checklist.md, 9g).
