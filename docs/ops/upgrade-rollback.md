# Upgrade and rollback

State lives on the `graphite-data` volume (`/data` in the container): the
append-only audit trail (`audit.jsonl`, its rotated archives
`audit.jsonl.<stamp>-<seq>` and their indexes under `audit.jsonl-index/`), the
semantic-graph snapshot (earned evidence, simulation baselines, quarantines),
`registry_state.json`, and `graphite.lock` while a server runs. The image holds
no state; manifests are compiled into the binary.

A newer release may write state an older binary cannot read. That is why every
upgrade starts with a backup, and why a rollback restores that backup rather
than pointing the old binary at the new state.

## Upgrade

1. Read the release's CHANGELOG entry and `docs/CURRENT.md` for anything that
   changes a verdict, a schema field or an environment variable. A new
   required variable, or a removed one (the server refuses to start on some
   retired settings), is the most common upgrade failure.
2. Confirm CI was green on the release commit (`CI gate`).
3. Back up the volume (backup-restore.md, "Cold backup"). Keep it until the
   new release has run cleanly for at least one full day.
4. Build and start the new release:
   ```sh
   git fetch --tags && git checkout v<new>
   docker compose build
   docker compose up -d          # recreates the container; the volume is kept
   docker compose ps             # (healthy)
   docker compose logs --since 5m graphite | grep -iE 'refus|error|warn'
   ```
   The compose stop grace is 30 s, so the old process drains its open
   requests (at most 10 s) before it is killed; every record is already on
   disk. With `deploy/compose/docker-compose.prod.yml`, set `GRAPHITE_IMAGE`
   and `GRAPHITE_IMAGE_DIGEST` in `deploy/compose/.env` to the new verified
   release (production-checklist.md, 10e) and run
   `docker compose -f docker-compose.prod.yml pull graphite && docker compose -f docker-compose.prod.yml up -d graphite`
   instead of building. Either way it is a stop and a start of the one Core,
   never a rolling update: two Cores cannot share the data volume.
5. Check: `/health` shows `degraded: false`; one known-good verification
   through your client still returns the verdict you expect; the dashboard's
   totals continued from where they were (the trail was read, not restarted).

## Rollback

1. `docker compose stop graphite`.
2. **Keep what the new release wrote.** Copy the volume's audit files aside
   before anything else (backup-restore.md, "Cold backup", to a separate
   directory). Those records are part of the trail even though the release
   is being withdrawn; never delete them.
3. Restore the pre-upgrade backup into the volume (backup-restore.md,
   "Restore").
4. `git checkout v<old> && docker compose build && docker compose up -d`.
5. Record the gap: the restored trail does not contain the records written by
   the withdrawn release. Keep the copy from step 2 with the incident notes,
   and reconcile any transaction signed in that window with
   `graphite execution` against the copy (`--data-dir <copy>`).

## Changing a single setting

`docker compose up -d` after editing `.env` recreates the container with the
new environment. Settings are read once at startup, and a malformed value
refuses to start rather than falling back, so check `docker compose ps` and
the logs after every change.
