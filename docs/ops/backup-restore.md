# Backup and restore

What to back up: the whole `graphite-data` volume (`/data`). It holds the
audit trail, the semantic-graph snapshot and `registry_state.json`. The `.env`
file holds secrets and is backed up separately, by your secret store, never
alongside the data.

## Cold backup (consistent; the server is stopped)

```sh
docker compose stop graphite
docker run --rm -v graphite_graphite-data:/data:ro -v "$PWD/backups":/out \
  debian:bookworm-slim tar -C /data -czf "/out/graphite-data-$(date -u +%Y%m%dT%H%M%SZ).tgz" .
docker compose start graphite
```

The volume name is `<project>_graphite-data`; `docker volume ls` shows it
(`graphite_graphite-data` when the checkout directory is `graphite`).

Record the archive's SHA-256 next to it (`sha256sum`) and copy both off the
host. An audit trail kept only on the machine it audits is lost with that
machine.

## Hot backup (the server keeps running)

The audit file is append-only and each record is written whole, so a copy
taken while the server runs is a valid trail up to some record; the last line
may be partial and is the one to distrust. The graph snapshot is replaced
atomically, so a copy is one complete snapshot. Use the same `docker run …
tar` command without stopping the service, then prefer a cold backup for
anything you will restore from.

## Restore

1. `docker compose stop graphite`.
2. Empty the volume and unpack the archive into it:
   ```sh
   docker run --rm -v graphite_graphite-data:/data -v "$PWD/backups":/in debian:bookworm-slim \
     sh -c 'find /data -mindepth 1 -delete && tar -C /data -xzf /in/<archive>.tgz && chown -R 10001:10001 /data'
   ```
   The ownership step matters: the server runs as UID 10001 and refuses to
   start on a data directory it cannot write.
3. `docker compose start graphite`, then check `docker compose ps` (healthy)
   and `/health` (`degraded: false`).
4. Note the restore in your incident log: verdicts issued after the backup was
   taken are not in the restored trail.

## Test the restore

A backup that has never been restored is a hope. Once per release, restore the
latest backup into a scratch volume and start a second, throwaway server on it
(different project name and port), then confirm `/health` and the dashboard
totals. Never point two servers at the same volume: the second refuses to start
(`graphite.lock`), which is the lock working.
