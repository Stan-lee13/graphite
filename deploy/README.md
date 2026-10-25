# Deploying Graphite Core

Production configuration for one Graphite Core node, in two forms (pick one),
plus the monitoring and the operational scripts both share. The runbooks in
[`docs/ops/`](../docs/ops/README.md) say when to use each piece; the go-live
list is [`docs/ops/production-checklist.md`](../docs/ops/production-checklist.md).

| Path | What it is | Checked by |
|---|---|---|
| `compose/docker-compose.prod.yml` | Caddy (TLS) + ONE Core (fixed `container_name`, `deploy.replicas: 1`) from a released image pinned by digest (`GRAPHITE_IMAGE` + the required `GRAPHITE_IMAGE_DIGEST`) + the optional AI layer (`--profile ai`); every key a file-backed secret | `docker compose config`, overrides with 2 replicas refused, the hardening read as data |
| `systemd/graphite.service` | The Core as a hardened systemd service (`systemd-analyze security`: 1.1), one instance (not a template), behind Caddy on the same host | `systemd-analyze verify`, exposure < 2 |
| `systemd/graphite-anchor.{service,timer}` | Hourly checkpoint export and off-host anchoring (the server's sandbox; exposure 1.1) | `systemd-analyze verify`, exposure < 1.5 |
| `systemd/graphite.env.example` | The service's `/etc/graphite/graphite.env` | — |
| `caddy/Caddyfile` | TLS, HSTS, a 1 MiB body limit (the Core's; since Round 34 a declared `Content-Length` over it is answered 413 at the edge, before anything is proxied), and only `/verify`, `/verify/execution`, `/audit/event` (POST), `/manifests`, `/api/*` (GET) reachable; `/health`, `/metrics`, `/admin/*` answer 404 at the edge | `caddy validate`, `caddy fmt` |
| `prometheus/graphite-alerts.yml` | 19 alerts on the series the server exports and on `/health`'s degraded reasons | `promtool check rules`, `promtool test rules` (`graphite-alerts.test.yml`: every alert fires in one case and stays quiet in another) |
| `prometheus/prometheus.example.yml` | Scrape config with the read key | `promtool check config --syntax-only` |
| `grafana/graphite-dashboard.json` | Verdicts, refusals, L8, audit trail | every query parsed by promtool; every series exists in `server.rs` |
| `scripts/health-textfile.sh` | `/health` `degraded_reasons` → `graphite_health_degraded{reason=…}` for node_exporter | `deploy/tests/run.sh` |
| `scripts/backup.sh` | Cold (stop/copy/start) or `--hot` backup; kept only if `graphite audit verify` passes on the copy; `.sha256` and a `.mac` (HMAC-SHA256 of the archive under the audit key) beside it; `--lost-key` after a lost audit key | same |
| `scripts/restore.sh` | `--anchor-dir` required; a `.sha256` naming the archive itself, then its `.mac` under the current key (`--current-key-file`); verify the unpacked trail and against the newest anchored checkpoint (by content), then swap it in, keeping the old directory; `--lost-key` | same |
| `scripts/anchor-checkpoints.sh` | `graphite audit checkpoint` into the anchor directory; optional upload to an S3 Object-Lock bucket | same (the S3 upload is not exercised: see below) |
| `scripts/rotate-keys.sh` | New API key in an env file or secret file (keeping the file's owner, or an explicit `UID:GID`), new audit MAC key, verify the trail under every key | same |
| `tests/run.sh` | All of the above, against a real Core and Caddy on loopback; plus a second Core on a live data directory, SIGTERM with a verdict in flight, a lost audit key, and a full data directory | — |

## Run the checks

```sh
cargo build --release --locked --features server,cli --manifest-path graphite-core/Cargo.toml
GRAPHITE_BIN=$PWD/graphite-core/target/release/graphite deploy/tests/run.sh
```

It needs `caddy`, `promtool`, `shellcheck`, `curl`, `jq`, `openssl`, `flock` and
Python 3 with PyYAML; `systemd-analyze`, `docker compose` and `unshare` (the
full-disk case mounts a 256 KiB tmpfs in an unprivileged user+mount namespace)
are used when present and reported as skipped otherwise (the full-disk case
needs no root). Override any binary with
`CADDY_BIN`, `PROMTOOL_BIN`, `SHELLCHECK_BIN`. It starts the Core and two
Caddy instances on free loopback ports in a temporary directory and removes
everything when it exits. Exit 0 only when every check passed.

## Choices worth knowing

- **One proxy hop.** Both forms set `GRAPHITE_TRUST_PROXY=1`. Caddy replaces
  any `X-Forwarded-For` a client sends (no `trusted_proxies` is configured),
  so the right-most entry the Core reads is the address Caddy saw; the test
  shows a client rotating that header still hits its own rate limit. Put
  another proxy or a load balancer in front and the hop count changes — set
  it to the real number, never higher.
- **Only the proxy is believed.** `GRAPHITE_TRUSTED_PROXIES` names the one
  address whose `X-Forwarded-For` the Core reads (Round 40): `127.0.0.1,::1`
  in the systemd unit, where Caddy reaches the Core over loopback; Caddy's
  fixed address `10.73.31.2` on the compose backend network (subnet
  `10.73.31.0/24`, dynamic addresses from `.128` up). Any other peer — the AI
  layer, or anything else that can reach the Core — is keyed by its own
  address, so it cannot choose a rate-limit bucket. The Core refuses to start
  with a hop count and no list.
- **`/health` and `/metrics` stay private.** Probe and scrape the Core on its
  private address. Operators reach `/admin/*` through an SSH tunnel, or not at
  all: leave the admin key empty and those routes are disabled.
- **The audit key and the anchors live outside the data volume.** systemd
  hands the key over as a credential (`LoadCredential=`); compose as a secret
  owned by the image's user (10001). A checkpoint on the same host protects
  nothing against whoever controls the host: ship them off it
  (`ANCHOR_S3_URI`, Object Lock in COMPLIANCE mode).
- **Scheduled checkpoints never take the server's file name.** The server
  creates `audit.jsonl-checkpoint-<seq>.json` exclusively at each rotation; the
  script writes `…-<seq>-scheduled.json`, so the two can never collide (a
  collision would fail the server's anchor write and degrade `/health`).
- **Backups exclude the key.** Back it up separately, to a different place.
  A restore without every key that signed the trail cannot verify its MACs
  (`graphite audit verify` exit 2) and `restore.sh` refuses it.
- **A backup is authenticated whole, not only its trail (Round 34).**
  `graphite audit verify` walks the audit trail; the graph snapshot and
  `registry_state.json` in the same archive were covered only by an unkeyed
  `.sha256`, which anyone who can write the archive can recompute, and
  `sha256sum -c` checked whatever file the list named. `backup.sh` now writes
  `<archive>.mac`, HMAC-SHA256 under the audit key of the archive's name and
  bytes; `restore.sh` requires the `.sha256` to name the archive itself and
  the `.mac` to verify. Round 38 (R37-11): the `.mac` is under the current key
  only — `backup.sh` uses the key the copied trail's head is MAC'd under, and
  `restore.sh` accepts it only under `--current-key-file`, else
  `GRAPHITE_AUDIT_KEY_FILE`, else the single `--key-file` given (several keys
  and none named current: exit 64). A MAC under a retired key is refused:
  whoever still holds one could MAC a forged archive under it. The newest
  anchored checkpoint is chosen by its content's `seq`, not its file name
  (T-9). `deploy/tests/backup-keys.test.sh` checks both. An unkeyed deployment's backup has no
  `.mac` and restores only with `ALLOW_UNKEYED_ARCHIVE=1`. `restore.sh` also
  requires `--anchor-dir` (`ALLOW_NO_ANCHOR=1` for a deployment that has
  never anchored a checkpoint).
- **A rotated secret keeps its owner (Round 34).** `rotate-keys.sh env|file`
  replaces the file by a rename, and under `sudo` the new file used to belong
  to root; the compose stack reads its secrets as 10001:10001, so the Core
  could not read its key after the restart. The new file now takes the old
  one's owner and group (mode 0600), or the `UID:GID` given.
- **A stale restore is refused by default.** Restoring a backup older than
  the newest anchored checkpoint loses the verdicts recorded since; the
  checkpoint makes that visible and `restore.sh` stops until
  `ACCEPT_STALE_RESTORE=1` (after the loss is recorded).

## Not exercised here

- ACME certificate issuance and TLS itself (the test serves Caddy on plain
  HTTP loopback; TLS needs a public name).
- The S3 Object-Lock upload (no S3 endpoint or `aws` CLI in the test
  environment); the `put-object` flags are from the AWS CLI reference.
- The units under a running systemd (only `systemd-analyze` ran), and the
  compose stack under a running Docker daemon (only `docker compose config`):
  not the hardened anchor unit running the aws CLI, not
  `docker compose up --scale graphite=2` (only the `replicas: 2` and
  `scale: 2` override files, refused at render time), not the image's
  read-only root filesystem at run time, not a second replica crash-looping
  on the lock inside a container (the lock refusal itself is rehearsed with
  the binary).
- A real host, DNS, and WORM storage: the anchors here are a local
  directory, so a host compromise that rewrites them is not modelled.
- A full disk on a real filesystem (ext4/xfs reserved blocks, a full volume
  under Docker): the rehearsal uses a size-limited tmpfs.
