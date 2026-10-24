# Deploying Graphite Core

Production configuration for one Graphite Core node, in two forms (pick one),
plus the monitoring and the operational scripts both share. The runbooks in
[`docs/ops/`](../docs/ops/README.md) say when to use each piece; the go-live
list is [`docs/ops/production-checklist.md`](../docs/ops/production-checklist.md).

| Path | What it is | Checked by |
|---|---|---|
| `compose/docker-compose.prod.yml` | Caddy (TLS) + Core from a released image pinned by digest + the optional AI layer (`--profile ai`); every key a file-backed secret | `docker compose config` |
| `systemd/graphite.service` | The Core as a hardened systemd service (`systemd-analyze security`: 1.1) behind Caddy on the same host | `systemd-analyze verify` |
| `systemd/graphite-anchor.{service,timer}` | Hourly checkpoint export and off-host anchoring | `systemd-analyze verify` |
| `systemd/graphite.env.example` | The service's `/etc/graphite/graphite.env` | — |
| `caddy/Caddyfile` | TLS, HSTS, a 1 MiB body limit (the Core's; since Round 34 a declared `Content-Length` over it is answered 413 at the edge, before anything is proxied), and only `/verify`, `/verify/execution`, `/audit/event` (POST), `/manifests`, `/api/*` (GET) reachable; `/health`, `/metrics`, `/admin/*` answer 404 at the edge | `caddy validate`, `caddy fmt` |
| `prometheus/graphite-alerts.yml` | 19 alerts on the series the server exports and on `/health`'s degraded reasons | `promtool check rules`, `promtool test rules` (`graphite-alerts.test.yml`) |
| `prometheus/prometheus.example.yml` | Scrape config with the read key | `promtool check config --syntax-only` |
| `grafana/graphite-dashboard.json` | Verdicts, refusals, L8, audit trail | every query parsed by promtool; every series exists in `server.rs` |
| `scripts/health-textfile.sh` | `/health` `degraded_reasons` → `graphite_health_degraded{reason=…}` for node_exporter | `deploy/tests/run.sh` |
| `scripts/backup.sh` | Cold (stop/copy/start) or `--hot` backup; kept only if `graphite audit verify` passes on the copy; `.sha256` and a `.mac` (HMAC-SHA256 of the archive under the audit key) beside it | same |
| `scripts/restore.sh` | `--anchor-dir` required; a `.sha256` naming the archive itself, then its `.mac` under a given key; verify the unpacked trail and against the newest anchored checkpoint, then swap it in, keeping the old directory | same |
| `scripts/anchor-checkpoints.sh` | `graphite audit checkpoint` into the anchor directory; optional upload to an S3 Object-Lock bucket | same (the S3 upload is not exercised: see below) |
| `scripts/rotate-keys.sh` | New API key in an env file or secret file (keeping the file's owner, or an explicit `UID:GID`), new audit MAC key, verify the trail under every key | same |
| `tests/run.sh` | All of the above, against a real Core and Caddy on loopback | — |

## Run the checks

```sh
cargo build --release --locked --features server,cli --manifest-path graphite-core/Cargo.toml
GRAPHITE_BIN=$PWD/graphite-core/target/release/graphite deploy/tests/run.sh
```

It needs `caddy`, `promtool`, `shellcheck`, `curl`, `jq`, `openssl`, `flock` and
Python 3 with PyYAML; `systemd-analyze` and `docker compose` are used when
present and reported as skipped otherwise. Override any binary with
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
  bytes (the last `--key-file`, else `GRAPHITE_AUDIT_KEY_FILE`); `restore.sh`
  requires the `.sha256` to name the archive itself and the `.mac` to verify
  under one of the keys it is given. An unkeyed deployment's backup has no
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
  compose stack under a running Docker daemon (only `docker compose config`).
