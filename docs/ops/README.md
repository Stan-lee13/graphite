# Operator runbooks

Short, executable procedures for running Graphite Core in production. Every
environment variable, command and file name below exists in this tree; if one
of them stops existing, the runbook is wrong, not the code.

| Runbook | When |
| --- | --- |
| [install.md](install.md) | First deployment, from a clean checkout |
| [upgrade-rollback.md](upgrade-rollback.md) | Moving to a new release, or back |
| [keys.md](keys.md) | Rotating the verify key, the operator key or an RPC credential |
| [backup-restore.md](backup-restore.md) | Backing up the data volume; restoring it |
| [incidents.md](incidents.md) | Disk full, audit-integrity alert, RPC degraded, program upgrade, failed finalization, security incident |
| [branch-protection.md](branch-protection.md) | Owner steps that make CI a gate (repository settings, not code) |

What these runbooks assume, and what is not provided here:

- **One replica.** The rate limiter, the concurrency caps and the data-directory
  lock are per process, and a second server on the same data directory refuses
  to start (`<GRAPHITE_DATA_DIR>/graphite.lock`). Horizontal scale needs a
  shared limiter that does not exist yet.
- **TLS is terminated in front of the container.** The server speaks plain
  HTTP/1.1. docker-compose.yml publishes it on host loopback only.
- **Monitoring, alert routing and on-call are the operator's.** The signals
  exist (`/health` `degraded_reasons`, `/metrics`, `graphite execution` exit
  codes); where they page is a deployment decision.
- **There is no release pipeline.** Nothing in CI builds, signs or publishes
  an image or a crate; a release is a tag plus a build the operator runs (see
  upgrade-rollback.md). Signed artifacts, an SBOM and build provenance are open
  owner items.
