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
| [production-checklist.md](production-checklist.md) | Going live: every owner and operator step, in order |
| [../../deploy/README.md](../../deploy/README.md) | The production configuration and scripts (TLS edge, systemd, compose, alerts, dashboard, backup, anchoring) |

What these runbooks assume, and what is not provided here:

- **One replica; scaling out is unsupported.** The Core is single-tenant and
  single-process: the data-directory locks (`graphite.lock`,
  `.audit.jsonl.lock`), the audit chain's head and index, the semantic graph,
  the rate limiter and the concurrency caps all belong to one process. A
  second server on the same data directory refuses to start; one on another
  directory keeps a second, disjoint audit trail. The production compose file
  and the systemd unit allow exactly one (production-checklist.md, 9g).
  Horizontal scale would need a shared trail and limiter that do not exist.
- **TLS is terminated in front of the container.** The server speaks plain
  HTTP/1.1. docker-compose.yml publishes it on host loopback only.
- **Monitoring, alert routing and on-call are the operator's.** The signals
  exist (`/health` `degraded_reasons`, `/metrics`, `graphite execution` exit
  codes); where they page is a deployment decision.
- **Releases are built by `.github/workflows/release.yml`** from a `v*` tag:
  a reproducible double build, SBOMs, the image on GHCR by digest, SLSA
  provenance and SBOM attestations, `SHA256SUMS`. Verify with
  `gh attestation verify` before deploying (production-checklist.md). The
  pipeline has not yet run on GitHub: the first tag is its first run.
