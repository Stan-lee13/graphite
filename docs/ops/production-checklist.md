# Go-live checklist

One list, in order, for taking Graphite Core to production. Every item names the
artifact in this repository and the exact command or click. Items 1–12 are the
owner and operator release gate of Round 30 (`docs/round30-forensic-audit-and-remediation-2026-10-22.md`,
§G), in its numbering; A–F are what a production service needs around them.
**Launch stays blocked until items 1, 2, 3 and 9 are done.**

Commands assume the repository `Stan-lee13/graphite`, a checkout at its root,
and `gh` authenticated as a repository admin.

## Repository (owner)

- [ ] **1. Branch protection and immutable tags — STOP-SHIP.**
  Artifact: `.github/rulesets/main.json`, `release-tags.json` (runbook: [branch-protection.md](branch-protection.md)).
  ```sh
  gh api -X POST repos/Stan-lee13/graphite/rulesets --input .github/rulesets/main.json
  gh api -X POST repos/Stan-lee13/graphite/rulesets --input .github/rulesets/release-tags.json
  gh api repos/Stan-lee13/graphite/rulesets --jq '.[] | [.name, .enforcement] | @tsv'   # both "active"
  ```
  Or Settings → Rules → Rulesets → New ruleset → Import a ruleset (one file at a time).
  Check: `git push origin main` from a clone is rejected; a PR with a red job shows `CI gate` failing.
  Then delete or protect the stale branches (K-14): `git ls-remote --heads origin`, and for each one
  not in use, `git push origin --delete <branch>`.
  When a second maintainer exists: `gh api -X POST repos/Stan-lee13/graphite/rulesets --input .github/rulesets/main-review.json`.
- [ ] **2. Private vulnerability reporting.**
  `gh api -X PUT repos/Stan-lee13/graphite/private-vulnerability-reporting`
  (or Settings → Security → Code security → Private vulnerability reporting → Enable).
  Then, in one PR: point the contact link in `.github/ISSUE_TEMPLATE/config.yml` at
  `https://github.com/Stan-lee13/graphite/security/advisories/new` and make `SECURITY.md`'s
  reporting section say the same.
  While there: Settings → Code security → enable Dependabot security updates and secret-scanning push protection.
- [ ] **3. Independent third-party audit.**
  Hand the auditors [`docs/audit-handoff/`](../audit-handoff/README.md): scope, threat model, build and test
  steps, the invariants and the tests that hold each, the known residuals, the questions, and the commit.
  Publish their report and the fixes before item 10.
- [ ] **4. Keep or relax the Round 32 refusal defaults.** Since Round 32 a signer's loss under an
  unreadable declaration (`GRAPHITE_ALLOW_UNREADABLE_VALUE_DECLARATIONS`), W19
  (`GRAPHITE_ALLOW_SIGNER_LAMPORTS_OUTSIDE_DECLARED_DEBIT`) and an unbounded granted withdrawal
  (`GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS`) are refused by default; each variable set to `1` restores
  the old behaviour and is logged at startup. Measured cost: W19 refused 1 of 200 replayed live mainnet
  transactions (0.5%). Run `.github/workflows/live-mainnet.yml` against your traffic profile; leave all
  three at `0` unless the measured false refusals are a cost you choose over the protection.
- [ ] **5. Decide R-M9** (Constitution P12 vs. the drainer heuristic), the default of
  `GRAPHITE_QUARANTINE_ON_UPGRADE` (`.env.example`), and the self-heal threshold (R-P10).
- [ ] **6. Dependabot majors.** Round 31 took every update except, with reasons: the oracle's
  `solana-transaction`/`solana-message` 6 and `bincode` 3 (`graphite-core/CHANGELOG.md`),
  `@solana/web3.js` 1.x, `@types/node` 22.x. Each stays an explicit decision; close or re-open the
  corresponding Dependabot PRs to match.
- [ ] **7. Assurance budgets.** After the first scheduled run of the weekly mutation and coverage jobs on
  the hosted runners: Actions → the run → read the measured scores; replace the three provisional
  mutation-score floors (each at 0.60) with measured ones in a PR.
- [ ] **8. Benchmark review before any public claim.** `cargo run --release --locked --features cli -- benchmark --json`
  (in `graphite-core/`): the holdout is 38 rows and every offline approval is `analysis_only`; say so
  next to any number quoted.

## Release integrity (owner only — Round 34, R33-9)

A `v*` tag runs the tagged commit's own copy of `.github/workflows/release.yml`. The workflow's gate
(`.github/scripts/release-gate.sh`) now requires the commit to be on `main`, its `CI gate` to have
passed in a **push** run of `ci.yml` on `main` (GitHub Actions app 15368), and the tag to be SSH-signed
by a key in `.github/allowed_signers` — but a tag on an unmerged branch runs that branch's copy of the
workflow, which can drop the gate. Only repository settings close that, and only an admin can apply
them. **Until R1–R4 are done, anyone with write access can still publish a release.**

- [ ] **R1. Rulesets.** Item 1's two rulesets, plus the tag-creation ruleset (only a repository admin
  may create a `v*` tag; `release-tags.json` keeps every tag immutable for everyone, admins included):
  ```sh
  gh api -X POST repos/Stan-lee13/graphite/rulesets --input .github/rulesets/main.json
  gh api -X POST repos/Stan-lee13/graphite/rulesets --input .github/rulesets/release-tags.json
  gh api -X POST repos/Stan-lee13/graphite/rulesets --input .github/rulesets/release-tags-create.json
  gh api repos/Stan-lee13/graphite/rulesets --jq '.[] | [.name, .enforcement] | @tsv'   # three, all "active"
  ```
  Check: a collaborator with write (not admin) access runs `git push origin <commit>:refs/tags/v9.9.9-test`
  and is rejected.
- [ ] **R2. A protected `release` environment** with a `v*` tag policy and you as required reviewer:
  ```sh
  me=$(gh api user --jq .id)
  gh api -X PUT repos/Stan-lee13/graphite/environments/release --input - <<EOF
  {"reviewers":[{"type":"User","id":$me}],
   "deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}
  EOF
  gh api -X POST repos/Stan-lee13/graphite/environments/release/deployment-branch-policies \
    -f name='v*' -f type=tag
  gh api repos/Stan-lee13/graphite/environments/release \
    --jq '[.protection_rules[].type, .deployment_branch_policy]'   # required_reviewers, branch_policy; custom policies
  ```
  (Or Settings → Environments → New environment → `release` → Required reviewers: you; Deployment
  branches and tags → Selected branches and tags → Add rule → Tag → `v*`.)
- [ ] **R3. Your release signing key in `.github/allowed_signers`.** The file is committed EMPTY on
  purpose: while it names no key, every release fails at the gate ("names no signer"). Sign tags with
  an SSH key (the same key can sign commits):
  ```sh
  git config --global gpg.format ssh
  git config --global user.signingkey ~/.ssh/id_ed25519.pub
  printf '%s namespaces="git" %s\n' "$(git config user.email)" "$(cut -d' ' -f1,2 ~/.ssh/id_ed25519.pub)" \
    >> .github/allowed_signers      # then commit it through a pull request to main
  ```
- [ ] **R4. Check the gate refuses.** After R1–R3: an unsigned annotated tag, or a signed tag on a
  commit that is not on `main`, must stop at the `Release gate` job (and R1 already rejects the push
  of such a tag from a non-admin).

## Release (owner)

- [ ] **10a. A `release` environment** — R2 above. `.github/workflows/release.yml`'s publish job runs in it.
- [ ] **10b. Rehearse.** Actions → Release → Run workflow (on `main`). Every build, the two-build
  reproducibility comparison, both SBOMs, the image smoke test and SHA256SUMS run; nothing is pushed,
  attested or released. Read the `reproducible` job: it fails if the two builds differ.
- [ ] **10c. Decide whether the crate goes to crates.io.** `graphite-core/Cargo.toml` has no `publish`
  key today, so `cargo publish` would be allowed; add `publish = false` if it should not be. The
  release workflow never publishes to crates.io either way.
- [ ] **10d. Tag.** The tag must be `v` + the crate's version, SSH-signed by a key in
  `.github/allowed_signers` (R3), on a commit of `main` whose `CI gate` passed in its push run:
  ```sh
  git tag -s v0.3.0-beta -m "graphite 0.3.0-beta" <commit> && git push origin v0.3.0-beta
  ```
  Attestations need the repository to be public (or GitHub Enterprise Cloud). After the run: the
  package `ghcr.io/stan-lee13/graphite-core` is private by default — Packages → graphite-core →
  Package settings → Change visibility, if it should be public.
- [ ] **10e. Verify what was published** (anyone can, and the operator must before deploying):
  ```sh
  gh release download v0.3.0-beta --repo Stan-lee13/graphite
  sha256sum -c SHA256SUMS
  gh attestation verify graphite-0.3.0-beta-x86_64-unknown-linux-gnu.tar.gz --repo Stan-lee13/graphite \
    --signer-workflow Stan-lee13/graphite/.github/workflows/release.yml \
    --source-ref refs/tags/v0.3.0-beta --deny-self-hosted-runners
  gh attestation verify oci://ghcr.io/stan-lee13/graphite-core@sha256:<digest> --repo Stan-lee13/graphite \
    --signer-workflow Stan-lee13/graphite/.github/workflows/release.yml \
    --source-ref refs/tags/v0.3.0-beta --deny-self-hosted-runners
  ```
  The digest is in the release notes. Deploy by that digest, never by the tag: compose takes it as
  `GRAPHITE_IMAGE_DIGEST=sha256:<digest>` beside `GRAPHITE_IMAGE=ghcr.io/stan-lee13/graphite-core:<version>`
  in `deploy/compose/.env`, and refuses to render without it. `--repo` alone would
  accept an attestation made by any workflow of the repository, on any ref; the three other flags
  require the release workflow, run for this tag, on a GitHub-hosted runner.

## Deployment (operator) — item 9

Pick one form: `deploy/compose/docker-compose.prod.yml` or `deploy/systemd/` (both behind
`deploy/caddy/Caddyfile`). Run `deploy/tests/run.sh` on the configuration you are about to ship.

- [ ] **9a. TLS and DNS.** An A/AAAA record for the public name pointing at the host; ports 80 and 443
  open to the internet (ACME). Compose: `GRAPHITE_SITE` and `ACME_EMAIL` in `deploy/compose/.env`.
  systemd: install Caddy, copy `deploy/caddy/Caddyfile` to `/etc/caddy/Caddyfile`, set the same two
  variables plus `GRAPHITE_UPSTREAM=127.0.0.1:7331` in Caddy's environment, `systemctl restart caddy`.
  Check: `curl -sI https://<name>/verify -X POST` shows `strict-transport-security` and a 401;
  `curl -s -o /dev/null -w '%{http_code}' https://<name>/health` is 404.
- [ ] **9b. Keys.** Three API keys and the audit MAC key, all `openssl rand -hex 32`, all different.
  Compose: the commands at the top of `docker-compose.prod.yml` (`secrets/`, owned 10001, mode 600).
  systemd: `deploy/systemd/graphite.env.example` → `/etc/graphite/graphite.env` (root, 600) and
  `/etc/graphite/audit.key` (root, 600; systemd hands it over as a credential). Leave the admin key
  empty unless someone uses `/admin/*`. Give the dashboard and Prometheus the **read** key only.
  Rotation: `deploy/scripts/rotate-keys.sh` and [keys.md](keys.md).
- [ ] **9c. The audit MAC key off the data volume** — done by both forms; check after start:
  `curl -s localhost:7331/health | jq .audit.integrity` is `"tamper_evident"`.
  Keep a copy of the key off the host (a password manager or HSM-backed vault), separately from backups.
- [ ] **9d. Checkpoints to WORM storage.** Create an S3 bucket with Object Lock enabled (it can only be
  enabled at creation): `aws s3api create-bucket --bucket <b> --object-lock-enabled-for-bucket …`.
  An IAM identity allowed only `s3:PutObject` and `s3:PutObjectRetention` on `arn:aws:s3:::<b>/<prefix>/*`.
  systemd: `ANCHOR_S3_URI=s3://<b>/<prefix>` and its credentials in `/etc/graphite/anchor.env` (600),
  then `systemctl enable --now graphite-anchor.timer`. Compose: run `deploy/scripts/anchor-checkpoints.sh`
  hourly from the host's cron with `GRAPHITE_DATA_DIR` pointing at the volume's mountpoint
  (`docker volume inspect graphite_graphite-data --format '{{.Mountpoint}}'`), `GRAPHITE_AUDIT_ANCHOR_DIR=deploy/compose/anchors`,
  the key file and `GRAPHITE_BIN` set. Check: `aws s3api get-object-retention --bucket <b> --key <prefix>/<file>`.
- [ ] **9e. An independent witness, high assurance.** Two providers run by different companies:
  `GRAPHITE_RPC_URL`, `GRAPHITE_RPC_WITNESS_URL` (both https), `GRAPHITE_RPC_PROVIDER`,
  `GRAPHITE_RPC_WITNESS_PROVIDER`, `GRAPHITE_L8_HIGH_ASSURANCE=1`. Check: the startup log names both
  providers; `/health` reports `"verification_mode": "executable"`.
- [ ] **9f. Pin the policy.** `GRAPHITE_WALLET_PROFILE` set (the example sets `treasury`); never
  `GRAPHITE_ALLOW_PERMISSIVE_PROFILES=1` unless the caller is the operator.
- [ ] **9g. A single replica — scaling the Core out is unsupported.** One Core process, on one data
  directory, behind one Caddy. The Core is single-tenant and single-process by design: it holds
  `graphite.lock` and `.audit.jsonl.lock` on its data directory, and keeps the audit chain's head and
  index, the semantic graph (earned evidence, baselines, quarantines) and the per-client rate limiter
  (R-M12) in its own memory. A second Core on the same directory refuses to start (rehearsed by
  `deploy/tests/run.sh`); a second Core on another directory is a second, disjoint audit trail, a
  second set of quarantines and a second rate-limit budget behind the same name, so a load balancer
  across several silently splits the record and multiplies every client's limit. The kit enforces it:
  the compose Core has a fixed `container_name` and `deploy.replicas: 1` (`replicas: 2` or
  `--scale graphite=2` is an error), and `graphite.service` is a plain unit, not a template. For
  availability, restart fast (`restart: unless-stopped`, `Restart=on-failure`) and restore from backup
  (9i); agents behind the guard fail closed while the Core is down.
- [ ] **9h. Monitoring.** Prometheus with `deploy/prometheus/prometheus.example.yml` (the read key in
  `credentials_file`) and `graphite-alerts.yml`; node_exporter with `--collector.textfile.directory=<dir>`
  and `deploy/scripts/health-textfile.sh` every minute (`TEXTFILE_DIR=<dir>`); Grafana: Dashboards →
  New → Import → upload `deploy/grafana/graphite-dashboard.json`, pick the Prometheus data source.
  Check: `promtool test rules deploy/prometheus/graphite-alerts.test.yml`; Prometheus → Alerts lists
  19 rules; stop the Core for three minutes and `GraphiteDown` fires.
- [ ] **9i. Backups and a restore drill.** Daily:
  `STOP_CMD="systemctl stop graphite" START_CMD="systemctl start graphite" deploy/scripts/backup.sh --key-file <audit key> /var/lib/graphite <backup dir>`
  (compose: `docker compose -f deploy/compose/docker-compose.prod.yml stop graphite` / `start graphite`
  and the volume's mountpoint), then copy the archive, its `.sha256` and its `.mac` off the host
  (`restore.sh` refuses an archive without a `.mac` that verifies, and runs without `--anchor-dir`).
  Before go-live and quarterly: restore the latest archive into a scratch directory on another host,
  `deploy/scripts/restore.sh --key-file <every audit key> --anchor-dir <anchors> <archive> <scratch dir>`,
  start a Core on it and check `/health`. Record the drill (date, archive, result).
  After an audit key was lost and replaced (`graphite audit adopt-key`, [keys.md](keys.md)), both
  scripts need `--lost-key <key id>` from then on: `audit verify` can no longer check that key's MACs.
- [ ] **11. Real baselines.** Tier 3+ baselines with `sample_count ≥ 20` (R-P7) exist only after
  production traffic; until then confidence for programs without history stays at its floor and
  refusals of them are expected. Check progress on `GET /api/graph` (read key).
- [ ] **12. MMM `updatePool`** stays ungranted until its IDL is in the repository.

## Running it

- [ ] **A. On-call.** A rota of at least two people with a pager. Route `severity: page` (gate bypassed,
  lifecycle on a blocked transaction, audit disabled or failing, Core down) to the pager at any hour;
  `severity: ticket` to the team's queue. Alertmanager: a route on `severity="page"` to your paging
  receiver, the default to the ticket receiver. Test the route once: `amtool alert add GraphiteTest severity=page`.
- [ ] **B. Incident response.** The runbooks are [incidents.md](incidents.md); every alert's description
  names its section. For a security incident (a `GraphiteBlockedTransactionExecuted` page, a leaked key,
  a suspected trail rewrite): (1) freeze — stop the agents that hold wallet keys, not the Core, which
  keeps refusing; (2) preserve — `deploy/scripts/backup.sh --hot` and copy the anchors before
  anything else; (3) verify — `graphite audit verify --checkpoint <newest anchored> --key-file …`;
  (4) rotate what may have leaked (`deploy/scripts/rotate-keys.sh`); (5) report through the private
  advisory (item 2) if the cause is in Graphite.
- [ ] **C. Logs.** The Core and Caddy log JSON to stdout (journald or Docker's json-file, rotated);
  ship them to your aggregator. Neither logs the bearer key or the RPC URLs.
- [ ] **D. Upgrades.** [upgrade-rollback.md](upgrade-rollback.md): verify the new release (10e), take a
  backup (9i), change `GRAPHITE_IMAGE` and `GRAPHITE_IMAGE_DIGEST` (compose; both required, so a tag
  alone does not render) or the binary, restart, watch `/health` and the alerts for an hour.
- [ ] **E. Capacity.** Defaults: 30 requests/s per client, 32 verifications in flight, 1,024 connections,
  2 CPUs and 512 MiB (compose) or 1 GiB (systemd). Watch `GraphiteLoadShedding`; raise
  `GRAPHITE_MAX_CONCURRENT` only with CPU to match.
- [ ] **F. Review this list** at every release and after every incident.
