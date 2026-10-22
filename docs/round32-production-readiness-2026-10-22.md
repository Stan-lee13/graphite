# Rounds 31–32 — every dependency updated, then everything code and CI can do toward production

> **Historical record.** This report describes the work done on top of `9f4556e`
> (the Round 30 merge) on 2026-10-22. For the current state of Graphite see
> [`CURRENT.md`](CURRENT.md).

**Date:** 2026-10-22 · **Base:** `9f4556e` (main, Round 30 merged) · **Branch:**
`claude/admiring-archimedes-lfhr7n` (PR #45). Internal engineering work by the maintainer and AI
engineering agents. **This is not an independent third-party audit and not a certification.**

The owner asked two things: update every dependency, and then do everything that can be done to
make Graphite production ready. This report is the honest answer to the second. Everything
that code, tests and CI can do has been done or is listed below with the reason it is not done.
What remains needs the owner, an independent auditor, or real infrastructure. Those items are
listed in §5. They are the release blockers.

## 1. Round 31 — dependencies

Every direct dependency was updated to its latest stable release. Lockfiles were regenerated
by the tools, and each package was re-tested as CI tests it. The CHANGELOG's Round 31 entry has
the list. The parts that matter for security:

- **reqwest 0.13.** It trusts the host's certificate store by default. Graphite's RPC client is
  held to the bundled Mozilla roots, so its trust anchors did not change. A test pins this.
- **Rust 1.99.1** in CI and in the builder image, pinned by digest.
- **Held back, with reasons:**
  - The runtime oracle's solana-transaction / solana-message 6. That release removes the v1
    limits Graphite is judged against, so adopting it is a decision about Graphite's own limits.
  - bincode 3. The runtime still decodes with bincode 1.
  - `@solana/web3.js` 1.x and `@types/node` 22.x.
- **No pinned output changed:** the mainnet digest, the regression corpus, the release
  evaluation and the cross-language corpus.

## 2. Round 32 — findings and fixes

Four workstreams ran in parallel worktrees, under the Round 30 discipline:
- reproduce before fixing;
- add a regression test for each fix, and break it deliberately (revert → test fails → restore);
- never weaken a gate, test or floor;
- change a pinned output only with each row's change attributed.

### P1 — risk defaults (core)

| ID | Severity | Finding | Fix |
|---|---|---|---|
| R32-P1-1 | High | A signer's loss under a declaration Graphite cannot read only warned when the instruction's class moves value (the Round 30 owner decision, R30-F-1). | Critical for every class by default. 16 declarations were rewritten from their IDLs: Orca Whirlpools ×7, Meteora DLMM ×5, Kamino ×3, Marginfi ×1. Each was checked slot by slot, and every account a declaration names must be writable and not a signer. Opt-out: `GRAPHITE_ALLOW_UNREADABLE_VALUE_DECLARATIONS=1`. |
| R32-P1-2 | Medium | Pump.fun `buy_v2`/`sell_v2` named `accounts.associated_user`, but the v2 layout calls that slot `associated_base_user`. A sell's base-token debit was outside every declared scope. | The slot name is corrected. A census test requires every declaration in every shipped manifest to name a real account; 2 did not. |
| R32-P1-3 | High | W19: lamports leaving a signer's wallet, under a declaration that debits other named accounts, only warned. | Critical by default. The loss is counted net of created accounts' rent and of SOL wrapped into the signer's own token accounts. Opt-out: `GRAPHITE_ALLOW_SIGNER_LAMPORTS_OUTSIDE_DECLARED_DEBIT=1`. |
| R32-P1-4 | High | A granted withdrawal was approved with every minimum output at zero, i.e. unbounded slippage. | A new finding, `UnboundedWithdrawal`. It applies to Raydium CLMM `decrease_liquidity_v2`, Raydium CPMM `withdraw` and Pump AMM `withdraw`, the only grants whose IDLs carry minimum outputs. A unit test checks the byte offsets against the IDL files. Opt-out: `GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS=1`. |

All three opt-outs are strict-parsed: a bad value refuses to start. They apply to the server's and
the CLI's engine alike and are logged when on. Breaks run: the old class rule (3 tests fail); W19
back to a warning (2); rent/wrap netting removed (1); the zero-minimum check disabled (2); the
opt-out not plumbed (1); a rewritten line and the Pump.fun fix reverted (3).

**Measured impact on committed data:**
- The census of unreadable declarations went from 382 to 366. Of those, 139 have value-moving
  classes and are now refused; the opt-out restores their warning.
- The mainnet conformance digest is unchanged. The committed blocks carry no state diffs, so the
  L4 changes cannot move them.
- Six synthetic corpus rows went from refused to approved: the rewritten deposits under a
  `transfer` intent. The accurate prose carries the words L5 needs.
- The release-evaluation dev split was re-pinned for those six rows: TP 11,808 → 11,802 and
  TN 1,097 → 1,103.

### P2 — the signing side, the contract, the console

| ID | Severity | Finding | Fix |
|---|---|---|---|
| R32-P2-1 | High | Two agent guards for the same wallet each spent the whole aggregate allowance: the cap held per process, not per wallet. | A per-wallet lock in a directory every guard on the host shares (`GRAPHITE_GUARD_LOCK_DIR`). A second guard for the same wallet refuses to start. `GRAPHITE_GUARD_ALLOW_SHARED_WALLET=1` opts out, and that is logged. The lock does not reach other hosts or pid namespaces; that limit is documented. |
| R32-P2-2 | Medium | The aggregate cap counted a transfer's amount but not its network fee. | The fee is counted. |
| R32-P2-3 | Low | Lifecycle requests only accepted the deprecated `content_hash` name. | `instruction_bind_key` is accepted as an alias by the server, `graphite execution --instruction-bind-key`, and the TypeScript and Go SDKs. |
| R32-P2-4 | Medium | The dashboard was never driven in a browser in CI. | A `dashboard-e2e` job seeds a live Core and walks every view on desktop and phone with axe. Its first run fixed label/name mismatches. |

### P3 — live measurement (`.github/workflows/live-mainnet.yml`, `live-devnet.yml`, `tools/live-measure/`)

This container's network policy blocks the Solana RPC endpoints, so the live work runs on
GitHub's runners. A pull request labelled `live-measure` triggers it, or a manual dispatch once
the files are on `main`. Results at `67920ae` (before P1's defaults):

- **Mainnet (run 39809387410).**
  - 818 transactions from two finalized blocks were read: 0 parse failures, 0 verify errors,
    818 artifact-bound.
  - A real RPC replayed 200 of them: 3 `executable_approved`, 8 inconclusive, 189 blocked.
    66 of the 200 had failed on chain.
  - 0 rate limits and 0 server errors. Latency p50 152 ms, p99 360 ms.
  - The leading reasons were simulation errors (147: the transactions' own on-chain failures
    and stale state) and L4 with nothing declared to compare (120).
  - A fresh-blockhash pass over 39 of them changed one outcome: a rate limit.
  - With System and SPL Token seeded as an operator would seed them, 2 of 2 System transfers
    and 1 of 2 token transfers were `executable_approved`.
  - L8 saw 5 transactions it had blocked execute on chain. That is the expected answer: the
    signer was not behind Graphite.
  - No Graphite defect.
- **Devnet (run 39809387361).** The faucet refused, so the run used the pinned Agave 4.2.2
  local validator (sha256 checked). The whole gated path passed: verify → `executable_approved`
  → sign → submit → L8 `ApprovedAndExecuted` → audit verify exit 0. From this round on, the run
  keys its audit trail and requires `tamper_evident` and a MAC-checked verify.

### P4 — release, deployment, hand-off

| ID | Severity | Finding | Fix |
|---|---|---|---|
| R32-P4-1 | Medium | There was no release pipeline. | `.github/workflows/release.yml`. It requires a v* tag matching the crate version and a passed CI gate on that commit. It builds the binary twice and compares the two byte for byte, and produces CycloneDX and SPDX SBOMs. The image is built once, smoke-tested, pushed to GHCR by digest, and given SLSA provenance and SBOM attestations. It also publishes SHA256SUMS. Permissions are empty by default; only the tag-only publish job can write. |
| R32-P4-2 | Medium | Degraded health reasons had no metric. | `deploy/scripts/health-textfile.sh` exports them for alerting. |
| R32-P4-3 | Low | The scheduled checkpoint name could clash with a rotation anchor. | Named apart. |
| R32-P4-4 | Info | `ci.yml` had a shellcheck warning and an info finding. | Both fixed (Round 32 integration). |
| R32-P4-5 | Info | There was no deployment kit or go-live checklist. | `deploy/` (a Caddy TLS edge, a hardened systemd unit, a production compose file, Prometheus alerts with unit tests, a Grafana dashboard, and backup / restore / anchoring / key-rotation scripts), `docs/ops/production-checklist.md`, and `docs/audit-handoff/` for the independent auditors. |

`deploy/tests/run.sh` validates every file with its own tool and runs the scripts against a
live Core and Caddy. CI now runs it in a `deploy` job: Caddy and promtool are built at pinned
releases, and the job requires the run's check count to stay at or above its floor.

## 3. Assurance

The first hosted run of `assurance.yml` was run 39798389463 at `bdc9dab`.
- All six fuzz targets ran for 30 minutes each with 0 crashes.
- The line-coverage floor held. The job now prints its measured total and per-file figures, so
  the next run gives the number to raise the floor to.
- The mutation jobs (risk engine, simulation integrity, transaction artifact, three state-diff
  shards) run for hours. Their scores are recorded in `docs/CURRENT.md` when they finish, and
  the provisional 0.60 floors are raised to the measured scores, never lowered.

## 4. What is not proven

- **The false-refusal rate of P1's new defaults on real traffic.** The committed blocks have no
  state diffs. W19 can refuse a transaction that adds a tip or a plain SOL transfer beside an
  instruction whose declaration names the debited account. The live mainnet workflow measures
  this; each rule has an opt-out for an operator who measures and accepts the trade.
- **The remaining 139 placeholder declarations** (Drift, Solend, Phoenix, Jupiter DCA/Limit,
  OpenBook, Switchboard, Wormhole, the loaders). No IDL for them is in the repository, and none
  was guessed.
- **The release workflow has never run against a real tag.** The deployment kit has never run
  on a real host with ACME, a real systemd or an S3 backup target.
- **The wallet lock does not reach across hosts.**
- **L8 still trusts RPC providers.** A witness and a high-assurance mode exist; a light-client
  proof does not.

## 5. Release blockers (owner and external)

1. **Branch protection on `main`.** Apply `.github/rulesets/` (`docs/ops/branch-protection.md`).
   Until then every CI gate is advisory.
2. **Private vulnerability reporting.** Enable it in the repository settings.
3. **An independent third-party audit.** `docs/audit-handoff/` is the pack.
4. **A real deployment.** Infrastructure, TLS, monitoring, on-call and backups:
   `docs/ops/production-checklist.md`.
5. **Tag the release** once 1–4 hold. The release workflow does the rest.
