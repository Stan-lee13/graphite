# Round 30 — the forensic audit of `29e4356`, remediated

> **Historical record.** This report describes the codebase at commit `29e4356`
> (the Round 29 merge) on 2026-10-21/22, and the changes made on top of it. For
> the current state of Graphite see [`CURRENT.md`](CURRENT.md).

**Date:** 2026-10-21 to 2026-10-22 · **Base:** `29e4356` (tree `0aeac5a`, 894 files; the Round 29
merge, PR #38) · **Scope:** the whole repository against a forensic brief of twelve leads
(G-01 … G-12), every open item in `AUDIT/`, `docs/CURRENT.md` and the round reports, and twenty
defects the ledger pass found (K-01 … K-20). Internal engineering work by the maintainer and AI
engineering agents — **not an independent third-party audit and not a certification.**

Findings, each with its regression test, the deliberate revert that showed the test fails without
the fix, and its residual: [`audit-r30/findings-registry.md`](audit-r30/findings-registry.md).
The file ledger, the architecture reconstructed from the code and the regression matrix of every
historical finding: [`audit-r30/`](audit-r30/README.md).

## A. Launch assessment

**Decision: RELEASE BLOCKED** — on owner and external gates, not on a known code defect:

1. Branch protection on `main` is not enforced (STOP-SHIP). The rulesets, CODEOWNERS and a single
   `CI gate` check are prepared in `.github/`; an owner has to apply them (`ops/branch-protection.md`).
2. No independent third-party audit has been performed.
3. No production deployment exists: TLS, DNS, monitoring and on-call, backups and restore drills,
   witness-provider selection, audit-key custody and checkpoint anchoring are operator work
   (`ops/`).

**Code state: READY FOR INDEPENDENT AUDIT.** Every confirmed P0/P1 is fixed with a test that a
deliberate revert showed failing; every known residual is written down.

| Severity | Found at `29e4356` | Fixed | Open |
|---|---|---|---|
| P0 | 0 | 0 | 0 |
| P1 | 5 | 5 | 0 |
| P2 | 14 | 13 | 1 — R30-J-2, branch protection (owner) |
| P3 | 35 | 35 | 0 |

Info items and non-findings are listed in the registry and not counted. <!-- WS-E --> WS-E's
findings are added when it merges.

**Unauthorised sign/send paths.** None known. Every live signing primitive in the repository is
reached only through `GraphiteGuard.executeTransfer` / `executeSwap`. In order, that path runs:

1. grounding of the request in the user's own text;
2. the spend cap and the rolling aggregate;
3. an in-flight claim and the unresolved-submission check;
4. `BoundTransaction.build` and the unsigned simulation;
5. the Core's verdict on those exact bytes, then AuditBind;
6. `executeBoundTransaction`, which:
   - recomputes the decision and requires the Core's to agree (`assertExecutableVerdict`);
   - asks the person to confirm (exactly `true`, within a timeout, on a frozen summary naming the digest);
   - signs with `signApproved` (digest and signer-set check, a non-extractable key);
   - records the signing on the trail and the unresolved submission before the bytes leave;
   - then calls `sendRawTransaction`.

The SolanaAgentKit wallet refuses every signing method. The MCP and Vercel tools go through the
same path, and the Vercel tools now require a post-resolution confirmation. The devnet demo goes
through it with a cap. `executeBoundTransaction` stays exported but cannot sign without the
caller's own key and the decision check, and no official example calls it. The signing classes
are frozen, and `fetch` is captured at load in the guard and in the SDK client, so a later plugin
can neither switch the gate off nor answer the Core for it. Escape tests (direct connection,
injected wallet, private fields, replaced methods, replaced `fetch`, missing await, concurrent
calls) are in `integrations/agent-guard/guard-round30.test.ts`; the call graph with its trust
boundaries is in `audit-r30/architecture.md`. Out of reach: code loaded into the process before
the guard, or code that patches `crypto.subtle` — that needs a separate signing process.

**The most serious findings fixed:**

| ID | What a caller could do at `29e4356` | Proof the old behaviour is gone |
|---|---|---|
| R30-A-1 / H-1 (G-01) | Get `approved: true` for bytes nothing had simulated, or for no bytes, and have any client gating on `approved` sign it | `tests/round30_execution_decision.rs` (6 of 8 fail with the rule reverted); TS and Go agreement tests; the guard's G-01 tests |
| R30-B-1 (G-02) | Name a permissive profile in their own requests and raise a fresh program's confidence for every caller (0.44 → 0.64 in three transfers) | `tests/round30_trust_learning.rs`: 40 attacker requests, sequential and 32 concurrent, add 0 samples; all 11 targeted tests fail with the eight reversions |
| R30-F-1 | Move a signer's tokens or lamports under a manifest whose declaration is silent or unreadable, at most a warning (5 SOL under "frobnicate the widget") | `tests/r30_declared_effects.rs` (6 fail with the signer rule off) |
| R30-C-1 (G-07) | With write access to the data directory, rewrite the audit trail coherently | `durable::chain_trail_tests`, `tests/round30_audit_chain.rs` (any-MAC break caught) |

**Remaining risk**, each detailed in §H and the registry:
- **Code:**
  - 155 unreadable value-moving declarations still only warn (owner).
  - The Core does not judge a withdrawal's minimum outputs.
  - Shape baselines and anchors are unmeasured on real RPC traffic.
  - L8 independence is a heuristic, not a light-client proof.
- **Operational:**
  - An unkeyed trail is corruption-evident only.
  - Checkpoint storage is the operator's.
  - Single replica.
- **Data and coverage:**
  - 13 manifests below the decode bar.
  - Most of the chain unmanifested.
  - A 38-row holdout.
- **For the external auditors:**
  - The execution-decision contract across four languages.
  - The guard's in-process threat model.
  - The audit chain's key handling.
  - Witness independence.
  - The 21 intent grants' facts.

## B. File coverage

The ledger (`audit-r30/file-ledger.json`, summary in `audit-r30/file-ledger-summary.md`) has an
entry for every one of the 894 files at `29e4356`; **not inspected: 0**. Honest depth:

| Depth | Files |
|---|---|
| Read in full by a reviewer | 47 |
| Read in named sections | 17 |
| Historical reports reviewed for their findings | 4 |
| Test files executed | 48 |
| Automatically validated (strict JSON parse, schema, counts, lockfile provenance and integrity, image and PDF headers) | 484 |
| Pattern-scanned only (panics, unwraps, `unsafe`, `as any`, skips, TODOs, masking, secrets) | 294 |

"Scanned" is not "read": 294 files had only the pattern triage. The source the workstreams changed
was read by those workstreams in full; that reading is recorded in their reports, not in the
ledger's read log, which reflects the ledger pass at `29e4356`.

## C. Findings registry

[`audit-r30/findings-registry.md`](audit-r30/findings-registry.md): every R30-* finding and every
K-01 … K-20, with ID, severity, class tag, location, status, regression test, break evidence,
residual and owner, and the disposition of each of the twelve leads.

## D. Architecture and data flow

[`audit-r30/architecture.md`](audit-r30/architecture.md), reconstructed from the code. It covers:
- the pipeline and its approval rule;
- every sign/send sink and what holds each;
- L8, persistence, credentials and CI;
- each integration, with every trust boundary and alternate path marked.

Round 30 changes to it:
- the decision is computed at the one place a result is built;
- the guard's path gains the decision check, the in-flight claim and the durable state file;
- the trail gains the chain and its writer lock;
- L8 gains `inclusion_assurance`.

## E. Fixes, by workstream

- **WS-A — the execution contract.**
  - `decision` / `executable` on every verdict: one function, schema invariants, and TS and Go recomputation.
  - `instruction_bind_key` beside a deprecated `content_hash`.
  - CLI exit 3 on an analysis-only approval.
  - `transaction_builder` renamed to what it is (a summary).
  - `with_data_dir` deprecated.
  - The TS client bounds response bodies.
  - Four real verdict fixtures, one per decision, read by Rust, TS and Go.
- **WS-B — trust.**
  - Evidence only at the built-in floor; the learning variable retired.
  - Shape baselines with a fixed anchor and a versioned snapshot.
  - Evidence withdrawn on an upgrade, and dated at first sighting.
  - A refusal-class table.
  - NaN-safe policy comparison; the confidence engine's claims corrected.
- **WS-C — the audit trail.**
  - A hash chain with HMAC under an operator key file.
  - `graphite audit verify` and `graphite audit checkpoint`, with checkpoints per rotation.
  - One writer per trail, and read-only opens.
  - A directory sync after a snapshot rename; a root-proof rotation-failure test.
- **WS-D — RPC, L8, server.**
  - `inclusion_assurance`, provider independence (the same provider under another key is one provider), and the high-assurance mode.
  - Metadata and link-local RPC addresses refused, re-checked at resolution.
  - Auth on the matched route and exactly one `Authorization` header.
  - A read-only key, and a route-by-key surface test.
- **WS-F — detectors and manifests.**
  - The L4 signer-loss rule under unreadable declarations; `graphite:` lines refused.
  - Unsealed fixtures refused; the PDA bump search tested.
  - Every unbroken Round 29 check broken; the nine uncaught given tests.
  - Attack cases assert their claimed approvals.
  - The census of 137 manifests, 3,541 instructions and 46 unclassed, re-counted.
- **WS-G — intents.** 21 grounded grants for withdraw, claim, close, burn and configure; the conformance harness no longer takes a nonce advance as the primary (re-pinned, attributed).
- **WS-H — the signing side.**
  - The guard enforces the decision.
  - Effect-keyed, durable duplicate-send state.
  - Confirmation hardened, and required for Vercel.
  - Frozen signing path; captured `fetch`; non-extractable key.
  - Anomalies recorded; capabilities and the wSOL refusal stated as data.
  - The devnet demo routed through the guard.
- **WS-I — dashboard and AI layer.**
  - Green only for an executable approval.
  - Shape-checked answers; a connection change clears stale figures.
  - CSP and header fixes; 0 axe violations.
  - The AI layer labels doubtful text `unknown` and never echoes key material.
- **WS-J — CI, supply chain, container, operations.**
  - Test-count floors, ignore and skip allowlists, pipefail, and a `CI gate` job.
  - Concurrency fixed; npm allowlist entries expire.
  - Compose: stop grace and a strict healthcheck; an MSRV job.
  - Rulesets and CODEOWNERS prepared; runbooks in `ops/`.
  - Seven safe Dependabot updates applied; ten deferred.
- **WS-K — the ledger, the architecture map and the historical regression matrix** (`audit-r30/`).
- **Integration (coordinator):**
  - the guard's test mocks speak the Round 30 contract;
  - the guard's own decision check is unit-tested;
  - the SDK client captures `fetch` at load (broken and caught);
  - the dashboard shows L8 assurance and audit integrity;
  - `.env.example`, compose and the key runbook document the audit key, the anchor directory and the read key.

## F. Test and build evidence

Integrated tree `1f5fc1f` (all workstreams but WS-E), release builds with thin LTO off, on a shared
4-CPU machine:

| Suite | Command | Result |
|---|---|---|
| Rust, all features | `cargo test --release --all-features --no-fail-fast` | 159 binaries: 2,224 passed, 0 failed, 13 ignored |
| Rust, featureless library | `cargo test --release --no-default-features --lib` | 459 passed, 0 failed, 2 ignored |
| Rust, cli only | `cargo test --release --no-default-features --features cli --no-fail-fast` | 159 binaries: 1,863 passed, 0 failed, 4 ignored |
| Rust type-check | `cargo check --release --all-features --all-targets` (and the two other legs) | clean |
| fmt | `cargo fmt --all -- --check` | clean |
| Agent guard | `npm test` | 277 passed |
| SolanaAgentKit / MCP / Vercel AI | `npm test` | 9 / 9 / 11 passed |
| TypeScript SDK | `npm run check && npm test` | 55 passed, 4 live skipped |
| Dashboard | `npm test && npm run build` | 31 passed; build OK |
| Go SDK | `gofmt -l`, `go vet`, `go test -count=1 -v ./...` | 59 top-level tests pass, 0 skipped (+5 under `liveserver`, not run) |
| Python AI layer | `pytest -q` (hash-locked requirements) | 50 passed |
| Docs consistency | `docs_numbers_match_the_code`, `docs_match_the_registry`, `docs_paths_resolve`, `contract_version_gate` | 8 / 2 / 1 / 4 passed |
| Hosted CI on the base `29e4356` | run 39610913297 | all 10 jobs green |
| Assurance | <!-- WS-E --> fuzz durations and execs, mutation scores, coverage, the release evaluation | pending the WS-E merge |

Each workstream also ran fmt and clippy `-D warnings` on all three feature legs at its own head.
Rust full-suite runs at each workstream head: WS-A 2,110; WS-B 2,113 (3 stale lib tests then fixed:
613 lib); WS-F 2,133; WS-G 2,116 — all 0 failed, 13 ignored.

**Deliberate breaks.** Every Round 30 fix was reverted against its own test, and the test failed.
The per-finding records are in the registry. In summary:
- **Batched reverts:**
  - WS-B applied eight reversions in one build; all 11 targeted tests failed.
  - WS-C applied five breaks together; 5 tests failed, 63 still passed.
  - WS-D applied seven breaks; each was caught by its named test.
- **WS-F's revalidation of Round 29:**
  - 62 mutants of risk checks, registry checks and manifest-validator checks, plus 6 fix breaks.
  - Nine checks no test caught (Check 6b, the A3-07 replay, submitted-corpus integrity, the registry's empty-discriminator rule, the low-reputation attester, `from_json` integrity, program-id-as-pubkey; Checks 6a and 9 thin) now have isolated tests that fail when broken.
  - One check, the 32-byte seed range, is unreachable and pinned as such.
- **WS-G:** grants off → 7 of 9 failed; facts unchecked → 5 failed.
- **WS-H:** every boundary fix broken and caught.
- **WS-I:** 9 breaks caught, including the browser smoke script against a broken colour rule.
- **WS-J:** the gate's expiry check off → 1 failed.
- **Integration:**
  - The guard's agreement check skipped → its unit test failed.
  - The SDK's captured `fetch` reverted → the escape test failed.

**Container.** A local Docker daemon was started, and a local copy of the Dockerfile was built with
offline crates and the CA bundle copied from the builder, because the build sandbox had no
network. These all passed:
- healthy; `/data` writable; 401 without a key;
- strict healthcheck; read-only root; capabilities dropped; uid 10001;
- SIGTERM exits 0; a keyless or dev-mode container refuses to start;
- audit records survive a recreate.

The unmodified `apt-get` step and the online crate fetch run only in CI.

## G. Owner and operator release gate

1. **Apply the rulesets** in `.github/rulesets/` (`gh api` steps in `ops/branch-protection.md`): no
   deletion, no force-push, PR-only, threads resolved, `CI gate` required from GitHub Actions; the
   review ruleset when a second maintainer exists; immutable `v*` tags. Delete or protect the stale
   branches (K-14). **STOP-SHIP until done.**
2. Enable GitHub private vulnerability reporting; link it from `.github/ISSUE_TEMPLATE/config.yml`.
3. Commission an independent third-party audit; hand it this report and the registry.
4. Decide R30-F-1's residual: refuse the 155 unreadable value-moving instructions until their
   manifests say what they move, or keep the warning. Decide W19 likewise.
5. Decide R-M9 (Constitution P12 vs. the drainer heuristic), `GRAPHITE_QUARANTINE_ON_UPGRADE`'s
   default (an upgrade already withdraws evidence), and the self-heal threshold (R-P10).
6. Review the deferred Dependabot updates as their own changes: #41 (13 new crates, including the
   archive compression backend), #12 (sha2 0.11), TypeScript 7 in six packages (#14, #18, #21,
   #23, #27, #28), #22 (React 19), #26 (rust 1.99 with the CI toolchain).
7. <!-- WS-E --> Confirm the fuzz, mutation and coverage workflows' budgets and floors.
8. <!-- WS-E --> Review the generated release evaluation before any public claim.
9. **Deployment:**
   - TLS at the proxy, DNS, monitoring and alerting on `/health` `degraded` and the `/metrics` series, with on-call.
   - Backups and a restore drill (`ops/backup-restore.md`).
   - An independent witness provider with `GRAPHITE_L8_HIGH_ASSURANCE=1`.
   - An audit MAC key kept off the data volume.
   - Scheduled checkpoints to WORM or object-lock storage.
   - A single replica: the rate limiter is per-process (R-M12).
   - The read-only key for the dashboard.
10. Decide the crate's publish flag and tag `0.3.0-beta`.
11. Sample data: real Tier 3+ baselines (`sample_count ≥ 20`, R-P7) need a running deployment.
12. MMM `updatePool` needs its IDL before it can be granted.

## H. What could not be proven

1. **No light-client proof.** L8's best answer is two providers agreeing. Independence is judged
   from URLs, DNS and the operator's provider names, with a short built-in suffix list. Two
   companies on one cloud are not detected. Behind an HTTPS proxy, only the proxy's address is
   checked. The high-assurance path with a real non-loopback witness was tested only through the
   independence override.
2. **Shapes and anchors on real traffic.** Their false-positive effect on real RPC traffic was not
   measured; the committed conformance blocks run offline and do not exercise L3.
3. **The audit trail's limits.**
   - Keyed, it still cannot show a dropped tail or a stale restore without an anchored checkpoint.
   - Nothing in Graphite makes anchor storage immutable.
   - The directory sync after a snapshot rename is fixed by inspection; proving it needs power-loss injection.
   - A full disk was simulated by fault injection, not a filled filesystem.
4. **The guard's reach.**
   - Code loaded before it, or patching `crypto.subtle`, is out of reach.
   - Two guard processes with one key share no ledger.
   - A transfer's cap counts the amount, not the about-5,000-lamport fee.
   - The devnet demo was not run live (no funded wallet or AI layer here).
   - The swap-output `deliveredAs: "wrapped_sol"` path has no end-to-end fixture.
5. **Withdrawals.** The Core does not judge a granted withdrawal's minimum outputs. The R-M14 (219)
   and R-M13 (9) costs were not re-measured: the 48,855-transaction sample is not in the
   repository. Pump AMM `withdraw` and the marketplace `update_offer` grants rest on the shipped
   manifests' layouts, not on IDLs in the repository.
6. **Tests not run.**
   - The two proptest suites under the risk mutants.
   - The CLI exit-code mapping as a break on its own.
   - `/health` with an RPC attached (the test state cannot attach one).
   - The Go `liveserver` and TS live-server suites (run only in CI's container job).
   - The ignored live-network tests.
7. **The dashboard.**
   - No screen-reader session; Chromium only.
   - Light mode captured, not redesigned.
   - The decision rendering was checked against a stand-in Core before the server emitted the field.
   - The browser smoke script is not in CI.
8. **Not run here:**
   - the new CI behaviour (`CI gate`, MSRV job, merge-queue and schedule triggers, test-count floors) has not yet run on the hosted runners;
   - govulncheck was blocked (the proxy refuses `vuln.go.dev`);
   - the unmodified Dockerfile's `apt-get` step ran only in CI.
9. <!-- WS-E --> Fuzzing, mutation testing and coverage: pending the WS-E merge.
10. <!-- WS-E --> The release evaluation's figures: pending the WS-E merge.
11. **Ledger depth.** 294 files were pattern-scanned rather than read by a person (§B).

Launch stays blocked on §G items 1–3 and 9 regardless of anything above.
