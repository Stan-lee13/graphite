# Independent audit hand-off

Everything an external auditor needs to start on Graphite without a briefing
call: what to audit, what we believe holds and which test holds it, what we
already know does not hold, and what we want you to tell us. Every earlier
review of this code was internal engineering work by the maintainer and AI
engineering agents; **none was independent, and nothing here is a
certification.** Disagree with any of it.

## 1. The commit

Audit the commit the release tag `v0.3.0-beta` names, once it exists:

```sh
git rev-parse 'v0.3.0-beta^{commit}'
gh attestation verify graphite-0.3.0-beta-x86_64-unknown-linux-gnu.tar.gz --repo Stan-lee13/graphite \
  --signer-workflow Stan-lee13/graphite/.github/workflows/release.yml \
  --source-ref refs/tags/v0.3.0-beta --deny-self-hosted-runners
```

The tag is built by `.github/workflows/release.yml` (two independent builds,
compared byte for byte; SLSA provenance and SBOMs attested), so the binary and
image you can verify are the ones built from the source you read. Until the tag
exists, the base to review is the head of the branch
`claude/admiring-archimedes-lfhr7n`: Round 38's answers to the Round 37 re-audit,
on top of `8b3d8a4` (`main` after Round 36, PR #53). That branch is not merged to
`main` yet, and it moves while the remaining Round 37 items are answered, so agree
the exact SHA with the maintainer before starting and record it in your report.
[`docs/CURRENT.md`](../CURRENT.md) says which round the code is at; `git log -1 --
docs/CURRENT.md` says when it last changed.

The state of the code is: **conditionally ready for an independent audit, with the
owner gates open** (`docs/ops/production-checklist.md`). Release is blocked on
those gates. Every review so far was internal engineering work.

## 2. Scope

| In scope | Where |
|---|---|
| The verification Core: transaction parsing, the layer pipeline (L1–L6), risk engine, state diff, simulation integrity, confidence, policy, L8 execution reconciliation | `graphite-core/src/` (Rust) |
| The HTTP server: auth, rate and connection limits, the routes, `/health`, `/metrics`, startup refusals | `graphite-core/src/server.rs` |
| The audit trail: hash chain, HMAC keying, rotation, archive index, checkpoints, `graphite audit verify` | `graphite-core/src/durable.rs`, `graphite-core/src/durable/` |
| Protocol manifests and the registry (signed submissions, revocation) | `graphite-core/protocols/`, `graphite-core/src/manifest_registry.rs` |
| The agent-side signing path: the guard, bound transactions, residual policy, the execution lifecycle | `integrations/agent-guard/` |
| The SDKs' decision contract (TypeScript, Go) and the framework adapters (MCP, Vercel AI, Solana Agent Kit) | `sdk/`, `integrations/` |
| Deployment and release configuration | `deploy/`, `.github/workflows/release.yml`, `Dockerfile` |

Lower priority: the Python AI layer (advisory only; it never decides,
`tests/ai_cannot_approve.rs`), the dashboard (read-only views), the runtime
oracle (`tools/runtime-oracle/`, a test harness).

Out of scope: the Solana runtime and programs themselves, RPC providers,
third-party protocols' own security, the operator's infrastructure.

## 3. Threat model

The system, reconstructed from the code, with every trust boundary (TB-1 …
TB-10) and alternate path marked: [`docs/audit-r30/architecture.md`](../audit-r30/architecture.md).
Read it first.

**Assets**, most valuable first:

1. **Signing authority over the user's wallet** — held only in the agent
   process, by the guard (`SOLANA_PRIVATE_KEY`, a non-extractable key).
2. **The verdict's meaning**: an `approved`/`executable` answer must be about
   the exact bytes that will be signed, simulated where an RPC is attached.
3. **The audit trail**: every verdict, lifecycle event and L8 reconciliation,
   tamper-evident when keyed (`GRAPHITE_AUDIT_KEY_FILE`), anchored by checkpoints.
4. **Learned trust**: per-program baselines and confidence, which must not be
   trainable by the callers they judge.
5. **Credentials**: the verify, read and admin API keys; RPC URLs (they embed
   provider keys); the audit MAC key; registry signing keys.

**Adversaries**:

| Adversary | Can | Must not be able to |
|---|---|---|
| A prompt-injected model or tool caller | choose the request text and, for swaps, the route | sign anything the user's text does not ground; exceed the spend cap; skip consent (TB-1) |
| A malicious transaction or protocol author | craft any transaction bytes, CPIs, account layouts, lookup tables, Token-2022 extensions | get `approved` for an effect the manifest does not declare or the user did not ask for |
| A holder of the verify key (any client) | call `/verify`, `/audit/event`, `/verify/execution` | raise another caller's trust (G-02), reach `/admin/*`, rewrite the trail (TB-5) |
| A faulty or hostile RPC provider | answer anything to the Core's or the guard's RPC calls | turn a refusal into an approval; forge inclusion when an independent witness disagrees (TB-3, TB-6) |
| Someone with write access to the data directory | edit, drop or restore files | rewrite the keyed trail without detection; hide a dropped tail or a stale restore from an anchored checkpoint (TB-7) |
| A registry submitter | submit signed manifests | replace an accepted manifest's lineage, replay a revoked one (TB-8) |
| A network attacker in front of the Core | send anything to the edge | reach `/health`, `/metrics`, `/admin/*` from outside; bypass the per-client rate limit by spoofing `X-Forwarded-For` (`deploy/caddy/Caddyfile`, `deploy/tests/run.sh`) |
| The supply chain | publish a malicious dependency or action version | change what ships without a lockfile or SHA-pin change in review (`--locked` builds, SHA-pinned actions, cargo-audit, the npm gate) |

**Out of reach by design**, stated so you can judge it: code loaded into the
agent process before the guard, or code that patches `crypto.subtle` (needs a
separate signing process); a compromised host running the Core (it can lie
in every verdict; the checkpoint anchors and the agent's own consent are what
remain).

## 4. Build, run, test

Toolchain: Rust 1.99.1 (CI and the container; MSRV 1.89), Node 22, Go
1.26/1.27, Python 3.11 or 3.13 (the versions CI runs).

```sh
# The Core: library, server and CLI
cd graphite-core
cargo build --release --locked --features server,cli
cargo test --locked --release                                # CI holds each leg to a floor:
cargo test --locked --release --no-default-features --lib    # see .github/workflows/ci.yml and
cargo test --locked --release --no-default-features --features cli   # docs/CURRENT.md for the counts
cargo clippy --locked --all-targets --all-features -- -D warnings

# Run it (the server refuses to start without a key of 32+ characters)
GRAPHITE_API_KEY=$(openssl rand -hex 32) ./target/release/graphite server --port 7331
curl -s localhost:7331/health
curl -s -H "Authorization: Bearer $GRAPHITE_API_KEY" -H 'Content-Type: application/json' \
  --data-binary @../examples/verify-input.json localhost:7331/verify

# The audit trail
./target/release/graphite audit verify --data-dir ./graphite-data --key-file <key>

# The agent guard and the SDKs
(cd ../integrations/agent-guard && npm ci --ignore-scripts && npm test)
(cd ../sdk/typescript && npm ci --ignore-scripts && npm test)
(cd ../sdk/go && go test ./...)

# Fuzzing (nightly toolchain, cargo-fuzz)
cd fuzz && cargo +nightly fuzz run state_diff -- -max_total_time=600

# Deployment configuration, end to end against a live Core and Caddy
cd ../.. && GRAPHITE_BIN=$PWD/graphite-core/target/release/graphite deploy/tests/run.sh
```

`.github/workflows/ci.yml` is the authoritative list: every job, its
commands and the test-count floors; the `CI gate` job passes only when every
other job did. Live-network tests are `#[ignore]`d and run with
`--ignored` against an RPC you supply (`GRAPHITE_RPC_URL`).

## 5. Invariants and the tests that hold them

Each was shown, in the round that added it, to fail with its fix reverted
(the break records are in `docs/audit-r30/findings-registry.md` and the round
reports). Paths are under `graphite-core/tests/` unless stated.

| # | Invariant | Held by |
|---|---|---|
| I-1 | `approved`/`executable` is about exact bytes: an approval for bytes nothing simulated, or for no bytes, is never executable | `round30_execution_decision.rs`, `round30_decision_fixtures.rs`, `artifact_binding.rs`; `sdk/typescript/src/execution-decision.test.ts`, `sdk/go/decision_test.go` (the same fixtures in each language) |
| I-2 | A caller cannot raise any program's confidence for other callers | `round30_trust_learning.rs` |
| I-3 | A signer's lamports or tokens move only under a manifest that declares the movement | `r30_declared_effects.rs`, `r30_declared_effects_census.rs`, `round30_fuzz_findings.rs` |
| I-4 | An L2, L4 or L5 failure refuses, whatever the confidence or the profile | `l2_l4_l5_hard_gate.rs`, `l4_state_diff_gate.rs` |
| I-5 | The AI layer cannot approve; intent text cannot clear danger | `ai_cannot_approve.rs`, `ai_layer_isolation.rs`, `audit_review_r2_r3_intent_cannot_clear_danger.rs`, `round30_grounded_intents.rs` |
| I-6 | Every audit record is chained; keyed, any edit, drop or reorder is detected; a checkpoint detects a dropped tail and a stale restore | `round30_audit_chain.rs`; `deploy/tests/run.sh` (tamper and stale-restore refusals) |
| I-7 | A verdict that cannot be recorded is not returned (503 `AuditWriteFailed`) and is not counted; an error record cannot be made arbitrarily large | `server::tests::a_verdict_that_could_not_be_recorded_is_not_counted` (`graphite-core/src/server.rs`), `audit_flooding.rs` |
| I-8 | The RPC is untrusted: its answers are bounded, cannot turn a refusal into an approval, and never leak its URL | `rpc_trust_boundary.rs`, `rpc_influence_bounds.rs`, `rpc_budget.rs`, `rpc_secret_redaction.rs`, `round29_rpc_client.rs` |
| I-9 | L8 reports inclusion only on chain bytes bound to the signature, and says what it rests on; a blocked transaction seen by either endpoint raises the alarm | `round30_l8_assurance.rs`, `l8_execution_reconciliation.rs`, `round12_rpc_equivocation.rs`, `audit_review_r1_l8_needs_chain_bytes.rs` |
| I-10 | Unsafe configuration refuses to start (no key, short or equal keys, empty audit variables, key inside the data dir, retired options) | `audit_2026_10_20_startup_refusals.rs` |
| I-11 | Requests are bounded: body 1 MiB, identifiers, header and body timeouts, connection caps | `wire_format_bounds.rs`, `audit_a4_slow_headers_hold_connections.rs`, `audit_w21_connection_lifetime.rs` |
| I-12 | The guard is the only signing path; the SAK wallet refuses every signing method; a forged verdict cannot get bytes sent | `integrations/agent-guard/guard-round30.test.ts`, `toctou-signing-boundary.test.ts`, `execution-lifecycle.test.ts`; `integrations/solana-agent-kit/gated-wallet.test.ts` |
| I-13 | A redeployed or quarantined program loses its evidence until re-earned or lifted | `rm1_program_upgrade_detection.rs`, `quarantine_gate.rs` |
| I-14 | Pinned outputs change only with row-by-row attribution | `mainnet_conformance.rs` (digest), `regression_corpus.rs`, `release_evaluation.rs` |
| I-15 | The edge exposes only the client routes; its body limit is the Core's; a spoofed `X-Forwarded-For` does not escape the rate limit | `deploy/tests/run.sh` |
| I-16 | A release binary is reproducible and published only from a CI-green commit | `.github/workflows/release.yml` (`gate`, `reproducible` jobs) |

## 6. Known residuals

We know these and have not fixed them; do not spend time rediscovering them,
but do tell us if one is worse than we say.

**The one current list is [`docs/CURRENT.md`](../CURRENT.md)** ("Security status",
"What is NOT enforced" and "Not yet done"). This page does not copy it,
so the two cannot drift. Where each residual came from, newest first:

| Round | Where its residuals are recorded |
|---|---|
| 38 (the Round 37 re-audit answered, in part) | [`round38-…-2026-10-24.md`](../round38-the-round-37-re-audit-answered-2026-10-24.md) §E and §F. The Round 37 findings past its first seven P1s were open when that report was written; later commits on the branch answer more of them by finding id (`git log --oneline 8b3d8a4..`) |
| 37 (internal re-audit of `8b3d8a4`) | The owner's re-audit report. It is not in the repository; Round 38 and the commits after it cite its findings by id (R37-n) |
| 36 (the owner's forensic brief, F-001..F-022) | [`round36-…-2026-10-24.md`](../round36-the-request-is-bound-to-the-bytes-2026-10-24.md) §E and §F |
| 35 (live mainnet, parsed CPIs) | [`round35-…-2026-10-23.md`](../round35-live-mainnet-and-the-parsed-cpi-report-2026-10-23.md) |
| 34 (the Round 33 deep audit answered) | [`round34-…-2026-10-23.md`](../round34-the-deep-audit-remediated-2026-10-23.md) §G. The Round 33 audit report and the Round 34 remediation brief it cites (R33-n, DOC-n) are not in the repository |
| 31–32 (dependencies, production readiness) | [`round32-…-2026-10-22.md`](../round32-production-readiness-2026-10-22.md); the dependency holds, with reasons, in `.github/dependency-holds.json` and `graphite-core/CHANGELOG.md` |
| 30 (forensic audit of `29e4356`) | [`round30-…-2026-10-22.md`](../round30-forensic-audit-and-remediation-2026-10-22.md) §H and [`docs/audit-r30/findings-registry.md`](../audit-r30/findings-registry.md) |

A residual recorded in an older report may since have been fixed or changed;
CURRENT says which. The owner and external gates (the rulesets, the `release`
environment, private vulnerability reporting, the dependency pull requests, the
sign-off of the nine medium-confidence declaration rewrites, deployment, WORM
anchoring, RPC independence, a live-mainnet replay, a larger holdout and this
audit) are items in [`docs/ops/production-checklist.md`](../ops/production-checklist.md).

## 7. What we want you to answer

1. **The execution-decision contract** (I-1): is there any input — bytes, lookup tables, a v1
   transaction, a simulation answer — for which the Core says `executable` about something other
   than what the guard then signs? Do the Rust, TypeScript and Go implementations agree on every
   input, not only the shared fixtures?
2. **The guard's in-process threat model** (I-12): within its stated limits (nothing loaded before
   it, `crypto.subtle` intact), can a tool caller, a plugin or a forged Core response get bytes signed
   or sent that the user did not ground and confirm?
3. **The audit chain's key handling** (I-6): MAC construction and canonicalisation, key-id derivation,
   rotation across keys, the checkpoint format; can someone without the key extend, truncate or
   splice the trail undetected, given an anchored checkpoint? Without one?
4. **Witness independence** (I-9): is the heuristic a reasonable basis for
   `GRAPHITE_L8_HIGH_ASSURANCE`, and what would you require instead?
5. **The 27 intent grants' facts** (`graphite-core/src/intent_grants.rs`): does each grant's declared effect match what the program does?
6. **Declared effects** (I-3): can value leave a signer under a manifest that declares something
   narrower — through CPIs, Token-2022 extensions, close/realloc, lookup-table indirection?
7. **Trust learning** (I-2): any path, including concurrency and the registry, by which callers
   move confidence?
8. **The edge and the release** (I-15, I-16): is `deploy/` a safe default production configuration;
   does the release workflow's permission split and digest handling hold?
9. **Residuals**: is any item in §6 worse than we describe, and which would you block a launch on?

Send findings privately to the contact in `SECURITY.md` (GitHub private vulnerability reporting is
not enabled on the repository yet; it is an owner item in `docs/ops/production-checklist.md`), one
per issue, with a reproduction where possible. We will answer each with its fix,
its regression test and the deliberate revert that shows the test catches it, as every earlier round did.
