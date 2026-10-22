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
gh attestation verify graphite-0.3.0-beta-x86_64-unknown-linux-gnu.tar.gz --repo Stan-lee13/graphite
```

The tag is built by `.github/workflows/release.yml` (two independent builds,
compared byte for byte; SLSA provenance and SBOMs attested), so the binary and
image you can verify are the ones built from the source you read. Until the tag
exists, the reviewed base is **`bdc9dab`** (Round 31: every dependency at its
latest release, on top of the Round 30 remediation `9f4556e`) plus the
Round 32 changes merged after it; agree the exact SHA with the maintainer
before starting and record it in your report.

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
but do tell us if one is worse than we say. Detail:
`docs/round30-forensic-audit-and-remediation-2026-10-22.md` §H and
`docs/audit-r30/findings-registry.md`.

From Round 30 §H:

1. **No light-client proof.** L8 independence is a heuristic over URLs, DNS and operator-named
   providers; two companies on one cloud are not detected; behind an HTTPS proxy only the proxy's
   address is checked.
2. **Shape baselines and anchors** are unmeasured on real RPC traffic (false-positive rate unknown).
3. **The trail's limits.** Without an anchored checkpoint a keyed trail cannot show a dropped tail or
   a stale restore; anchor immutability is the operator's storage; the post-rename directory sync is
   fixed by inspection, not power-loss injection; a full disk was fault-injected, not filled.
4. **The guard's reach.** Code loaded before it is out of reach; `deliveredAs: "wrapped_sol"` has
   no end-to-end fixture. (Two guards with one key, and the fee missing from the cap, were fixed in
   Round 32: R32-P2-1, R32-P2-2. The one-guard-per-wallet lock reaches only guards on the same host
   that share a pid namespace.)
5. **Withdrawals.** Only three grants carry a minimum output Graphite can read (Raydium CLMM
   `decrease_liquidity_v2`, Raydium CPMM `withdraw`, Pump AMM `withdraw`; an unbounded one is
   refused since Round 32, R32-P1-4); the Meteora DLMM remove and claim grants carry none, so they
   are not judged. Pump AMM `withdraw` and `update_offer` rest on the shipped manifests' layouts,
   not IDLs.
6. **Value-moving declarations.** Since Round 32 a signer's loss under an unreadable declaration is
   refused by default (R32-P1-1; opt-out `GRAPHITE_ALLOW_UNREADABLE_VALUE_DECLARATIONS`), and so is
   W19 (R32-P1-3; opt-out `GRAPHITE_ALLOW_SIGNER_LAMPORTS_OUTSIDE_DECLARED_DEBIT`). 139
   value-moving instructions still have placeholder prose (no IDL in the repository), so they are
   refused when they cost the signer value. The false-refusal cost of these defaults on real
   traffic: W19 refused 1 of 200 replayed live mainnet transactions (0.5%, Round 32); the other
   rates are measured by `.github/workflows/live-mainnet.yml`, not by the committed blocks, which
   carry no state diffs.
7. **Tests not run** in that round: the proptest suites under the risk mutants; `/health` with an
   RPC attached; the live-server SDK suites outside CI; the ignored live-network tests.
8. **Fuzzing, mutation, coverage.** Six fuzz targets run 30 minutes each on GitHub's runners (hosted
   run 39798389463: 0 crashes); no differential fuzzing against agave; the mutation floors for the
   state diff, artifact parser and simulation integrity are still provisional (0.60), unmeasured;
   the line-coverage floor (78%) held on the hosted run.
9. **The release evaluation** holdout is 38 rows; its false-refusal rate means almost nothing.
10. **Single replica**: the rate limiter and caps are per process.
11. **Ledger depth**: 294 files were pattern-scanned, not read by a person.

From Round 31 (dependencies held back, with reasons — `graphite-core/CHANGELOG.md`):

12. The runtime oracle's `solana-transaction`/`solana-message` stay below 6.0: 6.0 removes the v1
    `MAX_SIGNATURES`/`MAX_ADDRESSES`/`MAX_INSTRUCTIONS` limits the oracle checks Graphite against.
13. `bincode` stays on 1.x (the runtime's packet crate still decodes with bincode 1).
14. `@solana/web3.js` stays on 1.x and `@types/node` on 22.x.

From Round 32 (this hand-off's own work): the release workflow had not run on GitHub when this was
written; ACME/TLS, the systemd units under a running systemd and the S3 Object-Lock upload were
validated with their tools and a loopback test, not in a real deployment (`deploy/README.md`).

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
5. **The 21 intent grants' facts**: does each grant's declared effect match what the program does?
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
