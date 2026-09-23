<div align="center">

<img src="assets/brand/graphite-logo-256.png" alt="Graphite logo" width="140" />

# Graphite

**Deterministic semantic verification for Solana AI agents.**

Graphite sits between an AI agent's intent and the wallet's execution. It verifies that a constructed transaction actually does what was declared — with a falsifiable confidence score, not a binary safe/unsafe — and, when given the exact transaction bytes, binds its verdict to those bytes so that what gets signed is what was verified.

**Current status, in one place: [docs/CURRENT.md](docs/CURRENT.md).** Every dated report under `docs/` is a historical record and points there.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![Rust Tests](https://img.shields.io/badge/Rust_Tests-1562_passing-brightgreen?style=flat-square)](graphite-core/tests/)
[![Status](https://img.shields.io/badge/Status-security--hardened_alpha-orange?style=flat-square)](docs/CURRENT.md)
[![Clippy](https://img.shields.io/badge/Clippy-0_warnings-brightgreen?style=flat-square)](graphite-core/)
[![Protocols](https://img.shields.io/badge/Protocol_Manifests-129-blue?style=flat-square)](docs/protocol-coverage.md)
[![Risk Patterns](https://img.shields.io/badge/Risk_Patterns-11_red?style=flat-square)](graphite-core/src/risk_engine.rs)
[![Version](https://img.shields.io/badge/Version-v0.2.0--beta-orange?style=flat-square)](https://github.com/Stan-lee13/graphite/releases)

</div>

---

## The Problem This Solves

AI agents on Solana can construct and submit transactions autonomously. But nothing verifies that the transaction they *say* they're building is the transaction they *actually* build.

```
WITHOUT GRAPHITE:

  AI Agent → "Swap 1 SOL for USDC" → Construct Transaction → Wallet → Blockchain
                                         ↑
                                    No one checks if the
                                    transaction actually
                                    does what was declared

WITH GRAPHITE:

  AI Agent → "Swap 1 SOL for USDC" → Graphite verifies → Wallet → Blockchain
                                         ↓
                                    8-layer pipeline checks:
                                    • Accounts match the protocol
                                    • Instruction matches the intent
                                    • No drainer patterns
                                    • No authority hijacks
                                    • No hidden transfers
                                    • Confidence score is honest
                                    • Policy threshold is met

                                    If any check fails → BLOCKED. Period.
```

This is not a simulation. This is not advisory. Graphite is a **deterministic verification gate** — if Graphite blocks, the transaction is not submitted.

---

## What Ships Ready to Run

```bash
# Clone
git clone https://github.com/Stan-lee13/graphite.git
cd graphite

# Build the core engine
cd graphite-core
cargo build --release

# Run 1,455 tests — zero setup (1,465 total; 10 network-dependent tests ignored
# unless run explicitly with a live RPC)
cargo test --release
# summed across the test binaries: 1455 passed; 0 failed; 10 ignored

# The same gate CI runs on the feature matrix: the library with no features
# (301 tests) and the cli-only build (1,281) must pass too.
cargo test --release --no-default-features --lib
cargo test --release --no-default-features --features cli

# Run the benchmark (18 scored cases + 2 baseline comparisons, P16 compliant)
cargo run --release --bin graphite -- benchmark
```

---

## Architecture — 8-Layer Verification Pipeline

Each layer can only **reduce** confidence or **block**. No layer can invent confidence that lower layers didn't earn.

| Layer | Name | Responsibility | Failure Mode |
|-------|------|---------------|--------------|
| L1 | Account Resolution | Resolve all required accounts/PDAs | Missing/ambiguous → block |
| L2 | Instruction Verification | Confirm discriminator + args match known shape | Unknown → Unknown Protocol Mode |
| L3 | Simulation Verification | Run `simulateTransaction`, confirm it succeeds | Simulation failure → block |
| L4 | State Verification | Diff pre/post account state vs declared intent | Mismatch → block or flag |
| L5 | Semantic Verification | Compare diff against Semantic Graph expectations | Deviation → confidence penalty |
| L6 | Policy Verification | Apply wallet's policy profile thresholds | Policy violation → block |
| L7 | Risk Verification | Run Risk Engine — forbidden patterns, compositional risk | Forbidden pattern → block |
| L8 | Execution Verification | Post-submission: confirm on-chain result matches prediction | Mismatch → audit trail flag |

**Current status:** L1–L7 run inside every `/verify` call. L3 and L4 are live against real Solana RPC when `GRAPHITE_RPC_URL` is set — L3 simulates and accumulates its own baseline, L4 builds a real pre/post account diff. L8 runs after submission, because that is when there is an execution to verify: call `POST /verify/execution` (or `graphite execution`) with the `content_hash` and the signature, and it reconciles the chain against the verdict Graphite recorded — across the whole audit trail, rotated archives included. The outcome that matters is `BlockedButExecuted` — a transaction Graphite refused that was submitted anyway, which no layer inside a verification request can detect. Live-validated against mainnet.

**The transaction itself, not a description of it.** When the caller supplies `signed_transaction` (the serialized bytes, signature slots empty), Graphite parses the wire format itself — legacy and v0, address lookup tables fetched and resolved, privileges read from the header rather than from the caller — and returns `scope.kind = "artifact_bound"` with `transaction_sha256` over those exact bytes. L2 then requires that the described instruction is *in* the bytes, positionally, and that every sibling instruction is declared. Without the bytes the verdict is `descriptive`: an honest statement about what the caller said, constraining nothing about what gets signed.

---

## Risk Engine — 11 Attack Patterns (13 Risk Checks)

| Pattern | What It Catches |
|--------|----------------|
| **Drainer** | High account-to-change ratio — multi-transfer drain |
| **AuthorityHijack** | SetAuthority/CloseAccount via CPI from untrusted root |
| **HiddenTransfer** | Transaction touches accounts not in declared state changes |
| **UnexpectedCpi** | CPI target not in manifest's allowed list (fail-closed) |
| **FakeSwap** | Swap intent on a non-swap program |
| **PermissionEscalation** | SPL Token Approve instruction when intent is "transfer" |
| **MaliciousAccountChange** | CloseAccount/Allocate when intent is not "close" |
| **CompositionalDrainPattern** | Deep CPI chains (5+) from untrusted roots, or repeated program revisits |
| **Impersonation** | Fund movement to/from vanity addresses impersonating official system accounts (SolPhishHunter class) |
| **MultiInstructionDrain** | Coordinated mass-drain across multiple instructions in one tx (approve-then-transfer, authority-hijack-then-drain, close-and-sweep, mass multi-transfer sweep) |
| **CpiTraceAnomaly** | Malicious shape in hierarchical CPI trace — unknown program, repeated revisits, or vanity-impersonated program in the tree |

All 11 patterns are real detection logic — not stubs, not placeholders. Nine are emitted by the single-instruction risk engine (`risk_engine.rs`); `MultiInstructionDrain` and `CpiTraceAnomaly` are emitted by the transaction-level and CPI-trace analyzers (`tx_pattern_analysis.rs`) and mapped onto the same `RiskPattern` enum in the orchestrator.

---

## Supported Protocols (129 Manifests / 3,186 Instructions)

The full table — every program, its instruction count, the tier the loader
actually applied, and the mainnet measurement behind it — is
**[docs/protocol-coverage.md](docs/protocol-coverage.md)**, which is generated
from the manifests and compared against the loaded registry in CI, so it cannot
drift from the code the way a hand-maintained table does (it had: four rows of
the old table named the wrong tier).

Of those, **106 carry a BattleTested tier that a mainnet measurement supports** — up from 8 that merely declared one.

**A manifest does not get to award itself a trust tier.** `BattleTested` lifts
the confidence ceiling from 0.75 to 1.0 and is the floor the Enterprise profile
demands, so it is the difference between a protocol an agent can use and one it
cannot. `load_seed_manifests` lowers a declared `BattleTested` to
`OfficialManifest` unless `protocols/battle_tested_evidence.json` shows that the
program is executable on mainnet, that at least 1,000 successful transactions
carry its address over a stated window, and that the manifest can name at least
90% of the instructions really observed on chain. Measurements are read-only and
reproducible (`graphite-core/scripts/battle_tested_census.py`).

That tier is a statement about usage and description accuracy, **not about
safety**: a heavily used malicious program would clear the same bar. What judges
safety is L4, L5 and L7, which run identically at every tier.

Ninety-six of these manifests were onboarded in Round 18 from each program's
**own on-chain Anchor IDL** — the account the program itself owns — after
ranking the Solana program inventory by real usage over 80 finalized mainnet
blocks. On a 10,617-transaction sample, the share of non-vote transactions whose
primary program Graphite can name went from 20.8% to 44.0%
(`tools/mainnet-sample`); counted per program invocation over an 80-block
census, 64.5% to 79.5% ([docs/protocol-coverage.md](docs/protocol-coverage.md)).

## What's in the Box

```
graphite/
│
├── graphite-core/                  ← Rust verification engine (the heart)
│   ├── src/
│   │   ├── verification.rs         ← 8-layer pipeline orchestrator
│   │   ├── account_resolution.rs  ← L1: PDA derivation (Solana hash-chain), account matching
│   │   ├── risk_engine.rs         ← L7: 11 attack pattern detectors (14 checks)
│   │   ├── confidence_engine.rs   ← L6: Weighted signal scoring + tier ceilings
│   │   ├── policy_engine.rs       ← L6: Per-wallet policy profiles
│   │   ├── simulation_integrity.rs← L3: 3-signal z-score (compute/writes/CPI) + MAD baseline
│   │   ├── semantic_graph_store.rs← L5: Trust tier computation, append-only storage
│   │   ├── transaction_builder.rs ← Canonical serialization, compute budget estimate
│   │   ├── unknown_protocol_mode.rs← 0.55 confidence cap (P6/P12)
│   │   ├── tx_pattern_analysis.rs ← Multi-instruction drain + CPI trace analysis (C29)
│   │   ├── manifest.rs            ← Protocol manifest loading + registry
│   │   ├── manifest_registry.rs   ← Signed community manifest submissions (G5/P7/P10/P11)
│   │   ├── regression_engine.rs   ← P10 promotion gate + fixture corpus replay
│   │   ├── plugin_orchestrator.rs ← P8 plugin framework (sole plugin caller)
│   │   ├── plugins/               ← Built-in: FakeRewardsDrainer (L7), EventLogger (analytics)
│   │   ├── live_corpus.rs         ← Live RPC fixture seeding + devnet verification
│   │   ├── rpc_client.rs          ← Solana RPC client (L3 simulation + L8 execution)
│   │   ├── tx_artifact.rs         ← Wire-format parser (legacy + v0), ALT resolution, durable-nonce detection
│   │   ├── state_diff.rs          ← L4 pre/post diff, SPL Token / Token-2022 decoding + extension classification
│   │   ├── durable.rs             ← Append-only audit trail: fdatasync per record, rotation, whole-trail reads
│   │   ├── solana_types.rs        ← PDA derivation, base58, type primitives
│   │   ├── server.rs              ← HTTP API (axum): /verify, /verify/execution, /audit/event, /admin/quarantine, /metrics, /health, /api/*
│   │   ├── benchmark.rs           ← P16-compliant benchmark (18 scored + 2 baselines)
│   │   ├── bin/graphite.rs        ← Binary entry point (server + CLI)
│   │   └── cli.rs                 ← CLI (clap): verify, benchmark, regression, registry
│   ├── protocols/                 ← 129 JSON protocol manifests (3,186 instructions)
│   │                                 + battle_tested_evidence.json: the mainnet measurement behind each tier
│   └── tests/                     ← 1,455 tests (unit + adversarial + exploit + RPC trust boundary + live RPC)
│
├── dashboard/                     ← React + TS dashboard (5 views, polls /api/*)
│
├── sdk/
│   ├── typescript/                ← TS SDK (GraphiteClient + AuditBind TOCTOU binding)
│   └── go/                        ← Go SDK (same client + AuditBind, 19-field parity)
│
├── integrations/
│   └── solana-agent-kit/          ← SAK v2 integration (verified execution gate)
│       ├── graphite-sak-bridge.ts ← Builds ONE BoundTransaction, verifies it, signs only on artifact_bound approval
│       ├── artifact.ts            ← BoundTransaction: deep-copied, digest-rechecked, signer-set-checked signing gate; messageOf
│       ├── auditbind.ts           ← Secondary instruction-level binding (content_hash); the digest is authoritative
│       ├── bound-instruction.ts   ← Builds the swap instruction from the verified payload, never from SAK's builder
│       ├── emit-corpus.ts         ← Cross-language corpus: 12 shapes + 1,647 byte-level mutations, diffed in CI
│       ├── residual-policy.ts     ← Which unobserved residuals a deployment accepts; refuses the rest before signing
│       ├── execution-lifecycle.ts ← The one path from verdict to network: policy → sign → record → submit → record → confirm → L8
│       ├── demo.ts               ← End-to-end demo
│       ├── devnet-test.ts         ← Live devnet test (BoundTransaction → signApproved → sendRawTransaction)
│       └── mainnet-benchmark.ts   ← Real mainnet exploit benchmark runner
│
├── python-ai-layer/               ← Advisory intent parser (P1: AI never decides)
│   ├── intent_parser.py
│   └── test_intent_parser.py
│
├── examples/                      ← Sample verification inputs/outputs
├── schemas/                       ← JSON schemas (proposed-intent, verification-result)
├── docs/                          ← CURRENT.md (status now) + dated campaign reports (historical, banner-linked)
├── .github/                       ← CI workflow + issue/PR templates
│
├── ARCHITECTURE.md                ← System design specification
├── ROADMAP.md                     ← Phases 1–2 complete; hardening rounds; Phase 3 gates
├── SECURITY.md                    ← Security policy + known limitations
├── CONTRIBUTING.md                 ← How to contribute
├── GRAPHITE_FINAL_CERTIFICATION_REPORT.md ← Phase 1/1.5 certification (historical)
├── Dockerfile                     ← Multi-stage container build
├── docker-compose.yml             ← One-command deploy
└── README.md                      ← You are here
```
---

## Quick Start

### 1. Run the verification engine

```bash
cd graphite-core
GRAPHITE_API_KEY=$(openssl rand -hex 32) cargo run --release --bin graphite -- server --port 7331
# Graphite Core running on port 7331
```

The server is **authenticated by default** and refuses to start without
`GRAPHITE_API_KEY`. For local development only, `GRAPHITE_DEV_MODE=1` runs an
unauthenticated instance — and even then only on a loopback address.

### Production server configuration

| Env var | Default | Purpose |
|---------|---------|---------|
| `GRAPHITE_API_KEY` | *(required)* | Bearer token required on every route except `/health` (constant-time compared). **Startup refuses without it** unless `GRAPHITE_DEV_MODE=1`. |
| `GRAPHITE_DEV_MODE` | `0` | `1` permits an **unauthenticated** instance for local development, and only when bound to loopback (`127.0.0.1` / `::1`). Never set this on a reachable address; the server refuses the combination. |
| `GRAPHITE_MAX_CONCURRENT` | `32` | Verifications allowed in flight at once. Excess is shed immediately with `503` + `Retry-After` rather than accepted and left to expire at the 10s request timeout — a request that dies at the timeout carries no verdict and no audit record. Distinct from the per-IP `429`: `429` means one caller is asking too often, `503` means the instance is saturated. Both are counted separately at `/metrics`. Raise it when the upstream RPC can sustain more. |
| `GRAPHITE_RATE_LIMIT` | `30` | Per-IP token bucket, requests/second. Returns `429` when exceeded. |
| `GRAPHITE_CORS_ORIGINS` | *(denied)* | Comma-separated allowed browser origins. Default denies all cross-origin browser calls; server-to-server clients are unaffected. |
| `GRAPHITE_DATA_DIR` | `./graphite-data` | Durability: semantic-graph snapshot (trust tiers + earned simulation baselines) and append-only `audit.jsonl` written after every verification, reloaded on restart. **The server probes this directory for writability at startup and refuses to boot if it cannot write** — it never serves traffic with no audit trail (P9) — and holds an exclusive lock on `graphite.lock` so a second server on the same directory refuses to start (Round 12). |
| `GRAPHITE_RPC_URL` | *(off)* | Attaches a Solana RPC client — live L3: `simulateTransaction` runs and real compute usage feeds the trusted baseline accumulator. Validated at startup (http/https only, no fragment; a plaintext non-loopback endpoint is warned about) and redirects are never followed. Usually embeds a provider API key; Graphite redacts endpoint URLs from every error and log line it surfaces, but treat the value as a secret. |
| `GRAPHITE_RPC_WITNESS_URL` | *(off)* | A second, independent RPC that L8 asks about inclusion (Round 12). An approved transaction is reported `ApprovedAndExecuted` only when both endpoints place the signature in the same slot with the same outcome; either endpoint's sighting of a BLOCKED transaction raises `BlockedButExecuted`. Must differ from `GRAPHITE_RPC_URL`. Without it, `/health` says `inclusion_witness: false` and every reconciliation carries `inclusion_witness: null`. |
| `GRAPHITE_TRUST_PROXY` | `0` | Number of **trusted reverse-proxy hops** in front of the server, for per-IP rate limiting. `0` ignores `X-Forwarded-For` entirely (correct whenever clients can reach the server directly). Set it to the real number of proxies you control — the client IP is counted that many entries from the *right*, because proxies append the peer they observed and the left end is whatever the caller claimed. Over-counting re-opens the spoofing bypass. |
| `GRAPHITE_WALLET_PROFILE` | *(unset)* | **Pins the wallet policy profile server-side; the request body's profile is ignored.** Set this whenever the caller is not the wallet operator — the body is written by the agent, so a caller-supplied threshold is one the attacker gets to choose. Accepts `treasury`/`trading`/`gaming`/`enterprise`/`custom:<min_confidence>:<TrustTier>`. An unparseable value fails startup rather than silently falling back. |
| `GRAPHITE_ALLOW_PERMISSIVE_PROFILES` | `0` | Allow a caller-supplied `Custom` profile weaker than the weakest built-in (Gaming, 0.55). Off by default: otherwise a caller can disable the confidence/trust-tier gate outright. |
| `GRAPHITE_LOG_FORMAT` | *(text)* | `json` emits structured logs for aggregators. Level via `RUST_LOG` (default `info`). |
| `GRAPHITE_AUDIT_ROTATE_BYTES` | `67108864` (64 MiB) | Rotate the active audit file at this size, bounding disk growth and the dashboard's per-poll scan cost. `0` disables rotation. |
| `GRAPHITE_AUDIT_MAX_ARCHIVES` | `0` (keep all) | Rotated archives to retain. The default keeps the complete audit trail (P9); set a limit only if you accept that the oldest history is deleted. |

**Observability.** `GET /metrics` serves Prometheus text format (behind the API
key, like every endpoint except `/health`): verification request/approve/block/
error counts, auth failures, rate-limit rejections, audit-log write and
rotation success/failure counters, active log size and archive count,
semantic-graph snapshot success/failure counters, lifecycle reports against
blocked or unverified hashes, and the L8 counters — `graphite_execution_checks_total`,
`graphite_execution_discrepancies_total` (a blocked transaction executed: page
on this) and `graphite_execution_chain_bytes_rejected_total` (the RPC returned
bytes that are not the signature's: a faulty or hostile RPC). `GET /health` is open for
load balancers and reports `degraded` with a `degraded_reasons` list
(`audit_writes_failed`, `audit_rotation_failed`, `audit_disabled`,
`graph_snapshot_failed`) — a verdict that cannot be recorded is refused with
`503`, and every other durability failure is counted here so a node quietly
losing its trail or its earned state is alertable rather than invisible.

**Audit durability.** Every audit record is `fdatasync`'d to the device before
the response is sent (≈1.5 ms per record measured on an NTFS SSD; `File::flush`
is a no-op for an unbuffered file and was what the code called before
2026-09-12). Rotation renames the active file; the read APIs and L8
reconciliation cover every archive plus the active file, so a verdict never
disappears from Graphite's own view by rotating out.

```bash
# Minimal production launch (auth + rate limit + durability)
GRAPHITE_API_KEY=$(openssl rand -hex 32) GRAPHITE_RATE_LIMIT=100 \
  GRAPHITE_DATA_DIR=/var/lib/graphite GRAPHITE_CORS_ORIGINS= \
  cargo run --release --bin graphite -- server --port 7331 --host 0.0.0.0
```

> **Bind address.** `--host` defaults to `127.0.0.1` so running the server on a
> laptop, shared box, or cloud VM does not silently publish the API to every
> reachable network. Pass `--host 0.0.0.0` to expose it deliberately. Without
> `GRAPHITE_API_KEY` the server does not start at all; with `GRAPHITE_DEV_MODE=1`
> and no key it starts **only** on loopback.

### Integrating safely (read this before writing the integration)

Graphite verifies **before** the transaction is signed. Four rules make that
protection real; skipping any one of them produces an integration that looks
correct and protects nothing.

**1. Send the bytes, and require `artifact_bound`.** Build the transaction
first, serialize it with empty signature slots, and send it as
`signed_transaction`. The verdict then carries `scope.kind = "artifact_bound"`
and `scope.transaction_sha256`, the SHA-256 of those exact bytes. A verdict
without the bytes is `descriptive`: it describes what you *said*, and nothing
in it constrains what is signed.

| `scope.kind` | What the verdict covers | Safe to execute on `approved` alone? |
|---|---|---|
| `artifact_bound` | The exact transaction bytes you supplied, subject to `scope.unobserved` | Only if you sign and submit those exact bytes (rule 2) |
| `descriptive` | Only the metadata you described. Nothing constrains what is actually signed | **No** |
| *(absent)* | A server older than 2026-09-08 did not say | **No** — treat as unknown, not as either answer |

Read `scope.unobserved` in both modes: it lists, in words, the security-relevant
properties Graphite did *not* establish. It is never empty — a verdict claiming
to have observed everything would be a strong assertion, and one Graphite does
not make. Decide on `scope.unobserved_codes`, not on the prose (rule 3).

Always send `instruction_data` with the bytes. An artifact-bound verdict
identifies the described instruction in the message by its program, its exact
data and its accounts at one position; without the data L2 fails, because
Graphite will not bind a verdict to bytes it could not compare (Round 9: a
100 SOL transfer was approved under a 0.002 SOL description by omitting it).

A transport error, timeout, or non-200 means *verification did not happen*:
that is a hard stop, never an implicit pass.

**2. Sign exactly the bytes that were verified.** Between approval and the
chain, a transaction object can still be mutated — a compromised RPC proxy, a
malicious wallet adapter, a helper that "refreshes" the blockhash, a race in
your own pipeline. The SAK bridge's `BoundTransaction` is the reference shape:
it deep-copies the instructions at build time, exposes no mutable handle,
recomputes the digest against the approved `transaction_sha256` inside
`signApproved`, derives the required signer set from the compiled message
rather than from the caller, and returns the only bytes meant for submission.
A rebuilt or refreshed transaction is a different digest and is refused.

```ts
import { GraphiteClient, isArtifactBound } from "@graphite/sdk";
import { BoundTransaction } from "./artifact.js"; // integrations/solana-agent-kit
import { ResidualPolicy } from "./residual-policy.js";

const graphite = new GraphiteClient({ baseUrl, apiKey });
const bound = BoundTransaction.build({ instructions, feePayer, recentBlockhash, lastValidBlockHeight });

let result;
try {
  result = await graphite.verify({ ...input, signed_transaction: bound.artifact() });
} catch (e) {
  throw new Error(`verification did not happen: ${e}`); // never proceed
}

if (!result.approved) throw new Error(`blocked: ${result.summary}`);
if (!isArtifactBound(result)) throw new Error("verdict is descriptive; nothing is bound");
// Rule 3: refuses any residual that is not inherent and not accepted by name.
new ResidualPolicy(process.env.GRAPHITE_ACCEPT_UNOBSERVED?.split(",") ?? []).assertExecutable(result.scope, "transfer");

// Throws unless the digest of these exact bytes equals the approved one and
// the supplied signers are exactly the message's required signers.
const raw = bound.signApproved(result.scope.transaction_sha256, [walletKeypair]);
// Rule 4: the signing is on the trail before anything leaves the process.
const keys = { content_hash: result.content_hash, audit_trail_id: result.audit_trail_id, transaction_sha256: result.scope.transaction_sha256 };
const receipt = await graphite.recordLifecycleEvent({ event_type: "signing", ...keys });
if (receipt.verdict_on_record !== "approved" || receipt.verdict_on_record_key !== "audit_trail_id") {
  throw new Error("the approval in hand is not the approval on record");
}
const signature = await connection.sendRawTransaction(raw);
await graphite.recordLifecycleEvent({ event_type: "submission", ...keys, transaction_signature: signature });
const l8 = await graphite.verifyExecution({ signature, ...keys });
if (l8.discrepancy) throw new Error("BlockedButExecuted: the gate did not govern");
```

**3. Refuse any residual you have not accepted by name.** Every verdict carries
`scope.unobserved_codes`, one stable code per `unobserved` entry. Two codes are
inherent to every artifact-bound verdict — `program_semantics` and
`inner_instructions` — and a policy that accepts only those accepts nothing
Graphite could have observed and did not. Every other code (`no_state_diff`,
`simulation_failed`, `not_simulated`, `privileges_from_caller`, `privileges_absent`,
`lookup_tables_unresolved`, `artifact_unparsed`, `account_identity_unparsed`,
`instruction_not_located`) names an observation that was possible and did not
happen. The SAK bridge's `ResidualPolicy` refuses execution on any of them
unless the operator lists it in `GRAPHITE_ACCEPT_UNOBSERVED`, validates that
list at startup, refuses a server that reports prose only, and records the
accepted codes on the execution outcome. A verdict is a description of what was
checked; the policy is where a deployment says what it is willing to sign
without.

**4. Put your signing and submission on the trail, then reconcile — under the
exact keys.** Graphite records what it verifies; only you can record what you
sign and send. `recordLifecycleEvent({ event_type: "signing", content_hash,
audit_trail_id, transaction_sha256 })` *before* submission — and do not submit
if it is not recorded, if its `verdict_on_record` is not `approved`, or if
`verdict_on_record_key` is not `audit_trail_id` — then `submission` with the
signature, then `verifyExecution({ signature, content_hash, transaction_sha256,
audit_trail_id })` for L8. `content_hash` alone names every transaction
carrying that instruction; the exact keys name yours. L8 itself joins on the
chain's bytes when it can fetch them and reports which key it used
(`attribution`). The reference sequence is `executeBoundTransaction` in
`integrations/solana-agent-kit/execution-lifecycle.ts`; no irreversible step
proceeds unless the step before it is on the trail.

**`content_hash` is the audit key, not the binding.** `content_hash` is a
64-bit identifier over one instruction's projection — program, discriminator,
accounts, data, CPI targets. It links the verdict to the audit trail and to L8
reconciliation, and the SDKs' `verifyInstruction` / `VerifyInstruction`
(TypeScript, Go) re-hash an instruction against it as a secondary,
instruction-level check. It cannot see the fee payer, the blockhash, the
signer set, or any other instruction in the transaction; `transaction_sha256`
can, and is the authoritative binding whenever the bytes were supplied.

**Durable nonces are refused.** A transaction whose first instruction is a
System `AdvanceNonceAccount` does not expire, so every state-based conclusion
in a verdict holds only at verification time. L2 refuses them by default;
`GRAPHITE_ALLOW_DURABLE_NONCE=1` permits them only after the nonce account is
verified on-chain, and the bridge will not build one.

### Deployment, TLS, and scaling

- **TLS is terminated upstream.** The server speaks plain HTTP by design; run it
  behind a reverse proxy or load balancer that terminates TLS. Do not expose it
  directly to the internet. Set `GRAPHITE_TRUST_PROXY` to the number of proxy
  hops you control, and make sure that proxy *overwrites* rather than trusts any
  client-supplied `X-Forwarded-For`.
- **Single replica today.** Durable state (the append-only audit log and the
  semantic-graph snapshot) lives on a local volume with no cross-process
  coordination, so this stack is **not** currently safe to scale horizontally:
  two replicas sharing a volume would race, and two replicas with separate
  volumes would fragment the earned-trust history that the confidence model
  depends on. Run one replica (Kubernetes: `strategy: Recreate` with a PVC)
  until a shared-state backend lands. This is a known limitation, tracked in
  `SECURITY.md`, not an oversight.
- **Container hardening.** The shipped `docker-compose.yml` runs the image as a
  fixed non-root UID with a read-only root filesystem, all capabilities dropped,
  `no-new-privileges`, CPU/memory/PID limits, log rotation, and the host port
  bound to loopback. Change the port binding deliberately when putting a proxy
  in front of it.

### 2. Verify a transaction

```bash
curl -X POST http://localhost:7331/verify \
  -H "Content-Type: application/json" \
  -d @../examples/verify-input.json | jq .
```
> ⚠️ The example input uses the `TradingBot` profile (0.80 threshold). On a fresh Core (no earned evidence) the achievable confidence for a known protocol is ~0.44, so this example returns **BLOCKED** — that is the engine being honest, not a bug. The confidence signals are *earned*, not asserted: `SimulationMatch`, `HistoricalVolume`, and `CommunityVerification` read from the Semantic Graph's internal accumulator (RPC-verified baselines and Behavior evidence), so the presets become satisfiable as the graph accumulates verified history. To see an immediate approval on a fresh core, set a calibrated profile:
> 
> ```bash
> jq '.wallet_profile = {"Custom": {"min_confidence": 0.40, "min_trust_tier": "OfficialManifest"}}' ../examples/verify-input.json | curl -X POST http://localhost:7331/verify -H "Content-Type: application/json" -d @- | jq .approved
> ```

### 3. After submission: reconcile what happened (L8)

`/verify` answers "should this be signed?". It cannot answer "did my decision
govern the wallet?", because that happens after the request is over. L8 is the
call that closes the loop, and it is caller-driven by design — Graphite does not
watch the chain, so someone has to report the signature.

```bash
curl -X POST http://localhost:7331/verify/execution   -H "Content-Type: application/json"   -d '{"signature":"<base58 signature>","audit_trail_id":"<from the /verify response>","transaction_sha256":"<scope.transaction_sha256>","content_hash":"<content_hash>"}' | jq .
```

```bash
# Same reconciliation from the CLI. Exits 1 on a discrepancy, so it works as a
# monitoring check.
graphite execution --signature <base58 signature> --audit-trail-id <id> --transaction-sha256 <digest>
```

With an RPC that serves `getTransaction`, L8 does not need the keys at all: it
fetches the bytes behind the signature, checks that they are that signature's
— the first slot holds it and it verifies (ed25519) over the message under the
fee payer's key — zeroes the signature slots (which gives back exactly the
artifact that was verified) and joins on their digest — `attribution:
"chain"`. Bytes that fail that binding are refused: `chain_bytes_rejected`
says why, the reconciliation is `Unavailable`, and the keys you supplied are
*not* consulted in their place (an RPC that can substitute bytes must not also
choose the join). The keys are cross-checked against the chain's answer and
any disagreement is reported in `caller_keys_disagree`. Without the chain's
bytes the most exact key you supplied decides, and `content_hash` alone is
ambiguous by construction: it names every transaction carrying that
instruction.

The SAK bridge makes this call itself after every verified execution, and
records its `signing` and `submission` on the trail around it (`POST
/audit/event`); each such row carries `verdict_on_record`, what the trail said
about the hash when the report arrived, and a report against a blocked verdict
is counted at `/metrics` and logged at ERROR.

The field to watch is `reconciliation`. `ApprovedAndExecuted` and
`BlockedAndNotExecuted` are the gate being obeyed. `ApprovedButFailedOnChain` is
not a security failure — Graphite verifies intent and structure, not that a
transaction will succeed. **`BlockedButExecuted` is the one worth paging on:**
Graphite refused the transaction and it landed anyway, so the gate was bypassed
rather than obeyed — an integration ignoring the verdict, a key used out of
band, or an override. It sets `discrepancy: true`, logs at ERROR, and goes on
the append-only trail. Nothing inside a verification request can ever detect it,
because it happens entirely outside one.

Without an RPC endpoint, or with one that will not answer, the result is
`Unavailable` with the endpoint redacted. An unavailable check reports that it
is unavailable; it never reports a confirmation.

### Operator CLI

`graphite verify` answers "what does the gate decide?" as JSON. These answer the questions an operator actually asks around it. All of them read the same durable semantic graph the server does (`GRAPHITE_DATA_DIR`, default `./graphite-data`), so the CLI and the server never disagree about a program's earned trust.

```bash
# WHY did the gate decide that? Layer by layer, with the confidence breakdown,
# the risk findings, and the accounts. Same pipeline as `verify` — a renderer,
# not a second decision path. Exits 1 when the transaction is blocked.
graphite explain --file examples/verify-input.json
```

```bash
# What does the gate know about this program? Manifest, EARNED trust tier and
# the evidence behind it, simulation baseline, declared CPI targets, quarantine
# state. A declared tier is labelled as declared — a manifest claiming
# BattleTested with no evidence must not read as fact.
graphite protocol status --program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
```

```bash
# What am I signing off on? Compares a candidate manifest against the one
# currently in force: instructions added and removed, renames (identified by an
# unchanged discriminator, so a rename never reads as a breaking removal),
# account privilege changes, new CPI targets, changed risk classes.
# The reviewer's missing tool — their attestation is what earns the tier.
graphite protocol diff --manifest ./candidate.json
```

```bash
# Would the loader accept this? Run before signing, not after.
graphite manifest-verify --manifest ./candidate.json
```

```bash
# Bootstrap: a fresh graph has no earned evidence, and the evidence-derived
# confidence signals are half the total weight -- so an instance with an empty
# graph and no GRAPHITE_RPC_URL blocks 100% of traffic (max reachable
# confidence 0.44 against a 0.55 floor). These restore an exported graph or
# stand an instance up before that history exists. CLI-only: request-body
# evidence would let any caller mint an earned-looking tier.
graphite evidence seed --program <id> --signed-manifest --community-verified 2   --battle-tested 1500 --simulation-matches 100
graphite evidence baseline --program <id> --mean-compute-units 150   --std-compute-units 12 --samples 50
graphite evidence show --program <id>
```

```bash
# Withdraw a program from trust immediately, restore it, or see what is withdrawn.
graphite quarantine add --program <id> --reason "GHSA-2026-0001 authority takeover"
graphite quarantine list
graphite quarantine lift --program <id>
```

```bash
# Onboarding a new program: the P10 gate needs a regression baseline, and one
# cannot be recorded the ordinary way because the manifest is not installed yet.
graphite registry record-fixture --corpus-dir ./corpus   --manifest ./candidate.json --input ./tx.json
graphite registry submit --manifest ./candidate.json   --signer-key-file ./key.hex --corpus-dir ./corpus
```

There is deliberately no `build --simulate`. `verify` already simulates when an RPC client is attached, and a separate build-and-simulate command would need its own transaction-plan input format — inventing one to round out a list is the kind of surface that exists to be listed rather than used.

### 3. Run the SAK integration demo

```bash
# Start AI Layer (separate process, P1 compliance)
cd python-ai-layer
python3 intent_parser.py --serve --port 8081

# Run the demo
cd ../integrations/solana-agent-kit
npx tsx demo.ts "Swap 0.5 SOL for USDC"
```

The demo shows the full flow:
1. AI Layer parses "Swap 0.5 SOL for USDC" → `ProposedIntent`
2. SAK constructs the Jupiter V6 swap transaction
3. Graphite verifies the transaction → `VerificationResult`
4. If approved → SAK executes. If blocked → transaction is NOT submitted.

---

## Dashboard

The read-only dashboard (`dashboard/`) visualizes live Core state — protocol
overview with trust tiers, a Semantic Graph view with directed CPI edges, a
confidence time series, policy violations, and the Manifest Registry.

```bash
cd dashboard
npm install
npm run dev          # dev: proxies /api to http://localhost:7331
npm run build        # production build → dist/
```

It polls the read-only endpoints (`/api/graph`, `/api/confidence-history`,
`/api/policy-violations`, `/api/protocols/top`, `/api/registry`) that the
Core server exposes behind the same Bearer auth and rate limiting as
`/verify`. Point a browser at the dev server (or serve `dist/` statically)
and set `VITE_GRAPHITE_API` if Core lives elsewhere. Read-only by
construction (Constitution P4) — the dashboard never mutates graph state.

## Security Properties

| Property | How It's Enforced |
|----------|-------------------|
| **Unknown protocol cap** | Hard 0.55 confidence ceiling — no caller evidence can override (P6/P12) |
| **Fail-closed on unknown** | Unknown discriminator on known protocol → BLOCKED (confidence 0.0) |
| **NaN bypass prevention** | Explicit NaN/Infinity rejection in confidence engine |
| **AI never decides** | Python AI layer is advisory only — Core verification is deterministic (P1) |
| **Deterministic** | `content_hash` = SHA-256 of transaction config — same input, same output (P2) |
| **Compositional drain detection** | Both duplicate AND unique-program deep CPI chains caught |
| **Trusted simulation baselines** | Baselines live in the semantic-graph accumulator (earned via RPC-verified usage or operator-seeded) — the request body **cannot** supply one (anti-poisoning) |
| **Transaction identity** | With `signed_transaction` supplied: wire format parsed (legacy + v0), `transaction_sha256` over the exact bytes, L2 requires the described instruction to be in the bytes positionally and every sibling declared, privileges read from the header and resolved lookup tables — never from the caller |
| **Address lookup tables** | Fetched, owner-checked, decoded; runtime account numbering rebuilt (static ++ writable ++ readonly); all-or-nothing — an unresolved table is disclosed as unobserved, never treated as empty |
| **Token-2022** | Extensions classified, not modelled: transfer-semantics, authority and unknown extensions block; an unreadable extension region blocks; informational extensions warn |
| **Durable nonces** | Detected by the runtime's rule; refused at L2 by default; opt-in only after on-chain nonce verification |
| **Wire-format bounds** | Canonical compact-u16 (≤ 65,535, minimal encoding), trailing bytes refused, indexes bounds-checked, nothing over the 1232-byte packet — the same rules on the TypeScript side, asserted equal across 1,647 byte-level mutations in CI |
| **The described instruction is located, or L2 fails** | An artifact without `instruction_data`, or one that does not parse, fails L2; `artifact_bound` never claims a comparison L2 did not make (Round 9: a 100 SOL transfer was approved under a 0.002 SOL description by omitting the optional field) |
| **Residuals are gated at execution** | `scope.unobserved_codes` names each residual; the bridge's `ResidualPolicy` refuses any non-inherent one the operator has not accepted in `GRAPHITE_ACCEPT_UNOBSERVED` |
| **Lifecycle on the trail** | The bridge records signing before it submits (and aborts if it cannot), submission after, and runs L8 at the end; every caller-reported row carries the server's `verdict_on_record` and is bounded on disk |
| **L8 attribution is exact** | An execution is joined to the verification of *those bytes* — the chain's transaction with signature slots zeroed digests to `scope.transaction_sha256` — never to a same-instruction sibling by `content_hash` (Round 10: a blocked B executed after an approved A read as `ApprovedAndExecuted`). The bytes are the signature's, not merely the RPC's: first slot equal to it and verifying under the fee payer's key, or refused with nothing attributed (Round 11) |
| **L8 does not take one RPC's word for inclusion** | A status at `processed` commitment is one node's view and draws no positive conclusion; an RPC whose `getTransaction` contradicts its `getSignatureStatuses` (slot or outcome) draws none; a malformed status is `Unavailable`, never "included and failed"; redirects are not followed; with `GRAPHITE_RPC_WITNESS_URL` both endpoints must agree before an approval is reported executed. The alarm on a BLOCKED transaction fires on any sighting by either endpoint, at any commitment (Round 12) |
| **The parser is never looser than the runtime** | `tools/runtime-oracle` decodes the corpus, its 1,659 mutations and 600,000 generated frames with the agave crates as a validator's packet path does; Graphite parses nothing the runtime's `sanitize` refuses (program index 0, out-of-range account indexes, empty lookups, > 256 accounts — all found and closed in Round 12) and reads every accepted transaction identically. Runs in CI on every push |
| **The lifecycle trail knows its own order** | Every caller-reported row is checked against the rows already on record for the same transaction: a retry is named `duplicate`, a stage out of order or without its predecessor is named, and a second signature for one transaction is a `signature conflict` logged as loudly as a discrepancy. Recorded, never refused (Round 12) |
| **RPC evidence provenance** | Simulation writes/CPI hops derived only from canonical response fields; non-standard provider fields that disagree are reported as anomalies, never used |
| **API auth** | Bearer API key required by default — the server refuses to start without one, or with one shorter than 32 characters; `GRAPHITE_DEV_MODE=1` permits keyless on loopback only. Constant-time compared; `429` per-IP rate limiting with `Retry-After`; `503` load shedding; refusals drain the request body so the status is readable, never a reset; CORS allowlist (denied by default) |
| **Durability** | Every audit record `fdatasync`'d before the response; a verdict that cannot be recorded is refused with `503`; rotation is a rename, archives retained, and every reader (dashboard, L8) covers the whole trail; snapshot and rotation failures surface on `/health` as `degraded_reasons` |

---

## Honest Status

The single authoritative statement of what is enforced today, what is not, and
what remains undone is [docs/CURRENT.md](docs/CURRENT.md). The dated reports in
`docs/` are evidence of the work as it happened and are not edited afterwards.

What we **do not** claim:

- The benchmark is 18 scored cases (safe + malicious) plus 2 baseline comparisons — NOT a statistical evaluation on unseen data. "100% precision / 100% recall on the scored benchmark cases" is the honest claim. Composition (C52): 5 REAL mainnet exploit cases (STMT drainer 64tsGGe, AAT drainer 524t8LW, Wormhole $320M hack 5fKWY7X, fresh Aug-2026 drainer chain 2AWwL6dk, AAT mass drain 3PbK87 — pinned from `tests/real_onchain_exploits.rs` + `scripts/real_exploit_*.json`, reproducible offline) + 2 SYNTHETIC drainer cases, honestly labeled. Avg latency ~2.1ms with the real-data cases (release build); the earlier sub-ms figure predates them.
- 2 exploit reconstructions use real program IDs but fabricated account structures. They are labeled "SYNTHETIC" per P16, not "real mainnet data." The other 5 exploit cases are REAL mainnet data (Wormhole $320M, CLINKSINK STMT drainer, SlowMist AAT drainer, fresh drainer chain, AAT mass drain).
- L3 (Simulation) and L4 (State) are active when an RPC client is attached, and were validated end to end against live devnet on 2026-09-07 — including a transaction whose primary instruction is an ordinary transfer and whose second instruction reassigns the payer's account, which L1, L2 and L5 all pass and only L4's observed post-state catches. L8 (Execution Verification) is reachable in production as `POST /verify/execution` and `graphite execution`, live-validated against mainnet. It is caller-driven by design: Graphite does not watch the chain, so someone must report the signature after submission. Until that call is made, L8 reports `Inconclusive` and says which endpoint completes it. The RPC endpoint is inside the trust boundary — see SECURITY.md for what a hostile one can and cannot do.
- No LLM-based intent parsing in the verification path (P1: AI assists, never decides). Intent alignment is structural — the declared intent type is matched against the manifest's supported intents (L5, Check 9), and high-risk instruction classes with no declared intent fail closed (Check 10, C38).

What we **do** claim:

- **Confidence is calibrated honestly and earned, never asserted (G4).** The three evidence-derived signals (`SimulationMatch`, `HistoricalVolume`, `CommunityVerification`) read from the Semantic Graph's **internal accumulator** — the program's RPC-verified simulation baseline (`sample_count`, counting DISTINCT sound transactions: the same bytes re-verified are one observation, and a request refused at L2 or by the Risk Engine is none) and its earned Behavior evidence — never from request-body JSON, which an attacker could fabricate to mint confidence. Trust tiers are capped at `OfficialManifest` (P7: tiers 3+ must be earned via the Semantic Graph, not self-asserted). A fresh Core therefore scores a known, clean, intent-aligned protocol at **~0.44** and the built-in presets (TradingBot 0.80, Treasury 0.95, Gaming 0.55, Enterprise 0.99) block everything until evidence is earned — e.g. Gaming (0.55) is exactly satisfiable by a HeuristicInferred manifest-backed program (the P6 ceiling), Treasury unlocks at battle-tested evidence (≈ 0.98). The benchmark and SAK demo default to a `Custom { min_confidence: 0.40, min_trust_tier: OfficialManifest }` profile; `graphite verify --profile <preset>` or `graphite profiles` drives the presets from the CLI. Raise or lower the profile to change policy; the engine's score itself is the honest number.
- 1,455 Rust tests passing (1,465 total; 10 network-dependent ignored), 0 failures, 0 clippy warnings — every test has real assertions, and every security fix since 2026-09-08 has had its fix reverted once to show its test fails without it (the "deliberate break" logs in the round reports).
- 14 risk checks (13 risk patterns, incl. `UnspendableDestination` and `PluginBlock`) are real detection logic, not stubs. Multi-instruction drain, CPI trace analysis (C29), and manifest-declared high-risk class gating (C38) shipped.
- 33 protocol manifests / 803 instructions, program IDs verified against official on-chain sources (2026-08-07 + Drift/Kamino C27/C42 + Phoenix/OpenBook V2/Switchboard/Jupiter Limit/Solend/Marginfi C46 + Raydium CLMM/CPMM, Marinade, SPL Stake Pool, Orca TokenSwap V2 C56).
- Confidence engine uses real weighted computation with tier ceilings and NaN rejection.
- Simulation integrity uses 3-signal z-score (compute, writes, CPI hops) with Welford's algorithm and median/MAD baseline (C28).
- The SAK integration imports real `solana-agent-kit` v2 and calls real SAK methods — **verified on Solana devnet** (wallet `CWb8MciizembLV66kisYcXo3Cb91hdszxw74QHpEJKZR`, 5 finalized transactions: 2 faucet airdrops + 3 SAK test transfers; latest signature `xHa4dyuFS6JmSaTsmhcMpEtwbWnPjBoUGwk3wNixD2uw2Wmeui6GhnSmmdzNVkv85zXSd6g7QYhHymAjciwP3jJ` confirmed and finalized).
- 2,747-fixture regression corpus (C41 + C52): dev 2,676 + regression 31 + holdout 40 (37 real mainnet exploit signatures — 35 SolPhishHunter + 2 live-fetched from mainnet RPC — + 3 real mainnet txs), independently labeled, 0 false negatives.

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/CURRENT.md](docs/CURRENT.md) | **The current security status** — what is enforced, what is not, what is still undone. Every dated report in `docs/` is historical and points here. |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System design, 8-layer pipeline, subsystem specs |
| [ROADMAP.md](ROADMAP.md) | Phases 1–2 complete; the 2026-09 hardening rounds; what gates Phase 3 |
| [SECURITY.md](SECURITY.md) | Security policy, known limitations, reporting |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup, PR checklist, Constitution principles |
| [Engineering Skill](https://github.com/Stan-lee13/graphite-engineering-skill) | The skill that builds Graphite — Constitution, personas, checklists |

---

## License

MIT — Copyright (c) 2026 Victor Stanley

---

<div align="center">

*If an AI agent is going to submit transactions on your behalf, something should verify those transactions first. That's what Graphite does.*

</div>
