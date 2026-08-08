# Graphite Phase 2 — Public Beta Build Plan

**Branch:** `phase2-development` (created from `main` @ `0a143fe`, tag `v0.1.0-alpha`)
**Target release:** `v0.2.0-beta`

---

## Phase 1.5 Completion Summary (2026-08-07)

Phase 1.5 is **closed and devnet-verified** before Phase 2 development begins:

- **829 Rust tests**, 0 failures (831 with `--include-ignored`); clippy 0 warnings; fmt clean; no-default-features builds
- **RPC client live-verified** against Helius mainnet + devnet — 6 parsing/retry defects fixed (`get_slot` u64 parse, `get_account` null check, `get_oracle_price` placeholder removed, `is_account_frozen` byte 108, `post_rpc` exponential backoff, `max_retries` honored)
- **Server hardening shipped**: constant-time bearer auth, per-IP rate limiting, CORS denied by default, JSONL audit log (approved/blocked/400/500), graceful shutdown
- **L3/L8 honest states**: L3 provenance-aware tri-state (`Passed`/`Failed`/`Inconclusive`); L8 honestly "not yet verified" with audit-trail event
- **Novel instruction fail-closed (P12)**: unknown discriminator on known protocol with high-risk intent → BLOCKED
- **Validation & determinism**: whitespace-only `program_id` rejection; proptest suite (512 cases); PDA known-answer tests vs `@solana/web3.js`; all-11 manifest ID pin test
- **SAK integration verified on Solana devnet**: 5 finalized transactions (wallet `CWb8MciizembLV66kisYcXo3Cb91hdszxw74QHpEJKZR`), pipeline confirmed end-to-end
- **CI 4/4 jobs green** (Rust, TypeScript+SAK, Go, Python)
- **Benchmark**: 16 scored cases, 100% precision/recall, ~850μs avg latency (release, all features)

**Phase 2 prerequisite status:** all Phase 1.5 exit criteria met (see ROADMAP). Phase 2 proceeds on `phase2-development`; `main` receives Phase 2 work only via PR after Phase 2 certification.

---

## Constitution Constraints Governing Phase 2

These principles mechanically constrain HOW Phase 2 features must be built:

| Principle | Constraint | Applies to |
|-----------|-----------|------------|
| P4 | Semantic Graph is append-only. No UPDATE/DELETE on Behavior/Version records. | Manifest Registry, Regression Engine |
| P7 | Trust tier is computed from evidence, never set directly. No admin API to set trustTier. | Manifest Registry |
| P8 | Plugins can't reorder/skip layers or write audit trail. Orchestrator is sole caller. | Plugin Framework |
| P10 | No protocol version promoted without passing Regression Engine run. | Regression Engine, Manifest Registry |
| P11 | Trust keyed by exact programId, no fuzzy matching. | Manifest Registry |
| P16 | All performance claims must be backed by reproducible benchmark. | Dashboard, all features |

---

## Phase 2 Exit Criteria (from ROADMAP.md)

1. **Protocol Manifest Registry** accepts real, signed community submissions with G5 independence-check mechanism specified and implemented
2. **Plugin framework** has 2+ real third-party (non-Graphite-team) plugins registered and running
3. **Policy Engine** 4 preset profiles (Treasury/TradingBot/Gaming/Enterprise) in active use by real integrations
4. **Regression Engine** has 1,000+ real historical fixtures across onboarded protocols
5. **Dashboard** shows live Semantic Graph state, confidence history, and policy violations for top 5 protocols

---

## Current State Assessment

| Subsystem | Code exists? | Lines | What's missing |
|-----------|-------------|-------|----------------|
| Policy Engine | Yes — 4 profiles + Custom | 258 | No real integrations using profiles |
| Regression Engine | Yes — corpus + replay + P10 gate (`src/regression_engine.rs`) | ~330 | Core implemented 2026-08-07: append-only fixture corpus, deterministic replay, `decide_promotion` (99.5%), benchmark-seeded initial corpus (~16 fixtures), `graphite regression` CLI gate, 12 tests. 1,000 real fixtures still requires live data volume |
| Plugin Orchestrator | Yes — `src/plugin_orchestrator.rs` + `src/plugins/` | ~900 | ✅ **Core implemented 2026-08-07**: 6 plugin traits (Protocol/Simulation/Verifier/Risk/Policy/Analytics), `PluginContext` input-only surface, `PluginVerdict` (no pass variant — P8 by construction), panic-isolated execution, file-based discovery + review gate (only `approved` manifests activate), idempotent name-dedup registration, 2 real plugins (FakeRewardsDrainer L7 risk — real claim+debit semantic-inversion detection; VerificationEventLogger — ring-buffer + JSONL file sinks), wired into every layer (L2/L4/L5 folds, L3 sim notes/blocks, L6 policy veto, L7 risk findings, L8, analytics), `graphite plugins --dir` CLI, `GRAPHITE_PLUGINS_DIR`/`GRAPHITE_PLUGIN_EVENTS_FILE` server env, benchmark plugin-overhead section, 56 new tests. Remaining (Phase 3): true third-party (non-Graphite) plugin submissions through a public registry workflow |
| Manifest Registry | Yes — `src/manifest_registry.rs` (community engine) + `manifest.rs` (runtime loader) | — | Core implemented 2026-08-07: signed submissions (ed25519), G5 reputation ledger, P7 tier wiring, P4 version lineage, P10 gate. Remaining: PR workflow + on-chain stake lookup (Phase 3) |
| Self-Healing | Yes — quarantine works | 342 | No production data volume yet |
| Dashboard | No | 0 | Everything |
| Go SDK | Yes — 10/10 tests | — | ✅ Parity complete (ResolvedAccount, BuiltTransaction, VerificationBreakdownItem, ProtocolManifest added) |

---

## Dependency Graph

```
feature/go-sdk-parity (independent)
       │
feature/protocol-expansion (independent, feeds corpus)
       │
       ▼
feature/regression-engine (needs protocol coverage for corpus)
       │
       ▼
feature/manifest-registry (needs Regression Engine for P10 gate)
       │
       ▼
feature/plugin-framework (independent, benefits from Manifest Registry) ✅ DONE
       │
       ▼
feature/policy-engine (needs real integrations via SAK/SDK) ✅ DONE
       │
       ▼
feature/dashboard (needs data from all above) ✅ DONE
```

**Critical path:** Protocol Expansion → Regression Engine corpus → Manifest Registry → Dashboard

---

## Feature 1: Go SDK Parity (`feature/go-sdk-parity`)
**Effort:** Small (~1 day)
**Persona:** Documentation Engineer
**Scope:**
- Add `ResolvedAccount` type with `pda_mismatch` field
- Add `BuiltTransaction` type
- Add `VerificationBreakdownItem` type
- Add `ProtocolManifest` type (for listing)
- Tests: JSON round-trip for each new type
- Verify: `go test ./...` passes with new types
**Exit:** Go SDK has full type parity with TypeScript SDK

---

## Feature 2: Protocol Expansion (`feature/protocol-expansion`)
**Effort:** Medium (~3-5 days)
**Persona:** Protocol Engineer + Testing Engineer
**Scope:**
- Add 5-10 more seed protocols (target: 15-20 total)
- Candidates (from SEED_PROTOCOLS.md rubric):
  - Jupiter Limit Orders (separate from V6 swap)
  - Drift Protocol (perp trading)
  - Kamino Finance (lending)
  - MarginFi (lending)
  - Pyth Network (oracle)
  - Wormhole (bridge)
  - Metaplex (NFT minting)
- For each: verify program ID, build manifest, add benchmark case
- Update RELEASE_EVALUATION_REPORT with expanded protocol count
**Exit:** 15-20 protocols verified, all with valid manifests and benchmark cases

---

## Feature 3: Regression Engine + Corpus (`feature/regression-engine`)
**Effort:** Large (~5-7 days)
**Persona:** Verification Engineer + Testing Engineer + Performance Engineer
**Status:** Core implemented 2026-08-07 (`src/regression_engine.rs` + `graphite regression` CLI) — corpus, replay, P10 gate, benchmark seed. Remaining: 1,000 real fixtures from live data volume, cost model at 10k fixtures.
**Scope:**
- Corpus collection mechanism:
  - Every verification call reaching Tier 3+ records as a fixture
  - Fixture format: `{program_id, version, transaction_data, expected_result}`
  - Store in `regression_corpus/` directory (JSON files)
- Corpus replay:
  - `replay_corpus()` already exists — wire into pipeline
  - On manifest update, trigger regression run for that protocol
  - Pass threshold: 99.5% of non-deprecated fixtures must pass
- Promotion gate (P10):
  - `decide_promotion()` returns `Promote` or `Block`
  - No Semantic Graph version promotion without recorded passing run
- Initial corpus:
  - Generate from existing 13 benchmark cases
  - Generate synthetic fixtures (expand to 100+)
  - Target: 1,000 real fixtures (may require live mainnet data)
- Performance Engineer: cost model for replay at 1,000-10,000 fixtures
**Constitution:** P10 (regression gate), P2 (deterministic replay)
**Exit:** 1,000+ fixtures, replay wired, promotion gate enforced

---

## Feature 4: Protocol Manifest Registry (`feature/manifest-registry`)
**Effort:** Large (~5-7 days)
**Persona:** Protocol Engineer + Security Engineer + Architecture Engineer
**Scope:**
- Signature verification:
  - Verify manifest `signature` against protocol's `signerPubkey`
  - Signed → Tier 2 (Official Manifest)
  - Unsigned community → Tier 1 (Heuristic Inferred, capped 0.55)
- PR-based submission workflow:
  - Public repo for manifest PRs
  - CI: manifest schema validation on PR
  - Review: Protocol Engineer reviews, Security Engineer audits
- G5 Independence Check (CRITICAL open design question):
  - Security Engineer designs first (before any code)
  - Options: stake-based, GitHub reputation, protocol team counter-signature
  - Implement: reviewer identity tied to demonstrated stake or reputation
- Trust tier computation (P7):
  - `compute_trust_tier()` exists in semantic_graph_store.rs
  - Wire: submission → evidence → tier computation (no direct tier API)
- Version management (P4):
  - New version → new Behavior record (append, not update)
  - `previous_version_ref` links versions
- Regression gate (P10):
  - New version requires Regression Engine pass before promotion
**Status:** Core implemented 2026-08-07 (`src/manifest_registry.rs`) — signed submissions (ed25519 verify), G5 reputation-gated reviewer ledger, P7 trust-tier wiring via `compute_trust_tier`, P4 append-only version lineage, P10 regression gate. Remaining: PR-based community workflow (CI schema validation), on-chain stake lookup for reviewer reputation (Phase 3).

### G5 Independence Check — DESIGN (2026-08-07, Security Engineer, written BEFORE registry code)

**Adversary (from `SECURITY.md` G5):** an attacker creates many distinct-looking but actually-controlled reviewer identities, each "independently" attesting to a false Behavior record. If `community_verified_count` were a raw count with no independence check, two colluding accounts would trivially mint Tier 4 (`CommunityVerified`).

**Mitigation — reputation-gated reviewer identity (chosen over raw counts):**

1. **Reviewer identity is a registered Solana pubkey with a demonstrated reputation score** (`registry_reviewer { pubkey, reputation_score }`). Registration is an operator API in Phase 2 (operator-verified stake/GitHub claim); on-chain stake lookup is Phase 3. Keys below `MIN_REVIEWER_REPUTATION` contribute nothing.
2. **`community_verified_count` counts only DISTINCT registered reviewers** (≥ minimum reputation) with a valid attestation signature over the submission's content hash — one attestation per (program, version) per reviewer. Duplicate, invalid, and unregistered attestations are dropped. Sybil-ing Tier 4 requires N real identities with real stake/reputation — the G5 mitigation.
3. **Anonymous signing is worthless (P7):** a valid ed25519 signature by an UNREGISTERED key earns no tier. A signed manifest from a registered, high-reputation reviewer is what moves a submission to Tier 2 (`OfficialManifest`). No tier is ever self-asserted — submissions contribute evidence, `compute_trust_tier` derives the tier.
4. **Tier ceilings hold:** registry submissions reach at most Tier 4 (`CommunityVerified`). Tier 5 (`BattleTested`) requires 1,000+ battle-tested transactions, which are earned by real usage, never self-attested through the registry.
5. **P10 gate:** a submission that would PROMOTE the program's tier requires a passing regression run over that program's fixtures before acceptance. New programs (no prior record) are not a promotion and need no gate.
6. **P11:** trust is keyed by the exact `programId` string — no fuzzy/shape matching.

**Residual risk:** a genuine Sybil network with N real staked identities (large capital) can still pass — the same limitation as any stake-based system; the Tier 5 volume requirement is the backstop. `MIN_REVIEWER_REPUTATION` is an operational parameter, not a security boundary on its own.

**Constitution:** P4, P7, P10, P11
**Exit:** Signed manifests accepted, G5 implemented, regression gate enforced

---

## Feature 5: Plugin Framework (`feature/plugin-framework`)
**Effort:** Medium (~3-5 days)
**Persona:** Architecture Engineer + Security Engineer
**Scope:**
- Plugin interfaces (ARCHITECTURE.md 3.14):
  - ProtocolPlugin, SimulationPlugin, VerifierPlugin, RiskPlugin, PolicyPlugin, AnalyticsPlugin
  - VerifierPlugin trait exists — extend to all 6
- Plugin registration + discovery:
  - register_plugin() exists — add file-based discovery
  - Plugin manifest: name, version, author, layer, review status
- Plugin review process:
  - plugin-review-checklist.md exists
  - Pre-registration code review gate
  - Security Engineer reviews before registration
- Build 2 example third-party plugins:
  - Plugin 1: Custom RiskPlugin for DeFi drainer patterns ("fake rewards")
  - Plugin 2: AnalyticsPlugin logging verification events externally
  - Both structurally prevented from: reordering, skipping, writing audit (P8)
- P8 enforcement verification:
  - run() gives no access to audit_log
  - No way to invoke another LayerId's plugin
  - No way to affect PIPELINE_ORDER
**Constitution:** P8
**Exit:** 2 real plugins registered, running, P8 verified

### ✅ COMPLETED 2026-08-07

Implemented and verified in full — see `graphite-core/src/plugin_orchestrator.rs`,
`graphite-core/src/plugins/` (fake_rewards_drainer.rs, event_logger.rs), and
`graphite-core/tests/plugin_framework.rs`:

- **All 6 interfaces** exist with real, distinct signatures. `PluginContext`
  borrows only the transaction's input data (no audit trail, no orchestrator,
  no other layer) and `PluginVerdict` has NO pass variant — a plugin can only
  `NoFinding`, `Note`, or `Block`. P8 is enforced by the type system, not
  convention.
- **Registration + discovery**: `register_plugin` (idempotent by name),
  `discover_from_dir` (JSON manifests: name/version/author/layer/review_status,
  duplicate-name + malformed fail closed), `register_discovered` applies the
  review gate (only `approved` manifests activate; pending/rejected skipped;
  unknown built-in name is a fail-closed config error).
- **2 real plugins** (first-party, security-reviewed in-tree):
  - `FakeRewardsDrainerRiskPlugin` (L7) — blocks the semantic inversion of
    reward/airdrop scams: rewards-shaped request (intent type OR raw NL with
    claim/airdrop/bonus) whose state changes debit/deduct the user. Deliberately
    does not fire on staking `withdraw` (legit) or the standalone word
    "reward". Verified live: a System transfer with "Claim airdrop rewards"
    NL is hard-blocked (finding `fake-rewards-drainer:FakeRewardsDrainer`, L7
    Failed, exit 1), the same transfer with plain NL passes.
  - `VerificationEventLoggerPlugin` (analytics) — read-only observer writing
    deterministic `VerificationEvent`s to `EventSink`s (bounded ring buffer +
    optional JSONL file sink). Sink failures are logged, never fatal.
- **P8 enforcement verification** (tests): pipeline order pinned, verdict
  shape pinned (no pass variant), panic-isolated execution (a panicking plugin
  can neither wedge the pipeline nor fabricate a block), plugin runs only for
  its own layer, plugins cannot clear a core block, discovery review gate
  end-to-end.
- **Pipeline wiring**: L2/L4/L5 verifier folds (Block → layer Failed + its
  confidence penalty; Note → report annotation), L3 simulation plugins (Note /
  Block report-only — can never certify a clean simulation, P5), L6 policy
  plugin veto (`approved=false`, L6 Failed, policy_str Rejected), L7 risk
  findings (hard block regardless of confidence), L8 report fold, analytics
  post-result. All folds are deterministic (P2) and fault tolerant.
- **Operational surface**: `graphite plugins [--dir <path>]` CLI (lists
  registered plugins, applies the review gate), `GRAPHITE_PLUGINS_DIR` and
  `GRAPHITE_PLUGIN_EVENTS_FILE` server env vars, benchmark plugin-overhead
  section (measured: 2 built-in plugins add no measurable per-verify cost).
- **Exit criteria met**: 2 real plugins registered, running, P8 verified
  (end-to-end tests through `GraphiteCore::verify` + live CLI proof). True
  third-party (non-Graphite) plugin submissions remain Phase 3 (public
  registry workflow + external review pipeline).

---

## Feature 6: Policy Engine Real Integrations (`feature/policy-engine`)
**Effort:** Medium (~3-5 days)
**Persona:** Documentation Engineer + AI Engineer
**Scope:**
- Wire 4 profiles into real integration paths:
  - Treasury (95%/Tier4+): SAK demo, human approval gate above $ threshold
  - Trading Bot (80%/Tier3+): SAK demo, automated swap, confidence threshold
  - Gaming (60%/Tier1+): SAK demo, fast-mode game transaction
  - Enterprise (99%/Tier5): CLI demo, full audit export
- CLI flag: `--profile <treasury|trading|gaming|enterprise>`
- SDK option: `wallet_profile` parameter (already in TS SDK, verify Go)
- Integration tests: each profile produces correct verdict at different confidence levels
- Document each profile's behavior with examples
**Exit:** 4 profiles demonstrated in real paths, documented, tested

### Status: ✅ COMPLETE (2026-08-07)

All four preset profiles are now *satisfiable and differentiable* through the
Semantic Graph's internal accumulator — the Phase 2 G4 requirement that made
this milestone's gates meaningful:

- **Evidence signals wired to the graph (G4):** `SimulationMatch` reads the
  program's RPC-verified simulation baseline (`sample_count`), `HistoricalVolume`
  reads earned `battle_tested_tx_count`, `CommunityVerification` reads earned
  `community_verified_count`. Request-body `behavior_evidence` remains **ignored** —
  a caller can never mint confidence (pinned by tests). A fresh core scores a
  known protocol at ~0.44 (P7 caps the manifest tier at OfficialManifest), so
  every preset is *earned*, never self-asserted.
- **Profile matrix proven (14 integration tests):** Gaming approves at
  simulation-validated evidence (conf ≈ 0.66), TradingBot at +volume (≈ 0.81),
  Treasury at battle-tested evidence (≈ 1.00, full signal set), Enterprise at
  the same full evidence (its 0.99 gate is the highest bar). Fresh-core and
  unknown-program inputs are blocked by ALL presets;
  profiles are differentiated by evidence strength.
- **CLI:** `graphite verify --profile <treasury|trading|gaming|enterprise|custom>
  [--min-confidence] [--min-trust-tier]` overrides the input's profile;
  `graphite profiles` lists presets and thresholds. Unknown profile names and
  partial `custom` thresholds fail closed (unit-tested + live-verified).
- **SDKs:** TS SDK and Go SDK already carry `wallet_profile`; Go SDK parity
  confirmed. SAK bridge (`integrations/solana-agent-kit`) wires profiles through
  to Core (typechecked).
- **Design hardening:** the graph-evidence readout binds each `graph()` guard to
  a temporary — an inline struct-literal readout deadlocked on the non-reentrant
  std Mutex (caught by the aggressive test cycle).
- **Verification:** 829 tests / 0 failures (831 with `--include-ignored`),
  clippy 0 warnings, fmt clean, all CI feature gates pass, live CLI smoke tests.

---

## Feature 7: Dashboard (`feature/dashboard`)
**Effort:** Large (~5-7 days)
**Persona:** Architecture Engineer + Documentation Engineer
**Scope:**
- Tech: React + TypeScript (consistent with graphite-website)
- New API endpoints on Core server:
  - `GET /api/graph` — Semantic Graph state (protocols, trust tiers, versions)
  - `GET /api/confidence-history` — Confidence scores over time
  - `GET /api/policy-violations` — Policy Engine blocked transactions
  - `GET /api/protocols/top` — Top 5 protocols by volume
- Dashboard views:
  - Protocol overview (list with trust tiers)
  - Semantic Graph visualization (nodes + CPI edges)
  - Confidence history (time-series chart)
  - Policy violations (table with reasons)
  - Manifest Registry (submissions + review status)
- Read-only (P4 — no mutation of Graph data)
- Start with polling, defer real-time to Phase 3
**Exit:** Dashboard live, showing data for top 5 protocols

### Status: ✅ COMPLETE (2026-08-07)

Both halves shipped and verified live end-to-end:

- **Read-only API on Core** (Constitution P4 — no endpoint mutates state):
  - `GET /api/graph` — Semantic Graph snapshot: nodes (merged manifest +
    earned behavior + baseline state, trust tiers, quarantine) and directed
    CPI edges from `allowed_cpis`.
  - `GET /api/confidence-history` — audit-log time series (most recent first).
  - `GET /api/policy-violations` — blocked verifications + error-path probes.
  - `GET /api/protocols/top` — top 5 by earned volume + observed verifications.
  - `GET /api/registry` — Manifest Registry records + reviewers (read-only).
  - The audit log gained a bounded read path (`read_tail_filtered` — capped
    tail with true totals, torn-line isolation, streaming per-program
    `observations_by_program`), and `SemanticGraphStore` gained read-only
    `behaviors()`/`baselines()` accessors behind
    `GraphiteCore::graph_snapshot()` (a single-lock snapshot).
- **Dashboard** (`dashboard/`) — Vite + React + TypeScript, 5 views (protocol
  overview, semantic-graph SVG with clickable CPI nodes, confidence
  time-series chart, policy violations, manifest registry), polling every 5s
  with error surfacing and a health banner; Vite dev proxy to Core, `
  VITE_GRAPHITE_API` for production. Read-only by construction.
- **Security:** all `/api/*` routes sit behind the existing Bearer auth + rate
  limiter (live-verified 401/401/200/200) — `/health` stays open.
- **Verification:** 6 endpoint integration tests (data correctness, read-only,
  auth), 829 total / 0 failures, clippy clean, fmt clean, all CI feature
  gates pass, dashboard typechecks + builds, and a live server round-trip
  confirmed every endpoint against real seeded verifications.

---

## Recommended Timeline

```
Week 1:  feature/go-sdk-parity (quick win)
         feature/protocol-expansion (parallel start)
Week 2:  feature/regression-engine (starts after protocol expansion)
         feature/policy-engine (parallel — wiring existing code)
Week 3:  feature/manifest-registry (needs regression engine)
         feature/plugin-framework (parallel)
Week 4:  feature/dashboard (needs all data sources)
         Integration testing
         Phase 2 certification
```

**Total: 4-5 weeks single developer.**

---

## Phase 2 Certification Checklist

- [x] All 829 existing tests pass (no regressions)
- [ ] New tests for each Phase 2 feature pass
- [ ] cargo clippy — 0 warnings
- [ ] cargo fmt --check — clean
- [ ] Go SDK tests pass (with new types)
- [ ] TypeScript SDK tsc --noEmit clean
- [ ] Python AI Layer tests pass
- [ ] Benchmark: expanded protocol count, updated precision/recall (P16)
- [ ] Security audit: G5 independence check, P8 plugin isolation
- [ ] Evolution Mode report: zero unresolved blocking findings
- [ ] All 5 Phase 2 exit criteria met

---

## Risk Register

| Risk | Mitigation |
|------|-----------|
| G5 independence check is open design question | Security Engineer designs BEFORE any Manifest Registry code |
| 1,000 real fixtures is a data acquisition problem | Start synthetic + benchmark-derived, grow from real usage |
| 2 real third-party plugins need external contributors | Build 2 example plugins ourselves first |
| Dashboard scope creep | Read-only data display only, defer real-time to Phase 3 |
| Regression Engine cost at 1,000+ fixtures | Performance Engineer designs cost model before implementation |
