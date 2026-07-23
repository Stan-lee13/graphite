# Graphite Phase 2 — Public Beta Build Plan

**Branch:** `phase2-development` (created from `main` @ `0991d01`, tag `v0.1.0-alpha`)
**Target release:** `v0.2.0-beta`

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
| Regression Engine | Yes — replay_corpus() | 217 | 0 fixtures, no collection mechanism |
| Plugin Orchestrator | Yes — VerifierPlugin trait | 267 | No real plugins, no discovery |
| Manifest Registry | Yes — ManifestRegistry | — | No sig verification, no PR workflow, no G5 |
| Self-Healing | Yes — quarantine works | 342 | No production data volume yet |
| Dashboard | No | 0 | Everything |
| Go SDK | Yes — 7/7 tests | — | 3 missing types |

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
feature/plugin-framework (independent, benefits from Manifest Registry)
       │
       ▼
feature/policy-engine (needs real integrations via SAK/SDK)
       │
       ▼
feature/dashboard (needs data from all above)
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

- [ ] All 279 existing tests pass (no regressions)
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
