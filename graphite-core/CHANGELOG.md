# Changelog

All notable changes to Graphite Core are documented here.
Layer names follow `graphite-engineering-skill/ARCHITECTURE.md` section 3.12 as the canonical source.

## [Independent Gap Audit — C17 Tier-0 Protocol Surface] — 2026-08-08

### Tier-0 Foundational Programs Added (C17)
- **4 new seed manifests** (16 → 20): Associated Token Account (`ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL`), Compute Budget (`ComputeBudget111111111111111111111111111111`), BPF Loader classic (`BPFLoader2111…`), BPF Loader Upgradeable (`BPFLoaderUpgradeab1e…`). All four IDs verified executable on mainnet 2026-08-08 and added to `verified_program_ids.json`, the blessed-canonical-set test, `load_seed_manifests`, and the Python cross-check.
- **Grounded, not self-referential:** `test_tier0_manifest_discriminators_match_real_mainnet_fixtures` parses the pinned real mainnet fixtures and asserts every observed ComputeBudget/ATA instruction byte resolves to a manifest discriminator with an EQUAL value (0x02/0x03/0x04 ComputeBudget and 0x01 ATA observed live). Compute Budget instructions take zero accounts by design (Solana source) — documented, and the pipeline's rejection of a standalone empty plan is asserted as correct behavior.
- **`scripts/live_revalidate.py` retry+backoff** for 429/5xx: a transient public-RPC rate limit is retried (1.5s/3s) instead of being misreported as "program absent". Run result: registry 20/20 EXEC, manifests 20/20 EXEC, SAK Ok, exit 0.
- **Instruction surface total: 201 across 20 manifests.**

## [Independent Gap Audit — C16 Memo Restoration] — 2026-08-08

### Classic SPL Memo Restored (C16)
- **`MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr` restored as the 16th seed manifest** (`spl-memo-program.json`) and 16th entry in `protocols/verified_program_ids.json`. The earlier C1 conclusion that this ID "never existed on any cluster" was **itself wrong**: `getAccountInfo` on `api.mainnet-beta.solana.com` returns an executable account (99,736 B ELF, owner BPFLoader2111, actively used) — it is the classic SPL memo from solana-program-library, used in countless SPL token transfers.
- **Registry completeness now guarded three ways:** the new blessed-canonical-set test (`manifest.rs test_registry_contains_blessed_canonical_programs`) anchors the non-negotiable core IDs (System, SPL Token, Token-2022, Stake, and all three memo programs) so the registry cannot be silently corrupted by edit again; the bidirectional pin test (Rust + Python) checks manifests↔registry consistency; `scripts/live_revalidate.py` is fixed to skip non-manifest JSON files and to verify the registry's own IDs on-chain (non-zero exit on any absence) — it previously crashed with `KeyError: 'protocol'` on `verified_program_ids.json`.
- **Docs corrected** across `docs/forensic-audit-report.md`, `docs/independent-gap-audit.md`, `docs/release-evaluation-report.md`, and this changelog — every "never existed" claim replaced with the verified fact.

## [Phase 1.5 Completion — Devnet Verified] — 2026-08-07

### RPC Client (live-verified against Helius mainnet + devnet)
- **`get_slot` u64 parse fix** — the live `getSlot` response is a plain `u64`; the client parsed `result.value`, so every call failed `InvalidResponse`. This silently broke the live-corpus test and L3 wiring.
- **`get_account` null check** — a `value: null` response now returns `AccountNotFound` instead of fabricating a zeroed account that flowed through typed as real state.
- **`get_oracle_price` placeholder removed** — was a hardcoded zeroed `OraclePrice` fake (dead code, unused repo-wide).
- **`is_account_frozen` byte 108 fix** — the SPL token account `state` field sits at byte **108**; the client read byte 46 (the mint field), so freeze state was read from the wrong offset.
- **`post_rpc` exponential backoff** — retry-aware RPC helper with exponential backoff on `429`/`5xx`; `max_retries` config is now actually honored. New `RpcError::RateLimited` surfaced correctly.
- **9 new unit tests** for the RPC client (mock server, no network dependency).

### Server Hardening
- **Bearer API key auth** — constant-time SHA-256 comparison; `/verify` and `/manifests` protected, `/health` open for load balancers.
- **Per-IP token-bucket rate limiting** — configurable (`GRAPHITE_RATE_LIMIT`), FIFO eviction, returns `429`.
- **CORS denied by default** — configurable allowlist (`GRAPHITE_CORS_ORIGINS`); server-to-server clients unaffected.
- **Audit log persistence** — append-only JSONL (`audit.jsonl`) covering all 4 paths: approved / blocked / 400 / 500.
- **Graceful shutdown** and **`X-Forwarded-For` trusted only behind an explicit proxy flag**.

### L3/L8 Honest Layer States
- **L3 provenance-aware tri-state** — `Passed` / `Failed` / `Inconclusive`; the real simulation verdict is now reported (no more phantom `passed: true`).
- **L8 honestly reports "not yet verified"** with an audit-trail event until live execution is wired (Phase 2).
- Audit trail records `l3_status` / `l8_status`; verdict math unchanged (penalties key off `Failed` only) — 671 → 680 tests all green.

### Novel Instruction Fail-Closed (P12)
- **Unknown discriminator on a known protocol with a high-risk intent → BLOCKED**; a non-blocking warning is surfaced in the L7 layer report and the summary for novel instructions on known protocols (GAP-1).

### Validation & Determinism
- **Whitespace-only `program_id` rejection** in `seed_simulation_baseline` (GAP-9) — empty check extended to whitespace-only strings (poison key that survives snapshot restore).
- **Proptest invariant suite** — `proptest_engine.rs`: 512 cases, pinned regression.
- **PDA known-answer tests** — cross-validated against `@solana/web3.js` (Raydium AMM V4 `amm_authority`, CPMM `vault_and_lp_mint_auth_seed`), pinned 2026-08-06.
- **Manifest ID regression test** — `test_all_seed_manifest_program_ids_are_canonical` pins all 11 program IDs.

### Integration & CI
- **SAK integration verified on Solana devnet** — 5 finalized transactions (2 faucet airdrops + 3 SAK test transfers), wallet `CWb8MciizembLV66kisYcXo3Cb91hdszxw74QHpEJKZR`; latest signature `xHa4dyuFS6JmSaTsmhcMpEtwbWnPjBoUGwk3wNixD2uw2Wmeui6GhnSmmdzNVkv85zXSd6g7QYhHymAjciwP3jJ` confirmed and finalized.
- **CI: 4/4 jobs green** — Rust (fmt/clippy/tests + no-default-features gates), TypeScript SDK + SAK, Go SDK, Python AI layer.
- **Final state: 680 tests, 0 failures, 0 clippy warnings, fmt clean, ~850μs avg benchmark latency** (16 scored cases, 100% precision/recall).

## [Production Readiness Pass] — 2026-08-06

### Security Fixes
- **G4: caller evidence can no longer raise the trust tier above the manifest's declared tier.** `behavior_evidence` is request-body JSON; fabricated `has_signed_manifest`/community/battle counts could previously mint `OfficialManifest` on a low-tier manifest, escaping that tier's 0.55 P6 ceiling and inflating the `TrustTierLevel` signal. The manifest-found path now ignores caller evidence entirely (the Semantic Graph's internally-earned tier is still honored). Regression test: `test_caller_evidence_cannot_raise_tier_above_manifest_declared`.
- **TS AuditBind TOCTOU check fixed.** `AuditBind.computeHash` encoded fields with `|`/`,` separators, which never matched the Rust `content_hash` byte stream — the check always aborted. It now mirrors the Core byte-for-byte (SHA-256 over programId, discriminator, account addresses, raw data bytes, CPI targets, truncated to 16 hex chars) with cross-language pinned vectors in `integrations/solana-agent-kit/auditbind.test.ts`.
- **Out-of-manifest CPI warnings are no longer silently dropped.** `assess()` computed CPI warnings for known protocols then discarded them. New `assess_with_warnings()` returns `RiskAssessmentDetail { verdict, warnings }`; the orchestrator surfaces warnings in the L7 layer report and the result summary (Constitution P3), while keeping the binary verdict fail-open (P12 response 2).

### Correctness / Compile Fixes
- **`--features rpc` now compiles.** Two non-`mut` bindings (`l3_rpc_account_info`, `usage`) were assigned inside `#[cfg(feature = "rpc")]` blocks — a hard compile error for the RPC feature.
- **G7: `VerificationResult.manifest_version` added** — the version label of the manifest the result was checked against (`None` for unknown protocols), letting consumers detect cross-version replay confusion. Populated in the result and mirrored in the TS + Go SDKs.
- **Input size caps added** — `instruction_data` ≤ 64 KiB and `cpi_targets` ≤ 32, via new `VerificationError::InvalidInput` (HTTP 400). Prevents unbounded CPU/memory from in-process callers.
- **Server no longer spawns a Tokio runtime per request.** The axum handler now calls `verify_async` directly instead of the synchronous `verify()` wrapper (which created a full runtime + threads per request).
- **Removed dead code** in `manifest::load_seed_manifests` (orphan `include_str!` binding).

### Integration / Docs
- **SAK bridge defaults fixed** — AI layer URL default `7332` → `8081` (matches `intent_parser.py --serve`); default wallet profile is now a Phase-1-calibrated `Custom { min_confidence: 0.40, min_trust_tier: OfficialManifest }` (the built-in profiles — TradingBot 0.80 etc. — were tuned for the Phase 2 signal set and block everything in Phase 1); misleading "simulation raises confidence" comments corrected.
- **TS SDK `WalletProfile` now models the `Custom` object form** the Rust serde enum expects (`{ "Custom": { ... } }`).
- **CI added** — `.github/workflows/ci.yml` runs Rust fmt/clippy (all features)/tests, TS SDK typecheck + SAK typecheck + AuditBind cross-language tests, Go vet/tests, Python pytest.

## [Phase 1.5 — Audit Fixes Round 4] — 2026-07-30

### SAK Bridge
- **Pre-flight account reconstruction.** `executeSwap` and `executeTransfer` now pass the wallet public key (extracted from keypair at construction) and program IDs to Graphite. Previously passed empty `accountAddresses: []`, meaning L1 and L4 could not detect authority hijack or PDA mismatch.
- **TOCTOU documentation.** Added explicit comment and `content_hash` logging before SAK execution. Full TOCTOU prevention (re-hash signed tx vs approved hash) is Phase 2 AuditBind middleware.

### Intent Parser
- **Case-sensitive parsing.** Removed `.lower()` from `parse_intent()` — Solana base58 addresses are case-sensitive and lowercasing corrupts them. The regex already uses `re.IGNORECASE` for keyword matching.
- **Destination extraction.** Transfer intents now extract the destination address from natural language input and pass it through to the SAK bridge.

### TypeScript SDK
- **`content_hash` field added** to `VerificationResult` interface in `sdk/typescript/src/types.ts`.

### Compositional Drain
- **Pattern 2 added.** `detect_compositional_drain` now catches 5+ deep CPI chains with all-unique program IDs from untrusted roots (previously only caught duplicate program revisits). Trusted DEXs whitelisted. 3 new tests added.

### Test Suite
- Tests: 635 (630 Rust + 3 new compositional drain + 2 from SAK bridge updates)
- Python: 7 tests (destination extraction + 11 manifest cross-check)
- Go SDK: 9 tests
- Clippy warnings: 0

## [Phase 1.5 — Audit Fixes Round 3] — 2026-07-26

### Program ID Fixes
- **5 fake program IDs in `extreme_adversarial.rs`** corrected: Jupiter V6, Orca Whirlpools, Raydium AMM V4, Squads V4, Memo. Tests were unknowingly exercising the unknown-protocol path (0.55 ceiling) instead of manifest matching.
- **Legacy Memo program added as 11th manifest.** Both `Memo4c2pN8afCj432Lb7RMVKi9PbQnnW7ewFFaV3oAH` (p-memo) and `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr` (legacy SPL) are real on-chain programs.
  - ⚠️ **Superseded correction (2026-08-08):** the C1 conclusion that `MemoSq4gq…` "never existed on any cluster" was **itself wrong** — independent re-verification (same day, C16) shows it IS executable on mainnet (99,736 B ELF, owner BPFLoader2111) and it was restored as the classic SPL memo. The real story: all three memo programs exist on-chain — `MemoSq4gq…` (classic SPL), `Memo4c2pN8afCj…` (memo v4.0.0, upgradeable), `Memo1UhkJRfHyv…` (legacy, superseded). Since 2026-08-08 the program-ID single source of truth is `graphite-core/protocols/verified_program_ids.json`, guarded by the blessed-set test, the bidirectional pin tests (Rust + Python), and the fixed `scripts/live_revalidate.py` on-chain gate.

### Content Hash (P2)
- **`content_hash` field added to `VerificationResult`.** `audit_trail_id` includes an AtomicU64 counter (unique per call) — not deterministic. Added separate `content_hash` field — pure SHA-256 of transaction config, fully deterministic.

### SAK Integration
- **Port fixed.** SAK bridge was defaulting to `localhost:8080` but Rust server uses `7331`.
- **bs58 shim fixed.** Bare function → object with `decode`/`encode` methods.
- **TypeScript type errors fixed.** Re-exported `VerificationResult` from `graphite-sak-bridge.ts`.

## [Phase 1.5 — Audit Fixes Round 2] — 2026-07-26

### Trust Tier Fix
- **`TrustTierCeiling` breakdown bug (P3 violation).** Ceiling cap was never shown in verification breakdown because code compared two already-capped values. Fixed by using `ceiling_triggered` flag and reconstructing raw confidence. Added floating-point noise filter (>0.001).

### Benchmark Honesty (P16)
- **Benchmark labels corrected.** 5 cases labeled "REAL: ... (mainnet)" changed to "SYNTHETIC: ... (real program ID, synthetic accounts)".
- **Baseline comparison added.** Simulation-only baseline (approve if compute_units > 0) shows 0% recall — Graphite catches all 12 malicious cases.

### SAK Integration Rebuild
- **Previous fake integration removed.** Was an HTTP wrapper that did NOT import `solana-agent-kit`.
- **Real SAK v2 integration built.** Imports real `solana-agent-kit`, `@solana-agent-kit/plugin-token`, `@solana-agent-kit/plugin-defi`. Uses real SAK API.

## [Phase 1.5 — Audit Fixes Round 1] — 2026-07-24

### Architecture Fixes
- **8-layer pipeline tracking fixed.** The `layers` vec in `VerificationResult` now matches the architecture spec exactly: L1_AccountResolution → L2_InstructionVerification → L3_SimulationVerification → L4_StateVerification → L5_SemanticVerification → L6_PolicyVerification → L7_RiskVerification → L8_ExecutionVerification. Previously tracked 7 layers with wrong names and order.
- **L2/L4/L5 verification layers implemented.** Instruction verification (discriminator + arg structure check), state verification (expected state changes vs transaction structure), and semantic verification (intent-behavior matching) are now real checks, not stubs.

### Dead Code Removed
- **cpi_chain.rs** — CPI chain checking is done inline in risk_engine.rs.
- **regression_engine.rs** — Phase 2+ reference implementation, never called.
- **plugin_orchestrator.rs** — Phase 2+ reference implementation, never called.
- **self_healing.rs** — Phase 2+ reference implementation, never called.
- **Fake SAK integration** — HTTP wrapper that did NOT import solana-agent-kit.

### Test Quality
- **35 zero-assertion tests fixed.** Every test now has real assertions.
- **Layer tracking test added.** Dedicated test verifies 8 layers with correct names and order.

### Risk Engine Strengthened
- **PermissionEscalation** — Detects SPL Token Approve (discriminator 04) when intent is "transfer".
- **MaliciousAccountChange** — Detects CloseAccount/Allocate when intent is not "close".

## [Phase 1 — OMEGA RED TEAM Hardening] — 2026-07-22

### P0 CRITICAL Fixes
- **Corrected SPL Token and Token-2022 program IDs.** Case-sensitive base58 — `GKPfx` vs `GKPFX`.
- **NaN confidence bypass.** NaN passed range check → NaN < threshold is false → policy APPROVES. Fixed: explicit NaN/Infinity rejection.
- **Drainer ratio bypass.** 100 accounts + 1 declared change bypassed both drainer and hidden transfer detection. Fixed: ratio-based detection.

### P1 Fixes
- Drainer threshold: >5 → >=5
- Hidden transfer threshold: >12 → >=12
- Compositional drain threshold: >4 → >=3
- NaN/Infinity in simulation baseline values now rejected
- Empty discriminator on known risky programs now fails closed (P12)
- Account deduplication added to drainer detection

## [Phase 1.5 — Initial] — 2026-07-22

### Added
- FakeSwap detection — blocks swap intent on non-swap programs
- Simulation integrity check (3-signal z-score with Welford's algorithm)
- 4 additional seed protocols: Jupiter V6, Orca Whirlpools, Meteora DLMM, Memo
- TypeScript SDK with full type definitions
- Go SDK with integration tests

## [Phase 1 — MVP] — 2026-07-22

### Added
- Full Rust crate with real Solana types (curve25519-dalek, AccountMeta, Instruction, PDA derivation)
- 5 verified seed protocol manifests: System, SPL Token, Stake, Raydium AMM V4, Squads V4
- Risk Engine: 5 P0 patterns (Drainer, AuthorityHijack, HiddenTransfer, UnexpectedCpi, CompositionalDrain)
- 8-layer verification pipeline
- HTTP server (axum) + CLI (clap)
- Benchmark: 9 cases, 100% pass rate
- Release Evaluation Report (P16 compliant)
