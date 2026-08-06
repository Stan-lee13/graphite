# Changelog

All notable changes to Graphite Core are documented here.
Layer names follow `graphite-engineering-skill/ARCHITECTURE.md` section 3.12 as the canonical source.

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
