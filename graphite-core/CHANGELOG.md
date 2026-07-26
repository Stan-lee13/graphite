# Changelog

All notable changes to Graphite Core are documented here.

## [Phase 1 — Production Audit & Dead Code Removal] — 2026-07-24

### Architecture Fixes
- **8-layer pipeline tracking fixed.** The `layers` vec in `VerificationResult` now
  matches the architecture spec exactly: L1_AccountResolution → L2_InstructionVerification
  → L3_RiskEngine → L4_ConfidenceEngine → L5_ProtocolIntelligence → L6_SimulationIntegrity
  → L7_PolicyEngine → L8_EmitVerdict. Previously tracked 7 layers with wrong names and order.
- **L2/L4/L5 verification layers implemented.** Instruction verification (discriminator +
  arg structure check), state verification (expected state changes vs transaction structure),
  and semantic verification (intent-behavior matching) are now real checks, not stubs.
  These feed into L5_ProtocolIntelligence as sub-checks.

### Dead Code Removed (Production-Ready Standard)
- **cpi_chain.rs** — CPI chain checking is done inline in risk_engine.rs. Module was
  redundant with 6 internal tests never exercised by the pipeline.
- **regression_engine.rs** — Phase 2+ reference implementation, never called.
- **plugin_orchestrator.rs** — Phase 2+ reference implementation, never called.
- **self_healing.rs** — Phase 2+ reference implementation, never called from pipeline.
- **self_healing_integration_test.rs** — Tests for removed self_healing module.
- **integrations/solana-agent-kit/** — HTTP wrapper that did NOT import
  solana-agent-kit, call SAK methods, or execute transactions. Removed per
  production-ready standard. Real SAK integration is Phase 2.
- **AUDIT_INTEGRATION.md** — Referenced removed SAK integration.

### Test Quality Fixes
- **35 zero-assertion tests fixed.** Every test in adversarial_handcrafted.rs,
  novel_attacks.rs, and real_world_attacks.rs now has real assertions.
- **Layer tracking test added.** Dedicated test verifies 8 layers with correct
  names and order matching architecture spec.

### Risk Engine Strengthened
- **PermissionEscalation** — Now detects SPL Token Approve instruction (discriminator 04)
  when intent is "transfer" (mismatch — Approve grants token approval, not transfer).
- **MaliciousAccountChange** — Now detects CloseAccount/Allocate on System Program
  when intent is "transfer" (intent mismatch — these instructions change account
  structure, not transfer tokens).

### Metrics
- Tests: 626 (down from 651 — removed 26 dead module tests, added 1 layer test)
- Clippy warnings: 0
- Compiler warnings: 0
- Benchmark: 18 cases, 100% precision/recall, 35μs avg latency (release build)

## [Phase 1 — OMEGA RED TEAM Hardening] — 2026-07-22

### P0 CRITICAL Fixes

- **L4: Corrected SPL Token and Token-2022 program IDs.** The RISKY_PATTERNS table had wrong base58 addresses — `GKPfx` instead of `GKPFX` (case-sensitive) for SPL Token, and `TokenzQdQ81QPToVkTX67G9XGX46D3sC9Dq6EicgC6f` instead of `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb` for Token-2022 (verified from spl-token-2022-interface v3.1.1 source). SetAuthority and CloseAccount on the real mainnet programs were completely undetected.
- **L11: NaN confidence bypass.** NaN signal values passed the range check (NaN < 0.0 is false, NaN > 1.0 is false) → NaN confidence → NaN < threshold is false → policy APPROVES. Fixed: explicit NaN/Infinity rejection in confidence engine.
- **L18: Drainer ratio bypass.** 100 accounts with 1 declared "transfer" state change bypassed BOTH drainer detection (had "meaningful" change) AND hidden transfer detection (no "accounts." notation). Fixed: ratio-based detection (unique accounts / meaningful changes >= 10 AND >= 20 unique accounts).

### P1 Fixes

- **L1:** Drainer threshold changed from >5 to >=5 (5 accounts now correctly blocked)
- **L2:** Hidden transfer threshold changed from >12 to >=12 (12 accounts now correctly blocked)
- **L3:** Compositional drain threshold changed from >4 to >=3 (3+ repeated CPI targets now blocked)
- **L6/L6b:** NaN/Infinity in simulation baseline values now rejected (previously bypassed divergence check)
- **L8:** Empty discriminator on known risky programs (SPL Token, Token-2022, System) now fails closed (P12)
- **L12:** Account deduplication added to drainer detection (HashSet — 6 copies of same account = 1 unique)

### Test Suite

- 259 tests passing (83 unit + 45 adversarial + 43 deep extreme + 37 hell mode + 15 omega red team + 11 omega regression + 13 confidence + 9 integration + 3 self-healing)
- Clippy: 0 errors, 11 warnings
- Benchmark: 18 cases, 100% precision/recall, ~33μs avg latency
- All addresses corrected across src/, tests/, and protocols/

## [Phase 1.5 — Initial] — 2026-07-22

### Added

- FakeSwap detection (detect_intent_program_mismatch) — blocks swap intent on non-swap programs
- Simulation integrity check in verification pipeline
- 4 additional seed protocols: Jupiter V6, Orca Whirlpools, Meteora DLMM, Memo
- TypeScript SDK with full type definitions
- Go SDK with 5/5 integration tests passing
- Release build: 3.1MB binary

## [Phase 1 — MVP] — 2026-07-22

### Added

- Full Rust crate with real Solana types (Pubkey via curve25519-dalek, AccountMeta, Instruction, PDA derivation)
- 5 verified seed protocol manifests: System Program, SPL Token, Stake Program, Raydium AMM V4, Squads V4 Multisig
- Manifest-aware Risk Engine: 5 P0 patterns (Drainer, AuthorityHijack, HiddenTransfer, UnexpectedCpi, CompositionalDrain)
- 8-layer verification pipeline
- HTTP server (axum) and CLI (clap)
- Benchmark: 9 cases, 100% precision/recall, ~100μs avg latency
- Release Evaluation Report (P16 compliant)
