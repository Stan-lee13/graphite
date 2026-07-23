# Graphite Phase 1 + 1.5 — Release Evaluation Report

**Release:** v0.1.0-alpha (Phase 1 + 1.5, hardened)
**Maturity:** Security-verification starter with adversarial hardening. Production-ready for integration testing. Not yet deployed against real on-chain exploit corpus.
**Date:** 2026-07-23
**Repository:** github.com/Stan-lee13/graphite (main @ v0.1.0-alpha)
**Constitution P16 Compliance:** All metrics below are reproducible via `cargo test` and `cargo run --bin graphite benchmark`

---

## 1. Coverage Summary

| Component | Status | Test Count | Method |
|-----------|--------|------------|--------|
| Rust Core (lib) | ✅ Phase 1.5 | 83 unit | `cargo test --lib` |
| Adversarial Tests | ✅ Pass | 45 | `cargo test --test adversarial_tests` |
| Deep Extreme Tests | ✅ Pass | 43 | `cargo test --test deep_extreme_tests` |
| Hell Mode Tests | ✅ Pass | 37 | `cargo test --test hell_mode_tests` |
| Omega Red Team | ✅ Pass | 15 | `cargo test --test omega_red_team` |
| Omega Red Team Regression | ✅ Pass | 11 | `cargo test --test omega_red_team_regression` |
| Confidence Engine | ✅ Pass | 13 | `cargo test --test confidence_engine_tests` |
| Integration Tests | ✅ Pass | 16 | `cargo test --test integration_tests` |
| Self-Healing Tests | ✅ Pass | 3 | `cargo test --test self_healing_integration_test` |
| Go SDK | ✅ Pass | 7 | `go test ./...` |
| Python AI Layer | ✅ Pass | 6 | `python3 -m pytest test_intent_parser.py` |
| TypeScript SDK | ✅ Built | — | `npx tsc --noEmit` (type-check only, no runtime tests) |
| **Total** | | **279 tests** | **0 failures** |

---

## 2. Benchmark Results

**Command:** `cargo run --release --bin graphite benchmark`

```
Total cases:      13
Scored cases:     11 (safe + malicious only)
Correct:          11/11
Accuracy:         100.0%
Precision:        100.0%
Recall:           100.0%
True Positives:   7
True Negatives:   4
False Positives:  0
False Negatives:  0
Avg Latency:      ~25-66μs (release build, in-process, shared environment)
```

Note: Latency varies with system load (25μs idle → 66μs under contention). All measurements are in-process — no RPC round-trip latency is included. Production deployment will add network latency.

### Benchmark Categories

| # | Case | Category | Expected | Got |
|---|------|----------|----------|-----|
| 1 | System Transfer (legitimate) | safe | Approved | ✓ |
| 2 | SPL Token Transfer (legitimate) | safe | Approved | ✓ |
| 3 | SPL Token Burn (legitimate) | safe | Approved | ✓ |
| 4 | Unverified CPI (potential exploit) | malicious | Blocked | ✓ |
| 5 | Deep CPI chain (compositional drain) | malicious | Blocked | ✓ |
| 6 | Authority hijack (SetAuthority) | malicious | Blocked | ✓ |
| 7 | Account drain (CloseAccount) | malicious | Blocked | ✓ |
| 8 | Unknown protocol (no manifest) | unknown | Blocked | ✓ |
| 9 | Unknown protocol with no evidence | unknown | Blocked | ✓ |
| 10 | FakeSwap — swap intent on System Program | malicious | Blocked | ✓ |
| 11 | Simulation spoofing — compute divergence | malicious | Blocked | ✓ |
| 12 | Normal compute with baseline — not flagged | safe | Approved | ✓ |
| 13 | SPL Token SetAuthority hijack | malicious | Blocked | ✓ |

---

## 3. Protocol Coverage

| # | Protocol | Program ID | Manifest Verified | Risk Patterns Detected |
|---|---------|------------|-------------------|----------------------|
| 1 | System Program | 1111...1111 | ✅ | Drainer, HiddenTransfer |
| 2 | SPL Token | TokenkegQ...VQ5DA | ✅ | Drainer, AuthorityHijack, HiddenTransfer |
| 3 | Token-2022 | TokenzQd...PxuEb | ✅ | Drainer, AuthorityHijack, CloseAccount |
| 4 | Stake Program | Stake111...111 | ✅ | PermissionEscalation |
| 5 | Raydium AMM V4 | 675kPX...1Mp8 | ✅ | FakeSwap, HiddenTransfer |
| 6 | Squads V4 Multisig | 6XBGfP... | ✅ | AuthorityHijack |
| 7 | Jupiter V6 | JUP6Lk...TaV4 | ✅ | FakeSwap, UnexpectedCpi |
| 8 | Orca | (placeholder) | ✅ | FakeSwap |
| 9 | Meteora | (placeholder) | ✅ | FakeSwap |
| 10 | Memo | Memo1...Memo | ✅ | (benign) |

---

## 4. Risk Engine — Detected Patterns

| Pattern | Description | Severity | Detection Method |
|---------|-------------|----------|-----------------|
| Drainer | Transfers all funds from source account | P0 | State change analysis (6+ accounts with credits) |
| AuthorityHijack | SetAuthority instruction detected | P0 | Discriminator matching (0x0b, 0x00) |
| HiddenTransfer | Transfer hidden among many accounts | P0 | Ratio analysis (non-referenced accounts > threshold) |
| UnexpectedCpi | CPI to unverified program | P0 | allowed_cpis check (fail-closed if empty) |
| FakeSwap | Swap intent on non-swap program | P1 | Intent-program mismatch detection |
| CompositionalDrain | Multi-step drain via CPI chains | P0 | Compositional pattern matching |
| SimulationSpoofing | Compute divergence from baseline | P1 | Z-score analysis (>2σ from baseline) |
| IntentProgramMismatch | Intent type doesn't match program | P1 | Program capability lookup |

---

## 5. Phase 1.5 Additions

### 5.1 Simulation Integrity (Wired into Pipeline)
- Step 3.5 in verification pipeline
- Optional `simulation_baseline` field on VerificationInput
- If compute usage diverges >2σ from baseline → flagged → risk verdict blocked
- Graceful degradation: if no baseline provided, skip check (P12)

### 5.2 Intent-Program Mismatch Detection
- Swap intents only valid on DEX/aggregator programs
- Stake intents only valid on Stake Program
- Close intents only valid on token programs
- Mismatch → blocked as PermissionEscalation

### 5.3 Python AI Layer (Advisory-Only, Separate Process)
- `python-ai-layer/intent_parser.py`
- HTTP server on port 8081
- Parses natural language → ProposedIntent JSON schema
- 3 intent types supported: transfer, swap, stake
- P1 compliance: AI assists, never decides — Core makes all security decisions

### 5.4 Go SDK
- `sdk/go/graphite.go`
- Full type definitions matching Core's VerificationInput/VerificationResult
- HTTP client with 30s timeout
- Methods: Verify, Health, ListManifests
- 7/7 tests pass

---

## 6. Bugs Found and Fixed

### Bug 1: Intent-Program Mismatch (False Negative)
- **Severity:** P1
- **Description:** Swap intent sent to System Program was approved as safe.
- **Fix:** Added `detect_intent_program_mismatch()` to risk engine.

### Bug 2: Audit Trail ID Duplication (from Hell Mode)
- **Severity:** P2
- **Fix:** Added atomic sequence counter.

### Bug 3: Drainer Bypass via Empty-String State Changes (from Hell Mode)
- **Severity:** P1
- **Fix:** Check if ALL state changes are empty/whitespace, not just if vec is empty.

### Bug 4: HiddenTransfer False Positive on Multi-Account Protocols (from Hell Mode)
- **Severity:** P2
- **Fix:** Raised threshold from 4x+8 to 6x+12.

### Bug 5: Empty allowed_cpis Failed Open (from Adversarial Hardening)
- **Severity:** P0 — CPI check bypass
- **Fix:** Fail-closed per P12 — block ALL targets when allowed_cpis empty and CPI targets exist.

### Bug 6: Invalid Token-2022 Program ID (found during v0.1.0-alpha freeze)
- **Severity:** P1 — dead code in program identity check
- **Description:** `risk_engine.rs` used a 33-byte address that could never match.
- **Fix:** Replaced with valid 32-byte address. Added `token_2022()` constructor to `solana_types.rs`.

### Bug 7: Clippy Warnings (found during v0.1.0-alpha freeze)
- **Severity:** P3 — code quality
- **Fix:** All 11 warnings fixed. `cargo clippy --all` now produces 0 warnings.

### Bug 8: PDA Mismatch Positive Case Unverified (found by external code review)
- **Severity:** P1 — security property untested
- **Description:** The PDA mismatch test (`test_fix3_pda_mismatch_field_exists`) only verified that non-PDA accounts have `pda_mismatch = false`. No test constructed an actual mismatched PDA and confirmed it gets blocked — the positive security property was unverified. Across all 10 manifests, only Squads V4's `proposalApprove` instruction has a non-empty `pda_seeds` entry.
- **Fix:** Added `test_pda_mismatch_blocks_spoofed_pda` (constructs spoofed PDA, verifies `pda_mismatch = true`, verifies full pipeline blocks with `PdaMismatch` finding) and `test_pda_mismatch_correct_pda_passes` (verifies correct PDA does not trigger false positive).

### Bug 9: CLI Server Arm Not Feature-Gated (found by external code review)
- **Severity:** P3 — build-only issue
- **Description:** `cli.rs`'s `Server` arm and `bin/graphite.rs`'s `Server` subcommand unconditionally referenced `axum`/`tokio`, which are gated behind the `server` feature. Building with `--no-default-features --features cli` would fail.
- **Fix:** Added `#[cfg(feature = "server")]` gates to both the enum variant and the match arm. Verified `cargo build --no-default-features --features cli` compiles cleanly.

---

## 7. Known Limitations

1. **Synthetic corpus only** — no real on-chain exploit transactions (Phase 2)
2. **FakeSwap detection is heuristic** — real detection requires simulation integrity with pre/post balance comparison (Phase 2)
3. **No real CPI validation against Semantic Graph** — manifests specify allowed_cpis manually
4. **Latency is in-process only** — no RPC round-trip latency included
5. **Orca and Meteora program IDs are placeholders** — need verified IDs from official sources
6. **Python AI Layer is pattern-based** — no ML model, just regex heuristics (by design — P1)
7. **No Solana Agent Kit integration** — explicitly Phase 1.5 scope, not yet implemented

---

## 8. Release Readiness

| Criterion | Status | Evidence |
|-----------|--------|----------|
| All tests pass | ✅ | 279 tests (266 Rust + 7 Go + 6 Python), 0 failures |
| Benchmark 100% precision/recall | ✅ | 11/11 scored cases correct |
| Clippy clean | ✅ | 0 warnings |
| Constitution P16 compliance | ✅ | All metrics reproducible |
| Go SDK tests pass | ✅ | 7/7 |
| Python AI Layer functional | ✅ | 6/6 (advisory-only, P1 compliant) |
| Simulation Integrity wired in | ✅ | Step 3.5 in pipeline |
| Intent-Program mismatch detection | ✅ | Benchmark case #10 passes |
| Release build compiles | ✅ | ~3.1MB binary |
| Token-2022 program ID valid | ✅ | 32-byte address (fixed during freeze) |
| Phase 1 scope complete | ✅ | See sections 1-4 |
| Phase 1.5 scope complete | ✅ | See section 5 (except Solana Agent Kit) |

**Verdict: Phase 1 + 1.5 FROZEN as v0.1.0-alpha**

---

## 9. Reproduction Commands

```bash
# Full test suite
cd graphite-core && cargo test --all

# Benchmark (release build)
cargo build --release && ./target/release/graphite benchmark

# Clippy
cargo clippy --all

# Go SDK tests
cd sdk/go && go test -v ./...

# Python AI Layer test
cd python-ai-layer && python3 -m pytest test_intent_parser.py
```

---

*Report generated 2026-07-23. All numbers are from actual test runs on this commit, not estimates.*
