# Graphite v0.1.0-alpha — Release Evaluation Report

**Date:** 2026-08-07 (v0.1.0-alpha frozen 2026-07-23; Phase 1.5 completion update)  
**Version:** v0.1.0-alpha → Phase 1.5 complete (branch: phase2-development)  
**Repository:** github.com/Stan-lee13/graphite  
**Constitution Principle:** P16 — No public performance claim without a linked, reproducible benchmark run backing the exact number.

---

## 1. Executive Summary

Graphite v0.1.0-alpha is the first frozen release of a transaction intent verification engine for Solana AI agents. It verifies that constructed transactions actually do what was declared, produces a falsifiable confidence score, and fails closed on unknown protocols.

**Key results:**
- **680 Rust tests** (108 unit + 572 integration/adversarial), **0 failures** (682 with `--include-ignored`)
- **7 Python AI layer tests**, 0 failures
- **9 Go SDK tests**, 0 failures
- **TypeScript SDK**: clean compile (tsc --noEmit)
- **16 scored benchmark cases** (safe + malicious) + 2 baseline comparisons, **100% precision, 100% recall**
- **~850μs average latency** (release build, all features, live-measured 2026-08-07)
- **0 clippy warnings**, fmt clean, no-default-features builds
- **11 seed protocol manifests (10 original + legacy Memo)**, all program IDs verified from official sources
- **SAK integration verified on Solana devnet** — 5 finalized transactions (Aug 7, 2026)

---

## 2. Test Suite

### 2.1 Rust Test Breakdown

| Category | Test File | Tests | Status |
|---|---|---|---|
| **Unit** | `src/*.rs` (lib tests) | 108 | ✅ Pass |
| **Integration** | `tests/integration_tests.rs` | 16 | ✅ Pass |
| **Confidence** | `tests/confidence_engine_tests.rs` | 13 | ✅ Pass |
| **Layer Honesty** | `tests/layers_test.rs` | 5 | ✅ Pass |
| **Adversarial** | `tests/adversarial_tests.rs` | 45 | ✅ Pass |
| **Deep Extreme** | `tests/deep_extreme_tests.rs` | 44 | ✅ Pass |
| **Extreme Adversarial** | `tests/extreme_adversarial.rs` | 50 | ✅ Pass |
| **Hell Mode** | `tests/hell_mode_tests.rs` | 37 | ✅ Pass |
| **Omega Red Team** | `tests/omega_red_team.rs` | 15 | ✅ Pass |
| **Omega Regression** | `tests/omega_red_team_regression.rs` | 11 | ✅ Pass |
| **Proptest** | `tests/proptest_engine.rs` (512 cases) | 4 | ✅ Pass |
| **Trust Tier** | `tests/trust_tier_verify.rs` | 2 | ✅ Pass |
| **Real-World Attacks** | `tests/real_world_attacks.rs` | 100 | ✅ Pass |
| **Novel Attacks** | `tests/novel_attacks.rs` | 100 | ✅ Pass |
| **Handcrafted Adversarial** | `tests/adversarial_handcrafted.rs` | 100 | ✅ Pass |
| **Real Exploit Tests** | `tests/real_exploit_tests.rs` | 15 | ✅ Pass |
| **Real On-Chain Exploits** | `tests/real_onchain_exploits.rs` | 15 | ✅ Pass |
| **Live Devnet Corpus** | `tests/live_transactions.rs` (RPC; ignored by default) | 1 (ignored) | ✅ Pass with RPC |
| **Total** | | **680** | **0 failures** |

### 2.2 Adversarial Test Categories

The adversarial/exploit test suites cover 9 attack categories:

1. **Protocol impersonation** — real program IDs with fake data, hidden drainer CPI, wrong discriminators
2. **PDA spoofing & account substitution** — wrong seeds, address poisoning, empty/zero PDAs
3. **CPI-chain corruption** — hidden drainer at depth 3, CPI laundered through ComputeBudget
4. **Semantic-graph poisoning** — maxed BehaviorEvidence, intent laundering, trust tier manipulation
5. **Policy-ceiling** — all profiles enforce 0.55 cap on unknown protocols
6. **Serialization fuzzing** — truncated IDs, Unicode, empty accounts, 1000-account payloads
7. **Prompt injection** — "IGNORE INSTRUCTIONS", fake [SYSTEM] tags, JSON injection
8. **Replay & stale-state** — durable nonce time-bomb, account revival, SetAuthority
9. **Benchmark mutation** — mutated swaps, wrong discriminators, compound all-vectors attacks

### 2.3 Real Mainnet Exploit Coverage

15 tests use real exploit transaction data manually curated from published security research:

| Attack Class | Source | Program ID | Tests |
|---|---|---|---|
| STMT Drainer (CLINKSINK) | Mandiant/Google (Jan 2024) | `4PG6e97DLCn2PRN4ZMmTLg83jsetrDkvamr3JiXoiffa` | 10 |
| AAT Drainer (Account Authority Transfer) | SlowMist (Dec 2025) | `3W2y8TuU2rKf4qvrKZAbu8Tu9najg9Bvcwfsf28aW3rs` | 3 |
| Wormhole Bridge Hack ($320M) | Kudelski Security (Feb 2022) | `worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth` | 1 |
| Negative control (legitimate transfer) | — | SPL Token | 1 |

**Data sourcing note:** Transaction data is manually curated from published security research papers and postmortems — not fetched via live RPC. Program IDs, account structures, and CPI patterns are verified against the cited sources. Instruction data bytes are not included; detection is based on program identity, account structure, and CPI patterns.

### 2.4 Non-Rust Tests

| Surface | Tests | Status |
|---|---|---|
| Go SDK | 9 (`go test ./...`) | ✅ Pass |
| Python AI Layer | 7 (`pytest test_intent_parser.py`) | ✅ Pass |
| TypeScript SDK | — | ✅ Clean compile (`tsc --noEmit`) |
| Solana Agent Kit | — | ✅ TypeScript typecheck, AuditBind cross-language tests, **end-to-end verified on Solana devnet** (5 finalized transactions) |

---

## 3. Benchmark Suite

**Reproduce:** `cargo run --bin graphite --release -- benchmark`

### 3.1 Results

| Metric | Value |
|---|---|
| Total cases | 18 (16 scored + 2 baseline comparisons) |
| Scored cases | 16 (safe + malicious only) |
| Accuracy | 100.0% |
| Precision | 100.0% |
| Recall | 100.0% |
| True Positives | 12 (malicious → blocked) |
| True Negatives | 4 (safe → approved) |
| False Positives | 0 |
| False Negatives | 0 |
| Avg Latency | ~850μs (release, all features, 2026-08-07) |

### 3.2 Benchmark Cases

| # | Label | Category | Expected | Result |
|---|---|---|---|---|
| 1 | System Transfer (legitimate) | safe | Approved | Approved ✓ |
| 2 | SPL Token Transfer (legitimate) | safe | Approved | Approved ✓ |
| 3 | SPL Token Burn (legitimate) | safe | Approved | Approved ✓ |
| 4 | Unverified CPI (potential exploit) | malicious | Blocked | Blocked ✓ |
| 5 | Deep CPI chain (compositional drain) | malicious | Blocked | Blocked ✓ |
| 6 | Authority hijack (SetAuthority) | malicious | Blocked | Blocked ✓ |
| 7 | Account drain (CloseAccount) | malicious | Blocked | Blocked ✓ |
| 8 | Unknown protocol (no manifest) | unknown | Blocked | Blocked ✓ |
| 9 | Unknown protocol with no evidence | unknown | Blocked | Blocked ✓ |
| 10 | FakeSwap (swap intent on System Program) | malicious | Blocked | Blocked ✓ |
| 11 | Simulation spoofing (50000 vs 150 compute) | malicious | Blocked | Blocked ✓ |
| 12 | Normal compute with baseline | safe | Approved | Approved ✓ |
| 13 | SPL Token SetAuthority hijack | malicious | Blocked | Blocked ✓ |
| 14 | SYNTHETIC: CLINKSINK STMT Drainer (real program ID, synthetic accounts) | malicious | Blocked | Blocked ✓ |
| 15 | SYNTHETIC: AAT Drainer — Approve + assign (real program ID, synthetic accounts) | malicious | Blocked | Blocked ✓ |
| 16 | SYNTHETIC: Wormhole Hack ($320M, Feb 2022) (real program ID, synthetic accounts) | malicious | Blocked | Blocked ✓ |
| 17 | SYNTHETIC: AAT Mass Drain (25 accts) (real program ID, synthetic accounts) | malicious | Blocked | Blocked ✓ |
| 18 | SYNTHETIC: CLINKSINK Token Drain (real program ID, synthetic accounts) | malicious | Blocked | Blocked ✓ |

---

## 4. Protocol Coverage

11 seed protocol manifests (10 original + legacy Memo), all program IDs verified from official sources:

| Protocol | Program ID | Source |
|---|---|---|
| System Program | `11111111111111111111111111111111` | Solana docs |
| SPL Token | `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` | Solana docs |
| Token-2022 | `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb` | spl-token-2022 crate |
| Stake Program | `Stake11111111111111111111111111111111111111` | Solana docs |
| Jupiter V6 | `JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4` | Jupiter docs |
| Raydium AMM V4 | `675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8` | docs.raydium.io |
| Orca Whirlpools | `whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc` | Orca SDK |
| Meteora DLMM | `LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo` | Meteora docs |
| Squads V4 | `SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf` | Squads-Protocol/v4 GitHub |
| Memo Program | `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr` | Solana docs |

---

## 5. Risk Engine Coverage

8 risk pattern detectors:

| Pattern | Description | Severity |
|---|---|---|
| `Drainer` | STMT — too many unique accounts for instruction type | Critical |
| `AuthorityHijack` | SetAuthority transfers account ownership | Critical |
| `HiddenTransfer` | Extra transfer instructions hidden in account list | Critical |
| `UnexpectedCpi` | CPI target not in manifest's allowed list | Critical |
| `CompositionalDrainPattern` | Multiple risk patterns combined | Critical |
| `FakeSwap` | Swap intent routed to program with no swap output | Critical |
| `PermissionEscalation` | Unauthorized privilege escalation attempt | High |
| `MaliciousAccountChange` | Unauthorized account state modification | High |

---

## 6. Verification Pipeline

8-layer pipeline, fail-closed by default (Constitution P12):

1. **Account Resolution** — Resolve addresses, verify PDAs against expected seeds, flag mismatches as hard-fail
2. **Transaction Construction** — Decode signers, instructions, accounts, CPI tree, validate program IDs
3. **Risk Engine** — Detect drainers, authority hijacks, hidden transfers, unexpected CPI, fake swaps
4. **Confidence Engine** — Combine intent match, protocol trust tier, evidence signals into explainable score
5. **Protocol Intelligence** — Match against versioned manifests. Unknown protocols capped at 0.55
6. **Simulation Integrity** — Cross-check simulation evidence against independent signals
7. **Policy Engine** — Apply per-agent/per-org rules (Treasury/TradingBot/Gaming/Enterprise)
8. **Emit Verdict** — Return confidence-rich report with audit trail

---

## 7. Known Limitations

1. **Synthetic benchmark corpus** — 11 of the 16 scored benchmark cases use hand-crafted accounts (the 5 exploit reconstructions use real program IDs and are labeled SYNTHETIC per P16). Live on-chain verification is now exercised separately via `tests/live_transactions.rs` (real devnet corpus through the full pipeline) and the SAK devnet integration. Real on-chain instruction-level verification for drainer programs requires protocol manifests (Phase 2).

2. **Protocol expansion** — 11 seed protocols are included. Phase 2 will expand to 15-20 with community-contributed manifests.

3. **FakeSwap detection requires simulation integrity** — The FakeSwap pattern is detected by checking if swap intent routes to a swap program but expected state changes don't include output/credit. Full FakeSwap detection requires simulation integrity (Phase 2).

4. **No real CPI validation against Semantic Graph** — Manifests specify allowed_cpis manually. The Semantic Graph will provide automatic CPI validation in Phase 2.

5. **Latency is in-process only** — Benchmark latency excludes RPC round-trips. Real-world latency depends on RPC node speed and account resolution state-fetch time.

6. **Unknown protocol manifest data** — Unknown programs (including drainer programs) cannot have their instruction semantics verified without a manifest. Graphite correctly caps confidence at 0.55 and fails closed, but cannot provide semantic verification for unknown programs.

---

## 8. Code Quality

| Check | Result |
|---|---|
| `cargo test` | 680 passed, 0 failed (682 with `--include-ignored`) |
| `cargo clippy` | 0 warnings |
| `cargo fmt` | Clean |
| `cargo build --release` | ~3.1MB binary |
| Unsafe Rust | None |
| LLM calls in verification path | None (Constitution P1) |
| Secrets in codebase | None |

---

## 9. Reproducibility

All numbers in this report are reproducible:

```bash
# Full test suite
cargo test

# Clippy
cargo clippy

# Benchmark
cargo run --bin graphite --release -- benchmark

# Python AI layer
cd python-ai-layer && python3 -m pytest -q test_intent_parser.py

# Go SDK
cd sdk/go && go test ./...

# TypeScript SDK
cd sdk/typescript && npx tsc --noEmit
```

---

**Phase 1 + 1.5: COMPLETE (frozen v0.1.0-alpha; Phase 1.5 verified on devnet 2026-08-07)**  
**Phase 2 (Public Beta): READY TO BEGIN — all Phase 2 work on `phase2-development`**
