<!-- 
DEPRECATED: This audit was performed on an earlier version of the codebase (pre-Phase 1.5 audit).
The following findings have been RESOLVED:
- detect_fake_swap IS wired into assess() (P0 Check 8) — test_cpi_level_authority_hijack_blocked passes
- detect_intent_program_mismatch IS wired into assess() (P0 Check 9)
- All 8 risk patterns are real detection logic, not toys
- Confidence engine uses real weighted arithmetic with tier ceilings
- Simulation integrity uses 3-signal z-score comparison with Welford's algorithm
This document is retained for historical reference only.
-->

# Audit Report: Graphite Core Verification Engine Security Modules
**Target Directory:** `/app/.cert/graphite/graphite-core/src/`  
**Date:** July 24, 2026  
**Auditor:** Superagent Auditing Bot  
**Classification:** Brutally Honest / Highly Confidential  

---

## 1. Executive Summary

An in-depth code-level audit of the Graphite verification engine’s core security modules shows that while the architectural shell is clean, robust, and correctly enforces key rules (such as order of operations: Risk Gate $\rightarrow$ Policy), **the core security logic—specifically risk pattern detection, confidence score computation, and simulation spoofing prevention—currently consists of low-fidelity "toys" / prototypes.**

They rely heavily on:
1. **Coarse heuristics, basic string search, and count checks** rather than deep parsing of instruction layouts or transaction data.
2. **Hardcoded lookup constraints** and **empty placeholder logic** (especially inside the confidence engine).
3. **Severe architectural bypasses** that would allow an active adversary to trivially evade blocks.

The modules are **not production-grade** and should be considered a functional prototype or MVP skeleton.

---

## 2. Risk Engine Analysis (`risk_engine.rs`)
**File Path:** `.cert/graphite/graphite-core/src/risk_engine.rs`

### 2.1. Active Attack Pattern Detection (Enum vs. Reality)
The `RiskPattern` enum (lines 25–44) defines **8** attack patterns, but only **5** are actively checked during the core assessment function `assess` (lines 128–246):

1. **`UnexpectedCpi`** (P0 Check 1, lines 133–166): Blocks if any address in `cpi_targets` is missing from the manifest's `allowed_cpis`.
2. **`AuthorityHijack`** (P0 Check 2, lines 168–196): Checks for SetAuthority/System Assign commands using static discriminators.
3. **`Drainer`** (P0 Check 2, lines 168–196 & P0 Check 3, lines 203–229): Detects via CloseAccount discriminators, account-count heuristics, and account mismatches.
4. **`CompositionalDrainPattern`** (P0 Check 4, lines 231–238): Blocks repeated program targets in CPI chains.
5. **`HiddenTransfer`** (P0 Check 5, lines 240–245): Flags transactions referencing accounts not declared in expected state changes.

#### The "Toy" Detections:
* **`FakeSwap`** is defined as `detect_fake_swap` (lines 621–653) but is **never called** inside `assess`.
* **`PermissionEscalation`** is defined as `detect_intent_program_mismatch` (lines 697–702) but is **never called** inside `assess`.
* **`MaliciousAccountChange`** is **never checked or generated** anywhere in `risk_engine.rs` (though, as detailed below, the verification pipeline in `verification.rs` utilizes it as a wrapper override when a PDA mismatch is recorded).

---

### 2.2. Pattern Matching Fidelity
None of the checked patterns are based on real transaction deserialization, program state evaluation, or signature analysis. They are entirely basic string-matching and length-counting heuristics:
* **`UnexpectedCpi`**: Checks string containment against a static list of string public keys (`allowed_cpis`).
* **`AuthorityHijack` / `Drainer` (risky instructions)**: Simple string equality checks on hardcoded `program_id` strings and hex-string `instruction_discriminator` representations (e.g. `"0b"`, `"09"`, `"01000000"`).
* **`Drainer` (via `detect_drainer_pattern`)**: Count-based. Case 1 (lines 266–269) flags if unique account count $\ge 5$ and no state changes are declared. Case 2 (lines 271–280) flags if unique account count $\ge 20$ and the ratio of unique accounts to meaningful state changes $\ge 10$.
* **`STMT drainer`**: Checks if the unique accounts count exceeds the manifest's expected count plus 2 (`unique_count > expected_count + 2`).
* **`CompositionalDrainPattern`**: If the total CPI list length is $\ge 3$, it inserts program IDs into a HashSet and checks if `unique_len < total_len`. Any repeated program ID triggers a block.
* **`HiddenTransfer`**: If `expected_state_changes` contains the exact substring `"accounts."`, it counts those entries. If total accounts $\ge 6 \times \text{referenced\_count}$ and total accounts $\ge 12$, it flags.

---

### 2.3. Transaction Analysis Scope
The Risk Engine **does not** decode CPI chains at runtime (it receives a flat list of strings), **does not** verify Solana account structures or owners, and **does not** parse instruction layout data. It is completely metadata-dependent.

---

### 2.4. Unknown Transaction / Fail-Closed Behavior
The Risk Engine **does fail closed** in two core scenarios:
1. **Missing Manifest with CPI Targets** (lines 151–165): If the transaction performs CPI calls (`!cpi_targets.is_empty()`) but no manifest is registered (`allowed_cpis` is empty), it unconditionally blocks the transaction as `UnexpectedCpi` with the reason: `"(no manifest data — fail-closed)"`.
2. **Empty Discriminator on Risky Programs** (lines 187–195): If the program called is a token program (SPL Token or Token-2022) but the `instruction_discriminator` is empty, it fails closed and blocks as `AuthorityHijack` or `Drainer` with the reason: `"(P12 fail-closed)"`.

However, if an unknown transaction has **no CPI targets** and does not call a known risky program, it will **pass** through the risk engine.

---

### 2.5. Trivial Bypasses (Critical Vulnerabilities)
An attacker can easily bypass every active risk check:
1. **Risky Instructions Bypass**: The `RISKY_PATTERNS` check (line 175) only compares `input.program_id`. If an attacker executes `SetAuthority` or `CloseAccount` via a **CPI call** from their own custom deployer program (where `input.program_id` is the custom program ID, and the token program is just a CPI target), the check is completely bypassed.
2. **Drainer Bypass**: An attacker can touch 19 unique accounts and empty them, bypassing Case 1 by declaring a single dummy state change (e.g., `"transfer 1 lamport"`), and bypassing Case 2 because the account count is $< 20$.
3. **STMT Drainer Bypass**: If `expected_account_count` is passed as `None` (which is an `Option`), the check is skipped. Even if present, the attacker can still drain up to 2 extra accounts without triggering the limit (threshold is `expected_count + 2`).
4. **Compositional Drain Bypass**: An attacker can call separate cloned programs with unique program IDs instead of repeating a single target program ID, rendering the HashSet duplicate-detector useless.
5. **Hidden Transfer Bypass**: If the protocol manifest does not use the exact `"accounts."` string syntax in its state changes, the check is skipped entirely. Even if it does, the attacker can touch up to 11 accounts without triggering the check, since it requires a minimum of 12 accounts.
6. **Unexpected CPI Bypass**: If an attacker deploys a malicious program that directly executes exploits inside its main instruction body and makes no CPI calls, the `cpi_targets` list is empty, bypassing the CPI restriction entirely.

---

## 3. Confidence Engine Analysis (`confidence_engine.rs`)
**File Path:** `.cert/graphite/graphite-core/src/confidence_engine.rs`

### 3.1. Confidence Score Computation
The confidence score is computed as a basic weighted linear sum in `compute_confidence` (lines 157–164):
$$\text{confidence} = \sum (\text{signal.value} \times \text{signal.weight})$$
It then compares the resulting score against a hard ceiling corresponding to the contract's `TrustTier`.

---

### 3.2. Enforcing the 0.55 Cap on Unknown Protocols
Yes, the 0.55 ceiling is structurally enforced in the code:
* **The 0.55 Constant** is defined at line 69:
  ```rust
  pub const UNKNOWN_OR_HEURISTIC_MAX: f64 = 0.55;
  ```
* **Tier Ceiling Mapping** (lines 189–196):
  ```rust
  let ceiling = match trust_tier {
      TrustTier::Unknown | TrustTier::HeuristicInferred => ceilings::UNKNOWN_OR_HEURISTIC_MAX,
      TrustTier::OfficialManifest => ceilings::OFFICIAL_MANIFEST_MAX,
      TrustTier::SimulationValidated => ceilings::SIMULATION_VALIDATED_MAX,
      TrustTier::CommunityVerified | TrustTier::BattleTested => {
          ceilings::COMMUNITY_OR_BATTLE_TESTED_MAX
      }
  };
  ```
* **Enforcement & Capping** (lines 198–203):
  ```rust
  let ceiling_triggered = confidence > ceiling;
  let final_confidence = if ceiling_triggered {
      ceiling
  } else {
      confidence
  };
  ```

---

### 3.3. Real Multi-Signal Computation vs. Lookup Table
The calculation itself is a real arithmetic weighted sum (not a static lookup table), but it is a **toy implementation**:
* There are no complex interactions, non-linear mappings, or dependency analyses.
* The file contains explicit doc comments (lines 8–10) declaring:  
  *"This is a reference implementation demonstrating the SHAPE of the confidence computation, not a production-final algorithm."*

---

### 3.4. Input Signals: Real or Placeholders?
The signals are defined in the `SignalKind` enum (lines 81–92):
* `ManifestMatch`
* `SimulationMatch`
* `HistoricalVolume`
* `CommunityVerification`

**They are 100% placeholders.** There is absolutely no logic in this file (or the broader workspace) to compute, parse, on-chain query, or dynamically generate these values. They must be prepared entirely by an external orchestrator and passed as a static array to `compute_confidence`.

---

## 4. Account Resolution Analysis (`account_resolution.rs`)
**File Path:** `.cert/graphite/graphite-core/src/account_resolution.rs`

### 4.1. PDA Seed Verification
**Yes, it actually verifies PDAs against expected seeds.**
In `resolve_accounts` (lines 111–148), for any account defined as a PDA in the manifest, the engine:
1. Translates seed templates (like `{program_id}`).
2. Calls `solana_types::find_program_address(&seed_refs, &program_pk)`.
3. Compares the derived public key with the user-provided address (`derived_pk != *pk`).
4. If a mismatch occurs, it pushes to a `pda_mismatches` list and sets `pda_mismatch = true` on the returned `ResolvedAccount` (line 160).

### 4.2. Blocking Mismatched PDAs
To avoid terminating the resolution pipeline prematurely (allowing a complete analysis report to compile), it **does not hard fail** inside `account_resolution.rs`. 

Instead, the orchestration file `.cert/graphite/graphite-core/src/verification.rs` (lines 316–335) checks the `ResolvedAccount` collection. If any `pda_mismatch` is true, it overrides the `risk_verdict` to `Blocked`, using the pattern `RiskPattern::MaliciousAccountChange` and attaches a descriptive reason detailing the spoofed PDA account address.

---

## 5. Simulation Integrity Analysis (`simulation_integrity.rs`)
**File Path:** `.cert/graphite/graphite-core/src/simulation_integrity.rs`

### 5.1. Real or Stub?
It is a **simplistic prototype/stub**. It tries to detect "Simulation Spoofing" (where a program behaves differently under simulation than in execution) by performing a Z-score check on a simulated transaction's compute units (lines 103–104):
$$\text{z\_score} = \frac{\text{simulation\_usage.compute\_units} - \text{baseline.mean\_compute\_units}}{\text{baseline.std\_compute\_units}}$$
If $\text{abs(z\_score)} > \text{divergence\_threshold}$, it flags the transaction.

### 5.2. Core Limitations (Why it is a Toy)
* **Unused Fields**: Although the `ComputeUsage` struct defines `account_writes` (line 29) and `cpi_hops` (line 30), **these fields are completely ignored and unused** during the check. Only `compute_units` is assessed.
* **Trivial Evasion**: Z-score analysis on a single variable (`compute_units`) is incredibly weak. 
  * If the standard deviation is naturally high, the baseline becomes wide and useless, making spoofing invisible.
  * An attacker can easily add dummy loops or padding to their malicious on-chain path to ensure the real execution consumes the exact same amount of compute units as the clean simulation path, keeping $\text{z\_score} \approx 0.0$.

---

## 6. Policy Engine Analysis (`policy_engine.rs`)
**File Path:** `.cert/graphite/graphite-core/src/policy_engine.rs`

### 6.1. Risk Profile Differences
Yes, the 4 risk profiles (and the Custom option) defined in the `WalletProfile` enum (lines 32–48) are **actually different**. They enforce distinct minimum thresholds in `evaluate_policy` (lines 94–103):

1. **`Treasury`**: `min_confidence` = `0.95`, `min_trust_tier` = `TrustTier::CommunityVerified`
2. **`TradingBot`**: `min_confidence` = `0.80`, `min_trust_tier` = `TrustTier::SimulationValidated`
3. **`Unrestricted`**: `min_confidence` = `0.0`, `min_trust_tier` = `TrustTier::HeuristicInferred`
4. **`Enterprise`**: `min_confidence` = `1.0`, `min_trust_tier` = `TrustTier::BattleTested`
4. **`Enterprise`**: `min_confidence` = `0.99`, `min_trust_tier` = `TrustTier::BattleTested`

### 6.2. Risk Override (G4 Mitigation)
The engine correctly enforces the **G4 mitigation** (Confidence Gaming) by placing the Risk Engine block check at Step 1 of `evaluate_policy` (lines 89–91):
```rust
if input.risk_verdict != RiskVerdict::Passed {
    return Ok(PolicyVerdict::RejectedRiskEngineBlock);
}
```
Because of this ordering, a transaction blocked by the Risk Engine is **hard rejected** immediately, and a high confidence score from a permissive profile can never override or bypass a risk engine finding.

---

## 7. Audit Verdict: Toy vs. Production-Grade

| Module | Score / Status | Key Finding |
| :--- | :--- | :--- |
| **Risk Engine** | ❌ **Toy** | Fails to implement 3/8 patterns; depends entirely on trivial string/length heuristics; exhibits multiple bypasses. |
| **Confidence Engine** | ❌ **Toy** | Basic weighted linear sum; completely depends on placeholder/uncomputed signal inputs. |
| **Account Resolution** |  **Production-Ready Shell** | Correctly re-derives PDAs using Solana cryptographic primitives and successfully hooks into the verification block pipeline. |
| **Simulation Integrity** | ❌ **Toy** | Basic Z-score check on compute units only; ignores writing and CPI factors; easily spoofed. |
| **Policy Engine** |  **Production-Ready Shell** | Implements G4 hard-gate mitigation flawlessly and separates the profiles cleanly. |

### Summary Conclusion:
The verification engine is currently **not production-grade**. It provides a solid architectural structure (PDAs are verified, policy profile limits are separated, and order of operations is secure), but the underlying detection engines (Risk, Confidence, and Simulation) are **vulnerable prototypes/toys** that are highly susceptible to malicious exploitation and bypass.
