# Graphite — Clean-Room Forensic Revalidation (C26)

**Date:** 2026-08-09
**Method:** Clean-room. No prior certification, test count, audit report, or "implemented" label accepted as truth. Every conclusion below was reached by reading the code, then **disproving or confirming it empirically** — with runnable experiments and full-suite regression after every fix.
**Result:** **One previously-undetected architectural gap confirmed and its covering test repaired; two false-confidence claims corrected; one misleading metric layer fixed. No AI-layer-scale hidden incompleteness found in the Rust core.**

---

## Part 1 — Orca Whirlpools cross-validation (the follow-up)

**Goal:** Close the C25 gap — the census observed only 11 of the 66 manifest discriminators live; verify the remaining ones against a primary source.

**Method & evidence:**
1. **Anchor-convention cross-check** — every one of the 66 manifest discriminators was recomputed as `sha256("global:" + snake_case_name)[0..8]` against the IDL. 66/66 consistent. The IDL itself is internally consistent (each entry's own recomputed discriminator matches the IDL's declared one).
2. **2022-era surface continuity** — fetched the earliest program-source tree (v0.1.1, 2022) and latest 0.1.x (v0.1.19) from the official `orca-so/whirlpools` GitHub history. All 2022-era instruction names are a strict subset of the current 66; the 6 fabricated C23-era names (`updateFeeRate`, `transferPositionDelegate`, `applyDelta`, `syncTickArray`, `closeAccount`, `closeConfigExtension`) appear in **no** program-source tree at any tag.
3. **On-chain dispatch test (decisive)** — simulated a transaction per discriminator against the deployed mainnet binary (programdata fetched via the ELF-loader stub; `sigVerify:false`, real fee-payer). All 66 discriminators dispatch to their named handler (verified via program logs); a garbage discriminator returns `InstructionFallbackNotFound`. The 6 without explicit logs failed *after* dispatch with Anchor account-validation errors (3006/3007/3010) — the opposite of fallback. The `idl_include` entry — initially suspected as a non-dispatchable Anchor artifact — is a real handler on the deployed binary.

**Verdict:** The C25 Orca manifest is 66/66 verified against the live program. The instruction surface claim is now primary-source-proven, not census-inferred. The census's 11/66 was a coverage artifact, not a surface gap.

---

## Part 2 — Clean-room revalidation of the whole repository

### Scope actually covered

Every Rust source file in `graphite-core/src` (25 files) was read; every TS/Go SDK surface, the SAK bridge + AuditBind, the Python AI layer, the dashboard, the CLI, the server, all bundled manifests, and the regression/registry/plugin/PDA/simulation modules were read or traced. Findings were then **probed empirically** (see §F for the experiment table).

### A. Newly Discovered Blockers

**A1 — Manifest-spoofing defense existed but its only test was vacuous (fixed).**
- *What we believed:* H6 "MANIFEST SPOOFING" (hell_mode_tests) proved "Manifest injection must NOT make SetAuthority appear safe — risk engine must still block it."
- *What was actually true:* The H6 manifest used the **old string-array account schema** (`"accounts": ["source", "destination"]`), so `load_manifest` failed to parse and the injected manifest **never entered the registry**. The test then verified disc `06` against the *bundled* SPL Token manifest, where the `transfer` intent mismatched `SetAuthority` (L5) — the block came from the intent mismatch, not from any spoofing defense. The test passed while testing none of its claim.
- *Why we missed it:* the test asserted only `!result.approved`, and the mechanism (schema rejection → unknown-protocol-adjacent path) produced the same boolean.
- *Root cause:* test wrote to an outdated schema and asserted an outcome without asserting the mechanism.
- *Fix:* Rewrote H6 with a **schema-valid** malicious manifest (proper account objects, self-asserted `OfficialManifest`, disc `06` renamed "SafeTransfer", `variable_accounts: true`), asserting `load_manifest` succeeds and the block comes from the **risk engine** (`risk_verdict.status == "Blocked"`, finding `AuthorityHijack`). Verified: the risk engine's P0 Check 2 (RISKY_PATTERNS) blocks the known discriminator regardless of the spoof.
- *Regression protection:* H6 now fails if the manifest doesn't load, if the risk engine stops firing on `06`, or if the P7 tier cap is violated. Added H6b pinning the residual boundary explicitly.

**A2 — Benchmark claimed SetAuthority coverage it did not have (fixed).**
- Both benchmark cases labeled "SetAuthority hijack" used discriminator `0b` — which is **ThawAccount**, not SetAuthority (`0x06`). They were blocked by the L5 transfer-intent mismatch against the bundled SPL Token manifest, and the suite therefore never exercised SetAuthority-hijack detection (the risk engine's `06` pattern) end-to-end.
- *Fix:* corrected both cases to the real `06` discriminator. The seeded-corpus replay still passes (`benchmark_seeded_corpus_replays_clean_and_promotes`), and the labels now match the instructions under test.

**A3 — Fabricated transaction metrics in the output/audit layer (fixed).**
- `BuiltTransaction.instruction_count` was `1 + expected_state_changes.len() + allowed_cpis.len()` — a made-up number that grew with manifest metadata, displayed in API results, SDKs, dashboard, and event logs as if it were the transaction's real instruction count.
- `compute_budget_units` was an undocumented synthetic estimate; `data_hex` was labeled "canonical serialization for audit trail" while excluding the discriminator (the canonical audit identity is the `content_hash`, not this field).
- *Fix:* `instruction_count` is now `1` (the plan verifies exactly one instruction) with an explanatory comment; the budget estimate and the data-hex projection are documented as what they are. No test pinned the old values (verified by search), so this is a pure honesty correction.

**A4 — Registry review gate certifies evidence, not the reviewed surface (documented, not changed).**
- The review gate (`ManifestRegistryEngine::submit`) validates the submitted manifest, derives the tier from evidence (never self-asserted — correct), and appends a **flattened Behavior** (state-change strings + allowed-CPIs + evidence) to the semantic graph. The accepted manifest's **instruction surface never enters the runtime verification registry** — L2 stays `Inconclusive` for registry-tiered programs.
- *Empirical consequence:* a registry-accepted program gets an earned tier (e.g. `CommunityVerified`) but verification of any instruction on it never checks the reviewed instruction surface. Confirmed not exploitable for approval-minting today: a graph-tiered program with no manifest scores only ~0.33 confidence (EXP4), below every profile threshold that would matter. The risk is a *future* one — if the graph tier ever feeds a higher ceiling for manifest-less programs, the reviewed surface still wouldn't constrain what gets approved.
- *Recommendation (not implemented — requires a design decision):* persist accepted manifests into the runtime registry (or a per-program reviewed-surface file) so L2/L5 run against the reviewed surface, not just the flattened strings.

### B/C/D. Phase Revalidation

| Phase | Verdict | Evidence |
|---|---|---|
| Phase 1 (core pipeline) | **VERIFIED** | 8-layer pipeline deterministic and fail-closed; L1–L8 all read in full; content-hash cross-language pinned (`afb61d8865b4cb68` in Rust + TS AuditBind); request-body evidence zeroed (G4) and tiers capped (P7) — verified by reading the confidence path and by `test_caller_evidence_cannot_raise_tier_above_manifest_declared`. |
| Phase 1.5 (server/SAK/hardening) | **VERIFIED** | Server GET-only for manifests (no runtime manifest injection reachable from the network — checked every route); API-key auth, rate limiting, CORS defaults; AuditBind binds transfer amount (C22) and swap payload; `GRAPHITE_SWAP_STRICT` documented. Baseline trust model sound: baselines are operator-seeded/RPC-earned only, and record-after-check prevents poisoning. |
| Phase 2 (protocols/registry/plugins/PDA/regression) | **PARTIAL** | Registry review gate real (ed25519 signer, attestations, P10 replay gate by the engine itself); plugin gate P8 real; PDA known-answer tests against official implementations; regression engine append-only with dedupe + fail-closed corruption handling. **Partial because:** the accepted manifest surface is not wired into runtime verification (A4); runtime-loaded manifests self-assert tiers up to the P7 cap with no provenance marker (A5 below). |

### E. Engineering-Skill Alignment

The repo's Engineering Skill (Constitution P1–P16) is *mostly* honored by the code — this is the striking difference from the AI-layer discovery: the code repeatedly documents the honest boundary (e.g. "L8 inconclusive", "request-body evidence is attacker-controlled", "baselines are trusted server state", "simulation is evidence, never ground truth"). Misalignments found:

- **P3 explainability** — L4's "State verification passed: N state change(s) consistent with N account(s)" reads as stronger than it is: it checks *structural* consistency (writable/signer/close keywords vs account roles) against manifest-declared strings. For bundled reviewed manifests that is meaningful; for runtime-loaded (fabricatable) manifests the attacker authors both the strings and the accounts, so L4 passes trivially. The layer's phrasing overstates what it verifies.
- **P7 tier provenance** — a runtime-loaded manifest self-declaring `OfficialManifest` surfaces as `tier=OfficialManifest` in the audit trail, indistinguishable from a bundled/reviewed manifest. The P7 cap prevents tiers above OfficialManifest but does not mark *provenance*.
- **P16 reproducibility** — the benchmark is explicitly, honestly synthetic (a test pins this), and real-data validation lives in `live_corpus`'s pinned mainnet fixtures + `regression seed-live`. This separation is a strength, not a finding.

### F. False-Confidence Findings (mandatory section)

| # | Claim | Reality | Detection | Status |
|---|---|---|---|---|
| F1 | H6 test proves manifest-spoofing defense | Test never loaded its own malicious manifest (schema-invalid); blocked by L5 intent mismatch, not risk | EXP3 reproduced the exact H6 flow; EXP1/EXP2 with schema-valid spoofs showed the real behavior | **Fixed** (H6 rewritten + H6b) |
| F2 | Benchmark covers SetAuthority hijack | Both cases used `0b` = ThawAccount; blocked by intent mismatch | EXP5 reproduced the benchmark case: `instruction=ThawAccount`, blocked by L5 | **Fixed** (`0b`→`06`) |
| F3 | `instruction_count` is a real transaction metric | `1 + state_changes + allowed_cpis` — fabricated | Direct read of `transaction_builder.rs` | **Fixed** |
| F4 | Registry acceptance = reviewed surface verified at runtime | Only flattened strings + tier reach verification; L2 Inconclusive | Read of `submit` + EXP4 (0.33 confidence, L2 Inconclusive) | Documented (A4) |
| F5 | Runtime manifest "OfficialManifest" = official | Self-asserted up to the P7 cap; no provenance marker | EXP1/EXP2: `tier=OfficialManifest` on fabricated manifests | Documented (A5) |
| F6 | "State verification passed" = state changes verified | Structural keyword-consistency against manifest-declared strings | Read of `verify_state` | Documented |

**Where the same class of failure was searched and NOT found (evidence the pattern is contained):**
- Deletion/mutation probes on the gates that matter: the risk engine's known-pattern check has direct unit coverage (`test_authority_hijack_detected_via_known_pattern`, `test_system_assign_detected_as_authority_hijack`); the L5 semantic check is pinned by the benchmark corpus replay (removing it flips the `0b`→`06` fixture → `benchmark_seeded_corpus_replays_clean_and_promotes` fails); the P10 promotion gate is fail-closed on an empty corpus; the audit log's L3/L8 honesty is pinned (`audit_record_serializes_l3_and_l8_status`).
- The Python AI layer (the original discovery) was re-checked: it is advisory-only, deterministic, and structurally cannot weaken a decision (advisory labeler with manifest-grounded hints).
- No dead-code "capability exists but isn't wired" cases found in the runtime verification path other than A4 — every layer's output is consumed downstream or honestly reported as Inconclusive.

### G. Security Findings (AI Agent → Graphite → Wallet boundary)

1. **No network-reachable manifest injection.** The server exposes only GET routes for manifests; SDKs/CLI/bridge never call `load_manifest`. The fabricated-manifest vector requires embedder-side code execution (in-process API), where the manifest is the embedder's own trust root. Severity: low in the shipped topology; the H6 rewrite (F1) removes the false confidence that a defense existed where it didn't.
2. **Known risky instructions cannot be whitewashed by a spoofed manifest** (verified): `06` (SetAuthority), `09` (CloseAccount), `04` (Approve) on Token/Token-2022 and `01000000` (Assign) on System are blocked by P0 Check 2 regardless of manifest content. This is the actual, now-tested defense boundary.
3. **Non-covered instructions on fabricated manifests follow the manifest** (H6b, pinned): the manifest is the trust root for programs outside the risky-pattern list. An embedder loading a manifest vouches for it; the audit trail records the self-declared tier. Documented as the residual boundary.
4. **CPI drain via fabricated manifest is closed**: an unknown program CPI-ing to a token program is blocked fail-closed (untrusted-root check); the manifest's `allowed_cpis` list does not extend the trust boundary (deliberate: "an allowlist is an authorization decision, not evidence").
5. **Simulation path cannot be gamed from the request body**: baselines are operator-seeded/RPC-earned; partial RPC results record nothing (anti-poisoning); flagged observations never enter the accumulator (record-after-check).

### H. Test Reliability

The suite is **largely capable** of detecting architectural incompleteness — it is not a happy-path suite: 35 pinned real exploit transactions, real mainnet fixtures, hostile-shape parsers, fail-closed corruption tests, cross-language content-hash pins, and determinism tests exist. **The specific blind spot this revalidation exposed**: tests that assert a *defense* but pass via an *unrelated mechanism* (H6 via schema rejection, benchmark SetAuthority via L5 mismatch). The fix pattern — assert the mechanism (blocking layer + finding) as well as the outcome — is the durable lesson. F1/F2 are the concrete examples; the rest of the adversarial suite was audited for the same pattern and no other instance was found (each remaining H-test asserts a mechanism: H7 asserts `RiskVerdict::Passed` with explanation, H21 asserts fail-closed on zero thresholds, etc.).

### I. Remaining Unknowns

1. **On-chain census depth** — only 11/66 Orca discriminators observed live; the other 55 are IDL/dispatch-verified, not execution-witnessed. A deeper census (or the 2022-era binary cross-check) would close the last observational gap.
2. **The registry → runtime wiring (A4)** — whether the review gate should feed the verified instruction surface into runtime verification is a design decision, not a code fix; until decided, L2 Inconclusive for registry-tiered programs is the (honest) behavior.
3. **Embedder manifest provenance (A5)** — whether the audit trail should carry a "self-declared vs bundled vs reviewed" provenance marker for `trust_tier` is a schema/UX decision (SDK + dashboard + audit-record shape all change).
4. **Live L3/L8** — L3 (simulation) and L8 (post-submission) remain `Inconclusive` without `GRAPHITE_RPC_URL` and Phase-2 wiring respectively; this is documented, not hidden.

---

## Changes made this round

| File | Change |
|---|---|
| `graphite-core/tests/hell_mode_tests.rs` | H6 rewritten with schema-valid malicious manifest + mechanism assertions; H6b added pinning the non-covered boundary |
| `graphite-core/src/benchmark.rs` | Both "SetAuthority" cases corrected `0b`→`06` (real discriminator) |
| `graphite-core/src/transaction_builder.rs` | `instruction_count` = 1 (was fabricated formula); budget estimate + data-hex projection documented honestly |

**Verification:** full suite green (all 24 test binaries, 0 failures), `cargo fmt --check` clean, `cargo clippy --all-targets` clean.

**Bottom line:** Graphite's Rust core is *not* another AI-layer-scale hidden incompleteness. The revalidation found one real but low-severity gap (vacuous spoofing test, fixed with real coverage), two misleading claims (benchmark + metric layer, corrected), and two documented design boundaries (registry surface wiring, tier provenance). The strongest evidence of health is negative: every component that *could* have been fake — simulation integrity, P10 regression gate, P8 plugin gate, PDA derivation, audit durability, server hardening — was read and probed, and each holds up under the "what if it's fake" question.
