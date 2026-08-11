# Changelog

All notable changes to Graphite Core are documented here.
Layer names follow `graphite-engineering-skill/ARCHITECTURE.md` section 3.12 as the canonical source.

## [Current State — C47: 984 tests, 22 manifests, 561 instructions, 14 risk checks] — 2026-08-11

### Summary of all changes C28–C45

- **C28**: MAD (median absolute deviation) baseline for simulation integrity — replaces mean/stddev with robust statistics resistant to poisoning. Simulation z-score now uses MAD-based outlier detection.
- **C29**: Multi-instruction transaction analysis + CPI instruction trace analysis — 2 new RiskPattern variants (MultiInstructionDrain, CpiTraceAnomaly). Coordinated mass-drain detection across instructions in one tx (approve-then-transfer, authority-hijack-then-drain, close-and-sweep, mass multi-transfer sweep). Hierarchical CPI tree analysis for unknown, re-entered, or vanity-impersonated programs.
- **C30**: Real mainnet exploit data pinned in benchmark — 3 REAL mainnet exploit cases (STMT drainer 64tsGGe, AAT drainer 524t8LW, Wormhole $320M hack 5fKWY7X) replace 3 of 5 SYNTHETIC reconstructions. 2 SYNTHETIC remain, honestly labeled. Avg latency ~2.1ms (up from sub-ms, due to real-data cases).
- **C33**: Risk-engine discriminator-width bypass fix (CVE-class) — prefix-matching allowed short discriminators to match longer ones, bypassing detection. Now exact-match only.
- **C36**: P1 remediation — CPI flattening, instruction ordering, hidden-transfer semantics, swap classification.
- **C37**: CatchPanicLayer added to production router; formal discriminator-length decision (exact match, no prefix).
- **C38**: Phase 2 gates — real L8 execution verification (reports Confirmed/Unknown/Unavailable from mainnet RPC) + manifest-declared risk-class engine expansion.
- **C39**: Certification revalidation — fresh adversarial pass + malformed-discriminator fail-closed.
- **C40**: Live mainnet/devnet validation — L3 simulateTransaction on real devnet RPC; L8 execution verification on real mainnet RPC (Confirmed/UnknownSignature/Unavailable, honestly reported).
- **C41**: 2,181-fixture regression corpus — dev ~2,112 + regression 31 + holdout 38 (35 real SolPhishHunter mainnet exploit signatures from arXiv:2505.04094 + 3 real mainnet txs). 0 false negatives on holdout. Root fixes surfaced by the corpus.
- **C42**: Kamino V2 real layouts from live on-chain decoded streams; registry determinism fix; universal-CPI audit test.
- **C43**: Phase 2 certification report + ROADMAP sync.
- **C44**: Encoding-explicit manifest reads in Python test (Windows-locale fix — `encoding="utf-8"` on all `open()` calls).
- **C45**: Solana Foundation grant proposal ($120k, 3 milestones over 9 months).

### Current numbers (C45)
- **984 Rust tests**, 0 failures, 0 clippy warnings, fmt clean
- **22 protocol manifests**, 561 instructions, all program IDs verified executable on mainnet
- **11 risk patterns / 14 risk checks** (was 9/9)
- **2,181-fixture corpus**: 0 false negatives on 38-fixture holdout
- **3 REAL mainnet exploits** scored in benchmark (Wormhole $320M, CLINKSINK STMT, SlowMist AAT)
- **L3 live-validated** on devnet RPC; **L8 live-validated** on mainnet RPC
- **SAK integration verified** on devnet (5 finalized transactions)
- **Go SDK**: 10 tests, 16-field parity; **Python AI layer**: 27 tests; **TS SDK**: compiles clean

Layer names follow `graphite-engineering-skill/ARCHITECTURE.md` section 3.12 as the canonical source.

## [Round Six — C27: Drift + Kamino Lending on-boarded from official IDLs with live-verified discriminators and source-scoped PDA grounding] — 2026-08-09

### Two new BattleTested manifests: Drift Perpetuals (249 ix) + Kamino Lending (51 ix)
- **Official IDL ground truth**: Drift built from velocity-exchange/protocol-v2 `sdk/src/idl/drift.json` (program `dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH` — the SDK's DRIFT_PROGRAM_ID; the repo is the moved drift-labs/protocol-v2), Kamino from Kamino-Finance/klend-sdk `src/idl/klend.json` (program `KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD` — codegen PROGRAM_ID). Both confirmed executable on mainnet via getAccountInfo. IDLs committed as `scripts/drift_idl.json` / `scripts/klend_idl.json`; `scripts/rebuild_drift_kamino_manifest.py` regenerates both manifests.
- **Discriminators derived + verified LIVE**: neither IDL embeds discriminator bytes, so all 300 are derived as `sha256("global:"+snake_case)[0..8]` and then proven on the deployed binaries by on-chain census (`scripts/census_drift_kamino.py`, base58-correct decode): 14/300 observed on mainnet — Drift placePerpOrder ×128, cancelOrdersByIds ×41, placeOrders ×41; Kamino flashBorrow ×136, flashRepay ×136, refreshReserve ×19, refreshReservesBatch ×13, refreshObligation ×8, depositReserveLiquidityAndObligationCollateralV2 ×5, borrowObligationLiquidityV2 ×3, redeemReserveCollateral ×3, depositReserveLiquidity ×2, initUserMetadata ×1, initObligation ×1 — all matched the derived values, zero unmatched. Kamino's deployed `InitObligationArgs` carries only tag+id (no seed1/seed2), matching the observed 10-byte instruction data.
- **PDA grounding scoped to what the deployed program actually seed-constrains (C26 principle)**: `scripts/verify_dk_pdas.py` re-derives every grounded PDA from real txs (manifest-driven acceptance test) — all 5 live-observable grounds MATCH (Drift n/a in recent surface; Kamino lma in deposit/flashBorrow/flashRepay, obligation in initObligation, userMetadata in initUserMetadata). Notably: Kamino runtime ixs (deposit/borrow/flashBorrow/etc.) constrain vaults by `address = reserve.state.vault`, NOT by PDA — grounding them as `[const, reserve]` would false-flag legitimate txs, so vaults are grounded ONLY in initReserve. Drift user_stats is PDA-derived ONLY in initializeUserStats (elsewhere the program uses `has_one`/`is_stats_for_user` consistency checks), and spot_market_vault is grounded in deposit/withdraw/transferDeposit where the program seed-constrains it.
- **variable_accounts**: Kamino refreshReservesBatch reads (reserve, market) pairs from `remaining_accounts` (deployed handler) — marked variable so drainer heuristics don't false-flag legitimate batch refreshes.
- **Regression protection**: C27 test module pins the full 300-instruction surface against the snake_case convention (C18 bug class), 9 chain-observed discriminators, the exact PDA-grounding scope per instruction, and an end-to-end initObligation obligation-PDA derivation (correct key passes, spoofed key flagged as PDA mismatch). Verified program IDs added to `protocols/verified_program_ids.json` (bidirectional pin test: 22 programs). Manifest count assertions updated (Rust + Python AI layer).
- Validation: full Rust suite green (869 tests, 0 failures), Python AI-layer green (22 manifests), AuditBind 9/9, TS typecheck clean, fmt + clippy clean.

## [Round-Five Clean-Room Revalidation — C26: Orca 66/66 On-Chain Proof + Manifest-Spoofing Defense Repair] — 2026-08-09

### Orca Whirlpools: all 66 discriminators verified against the DEPLOYED program, not just the census (C26.1)
- **On-chain dispatch proof**: every one of the 66 manifest discriminators was simulated against the live mainnet binary (programdata fetched via the ELF-loader stub, `sigVerify:false`, real fee-payer) — each dispatches to its named handler; a garbage discriminator returns `InstructionFallbackNotFound`. The 6 entries without explicit handler logs failed AFTER dispatch with Anchor account-validation errors (3006/3007/3010). The `idl_include` entry (suspected as a non-dispatchable Anchor artifact) is a real handler on the deployed binary.
- **Anchor-convention cross-check**: all 66 discriminators re-derive as `sha256("global:"+snake_case)[0..8]`; the IDL is internally consistent.
- **2022-era continuity**: earliest program-source tree (v0.1.1) through latest 0.1.x (v0.1.19) — all 2022-era instruction names are a strict subset of the current 66; the 6 fabricated C23-era names appear in NO program-source tree at any tag.
- Full report: `docs/clean-room-revalidation-C26.md`.

### Manifest-spoofing defense: the H6 test was vacuous and is repaired (C26.2)
- H6's malicious manifest used the OLD string-array account schema, so `load_manifest` rejected it and the injected manifest NEVER entered the registry — the test passed because the transfer intent mismatched SetAuthority (L5) against the bundled manifest, not because any spoofing defense fired.
- H6 rewritten with a schema-valid malicious manifest (self-asserted `OfficialManifest`, real SetAuthority discriminator `06` renamed "SafeTransfer"): it now asserts the manifest loads AND the risk engine's P0 Check 2 blocks with an `AuthorityHijack` finding. H6b pins the residual boundary: non-pattern-covered discriminators on fabricated manifests follow the manifest (the risky-pattern list is the defense).
- Benchmark correction: both "SetAuthority hijack" cases used discriminator `0b` (ThawAccount, blocked by L5 intent mismatch) — corrected to the real `06` so the suite actually exercises SetAuthority-hijack detection.
- Audit honesty: `BuiltTransaction.instruction_count` was a fabricated `1 + state_changes + allowed_cpis`; now `1` (the plan verifies exactly one instruction). The compute-budget estimate and data-hex projection are documented as what they are.
- Validation: full suite green (all 24 test binaries, 0 failures), clippy clean, fmt clean.

## [Round-Four Independent Audit — C25: Orca Full-Surface Rebuild + Fabricated-Instruction Removal] — 2026-08-09

### Orca Whirlpools: 6 FABRICATED instructions removed; manifest rebuilt to the full deployed surface (C25.1/C25.2)
- **6 of 24 manifest entries were fabricated** — `updateFeeRate`, `transferPositionDelegate`, `applyDelta`, `syncTickArray`, `closeAccount`, `closeConfigExtension` appear in NEITHER the 2022-era deployed IDL (v0.1.0, 25 instructions) NOR the current deployed IDL (66 instructions), and the orca-so/whirlpools git history has zero occurrences. The C24 note's claim that these were "corrected to the snake_case convention" was itself built on the false premise that they existed; this round supersedes it.
- The manifest previously covered only 24 of the 66 deployed instructions — every legitimate Orca txn using any other instruction fell to unknown-protocol mode (0.55 confidence ceiling). The manifest now covers the FULL deployed surface: all 66 discriminators are the explicit byte arrays from the official deployed-program IDL (npm `@orca-so/whirlpools`, program v0.9.0; the repo's Anchor.toml maps `whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc` to this source), NOT re-derived hashes. The IDL is committed as `scripts/whirlpool_idl.json` for reproducibility; `scripts/rebuild_orca_manifest.py` regenerates the manifest.
- **3 discriminators corroborated by live on-chain census** (base58-correct decode, 528 Orca txs): `swap = f8c69e91e17587c8` (×153), `swap_v2 = 2b04ed0b1ac91e62` (×342), `increase_liquidity_by_token_amounts_v2 = effb097cd2c6352b` (×7 — an instruction that exists only in the current IDL, proving the IDL is the deployment's instruction set). Census script: `scripts/census_orca.py` (progress cache gitignored).
- Regression: `orca_discriminators_pin_onchain_verified_values` now asserts the manifest covers all 66 instructions, pins the 3 live-observed values, and asserts all 6 fabricated names are ABSENT from the table.

### Instruction-surface total updated
- 219 → **261 instructions** across 20 manifests (Orca 24 → 66); manifest version bumped 1.0.0 → 2.0.0 with `previous_version_ref`.
- Validation: **864 Rust tests / 0 failed**, clippy `-D warnings` clean, fmt clean.

## [Round-Two Sub-Agent Verification — C23: Manifest Discriminator Ground Truth] — 2026-08-09

### Jupiter V6: 16 legacy camelCase hashes corrected to the deployed program's snake_case convention (C23.1)
- `route` (`e517cb977ae3ad2a`) and `route_v2` (`bb64facc31c4af14`) are CONFIRMED on-chain (C19/C21 claim stood; an early base64-vs-base58 decode artifact was caught and reverted before any claim was made).
- 16 old-era entries (`sharedAccountsRoute`, `setTokenLedger`, `routeWithTokenLedger`, all account-compression/check variants) carried `sha256("global:"+camelCase)` hashes that never match the deployed program — the C18 bug class. Corrected to snake_case; `sharedAccountsRoute=c1209b3341d69c81`, `setTokenLedger=e455b9704e4f4d02`, `routeWithTokenLedger=96564774a75d0e68` verified on-chain, the rest follow the program's confirmed convention.
- Manifest `note` documents the correction methodology and the internal `e445a52e51cb9a1d` route (1-account CPI under `shared_accounts_route_v2`) as non-top-level provenance.
- Regression: `jupiter_discriminators_pin_onchain_verified_values` pins verified values AND asserts the old camelCase hashes must NOT resolve; `jupiter_pinned_fixture_discriminator_resolves_in_manifest` asserts the pinned fixture carries `bb64facc31c4af14` under base58 decode.

### Jupiter DCA: corrupted discriminator table replaced + live fill path declared (C23.2)
- The previous 7-value table was never observed on-chain (stale/contaminated values; `verification.notes` falsely claimed live observation). On-chain census with base58-correct decode shows the deployed program is STANDARD ANCHOR: `initiate_flash_fill=8fcd03bfa2d7f531`, `fulfill_flash_fill=7340e24e21d369a2`, `transfer=a334c8e78c0345ba` observed live; remaining instructions follow `sha256("global:"+snake_case)[:8]`.
- The 3 fill-path instructions were MISSING entirely — the dominant real DCA traffic (keeper fills) was falling to unknown-protocol mode (0.55 ceiling). Added with accounts, expected state changes, and risk rules (flash-loan repayment must match borrow; diverted swap output = compositional drain; transfer recipient must be the owner's ATA).
- All 7 stale discriminators updated to confirmed values; `verification.notes` corrected; `probe_dca_pda.py` and tests referencing the stale `131cb5dbd74f7e19` updated to `16072162a8b722f3`.
- Regression: `jupiter_dca_discriminators_pin_onchain_verified_values` pins all 10 values, asserts the 7 stale values must NOT resolve, and verifies the fill path resolves as known protocol.

### Docs-vs-reality synced
- README/ARCHITECTURE/ROADMAP/release-evaluation/phase2-plan/branch-strategy/gap-audit updated: 861 tests (was 844), 20 manifests (was 15), 219 instructions (was 216), 9 risk patterns (was 8).

## [Round-Three Independent Audit — C24: Orca + Metaplex Discriminator Ground Truth] — 2026-08-09

### Orca Whirlpools: 23 camelCase hashes corrected to the deployed program's snake_case convention (C24.1)
- Only `swap` was correct. On-chain census with base58-correct decode observed `swap_v2 = 2b04ed0b1ac91e62` (×17) and `swap = f8c69e91e17587c8` (×4) — both equal `sha256("global:" + snake_case)[:8]`, proving the deployed program is standard Anchor.
- All 23 camelCase-hashed entries (`increaseLiquidity`, `initializePool`, `collectFees`, `openPosition`, …) corrected to snake_case; provenance note added to the manifest.
- Regression: `orca_discriminators_pin_onchain_verified_values` pins `swap`/`swapV2` (directly observed), pins the convention for 3 more, asserts the stale camelCase values are absent from the table, and proves a verified swap passes the pipeline as Clear.

### Metaplex Token Metadata: Shank u8 discriminators replace fabricated 8-byte values (C24.2)
- The deployed program (metaqbxx…) is Shank-derived, NOT Anchor. On-chain census observed instruction data starting `0x21` (=33, CreateMetadataAccountV3) and `0x0f` (=15, UpdateMetadataAccountV2). Per the enum order in mpl-token-metadata program/src/instruction/mod.rs: SignMetadata=07, VerifyCollection=12, BurnNft=1d.
- The old 8-byte values (0fd902b83e0f4ee4, …) were never observed on-chain — the previous verification note claiming live observation was fabricated (same artifact class as C22.4/DCA).
- Manifest rewritten to u8 discriminators; `verification.notes` corrected; `metaplex_discriminators.txt` regenerated with the full Shank enum order; `test_metaplex_token_metadata_manifest_has_create` and the pipeline test updated.
- Regression: `metaplex_discriminators_are_shank_u8_values` pins all 5 values, asserts fabricated values are absent, and proves real u8-prefixed data resolves via the registry's prefix match.

### Systemic guard: the C18 camelCase disease can no longer re-enter any manifest (C24.3)
- New `no_manifest_discriminator_is_a_camelcase_anchor_hash` scans every loaded manifest and fails on any camelCase-named instruction storing `sha256("global:" + camelCaseName)` — the bug class that recurred in Squads (C18), Jupiter V6 (C22.3), DCA (C22.4), and Orca (C24.1) is now structurally impossible.

## [Clean-Room Revalidation — C22: Live-Corpus Selection + Transfer TOCTOU Binding] — 2026-08-09

### Live-corpus selection records the protocol call, not the fee payment (C22.1)
- `live_corpus::tx_to_input` prefer-selection was first-match over the prefer-set. The production `seed-live` path passes EVERY manifest program ID (including System and ComputeBudget), so first-match degenerated to the System fee payment (2–3 accounts) that real blocks front-load — the corpus recorded fee payments instead of protocol interactions.
- Selection now ranks prefer-matching instructions by **account count** AND **excludes infrastructure programs** (System, ComputeBudget, ATA, Memo×3) from prefer-matching: set membership alone cannot mean "the interesting program" when the set contains the boilerplate. The actual invocation wins (Jupiter route: 40 accounts), or the max-accounts fallback for CPI-only protocols (pump.fun: 20-account router). Deterministic (ties → last maximal).
- **ALT placeholders fixed:** ALT-resolved account positions (`alt:{table}:{entry}`) are not valid base58 and silently failed verification, dropping transactions from the corpus. They are now skipped; an instruction whose accounts are ALL ALT-resolved yields no input (fail-closed).
- Regression protection: `full_pipeline_over_real_mainnet_transactions` now pins the selected program per pinned fixture (pump → router, jup → Jupiter, system → AMM) under the PRODUCTION prefer-set; new `production_prefer_set_never_selects_fee_payment` and `alt_placeholder_accounts_are_skipped_not_recorded`.

### Transfer-path AuditBind binds the amount (C22.2)
- `executeTransfer` (SAK bridge) verified and AuditBind-bound only `programId + discriminator + accounts` — the transfer amount (u64 LE lamports in the instruction data) was UNBOUND, so mutating the amount between verification and execution passed the TOCTOU check.
- Fix is two-sided by contract (Rust `content_hash` includes `instruction_data` only when present): the bridge now sends `instructionData` to verification AND to the AuditBind projection (4-byte `02000000` discriminator shape). Amount mutation now changes the hash and ABORTS.
- Regression protection: pinned TS test `C22 transfer binding: amount is bound via instructionData` (1 SOL vs 100 SOL differ; old no-data projection differs; bound projection verifies).

### Validation
- **858 Rust tests / 0 failed** (+2), clippy `-D warnings`, fmt clean, no-default-features + cli + rpc gates green, 27/27 Python, **9/9 AuditBind** (+1), TS SDK + SAK typecheck clean, dashboard builds.

## [Final Forensic Re-run — C21: Advisory Labeler v2 + Intent-Vocabulary Alignment] — 2026-08-08

### Advisory labeler expanded without an LLM (C21.2)
- `python-ai-layer/intent_parser.py` v2: emits the FULL Core semantic vocabulary (`swap|trade|exchange`, `transfer|send`, `stake|delegate`, `close|close_account`, `create|create_account`, `approve|revoke`) instead of 4 hardcoded classes. `mint`/`bridge`/`lend` are detected and surfaced as advisory warnings but labeled `unknown` (fail-closed) because the Core has no semantic class for them.
- `suggested_program_id`/`suggested_discriminator`/`protocol_candidates` are now **derived from the verified manifest registry** at load time (embedded fallback for standalone deployments) — swap → Jupiter `route_v2` `bb64facc31c4af14` (deployed entrypoint), transfer → System `02000000`, stake → `DelegateStake`, close → SPL Token `09`, create → ATA `00`, approve → `04`, revoke → `05`.
- Risk-hint warnings (advisory): impersonation-vanity destinations (`…11111`, `Compu…` — validated against the real exploit corpus), authority changes, approve-delegate escalation, close rent recovery, unknown token symbols, large amounts.
- Per-signal confidence (`confidence_components`: phrase/parameters/token/protocol) replaces the hardcoded 0.9. Deterministic, pure stdlib, no network — **~47k parses/sec, p50 ~21 µs** (50k-parse benchmark). 27 Python tests (was 8).

### Root-level risk-engine contradiction fixed (C21.1)
- `program_supports_intent` (P0 Check 9) returned `false` for `create`/`approve`/`revoke` — the L5 semantic layer's own vocabulary — so every legitimate create/approve/revoke transaction was blocked as `PermissionEscalation` even when the instruction matched the intent, contradicting Check 6b/7. Expanded to the full L5 vocabulary with correct program sets (create → System/ATA/Token/Token-2022/Metaplex/Pump.fun; approve/revoke → Token/Token-2022; aliases trade/exchange/send/delegate/close_account). Unknown intents remain fail-closed. 4 regression tests (`protocol_expansion_tests.rs`).

### Integration-surface fixes
- **Bridge default discriminator corrected (C21.3):** `executeSwap` defaulted to the LEGACY `route` (`e517cb97…`); live txs carry `route_v2` (`bb64facc…`) — default now `bb64facc31c4af14`.
- **TS SDK `IntentType` aligned (C21.4):** removed `lend` (no Core semantic class — would fail closed), added close/create/approve/revoke + aliases to match L5.

### Validation
- **856 Rust tests / 0 failed** (was 852), clippy `-D warnings`, fmt clean, no-default-features + cli gates green, 27/27 Python, 8/8 AuditBind, TS SDK + SAK typecheck clean.
- Live-server probes: create/revoke intents now pass the risk engine (Clear); approve still hard-blocks by design (risky-pattern PermissionEscalation); 2 MB body → 413; malformed Content-Length → 413; trailing-JSON → 422.
- On-chain: all manifest IDs involved (Jupiter V6, System, SPL Token, ATA, Stake) re-verified executable on mainnet.

## [P16 Real-Mainnet Benchmark — C19: Real Exploit Corpus + Two Real Defects Fixed] — 2026-08-08

### First P16 run on unseen real data
- **Real pinned exploit corpus (35 entries):** `tests/fixtures/exploit_corpus.json` — transactions pinned by signature from documented phishing accounts (SolPhishHunter arXiv:2505.04094; STMT/AAT/ISA attack classes), reproducible via `integrations/solana-agent-kit/build_exploit_corpus.mts`. `tests/exploit_corpus_tests.rs` enforces: every entry blocked, ISA blocks principled (`Impersonation` pattern).
- **`mainnet-benchmark.ts` rewritten honestly:** per-protocol real intents (DEX → swap; Squads → empty intent, reported honestly), real pinned corpus for the malicious half, JSON report output. Old fake "drainer" section (two invalid addresses rejected by the RPC: fabricated Marinade/Drift IDs) removed.
- **Result (fresh node):** malicious recall **100%** (35/35 blocked, 0 missed); legitimate 0/7 — all root-caused: cold-start confidence ceiling (0.44 < 0.80 TradingBot threshold, P7 earned evidence by design; steady-state approval proven by a seeded regression test) and Raydium CLMM unknown-protocol.

### Two real defects found and fixed
- **64-account input cap rejected legitimate modern transactions (C19.1):** a real 72-account Jupiter V6 route tx was rejected with `Account count mismatch: expected 64, got 72`. Cap raised to Solana's protocol limit (**256**); regression test proves the exact 72-account route verifies and approves with earned evidence.
- **ISA (system-account impersonation) not detected (C19.2):** added **P0 Check 10** — fund movement (System transfer 0x02, Token transfer 0x03 / transferChecked 0x0c) to/from an address impersonating an official system account (vanity `…11111` suffix or `Compu` prefix) is blocked with the new `Impersonation` risk pattern. Grounded in the paper's own detection criteria; corpus test asserts the blocks are principled (risk = Impersonation), not incidental low-confidence rejections.

### Honest cold-start finding (documented, by design)
- On a fresh node, earned-evidence signals (HistoricalVolume, CommunityVerification) are zero (P7), so max confidence for a manifest-matched tx is 0.44 — below every production profile threshold. Not a regression; a live deployment accrues evidence and attaches an RPC client for L3 simulation. Full numbers and reproducibility in `docs/p16-mainnet-benchmark.md`.

## [Independent Gap Audit — C18 Squads Rebuild + Dynamic PDA Grounded] — 2026-08-08

### Squads V4 Manifest Rebuilt from the Official IDL (C18)
- **The Squads manifest was fabricated.** Its discriminators were computed by hashing the camelCase IDL display names (`sha256("global:multisigCreateV2")`); Anchor actually hashes the snake_case Rust fn name (`sha256("global:multisig_create_v2")`). It also carried 18 v1-era instructions (`add_member`, `create_proposal`, `execute_transaction`, …) that do not exist in the deployed program. Only 3 of 21 instructions were real, and 2 had wrong discriminators.
- **Chain evidence:** official `squads_multisig_program` IDL v2.1.0 + live mainnet txs — `vaultTransactionCreate` = `30fa4ea8d0e2dad3` (observed in a live tx; manifest said `ed3256172ab558fc`), `multisigCreateV2` = `32ddc75d28f58be9` (manifest said `8faecbbfaecf93c5`), `proposalCreate` = `dc3c49e01e6c4f9f` and `proposalApprove` = `9025a488bcd82af8` (both observed live, neither in the manifest).
- **Fix:** `squads-v4.json` rebuilt from the IDL — all **36 deployed instructions** with correct discriminators, IDL account lists, honest risk rules (execute/approve/threshold/rent-collector flagged).
- **Dynamic PDA grounded in a real manifest (finally):** `multisigCreateV2`'s multisig account now has `pda_seeds: ["multisig", "multisig", "{account_3}"]` (create_key) — official SDK `pda.ts` layout, IDL-confirmed ("createKey … used as a seed for the Multisig PDA"). New tests: snake_case-hash discriminator guard (bug class cannot recur), 4 chain-verified discriminator constants, and an end-to-end resolver test proving correct derivation + spoofed-multisig flagging. Transaction/vault PDAs need account-state seeds beyond the template engine — documented, not faked.
- **Honest caveat:** a direct chain reproduction of the multisig PDA from a create tx was attempted but not completed (create-tx scans timed out on the public RPC; the multisig whose account data was parsed predates the current struct layout). The layout is grounded in the program's own SDK + IDL; the deployed program version was proven current via the 4 chain-verified discriminators.

## [Independent Gap Audit — C17 Tier-0 Protocol Surface] — 2026-08-08

### Tier-0 Foundational Programs Added (C17)
- **4 new seed manifests** (16 → 20): Associated Token Account (`ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL`), Compute Budget (`ComputeBudget111111111111111111111111111111`), BPF Loader classic (`BPFLoader2111…`), BPF Loader Upgradeable (`BPFLoaderUpgradeab1e…`). All four IDs verified executable on mainnet 2026-08-08 and added to `verified_program_ids.json`, the blessed-canonical-set test, `load_seed_manifests`, and the Python cross-check.
- **Grounded, not self-referential:** `test_tier0_manifest_discriminators_match_real_mainnet_fixtures` parses the pinned real mainnet fixtures and asserts every observed ComputeBudget/ATA instruction byte resolves to a manifest discriminator with an EQUAL value (0x02/0x03/0x04 ComputeBudget and 0x01 ATA observed live). Compute Budget instructions take zero accounts by design (Solana source) — documented, and the pipeline's rejection of a standalone empty plan is asserted as correct behavior.
- **`scripts/live_revalidate.py` retry+backoff** for 429/5xx: a transient public-RPC rate limit is retried (1.5s/3s) instead of being misreported as "program absent". Run result: registry 20/20 EXEC, manifests 20/20 EXEC, SAK Ok, exit 0.
- **Instruction surface total: 216 across 20 manifests** (Squads rebuilt to the full 36-instruction IDL surface by C18).

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
- **self_healing.rs** — Phase 2+ reference implementation, never called.
- **Fake SAK integration** — HTTP wrapper that did NOT import solana-agent-kit.

### Later Re-Integrated
- **regression_engine.rs** — Was initially removed, later re-implemented as an active module (P10 promotion gate, fixture corpus replay, `graphite regression` CLI gate, 12 tests).
- **plugin_orchestrator.rs** — Was initially removed, later re-implemented as an active module (6 plugin traits, panic-isolated execution, 2 real plugins, 56 tests).

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
