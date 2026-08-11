# Graphite — Independent Gap Analysis, Web Research & Production Readiness Audit

**Date:** 2026-08-08 (third audit cycle)

> **Update (2026-08-10, C28–C33):** the "synced" numbers in §Docs-vs-reality are superseded — now 976 tests / 22 manifests / 561 instructions / 13 risk checks; the benchmark is no longer all-synthetic (3 REAL mainnet exploit cases, C30) and the composition test pins 3 REAL + 2 SYNTHETIC; MAD baseline (C28) and multi-instruction + CPI trace analysis (C29) shipped; the risk-engine exact-equality discriminator bypass (C33) is fixed and regression-pinned.
**Method:** clean-slate repo inspection (no prior reports trusted), live Solana RPC probing, web research on the 2022–2026 exploit/ecosystem record, benchmark deconstruction, and first-principles architecture comparison.
**Branch:** `phase2-development` → merged to `main` as `03b15b6` (prior cycle) + this cycle's commit.

---

## Executive Summary

The prior assessment claimed **Phase 1 ~95% / Phase 1.5 ~92% / Phase 2 ~58% / overall ~67%**. Independent verification:

| Phase | Claimed | Verified (pre-fix) | Verified (post-fix) |
|---|---|---|---|
| Phase 1 (core pipeline, confidence, risk, audit, SDKs) | 95% | **88%** | 88% |
| Phase 1.5 (hardening, auth, gates, durability) | 92% | **85%** | 85% |
| Phase 2 (regression, registry, plugins, dashboard, corpus, protocol expansion, PDA) | 58% | **57%** | **63%** |
| **Overall** | 67% | **~72%** | **~74%** |

The overall number is HIGHER than the assessment's 67%, because the assessment under-rated the genuinely solid, live-validated core (837→976 tests, 0 failures, 20/20 on-chain-verified manifest IDs after the C16 memo restoration and C17 Tier-0, durable audit, shared-state concurrency proven). But Phase 2 was *exactly* where the assessment said: **synthetic benchmark, dynamic PDA unused, thin protocol surface, no live deployment** — and this cycle proved two of those were worse than stated:

1. **The ALT gap (P1, fixed):** all three "real mainnet" fixtures are v0 transactions with Address Lookup Tables, and the parser silently DROPPED every ALT-resolved account (26 references in the Jupiter fixture, 8 in the System fixture). Account-level analysis on modern txs was wrong. Fixed with positional ALT expansion + fixture-pinned regression test.
2. **Program-ID architecture (P1, fixed):** program IDs were duplicated across **8+ sources** with no single source of truth — the exact architecture that lets the memo class of bug recur. Fixed with `protocols/verified_program_ids.json` as the single source, checked bidirectionally by both the Rust pin test and the Python AI-layer test. **Follow-up (C16):** this cycle's "fabricated MemoSq4gq…" framing was itself wrong — MemoSq4gq is EXEC on mainnet (99,736 B ELF) and was restored; the registry now carries all three real memo programs and a blessed-set test anchors the canonical core IDs.
3. **Benchmark is 100% synthetic and self-referential (P2, now CI-pinned):** all 18 cases are hand-constructed `VerificationInput`s with manually-encoded labels; the "100% precision/recall" mostly measures whether the rules agree with the cases built from the rules. Now pinned by a composition test; real-data validation is explicitly the live/fixture path.
4. **Deployment (P2, partially closed):** a good Dockerfile exists but no reproducible compose/env contract; added `docker-compose.yml` + `.env.example` (fail-closed API key).

---

## What Was Actually Good (evidence-backed)

- **Core pipeline is real and live-validated.** 15/15 manifest program IDs re-verified executable on mainnet (twice, two separate cycles; `scripts/live_revalidate.py` reproduces it). Real devnet transactions run the full pipeline (30 live verification events across two cycles; 20-fixture corpus replays 20/20 → P10 PROMOTE).
- **Durability + concurrency are proven, not assumed.** The audit log is Mutex-guarded; a real-listener storm (8×25 concurrent verifies + 16 dashboard reads) produced 200/200 durable records, 0 5xx, shared semantic-graph evidence intact — 246 verifies/s end-to-end.
- **Fail-closed posture is consistent.** Unknown programs get confidence ceilings; registry submissions now have size caps (512 instructions / 256 accounts / 128 chars / 64 items + per-entry strings); hostile-body battery (11 malformed/oversized payloads) returns clean 4xx, never 5xx.
- **The 8-layer verification pipeline** (intent, account resolution, discriminator, risk patterns, policy, confidence, L3 simulation, L8 execution) is genuinely implemented with honest layer states.
- **Measured performance:** p50 945μs / p95 1330μs / p99 1490μs in-process; sequential 1011 v/s; **linear scaling proven** (5,000 verifies → 979.8μs/verify, no O(n²)).

## What Was Actually Bad

- **ALT/versioned-transaction handling was missing** (see C13) — silently wrong account lists on 2 of 3 real fixtures.
- **No single source of truth for program IDs** (C14) — 8+ duplicated ID sources; the fabricated memo ID survived in two docs after C1.
- **Benchmark is not evidence of real-world detection** (C15) — all-synthetic, label-leaked, 10–12 attack classes, no real holdout.
- **Dynamic PDA capability exists but is deployed nowhere** — no manifest uses `{instruction_data:…}` seeds; Squads V4 devnet is stale and DCA seed layouts unconfirmed (documented honestly, no fabricated offsets).
- **Protocol surface is Tier-0-incomplete** — missing ATA, ComputeBudget, BPF Loader, Raydium CLMM/CPMM, PumpSwap, Kamino, Drift, Pyth — programs that dominate real traffic (see Protocol Coverage).
- **No live public deployment; no CI branch protection on `main`.**
- **Exploit corpus is thin:** 3 "SYNTHETIC:" drainer patterns (CLINKSINK, AAT, Wormhole shapes) with real program IDs but synthetic accounts; no pinned real malicious transaction.

---

## Verification Table (claimed vs. actual)

| Area | Claimed | Actual | Evidence | Confidence | Action |
|---|---|---|---|---|---|
| Regression engine | 90% | **75%** | Real corpus + P10 replay proven; but only 20 live + 3 pinned fixtures; no 1,000-fixture volume | High | Keep; grow corpus |
| Manifest registry | 85% | **70%** | Operator CLI, signing, tier derivation, size caps (C11); no PR/community workflow, no on-chain stake lookup | High | Keep; Phase-3 community flow |
| Plugin framework | 70% | **65%** | 6 interfaces, 2 real plugins, benchmark shows ~0 overhead, H25 scoping tests | Med | Keep |
| Dashboard | 90% | **85%** | 6 endpoint tests, live E2E, auth, CI build job; read-only by design | High | Keep |
| AuditBind TOCTOU | 85% | **80%** | Strict payload-binding + 8 tests; full auto pre-submit hook missing (needs executor API) | Med | Keep |
| Real mainnet fixtures | 75% | **80%** | 3 real txs; **all v0+ALT — and the ALT gap they exposed is now fixed** | High | Keep |
| Test expansion | 85% | **88%** | 976 tests incl. concurrency storm, hostile-body battery, registry caps, ALT regression | High | Keep |
| Live corpus collection | 75% | **75%** | seed-live on live devnet works; corpus dedupe + fail-closed load | High | Keep |
| Protocol expansion | 4/15–20 target | **8/15–20** (22 total manifests; Tier-0 + Tier-1 complete (Drift+Kamino C27/C42) — ATA, Compute Budget, BPF Loader, BPF Loader Upgradeable added C17) | 22 manifests on-chain verified; Tier-1 (Drift+Kamino) built C27/C42; Pyth remains for future expansion | High | **Build Tier-1 next** |
| Dynamic PDA resolution | 30% | **30%** | `{instruction_data:…}` templates implemented + tested (10 tests, official-SDK pins); **zero manifests use them** | High | Ground in a real manifest or say "not deployed" |
| Benchmark meaningfulness | — | **35%** | 18/18 synthetic, labels hand-encoded, no real holdout (C15) | High | Build real holdout |
| Memo/ID architecture | — | **pre-fix broken → post-fix 80%** | 8+ ID sources; fabricated ID survived in 2 docs; now single registry (C14) | High | Done |
| Deployment | — | **40% → 55%** | Good Dockerfile; compose + env contract added this cycle; no live public deployment | Med | Operator deploy |
| Phase 2 overall | 58% | **57% pre-fix → 63% post-fix** | Above | High | — |
| Overall | 67% | **~72% → ~74%** | Core stronger than claimed; Phase 2 gaps real | High | — |

---

## Critical Findings

### C13 — Address Lookup Tables silently dropped (P1, FIXED this cycle)
- **Problem:** `tx_to_input` read only static `accountKeys`; v0 transactions carry `addressTableLookups` whose entries occupy indices beyond the static key list. All 3 pinned "real mainnet" fixtures are v0; the Jupiter fixture has **26** instruction-account references into ALT space, the System fixture **8** — all silently dropped. Account-role analysis and drainer account-count heuristics on modern txs were wrong.
- **Root cause:** the parser was written for legacy messages; nothing consumed `addressTableLookups`.
- **Impact:** wrong account lists on the majority of real mainnet transactions (ALTs are standard in 2025–26 high-throughput txs) → weakened/incorrect analysis, potential false negatives on drainer patterns.
- **Fix:** `expand_account_keys()` in `live_corpus.rs` expands the key space positionally (`alt:{table}:{entry}` placeholders — index space exact; address resolution needs ALT account data). One call site, used by corpus + seed paths.
- **Regression protection:** `alt_lookup_expansion_matches_real_fixtures` pins 14+19=33 keys for jup, identity for the empty-lookup pump fixture, and end-to-end program identification.
- **Why prior audits missed it:** fixtures "passed" because program identification only needs the top-level program (always a static key); the wrong part was the account lists, which tests didn't assert.

### C14 — Program-ID duplication, no single source of truth (P1, FIXED this cycle)
- **Problem:** the `MemoSq4gq…` ID (claimed fabricated by C1) was still present in `docs/release-evaluation-report.md` and `graphite-core/CHANGELOG.md`; IDs were duplicated across manifests, the `manifest.rs` pin list, README, changelog, release-eval, 2 test files, Python test, and the live script — 8+ independent copies.
- **Root cause:** no single registry; each doc/test re-encoded IDs by hand.
- **Impact:** exactly the failure mode that let the memo class of bug recur (C1 → C10 → C16).
- **Fix:** `protocols/verified_program_ids.json` = single source of truth (name, ID, provenance, verification date). Rust pin test rewritten to load it and assert **bidirectional exact match** against manifests (fabricated/removed/duplicated/renamed IDs all fail CI); Python AI-layer test does the same; stale docs corrected.
- **Regression protection:** two independent enforcement points + the on-chain gate + the blessed-set test added by C16; new manifests cannot land without a registry entry backed by evidence.

### C16 — MemoSq4gq was real all along; the "fabricated" claim corrupted the registry (P0, FIXED this cycle)
- **Problem:** the first forensic cycle (C1) removed the canonical SPL memo `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr` claiming it "never existed on any cluster". Independent re-verification (third cycle, 2026-08-08) proves that claim false: `getAccountInfo` on mainnet returns an **executable account, 99,736 B ELF, owner BPFLoader2111, actively used** — the classic SPL memo used in countless token transfers.
- **Root cause:** the previous "verification" was asserted in prose, not reproducible; the registry could be edited wrongly with no guard, and `scripts/live_revalidate.py` — the one tool that would have caught it — crashed with `KeyError: 'protocol'` on `verified_program_ids.json`.
- **Impact:** Graphite could not match the most common memo program for two audit cycles; docs asserted a false fact about the chain.
- **Fix:** restored `MemoSq4gq…` as the 16th manifest + registry entry; fixed `live_revalidate.py` (skips non-manifest JSON, verifies registry IDs on-chain, non-zero exit on absence); added the blessed-canonical-set test anchoring the core IDs; corrected all docs.
- **Regression protection:** three independent layers — offline blessed-set test, bidirectional pin tests (Rust + Python), and a working on-chain revalidation script.

### C17 — Tier-0 protocol surface completed (P1, FIXED this cycle)
- **Problem:** the Tier-0 list from the gap matrix (ATA, ComputeBudget, BPFLoader) was missing — foundational programs in nearly every modern transaction were unpinned. ComputeBudget instructions appeared in all three pinned fixtures; ATA creates in the Jupiter fixture; BPF Loader Upgrade/SetAuthority (upgrade-abuse surface) was unmodeled.
- **Root cause:** expansion targeted DEX/DeFi; the ubiquitous system programs were skipped.
- **Impact:** unknown-protocol ceiling (0.55) on priority-fee/token-account/loader instructions instead of manifest matching.
- **Fix:** 4 new manifests (ATA, Compute Budget, BPF Loader, BPF Loader Upgradeable) — IDs EXEC-verified on mainnet 2026-08-08, discriminators from official sources AND grounded against the real fixture bytes by a new regression test; registry 16 → 20, blessed set extended, Python cross-check synced; `live_revalidate.py` gained 429/5xx retry+backoff.
- **Regression protection:** grounded fixture test (real data, not self-reference) + bidirectional checks + on-chain script; Compute Budget's zero-account instructions documented as by-design.

### C18 — Squads manifest fabricated + dynamic PDA finally grounded (P0, FIXED this cycle)
- **Problem:** the Squads V4 manifest used camelCase-hash discriminators (`sha256("global:multisigCreateV2")`) instead of Anchor's snake_case values, and carried 18 v1-era instructions that don't exist in the deployed program. Only 3/21 instructions were real; 2 had wrong discriminators.
- **Evidence:** official IDL v2.1.0 + live mainnet txs — `vaultTransactionCreate` = `30fa4ea8d0e2dad3` (observed live) vs manifest `ed3256172ab558fc`; `multisigCreateV2` = `32ddc75d28f58be9` vs `8faecbbfaecf93c5`; `proposalCreate`/`proposalApprove` observed live and absent.
- **Fix:** rebuilt from the IDL — all 36 deployed instructions, correct discriminators (4 chain-verified), IDL account lists. Multisig PDA seeds added (`['multisig','multisig',create_key]`, SDK + IDL grounded) — the first real dynamic PDA in any manifest, with resolver end-to-end + spoof-flagging regression tests. Transaction/vault PDAs need account-state seeds beyond the template engine (documented).
- **Remaining risk (honest):** the multisig PDA layout is source-grounded; a direct chain reproduction was attempted (create-tx scan timed out; an old multisig's account data predates the current struct) — flagged, not hidden.

### C19 — P16 real-mainnet benchmark + real pinned exploit corpus (P1, delivered this cycle)
- **Delivered C15's "Next (Phase 3)" item:** a real-transaction holdout corpus now exists (`graphite-core/tests/fixtures/exploit_corpus.json`) — 35 transactions pinned by signature from documented phishing accounts (SolPhishHunter arXiv:2505.04094), with provenance per entry. `mainnet-benchmark.ts` runs live mainnet legitimate txs (with real per-protocol intents) against the corpus. Full report: `docs/p16-mainnet-benchmark.md`.
- **Measured on unseen real data (fresh node):** malicious recall **100%** (35/35 blocked), legitimate 0/7 — all 7 root-caused: cold-start confidence ceiling (0.44 < 0.80 TradingBot threshold, P7 earned-evidence by design; steady-state approval proven by a seeded regression test) and Raydium CLMM unknown-protocol.
- **Two real defects found and fixed:** (1) the 64-account input cap rejected legitimate 72-account Jupiter routes — raised to Solana's protocol limit (256) with a regression test; (2) ISA (system-account impersonation) was not detected — added P0 Check 10 (`Impersonation` pattern) blocking fund movement to/from vanity `…11111`/`Compu…` addresses, with principled-block assertions in the corpus test.
- **Fabricated addresses purged:** the old harness's fake "drainer" section (two invalid IDs rejected by the RPC) is gone, replaced by the real corpus.

### C21 — Advisory labeler v2 + intent-vocabulary alignment (P1, delivered this cycle)
- **Problem:** the advisory labeler was thin by design (4 intent classes, hardcoded confidence, no protocol grounding) AND the risk engine contradicted the semantic layer: `program_supports_intent` returned false for `create`/`approve`/`revoke`, so every legitimate create/approve/revoke was blocked by P0 Check 9 despite Check 6b/7 explicitly allowing those intents.
- **Fix (labeler, no LLM):** v2 emits the full Core semantic vocabulary, derives suggestions from the verified manifest registry at load time, adds risk-hint warnings (impersonation-vanity destinations, authority changes, approve escalation, unmodeled mint/bridge/lend → advisory + fail-closed `unknown`), per-signal confidence, and a benchmark mode — **~47k parses/sec, p50 ~21 µs**.
- **Fix (core):** `program_supports_intent` expanded to the L5 vocabulary (create/approve/revoke + aliases) with correct program sets; unknown intents stay fail-closed. Live probes confirm create/revoke now pass the risk engine while approve still hard-blocks by design (risky-pattern PermissionEscalation).
- **Surface fixes:** bridge swap default corrected from legacy `route` (`e517cb97…`) to deployed `route_v2` (`bb64facc…`); TS SDK `IntentType` removed unsupported `lend` and added close/create/approve/revoke.
- **Validation:** 856 Rust tests / 0 failed (+4), 27/27 Python (+19), 8/8 AuditBind, clippy/fmt/gates green, TS/SAK clean, on-chain program IDs re-verified.

### C22 — Clean-room revalidation: two false-confidence findings fixed (P1, delivered this cycle)
- **Method:** the clean-room pass re-read the entire repository, treated every prior certification as untrusted, and ran mutation/deletion-style challenges — "what happens if this component is removed/bypassed?" — against every critical module. Both findings below are test-passing-but-wrong: the tests passed while the capability was broken.
- **C22.1 live-corpus seeding recorded fee payments, not protocol calls.** `tx_to_input`'s prefer-selection was first-match over the prefer-set; the production `seed-live` path passes ALL manifest IDs (including System/ComputeBudget), so selection degenerated to the System fee payment (2–3 accounts). The pipeline test passed because it never asserted which instruction won. Fix: prefer-matching ranks by account count AND excludes infrastructure programs (System, ComputeBudget, ATA, Memo×3) from the match — the actual protocol invocation (Jupiter route, 40 accounts; or the max-accounts fallback for CPI-only protocols like pump.fun) wins. ALT-resolved `alt:{table}:{entry}` placeholders (not valid base58) are also skipped instead of silently failing verification. 2 new tests; the pipeline test now pins the selected program per fixture.
- **C22.2 transfer-path AuditBind did not bind the amount.** `executeTransfer` bound only programId + discriminator + accounts; the amount (in instruction data) was unbound, so a mutated amount passed the TOCTOU check. Fix (both sides together, per the Rust `content_hash` contract): the bridge now sends `instructionData` to verification AND to the AuditBind projection (4-byte `02000000` discriminator shape). Amount mutation now aborts. 1 pinned TS regression test.

### C23 — Manifest discriminator ground truth: Jupiter V6 + DCA (P1, FIXED this cycle)

Round-two sub-agent verification closed the highest-risk unchecked surface: computing every manifest discriminator from first principles and diffing against on-chain observation. The critical methodology correction: `getTransaction` JSON encoding returns instruction data as **base58**, not base64 — the prior census mis-decoded and produced garbage "observations". With base58-correct decoding, two real findings surfaced (the C18 discriminator-fabrication class):

- **C23.1 Jupiter V6: 16 old-era entries carried camelCase hashes.** `route`/`route_v2` were confirmed correct on-chain (C19/C21 claim stood). But 16 legacy entries (`sharedAccountsRoute`, `setTokenLedger`, `routeWithTokenLedger`, compression/check variants) carried `sha256("global:"+camelCase)` hashes that never match the deployed program. `sharedAccountsRoute=c1209b3341d69c81`, `setTokenLedger=e455b9704e4f4d02`, `routeWithTokenLedger=96564774a75d0e68` verified on-chain; the rest follow the program's confirmed snake_case convention. Manifest note documents the internal `e445a52e…` route (1-account CPI) as non-top-level provenance. Regression test pins verified values and asserts old camelCase hashes must NOT resolve.
- **C23.2 Jupiter DCA: entire discriminator table corrupted + live fill path missing.** None of the 7 stored values match the deployed program (the `verification.notes` falsely claimed live observation — same decode artifact). The deployed program is STANDARD ANCHOR: `initiate_flash_fill=8fcd03bfa2d7f531`, `fulfill_flash_fill=7340e24e21d369a2`, `transfer=a334c8e78c0345ba` observed live — and those 3 instructions were missing from the manifest, so the dominant real DCA traffic (keeper fills) fell to unknown-protocol mode. Table rewritten to confirmed snake_case hashes, 3 fill-path instructions added with flash-loan/compositional-drain risk rules, stale values in tests/scripts updated, regression test pins all 10 values + asserts stale values must NOT resolve.
- **Server security re-probed live** (the surface the sub-agent refused): auth 401/200, malformed JSON/deep nesting → 422, 2MB body → 413, rate limit 5/s → 6th request 429, and **X-Forwarded-For spoofing does NOT bypass rate limiting** without `GRAPHITE_TRUST_PROXY=1` (rotating spoofed IPs all bucketed to the real IP → 6th request 429). Constant-time auth, bounded FIFO rate limiter, CORS denied by default, body cap + timeout layers all confirmed.
- **Docs-vs-reality synced:** README/ARCHITECTURE/ROADMAP/release-evaluation/phase2-plan/branch-strategy/gap-audit updated to 976 tests / 22 manifests / 561 instructions / 11 risk patterns (were 844/15/216/8).

### C24 — Orca + Metaplex discriminator ground truth (P1, FIXED this cycle)

- **C24.1 Orca Whirlpools: 23/24 camelCase hashes.** Only `swap` was correct. On-chain census (base58-correct) observed `swap_v2=2b04ed0b1ac91e62` (×17) and `swap=f8c69e91e17587c8` (×4) — both `sha256("global:"+snake_case)[:8]`, confirming the deployed program is standard Anchor. All 23 corrected; stale values asserted absent.
- **C24.2 Metaplex Token Metadata: not Anchor — Shank u8 discriminators, fabricated 8-byte values.** On-chain census observed data starting `0x21` (CreateMetadataAccountV3=33) and `0x0f` (UpdateMetadataAccountV2=15); enum order gives SignMetadata=07, VerifyCollection=12, BurnNft=1d. The old 8-byte values and the verification note claiming live observation were fabricated (C22.4/DCA class). Rewritten to u8 values; reference file regenerated; tests updated.
- **C24.3 systemic guard:** `no_manifest_discriminator_is_a_camelcase_anchor_hash` scans every manifest — the C18 camelCase disease can no longer re-enter any manifest.
- **Verification:** 864 Rust tests / 0 failures (+3: Orca pin, Metaplex pin, systemic guard), clippy/fmt clean, 27 Python, all feature gates.
- **Validation:** 858 Rust tests / 0 failed (+2), 27/27 Python, 9/9 AuditBind (+1), clippy/fmt/gates green, TS/SAK clean, dashboard builds.

### C25 — Orca full-surface rebuild: 6 fabricated instructions removed (P1, FIXED this cycle)

Round four (independent audit of C24) rebuilt the Orca Whirlpools manifest from the deployed program's official IDL and exposed a second-order fabrication: C24 "corrected" 6 entries that never existed.

- **C25.1 6 of 24 entries were fabricated.** `updateFeeRate`, `transferPositionDelegate`, `applyDelta`, `syncTickArray`, `closeAccount`, `closeConfigExtension` appear in neither the 2022-era deployed IDL (v0.1.0, 25 instructions) nor the current deployed IDL (66 instructions), and the orca-so/whirlpools git history has zero occurrences. The C24 note's claim that they were "corrected to the snake_case convention" rested on the false premise that they existed; the note is superseded. All 6 removed; the regression test asserts each name is ABSENT.
- **C25.2 manifest covered only 24 of 66 deployed instructions.** Every legitimate Orca txn using any other instruction fell to unknown-protocol mode (0.55 ceiling). Rebuilt from the official deployed-program IDL (npm `@orca-so/whirlpools`, program v0.9.0): all 66 discriminators are the IDL's explicit byte arrays (not re-derived hashes); IDL committed as `scripts/whirlpool_idl.json`; `scripts/rebuild_orca_manifest.py` regenerates; manifest version 2.0.0. Instruction surface total: 219 → **561** across 22 manifests.
- **C25.3 extended live corroboration.** Base58-correct census over 528 Orca txs: `swap=f8c69e91e17587c8` (×153), `swap_v2=2b04ed0b1ac91e62` (×342), `increase_liquidity_by_token_amounts_v2=effb097cd2c6352b` (×7 — an instruction that exists only in the current IDL, proving the IDL is the deployment's instruction set). Script: `scripts/census_orca.py` (progress cache gitignored).
- **Verification:** 864 Rust tests / 0 failures, clippy `-D warnings` clean, fmt clean.

### C15 — Benchmark is synthetic and self-referential (P2, now explicit + CI-pinned)
- **Problem:** all 18 cases are hand-constructed `VerificationInput`s with manually-encoded `expected_approved` labels; 16 scored (4 safe, ~10–12 malicious), 2 unknown; three cases are labeled `SYNTHETIC:` (real program IDs, synthetic accounts). Zero cases come from real transactions. The "100% precision/recall" substantially measures the rules agreeing with the cases built from the rules.
- **Root cause:** P16 reproducibility (deterministic benchmark) was prioritized over real-data validation; the two are different things and the benchmark only satisfies the first.
- **Impact:** benchmark results are NOT evidence of real-world detection precision/recall; they are regression coverage.
- **Fix (honest classification):** `benchmark_composition_is_explicit_and_synthetic` pins the composition (18 cases, 0 real, ≥3 SYNTHETIC, ≥10 malicious classes) so the claim "real-data benchmark" can never be made without changing the test. Real-data validation lives in `live_transactions.rs` (live devnet) + pinned real fixtures.
- **Next (now delivered):** the real-transaction holdout corpus exists (C19 — 35 pinned malicious txs) and `mainnet-benchmark.ts` scores it plus live legitimate txs with no label leakage. Remaining: a pinned corpus of *legitimate* transactions (not just live-fetched) and a steady-state (evidence-seeded) scoring mode.

### C16 — No live public deployment / no branch protection (P2, partially closed)
- Dockerfile is sound (multi-stage, non-root, healthcheck). Added `docker-compose.yml` + `.env.example` (fail-closed API key, volume-persisted state, healthcheck). **Not deployed anywhere** — remains an operator action; not a code blocker for the mission, but required before any public use.
- `main` receives direct pushes (CI runs on every push and is green, but nothing *blocks* a red merge or unreviewed push). Branch protection is a GitHub setting that must be enabled by a repo admin; the concrete minimum is documented below (Engineering Process).

---

## Research Findings (external, with sources)

**Exploit corpus for a verifier's threat model** (all shapes a static transaction verifier should consider):

| Incident | Date | Program | Attack class | Verifier-detectable signal | Source |
|---|---|---|---|---|---|
| Wormhole bridge | 2022-02 | `worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth` | Sysvar/instruction spoofing | forged `instructions` sysvar account bypassing guardian sigs | certik.com/blog/wormhole-bridge-exploit-incident-analysis; halborn.com/blog/post/explained-the-wormhole-hack-february-2022 |
| Cashio | 2022-03 | Cashio program | Missing account validation / infinite mint | collateral accounts not owner/mint-verified | theblock.co/post/139311; halborn.com/blog/post/explained-the-cashio-hack-march-2022 |
| Mango Markets | 2022-10 | `MangoCzJ33MR5rcFDff3QntMDZiqvWb3kMC3jJtP6n9U` | Oracle manipulation | thin-liquidity spot moves before leveraged borrow | soliduslabs.com/post/mango-hack; blockworks.com/news/mango-markets… |
| Raydium | 2022-12 | `675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8` | Authority abuse | privileged `withdraw_pnl` without timelock/multisig | certik.com/blog/raydium-protocol-exploit-incident-analysis; raydium.medium.com postmortem |
| Banana Gun bot | 2024-09 | bot backend | Drainer / message-oracle abuse | unrequested external transfers from bot sessions | quillaudits.com/blog/hack-analysis/banana-gun-exploit; theblock.co/post/318074 |
| **Drift v2** | **2026-04** | `dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH` | **Durable-nonce abuse of pre-signed multisig txs** | high-privilege instruction executed via `AdvanceNonceAccount` with stale recent blockhash | blocksec.com/blog/drift-protocol-incident…; coindesk.com/tech/2026/04/02/…; halborn.com/blog/post/explained-the-drift-hack-april-2026 |

**Direct implications for Graphite:** (1) authority-abuse and account-confusion classes are already modeled (SetAuthority, drainer, CPI chains). (2) The Drift durable-nonce class is NOT — Graphite's `VerificationInput` has no recent-blockhash/nonce field, so a pre-signed durable-nonce admin tx would verify identically to a live one. This is a genuine, recent, high-value gap for the Phase-3 executor/raw-tx path. (3) Oracle manipulation (Mango) is only partially addressable statically — Graphite's simulation layer (L3) is the right hook, and it is not yet production-active.

**Ecosystem ranking (protocol coverage input):** Jupiter (aggregator, billions/day) > Raydium family (AMM v4/CLMM/CPMM) > Meteora DLMM > Orca Whirlpools > Pump.fun (+PumpSwap) > Jito > Kamino (~$3B TVL) > Drift (~$500M) > Marinade/Sanctum (LSTs) > Tensor (NFTs) > Pyth/Switchboard (oracles) > Squads (multisig) > Wormhole/LayerZero (bridges). Tier-0 programs every verifier must know: System, SPL Token, Token-2022, **Associated Token Account**, **Compute Budget**, **BPF Loader Upgradeable**, Memo, Stake.

## Protocol Coverage — prioritized roadmap

**Tier 0 (must have — foundational):**
| Program | ID | Why |
|---|---|---|
| Associated Token Account | `ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL` | in nearly every token tx (wrap/unwrap) |
| Compute Budget | `ComputeBudget111111111111111111111111111111` | every modern tx (CU limit/priority fee); must never be "unknown" |
| BPF Loader Upgradeable | `BPFLoaderUpgradeab1e11111111111111111111111` | program deploy/upgrade txs (upgrade-authority security surface) |

**Tier 1 (highest-value risk surface):** Jupiter V6 ✓, Raydium AMM v4 ✓, **Raydium CLMM `CAMMCzo5…`**, **Raydium CPMM `CPMMoo8…`**, **Pump.fun AMM/PumpSwap `pAMMBay6…`** (rug/drainer volume), Meteora DLMM ✓, Orca Whirlpools ✓, **Kamino `KLend2g3…`** (liquidation cascades), **Drift `dRiftyHA…`** (2026 exploit).

**Tier 2 (important):** Jito (restaking/MEV), Marinade, Sanctum, Tensor, Pyth pull `rec5EKMGg…` (oracle verification), Switchboard, Squads ✓ (multisig — dynamic PDA target), Wormhole ✓.

**Tier 3 (long-tail):** Zeta, Phoenix, Save/Solend, MarginFi, Solayer, Blinks/actions, others.

**Priority recommendation (Phase 3):** add the three Tier-0 programs + PumpSwap + Raydium CLMM first — they are high-volume, low-complexity manifests that immediately reduce "unknown program" false positives on real data — before any further long-tail coverage. **Ten deeply verified manifests beat thirty superficial ones.**

## Real-World Data

- **Real benign txs through the pipeline:** 3 pinned mainnet (Jupiter v6 swap, pump.fun market, System batch — all v0) + 20 live devnet corpus fixtures + 10 live devnet verify events. All finite confidence, correct hashes, correct program identification (post-ALT-fix).
- **Real malicious txs:** **0** in the corpus or benchmark. The 3 drainer patterns are synthetic reconstructions of documented attack shapes (CLINKSINK, AAT, Wormhole) with real program IDs.
- **Protocol diversity:** 22 manifests (incl. classic SPL memo C16 + Tier-0 ATA/Compute Budget/BPF Loaders C17 + Tier-1 Drift+Kamino C27/C42); Pyth remains for future expansion.
- **Attack-class diversity:** ~10–12 classes in the benchmark (CPI spoofing, compositional drain, authority abuse ×2, account drain, wrong-program swap, simulation spoofing, 3 synthetic drainers) + live adversarial suites (hell-mode H25, omega, deep-extreme).
- **Benchmark:** 18/18 synthetic, 16 scored, 100% precision/recall — honest meaning: rule-vs-case consistency, not real-world detection.

## Architecture — verdicts

- **KEEP:** 8-layer pipeline; semantic-graph evidence store (Arc-shared, append-only, P4); risk engine patterns; confidence engine (tier-capped, NaN-rejecting); durable audit log (Mutex-guarded); rate limiter (bounded FIFO buckets); unknown-program ceilings; policy engine; plugin boundary (typed, P8); CLI/server split.
- **IMPROVE:** corpus reader (ALT done); program-ID registry (done); benchmark honesty (done); per-program graph mutex granularity for higher throughput (currently one global mutex, ~6 acquisitions/verify — measured 246 v/s E2E single node, fine for Phase 2).
- **REFACTOR:** none found fundamentally broken this cycle.
- **REPLACE:** none.
- **ADD (Phase 3, evidence-ranked):** (1) raw-transaction input path (blockhash/nonce → Drift-class durable-nonce detection); (2) real malicious-tx holdout corpus; (3) Tier-0 manifests; (4) live deployment (compose exists now); (5) branch protection on `main`; (6) dynamic-PDA manifest grounding (needs Squads mainnet data or program IDL).

## Performance (measured 2026-08-08, release build, x86_64)

| Metric | Value |
|---|---|
| p50 / p95 / p99 in-process | **945 / 1330 / 1490 μs** |
| Sequential throughput | 1011 v/s (pipeline only) |
| HTTP E2E (8 workers, full durability) | **246 v/s**, 0 5xx, 200/200 audit records |
| Scaling | **linear** — 5,000 sequential verifies at 979.8μs/verify (no O(n²)) |
| Memory | semantic graph grows 1 behavior/verify (append-only, P4); 5,000-verify soak stayed stable; no compaction (documented design, Phase-3 eviction strategy needed for long-running servers) |
| Bottleneck | RPC `getBlock` dominates live seeding; pipeline is sub-millisecond |

## Gap Matrix (prioritized by impact)

| Capability | Current | Required | Gap | Severity | Fix |
|---|---|---|---|---|---|
| ALT/versioned parsing | fixed this cycle | correct account space | closed | P1→closed | expand_account_keys + fixture pin |
| Program-ID single source | fixed this cycle | one registry, 2-way CI check | closed | P1→closed | verified_program_ids.json |
| Real malicious corpus | 0 real | ≥5 pinned real malicious txs w/ provenance | **P1** | High | capture from incident signatures; score + document decisions |
| Raw-tx input (blockhash/nonce) | absent | detect Drift-class durable-nonce abuse | **P1 (Phase 3)** | High | extend VerificationInput + risk pattern |
| Tier-0 manifests | missing | ATA, ComputeBudget, BPFLoader | **P1** | High | add manifests w/ verified IDs |
| Dynamic PDA deployment | capability only | ≥1 real manifest uses it | P2 | Med | Squads mainnet / IDL grounding |
| Benchmark honesty | pinned as synthetic | real holdout corpus | P2 | Med | Phase-3 holdout |
| Live deployment | compose ready, not deployed | operator deployment + branch protection | P2 | Med | operator action + GitHub settings |
| Graph memory compaction | none | bounded long-run memory | P3 | Low | Phase-3 eviction strategy |

## Engineering Process (direct-to-main)

- **Current reality:** CI runs on every push (all 5 jobs), all pushes to `main` since the audit started have been green; nothing *blocks* a red push or unreviewed change — protection is procedural, not enforced.
- **Minimum required (admin action, GitHub):** enable branch protection on `main` — (1) require status checks (the 5 CI jobs), (2) require PR review for `graphite-core/src`, `graphite-core/protocols`, `python-ai-layer`, (3) require updated branches. This is a settings change, not a code change; it is documented here so a repo admin can apply it.

## Remaining Risks (honest)

- **No real malicious transaction has ever been scored end-to-end** — the strongest claim we can make about malicious detection is "10–12 hand-constructed attack shapes are detected; the rules are scoped by adversarial suites." Real-world precision/recall is **unmeasured**.
- **Drift-class durable-nonce attacks are invisible to the current input schema.**
- **Dynamic PDA is not deployed** in any manifest; Squads V4 devnet is stale and DCA seed layouts unconfirmed — no fabricated offsets were shipped.
- **L8 execution verification** remains unimplemented (needs a live executor).
- **Oracles (Pyth) are not modeled** — oracle-manipulation detection (Mango class) is out of scope until the L3 simulation path is production-active.
- The 2026 exploit details above (esp. exact Drift signatures) were gathered via web research; the two cited security-firm postmortems agree on the durable-nonce mechanism, but Graphite has not re-derived them from raw chain data (no signature-level pin in this cycle).
