# Graphite — Full Production Forensic Audit & Independent Reconstruction

**Date:** 2026-08-08
**Branch:** `phase2-development`
**Method:** adversarial real-world validation, live RPC evidence, root-cause investigation, roadmap/skill compliance audit, first-principles reconstruction, gap implementation, full re-validation loop.

---

## A. System Health

| Signal | Result |
|---|---|
| Full Rust test suite | **837 passed / 0 failed** (23 binaries) |
| clippy `--all-targets --all-features -D warnings` | 0 warnings |
| `cargo fmt --check` | clean |
| `cargo check --no-default-features` (CI gate) | clean |
| `cargo check --no-default-features --features cli` (CI gate) | clean (after C9) |
| GitHub Actions CI on `main` | **5/5 jobs green** across every audit-commit push — Rust core, TS SDK + SAK, Go SDK, Python AI layer, Dashboard |
| Benchmark (P16) | 16/16 scored cases, 100% precision / 100% recall, avg **989μs**/verify (p50 945 / p95 1330 / p99 1490μs) |
| Live mainnet program IDs | **15/15 executable live** (re-verified 2026-08-08); 0 retired — the previous "1 retired" claim was a documentation error (C10) |
| Live devnet pipeline | 30 verification events over real devnet transactions (10 live test + 20 `seed-live`; the two runs walk overlapping recent blocks, so distinct-tx count may be less) |
| Server concurrency (real listener, 8 workers) | **246 verifies/s** over HTTP; 200/200 audit records durable under concurrency; 0 5xx; shared evidence intact (F) |

**Overall status: production-capable for the Phase-2 feature set, with three honest caveats** — dynamic PDA seed resolution (roadmap open item), L8 execution verification (requires a live executor), and the P16 deterministic benchmark remaining synthetic by design. All exit criteria that CAN be met without those are now met and evidence-backed.

**Critical finding:** one root-level data defect (swapped/fabricated memo program IDs — see C1) was discovered and fixed; the CI-equivalent validation pass additionally surfaced and fixed two integration defects (C8: stale Python cross-check with a masked false-equality bug; C9: dead code under the `cli`-only gate). This cycle's re-validation caught two more: C10 (a "retired memo" documentation claim that was factually wrong — the program is live on both clusters) and C11 (registry submissions had no size caps — a resource-exhaustion vector).

---

## B. Real-World Validation

All checks below ran against **live Solana RPC** (api.mainnet-beta.solana.com / api.devnet.solana.com) on 2026-08-08.

1. **All 15 seed manifest program IDs checked on mainnet** (`getAccountInfo` → `executable=true`):
   - 14 executable: System, SPL Token, Token-2022, Stake, Memo (live), Raydium AMM V4, Orca Whirlpools, Meteora DLMM, Squads V4, Jupiter V6, Pump.fun, Jupiter DCA, Wormhole Core, Metaplex Token Metadata.
   - **1 defect:** `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr` (pinned by `memo-program.json`) **never existed on any cluster** — see C1. Fixed.
2. **SAK devnet claim independently re-verified on-chain:** signature `xHa4dyuFS6JmSaTsmhcMpEtwbWnPjBoUGwk3wNixD2uw2Wmeui6GhnSmmdzNVkv85zXSd6g7QYhHymAjciwP3jJ` re-fetched via `getTransaction` — real finalized System transfer from wallet `CWb8MciizembLV66kisYcXo3Cb91hdszxw74QHpEJKZR` (slot 481727834, status Ok, fee 5000 lamports). Wallet balance confirmed. The claimed SAK→Graphite→execution pipeline is real.
3. **Real devnet transaction corpus through the full pipeline:** the network-gated live test verified **10 real devnet transactions** (`getBlock` shapes → `VerificationInput` → full 8-layer pipeline), all with finite confidence in [0,1] and 16-char content hashes.
4. **Real mainnet fixtures (pinned, deterministic):** 3 genuine mainnet transactions captured live (a Jupiter v6 swap with 40-account instruction, a pump.fun-market tx, a System batch tx) stored in `tests/fixtures/` in the exact RPC shape and run through the full pipeline in unit tests.
5. **`graphite regression seed-live` on live devnet:** verified=20, approved=1, recorded=20 fixtures, skipped=0; corpus replayed **20/20 (100%), P10 gate PROMOTE**.
6. **Registry operator path live:** registered reviewer → signed submission → **ACCEPTED at derived tier OfficialManifest** (P7: tier computed, never asserted); unregistered signer → REJECTED; no-evidence → REJECTED; invalid manifest → REJECTED; state persisted across invocations.
7. **Adversarial suites on the expanded trusted roots:** H25 hell-mode tests pin that the Pump.fun/Jupiter-DCA `DEX_PROGRAMS` relaxations stay scoped (repeated-CPI compositional drains still block on pump.fun; DCA token CPIs from the trusted root pass; Wormhole is NOT exempt); omega_red_team exercises both roots.
8. **Full live re-validation (2026-08-08, second cycle):** all 15 manifest IDs re-checked on mainnet — **15/15 executable** (the legacy memo `Memo1UhkJRf…` is EXEC on mainnet AND devnet, owner BPFLoader — the previous "retired" label was wrong, see C10; `MemoSq4gq…` remains the only ID that never existed). SAK devnet signature re-fetched again: status Ok, slot 481727834, fee 5000 — the claim still holds. Reproducible via `scripts/live_revalidate.py`.

---

## C. Root-Level Findings

### C1. SWAPPED / FABRICATED MEMO PROGRAM IDS (fixed)
- **Symptom:** the canonical-ID pin test passed while one seed manifest pointed at a program that does not exist.
- **Root cause:** `memo-program.json` pinned `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr` (never existed on mainnet or devnet — verified `getAccountInfo` ABSENT on both), while `legacy-memo-program.json` pinned `Memo4c2pN8afCj432Lb7RMVKi9PbQnnW7ewFFaV3oAH` (the LIVE memo program). The "on-chain-verified" pin test was written **from the manifests themselves** (self-referential), not from on-chain data — so it codified the wrong data.
- **Impact:** real memo transactions (which use `Memo4c2pN8af...`) would not match the "Memo Program" manifest, and the "legacy" manifest mislabeled the live program. Dead trust weight + mislabeled identity.
- **Fix:** `memo-program.json` → `Memo4c2pN8afCj432Lb7RMVKi9PbQnnW7ewFFaV3oAH` (live, EXEC both clusters); `legacy-memo-program.json` → `Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo` (the true legacy memo — re-verified EXEC on both clusters 2026-08-08, superseded not retired, see C10); pin test + `extreme_adversarial.rs` const + README table updated with an on-chain-dated comment.
- **Regression test:** the 15-ID pin test now asserts the corrected IDs (13 manifest tests green); README/ROADMAP claims corrected.
- **Why existing tests missed it:** the pin test compared manifests against each other's stored strings, not against chain state.

### C2. AUDITBIND SWAP-PATH TOCTOU COVERAGE (hardened)
- **Finding:** `executeSwap` originally verified only `programId + discriminator + wallet` — the SAK-built swap's instruction data and full account list were not part of the checked projection.
- **Fix (2026-08-08):** AuditBind now exposes `projectionFromInstruction` + `verifyInstruction` — a pure, tested capability that binds the EXACT instruction (full account list + raw data bytes) — and the bridge's `executeSwap` accepts a built payload and binds it; with `GRAPHITE_SWAP_STRICT=1` the opaque SAK path FAILS CLOSED unless a payload is supplied. 8/8 AuditBind tests (incl. 4 new: discriminator extraction, exact-payload binding, data/account mutation aborts, empty-data parity).
- **Residual:** binding requires the caller to supply the real payload; a fully automatic pre-submit hook needs an executor-side build API (Phase 3).

### C3. REGISTRY / RUNTIME DISCRIMINATOR SCHEMA DIVERGENCE (documented)
- The registry's `validate_manifest` requires a non-empty discriminator per instruction; the runtime loader allows empty (Memo's raw-UTF-8 design). Consequence: memo-style manifests cannot be enshrined via the registry. This is fail-closed and acceptable, but undocumented — the report records it as a deliberate stricter-registry contract.

### C2b. DYNAMIC PDA SEED RESOLUTION — CAPABILITY PROVEN, PROTOCOL GROUNDING REMAINS
- The resolver already supported `{instruction_data}`, `{instruction_data:start:end}`, `{instruction_data:start}` templates, but they were UNTESTED and unused (a function existing ≠ implemented).
- **Now tested:** 5 deterministic tests with known-answer PDAs pinned from the OFFICIAL Solana JS SDK (cross-checked equal to the Rust canonical derivation — `UnoGavu…` matches both) plus a false-positive guard (mutated data → different PDA → mismatch flagged).
- **On-chain ground truth (2026-08-08):** devnet Squads V4 transactions all fail `InstructionError` (stale program), and Jupiter DCA `openDca` PDAs did not match candidate data-seed layouts — so NO manifest declares data-derived seeds yet (fabricating offsets would violate the audit's own honesty bar). Protocol-specific seed layouts require the program source/IDL — a documented Phase-3 data task, not a code gap.

### C3b. REGISTRY / RUNTIME DISCRIMINATOR DIVERGENCE (now explicit)
- The registry's `validate_manifest` rejects empty discriminators with an error that now names the exception: raw-UTF-8-data programs (Memo-style) must be onboarded via the seed registry, not community submission. Fail-closed and documented in the error itself.

### C8. PYTHON AI-LAYER CROSS-CHECK STALE + LATENT FALSE-EQUALITY (found via CI-equivalent run, fixed)
- **Symptom:** `test_program_ids_match_manifests` failed only after the memo/expansion work — hardcoded `11` manifests against the 15 now shipped.
- **Root cause 1 (stale):** the test asserted `len(manifests) == 11`; the protocol expansion to 15 (Pump.fun, Jupiter DCA, Wormhole, Metaplex) never propagated to the Python layer — a cross-component integration break.
- **Root cause 2 (latent, masked):** for non-canonical swap manifests (Raydium/Orca/Meteora) the test asserted `parse_intent("swap") == manifest.program_id`, but the AI layer's canonical swap suggestion is Jupiter's ID — the assertion was wrong by construction and only passed because the count assert short-circuited first.
- **Fix:** exact 15-manifest set assertion (fails loudly on add/remove drift), honest group cross-check (AI-layer suggestion must be backed by SOME manifest declaring that intent), duplicate-ID detection replacing the pass-stub, and the 4 new manifests mapped to `None` (no AI-layer intent exists for mint/bridge/DCA yet).
- **Regression test:** 7/7 Python tests green locally and on CI.

### C9. DEAD CODE UNDER THE `cli`-ONLY FEATURE GATE (fixed)
- `load_corpus_for_seed` was ungated but only reachable from the rpc-gated `run_regression_seed_live` and tests — the `cargo check --no-default-features --features cli` gate emitted a dead-code warning (CI would have failed it).
- **Fix:** `#[cfg(any(feature = "rpc", test))]` — present for the rpc path and tests, excluded from the cli-only library build.

### C10. "RETIRED MEMO" DOCUMENTATION CLAIM WAS FACTUALLY WRONG (fixed)
- **Symptom:** the report/README/manifest labeled `Memo1UhkJRf…` (legacy memo) "retired", and the manifest carried `retired_on_mainnet: true`.
- **Root cause:** the label was inherited from historical prose, not from chain state. The previous cycle's own live check already showed 14 EXEC (which included `Memo1UhkJRf…`) — the "1 retired" slot was an unverified assumption, the same self-referential-documentation failure mode as C1.
- **Live evidence (2026-08-08):** `getAccountInfo` → `executable=true` for `Memo1UhkJRf…` on BOTH mainnet and devnet (owner BPFLoader, full program bytes present). It is superseded in ecosystem use by `Memo4c2pN8af…`, but NOT retired.
- **Fix:** manifest marker → `superseded: true` + dated note; `manifest.rs` pin-test comment corrected; README table "legacy SPL, superseded"; report rows corrected; `scripts/live_revalidate.py` added so the claim is re-checkable with one command.
- **Regression test:** the 15-ID pin test (assertions unchanged — the IDs were already correct; the wrong part was the prose).

### C11. REGISTRY SUBMISSION HAD NO SIZE CAPS — RESOURCE EXHAUSTION (fixed)
- **Root cause:** `validate_manifest` only checked non-empty instructions + non-empty discriminators; a community submission could carry unbounded instruction/account/list payloads through hashing, serialization, and graph storage (memory + CPU DoS on an operator-facing surface).
- **Fix:** caps in `validate_manifest` — ≤512 instructions, ≤256 accounts/instruction, ≤128 chars per name/discriminator, ≤64 items per list (allowed_cpis / state_changes / risk_rules / pda_seeds); every cap errors with a named "resource-exhaustion guard" message.
- **Regression test:** `registry_rejects_resource_exhaustion_manifest` — a 1000-instruction manifest and a 300-account instruction are rejected cleanly; a normal manifest still passes (no false positives).

### C12. VERIFY_ASYNC IS A READ-ONLY SCORER (documented, by design)
- **Measured:** the semantic graph has exactly ONE `append` site (the sync `verify` used by CLI/benchmark); `verify_async` (the HTTP path) reads evidence but never appends behaviors. The concurrency storm proved it: 200 HTTP verifies → 0 new graph behaviors, 200/200 durable audit records.
- **Assessment:** not a defect — evidence is *earned* via operator-seeded baselines, L3 simulation recording (`record_simulation` runs inside `verify_async`), and registry submissions; the audit log is the per-event record. Recording every HTTP verify into the graph without replay-dedup would let a client mint `battle_tested` evidence by replaying the same transaction — the current split prevents that.
- **Open question (Phase 3):** if the HTTP surface should mint earned evidence, append with content-hash replay dedup and independent-credibility checks.

### C7. DASHBOARD BUILT INDEX.HTML RENDERED BLANK (fixed)
- **Root cause:** the Vite build emitted absolute `/assets/…` URLs (no `base`), so opening `dist/index.html` via `file://` or serving from a subpath produced a blank page (script 404).
- **Fix:** `base: "./"` in `vite.config.ts`; rebuilt output now references `./assets/…` and renders from any path.

### C4. LIVE-DATA HEURISTIC WEAKNESS IN TX-TO-INPUT (fixed by construction)
- The original live-corpus reader picked the **first** instruction with accounts — on real blocks that is the System fee payment, not the protocol call (proven by the pinned fixtures). The production reader now selects **preferred known-manifest program → else the most-accounted instruction**, with hostile-shape fuzz coverage.

### C6. SEED-LIVE CORPUS LOAD SWALLOWED CORRUPTION → SILENT DATA LOSS (found in review, fixed)
- **Root cause:** `run_regression_seed_live` matched `Err(_)` on corpus load and started fresh on ANY failure — including `CorruptFixture`. Because `load_from_dir` loads valid files before hitting a corrupt one, and `save_to_dir` then snapshots the in-memory corpus per program, a partially corrupt corpus would be silently reset and the valid programs' fixtures overwritten/dropped.
- **Fix:** `load_corpus_for_seed` distinguishes `MissingDirectory` (fresh first-run, OK) from `CorruptFixture`/`InvalidFixture` (abort, nothing written). Deterministic test added (`seed_live_corpus_load_fails_closed_on_corruption`).

### C5. O(n) AUDIT-LOG READ (fixed in the prior hardening pass, re-validated here)
- Bounded `read_tail_filtered` (capped tail + true totals, torn-line isolation) and streaming `observations_by_program` — the dashboard endpoints never materialize the whole log.

---

## D. Engineering Skill / Phase-2 Roadmap Compliance Audit

| Requirement (roadmap) | Status | Evidence | Missing work |
|---|---|---|---|
| 15 manifests, IDs on-chain verified | **Implemented** (corrected) | live getAccountInfo 15/15 EXEC re-verified 2026-08-08; memo swap fixed; C10 corrected the "retired" prose | — |
| Feed actual transaction data through Graphite | **Implemented** (new) | `live_corpus.rs`, `regression seed-live`, 30 live devnet verifies, 3 pinned real mainnet fixtures | — |
| Regression Engine corpus + replay + P10 gate | **Implemented** | 20 real fixtures replayed 100%, PROMOTE; deterministic replay | 1,000-fixture volume (data acquisition), 10k cost model |
| Manifest Registry: signed submissions, G5, P7/P10/P11 | **Implemented** (operator path, new CLI) | register-reviewer / submit / reviewers live-verified ACCEPT/REJECT | PR-based community workflow + on-chain stake lookup (Phase 3 by design) |
| Plugin framework: 6 interfaces + 2 real plugins, P8 | **Implemented** | plugin_framework.rs, H25 coverage, benchmark shows ~0 overhead | true third-party submissions (Phase 3) |
| Policy Engine 4 profiles + integrations | **Implemented** | 14 profile-matrix tests; SAK bridge wiring | — |
| Dashboard (read-only, 5 views) | **Implemented** | 6 endpoint tests, live E2E, auth live-verified, CI typecheck+build job (C7) | real-time (Phase 3) |
| AuditBind TOCTOU middleware | **Implemented** | auditbind.ts + pinned cross-language vectors; devnet execution verified | swap-payload projection (C2) |
| L3 Simulation active in production | **Partial** | simulateTransaction wired in verify path; SAK feeds CU/writes/hops | production activation gate |
| L8 Execution Verification | **Missing** | requires a live executor | executor integration (Phase 3) |
| Dynamic PDA seed resolution | **Missing** | manifests use static templates only (documented false-positive avoidance) | runtime instruction-data seed parsing (Squads V4 proposals) |
| Benchmark uses real on-chain data | **Partial** | real-data corpus + replay proven; P16 deterministic benchmark stays synthetic **by design** | decide the P16-compatible "real-data evidence" story |

---

## E. Independent Reconstruction (first principles → comparison)

**What Graphite must fundamentally be:** a deterministic, evidence-derived, append-only verification gate that (a) maps a proposed intent to a real transaction shape, (b) prices trust ONLY from earned evidence (P7) against exact program IDs (P11), (c) blocks by risk pattern regardless of confidence, (d) leaves an uneditable audit trail, (e) lets protocols and communities contribute manifests without ever self-asserting tier, and (f) can prove on real data that it behaves.

**Independent architecture requires:** an evidence store (Semantic Graph — exists, append-only P4 ✓), a registry with independent-reviewer economics (exists + now operator-reachable ✓), a plugin boundary enforced by types not convention (exists, P8 ✓), a regression gate keyed to promotion (exists, P10 ✓), a bounded observability surface (exists ✓), and a real-data ingestion path (now exists ✓).

**Gaps the reconstruction surfaced that the codebase did not have:**
1. **No operator-reachable registry submission path** — the engine's `submit()` was library-only. **Built:** `graphite registry register-reviewer|submit|reviewers` with JSON state persistence shared with the server contract.
2. **No real on-chain data path into the corpus/benchmark evidence chain.** **Built:** `live_corpus` module + `graphite regression seed-live`, pinned real fixtures, live-verified.
3. **The fabricated memo ID** — a trust-store data-integrity defect the pinning test could not see. **Fixed** with on-chain-corrected pins.
4. **Reconstruction-independent review of the "on-chain-verified" documentation claim:** the docs claimed all manifest IDs were on-chain verified; the memo pair proves this was partially self-referential. Corrected and re-verified live.

**Modules rebuilt/replaced:** none were fundamentally flawed — the reconstruction validated the existing architecture and filled integration gaps rather than replacing subsystems.

---

## F. Performance (measured 2026-08-08, release build)

| Metric | Value |
|---|---|
| Benchmark scored cases | 16/16 correct — precision 100%, recall 100% |
| Average verify latency | **989μs** (range 817–1353μs per case) |
| Latency percentiles (release) | p50 **945μs** / p95 **1330μs** / p99 **1490μs** |
| Sequential throughput | **1011 verifies/s** in-process (pipeline only) |
| HTTP concurrency (8 workers × 25 + 16 dashboard reads) | **246 verifies/s** end-to-end; 0 5xx; 200/200 durable audit records (C12 evidence) |
| Plugin overhead | 884.80μs/verify (2 plugins) vs 903.99μs bare — Δ −2.1% (noise; plugins add no measurable cost) |
| Bounded audit read | capped tail, true totals, torn-line isolation (per-CPU bounded memory) |
| Live corpus per-tx cost | dominated by RPC `getBlock` fetch, not the pipeline |

Bottleneck: RPC round-trips for block fetching dominate live seeding; the verification pipeline itself is sub-millisecond.

---

## G. Remaining Risks

1. **L8 Execution Verification** — not implementable without a live executor; the TOCTOU window between verification and execution is only partially closed: the payload-binding capability + `GRAPHITE_SWAP_STRICT` fail-closed mode exist, but a fully automatic pre-submit hook needs an executor-side build API (Phase 3 AuditBind v2).
2. **Dynamic PDA seeds — protocol grounding** — the extraction capability is now implemented and tested; Squads V4 (devnet currently errors) and Jupiter DCA seed layouts could not be confirmed from observed on-chain data on 2026-08-08, so no manifest declares data-derived seeds. Confirming the layouts needs the programs' IDL/source (Phase 3 data task).
3. **Benchmark synthetic-by-design** — P16 reproducibility conflicts with "real-data benchmark"; the real-data replay evidence path is the honest bridge, but the exit criterion wording is only partially met until that is formalized.
4. **1,000-fixture corpus volume** — a data acquisition problem, not an engineering one.
5. **Sybil residual (G5)** — N genuinely staked identities can still pass; the Tier-5 volume backstop holds; on-chain stake lookup is Phase 3.
6. **Registry state persistence is file-based** — no replication; an operator deploying the registry to multiple nodes must share/exclude the state file explicitly.
7. **Dashboard index.html** — fixed (relative base); dev-proxy flow, built artifact, and a new CI build job all verify it. The dashboard is now covered by CI (typecheck + production build).
8. **HTTP evidence-earning asymmetry (C12)** — the HTTP /verify surface records to the audit log but never appends earned graph evidence; evidence is written by the operator-seeded/L3/registry paths. Deliberate (prevents replay-minted evidence), but revisit with content-hash dedup if the API should earn evidence (Phase 3).
9. **Concurrency throughput ceiling** — the global semantic-graph mutex is taken ~6× per verify; measured 246 verifies/s end-to-end single-node (the in-process pipeline alone is ~1000/s). Fine for Phase 2; shard per-program locks or an append buffer for higher sustained throughput.
