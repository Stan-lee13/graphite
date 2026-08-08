# Graphite — Full Production Forensic Audit & Independent Reconstruction

**Date:** 2026-08-08
**Branch:** `phase2-development`
**Method:** adversarial real-world validation, live RPC evidence, root-cause investigation, roadmap/skill compliance audit, first-principles reconstruction, gap implementation, full re-validation loop.

---

## A. System Health

| Signal | Result |
|---|---|
| Full Rust test suite | **829 passed / 0 failed** (23 binaries) |
| clippy `--all-targets --all-features -D warnings` | 0 warnings |
| `cargo fmt --check` | clean |
| `cargo check --no-default-features` (CI gate) | clean |
| Benchmark (P16) | 16/16 scored cases, 100% precision / 100% recall, avg **1002μs**/verify |
| Live mainnet program IDs | 14/15 executable live; 1 legitimately retired (documented) |
| Live devnet pipeline | 30 verification events over real devnet transactions (10 live test + 20 `seed-live`; the two runs walk overlapping recent blocks, so distinct-tx count may be less) |

**Overall status: production-capable for the Phase-2 feature set, with three honest caveats** — dynamic PDA seed resolution (roadmap open item), L8 execution verification (requires a live executor), and the P16 deterministic benchmark remaining synthetic by design. All exit criteria that CAN be met without those are now met and evidence-backed.

**Critical finding:** one root-level data defect (swapped/fabricated memo program IDs — see C1) was discovered and fixed.

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

---

## C. Root-Level Findings

### C1. SWAPPED / FABRICATED MEMO PROGRAM IDS (fixed)
- **Symptom:** the canonical-ID pin test passed while one seed manifest pointed at a program that does not exist.
- **Root cause:** `memo-program.json` pinned `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr` (never existed on mainnet or devnet — verified `getAccountInfo` ABSENT on both), while `legacy-memo-program.json` pinned `Memo4c2pN8afCj432Lb7RMVKi9PbQnnW7ewFFaV3oAH` (the LIVE memo program). The "on-chain-verified" pin test was written **from the manifests themselves** (self-referential), not from on-chain data — so it codified the wrong data.
- **Impact:** real memo transactions (which use `Memo4c2pN8af...`) would not match the "Memo Program" manifest, and the "legacy" manifest mislabeled the live program. Dead trust weight + mislabeled identity.
- **Fix:** `memo-program.json` → `Memo4c2pN8afCj432Lb7RMVKi9PbQnnW7ewFFaV3oAH` (live, EXEC both clusters); `legacy-memo-program.json` → `Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo` (the true retired legacy memo, documented `retired_on_mainnet`); pin test + `extreme_adversarial.rs` const + README table updated with an on-chain-dated comment.
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
| 15 manifests, IDs on-chain verified | **Implemented** (corrected) | live getAccountInfo 14 EXEC + 1 retired; memo swap fixed | — |
| Feed actual transaction data through Graphite | **Implemented** (new) | `live_corpus.rs`, `regression seed-live`, 30 live devnet verifies, 3 pinned real mainnet fixtures | — |
| Regression Engine corpus + replay + P10 gate | **Implemented** | 20 real fixtures replayed 100%, PROMOTE; deterministic replay | 1,000-fixture volume (data acquisition), 10k cost model |
| Manifest Registry: signed submissions, G5, P7/P10/P11 | **Implemented** (operator path, new CLI) | register-reviewer / submit / reviewers live-verified ACCEPT/REJECT | PR-based community workflow + on-chain stake lookup (Phase 3 by design) |
| Plugin framework: 6 interfaces + 2 real plugins, P8 | **Implemented** | plugin_framework.rs, H25 coverage, benchmark shows ~0 overhead | true third-party submissions (Phase 3) |
| Policy Engine 4 profiles + integrations | **Implemented** | 14 profile-matrix tests; SAK bridge wiring | — |
| Dashboard (read-only, 5 views) | **Implemented** | 6 endpoint tests, live E2E, auth live-verified | real-time (Phase 3) |
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
| Average verify latency | **1002μs** (range 817–1353μs per case) |
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
7. **Dashboard index.html** — fixed (relative base); the dev-proxy flow and the built artifact both verified.
