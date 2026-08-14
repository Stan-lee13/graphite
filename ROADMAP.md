# Graphite — Roadmap

## Phase 1 (COMPLETE — v0.1.0-alpha, frozen)

- [x] Core verification engine (Rust)
- [x] 8-layer pipeline (L1-L7 active, L3/L8 live-validated in Phase 2)
- [x] 33 protocol manifests (16 base + Tier-0: ATA, Compute Budget, BPF Loaders + Drift, Kamino, Phoenix, OpenBook V2, Switchboard, Jupiter Limit, Solend, Marginfi + C56: Raydium CLMM/CPMM, Marinade, SPL Stake Pool, Orca TokenSwap V2)
- [x] Risk engine: 11 attack pattern detectors (14 risk checks)
- [x] Confidence engine with 0.55 cap on unknown protocols (P6/P12)
- [x] Policy engine: 4 wallet profiles (Treasury, TradingBot, Gaming, Enterprise)
- [x] Policy engine real integrations: evidence signals read the Semantic Graph accumulator (G4), all 4 presets satisfiable/differentiable, CLI `--profile` + `profiles`, 14 profile-matrix tests
- [x] TypeScript SDK
- [x] Go SDK (full VerificationResult parity — 19 fields)
- [x] Python advisory layer (separate process — P1 compliance)
- [x] HTTP server (axum) + CLI (clap)
- [x] Dockerfile + .dockerignore
- [x] 987 unit/integration tests passing, 0 clippy warnings (2026-08-11)

### Phase 1 Honest Status

The benchmark is 16 scored cases (safe + malicious) plus 2 baseline comparisons — NOT a
statistical evaluation on unseen data. "100% precision / 100% recall on scored cases" is
the honest claim. Of the exploit cases, 2 are SYNTHETIC reconstructions (CLINKSINK-style,
AAT-style) using real program IDs but fabricated account structures and no
instruction data bytes. The other 3 are REAL mainnet data (Wormhole $320M hack,
CLINKSINK STMT drainer TX 64tsGGe, SlowMist AAT drainer TX 524t8LW) with actual
instruction data from published security research. All are labeled per P16.

### TOCTOU Mitigation (Phase 1.5 Partial)

The `content_hash` field is a SHA-256 hash of the transaction configuration — program ID, instruction discriminator, account addresses, instruction data, and CPI targets. This means each verification result is cryptographically tied to the exact transaction it verified.

**Phase 1.5 limitation:** Graphite verifies the transaction structure but does not re-hash the final signed transaction against the approved `content_hash` before execution. Full TOCTOU prevention requires the executor (SAK integration) to verify that the executed transaction matches the verified one — Phase 2 AuditBind middleware.

## Phase 1.5 (COMPLETE — devnet verified Aug 7, 2026)

- [x] Extreme adversarial test suite (50+ tests)
- [x] Real exploit pattern reconstructions (5 classes, honestly labeled SYNTHETIC)
- [x] SAK integration rebuilt with real solana-agent-kit v2 imports — **VERIFIED ON DEVNET**
- [x] Pre-flight account reconstruction (wallet authority always present)
- [x] Case-sensitive intent parsing (Solana addresses are case-sensitive)
- [x] content_hash field for deterministic verification (P2)
- [x] .github CI templates + issue templates
- [x] LICENSE, SECURITY.md, CONTRIBUTING.md

### Phase 1.5 Honest Status

The SAK integration is code-complete with real imports and **verified on Solana devnet (Aug 7, 2026)**:
- Imports `solana-agent-kit` v2 (real npm package, not an HTTP wrapper)
- Imports `@solana-agent-kit/plugin-token` and `@solana-agent-kit/plugin-defi`
- Uses real SAK API: `SolanaAgentKit`, `KeypairWallet`, `.use()`, `.methods.swap()`
- Imports the Graphite TS SDK (`GraphiteClient`)
- Every transaction goes through Graphite verification before SAK execution
- Pre-flight account reconstruction: wallet authority + program IDs always present
- If Graphite blocks, the transaction is NOT submitted to the network
- **5 finalized transactions on Solana devnet** (2 faucet airdrops + 3 SAK test transfers),
  wallet `CWb8MciizembLV66kisYcXo3Cb91hdszxw74QHpEJKZR` — latest signature
  `xHa4dyuFS6JmSaTsmhcMpEtwbWnPjBoUGwk3wNixD2uw2Wmeui6GhnSmmdzNVkv85zXSd6g7QYhHymAjciwP3jJ`
  confirmed and finalized. SAK → Graphite pipeline confirmed end-to-end.

### Phase 1.5 Exit Criteria (all checked)

- [x] Extreme adversarial test suite (50+ tests)
- [x] Real exploit pattern reconstructions (5 classes, honestly labeled SYNTHETIC)
- [x] SAK integration rebuilt with real solana-agent-kit v2 imports
- [x] SAK integration verified on Solana devnet (5 finalized transactions, Aug 7 2026)
- [x] Pre-flight account reconstruction (wallet authority always present)
- [x] Case-sensitive intent parsing (Solana addresses are case-sensitive)
- [x] content_hash field for deterministic verification (P2)
- [x] .github CI templates + issue templates
- [x] LICENSE, SECURITY.md, CONTRIBUTING.md
- [x] 1,007 tests passing, 0 clippy warnings, fmt clean (2026-08-12)
- [x] Server hardening: constant-time bearer auth, per-IP rate limiting, CORS denied by default, JSONL audit log
- [x] RPC client live-verified against Helius (mainnet + devnet)

## Phase 2 (COMPLETE — v0.2.0-beta tagged at C54)

### Month 1: Real Data + Protocol Expansion
- [x] Fetch REAL exploit transactions from Solana RPC (raw instruction bytes) — 3 pinned mainnet exploits scored in the benchmark (C30); 35 real mainnet exploit signatures from SolPhishHunter arXiv:2505.04094 + 3 real successful mainnet txs in the holdout corpus (C41); **C52 fetched 2 more live from api.mainnet-beta.solana.com** — fresh Aug-2026 drainer chain TX 2AWwL6dk (unknown 8MjG72/GieMfa5 + known HELPER, real Token-2022 mintTo) + AAT mass drain TX 3PbK87 (20 calls, real disc 0e) — exploit corpus now 37, both scored as REAL benchmark cases with raw evidence in scripts/real_exploit_*.json
- [x] Feed actual transaction data through Graphite (not synthetic reconstructions) — `src/live_corpus.rs` + `graphite regression seed-live` (2026-08-08): live devnet verified=20 / recorded=20, live test verified 10 real devnet txs, 3 pinned REAL mainnet fixtures (Jupiter swap, pump.fun market, System) through the full pipeline
- [x] Add 6 more protocol manifests (Pump.fun, Jupiter DCA, Wormhole Core, Metaplex Token Metadata — C27; Drift + Kamino — C42): 22 total at the time; **28 total with C46** (Phoenix, OpenBook V2, Switchboard, Jupiter Limit, Solend, Marginfi); **33 total with C56** (Raydium CLMM/CPMM, Marinade, SPL Stake Pool, Orca TokenSwap V2), all program IDs confirmed executable on mainnet
- [x] Regression Engine core: append-only fixture corpus, deterministic replay, P10 promotion gate (99.5%), benchmark-seeded initial corpus, `graphite regression` CLI gate — 12 tests (2026-08-07)
- [x] Replace synthetic exploit tests with real on-chain data — 3 REAL mainnet exploit cases (STMT drainer 64tsGGe, AAT drainer 524t8LW, Wormhole $320M hack 5fKWY7X) scored in the P16 benchmark binary, replacing 3 of 5 SYNTHETIC reconstructions (C30); 2 SYNTHETIC remain, honestly labeled
- [x] Multi-instruction transaction analysis — coordinated mass-drain patterns ACROSS instructions in one tx (AAT approve+transfer, authority-hijack SetAuthority+Transfer, close-and-sweep, mass multi-transfer sweep, AAT ownership-theft via System assign) — hard gates (C29)
- [x] CPI instruction trace analysis — unknown, re-entered (compositional), or vanity-impersonated programs in the hierarchical CPI tree; deep-chain warning — hard gates except the depth warning (C29)
- [x] **Dynamic PDA seed resolution**: extraction capability implemented + tested (2026-08-08) — `{instruction_data}`, `{instruction_data:start:end}`, `{instruction_data:start}` templates, 5 tests with known-answer PDAs pinned from the official Solana JS SDK + a false-positive guard. (C42: Kamino V2 lending_market_authority PDA seeds verified and added. **C52: Jupiter DCA + Squads V4 layouts confirmed from official IDL/source and VERIFIED against live mainnet** — DCA `["dca", user, inputMint, outputMint, uid]` derives exactly the live account; Squads `["multisig", "multisig", createKey]` derives exactly the real multisig; both manifests rebuilt with correct account order/roles; 4 new known-answer PDA tests.)

### Month 2: Manifest Registry + Plugin Framework
- [x] Manifest Registry with signature verification + G5 reviewer reputation — `graphite registry register-reviewer|submit|reviewers` operator CLI (2026-08-08), live-verified signed submission ACCEPTED at derived tier
- [ ] Community submission workflow (PR-based) — Phase 3
- [x] Plugin framework: 6 interfaces
- [x] 2 real reference plugins
- [x] AuditBind middleware (TOCTOU prevention — re-hash signed tx vs approved content_hash)

### Month 3: Live Integration + Dashboard
- [x] Live SAK integration on devnet — **re-verified on-chain Aug 8, 2026** (signature `xHa4dyuFS6JmSaTsmhcMpEtwbWnPjBoUGwk3wNixD2uw2Wmeui6GhnSmmdzNVkv85zXSd6g7QYhHymAjciwP3jJ` re-fetched: finalized System transfer, slot 481727834)
- [x] L3 Simulation Verification live-validated against real RPC — `tests/l3_live_simulation.rs` (C40): real simulateTransaction returns a result, partial/no-baseline results are non-events, malformed payloads fail safely
- [x] L8 Execution Verification live-validated against mainnet — `tests/l8_live_mainnet.rs` (C40): Confirmed (real signature, slot 438408575), UnknownSignature (fabricated), Unavailable (unreachable RPC)
- [x] React dashboard showing live verification state (read-only /api endpoints + 5 views)
- [x] 1,000+ meaningful regression fixtures — **2,747-fixture corpus** (C41 + C52): dev 2,676 (manifest-driven synthetic) + regression 31 (re-pinned attack classes) + holdout 40 (37 real mainnet exploits — 35 SolPhishHunter + 2 live-fetched — + 3 real mainnet txs, independently labeled, never used for tuning); replay 0 divergences, byte-identical across runs (C42 registry determinism fix)
- [x] Real holdout evaluation — holdout n=38: precision 1.000, recall 1.000, F1 1.000, 0 false negatives (C41)
- [x] 22-manifest revalidation — all program IDs base58-decode to 32 bytes; Kamino V2 stub layouts rebuilt from live on-chain decoded streams (C42); Orca roles fixed to real SDK layouts (C41); universal-CPI audit: infra exclusion is per-target and cannot shield a malicious caller (C42)
- [x] Public deployment endpoint — **image builds + runs + security-tested live (C54)**: the Dockerfile had 3 real defects (toolchain pinned too old for the locked clap tree; `--features server` never built the `graphite` bin which requires `cli`; wrong target-dir COPY path) — all fixed; `docker build` now succeeds (185MB), container runs non-root (uid 999), HEALTHCHECK healthy, and auth (401s), rate limiting (429 on concurrent burst), CORS default-deny + allowlist, audit log, and hostile/oversized bodies (422/413, server survives) were verified against the deployed container. Still no public internet endpoint — TLS/DNS/monitoring are reverse-proxy platform concerns, documented in docker-compose.yml
- [x] Phase 2 certification — report upgraded **CONDITIONAL GO → GO** (docs/phase2-certification-report.md, §7/§10/§11)
- [x] Tag v0.2.0-beta — tagged at C54 (Cargo.toml 0.1.1 → 0.2.0-beta)

### Phase 2 Exit Criteria
- [x] Benchmark uses real on-chain transaction data — **5 REAL mainnet exploit cases** (STMT drainer 64tsGGe, AAT drainer 524t8LW, Wormhole $320M hack 5fKWY7X, fresh Aug-2026 drainer chain 2AWwL6dk, AAT mass drain 3PbK87) pinned in the P16 benchmark binary from `tests/real_onchain_exploits.rs` + live-fetched `scripts/real_exploit_*.json` (real program IDs, accounts, CPI structure; reproducible offline), replacing 3 of the 5 SYNTHETIC reconstructions; 2 SYNTHETIC cases remain, honestly labeled, for classes not yet pinned from mainnet
- [x] SAK integration executes real devnet transactions after Graphite approval — 5 finalized devnet txs, re-verified on-chain 2026-08-08
- [x] Protocol Manifest Registry accepts signed community submissions — CLI operator path live-verified (signed → ACCEPTED at derived tier; unregistered → REJECTED)
- [x] Plugin framework has 2+ real plugins
- [x] L3 and L8 pipeline layers live-validated — L3 against real devnet RPC, L8 against real mainnet RPC (C40); production default-on wiring remains pending public deployment
- [x] TOCTOU prevention via AuditBind middleware
- [x] Dashboard shows live verification state
- [x] 1,000+ meaningful regression fixtures (2,181 corpus, C41)
- [x] Real holdout evaluation with independent labels (38 fixtures, 0 FN, C41)

## Phase 3+ (Future)

- **Phase 3 (Production):** Mainnet deployment, professional security audit, enterprise integrations
- **Phase 4 (Ecosystem):** Standard verification layer for Solana AI agents
- **Phase 5 (Multi-chain, exploratory):** Evaluate SVM-compatible chains only — full rewrite required for non-SVM chains
