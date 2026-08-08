# Graphite — Roadmap

## Phase 1 (COMPLETE — v0.1.0-alpha, frozen)

- [x] Core verification engine (Rust)
- [x] 8-layer pipeline (L1-L7 active, L3/L8 Phase 2)
- [x] 15 seed protocol manifests (11 Phase 1 + Pump.fun, Jupiter DCA, Wormhole Core, Metaplex Token Metadata added Phase 2 Month 1)
- [x] Risk engine: 8 attack pattern detectors
- [x] Confidence engine with 0.55 cap on unknown protocols (P6/P12)
- [x] Policy engine: 4 wallet profiles (Treasury, TradingBot, Gaming, Enterprise)
- [x] Policy engine real integrations: evidence signals read the Semantic Graph accumulator (G4), all 4 presets satisfiable/differentiable, CLI `--profile` + `profiles`, 14 profile-matrix tests
- [x] TypeScript SDK
- [x] Go SDK (full VerificationResult parity — 16 fields)
- [x] Python advisory layer (separate process — P1 compliance)
- [x] HTTP server (axum) + CLI (clap)
- [x] Dockerfile + .dockerignore
- [x] 819 unit/integration tests passing, 0 clippy warnings

### Phase 1 Honest Status

The benchmark is 16 scored cases (safe + malicious) plus 2 baseline comparisons — NOT a
statistical evaluation on unseen data. "100% precision / 100% recall on scored cases" is
the honest claim. The 5 exploit reconstructions (CLINKSINK, AAT, Wormhole) use real
program IDs but fabricated account structures and no instruction data bytes.
They are labeled "SYNTHETIC" per P16.

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
- [x] 819 tests passing, 0 clippy warnings, fmt clean
- [x] Server hardening: constant-time bearer auth, per-IP rate limiting, CORS denied by default, JSONL audit log
- [x] RPC client live-verified against Helius (mainnet + devnet)

## Phase 2 (PLANNED — branch: phase2-development)

### Month 1: Real Data + Protocol Expansion
- [ ] Fetch REAL exploit transactions from Solana RPC (raw instruction bytes) — real txs now flow through; exploit-class reconstruction still synthetic
- [x] Feed actual transaction data through Graphite (not synthetic reconstructions) — `src/live_corpus.rs` + `graphite regression seed-live` (2026-08-08): live devnet verified=20 / recorded=20, live test verified 10 real devnet txs, 3 pinned REAL mainnet fixtures (Jupiter swap, pump.fun market, System) through the full pipeline
- [x] Add 4 more protocol manifests (Pump.fun, Jupiter DCA, Wormhole Core, Metaplex Token Metadata — program IDs confirmed executable on mainnet 2026-08-07); 15 total now, expansion toward 20 continues
- [x] Regression Engine core: append-only fixture corpus, deterministic replay, P10 promotion gate (99.5%), benchmark-seeded initial corpus, `graphite regression` CLI gate — 12 tests (2026-08-07)
- [ ] Replace synthetic exploit tests with real on-chain data
- [~] **Dynamic PDA seed resolution**: extraction capability implemented + tested (2026-08-08) — `{instruction_data}`, `{instruction_data:start:end}`, `{instruction_data:start}` templates, 5 tests with known-answer PDAs pinned from the official Solana JS SDK + a false-positive guard. Remaining: confirming real protocol seed layouts (Squads V4 devnet txs currently error; Jupiter DCA layout unmatched by candidates) — a Phase 3 IDL/source data task.

### Month 2: Manifest Registry + Plugin Framework
- [x] Manifest Registry with signature verification + G5 reviewer reputation — `graphite registry register-reviewer|submit|reviewers` operator CLI (2026-08-08), live-verified signed submission ACCEPTED at derived tier
- [ ] Community submission workflow (PR-based) — Phase 3 as planned
- [x] Plugin framework: 6 interfaces
- [x] 2 real reference plugins
- [x] AuditBind middleware (TOCTOU prevention — re-hash signed tx vs approved content_hash)

### Month 3: Live Integration + Dashboard
- [x] Live SAK integration on devnet — **re-verified on-chain Aug 8, 2026** (signature `xHa4dyuFS6JmSaTsmhcMpEtwbWnPjBoUGwk3wNixD2uw2Wmeui6GhnSmmdzNVkv85zXSd6g7QYhHymAjciwP3jJ` re-fetched: finalized System transfer, slot 481727834)
- [ ] L3 Simulation Verification fully active in production (RPC wiring exists; production activation is Phase 2 exit)
- [ ] L8 Execution Verification active (requires live execution)
- [x] React dashboard showing live verification state (read-only /api endpoints + 5 views)
- [ ] Phase 2 certification
- [ ] Tag v0.2.0-beta

### Phase 2 Exit Criteria
- [~] Benchmark uses real on-chain transaction data — REAL data infrastructure done (`seed-live` + pinned real-tx tests + 20 real fixtures replayed 100%); the P16 deterministic benchmark binary itself stays synthetic BY DESIGN (reproducibility) — real-data replay is the honest evidence path
- [x] SAK integration executes real devnet transactions after Graphite approval — 5 finalized devnet txs, re-verified on-chain 2026-08-08
- [x] Protocol Manifest Registry accepts signed community submissions — CLI operator path live-verified (signed → ACCEPTED at derived tier; unregistered → REJECTED)
- [x] Plugin framework has 2+ real plugins
- [ ] L3 and L8 pipeline layers active — L3 wired (RPC simulateTransaction) but needs production activation; L8 requires live execution
- [x] TOCTOU prevention via AuditBind middleware
- [x] Dashboard shows live verification state

## Phase 3+ (Future)

- **Phase 3 (Production):** Mainnet deployment, professional security audit, enterprise integrations
- **Phase 4 (Ecosystem):** Standard verification layer for Solana AI agents
- **Phase 5 (Multi-chain, exploratory):** Evaluate SVM-compatible chains only — full rewrite required for non-SVM chains
