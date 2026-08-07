# Graphite — Roadmap

## Phase 1 (COMPLETE — v0.1.0-alpha, frozen)

- [x] Core verification engine (Rust)
- [x] 8-layer pipeline (L1-L7 active, L3/L8 Phase 2)
- [x] 11 seed protocol manifests (10 + legacy Memo)
- [x] Risk engine: 8 attack pattern detectors
- [x] Confidence engine with 0.55 cap on unknown protocols (P6/P12)
- [x] Policy engine: 4 wallet profiles (Treasury, TradingBot, Gaming, Enterprise)
- [x] TypeScript SDK
- [x] Go SDK (full VerificationResult parity — 16 fields)
- [x] Python advisory layer (separate process — P1 compliance)
- [x] HTTP server (axum) + CLI (clap)
- [x] Dockerfile + .dockerignore
- [x] 680 unit/integration tests passing, 0 clippy warnings

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
- [x] 680 tests passing, 0 clippy warnings, fmt clean
- [x] Server hardening: constant-time bearer auth, per-IP rate limiting, CORS denied by default, JSONL audit log
- [x] RPC client live-verified against Helius (mainnet + devnet)

## Phase 2 (PLANNED — branch: phase2-development)

### Month 1: Real Data + Protocol Expansion
- [ ] Fetch REAL exploit transactions from Solana RPC (raw instruction bytes)
- [ ] Feed actual transaction data through Graphite (not synthetic reconstructions)
- [ ] Add 15-20 more protocol manifests
- [ ] Build regression engine corpus collection pipeline
- [ ] Replace synthetic exploit tests with real on-chain data
- [ ] **Dynamic PDA seed resolution**: Parse instruction data at runtime to resolve
      PDA seeds that depend on instruction arguments (e.g., Squads V4 proposal PDAs).
      Phase 1 manifests have `pda_seeds: []` because static templates produce false
      positives. Only `{program_id}` and `{account_index:N}` templates work without
      instruction data parsing.

### Month 2: Manifest Registry + Plugin Framework
- [ ] Manifest Registry with signature verification
- [ ] Community submission workflow (PR-based)
- [ ] Plugin framework: 6 interfaces
- [ ] 2 real reference plugins
- [ ] AuditBind middleware (TOCTOU prevention — re-hash signed tx vs approved content_hash)

### Month 3: Live Integration + Dashboard
- [x] Live SAK integration on devnet — **COMPLETE (devnet verified Aug 7, 2026)**
- [ ] L3 Simulation Verification fully active in production (RPC wiring exists; production activation is Phase 2 exit)
- [ ] L8 Execution Verification active (requires live execution)
- [ ] React dashboard showing live verification state
- [ ] Phase 2 certification
- [ ] Tag v0.2.0-beta

### Phase 2 Exit Criteria
- [ ] Benchmark uses real on-chain transaction data (not synthetic)
- [ ] SAK integration executes real devnet transactions after Graphite approval
- [ ] Protocol Manifest Registry accepts signed community submissions
- [ ] Plugin framework has 2+ real plugins
- [ ] L3 and L8 pipeline layers active
- [ ] TOCTOU prevention via AuditBind middleware
- [ ] Dashboard shows live verification state

## Phase 3+ (Future)

- **Phase 3 (Production):** Mainnet deployment, professional security audit, enterprise integrations
- **Phase 4 (Ecosystem):** Standard verification layer for Solana AI agents
- **Phase 5 (Multi-chain, exploratory):** Evaluate SVM-compatible chains only — full rewrite required for non-SVM chains
