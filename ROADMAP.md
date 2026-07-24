# Graphite — Roadmap

## Phase 1 (COMPLETE — v0.1.0-alpha, frozen)

- [x] Core verification engine (Rust)
- [x] 8-layer pipeline
- [x] 10 seed protocol manifests
- [x] Risk engine: 8 attack pattern types
- [x] Confidence engine with 0.55 cap on unknown protocols
- [x] Policy engine: 4 risk profiles
- [x] TypeScript SDK
- [x] Go SDK
- [x] Python advisory layer (separate process)
- [x] HTTP server (axum)
- [x] CLI (clap)
- [x] Dockerfile + .dockerignore
- [x] 626 unit/integration tests passing

### Phase 1 Honest Status

The benchmark is 18 unit test cases with hardcoded expected outcomes — NOT a
statistical evaluation on unseen data. "100% pass rate on handcrafted tests" is
the honest claim. The 5 real exploit classes (CLINKSINK, AAT, Wormhole) use real
program IDs but fabricated account structures and no instruction data bytes.
Benchmark latency: 34μs avg (release build) with 8-layer pipeline active.

## Phase 1.5 (COMPLETE — merged to main)

- [x] Extreme adversarial test suite (50 tests)
- [x] Real exploit pattern reconstructions (5 classes)
- [ ] SAK integration (requires real solana-agent-kit import — Phase 2)
- [x] .github CI workflows + issue templates
- [x] LICENSE, ARCHITECTURE.md, ROADMAP.md

### Phase 1.5 Honest Status

The SAK integration was removed — it was an HTTP wrapper, not a real
solana-agent-kit integration. It did not import SAK, call SAK methods, or
execute transactions. Per the production-ready standard, non-production
code was removed. Real SAK integration is a Phase 2 deliverable.

Dead code modules (cpi_chain, regression_engine, self_healing,
plugin_orchestrator) were also removed — they were Phase 2+ reference
implementations never wired into the verification pipeline.

## Phase 2 (PLANNED — not started)

### Month 1: Real Data + Protocol Expansion
- [ ] Fetch REAL exploit transactions from Solana RPC (raw instruction bytes)
- [ ] Feed actual transaction data through Graphite (not synthetic reconstructions)
- [ ] Add 15-20 more protocol manifests
- [ ] Build regression engine corpus collection pipeline
- [ ] Replace synthetic exploit tests with real on-chain data

### Month 2: Manifest Registry + Plugin Framework
- [ ] Manifest Registry with signature verification
- [ ] Community submission workflow (PR-based)
- [ ] Plugin framework: 6 interfaces
- [ ] 2 real reference plugins

### Month 3: Live Integration + Dashboard
- [ ] Live SAK integration on devnet (real transactions, not simulated)
- [ ] React dashboard
- [ ] Phase 2 certification
- [ ] Tag v0.2.0-beta

### Phase 2 Exit Criteria
- [ ] Benchmark uses real on-chain transaction data (not synthetic)
- [ ] SAK integration executes real devnet transactions after Graphite approval
- [ ] Protocol Manifest Registry accepts signed community submissions
- [ ] Plugin framework has 2+ real plugins
- [ ] Dashboard shows live verification state

## Phase 3+ (Future)

- Phase 3 (Production): Mainnet deployment, security audit, enterprise integrations
- Phase 4 (Ecosystem): Standard verification layer for Solana AI agents
- Phase 5 (Multi-chain, exploratory): Evaluate SVM-compatible chains only — full
  rewrite required for non-SVM chains
