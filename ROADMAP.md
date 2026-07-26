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
- [x] 630 unit/integration tests passing

### Phase 1 Honest Status

The benchmark is 18 unit test cases with hardcoded expected outcomes — NOT a
statistical evaluation on unseen data. "100% pass rate on handcrafted tests" is
the honest claim. The 5 real exploit classes (CLINKSINK, AAT, Wormhole) use real
program IDs but fabricated account structures and no instruction data bytes.
### TOCTOU Mitigation (Phase 1 Partial)

The `audit_trail_id` is a SHA-256 hash bound to the specific transaction configuration — program ID, instruction discriminator, account addresses, instruction data, and CPI targets. This means each verification result is cryptographically tied to the exact transaction it verified.

**Phase 1 limitation:** Graphite verifies the transaction structure but does not sign or bind the result to the execution payload. Full TOCTOU prevention requires the executor (SAK integration, Phase 2) to verify that the executed transaction matches the verified one using the audit_trail_id.

Benchmark latency: ~35μs avg (release build) with 8-layer pipeline active.

## Phase 1.5 (SAK integration rebuilt — pending live devnet test)

- [x] Extreme adversarial test suite (50 tests)
- [x] Real exploit pattern reconstructions (5 classes)
- [x] SAK integration (real solana-agent-kit import, verified execution gate)
- [x] .github CI workflows + issue templates
- [x] LICENSE, ARCHITECTURE.md, ROADMAP.md

### Phase 1.5 Honest Status

The SAK integration was rebuilt with real imports:
- Imports `solana-agent-kit` v2 (real npm package, not an HTTP wrapper)
- Imports `@solana-agent-kit/plugin-token` and `@solana-agent-kit/plugin-defi`
- Uses real SAK API: `SolanaAgentKit`, `KeypairWallet`, `.use()`, `.methods.swap()`
- Imports the Graphite TS SDK (`GraphiteClient`)
- Every transaction goes through Graphite verification before SAK execution
- If Graphite blocks, the transaction is NOT submitted to the network

**Not yet tested on devnet** — requires npm install + Solana RPC + wallet key.
Code is production-ready but needs live integration testing (Phase 2 exit criteria).

Dead code modules (cpi_chain, regression_engine, self_healing,
plugin_orchestrator) were also removed — they were Phase 2+ reference
implementations never wired into the verification pipeline.

Benchmark labels corrected (P16 compliance): "REAL" → "SYNTHETIC" for
cases using real program IDs but synthetic account data.
Baseline comparison added (P16 requirement): simulation-only vs Graphite.

## Phase 2 (PLANNED — not started)

### Month 1: Real Data + Protocol Expansion
- [ ] Fetch REAL exploit transactions from Solana RPC (raw instruction bytes)
- [ ] Feed actual transaction data through Graphite (not synthetic reconstructions)
- [ ] Add 15-20 more protocol manifests
- [ ] Build regression engine corpus collection pipeline
- [ ] Replace synthetic exploit tests with real on-chain data
- [ ] **Dynamic PDA seed resolution**: Parse instruction data at runtime to resolve PDA seeds that depend on instruction arguments (e.g., Squads V4 proposal PDAs derived from `[multisig, proposal_index]`). Phase 1 manifests have `pda_seeds: []` because static templates like `["proposal"]` produce false-positive mismatches on every legitimate transaction. Only `{program_id}` and `{account_index:N}` templates work without instruction data parsing.

### Month 2: Manifest Registry + Plugin Framework
- [ ] Manifest Registry with signature verification
- [ ] Community submission workflow (PR-based)
- [ ] Plugin framework: 6 interfaces
- [ ] 2 real reference plugins

### Month 3: Live Integration + Dashboard
- [ ] Live SAK integration on devnet (code exists in integrations/solana-agent-kit/, needs npm install + RPC + wallet key to test)
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
