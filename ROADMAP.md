# Graphite — Roadmap

## Phase 1 (COMPLETE — v0.1.0-alpha, frozen)

- [x] Core verification engine (Rust)
- [x] 8-layer pipeline (L1-L7 inside every /verify; L8 post-submission via POST /verify/execution; L3/L4/L8 live-validated against real RPC)
- [x] 33 protocol manifests (16 base + Tier-0: ATA, Compute Budget, BPF Loaders + Drift, Kamino, Phoenix, OpenBook V2, Switchboard, Jupiter Limit, Solend, Marginfi + C56: Raydium CLMM/CPMM, Marinade, SPL Stake Pool, Orca TokenSwap V2)
- [x] Risk engine: 11 attack pattern detectors (13 risk checks)
- [x] Confidence engine with 0.55 cap on unknown protocols (P6/P12)
- [x] Policy engine: 4 wallet profiles (Treasury, TradingBot, Gaming, Enterprise)
- [x] Policy engine real integrations: evidence signals read the Semantic Graph accumulator (G4), all 4 presets satisfiable/differentiable, CLI `--profile` + `profiles`, 14 profile-matrix tests
- [x] TypeScript SDK
- [x] Go SDK (full VerificationResult parity — 19 fields)
- [x] Python advisory layer (separate process — P1 compliance)
- [x] HTTP server (axum) + CLI (clap)
- [x] Dockerfile + .dockerignore
- [x] 987 unit/integration tests passing at the time, 0 clippy warnings (2026-08-21; 1,422 as of 2026-09-12)

### Phase 1 Honest Status (as recorded then; the benchmark is 18 scored + 2 baselines as of C52)

The benchmark was 16 scored cases (safe + malicious) plus 2 baseline comparisons — NOT a
statistical evaluation on unseen data. "100% precision / 100% recall on scored cases" is
the honest claim. Of the exploit cases, 2 are SYNTHETIC reconstructions (CLINKSINK-style,
AAT-style) using real program IDs but fabricated account structures and no
instruction data bytes. The other 3 are REAL mainnet data (Wormhole $320M hack,
CLINKSINK STMT drainer TX 64tsGGe, SlowMist AAT drainer TX 524t8LW) with actual
instruction data from published security research. All are labeled per P16.

### TOCTOU Mitigation (Phase 1.5 Partial — superseded 2026-09-11)

The `content_hash` field is a hash of one instruction's projection — program ID, instruction discriminator, account addresses, instruction data, and CPI targets. It ties a verdict to the instruction it described. **Since 2026-09-11 the authoritative binding is `scope.transaction_sha256` over the supplied transaction bytes, and the SAK bridge signs only bytes whose digest equals the approved one** (see "Hardening Rounds" below). The paragraph that follows is the Phase 1.5 record.

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
- [x] 1,272 tests passing at the time, 0 clippy warnings, fmt clean (1,422 as of 2026-09-12)
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
- [x] L3, L4 and L8 live-validated against real RPC (2026-09-07/08) — L3 grows its own baseline from live devnet observations, L4 caught an undeclared owner reassignment that L1/L2/L5 all passed, and L8 is reachable in production as POST /verify/execution + `graphite execution` with reconciliation against the append-only record
- [x] TOCTOU prevention via AuditBind middleware
- [x] Dashboard shows live verification state
- [x] 1,000+ meaningful regression fixtures (2,181 corpus, C41)
- [x] Real holdout evaluation with independent labels (38 fixtures, 0 FN, C41)

## Hardening Rounds (2026-09-05 → 2026-09-25) — reports in `docs/`

Twenty rounds run after Phase 2, each driven by an adversarial review of the
previous commit and each closed with reproductions committed as tests and every
fix reverted once to prove its test fails without it. Status of every guarantee:
[docs/CURRENT.md](docs/CURRENT.md).

- [x] Production readiness: RPC credential redaction, `X-Forwarded-For` trust hops, writable-data-dir probe, loopback default, tracing subscriber, container hardening, `cargo audit` + container smoke in CI, audit rotation, `/metrics` (2026-09-05)
- [x] Red-team of the pipeline: empty-discriminator carve-out, caller-chosen policy profile, dead simulation-integrity path, canonical intent vocabulary, immutable seed manifests, ambiguous discriminators, P9 lifecycle events (2026-09-05)
- [x] RPC trust boundary measured and bounded: fee cap, compute cap, unreadable-means-absent, body ceiling, verdict-field bounding; budget that fits inside the request timeout; load shedding (2026-09-08)
- [x] Transaction identity: wire-format parser (legacy + v0), `artifact_bound` / `descriptive` scope with `transaction_sha256`, positional instruction-account identity, bijective sibling coverage, privileges from the header (2026-09-08 → 09-11)
- [x] Address lookup tables: fetched, owner-checked, decoded all-or-nothing; runtime account numbering rebuilt; ground-truthed against three real mainnet v0 transactions (2026-09-11)
- [x] Execution boundary: one `BoundTransaction`, deep-copied, digest-rechecked, signer set from the message, single private signing path; descriptive verdicts never execute; swap opt-out is a phrase and reports `verifiedExecution: false` (Rounds 6–7)
- [x] Token-2022 extensions classified (block on semantics/authority/unknown/unreadable); the Round-6 fail-open on malformed TLV found and fixed in Round 7
- [x] Cross-language corpus: 12 shapes + 1,641 byte-level mutations from `@solana/web3.js`, Rust must agree, CI diffs the corpus (Rounds 7–8)
- [x] Audit durability: `fdatasync` per record, whole-trail reads across archives (L8 could not find rotated verdicts), rotation/snapshot failures surfaced, handler panics → `503 NOT recorded` (Round 8)
- [x] Authenticated by default; `GRAPHITE_DEV_MODE=1` loopback-only; keyless container refusal proven in CI (Round 8)
- [x] Durable-nonce transactions refused at L2; opt-in only after on-chain nonce verification; bridge refuses to build them (Round 8)
- [x] Documentation provenance: `docs/CURRENT.md`; every dated report banner-linked as historical (Round 8)
- [x] Artifact identity requires the data: no `instruction_data` or no parse → L2 fails; a 100 SOL transfer under a 0.002 SOL description reproduced and refused (Round 9, P1)
- [x] Residual codes (`scope.unobserved_codes`) and the bridge's `ResidualPolicy`: non-inherent residuals refuse execution unless accepted by code (Round 9)
- [x] Packet-size bound (1232 bytes) at entry, parser and `messageOf`; 256 declared siblings; 122 s → 1.6 ms (Round 9)
- [x] Lifecycle rows bounded, `verdict_on_record` on every row, the bridge reports signing/submission and runs L8; indexed L8 join (Round 9)
- [x] CI token read-only, actions pinned by SHA, base images pinned by digest (Round 9)
- [x] L8 attribution joined on the chain's bytes (signature slots zeroed → `transaction_sha256`), caller keys most-exact-first without fallback; `verdict_on_record` resolved the same way (Round 10, P1)
- [x] Tested compiler = shipped compiler (`1.98.1` in CI and the container); Go, cargo-audit and Python test deps pinned/hash-locked (Round 10)
- [x] L8 chain bytes bound to the signature (first slot + ed25519 under the fee payer), refused otherwise with no fallback; request path no longer deep-copies state (`/health` 100 ms → 1 ms, 21 → 960 verifies/s); refusals readable; parser matches the runtime's signer-count rule; 32-character API keys; TS SDK live conformance in CI (Round 11)
- [x] Parser proven never looser than the runtime (`tools/runtime-oracle` against the agave decoder + `sanitize`, in CI; five accepted-but-unexecutable frame classes closed); L8 weighs inclusion (commitment read, self-contradiction and malformed statuses withheld, redirects refused, optional independent witness `GRAPHITE_RPC_WITNESS_URL`); lifecycle sequence findings on every report; one server per data directory (Round 12)
- [x] The instruction's own leading bytes decide identity everywhere — every manifest lookup, the known-risky table, declared siblings; a hex discriminator contradicting its `instruction_data` fails L2 for every program (Round 13)
- [x] `content_hash` framed against field-boundary collisions; the artifact's discriminator re-grounded and pinned across Rust, the TS SDK, AuditBind and Go (Rounds 13–14)
- [x] Evidence is earned, not asserted: the baseline records only sound, risk-clear, successfully simulated transactions, keyed on the artifact digest so the same bytes are one observation; a failed simulation is named `simulation_failed`, never "clean" (Rounds 15–17)
- [x] A pre-signed artifact is refused at `/verify`; L8 names a cited verdict about other bytes and alarms when it was a refusal; every verdict on record for the chain digest is reported (Rounds 16–17)
- [x] A uniform compute history is a ±25% band, not a point; flagged-but-clean executions accumulate in a shadow baseline `/health` reports and an operator promotes (Round 17)
- [x] Blocking plugins fail closed on panic; `min_confidence > 1` is a 400 before the pipeline; the PDA seed-template grammar is closed at manifest load, at registry submission and at verify (Round 17)
- [x] **The registry is measured, not asserted (Round 18):** the Solana program inventory ranked from real mainnet blocks; 98 programs onboarded from their own on-chain Anchor IDLs; `protocols/battle_tested_evidence.json` records identity, volume and how much of each program's REAL traffic its manifest can name; `load_seed_manifests` lowers any `BattleTested` the measurement does not support
- [x] **What one observation is, and who may sign (Round 19):** the baseline identity ignores the blockhash the simulator replaces (a refused transfer was approved on its third ask with only the blockhash changed); only the artifact is simulated; exact per-program observation memory; the CPI-trace rules run on the tree the simulator reports; every writable account of an undescribed instruction is diffed; a separate operator key for `/admin/*`; the concurrency permit taken after rate, auth and body; one writer per data directory with ordered snapshots; the reference bridge no longer signs before the verdict and SolanaAgentKit holds no key that can sign
- [x] **The transfer fee is modelled (Round 20):** Token-2022 fee-bearing transfers stop blocking where Graphite accounts for the fee exactly against the mint's own schedule (checked against real fee mints); the fee payer's writable flag stops blocking every self-paid token transfer (156 real transactions went Blocked → Clear); a caller can no longer label its own diff as Graphite's
- [x] **Message version 1 parsed (Round 19):** never looser than agave's decoder (runtime oracle, both CI seeds, zero looser frames); 3,302 of 3,302 real mainnet v1 transactions read and bound
- [x] 1,652 Rust tests at Round 20 (327 featureless, 1,436 cli-only), 119 in the SAK integration, 32 in the TS SDK, 34 Go, 31 Python, 6 dashboard; CI green on every commit since `f10e4ab`

## Phase 3 (Production) — what gates it

Not a feature list; a list of what has to be true before real user funds go through
the public service. Owner decisions are marked.

- [ ] **Independent third-party audit** — every report so far is internal engineering work and says so (owner)
- [ ] **Branch protection on `main`** — required CI, no force-push; today CI is advisory because the branch accepts direct pushes (owner)
- [x] Token-2022 `TransferFee` modelled — done in Round 20 for transfers and harvests (withdrawals of withheld fees still block)
- [x] **Message version 1 parsed** — done in Round 19 (it was 17.0% of the 19,458-transaction mainnet sample of 2026-09-23 and refused by name until then); the v1 config values are parsed and bounded but not yet surfaced in verdicts
- [ ] **Manifest coverage of the traffic that has no published IDL.** Round 18 took the manifested share of non-vote mainnet transactions from 20.8% to 44.0% by onboarding every heavily used program that publishes its own on-chain Anchor IDL. The programs that now dominate the unmanifested remainder do not publish one, so they need a different, per-protocol route
- [x] A hard L2 failure on an unparseable artifact — done in Round 9: no `instruction_data`, or an artifact that does not parse, fails L2
- [x] Graphite's parser checked against Solana's own decoder over the mutation corpus — done in Round 12 (`tools/runtime-oracle`, in CI over the corpus and 600,000 generated frames); this line contradicted the Round 12 entry above for six rounds
- [ ] `content_hash` renamed to say it is an instruction-level identifier
- [ ] Persisted archive index so a node with years of audit archives does not scan them once at startup
- [ ] Mainnet deployment; enterprise integrations

## Phase 3+ (Future)

- **Phase 3 (Production):** see the gates above
- **Phase 4 (Ecosystem):** Standard verification layer for Solana AI agents
- **Phase 5 (Multi-chain, exploratory):** Evaluate SVM-compatible chains only — full rewrite required for non-SVM chains
