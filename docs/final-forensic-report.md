# Graphite — Final Full-System Forensic Validation Report

**Date:** 2026-08-08
**Scope:** Phase 1 + Phase 1.5 + Phase 2, all surfaces (core, CLI, server, SDKs, AI layer, dashboard, manifests, plugins, PDA, AuditBind, CI, docs, on-chain behavior)
**Method:** No prior certification accepted as truth. Every claim traced to code, tests, or live data.

---

## 1. Executive Summary

| Phase | Verdict |
|---|---|
| Phase 1 (core verification) | ✅ **STRONG** — deterministic 8-layer pipeline, fail-closed, genuinely tested |
| Phase 1.5 (server/SAK/hardening) | ✅ **STRONG** — server hardening verified by live attack probes; AuditBind parity proven cross-language |
| Phase 2 (protocols/registry/PDA/plugins) | 🟡 **PARTIAL→STRONG** — registry single-source-of-truth real; PDA grounded in one manifest; Tier-1 surface still thin |
| AI/Python layer | ✅ **CORRECT BY DESIGN (thin)** — advisory labeler per ARCHITECTURE.md's own honest framing; cannot weaken security |
| Overall | 🟡 **CONDITIONALLY READY** (see §12) |

**The system behaves as intended between an AI agent and a wallet.** The Rust core is a deterministic, keyless, fail-closed verification engine. The AI layer is advisory-only and structurally unable to weaken a decision. Real-world evidence: 35 pinned real exploit transactions → 100% recall; real mainnet legitimate transactions blocked only for documented cold-start/coverage reasons.

---

## 2. Real Architecture (traced, not assumed)

```
AI Agent (untrusted) ──NL──▶ Python AI Layer (advisory labeler, :8081)
                                   │ ProposedIntent {intent_type, confidence}
                                   ▼
                    VerifiedSakAgent (SAK bridge, TS)
                     │  build instruction(s)
                     ▼
              RpcSimulator (simulateTransaction → real CU/writes/hops)
                     ▼
              Graphite Core HTTP /verify (:7331)
                 ├─ L1 Account Resolution (manifest + PDA)
                 ├─ L2 Instruction Verification (discriminator/count)
                 ├─ L3 Simulation Verification (z-score vs earned baselines; Inconclusive w/o RPC)
                 ├─ L4 State Verification
                 ├─ L5 Semantic Verification (intent vs manifest behavior)
                 ├─ L6 Policy Verification (confidence + profile threshold + tier)  ← FINAL GATE
                 ├─ L7 Risk Verification (9 hard-gate patterns, runs early)
                 └─ L8 Execution Verification (honest "not yet verified" until Phase 3)
                     │ approved + content_hash (deterministic, client-reproducible)
                     ▼
              AuditBind (re-hash the exact instruction → compare content_hash; fail-closed)
                     ▼
              Wallet / signing boundary (SAK holds key; Rust core NEVER sees it)
```

**Call graph facts verified in code:**
- `graphite-sak-bridge.ts` → `parseIntent()` (Python :8081) → `verifyTransaction()` → `GraphiteClient.verify()` (Rust :7331) → `AuditBind` → sign+send. Real and wired end-to-end.
- `content_hash` = SHA-256(programId‖disc‖accounts‖instruction_data‖cpi_targets)[:16 hex] — deterministic and client-reproducible. `audit_trail_id` adds confidence+risk+seq (`gr-…-seq`). **The two are deliberately separated** (C2) so AuditBind is possible; AuditBind correctly fail-closes when handed a `gr-…` id.
- Dead/duplicated code: none found in the core (`cpi_chain.rs`, `self_healing.rs` were removed in an earlier cycle as confirmed dead). The Python parser's `suggested_program_id`/`suggested_discriminator` are unused by the bridge (advisory-only, now kept accurate).

---

## 3–5. Phase 1 / 1.5 / 2 Alignment — Verified Highlights

**Phase 1 — core guarantees (verified):**
- 8-layer pipeline executes in order; L7 hard-gate independent of confidence (tested: perfect confidence cannot override a detected pattern).
- Unknown protocols hard-capped at 0.55 (P12) — verified in code + tests.
- NaN/Infinity rejection in confidence and baselines (tested).
- Determinism: same input → same output (pinned-vector tests).

**Phase 1.5 — hardening (verified by live probes this cycle):**
- **2 MB body → HTTP 413** (body limit works).
- **Malformed `Content-Length` → HTTP 400, connection closed, server stays alive.**
- Bearer auth constant-time (SHA-256 digest comparison), rate limiting FIFO-bounded, CORS denied by default, trusted-proxy gated `X-Forwarded-For` — all verified in code.
- Audit log append-only, all four outcomes recorded (approved/blocked/400/500).

**Phase 2 — milestones (verified):**
- Registry `verified_program_ids.json` is the single source of truth; bidirectional pin test (Rust+Python) + blessed-canonical-set test (11 core IDs can never vanish).
- 20 manifests, 216 instructions; all 20 program IDs verified executable on mainnet (2026-08-08).
- Squads V4 rebuilt from official IDL (C18) — 36 instructions, snake_case-hash discriminators, 4 chain-verified.
- Dynamic PDA: multisigCreateV2 grounded (`["multisig","multisig",create_key]`), spoof-flagging proven. Vault/transaction PDAs need account-state seeds beyond the template engine (documented).
- Exploit corpus: 35 real pinned malicious txs (SolPhishHunter arXiv:2505.04094) → **100% recall**; ISA blocks now principled (Impersonation rule).
- P10 regression gate: `replay_corpus` + `decide_promotion` real; corrupt fixture = error, never skip.
- Plugin framework: registered/skipped-pending/skipped-rejected gate, event-file sink — tested.

---

## 6. Engineering Skill Alignment

Source: `ARCHITECTURE.md` (the canonical skill) + `SECURITY.md`.

| Claim | Reality | Status |
|---|---|---|
| 8-layer pipeline | Matches exactly | ✅ Aligned |
| L7 hard gate | Verified | ✅ Aligned |
| P1 AI-advisory | Verified (separate process, no override) | ✅ Aligned |
| P12 unknown cap 0.55 | Verified | ✅ Aligned |
| Server hardening table | Matches code | ✅ Aligned |
| "15 manifests / 819 tests" | 20 / 852 | ❌ Stale → **fixed this cycle** |
| "`POST /manifests`" | `GET /manifests` | ❌ Stale → **fixed this cycle** |
| "8 attack patterns" | 9 (Impersonation added) | ❌ Stale → **fixed this cycle** |
| SECURITY.md duplicate header | Duplicated | ❌ **fixed this cycle** |
| "TOCTOU gap — Phase 2 AuditBind" | AuditBind shipped; **residual gap on SAK swap path** | ⚠️ Corrected + documented this cycle |

---

## 7. AI/Python Layer — Deep Forensic Verdict

**What it is:** one file (`intent_parser.py`) — a regex-based natural-language → `ProposedIntent` labeler, running as a separate HTTP process. No model calls, no context, no risk reasoning.

**What it is supposed to be:** per ARCHITECTURE.md's own honest framing — "the AI layer (Python, separate process) parses natural language into a JSON label; the Rust core makes all security decisions deterministically." **It fulfills exactly that documented role.**

**Security analysis (the part that matters):**
- It is wired (bridge → :8081 → ProposedIntent) but **structurally cannot weaken a decision**: its output is a label; L6/L7 deterministic gates decide; the bridge never feeds its `suggested_*` fields into verification.
- It receives **only text** — never keys, never verification results it could game, never signing material.
- Its failure modes are safe: wrong/stale suggestions → verify mismatch → block (fail-closed).
- **Fixed this cycle:** unbounded request-body read (no cap — memory DoS on a public host) and unhandled `Content-Length` ValueError → 64 KiB cap + robust parsing + 413 + regression test. Stale advisory swap discriminator (`route` → `route_v2`) corrected.

**Verdict: CORRECT BY DESIGN, THIN BY DESIGN.** The user's instinct ("too thin") is right in the sense that there is no semantic intent verification — but that is the documented architecture, and adding an LLM into the decision path would be a security regression, not an improvement. Real semantic verification (if ever wanted) belongs in Phase 3 as a *pre-parse* enrichment that still feeds the deterministic core.

---

## 8–9. Agent ↔ Graphite ↔ Wallet Security Model — Attack Results

**Trust boundary (verified):**
- Agent can request anything; Graphite can only approve/block; Graphite never modifies the instruction it approves (it returns a verdict + hash); the wallet signs only what the bridge builds.
- **TOCTOU transfer path: CLOSED.** The same `transferIx` object is verified and executed; AuditBind's reduced projection covers programId/discriminator/accounts.
- **TOCTOU swap path: PARTIALLY OPEN (documented, HIGH).** `executeSwap` binds the caller-supplied payload (`verifyInstruction`, full data + accounts) but then calls `sakAgent.methods.swap(...)`, which **rebuilds the instruction internally** — the executed instruction is not guaranteed to be the bound payload. The payload schema (base58 strings) lacks isSigner/isWritable, so the bridge cannot safely reconstruct+sign the bound instruction itself. `GRAPHITE_SWAP_STRICT=1` forces a payload to exist but does not force the executor to submit it. **Full closure requires the operator to build/verify/submit the exact instruction** (documented in ARCHITECTURE.md, SECURITY.md, and the bridge code this cycle).
- **Key boundary: CLEAN.** The Rust core's `/verify` contract has no key field; keys live at the SAK/wallet layer only. No env var reaches the core.
- **Program/account substitution, reordering, LUTs:** L1/L2 + content_hash bind program, discriminator, full account list, and instruction data (when present). LUT-expanded accounts are folded (C13 fix).

**Infrastructure attacks (live probes this cycle):** oversized body → 413; malformed Content-Length → 400 + alive; 800-request concurrent storm → no 5xx, no crash; rate limiter FIFO-bounded (eviction test). RPC client retries 429/5xx with backoff, distinguishes AccountNotFound from zeroed accounts.

---

## 10–11. Privacy + Key Verdict

- Audit records store: timestamp, program_id, instruction name, protocol, verdicts, confidence, hashes. **Not stored:** account lists, amounts, natural-language prompts, agent context, request bodies. Verified in `durable.rs` + server handler.
- Dashboard exposes program-level aggregates only.
- The Rust core never receives or stores private keys. The bridge holds the wallet key in memory to sign (self-custody agent wallet model) — this is the wallet boundary, not Graphite Core. Python layer receives text only.
- **No secrets in logs:** verified (auth path never logs the key; RPC client doesn't log credentials).
- Residual: `audit.jsonl` file mode on Linux deployments is operator-controlled (should be 0600; Dockerfile runs non-root).

---

## 12. Final Certification

### 🟡 CONDITIONALLY READY

**Can Graphite safely sit between an autonomous AI agent and a wallet? — YES with conditions.** The verification engine itself is sound: deterministic, fail-closed, keyless, evidence-real (100% recall on 35 real exploits; legitimate blocks all root-caused). It is the *integration surface* where the residual risk lives.

**Blockers to 🟢 (each documented with justification):**
1. **SAK swap-path TOCTOU residual** (HIGH, by-integration) — bound payload ≠ executed instruction unless the operator executes the payload directly. Core is not at fault; the SAK integration contract is.
2. **No live public deployment** (P2, operator action) — Dockerfile/compose ready, never deployed; branch protection not enabled.
3. **L8 execution verification not wired** (honest "inconclusive") — post-submission confirmation is Phase 3.
4. **Cold-start confidence ceiling** (by design, P7) — fresh node caps at 0.44 < 0.80 TradingBot threshold; steady-state proven by seeded regression test; needs evidence accumulation + attached RPC for L3.
5. **Protocol surface thin vs. ecosystem** — 20 manifests / 216 instructions; Drift, Kamino, Pyth, Raydium CLMM IDs verified on-chain but manifests not yet built; every unknown program fails closed (safe but restrictive).
6. **Vault/transaction PDAs** need account-state seeds beyond the template engine (documented).

**What would change the verdict:** close the swap-path TOCTOU (execute the bound instruction), deploy publicly with a warmed evidence store, wire L8, and add the Tier-1 manifests.

---

## 13. Testing & Performance (measured this cycle)

- **852 Rust tests / 0 failed**, including 470 adversarial/attack tests across 9 suites (adversarial, handcrafted, extreme, hell-mode, omega red-team ×2, novel attacks, property-based, real-world) — all green.
- **8/8 Python** (incl. new body-limit regression), **TS SDK + SAK clean**, **Go SDK green in CI**, **Dashboard builds**, clippy `-D warnings`, fmt, all feature gates.
- **On-chain:** 35/35 real exploits blocked; 20/20 program IDs executable on mainnet; 4 Squads discriminators chain-verified.
- **Latency (release build, HTTP round-trip, Windows):** sequential p50 **11.2 ms**, p95 **17.6 ms**, p99 **66.2 ms**; core verification itself sub-ms (benchmark ~600 µs). Concurrent ceiling **~244 req/s** single-node (audit-log mutex convoy — acceptable for a wallet guard; async audit writer is a Phase 3 perf item).

---

## 14. Changes Made This Cycle (C20)

| # | Finding | Class | Fix |
|---|---|---|---|
| C20.1 | Python HTTP server: unbounded body read + unhandled Content-Length ValueError (memory DoS on public host) | Root (resource-exhaustion) | 64 KiB body cap, robust parsing, 413, regression test |
| C20.2 | SAK swap-path TOCTOU: bound payload ≠ executed instruction | Root (integration trust boundary) | Documented precisely in ARCHITECTURE.md/SECURITY.md/bridge; strict-mode message corrected |
| C20.3 | Stale advisory discriminator (route vs route_v2) + duplicate manifest data in Python layer | Surface | Corrected + documented as advisory-only |
| C20.4 | ARCHITECTURE.md stale: 15 manifests/819 tests/POST /manifests/8 patterns | Surface (docs-vs-reality) | Corrected to 20/852/GET/9 |
| C20.5 | SECURITY.md duplicated header + stale TOCTOU claim | Surface | Deduped + updated to reflect AuditBind status and residual gap |

**No regression introduced:** full suite green after every change (per change-safety protocol §15).

## 15. Remaining Risks (honest, unresolved)

- Swap-path TOCTOU (blocker, §12.1) — requires integration-level change, not core.
- A direct chain reproduction of the Squads multisig PDA from a create tx is still open (public-RPC scan timeouts) — layout is SDK/IDL-grounded.
- The `audit.jsonl` file mode on Linux deployments should be 0600 (operator hardening item).
- Concurrent throughput ceiling ~244 req/s single-node (fine for wallet-guard, not for high-TPS serving).
