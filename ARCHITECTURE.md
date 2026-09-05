# Graphite — Architecture

## Overview

Graphite is a deterministic semantic verification engine for Solana. It verifies
that transactions constructed by AI agents match their declared intent by checking
program IDs, CPI chains, account structures, cross-instruction patterns, and risk
patterns against a curated knowledge base of 33 protocol manifests covering 803
instructions.

**Honest framing:** Graphite performs deterministic pattern matching on program
identity, CPI chains, and account structures. The AI layer (Python, separate process)
parses natural language into a JSON label; the Rust core makes all security decisions
deterministically. The semantic layer (L5) verifies intent↔program alignment —
intent is a label, not a semantic constraint, but the alignment check is real and
fail-closed.

## Language Split

| Component | Language | Why |
|---|---|---|
| Core engine | Rust | Deterministic, no GC, auditable, fast |
| AI layer (advisory) | Python | Separate process — enforces P1 (AI assists, never decides) |
| SDK | TypeScript + Go | Consumer-facing, typed |

## 8-Layer Verification Pipeline

The pipeline executes in order. Each layer is tracked in the verification result with pass/fail status and a human-readable reason.

1. **L1 Account Resolution** — Resolves all accounts, verifies PDAs against protocol manifests (PDA derivation uses Solana's actual `create_program_address` hash-chain algorithm), and — for the fixed, well-known-constant account roles (SPL Token/Token-2022/System/Compute Budget/Associated-Token-Account programs, a manifest's own program self-reference) that are neither a PDA nor legitimately caller-chosen — checks the supplied address against the manifest's declared `expected_address` constant(s). When a caller supplies real per-account signer/writable bits (`real_account_metas`), also cross-checks them against the manifest's declared signer/writable expectations. See "Account Identity" and "Privilege (Signer/Writable) Grounding" below.
2. **L2 Instruction Verification** — Confirms the instruction discriminator and account count match the manifest's declared shape (exact-match, no prefix bypass since C33)
3. **L3 Simulation Verification** — Runs `simulateTransaction` and checks compute/account-write/CPI divergence. Active whenever an RPC client is attached (`GRAPHITE_RPC_URL`); the simulation-integrity module runs a 3-signal z-score (compute, writes, CPI hops) with Welford's algorithm against earned baselines, plus median/MAD baseline (C28) for poisoning resistance. Live-validated against real Solana devnet transactions (C40). Without an RPC client the layer reports an honest `Inconclusive` state, never a phantom pass.
4. **L4 State Verification** — Diffs pre/post account state against the manifest's expected state changes
5. **L5 Semantic Verification** — Compares the proposed intent against the Semantic Graph's expected behavior for this program. The intent vocabulary is exactly: `swap|trade|exchange`, `transfer|send`, `stake|delegate`, `close|close_account`, `create|create_account`, `approve|revoke` (anything else fails closed). The advisory labeler (v2, C21) emits only this vocabulary.
6. **L6 Policy Verification** — Computes confidence (0.0–1.0 from weighted signals + tier ceilings) and applies wallet profile thresholds (TradingBot 80%, Treasury 95%, Gaming 55%, Enterprise 99%) and trust tier requirements
7. **L7 Risk Verification** — Pattern-matches against 11 known attack patterns (13 risk checks, hard gate, independent of confidence): Drainer, HiddenTransfer, AuthorityHijack, FakeSwap, UnexpectedCpi, PermissionEscalation, MaliciousAccountChange, CompositionalDrainPattern, Impersonation (system-account impersonation — SolPhishHunter arXiv:2505.04094), MultiInstructionDrain (C29), and CpiTraceAnomaly (C29). Runs early for fail-fast but is reported at L7 per architecture spec. Every instruction in the transaction is assessed, not just the primary — see "Secondary Instruction Risk Assessment" below.
8. **L8 Execution Verification** — Post-submission: confirm finalized on-chain result matches prediction. Live-validated against real mainnet RPC (C40) — reports honest execution status (Confirmed / Unknown / Unavailable). Production default-on wiring pending public deployment.

### Key Properties
- **L7 Risk Verification is a hard gate** — it blocks independently of confidence score. A malicious pattern blocks the transaction even if confidence is high. The Risk Engine executes early in the pipeline (before L4/L5) for fail-fast performance, but is reported at L7 per this spec.
- **L2/L4/L5 are hard gates when genuinely Failed** — a confirmed L2 instruction/data mismatch, L4 state-verification failure, or L5 intent-vs-instruction mismatch blocks approval unconditionally, exactly like an L7 risk finding, regardless of trust tier or wallet-profile confidence threshold. This is distinct from `Inconclusive` (insufficient evidence — e.g. an unknown protocol — which never blocks and only reduces confidence via the P12 tier ceiling, never via this gate). A genuine `Failed` also still applies its confidence penalty (0.2 / 0.15 / 0.3 for L2/L4/L5) so the breakdown stays explainable, but the penalty is no longer what enforces the rejection.
- **L6 Policy Verification applies tier ceilings** — Unknown/Heuristic protocols are capped at 0.55 (hard-coded, not overridable per P12). Confidence computation is included in L6.
- **L6 Policy Verification is the final gate** — it checks both confidence threshold and minimum trust tier for the wallet's profile, AND that no L2/L4/L5 layer genuinely failed.
- **L3 Simulation Verification is active when an RPC client is attached** — `GRAPHITE_RPC_URL` wires a live `simulateTransaction` call into the pipeline, live-validated against real Solana devnet transactions (C40). Without an RPC client, L3 reports `Inconclusive` (honest tri-state: `Passed` / `Failed` / `Inconclusive`) rather than a phantom pass. A flagged simulation (genuine `Failed`) is folded into the L7 risk finding `SimulationSpoofing` and is therefore already a hard gate, consistent with L2/L4/L5 above.

### Account Identity (P0-1 fix, 2026-09-05)

Most account roles in an instruction are genuinely **externally-determined** — which token account to debit, who the recipient is — and cannot be pre-verified by any means; requiring a PDA seed or an expected address on every role would be both wrong (there is nothing to check against) and infeasible. But a large, high-value subset of roles are **fixed, well-known constants**: the SPL Token, Token-2022, System, Compute Budget, and Associated-Token-Account program IDs, and a manifest's own program self-reference (the `"{program_id}"` seed-template sentinel). These are neither a PDA (no seed formula exists) nor legitimately caller-chosen.

`AccountRoleDef.expected_address` (a manifest-declared constant, or a small set of acceptable constants — e.g. a generic "token program" slot that legitimately accepts either classic SPL Token or Token-2022) lets the manifest pin these slots. Account resolution checks the supplied address against them and, on mismatch, sets `ResolvedAccount.expected_address_mismatch` — folded into the SAME hard-block risk finding (`AccountIdentityMismatch`) that a PDA mismatch already produces (Constitution P4). 542 account roles across 19 manifests are pinned this way as of this fix (`graphite-core/scripts/populate_expected_addresses.py` — rerun when onboarding a new protocol).

`ResolvedAccount.identity` (`Pda` / `Constant` / `Unverified`) makes the **remaining, unavoidable trust boundary** visible rather than silently assumed safe: an externally-determined account (the large majority of roles) reports `Unverified` honestly — this is not a finding or a penalty, just disclosure (P12: absence of verification is not itself evidence of harm). Closing that remaining boundary for fund-critical externally-determined accounts (e.g. confirming a token account's on-chain owner matches the transaction signer) requires live account data and is tracked as a follow-up, not claimed here.

### Address Lookup Table / Versioned Transaction Awareness (P1 fix, 2026-09-05)

Graphite has no independent way to detect that a transaction is a versioned (v0) message or that it resolves accounts through Address Lookup Tables — it only ever sees the flat `account_addresses` list a caller supplies, never raw transaction bytes' message-version byte or ALT references. Full bincode `VersionedTransaction` parsing and RPC-based ALT resolution would close this properly, but this crate deliberately has no `solana-sdk` dependency (see `solana_types.rs`), so a correct wire-format parser is a substantial, hand-rolled undertaking — attempting a rushed one risks parsing bugs that are worse than the current honest gap, so it is tracked as a follow-up rather than attempted here.

`VerificationInput.uses_versioned_transaction` / `.lookup_table_count` let a caller who DOES know this (the SDK/bridge constructing the input from a real transaction object) disclose it. When set, a non-blocking warning is surfaced ("versioned (v0) transaction using N address lookup table(s) — accounts resolved via ALT are not independently verified by this pipeline") — this is pure disclosure, never a confidence penalty or a block: ALT usage is normal and common in legitimate complex swaps/routes (P12). The pre-existing `account_count_shortfall` finding (C57) already covers one symptom — a real transaction supplying fewer accounts than the manifest declares because ALT-resolved positions were skipped by a pure reader — this fix adds an explicit, caller-declared signal for the general case.

### Privilege (Signer/Writable) Grounding (P1 fix, 2026-09-05)

`ResolvedAccount.is_signer` / `.is_writable` are manifest-declared **expectations** for a role, not observations of the real transaction — nothing previously cross-checked them against the actual per-account `AccountMeta` bits a caller may already hold (e.g. an SDK/bridge that built the instruction from a real `AccountMeta[]`). A manifest could declare a slot "must be signed" or "read-only", and the pipeline would approve a transaction where the real transaction quietly failed to sign that account, or marked a read-only slot writable, without ever noticing the discrepancy.

`AccountResolutionInput.real_account_metas` (a caller-supplied `Vec<RealAccountMeta>`, same order as `account_addresses`) closes this gap. Only the two security-relevant mismatch directions are flagged as `ResolvedAccount.privilege_mismatch`:

- the manifest requires a signer, but the real transaction shows it is **not** signed (the role this account is supposed to play cannot actually be authorized), or
- the manifest declares the slot read-only, but the real transaction marks it **writable** (a privilege escalation beyond what the manifest's own account-role analysis accounted for — the classic shape of a hidden-write/drain attempt).

The reverse directions (manifest expects signer/writable but the real transaction is more restrictive) are deliberately **not** flagged — an over-cautious real transaction is not a security concern and would self-limit on-chain regardless. `real_account_metas` is empty by default (most callers don't have this data), and a length mismatch against `account_addresses` is treated identically to "not supplied" — the whole list is either usable or not, never partially applied to a prefix of positions (which could silently skip checking exactly the positions that were added or reordered). Absence therefore leaves `privilege_mismatch` honestly `false`: "not checked", never "assumed to match" (P12). Like `pda_mismatch` and `expected_address_mismatch`, a `privilege_mismatch` is folded into the SAME hard-block risk finding (`AccountIdentityMismatch`) rather than a new independent pathway.

### Secondary Instruction Risk Assessment (P0-3 fix, 2026-09-05)

Before this fix, `risk_engine::assess()` ran exactly once per verification — against the PRIMARY instruction only. Everything else in the transaction (CPI-flattened callees, top-level sibling instructions) was invisible to the 23 structural risk checks, reachable only via `tx_pattern_analysis`'s narrow, correlation-based rules (e.g. an Approve must be immediately followed by a Transfer of the same account to trigger AAT detection). A standalone secondary instruction with no such pairing — a bare `SetAuthority`, a manifest-tagged high-risk withdraw/mint/close call — passed through completely unscrutinized.

`GraphiteCore::assess_secondary_instructions` now risk-assesses every instruction in `effective_instructions` (primary + CPI-trace pre-order flatten + top-level secondaries, in execution order), with an EMPTY declared intent — never the primary's — so intent-DEPENDENT checks never false-positive on ordinary multi-instruction patterns (e.g. a swap's secondary ATA-creation instruction), while every intent-INDEPENDENT structural check (the known-risky-discriminator table, CPI checks, drainer/hidden-transfer heuristics, system-account impersonation) stays fully active. A blocked secondary instruction is a hard gate, exactly like a primary-instruction risk finding — it can never be "outvoted" by other, benign instructions in the same transaction, and duplicate copies of the same risky secondary each independently re-confirm the block rather than diluting it. A secondary instruction with no discriminator (the common shape for CPI-trace-flattened nodes, whose data is frequently not recoverable by trace introspection) is surfaced as a non-blocking warning rather than routed into the fail-closed empty-discriminator check meant for the primary instruction. An unmanifested secondary program similarly produces a non-blocking warning, not a block (P12 — unknown is not itself proof of harm); it remains fully covered by the checks that don't require a manifest.

**Repeated unmanifested secondary program disclosure (P1 fix, 2026-09-05).** An unmanifested secondary instruction can only ever be BLOCKED by the checks above that don't need a manifest — never by repetition count alone: Graphite has no transaction amount/value data to bound cumulative damage from N calls to an unrecognized program, and a hard cap on repetition would be trivially evaded (stay one call under the threshold) while false-positiving on a legitimate multi-call batch to a protocol that simply hasn't been onboarded yet (P12). What this fix adds is pure disclosure, mirroring the ALT-awareness pattern above: once the SAME unmanifested program is invoked 3+ times as a secondary instruction (the same floor `tx_pattern_analysis`'s mass-sweep rule uses), an explicit aggregate warning is surfaced — "unmanifested program X was invoked N times as a secondary instruction" — so a human or downstream auditor can see the repetition pattern that per-occurrence warnings alone don't make visible. Never a confidence penalty, never a block.

### CPI Trust Allowlist Consolidation (P1 fix, 2026-09-05)

`risk_engine.rs` exempts a curated set of DEX/aggregator/multisig programs from three otherwise-fail-closed checks: Check 1b (a risky CPI target — SPL Token/Token-2022 — from an untrusted root is blocked, since a custom contract's CPI into Token could be a hidden `SetAuthority`/`CloseAccount`), the drainer heuristic (high account-to-change ratio, normal for DEX routing but suspicious from an arbitrary program), and Pattern 2 (a 5+-deep unique-program CPI chain, normal DEX routing but a strong drain signal otherwise). This exemption list previously existed as **two** separately hand-maintained arrays — `TRUSTED_CPI_ROOTS` and `DEX_PROGRAMS` — with byte-identical contents kept in sync only by discipline. That discipline already failed once for real: three DEXes (Phoenix, OpenBook V2, Jupiter Limit Order) were added to one list but not the other, silently misflagging their legitimate swaps as `AuthorityHijack` until caught by audit (documented inline as "C56" — still preserved as a comment on the merged list).

Both names are now aliases of a single canonical `TRUSTED_COMPOSABILITY_PROGRAMS` array (`const DEX_PROGRAMS: &[&str] = TRUSTED_COMPOSABILITY_PROGRAMS;`, likewise for `TRUSTED_CPI_ROOTS`) — onboarding a new protocol into this trust category now requires editing exactly ONE place, and a compile-time-enforced regression test (`trusted_cpi_roots_and_dex_programs_share_one_canonical_list`) makes any future re-divergence attempt fail immediately rather than silently reintroducing the C56 bug class. Purely a deduplication refactor: the merged list has identical membership to both prior lists (verified before merging, and by the full regression suite passing unchanged after), so no transaction's verdict changes.

## Security Boundaries (Constitution)

- **P1:** AI assists, never decides — separate process, no override capability
- **P2:** Deterministic/reproducible — same input → same output, always (`content_hash` = SHA-256)
- **P3:** Confidence scored (0.0–1.0), never bare boolean
- **P12:** Unknown protocols capped at 0.55 confidence — hard-coded, not overridable
- **P16:** No public performance claim without reproducible benchmark

## Server (HTTP API)

The axum-based HTTP server exposes `POST /verify`, `GET /manifests` (listing), `GET /health`, and the read-only dashboard API (`/api/graph`, `/api/confidence-history`, `/api/policy-violations`, `/api/protocols/top`, `/api/registry`).

| Concern | Implementation |
|---|---|
| **Authentication** | Optional Bearer API key (`GRAPHITE_API_KEY`), compared in constant time (SHA-256). `/verify` and `/manifests` require it when set; `/health` stays open for load balancers. |
| **Rate limiting** | Per-IP token bucket (`GRAPHITE_RATE_LIMIT`, default 30 req/s), FIFO eviction, returns `429` on exhaustion. |
| **CORS** | Denied by default; `GRAPHITE_CORS_ORIGINS` (comma-separated) enables specific browser origins. Server-to-server clients are unaffected. |
| **Audit log** | Append-only JSONL (`audit.jsonl` under `GRAPHITE_DATA_DIR`) written after every verification — covers all four outcomes: approved, blocked, HTTP 400, HTTP 500. |
| **Durability** | Semantic-graph snapshot (trust tiers + earned simulation baselines) and the audit log are reloaded on restart. |
| **Graceful shutdown** | SIGINT/SIGTERM drain in-flight requests before exit. |
| **Trusted proxy** | `X-Forwarded-For` is honored only when the server is explicitly configured behind a trusted proxy. |

## What Graphite Does NOT Do (Honest)

- Does NOT parse instruction data semantics beyond the discriminator (instruction bytes are not analyzed for meaning)
- Does NOT detect novel attack patterns (only the 11 known patterns / 14 checks are matched)
- Does NOT use AI/ML in the verification path (deterministic pattern matching only; the Python layer is an advisory labeler)
- Does NOT treat the advisory labeler's suggestions as decisions — a wrong suggestion simply fails to match and the verification blocks (P1)
- Does NOT work on chains other than Solana (SVM-specific, complete rewrite needed)
- Does NOT hold wallet private keys — the Rust core never receives signing material; keys live at the wallet/SAK boundary (the integration bridge holds them to execute, like any self-custody agent wallet)

## Known Boundary Limitations (honest)

- **SAK swap-path TOCTOU — CLOSED for the payload-provided path (2026-09-05).** When `executeSwap` is called with a `payload` (the exact instruction: programId, discriminator, full account list with real isSigner/isWritable flags, raw data), the bridge builds and submits that SAME instruction directly (`bound-instruction.ts::buildInstructionFromPayload`) — it no longer hands off to SAK's `methods.swap`, which used to rebuild the instruction internally after AuditBind had already verified a different object. What executes is now deterministically derived from what was hashed, not merely hash-checked and then independently reconstructed. See `integrations/solana-agent-kit/bound-instruction.test.ts` for the regression coverage proving the built instruction always re-hashes to the exact verified value. **Residual (unchanged):** without a `payload`, execution still goes through SAK's opaque builder with only a reduced (programId + discriminator + wallet) AuditBind projection — `GRAPHITE_SWAP_STRICT=1` refuses that path entirely rather than accepting the residual. The transfer path was already fully bound (same instruction object verified and executed).
- **SAK swap-path privilege grounding — CLOSED for the payload-provided path (2026-09-05).** `payload.accounts`' real isSigner/isWritable flags (the same ones used to build the submitted instruction) are now also forwarded to Graphite as `VerificationInput.real_account_metas`, so a required signer that isn't actually signed, or a manifest-readonly slot marked writable, is hard-blocked BEFORE the instruction is built — closing the Core-side "Privilege (Signer/Writable) Grounding" gap for this path specifically. **Residual (unchanged):** without a `payload`, no real per-account metadata is available to forward, so this check is inert on that path — the same residual as the TOCTOU gap above.

## Repository Structure

```
graphite/
├── graphite-core/          # Rust verification engine
│   ├── src/                # core modules + plugins/ + feature-gated server/cli/rpc
│   ├── protocols/          # 33 JSON protocol manifests (803 instructions)
│   ├── tests/              # 1,014 tests (unit + adversarial + exploit + pinned real corpus)
│   └── Cargo.toml
├── sdk/
│   ├── typescript/         # TypeScript SDK (GraphiteClient)
│   └── go/                 # Go SDK (19-field VerificationResult parity)
├── integrations/
│   └── solana-agent-kit/   # SAK v2 integration (verified execution gate)
├── python-ai-layer/        # Advisory intent parser (separate process, P1)
├── schemas/                # JSON schemas (proposed-intent, verification-result)
├── examples/               # Sample verification inputs/outputs
├── docs/                   # Audit reports, certification, grant proposal
├── .github/                # CI workflow + issue templates
├── ARCHITECTURE.md          # This file
├── ROADMAP.md              # Phase 1 (done) → Phase 2 (in progress) → Phase 3+
├── SECURITY.md             # Security policy + known limitations
├── CONTRIBUTING.md         # Development setup + PR checklist
├── Dockerfile              # Multi-stage container build
└── LICENSE                 # MIT
```
