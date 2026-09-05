# Security Policy

## Reporting a Vulnerability

Graphite is a transaction verification engine — security bugs in the verification path are critical.

**Do NOT open a public issue for security vulnerabilities.**

Instead, email: victorstanley13@gmail.com with:
- A clear description of the vulnerability
- The affected component (core engine, SAK integration, SDK, AI layer)
- Steps to reproduce or proof of concept
- Your assessment of severity (CRITICAL / HIGH / MEDIUM / LOW)

You will receive a response within 72 hours. If the vulnerability is confirmed, a fix will be prioritized and a security advisory will be published after the fix is released.

## Security Architecture

Graphite follows a **fail-closed by default** philosophy (Constitution P12):

- Unknown protocols are hard-capped at 0.55 confidence — no amount of caller-provided evidence can override this
- Unknown instructions on known protocols return `BLOCKED` (confidence 0.0), not an error; novel instructions on known protocols surface a non-blocking warning (GAP-1)
- NaN, Infinity, empty, and whitespace-only values in confidence signals and simulation baselines are rejected — they cannot bypass range checks or poison the trusted baseline accumulator
- The 8-layer pipeline can only reduce confidence or block — no layer can invent confidence that lower layers didn't earn
- Account roles that are fixed, well-known constants (SPL Token/Token-2022/System/Compute-Budget/ATA program IDs, a manifest's own program self-reference) are checked against the manifest's declared `expected_address` and hard-blocked on mismatch (`AccountIdentityMismatch`), exactly like a PDA mismatch — 542 account roles across 19 manifests as of 2026-09-05. Externally-determined roles (which cannot be pre-verified — the large majority) are honestly reported as `Unverified` on `ResolvedAccount.identity` rather than silently assumed safe; see `ARCHITECTURE.md` → Account Identity.
- When a caller supplies real per-account signer/writable bits from the actual transaction (`VerificationInput.real_account_metas`), a manifest-required signer the real transaction did not sign, or a manifest-readonly slot the real transaction marks writable, is hard-blocked (`ResolvedAccount.privilege_mismatch`, folded into the same `AccountIdentityMismatch` finding) — fixed 2026-09-05. Optional and caller-supplied: absent or length-mismatched data never blocks and is never assumed to match; see `ARCHITECTURE.md` → Privilege (Signer/Writable) Grounding.
- Every instruction in a transaction is risk-assessed, not just the primary — CPI-flattened callees and top-level siblings are checked against the same structural risk rules (known-risky-discriminator table, CPI checks, drainer/hidden-transfer heuristics, impersonation), with an empty declared intent so intent-dependent checks never false-positive on ordinary multi-instruction patterns. A blocked secondary instruction is a hard gate exactly like a primary-instruction finding, and duplicate copies of the same risky secondary each independently re-confirm the block rather than diluting it — fixed 2026-09-05 (`tests/secondary_instruction_risk.rs`). See `ARCHITECTURE.md` → Secondary Instruction Risk Assessment.
- The CPI-trust exemption list (DEXes/aggregators/multisigs exempted from the untrusted-CPI-root, drainer-heuristic, and deep-chain checks) is a single canonical array, not two hand-maintained ones — a prior real drift between the two (three DEXes present in one but not the other) had silently misflagged their legitimate swaps ("C56") until caught by audit; a regression test now fails immediately if that drift is ever reintroduced — fixed 2026-09-05. See `ARCHITECTURE.md` → CPI Trust Allowlist Consolidation.
- A genuinely `Failed` L2 (instruction/data mismatch), L4 (state-verification failure), or L5 (intent/instruction mismatch) result is a hard gate — approval is blocked unconditionally, the same as an L7 risk finding, regardless of trust tier or wallet-profile threshold. This is distinct from `Inconclusive` (insufficient evidence, e.g. an unknown protocol), which never blocks and only affects confidence via the existing P12 tier ceiling. (Fixed 2026-09-05: a prior tri-state refactor correctly preserved Inconclusive's non-penalizing behavior but had unintentionally reduced a genuine Failed to a confidence penalty alone, which a high trust tier or a loose wallet profile could absorb — see `tests/l2_l4_l5_hard_gate.rs`.)
- AI/LLM output is advisory only (Constitution P1) — it never enters the verification path as a decision

## Server Hardening (shipped 2026-08-07)

The HTTP server defends against direct and replay-style abuse:

- **Authentication** — optional Bearer API key (`GRAPHITE_API_KEY`), compared in constant time (SHA-256). `/verify` and `/manifests` require it when set; `/health` stays open for load balancers.
- **Rate limiting** — per-IP token bucket (`GRAPHITE_RATE_LIMIT`, default 30 req/s), FIFO eviction, returns `429` on exhaustion. Protects the verification path from brute force and resource exhaustion.
- **CORS** — denied by default; `GRAPHITE_CORS_ORIGINS` enables specific browser origins only. Server-to-server clients are unaffected.
- **Audit log** — append-only JSONL (`audit.jsonl` under `GRAPHITE_DATA_DIR`) recorded after every verification, covering all four outcomes: approved, blocked, HTTP 400, HTTP 500. Never logs request API keys or wallet private keys.
- **Graceful shutdown** and **trusted-proxy gating** — `X-Forwarded-For` (used for per-IP limiting) is honored only when the server is explicitly configured behind a trusted proxy.

## RPC Client Security

The RPC client (active when `GRAPHITE_RPC_URL` is set) was live-audited against Helius mainnet + devnet:

- Retries with exponential backoff on `429`/`5xx`; `max_retries` honored
- `getAccountInfo` distinguishes `AccountNotFound` from a real zeroed account (no fabricated state)
- Token freeze state is read from the correct byte offset (108)
- No credentials are logged; the API key is passed via request header/URL only

## Known Limitations

These are documented scope boundaries, not hidden vulnerabilities:

- **No instruction data semantic parsing** — Graphite matches known discriminators (hex byte comparison) but does not parse the semantic meaning of instruction data beyond the discriminator.
- **L3 simulation is opt-in** — L3 (Simulation Verification) runs live `simulateTransaction` when an RPC client is attached (`GRAPHITE_RPC_URL`). Without an RPC client it reports an honest `Inconclusive` state, never a phantom pass.
- **AuditBind closes the verify-to-execute TOCTOU for the transfer path and any payload-bound swap** (`verifyInstruction` re-hashes the exact instruction against the approved `content_hash`, cross-language pinned-vector tested — `integrations/solana-agent-kit/bound-instruction.test.ts`). A payload-bound swap now builds and submits the SAME instruction directly rather than handing off to SAK's internal builder (fixed 2026-09-05). **Residual gap only when NO payload is supplied to `executeSwap`:** execution then goes through SAK's opaque `methods.swap`, which is not guaranteed to submit the reduced-projection-verified instruction — `GRAPHITE_SWAP_STRICT=1` refuses that path entirely. See `ARCHITECTURE.md` → Known Boundary Limitations.
- **Caller-provided behavior evidence** — `behavior_evidence` fields are caller-supplied; the confidence engine deliberately zeroes the evidence-derived signals (Constitution G4) so this cannot inflate confidence.
- **No independent Address Lookup Table / versioned-transaction (v0) detection** — Graphite only sees the flat `account_addresses` a caller supplies, never raw transaction bytes' version byte or ALT references; it cannot itself tell whether accounts a caller omitted were dropped because of ALT resolution. `VerificationInput.uses_versioned_transaction`/`.lookup_table_count` let a caller disclose this (surfaced as a non-blocking warning — never a confidence penalty, since ALT usage is normal for legitimate complex swaps). Full independent detection requires bincode `VersionedTransaction` parsing this crate does not implement (no `solana-sdk` dependency, by design) and is tracked as a follow-up.
- **No transaction amount/value data, and no hard cap on repeated calls to an unmanifested secondary program** — Graphite has no visibility into lamport/token amounts anywhere in its schema, so it cannot bound the cumulative damage of N calls to a program it has no manifest for. A repetition COUNT cap was deliberately not added as a hard gate: it would be trivially evaded (stay one call under the threshold) and would false-positive on a legitimate multi-call batch to a protocol that simply hasn't been onboarded yet (P12). What IS surfaced (fixed 2026-09-05): a non-blocking warning once the SAME unmanifested program is invoked 3+ times as a secondary instruction, so the pattern is visible to a human/downstream auditor even though it is not itself blocked. Genuinely dangerous secondary instructions remain hard-blocked regardless of repetition by the checks that don't require amount data or a manifest (the known-risky-discriminator table, impersonation detection) — see `ARCHITECTURE.md` → Secondary Instruction Risk Assessment.

See [ROADMAP.md](ROADMAP.md) for the full Phase 2 plan.
