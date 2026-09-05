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

See [ROADMAP.md](ROADMAP.md) for the full Phase 2 plan.
