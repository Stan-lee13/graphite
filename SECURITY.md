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

## Known Limitations (Phase 1.5)

## Known Limitations (Phase 1.5)

These are documented scope boundaries, not hidden vulnerabilities:

- **No instruction data semantic parsing** — Graphite matches known discriminators (hex byte comparison) but does not parse the semantic meaning of instruction data beyond the discriminator. Phase 2.
- **L3 simulation is opt-in** — L3 (Simulation Verification) runs live `simulateTransaction` when an RPC client is attached (`GRAPHITE_RPC_URL`), verified on Solana devnet. Without an RPC client it reports an honest `Inconclusive` state, never a phantom pass. Full production activation of L3/L8 across all deployments is a Phase 2 exit criterion.
- **TOCTOU gap** — The SAK integration verifies transaction structure before execution but does not re-hash the final signed transaction against the approved `content_hash`. Phase 2 AuditBind middleware.
- **Caller-provided behavior evidence** — `behavior_evidence` fields are caller-supplied in Phase 1.5. Phase 2 Manifest Registry will query trusted historical data instead.

See [ROADMAP.md](ROADMAP.md) for the full Phase 2 plan.
