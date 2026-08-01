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
- Unknown instructions on known protocols return `BLOCKED` (confidence 0.0), not an error
- NaN and Infinity in confidence signals are rejected — they cannot bypass the range check to produce a false approval
- The 8-layer pipeline can only reduce confidence or block — no layer can invent confidence that lower layers didn't earn
- AI/LLM output is advisory only (Constitution P1) — it never enters the verification path as a decision

## Known Limitations (Phase 1.5)

These are documented scope boundaries, not hidden vulnerabilities:

- **No instruction data semantic parsing** — Graphite matches known discriminators (hex byte comparison) but does not parse the semantic meaning of instruction data beyond the discriminator. Phase 2.
- **No live RPC simulation** — L3 (Simulation Verification) requires a Solana RPC endpoint to call `simulateTransaction`. Phase 2.
- **TOCTOU gap** — The SAK integration verifies transaction structure before execution but does not re-hash the final signed transaction against the approved `content_hash`. Phase 2 AuditBind middleware.
- **Caller-provided behavior evidence** — `behavior_evidence` fields are caller-supplied in Phase 1.5. Phase 2 Manifest Registry will query trusted historical data instead.

See [ROADMAP.md](ROADMAP.md) for the full Phase 2 plan.
