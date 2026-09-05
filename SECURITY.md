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

## Production Hardening (shipped 2026-09-05)

A production-readiness audit of the server, container, and deployment surface produced the following fixes. Each is covered by a regression test.

- **RPC credentials can no longer leak into an API response (CRITICAL).** `reqwest::Error`'s `Display` appends `" for url (…)"`, and managed Solana RPC providers embed the operator's API key directly in that URL. Those error strings reached the L3 layer `reason` field, which is serialized into the `/verify` response body — so any ordinary transport hiccup (timeout, DNS blip, provider outage) handed the operator's paid RPC credentials to whoever made the request, with no attacker infrastructure required. Transport errors are now classified by category (`timeout`, `connection failed`, …) and never stringified. See `tests/rpc_secret_redaction.rs`, which asserts on the secret's *absence* across query-string, path-segment, and basic-auth key placements, on timeouts, and after retry exhaustion.
- **Per-IP rate limiting can no longer be bypassed by spoofing `X-Forwarded-For` (HIGH).** The client IP was read from the *leftmost* `X-Forwarded-For` entry — the attacker-controlled one, since every standard reverse proxy *appends* the peer it observed. Rotating that header produced a fresh token bucket per request, making the limiter a no-op. `GRAPHITE_TRUST_PROXY` is now the *number of trusted proxy hops*, and entries are counted from the right; a chain shorter than the configured hop count falls back to the direct peer rather than trusting a partial chain. See the `xff_*` tests in `server.rs`.
- **The server refuses to start without a writable audit directory.** The standard container failure — a named volume mounted `root:root` while the process runs unprivileged — let `create_dir_all` succeed while every subsequent audit append silently failed, producing a service that looked healthy and recorded nothing. An unwritable data directory is an internal integrity failure (P9 cannot be satisfied), so startup now probes writability and aborts with an actionable message. The image creates and owns `/data` at a fixed UID/GID so this cannot recur by default.
- **An unauthenticated server can no longer be exposed to the network by accident.** `graphite server` bound `0.0.0.0` unconditionally, so a developer running it locally published an API — unauthenticated when `GRAPHITE_API_KEY` is unset — to every reachable network. It now binds loopback by default (`--host` to override) and *refuses* to bind a non-loopback address when no API key is set.
- **Logging actually works.** The crate emits `tracing` events throughout — including audit-write failures — but no subscriber was installed, so every one of them was a silent no-op: an operator whose disk filled got no signal that the audit trail had stopped. A subscriber is now installed at startup (`GRAPHITE_LOG_FORMAT=json` for structured output, `RUST_LOG` for level).
- **Container/runtime hardening.** Non-root fixed UID, `read_only` rootfs with a `tmpfs` for `/tmp`, `cap_drop: ALL`, `no-new-privileges`, CPU/memory/pids limits, log rotation, host port bound to loopback by default, and `curl` removed from the runtime image in favor of a built-in `graphite healthcheck` subcommand. Builds use `--locked` and no longer suppress errors in the dependency-cache stage.
- **CI now gates the things that ship.** `cargo audit` fails the build on any RUSTSEC advisory in the dependency tree, and a container job builds the actual image, boots it, and asserts it becomes healthy, that `/data` is writable, and that unauthenticated `/verify` returns `401`.

## RPC Client Security

The RPC client (active when `GRAPHITE_RPC_URL` is set) was live-audited against Helius mainnet + devnet:

- Retries with exponential backoff on `429`/`5xx`; `max_retries` honored
- `getAccountInfo` distinguishes `AccountNotFound` from a real zeroed account (no fabricated state)
- Token freeze state is read from the correct byte offset (108)
- No credentials are logged, and RPC endpoint URLs (which embed provider API keys) are redacted from every error surfaced to a caller or written to the audit trail — see Production Hardening above

## Known Limitations

These are documented scope boundaries, not hidden vulnerabilities:

- **No instruction data semantic parsing** — Graphite matches known discriminators (hex byte comparison) but does not parse the semantic meaning of instruction data beyond the discriminator.
- **L3 simulation is opt-in** — L3 (Simulation Verification) runs live `simulateTransaction` when an RPC client is attached (`GRAPHITE_RPC_URL`). Without an RPC client it reports an honest `Inconclusive` state, never a phantom pass.
- **AuditBind closes the verify-to-execute TOCTOU for the transfer path and any payload-bound swap** (`verifyInstruction` re-hashes the exact instruction against the approved `content_hash`, cross-language pinned-vector tested — `integrations/solana-agent-kit/bound-instruction.test.ts`). A payload-bound swap now builds and submits the SAME instruction directly rather than handing off to SAK's internal builder (fixed 2026-09-05). **Residual gap only when NO payload is supplied to `executeSwap`:** execution then goes through SAK's opaque `methods.swap`, which is not guaranteed to submit the reduced-projection-verified instruction — `GRAPHITE_SWAP_STRICT=1` refuses that path entirely. See `ARCHITECTURE.md` → Known Boundary Limitations.
- **Caller-provided behavior evidence** — `behavior_evidence` fields are caller-supplied; the confidence engine deliberately zeroes the evidence-derived signals (Constitution G4) so this cannot inflate confidence.
- **No independent Address Lookup Table / versioned-transaction (v0) detection** — Graphite only sees the flat `account_addresses` a caller supplies, never raw transaction bytes' version byte or ALT references; it cannot itself tell whether accounts a caller omitted were dropped because of ALT resolution. `VerificationInput.uses_versioned_transaction`/`.lookup_table_count` let a caller disclose this (surfaced as a non-blocking warning — never a confidence penalty, since ALT usage is normal for legitimate complex swaps). Full independent detection requires bincode `VersionedTransaction` parsing this crate does not implement (no `solana-sdk` dependency, by design) and is tracked as a follow-up.
- **Single-replica only; no horizontal scaling** — durable state (the append-only audit log and the semantic-graph snapshot holding earned trust tiers and simulation baselines) lives on a local volume with no cross-process locking or coordination. Two replicas sharing a volume would race on those writes; two replicas with separate volumes would fragment the earned-trust history the confidence model depends on, so a protocol's tier would differ depending on which replica answered. Run exactly one replica (Kubernetes: `strategy: Recreate` with a PVC) behind your load balancer until a shared-state backend exists. Documented rather than silently assumed — an operator scaling this to 3 pods for HA would get subtly wrong confidence scores, not an error.
- **TLS is terminated upstream, not in-process** — the server speaks plain HTTP by design and has no TLS listener. The bearer API key and full verification payloads therefore travel in cleartext unless a reverse proxy terminates TLS in front of it. The server refuses to bind a non-loopback address without an API key, but it cannot detect the absence of TLS; that remains an operator responsibility.
- **No transaction amount/value data, and no hard cap on repeated calls to an unmanifested secondary program** — Graphite has no visibility into lamport/token amounts anywhere in its schema, so it cannot bound the cumulative damage of N calls to a program it has no manifest for. A repetition COUNT cap was deliberately not added as a hard gate: it would be trivially evaded (stay one call under the threshold) and would false-positive on a legitimate multi-call batch to a protocol that simply hasn't been onboarded yet (P12). What IS surfaced (fixed 2026-09-05): a non-blocking warning once the SAME unmanifested program is invoked 3+ times as a secondary instruction, so the pattern is visible to a human/downstream auditor even though it is not itself blocked. Genuinely dangerous secondary instructions remain hard-blocked regardless of repetition by the checks that don't require amount data or a manifest (the known-risky-discriminator table, impersonation detection) — see `ARCHITECTURE.md` → Secondary Instruction Risk Assessment.

See [ROADMAP.md](ROADMAP.md) for the full Phase 2 plan.
