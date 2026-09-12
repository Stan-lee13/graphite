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

**Two inputs, two kinds of verdict.** A caller always describes the transaction
(program, discriminator, accounts, data, siblings). A caller *may* also supply the
serialized transaction bytes as `signed_transaction`. With the bytes, Graphite parses
the wire format itself and the verdict is `artifact_bound` — tied by
`transaction_sha256` to those exact bytes, with the description checked *against*
them. Without the bytes the verdict is `descriptive` and says so. The current status
of every guarantee below is kept in one place: [docs/CURRENT.md](docs/CURRENT.md).

## Language Split

| Component | Language | Why |
|---|---|---|
| Core engine | Rust | Deterministic, no GC, auditable, fast |
| AI layer (advisory) | Python | Separate process — enforces P1 (AI assists, never decides) |
| SDK | TypeScript + Go | Consumer-facing, typed |

## 8-Layer Verification Pipeline

The pipeline executes in order. Each layer is tracked in the verification result with pass/fail status and a human-readable reason.

1. **L1 Account Resolution** — Resolves all accounts, verifies PDAs against protocol manifests (PDA derivation uses Solana's actual `create_program_address` hash-chain algorithm), and — for the fixed, well-known-constant account roles (SPL Token/Token-2022/System/Compute Budget/Associated-Token-Account programs, a manifest's own program self-reference) that are neither a PDA nor legitimately caller-chosen — checks the supplied address against the manifest's declared `expected_address` constant(s). When a caller supplies real per-account signer/writable bits (`real_account_metas`), also cross-checks them against the manifest's declared signer/writable expectations. See "Account Identity" and "Transaction Artifact" below — when the transaction bytes are supplied, the signer/writable bits are read from the message header and resolved lookup tables rather than from the caller.
2. **L2 Instruction Verification** — Confirms the instruction discriminator and account count match the manifest's declared shape (exact-match, no prefix bypass since C33). When `signed_transaction` is supplied, L2 additionally requires that the described instruction is *in* the bytes — an instruction under the described program carrying exactly the described data, whose accounts match the described accounts position by position, with lookup-table positions resolved (see "Transaction Artifact" below) — and that every other instruction in the message is declared in `transaction_instructions` (bijective sibling coverage; an undeclared sibling fails the layer). A durable-nonce transaction (instruction 0 is System `AdvanceNonceAccount`) fails L2 by default because it does not expire; see "Durable Nonces" below. L2 is a hard gate.
3. **L3 Simulation Verification** — Runs `simulateTransaction` and checks compute/account-write/CPI divergence. Active whenever an RPC client is attached (`GRAPHITE_RPC_URL`); the simulation-integrity module runs a 3-signal z-score (compute, writes, CPI hops) with Welford's algorithm against earned baselines, plus median/MAD baseline (C28) for poisoning resistance. Live-validated against real Solana devnet transactions (C40). Without an RPC client the layer reports an honest `Inconclusive` state, never a phantom pass.
4. **L4 State Verification** — Diffs pre/post account state against the manifest's declared `expected_state_changes`. With an RPC client attached and a signed transaction to simulate, Graphite builds the diff itself: pre-state from `getMultipleAccounts`, post-state from `simulateTransaction`'s `accounts` request, over exactly the instruction's writable accounts. `state_diff.rs` decodes SPL Token and Token-2022 accounts and mints (using the Token-2022 account-type byte to tell an extended mint from an extended account) and reports what changed: lamport and token balance movement, ownership reassignment, account creation and closure, delegate and close-authority grants, freezes, and mint supply changes. Token-2022 extensions are **classified, not modelled**: the TLV region is scanned and each extension is `AltersTransferSemantics` (TransferFee, TransferHook, ConfidentialTransfer, …), `AltersAuthority` (PermanentDelegate, …), `Informational`, or `Unknown`. The first, second and fourth classes fail L4 (`Token2022ExtensionNotModelled`), an unreadable or truncated extension region fails it (`Token2022ExtensionRegionUnreadable` — an empty list is never inferred from unparseable data), and informational extensions warn. A fee-bearing mint is therefore refused today; modelling `TransferFee` is the path to accepting it, lowering the classification is not.

   The rule is **observed-but-undeclared is a failure; declared-but-unobserved is a note.** A manifest is a promise about an instruction's effects, so an effect it never promised — a delegate granted during a swap, an owner reassignment during a transfer — fails the layer, and a failed L4 is a hard gate. The reverse is usually a legitimate no-op and only warns. A diff that claims to cover every writable account is additionally held to Solana's lamport-conservation identity, which catches an incomplete or fabricated diff without trusting anything in it.

   **Provenance (P5):** a caller may supply a diff, but a caller-supplied diff can only ever *fail* this layer — with no findings it yields `Inconclusive`, never `Passed`. Only a diff Graphite measured itself certifies a clean state. This is the same asymmetry L3 applies to compute usage, for the same reason. Graphite's own diff always takes precedence over a supplied one.

   Without RPC and without a supplied diff, the layer falls back to a structural consistency check on the manifest prose against the resolved account list (fund-movement wording must be matched by at least two writable accounts, authority wording by a signer, and so on) — honest about being a consistency check rather than a diff. See `tests/l4_state_diff_gate.rs`, which asserts the diff path through `verify` rather than against `check_state_diff` directly.
5. **L5 Semantic Verification** — Compares the proposed intent against the Semantic Graph's expected behavior for this program. The intent vocabulary is exactly: `swap|trade|exchange`, `transfer|send`, `stake|delegate`, `close|close_account`, `create|create_account`, `approve|revoke` (anything else fails closed). The advisory labeler (v2, C21) emits only this vocabulary.
6. **L6 Policy Verification** — Computes confidence (0.0–1.0 from weighted signals + tier ceilings) and applies wallet profile thresholds (TradingBot 80%, Treasury 95%, Gaming 55%, Enterprise 99%) and trust tier requirements
7. **L7 Risk Verification** — Pattern-matches against 11 known attack patterns (13 risk checks, hard gate, independent of confidence): Drainer, HiddenTransfer, AuthorityHijack, FakeSwap, UnexpectedCpi, PermissionEscalation, MaliciousAccountChange, CompositionalDrainPattern, Impersonation (system-account impersonation — SolPhishHunter arXiv:2505.04094), MultiInstructionDrain (C29), and CpiTraceAnomaly (C29). Runs early for fail-fast but is reported at L7 per architecture spec. Every instruction in the transaction is assessed, not just the primary — see "Secondary Instruction Risk Assessment" below.
8. **L8 Execution Verification** — Post-submission: `POST /verify/execution` (or `graphite execution`) confirms the signature on-chain and reconciles it against the verdict on the append-only trail. Outcomes: ApprovedAndExecuted, ApprovedButFailedOnChain, **BlockedButExecuted** (the gate was bypassed — the one worth paging on, and invisible to every layer inside a verification request), BlockedAndNotExecuted, NotFound, NoVerificationOnRecord, Unavailable. Caller-driven by design: Graphite does not watch the chain. Live-validated against mainnet.

### Key Properties
### CPI trace analysis

The hierarchical CPI tree of the primary instruction is scrutinised on five axes. Four measure the tree's DEPTH and its membership: an unknown program invoked anywhere in the chain, a program re-entered three or more times along a single path (the compositional-drain signature), unusual nesting depth, and a vanity-impersonated program id inside an otherwise legitimate wrapper.

The fifth measures its BREADTH, because an attacker who reads the fourth flattens their tree. A sweep does not need to nest: an instruction that loops over twenty token accounts emits twenty siblings at the same depth, and every depth-based rule sees path occurrences of one, depth of one, and a perfectly well-known Token Program. That shape was structurally invisible. Sibling fan-out groups a node's direct children by (program, instruction) and reports a group of six or more, blocking at twelve when the calls act on twelve distinct account sets.

Grouping is per PARENT rather than across the whole tree, because that is what separates a sweep from a route: a multi-hop swap also calls the Token Program a dozen times over a dozen distinct account pairs, but those calls hang off a dozen different venue programs, one or two per hop. The distinct-account requirement separates sweeping from rebalancing — repeatedly acting on the same accounts is wide but not a sweep. A trace carrying no account data can only warn: without accounts nothing corroborates the count, and no data means no verdict (P12).

The thresholds are a judgment call, stated as one. There was no corpus of real CPI traces to calibrate against — five fixtures carry a trace and none carry discriminators — so twelve is set well above any routine per-parent fan-out (a route hop makes one or two token calls; an ATA batch a handful), and the warning at six surfaces the shape long before the block. The residual gap is a deliberately shallow bush: three known intermediate programs each calling the target three times evades both the path rule and the per-parent rule, and is genuinely route-shaped.

### Quarantine (Self-Healing Semantic Graph, 3.8)

An operator can withdraw a program from trust at any time. A quarantined program's tier is forced to `Unknown` and its verifications carry a `ProgramQuarantined` risk finding, which is a hard gate — a tier downgrade alone would still let a permissive profile through, which is not what an operator means when they pull the switch.

Both quarantining and lifting are appends (P4): the pre-quarantine record stays in history reporting the tier its evidence earned at the time. Lifting RECOMPUTES the tier from evidence rather than restoring what it used to be (P7). A program with no prior record can be quarantined pre-emptively — reacting to an advisory about a program the gate has never seen traffic for is the normal case.

An accepted manifest submission appends a behaviour record, and a resubmission at the same tier is not a promotion and so is not P10-gated. An append therefore carries an active quarantine forward: otherwise publishing any new version would be a self-service restore, available to the actor whose program had just been withdrawn, with nothing checking that the new version fixed anything.

Reachable through `graphite quarantine add|lift|list` (operating on the server's durable graph, so a restart picks the change up) and `POST/GET /admin/quarantine` on a running server. The endpoint is refused outright unless `GRAPHITE_API_KEY` is configured — a `GRAPHITE_DEV_MODE=1` instance is loopback-only and keyless, and even there this switch stays closed.

**Deliberately operator-triggered, not automatic (recorded tradeoff, P14).** Quarantine forces a program to `Unknown`, which is a denial of service on every wallet profile with a tier floor. Triggering it from request traffic — N blocked verifications, N risk findings — would hand that denial to anyone who can send requests, because the inputs those checks judge are chosen by the caller: a handful of crafted transactions would withdraw Jupiter from trust for every user of the gate. The evidence for the decision is surfaced on `/api/policy-violations` and `/api/graph`; the decision itself belongs to an operator or an external monitor holding the API key.

- **L7 Risk Verification is a hard gate** — it blocks independently of confidence score. A malicious pattern blocks the transaction even if confidence is high. The Risk Engine executes early in the pipeline (before L4/L5) for fail-fast performance, but is reported at L7 per this spec.
- **L2/L4/L5 are hard gates when genuinely Failed** — a confirmed L2 instruction/data mismatch, L4 state-verification failure, or L5 intent-vs-instruction mismatch blocks approval unconditionally, exactly like an L7 risk finding, regardless of trust tier or wallet-profile confidence threshold. This is distinct from `Inconclusive` (insufficient evidence — e.g. an unknown protocol — which never blocks and only reduces confidence via the P12 tier ceiling, never via this gate). A genuine `Failed` also still applies its confidence penalty (0.2 / 0.15 / 0.3 for L2/L4/L5) so the breakdown stays explainable, but the penalty is no longer what enforces the rejection.
- **L6 Policy Verification applies tier ceilings** — Unknown/Heuristic protocols are capped at 0.55 (hard-coded, not overridable per P12). Confidence computation is included in L6.
- **L6 Policy Verification is the final gate** — it checks both confidence threshold and minimum trust tier for the wallet's profile, AND that no L2/L4/L5 layer genuinely failed.
- **L3 Simulation Verification is active when an RPC client is attached** — `GRAPHITE_RPC_URL` wires a live `simulateTransaction` call into the pipeline, live-validated against real Solana devnet transactions (C40). Without an RPC client, L3 reports `Inconclusive` (honest tri-state: `Passed` / `Failed` / `Inconclusive`) rather than a phantom pass. A flagged simulation (genuine `Failed`) is folded into the L7 risk finding `SimulationSpoofing` and is therefore already a hard gate, consistent with L2/L4/L5 above.

### Account Identity (P0-1 fix, 2026-09-05)

Most account roles in an instruction are genuinely **externally-determined** — which token account to debit, who the recipient is — and cannot be pre-verified by any means; requiring a PDA seed or an expected address on every role would be both wrong (there is nothing to check against) and infeasible. But a large, high-value subset of roles are **fixed, well-known constants**: the SPL Token, Token-2022, System, Compute Budget, and Associated-Token-Account program IDs, and a manifest's own program self-reference (the `"{program_id}"` seed-template sentinel). These are neither a PDA (no seed formula exists) nor legitimately caller-chosen.

`AccountRoleDef.expected_address` (a manifest-declared constant, or a small set of acceptable constants — e.g. a generic "token program" slot that legitimately accepts either classic SPL Token or Token-2022) lets the manifest pin these slots. Account resolution checks the supplied address against them and, on mismatch, sets `ResolvedAccount.expected_address_mismatch` — folded into the SAME hard-block risk finding (`AccountIdentityMismatch`) that a PDA mismatch already produces (Constitution P4). 542 account roles across 19 manifests are pinned this way as of this fix (`graphite-core/scripts/populate_expected_addresses.py` — rerun when onboarding a new protocol).

`ResolvedAccount.identity` (`Pda` / `Constant` / `Unverified`) makes the **remaining, unavoidable trust boundary** visible rather than silently assumed safe: an externally-determined account (the large majority of roles) reports `Unverified` honestly — this is not a finding or a penalty, just disclosure (P12: absence of verification is not itself evidence of harm). Closing that remaining boundary for fund-critical externally-determined accounts (e.g. confirming a token account's on-chain owner matches the transaction signer) requires live account data and is tracked as a follow-up, not claimed here.

### Transaction Artifact: Parsing, Lookup Tables, Privileges, Scope (2026-09-08 → 2026-09-12)

Until 2026-09-08 Graphite only ever saw the flat `account_addresses` list a caller
supplied. It now reads the transaction itself when one is supplied.

**Parsing (`tx_artifact.rs`).** A hand-written parser for the Solana wire format —
`[compact-u16 signature count][64-byte signatures][message]`, legacy and v0 — with no
`solana-sdk` dependency. Every length is a canonical compact-u16 (three groups at most,
minimal encoding, ≤ 65,535); trailing bytes, out-of-range program and account indexes,
and impossible headers are refused. It yields the static keys, the header-derived signer
and writable sets, the fee payer, the recent blockhash (or nonce value), every
instruction with its program, account indexes and raw data, and the address-table
lookups with their indexes. A parse failure never yields a partial answer.
`message_bytes` — the same signature skip the parser uses — is exported so the
TypeScript bridge's `messageOf` and Graphite's acceptance language can be asserted equal:
`tests/sak_bridge_corpus.rs` replays 12 transaction shapes and 1,641 byte-level
mutations emitted by `@solana/web3.js` and requires exact agreement on every one.

**Address lookup tables.** A v0 message names tables and indexes, not addresses. With
an RPC client attached, the tables are fetched under the RPC budget *before* account
resolution, the owner is checked (`AddressLookupTab1e1111111111111111111111111` — bytes
under any other owner would be refused at execution and must not resolve anything),
deactivating tables are refused, and the addresses are decoded. Resolution is
all-or-nothing: a partial list would renumber every later position, which is worse than
no answer. `runtime_account_list` rebuilds the runtime's numbering — static keys, then
resolved writables in message order, then resolved readonlies — so an instruction's
account indexes map to identities exactly as the runtime maps them; the positional L2
comparison covers every position, including the ones a v0 transaction reaches without
naming. Ground truth: three real mainnet v0 transactions and eight real tables in
`fixtures/artifacts/mainnet_v0_alt.json`, checked against `meta.loadedAddresses`
(`tests/alt_real_v0.rs`). When tables cannot be resolved (no RPC, budget, wrong owner)
the accounts are *counted and not identified*, and `scope.unobserved` says so.

**Privileges come from the bytes.** `ResolvedAccount.is_signer` / `.is_writable` are
manifest-declared expectations. What they are checked against is now derived from the
artifact — the header for static accounts, the resolved table half (writable or readonly
list) for ALT accounts, which are never signers — and only when the artifact cannot
answer for every described account does the caller's `real_account_metas` stand in.
`PrivilegeSource` is reported in L1: `Artifact`, `ArtifactWithLookupTables`,
`ArtifactContradictingCaller` (the header was used and the caller's description
disagreed with it — the description is unreliable), `Caller`, or `Absent`. Two artifacts
that differ only in one header count — a manifest-readonly account moved into the
writable section — reach different verdicts (`tests/privilege_from_artifact.rs`,
`tests/alt_privilege.rs`). The security-relevant mismatch directions (required signer
unsigned; readonly slot writable) fold into the hard-block `AccountIdentityMismatch`.

**Scope.** `VerificationResult.scope` is `oneOf` two shapes (`schemas/verification-result-v1.json`):
`artifact_bound { transaction_sha256, transaction_bytes, simulated, unobserved }` when
bytes were supplied, `descriptive { unobserved }` otherwise. `unobserved` names, in
words, what was not established — unsimulated bytes, unresolved tables, the caller's
privileges having been used, inner instructions invisible to a message parser. It is
never empty; which residuals a deployment accepts is a deployment decision, and the
bridge surfaces them without deciding.

**Durable Nonces.** The runtime treats a transaction whose instruction 0 is a System
`AdvanceNonceAccount` as nonce-based: its `recent_blockhash` slot carries the nonce
account's stored value and the transaction does not expire. Every state-based
conclusion in a verdict is true at verification time only, and the bridge's
`lastValidBlockHeight` — its only bound on the verify → sign → send window — does not
apply. `tx_artifact::durable_nonce` detects the shape by the runtime's rule; L2 refuses
it by default, naming the nonce account, authority and value. An operator whose flow
needs them (offline or hardware-wallet signing) sets `GRAPHITE_ALLOW_DURABLE_NONCE=1`,
after which the nonce account is fetched and must be System-owned, initialized, hold
exactly this value under the instruction's named authority, which must be a required
signer — every mismatch is one the runtime refuses at load, or a nonce that already
advanced. No RPC refuses: the opt-in is "permitted once verified". The bridge refuses
to build the shape at all.

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
- **P5:** Simulation is evidence, not truth — RPC-derived numbers come only from canonical response fields, are bounded, and can lower or fail a verdict; a caller-supplied diff can only fail L4, never pass it
- **P9:** The audit trail is append-only, every record is synced to the device before the response, a verdict that cannot be recorded is refused (`503`), and every reader covers rotated archives
- **P12:** Unknown protocols capped at 0.55 confidence — hard-coded, not overridable; anything Graphite cannot observe is disclosed as unobserved, never assumed
- **P14:** Recorded tradeoffs — operator opt-ins (`GRAPHITE_ALLOW_DURABLE_NONCE`, `GRAPHITE_ALLOW_PERMISSIVE_PROFILES`, the SAK swap opt-out phrase) are named, logged at startup, and default off
- **P16:** No public performance claim without reproducible benchmark

## Server (HTTP API)

The axum-based HTTP server exposes `POST /verify`, `POST /verify/execution` (L8
reconciliation), `POST /audit/event` (caller-reported lifecycle events, P9),
`POST`/`GET /admin/quarantine` (operator), `GET /manifests`, `GET /metrics`
(Prometheus), `GET /health` (open), and the read-only dashboard API (`/api/graph`,
`/api/confidence-history`, `/api/policy-violations`, `/api/protocols/top`,
`/api/registry`).

| Concern | Implementation |
|---|---|
| **Authentication** | Bearer API key (`GRAPHITE_API_KEY`), compared in constant time (SHA-256), required on every route except `/health`. Startup refuses without a key unless `GRAPHITE_DEV_MODE=1`, which is permitted only on loopback (`server::auth_posture`, decided before anything binds). |
| **Rate limiting / load shedding** | Per-IP token bucket (`GRAPHITE_RATE_LIMIT`, default 30 req/s) returns `429`; in-flight verifications capped (`GRAPHITE_MAX_CONCURRENT`, default 32) and excess shed with `503` + `Retry-After`. Counted separately at `/metrics`. |
| **Request bounds** | 1 MiB body, 10 s request timeout that the RPC budget fits inside, identifier length caps on every caller-influenced field that reaches a log or the audit trail. |
| **CORS** | Denied by default; `GRAPHITE_CORS_ORIGINS` (comma-separated) enables specific browser origins. |
| **Audit trail** | Append-only JSONL under `GRAPHITE_DATA_DIR`. Every record is `sync_data`'d to the device before the response is sent; a verification whose record cannot be written is refused with `503` rather than answered. Rotation at `GRAPHITE_AUDIT_ROTATE_BYTES` (64 MiB) is a rename, never a rewrite; archives are kept unless `GRAPHITE_AUDIT_MAX_ARCHIVES` is set. Every reader — dashboard endpoints and L8's `last_verification_for` — covers the archives plus the active file, with per-archive statistics cached because archives are immutable. Lifecycle events reported by callers are stored as attestations with `reported_by`; no reader treats them as a verdict. |
| **Durability** | Semantic-graph snapshot (trust tiers + earned simulation baselines) written atomically (temp file synced, then renamed) and reloaded on restart. Snapshot failures are counted. |
| **Health** | `/health` reports `degraded` with `degraded_reasons` (`audit_writes_failed`, `audit_rotation_failed`, `audit_disabled`, `graph_snapshot_failed`), audit counters, and `graph_persistence`; `status` stays `ok` while traffic can be served so load balancers do not pull a working node. |
| **Metrics** | Verification volume / approve / block / error, auth failures, `429` and `503` counts, lifecycle events, audit writes and rotations, archive count, snapshot outcomes. Every series is genuinely incremented. |
| **Operator policy** | `GRAPHITE_WALLET_PROFILE` pins the profile server-side (the request body's profile is then ignored); `GRAPHITE_ALLOW_PERMISSIVE_PROFILES` gates `Custom` profiles below the weakest built-in; `GRAPHITE_ALLOW_DURABLE_NONCE` permits nonce transactions after on-chain verification. All default closed. |
| **Graceful shutdown** | SIGINT/SIGTERM drain in-flight requests before exit. |
| **Trusted proxy** | `GRAPHITE_TRUST_PROXY` is the number of proxy hops; the client IP is taken that many entries from the right of `X-Forwarded-For`, never the attacker-controlled left end. |

## What Graphite Does NOT Do (Honest)

- Does NOT decode instruction data semantics beyond the discriminator for protocols it has no manifest for (it parses the transaction's wire format — structure, accounts, privileges, data bytes — but reads amounts and arguments only where a manifest or the state diff gives them meaning)
- Does NOT detect novel attack patterns (only the 11 known patterns / 14 checks are matched)
- Does NOT use AI/ML in the verification path (deterministic pattern matching only; the Python layer is an advisory labeler)
- Does NOT treat the advisory labeler's suggestions as decisions — a wrong suggestion simply fails to match and the verification blocks (P1)
- Does NOT watch the chain — L8 is caller-driven; someone must report the signature after submission
- Does NOT execute a durable-nonce transaction's freshness assumption for the operator — a permitted nonce transaction is verified as executable *if submitted before the nonce advances*, and the missing clock is the operator's accepted tradeoff
- Does NOT work on chains other than Solana (SVM-specific, complete rewrite needed)
- Does NOT hold wallet private keys — the Rust core never receives signing material; keys live at the wallet/SAK boundary (the integration bridge holds them to execute, like any self-custody agent wallet)

## The Execution Boundary (SAK bridge)

The integration under `integrations/solana-agent-kit/` is the reference for how a
verdict reaches a signer. Its invariant, established 2026-09-11 and attacked in Rounds
6–8: **for every executable `artifact_bound` approval, the exact Solana message
Graphite approved is the exact message contained in the bytes signed and submitted.**

- **One transaction object, built before verification.** Both the transfer and the swap
  path build a single `BoundTransaction` (`artifact.ts`) from deep-copied instructions
  — program id, keys, flags and data all copied at build time, so no alias the caller or a
  plugin holds can reach the transaction — and send its bytes as `signed_transaction`.
- **One signing path.** `signApproved(transaction_sha256, signers)` is the only way to
  obtain signed bytes: it recomputes the digest of the exact artifact and refuses a
  mismatch; it derives the required signer set from the compiled message's header and
  refuses a wrong, missing or extra signer; it signs and asserts the signed bytes carry
  the same message slice; and it returns the only bytes meant for `sendRawTransaction`.
  `assertApproved`, `assertSignersMatchTheMessage` and `signAndFreeze` are private.
  A refreshed blockhash, a changed fee payer, an appended instruction, a rewritten
  amount, a redirected destination or a flipped writable bit after approval is a
  different digest and is refused (`bound-transaction.test.ts`,
  `execution-boundary-fuzz.test.ts`).
- **A descriptive verdict never executes.** The bridge requires
  `scope.kind === "artifact_bound"` before signing.
- **Swaps require the built payload.** Without the exact instruction (program id,
  discriminator, accounts with real flags, data) there is nothing to bind, and the bridge
  aborts. Executing an unverified swap requires
  `GRAPHITE_SWAP_ALLOW_UNVERIFIED_EXECUTION=I_ACCEPT_UNVERIFIED_SWAP_EXECUTION` — a phrase,
  not a `1`, so it is not set by accident — and the result then reports
  `verifiedExecution: false` with `unverifiedReason`.
- **`content_hash` / AuditBind is secondary.** It re-hashes one instruction's projection
  and is kept as an instruction-level invariant and the audit/L8 join key; it is not the
  transaction's identity and is not what the signing gate checks.
- **Durable-nonce shapes are refused at build.** `lastValidBlockHeight` does not bound them.
- **Cross-language agreement is asserted, not assumed.** `emit-corpus.ts` records what
  `@solana/web3.js` and `messageOf` conclude about 12 shapes and 1,641 mutations;
  `tests/sak_bridge_corpus.rs` requires Graphite to agree; CI regenerates the corpus and
  fails on drift.

**Outside the boundary, stated as such:** a process that can rewrite the bridge module
can replace the gate itself; `unobserved` is surfaced and not gated; a permitted
durable-nonce transaction has no clock.

## Repository Structure

```
graphite/
├── graphite-core/          # Rust verification engine
│   ├── src/                # core modules + plugins/ + feature-gated server/cli/rpc
│   ├── protocols/          # 33 JSON protocol manifests (803 instructions)
│   ├── tests/              # 1,422 tests (unit + adversarial + exploit + RPC trust boundary + real mainnet v0/ALT + cross-language corpus)
│   └── Cargo.toml
├── sdk/
│   ├── typescript/         # TypeScript SDK (GraphiteClient)
│   └── go/                 # Go SDK (19-field VerificationResult parity)
├── integrations/
│   └── solana-agent-kit/   # SAK v2 integration (verified execution gate)
├── python-ai-layer/        # Advisory intent parser (separate process, P1)
├── schemas/                # JSON schemas (proposed-intent, verification-result)
├── examples/               # Sample verification inputs/outputs
├── docs/                   # CURRENT.md (status now) + dated campaign reports (historical)
├── .github/                # CI workflow + issue templates
├── ARCHITECTURE.md          # This file
├── ROADMAP.md              # Phases 1–2 complete; hardening rounds; Phase 3 gates
├── SECURITY.md             # Security policy + known limitations
├── CONTRIBUTING.md         # Development setup + PR checklist
├── Dockerfile              # Multi-stage container build
└── LICENSE                 # MIT
```
