# Graphite — Current Status

**This is the one document that describes the codebase as it is now.** Every
other file in `docs/` is a dated record of what was true when it was written;
each carries a banner pointing here. When this file and a report disagree,
this file is current and the report is history.

Updated: 2026-10-22, after Round 30 — the forensic whole-repository audit of `29e4356` remediated: every verdict says whether it permits signing (`decision`, `executable`); evidence trains only at the built-in floor; baselines are per shape and anchored; an upgrade withdraws evidence; the audit trail is hash-chained and, keyed, tamper-evident; L8 says what its answer rests on; honest intents for 21 grounded withdraw/claim/close/burn/configure instructions (see `git log -1 -- docs/CURRENT.md`). Round 30 report: [`round30-forensic-audit-and-remediation-2026-10-22.md`](round30-forensic-audit-and-remediation-2026-10-22.md).
If that commit is not HEAD, later commits may have moved things;
`git log --oneline -- docs/CURRENT.md` shows when this page last changed.

---

## What Graphite is

A deterministic, pre-signature verification gate between an AI agent and a
Solana wallet. It takes a description of an intended transaction plus,
whenever possible, the exact serialized transaction bytes, runs an eight-layer
pipeline over them, and returns `approved: true | false` with a full account
of what was and was not observed — and, since Round 30, a `decision`: only
`executable_approved` (`executable: true`) permits signing; an approval whose
bytes nothing simulated is `analysis_only`. **AI never decides** (Constitution P1); the
verdict is deterministic (P2) and explainable (P3); anything Graphite cannot
observe is refused rather than assumed (P12).

## Security status

```
Overall:                         CONDITIONAL — security-hardened alpha. Round 30 verdict: RELEASE BLOCKED on
                                 owner and external gates (branch rules not applied, no independent audit, no
                                 production deployment or operations); the code is READY FOR INDEPENDENT AUDIT
Exact transaction identity:      enforced (artifact_bound scope, transaction_sha256, message-equality at signing);
                                 an artifact without instruction_data, or one that does not parse, FAILS L2 (Round 9)
Execution decision:              every verdict carries `decision` (executable_approved | analysis_only |
                                 inconclusive | blocked) and `executable`, computed once in the Core: executable
                                 only when approved, risk Clear, policy Approved, artifact_bound AND simulated,
                                 every residual inherent, no layer Failed. No RPC → analysis_only; a refusal for
                                 missing evidence → inconclusive. The TS and Go SDKs, the agent guard and the
                                 dashboard recompute it and refuse a disagreement or an unknown value; `graphite
                                 verify` exits 0 only for executable_approved, 3 for analysis_only (Round 30, G-01)
Residuals at execution:          gated — scope.unobserved_codes; the bridge refuses any non-inherent residual
                                 the operator has not accepted by code (GRAPHITE_ACCEPT_UNOBSERVED); a verdict
                                 executed under an accepted residual is recorded as analysis_only, on the
                                 operator's named acceptance, never as executable_approved
ALT / v0 account identity:       enforced (runtime numbering rebuilt; all-or-nothing resolution; owner checked)
Privilege source:                the transaction's header / tables, never the caller's description; the fee
                                 payer's writable flag is structural and is not an escalation (Round 20); L4
                                 observes every account the transaction can write. A declared-read-only account
                                 marked writable is judged by what happened (Round 21): another located
                                 instruction's declared write explains it; otherwise it passes only when
                                 Graphite's simulation observed it unchanged, and blocks without that observation.
                                 A declared signer that does not sign always blocks. Writability is the RUNTIME's
                                 (Round 22): sysvars, builtins and invoked program ids are demoted as agave does;
                                 an Anchor program's own id in a slot its IDL marks optional is the account ABSENT
Instruction identity for risk:   the instruction's own leading bytes, never the caller's label — a hex
                                 discriminator contradicting its instruction_data fails L2 for every protocol,
                                 a non-hex one never reaches a verdict, and the known-risky table is keyed on
                                 the bytes so a truncated but truthful label hides nothing (Round 13)
Authority changes in the diff:   the SPL owner field, mint authority and freeze authority are each watched;
                                 an undeclared change is Critical, so a hand-over that moves no value is seen
Measured on real mainnet:        19,458 transactions fetched 2026-09-23 (12,134 legacy, 4,022 v0, 3,302 v1),
                                 283 programs, run artifact-bound through the whole pipeline: 0 parse failures,
                                 0 verify errors, 0 false refusals from the L2 self-consistency check. Round 19's
                                 fixes changed 0 of 16,149 verdicts on the rows both builds read, except F-19-28,
                                 which moved 104 executed transactions from refused to L2-passed. 40 of them were
                                 also verified one at a time against the public mainnet RPC (Graphite's own
                                 simulation and state reads): 0 invariant violations (`tools/mainnet-sample`,
                                 `tests/mainnet_live_rpc.rs`). Round 21 widened it to three days (2026-09-23,
                                 -25, -27; 39,857 verified): 0 parse failures, 0 verify errors; Round 21 moved
                                 2,553 executed transactions Blocked → Clear on risk and 0 the other way; Round 22
                                 another 230, 0 the other way, and grounded every manifest in 2,998 of its
                                 programs' own executed transactions (45,253 of 45,282 instructions clean).
                                 Round 23 (2026-10-01) re-ran four days (+2026-09-30; 48,855 verified) against
                                 3327fcf: 0 parse failures, 0 verify errors, 461 Blocked → Clear (durable-nonce
                                 transactions no longer refused for their nonce advance, F18) and 9 Clear →
                                 Blocked (protocol or pool configuration and one program-upgrade hand-over, F3).
                                 Round 24 (2026-10-03), the same four samples against eb17aa5 and the labels it
                                 was measured with: 0 parse failures, 0 verify errors, 302 Clear → Blocked (a
                                 transfer label on a buy, a close, a creation or a withdrawal, which R2 refuses),
                                 0 Blocked → Clear, 0 approved before or after. Under honest labels 219
                                 transactions with a manifested primary are newly refused (AUDIT R2-c).
                                 The samples are not in the repo (gitignored); since Round 24 they are fetched
                                 by slot list and their SHA-256 is recorded in tools/mainnet-sample/SAMPLES.md,
                                 so a re-run can be checked against these files. Since Round 26 two of the
                                 blocks (2,284 transactions) ARE committed and run on every cargo test with
                                 the verdict file's SHA-256 pinned (equal to the full run's for those rows).
                                 Round 29 re-pinned them on 2026-10-21: 3 of 2,277 rows changed, each attributed
                                 to the manifest reclassification in the test's comment; 0 approvals before and after.
                                 Round 30 re-pinned them once more: the harness no longer takes a durable-nonce
                                 advance as a transaction's primary (rows 442, 1272, 1366 now read their System
                                 transfer and are still refused at L2); 0 approvals before and after
Manifest coverage of the chain:  137 manifests / 3,541 instructions (129 / 3,195 when the sample below was measured). On a 10,617-transaction mainnet sample
                                 fetched on 2026-09-22 (not in the repo; 1,829 of it, 17.2%, version 1),
                                 44.0% of non-vote transactions have a manifested primary program, up from 20.8%
                                 for the same sample before Round 18. The rest still meet the drainer heuristic
                                 (>=3 accounts, no declared state changes), which is the fail-closed posture at
                                 the coverage boundary, not a bug. Measured in Round 22: 71% of its refusals are of
                                 programs every transaction of which was signed by five or fewer fee payers (bots
                                 running their own, IDL-less programs)
Trust tier a manifest declares:  checked, not believed - `BattleTested` is lowered to `OfficialManifest` at load
                                 unless protocols/battle_tested_evidence.json shows an executable program, >=1,000
                                 successful transactions over a stated window, and >=90% of really-observed
                                 instructions named by the manifest (Round 18). The measured tier is registry and
                                 display information: the verdict path caps every manifest at OfficialManifest, and
                                 a verdict reaches BattleTested only through operator-seeded graph evidence
Verdict trust tier:              the MINIMUM over every top-level program the transaction invokes (primary,
                                 declared siblings, artifact instructions), each tiered like the primary; an
                                 unmanifested sibling makes it Unknown, refused on every built-in profile (Round 29).
                                 The evidence signals stay the primary's
Grounded intents:                `withdraw`, `claim`, `burn` and `configure` (and `close` widened) since Round 30, each
                                 for named instructions only (src/intent_grants.rs, 21 grants) and only when the
                                 transaction's own accounts show the proceeds or rent go to the signer (its
                                 associated token account, derived; the same key; a PDA seeded by it). A failed fact
                                 leaves the manifest's class in force and names itself in the refusal. The Core does
                                 not judge a withdrawal's minimum outputs; the guard builds only transfers and swaps
L4 under an unreadable manifest: a signer's token debit or lamport loss under a silent or unreadable declaration is
                                 Critical unless the instruction's class moves value (Round 30, R30-F-1); a manifest
                                 line may not start with `graphite:`
Simulation as a gate:            with an RPC client and an artifact, an errored simulation is SimulationFailed (L3
                                 Failed) and one that could not be obtained or is incomplete (RPC error, timeout,
                                 budget, implausible answer, unreadable callee report, unrebuildable CPI tree,
                                 missing pre/post diff) is VerificationIncomplete; both refuse (Round 29). WITHOUT an
                                 RPC client nothing is simulated: L3 Inconclusive, `not_simulated` residual, and every
                                 approval is `decision: analysis_only` — never permission to sign (Round 30). The
                                 server says so at startup and on /health (`verification_mode`, `rpc_attached`)
Message version 1:               parsed since Round 19 (17.0% of the sample): never looser than agave's wincode
                                 decoder + sanitize (runtime oracle, ~628,500 frames per CI seed, 0 looser);
                                 3,302 of 3,302 real v1 transactions read and bound; ≤ 4,096 bytes; the config
                                 values surfaced in scope.compute_budget with the legacy/v0 Compute Budget
                                 instructions' (Round 21); a requested priority fee above the plausible-fee
                                 ceiling is refused (ExcessivePriorityFee)
Durable-nonce transactions:      refused at L2 by default; opt-in requires on-chain nonce verification
Token-2022 extensions:           classified; the TRANSFER FEE is modelled (Round 20) and, since Round 21, REPLAYED:
                                 every Token-2022 instruction the simulator executed (top level and CPI) is replayed
                                 from the pre-state and must end exactly at the post-state — withdrawals of withheld
                                 fees, several transfers into one account and accounts that send and receive are
                                 modelled; the epoch is read and only its schedule accepted; a pending schedule is
                                 always judged — no slot margin bounds a blockhash's landing (Round 22). A hook naming
                                 no program, untouched confidential state and a mint's unchanged standing powers are
                                 inert; a hook that RUNS a program is inert when the bytes bound it — nothing
                                 Token-2022 can hand it signs, and every writable account among them is its own
                                 (Round 22); a permanent delegate moving someone else's tokens is Critical. Anything
                                 the model cannot account for exactly — a hook the bytes do not bound, changed
                                 confidential state, an unknown or unreadable extension — blocks
Input bounds:                    artifact ≤ 1232 bytes (PACKET_DATA_SIZE) for legacy/v0, ≤ 4,096 for v1,
                                 ≤ 256 declared siblings, every
                                 audit-trail field bounded on the way to disk
Pre-signed artifacts:            refused at /verify — any non-zero signature slot is a 400; the bound digest is
                                 the unsigned frame's, the same one L8 recovers from the chain (Round 17)
What trains the baseline:        only a sound, risk-clear, successfully simulated ARTIFACT whose described
                                 instruction was located in it; err != null is not evidence; one observation per
                                 simulation identity — the frame with signatures and blockhash zeroed, so a fresh
                                 blockhash is not a new observation (Round 19; it approved a refused transfer on
                                 its third ask before); identities remembered exactly per program (16,384, never
                                 forgotten; a full memory routes to the shadow); a uniform history is a ±25% band;
                                 refused-but-clean executions accumulate in a shadow /health reports and an
                                 operator can promote (Round 17). Since Round 30 a simulation counts only when the
                                 verdict clears the weakest BUILT-IN bar on its own (0.55 / HeuristicInferred) —
                                 never the profile the request named, so a verify-key holder's self-approved
                                 requests teach nothing (R30-B-1); GRAPHITE_LEARN_FROM_POLICY_REFUSALS is retired
                                 and refuses startup; operator seeding is `graphite evidence seed` / `baseline`.
                                 Baselines are kept per transaction SHAPE (program, instruction, the other top-level
                                 programs) once 10 samples exist, and a mature baseline is ANCHORED: a value more
                                 than 2σ from the anchor is flagged, so a slow drip cannot walk the band (R30-B-2).
                                 A detected upgrade or authority change withdraws the program's evidence (R30-B-3)
Observed CPI targets:            read from the simulation's innerInstructions and judged by the same rules as a
                                 declaration; declaring nothing switches nothing off (Round 17). Since Round 19 the
                                 whole observed call TREE (by stackHeight, with accounts and data) is judged by the
                                 CPI-trace rules — re-entry, sweep fan-out, impersonation — not only a declared one
Lookup-table resolution:         approval is conditioned on it — an unresolved position fails L2 (Round 17)
Audit trail durability:          fdatasync per record; whole-trail reads across rotated archives; indexed L8 join
L8 execution attribution:        joined on the chain's bytes (signature slots zeroed → scope.transaction_sha256),
                                 accepted only when bound to the signature — first slot equal to it, verifying
                                 under the fee payer's key — else refused with nothing attributed (Round 11);
                                 caller keys audit_trail_id → transaction_sha256 → content_hash, most exact first,
                                 cross-checked, never falling back (Round 10); a cited audit_trail_id for OTHER
                                 bytes is named (RecordedForDifferentBytes, a discrepancy when it was a refusal)
                                 and every verdict on record for the chain digest is counted (Round 17)
L8 inclusion evidence:           commitment read (processed proves nothing); an RPC contradicting itself or answering
                                 malformed draws no conclusion; redirects refused; optional independent witness
                                 (GRAPHITE_RPC_WITNESS_URL) must agree before an approval is reported executed;
                                 a blocked transaction sighted by either endpoint alarms (Round 12). Since Round 30
                                 every reconciliation says what it rests on (`inclusion_assurance`: single_provider,
                                 witnessed, witnessed_not_independent, witness_disputed, witness_unavailable); a
                                 witness on the same host, registrable domain or resolved address — or the same
                                 provider under another API key — is not independent; GRAPHITE_L8_HIGH_ASSURANCE=1
                                 withholds every chain statement an independent witness does not agree with (never
                                 the BlockedButExecuted alarm) and refuses to start without https on both, an
                                 independent witness and distinct GRAPHITE_RPC_PROVIDER / GRAPHITE_RPC_WITNESS_PROVIDER
                                 names. Two providers agreeing is not a light-client proof
Parser vs the runtime:           never looser than agave's decoder + sanitize, proven in CI over the corpus and
                                 seeded generated frames — bincode and wincode, legacy, v0 and v1; frames naming
                                 one account twice, lookups resolving a named address and non-table lookup
                                 accounts refused (tools/runtime-oracle, Rounds 12 and 19). The oracle runs the
                                 Anza SDK crates (solana-transaction, solana-message); since Round 29 it also
                                 generates frames either side of the 64-instruction, 64-lock and 256-account limits
                                 and cross-checks the 32 reserved ids. Legacy (version 0) nonce accounts are
                                 refused, as the runtime refuses them; PDA derivation tries bumps 255..1
SDKs and schema:                 both SDKs validate every verdict against the v1 schema's rules (the schema
                                 requires scope; a verdict without it is refused) and allow plain http only to
                                 loopback; VerificationResult has 24 fields (Round 30 added `decision`, `executable`
                                 and `instruction_bind_key`, which carries `content_hash`'s value under an honest
                                 name; `content_hash` is deprecated), at parity across Rust, the schema, TypeScript
                                 and Go; the schema states the decision invariants; Go bounds bodies (16 MiB) and has
                                 a 30 s no-redirect default client (Round 29), the TS client bounds them too (16 MiB,
                                 64 KiB for errors) and captures fetch at load (Round 30)
Operator console and AI layer:   the dashboard shows the server's whole-trail totals, labels window figures "last
                                 N", shows a failed /metrics read as unknown, keeps the key per tab by default and
                                 ships a strict CSP and no source maps; the advisory AI layer answers 400/408/413/
                                 415/403, has a 15 s request deadline and at most 32 connections (Round 29). Since
                                 Round 30 the console draws an approval green only when it is executable_approved;
                                 it checks every answer's shape, clears a previous Core's figures on a connection
                                 change, shows L8 assurance and audit integrity, and passed an axe scan with 0
                                 violations on every view; the AI layer labels a question, a conditional, a negation,
                                 quoted speech or two amounts `unknown`, and never echoes key material
Lifecycle sequence:              every report checked against the rows on record — duplicate / out of order /
                                 unpreceded / signature conflict — recorded, never refused (Round 12)
One writer per data directory:   an exclusive lock on graphite.lock, taken by the server AND by every CLI command
                                 that writes (Rounds 12, 19); snapshots carry a generation, so an older one never
                                 replaces a newer one; a corrupt snapshot refuses to start instead of starting
                                 fresh and lifting every quarantine. Since Round 30 the audit trail has its own
                                 exclusive writer lock, and `graphite execution` opens it read-only
Lifecycle on the trail:          the bridge records signing before submission and submission after it, and runs
                                 L8 at the end, with the exact keys; every lifecycle row carries verdict_on_record
                                 and the key that resolved it
Server authentication:           required by default, ≥ 32 characters; GRAPHITE_DEV_MODE=1 permits keyless on loopback only.
                                 /admin/* takes a separate operator key (GRAPHITE_ADMIN_API_KEY, ≥ 32 characters, not
                                 the verify key) and is disabled without one (Round 19); the concurrency permit is
                                 taken after rate limiting, authentication and receipt of the body (2 s). Every
                                 GRAPHITE_* variable is parsed strictly: a value that does not parse refuses to start;
                                 a keyless dev instance answers 421 to a non-loopback Host (Round 29). Since Round 30
                                 an optional read-only key (GRAPHITE_READ_API_KEY) opens only GET /metrics, /manifests
                                 and /api/* — the dashboard's key; auth follows the route that matched, and exactly
                                 one Authorization header is accepted. RPC, witness and AI URLs naming link-local,
                                 cloud-metadata, unspecified, multicast or broadcast addresses refuse to start, and a
                                 resolver re-checks every host name at connect time
Signing before the verdict:      never, in the reference bridge (Round 19): the pre-verdict simulation is unsigned by
                                 construction, and SolanaAgentKit holds a wallet that cannot sign
Request path:                    no per-request deep copy of state (/health ~1 ms; 960 verifies/s in-process with
                                 fdatasync per record, measured locally on 2026-09-15, no run artifact in the repo);
                                 refusals drain the body and are readable (Round 11); every audit append runs on
                                 the blocking pool, so a slow disk flush holds a blocking thread, not an async
                                 worker; HTTP/1.1 only, a request head within 5 s, a body within 2 s, at most
                                 GRAPHITE_MAX_CONNECTIONS (1,024) connections open, at most
                                 GRAPHITE_MAX_CONNECTIONS_PER_IP (64; none behind a trusted proxy) per peer (per /64;
                                 a /48 at most four times that), each for at most 120 s; verifications draw on
                                 GRAPHITE_MAX_CONCURRENT permits, every other route on a fixed pool of 16, and
                                 /health on neither and is exempt from rate limiting (Round 29)
Container health:                `graphite healthcheck` (the image's HEALTHCHECK) passes any 2xx from /health;
                                 `--strict` also fails on `degraded: true`, for an orchestrator that should
                                 replace a node whose audit trail is failing. The image keeps the default; the
                                 compose file uses `--strict` and a 30 s stop grace (Round 30), and CI checks that a
                                 real /verify is recorded, survives a recreate, and that a stop exits 0
Repository integrity:            CI token read-only; actions pinned by commit SHA; base images pinned by digest;
                                 toolchain 1.98.1 in CI and in the container, and the declared MSRV (1.89) built by
                                 its own job (Round 30); Go, cargo-audit and Python (hash-locked) pinned; runner
                                 image (ubuntu-24.04) and Node (22.23.3) exact; npm installs run no dependency
                                 install scripts; the Cargo and Python lockfiles audited, and six npm lockfiles
                                 through a gate that fails on any moderate, high or critical advisory not listed
                                 with its reachability reasoning in .github/npm-audit/ (Round 29), each entry with a
                                 review-by date at most 120 days out (Round 30); every job time-bounded and run under
                                 bash with pipefail; every suite's log is counted against a floor of passing tests,
                                 and a new ignore or skip outside an allowlist fails (Round 30); one `CI gate` job
                                 needs every other job. CI runs on pull requests, the merge queue, pushes to main
                                 and v* tags, and weekly. Branch rules that would make it binding are prepared, not
                                 applied (below)
Audit trail integrity:           hash-chained since Round 30: every record carries its sequence number, the previous
                                 record's hash and its own, across rotation. With GRAPHITE_AUDIT_KEY_FILE (hex, ≥ 32
                                 bytes, mode 600, outside the data directory) each link also carries an HMAC-SHA256:
                                 TAMPER-EVIDENT against anyone without the key. Without a key it is CORRUPTION-EVIDENT
                                 only — a writer to the data directory can rewrite it coherently. Neither shows a
                                 dropped tail or a restored older backup on its own: that needs a checkpoint
                                 (`graphite audit checkpoint`, or one per rotation in GRAPHITE_AUDIT_ANCHOR_DIR) kept
                                 where the server cannot rewrite it, and `graphite audit verify --checkpoint`. One
                                 writer per trail (an exclusive lock); /health reports `audit.integrity`. Archive
                                 order no longer follows the wall clock, only exact archive names count, a failed
                                 append is undone or appends stop (Round 29)
Request objects:                 every nested request object refuses unknown fields, not only the top level (Round 29)
Agent guard (the signing side):  a transfer must match one grammar ([please] send|transfer|pay <amount> SOL to
                                 <address>); a swap runs only on six decoded programs, exact-in, its route's own
                                 minimum held to the simulated delivery, a slippage bound and a price floor; a
                                 per-transaction cap is required in every adapter; a confirm hook shows the resolved
                                 transaction before signing (Round 29). Since Round 30 it executes only a verdict
                                 whose decision it recomputes and agrees with; a confirmation is exactly `true`,
                                 within confirmTimeoutMs (120 s), on a frozen summary naming the digest to be signed,
                                 and the Vercel tools require one; a repeat is keyed by its effect, an in-flight one
                                 refused, and an unresolved submission recorded before the bytes leave (durable with
                                 GRAPHITE_GUARD_STATE_FILE); the signing classes are frozen, fetch is captured at load
                                 (guard and SDK client), the key is a non-extractable WebCrypto key; unsupported
                                 operations (wSOL wrap/unwrap) are refused by name (GUARD_CAPABILITIES)
Independent third-party audit:   NOT PERFORMED — every campaign report is internal engineering work
Branch protection on main:       ABSENT — rulesets, CODEOWNERS and the `CI gate` job are prepared (Round 30,
                                 .github/rulesets/); an owner must apply them; see "Not yet done"
```

"Conditional" means: no known way to turn a blocked verdict into an executed
transaction under the stated threat model, and no external party has yet tried.

## What is enforced (and where the test lives)

| Property | Enforced by | Reproduction |
|---|---|---|
| The signed message is the verified message | `BoundTransaction.signApproved` (TS): digest re-check, signer set derived from the compiled message, message-slice equality | `integrations/agent-guard/bound-transaction.test.ts`, `execution-boundary-fuzz.test.ts` |
| A descriptive verdict never reaches execution | `ResidualPolicy.assertExecutable` requires `scope.kind === "artifact_bound"` | `residual-policy.test.ts`, `toctou-signing-boundary.test.ts` |
| An approved verdict with an unaccepted residual never reaches execution | `ResidualPolicy` (bridge): every non-inherent `unobserved_codes` entry refuses unless named in `GRAPHITE_ACCEPT_UNOBSERVED` / `acceptUnobserved`; a server reporting no codes refuses | `residual-policy.test.ts` (each of the 13 non-inherent codes), `execution-lifecycle.test.ts` |
| `artifact_bound` means the described instruction was located in the bytes | L2 artifact branch: parse failure fails; missing `instruction_data` fails; exact-data match at one position under the described program and accounts | `tests/round9_identity_requires_data.rs` (100 SOL under a 0.002 SOL description, refused), `tests/artifact_binding.rs` |
| Instruction identity is positional and complete | `compare_instruction_accounts`, `sibling_coverage` | `tests/instruction_account_identity.rs`, `tests/described_siblings.rs` |
| An artifact the network would refuse is refused before it is parsed | `MAX_TRANSACTION_BYTES` = 1232 (4,096 for a v1 frame: `max_frame_bytes`, Round 19) at `/verify` entry, in `parse_transaction`, and in TS `messageOf`; `MAX_TRANSACTION_INSTRUCTIONS` = 256 | `tests/round9_resource_bounds.rs` (122 s → 1.6 ms) |
| ALT accounts are identified, not counted | `runtime_account_list`, `resolve_lookups`, owner check | `tests/alt_real_v0.rs` (3 real mainnet v0 txs, `meta.loadedAddresses` ground truth), `tests/alt_privilege.rs` |
| Privileges come from the bytes | `privileges_from_artifact` | `tests/privilege_from_artifact.rs` |
| A risky instruction cannot hide behind the name it was given | L2's `declared_discriminator_contradicts_data` runs first, for every protocol, manifested or not; `transaction_builder` refuses a non-hex discriminator outright; **every manifest lookup — account resolution, the declared-effects lookup, the risk context, the plugin rules — is keyed on the instruction's own first eight bytes, not on the caller's label** | `tests/mislabelled_discriminator.rs` (16), `tests/truncated_discriminator.rs` (22) |
| A label that is TRUE BUT SHORT cannot switch off the account checks | Round 14 (GFX-101): `discriminator_matches` is `input.starts_with(selector)`, so a label shorter than a selector missed the manifest, and the miss took `resolve_accounts` down the P12 path whose accounts carry `pda_mismatch`/`expected_address_mismatch`/`privilege_mismatch` all false. One `effective_discriminator`, derived from the bytes, now keys them all; an EMPTY label is covered too (GFX-108) | `tests/truncated_discriminator.rs` (Jupiter V6 route with an attacker program in the pinned token-program slot: full label and 4-byte label and empty label all produce the identity finding; the honest pinned account still clears) |
| A declared sibling is judged on its own bytes, not its label | Round 14 (GFX-106): `sibling_coverage` records which artifact instruction each declaration matched and `siblings_keyed_on_their_bytes` rewrites the discriminator from that instruction's data before the Risk Engine sees it. A declaration matching nothing is left as written — L2 has already failed | `tests/truncated_discriminator.rs` (a real System `Assign` declared `01`/`0100`, a real SPL `SetAuthority` declared `0`, and a Raydium CPMM `close` declared at half length, all still block) |
| A sibling's lookup-table accounts are compared, not assumed | Round 14 (GFX-107): the primary's comparison resolved ALT positions and a sibling's did not, so every lookup slot in a declared sibling accepted any address — and declared accounts widen the set `ArtifactAccountsNotDescribed` treats as named | `tests/sibling_lookup_accounts.rs` (mock RPC serving one table: the honest declaration is accepted, one naming a different address at the resolved position fails L2) |
| A declaration too short to identify a risky instruction is refused | Round 14: `disc_matches` fires when the input is at least as long as the selector; a strict PREFIX of one sat in the gap. Reachable only in descriptive mode, where there are no bytes to re-derive from | `tests/truncated_discriminator.rs` (a descriptive `01` on System, and a descriptive `0` sibling on SPL Token, are both refused; a complete `03` still clears) |
| The gate behaves the same on real traffic as on the fixtures | Whole finalized mainnet blocks, every transaction pushed through the full pipeline artifact-bound — real bytes, real data, accounts resolved from the block's own `loadedAddresses`, every sibling declared | `tests/mainnet_conformance.rs` + `tools/mainnet-sample` (10,669 transactions, 2026-09-17: 0 parse failures, 0 false refusals, 1,087/1,087 risky-table blocks confirmed against the real bytes, 0 verdicts changed by Round 13) |
| An undeclared authority change is a finding, not silence | `state_diff::AccountDelta::{token_authority_change, mint_authority_change, freeze_authority_change}` — the SPL `owner` field is the authority, distinct from `owner_change`'s owning program | `state_diff::tests::{a_token_account_changing_hands_is_critical, a_mint_authority_changing_hands_is_critical, a_freeze_authority_appearing_from_nothing_is_critical}` plus four controls |
| Wire-format bounds on both sides | `compact_u16` (Rust), `messageOf` / `readSignatureCount` (TS) | `tests/wire_format_bounds.rs`; 2,897-mutation cross-language corpus in `tests/sak_bridge_corpus.rs` |
| Provider fields cannot override canonical evidence | `rpc_client.rs` derives writes/hops from canonical fields only | `tests/provider_field_precedence.rs` |
| Token-2022 classification is fail-closed | `detect_token2022_extensions`, `ExtensionScan.malformed` | `tests/token2022_extensions.rs`, `tests/l4_state_diff_gate.rs` |
| Durable-nonce transactions are refused unless verified | `tx_artifact::durable_nonce`, L2 gate | `tests/durable_nonce.rs`, `tests/durable_nonce_rpc.rs` |
| Audit records are synced to the device before the response | `AuditLog::append_line` → `sync_data` | Established by code reading — no userspace test can observe it; `durable::tests::audit_append_syncs_the_device` measures the cost (1.2 ms vs 19 µs for the no-op it replaced) and asserts nothing |
| L8 reconciliation sees the whole trail | `AuditLog::find_verification` by `audit_trail_id` / `transaction_sha256` / `content_hash`: indexed active file, archives newest-first. `count_verifications` (the verdicts on record beside it): per-key counts of the active file, trusted only while they account for its exact length, else recounted; archives scanned | `durable::tests::read_path_covers_every_archive_after_rotation`, `last_verification_index_tracks_rotation_and_reopen`, `verdict_counts_are_indexed_across_open_append_and_rotation`, `a_verdict_count_the_active_file_contradicts_is_recounted`, `verdict_counts_account_for_a_terminated_torn_tail`, `tests/round10_attribution.rs` |
| An executed blocked transaction is attributed to ITS verification, not to a same-instruction approval | `audit_execution`: `getTransaction` bytes → `bound_artifact_sha256` → digest → `find_verification(TransactionSha256)`; caller keys most-exact-first with no fallback; `caller_keys_disagree` | `tests/round10_attribution.rs` (approved A newest, blocked B executed → `BlockedButExecuted`, attribution `chain`) |
| The chain's bytes are the signature's, not merely the RPC's | `tx_artifact::bound_artifact_sha256`: first slot equals the signature; ed25519 `verify_strict` over the message under the fee payer's key; rejected bytes → `Unavailable`, `chain_bytes_rejected`, no fallback to caller keys | `tests/round10_attribution.rs::{chain_bytes_are_accepted_only_when_bound_to_the_signature, an_rpc_that_substitutes_bytes_cannot_attribute_the_execution}`; `tests/l8_live_mainnet.rs::l8_real_chain_bytes_are_bound_to_their_signature` (public devnet, ignored by default) |
| A frame the runtime would not sanitize is not a transaction | `parse_transaction`: `SignatureCountMismatch`, `ImpossibleHeader` (no writable signer), `ProgramIsFeePayer`, `AccountIndexOutOfRange` (legacy and v0), `EmptyLookup`, `TooManyAccounts` | `tests/round12_runtime_sanitize.rs`; `tests/sak_bridge_corpus.rs`; **`tools/runtime-oracle`** against the Anza SDK decoder (`solana-transaction`, `solana-message`) + `sanitize` over the corpus and ~628,500 frames per CI seed (300,000 legacy/v0, 300,000 v1, a systematic pass and the corpus), with frames either side of the 64-instruction / 64-lock / 256-account limits and a cross-check of the 32 reserved ids (Round 29), in CI (job `runtime-oracle`) |
| L8 draws no positive conclusion from one node's view, a self-contradicting RPC, or a malformed status | `rpc_client::InclusionCommitment`; `get_signature_status` strict; `ChainTransaction` slot/outcome held against the status → `chain_inconsistent` | `tests/round12_rpc_equivocation.rs::{a_processed_status_is_not_a_positive_conclusion, an_rpc_that_contradicts_itself_gets_no_positive_conclusion, a_malformed_status_is_never_a_conclusion, a_status_without_bytes_is_disclosed_as_caller_attributed}` |
| Redirects from an RPC are never followed | `SolanaRpcClient::new` → `Policy::none()` | `tests/round12_rpc_equivocation.rs::a_redirecting_rpc_is_not_followed` (the target records zero hits) |
| An approval is reported executed only when two independent RPCs agree; a blocked transaction seen by either alarms | `GraphiteCore::attach_inclusion_witness`, `compare_witness`, `ExecutionAudit.inclusion_witness` | `tests/round12_rpc_equivocation.rs::{a_positive_conclusion_needs_the_witness_to_agree, either_endpoint_seeing_a_blocked_transaction_alarms, a_witness_that_is_the_primary_is_refused}`; the probe with a mock witness |
| The RPC endpoint is validated before the process claims to simulate | `rpc_client::validate_endpoint` at server startup and in the CLI | `tests/round12_rpc_equivocation.rs::endpoints_are_validated_before_a_client_exists`; the probe's startup refusals |
| One server per data directory | `server::lock_data_dir` (`graphite.lock`, exclusive advisory lock) | `server::tests::a_data_directory_is_held_by_one_process`; the probe (a second server refuses while the first runs) |
| A lifecycle report is checked against the rows on record for its transaction | `AuditLog::lifecycle_history` (per-transaction index), `lifecycle_sequence_anomalies` | `server::tests::{lifecycle_reports_in_order_carry_no_anomaly_and_a_retry_is_a_duplicate, lifecycle_reports_out_of_sequence_are_named_and_a_second_signature_is_loud, graphite_observed_rows_are_marked_and_are_not_duplicates_of_reports, submission_onward_requires_a_real_signature}`; `durable::tests::lifecycle_history_*` |
| An L8 row attributed by `content_hash` claims no exact identity | `execution_handler` writes exact keys only for exact attributions | `server::tests::an_l8_row_attributed_by_content_hash_carries_no_exact_keys` |
| The bridge's submission report survives a lost answer | `executeBoundTransaction` retries (3 × doubling backoff); a repeat is a `duplicate` on the trail | `execution-lifecycle.test.ts` (fails once → recorded on the second try; lost answer → duplicate, counted as recorded) |
| The request path does not deep-copy state | `AppState.core: Arc<GraphiteCore>`, `registry_engine: Arc<…>` | `server::request_path_cost::{app_state_clone_is_a_reference_count_not_a_deep_copy, health_answers_in_milliseconds_on_loopback}` |
| A refusal is readable, never a reset | `refuse_after_draining` on 401 / 429 / 503 | `server::request_path_cost::early_refusals_drain_the_body_so_the_status_is_readable` |
| The API key is not guessable by length | `server::MIN_API_KEY_CHARS` = 32 in `auth_posture` | `server::tests::auth_is_required_unless_dev_mode_is_named_and_the_bind_is_loopback` |
| The SDK and the server agree on the wire | `sdk/typescript/src/live-server.test.ts` and `sdk/go/live_server_test.go` (`-tags liveserver`) against the CI container, failing on any failed or skipped test and requiring each live test to pass by name | `.github/workflows/ci.yml` container job |
| A lifecycle `verdict_on_record` is about the transaction the event names | `/audit/event` resolves by `audit_trail_id`, else `transaction_sha256`, else `content_hash`; contradicting keys → 400 | `server::tests::lifecycle_verdict_resolves_by_the_most_exact_key_and_refuses_contradiction` |
| A compressed RPC response cannot outgrow the cap | `read_body_capped` bounds decompressed chunks | `tests/round10_rpc_decompression.rs` (65 KB → 64 MiB refused in 35 ms) |
| Caller-reported lifecycle rows are bounded and carry what the trail knows | `LifecycleEventRecord::bounded`, `/audit/event` shape and length checks, `verdict_on_record` computed server-side | `durable::tests::lifecycle_event_fields_are_bounded_on_disk`, `server::tests::lifecycle_events_carry_the_verdict_on_record` |
| The bridge's signing and submission are on the trail, in order | `executeBoundTransaction`: policy → sign → record signing (abort if not recorded or not `approved` on record) → submit → record submission → confirm → L8 | `execution-lifecycle.test.ts` |
| Keyless server cannot start on a reachable address | `server::auth_posture` | `server::tests::auth_is_required_unless_dev_mode_is_named_and_the_bind_is_loopback` |
| L8 rows on the trail carry the whole reconciliation detail | `durable::MAX_LIFECYCLE_DETAIL_CHARS` (1024) at the boundary and on disk | `durable::tests::lifecycle_event_fields_are_bounded_on_disk` |
| An artifact signed before it was shown is refused | Round 17 (F-16-01): `tx_artifact::filled_signature_slots` at `/verify` entry — any non-zero slot is a 400; `scope.transaction_sha256` is the digest of the unsigned frame by construction | `tests/round17_remediations.rs::a_presigned_artifact_is_refused_at_verify` |
| L8 names a cited verdict about OTHER bytes, and alarms when it was a refusal | Round 17 (F-16-01): `ExecutionReconciliation::RecordedForDifferentBytes { recorded_approved, .. }`, a discrepancy when `!recorded_approved`; `recorded_verdicts {approved, refused}` for the chain digest (F-16-11) | `round17_remediations::a_cited_verdict_about_other_bytes_is_reported_and_a_cited_refusal_alarms`, `::l8_reports_every_verdict_recorded_for_the_chain_digest` |
| Only a SOUND transaction trains the baseline, and the same bytes are one observation | Round 17 (F-16-03 / F-15-01 / F-15-02): recording after the verdict, gated on `rpc_sim_ok` (now `err == null`), no structural failure, risk Clear; keyed on the artifact digest (`record_simulation_keyed`) — since Round 19 on the simulation identity, which ignores the blockhash the simulator replaces | `round17_remediations::an_l2_refused_request_does_not_grow_the_baseline`, `::an_errored_simulation_is_not_evidence_and_is_named`, `::identical_approved_bytes_are_one_observation`, `::the_same_request_is_not_approved_on_the_second_call` |
| A failed simulation is named, never "clean" | Round 17 (F-16-04): `UnobservedCode::SimulationFailed`; L3 reports "FAILED" | `round17_remediations::an_errored_simulation_is_not_evidence_and_is_named` |
| A uniform history is a band, not a point | Round 17 (F-16-02): `simulation_integrity::effective_spread` (25% of centre, floor 1.0) on both the mean/std and robust paths; flagged-but-clean executions go to the shadow accumulator; `/health.frozen_baseline_count` (the list at the authenticated `GET /api/frozen-baselines` since Round 29); `graphite evidence promote-shadow` | `round17_remediations::ten_identical_samples_do_not_refuse_the_eleventh_at_plus_one_cu`, `simulation_integrity::tests::test_zero_variance_baseline_is_a_band_not_a_point` |
| Approval is conditioned on lookup-table resolution | Round 17 (F-15-05): an unresolved primary position fails L2; `SiblingCoverage.unresolved_positions` fails L2 | existing ALT tests; `tests/alt_*.rs` |
| Manifest risk metadata is keyed on the bytes | Round 17 (F-15-03): `manifest_risk_class` / expected count / variable flag looked up with `effective_discriminator` | `tests/mislabelled_discriminator.rs`, `tests/truncated_discriminator.rs` |
| Observed CPI targets are judged like declared ones | Round 17 (F-16-05): `rpc_client::SimulationResult.inner_program_indexes` → `observed_cpi_callees` → `assess_with_warnings` | `round17_remediations::an_observed_cpi_target_the_caller_omitted_is_judged_like_a_declared_one` |
| The PDA seed template grammar is closed | Round 17 (F-16-06): `resolve_pda_seed_template` returns `Result`; `validate_seed_template` at manifest load and registry submission; an unresolvable-for-this-request template flags the slot | `manifest::tests::test_unsupported_seed_templates_are_refused_at_load` |
| A panicking blocking plugin fails closed | Round 17 (F-16-07): Risk/Verifier/Policy panic → `Block { pattern: "<name>:panicked" }`; plugin-dir load failure is a startup error | `plugin_orchestrator::tests::test_panicking_blocking_plugin_fails_closed`, `tests/plugin_framework.rs` |
| Malformed policy input is a 400 before the pipeline; both profile axes are clamped | Round 17 (F-16-08 / F-15-07): `enforce_wallet_profile` returns `Err` for `min_confidence > 1`; `WEAKEST_BUILTIN_MIN_TRUST_TIER` | `server::tests::min_confidence_above_one_is_refused_up_front`, `::unknown_tier_floor_is_raised_to_the_weakest_builtin` |
| `content_hash` is framed | Round 17 (F-16-09): domain tag + u32 LE length prefixes + list counts, mirrored in TS SDK, SAK AuditBind, Go | `verification::tests::test_content_hash_is_injective_across_field_boundaries`; pinned vectors `48c65c638aceb5de` / `dd8569c46af7e6c0` in all four suites |
| Manifest URLs are links only when http(s) | Round 17 (F-16-10): `manifest::validate`, `manifest_registry::validate_manifest`, console `httpUrl()` | `manifest::tests::test_manifest_url_fields_must_be_http` |
| A manifest may not award itself a trust tier | Round 18: `load_seed_manifests` lowers a declared `BattleTested` unless `protocols/battle_tested_evidence.json` clears `manifest::battle_tested_bar` on all three axes; the gate reads the raw measurements, never the file's own verdict field | `tests/battle_tested_evidence.rs` (8 tests, one per axis and one proving the verdict field is ignored) |
| Every seed manifest has a mainnet measurement on record | Round 18: identity, volume over a stated window, and the share of really-observed instructions the manifest can name; reproducible with `scripts/battle_tested_census.py` | `battle_tested_evidence::every_seed_manifest_has_a_measurement_on_record` |
| The manifest list and the manifest directory agree | Round 18: one `SEED_MANIFESTS` list produces both the name and the baked-in contents (the `include_str!` match arms are gone), and the list is compared to `protocols/` in both directions | `manifest::tests::test_every_protocol_file_is_a_seed_manifest` |
| The documented protocol table is the loaded registry | Round 18: `docs/protocol-coverage.md` is generated; the test compares every row's program id, name, instruction count and APPLIED tier against `load_seed_manifests()`, and the README's headline counts too | `tests/docs_match_the_registry.rs` |
| An account the manifest never declared has no privilege to mismatch | Round 18: an `extra` slot past the declared list is `remaining_accounts`; comparing the real `AccountMeta` against the placeholder blocked 1,036 real mainnet transactions across four programs | `privilege_mismatch::an_undeclared_extra_account_has_no_privilege_to_mismatch`, `::extras_do_not_mask_a_real_privilege_mismatch_on_a_declared_slot` |
| A swap program is one whose manifest says so | Round 18: `is_swap_program` reads `"category": "swap"` from the loaded manifests instead of a second hand-kept list; the trusted-CPI list stays hand-curated, because it RELAXES checks | `manifest::tests::manifest_category_aligns_with_swap_set` |

| One observation is one distinct execution | Round 19 (F-19-01/02/03): `tx_artifact::simulation_identity` keys the baseline (signatures and blockhash zeroed); only the artifact is simulated and recorded, and only when the described instruction was located; `ObservationMemory` remembers identities exactly | `tests/round19_what_one_observation_is.rs`; live: the `a1db51f` binary approved a refused transfer on its third ask with only the blockhash changed, this round's binary never did |
| The CPI-trace rules judge what executed | Round 19 (F-19-22): `rpc_client` parses `innerInstructions` with accounts, data and `stackHeight`; `observed_cpi_tree_of` → `analyze_observed_cpi_trace` | `tests/round19_observed_execution.rs` (a twelve-way sweep reported by the simulator, no trace declared, is refused) |
| An undescribed instruction is diffed and promises nothing | Round 19 (F-19-04/05): privileges from the artifact, every writable account observed; `state_diff::UNDESCRIBED_INSTRUCTION_EFFECTS` | `round19_observed_execution::an_undescribed_instruction_has_every_writable_account_diffed`, `round19_binding_and_ownership` |
| The verify key is not the operator key | Round 19 (F-19-13/15): `GRAPHITE_ADMIN_API_KEY`, `/admin/*` disabled without it; quarantine input validated, idempotent, `persisted` real | `server::tests::{the_verify_key_cannot_lift_or_add_a_quarantine, without_an_operator_key_the_admin_surface_is_disabled, quarantine_input_is_validated_and_idempotent}` |
| Unauthenticated slow clients cannot hold capacity | Round 19 (F-19-14): rate → auth → body (5 s) → permit; refusal drain ≤ 1 s | `server::tests::an_unauthenticated_slow_body_does_not_hold_a_permit`; live: 40 trickling connections, a real request answered in 10 ms |
| One writer per data directory; snapshots in order | Round 19 (F-19-12): `GraphiteCore::open_data_dir` / `open_data_dir_read_only`, snapshot generations, strict load | `round19_binding_and_ownership::{a_data_directory_has_one_writer, a_corrupt_snapshot_is_refused_not_replaced}`, `verification::tests::an_older_snapshot_never_overwrites_a_newer_one` |
| Version-1 transactions are read as the runtime reads them | Round 19: `tx_artifact::parse_v1`, v1-aware frame helpers, `max_frame_bytes` | `tests/round19_v1_transactions.rs` (27, one the 3,302-transaction mainnet check); `tools/runtime-oracle` (wincode, v1 generator, systematic v1 pass) |
| Real traffic is not refused for its shape | Round 19 (F-19-28): same-data instructions told apart by their accounts; an empty discriminator describes an empty-data sibling | `tests/round19_real_traffic_shapes.rs`; 104 executed mainnet transactions moved from refused to L2-passed |
| A threshold outside [0, 1] is not a policy | Round 19 (F-19-27): a 400 in every mode | `server::tests::non_finite_or_negative_custom_thresholds_are_refused_in_every_mode` |
| The bridge never signs before the verdict | Round 19 (F-19-C1/C2): `rpc-simulator.ts` (unsigned, `sigVerify: false`, `replaceRecentBlockhash: true`, filled slots refused); `VerificationGatedWallet` | `rpc-simulator.test.ts`, `gated-wallet.test.ts`, `graphite-sak-bridge.test.ts` |
| An executor that is not the bridge can bind the whole transaction | Round 19 (F-19-C3): `verifyTransactionDigest` (TS), `VerifyTransactionDigest` (Go), v1-aware | `transaction-digest.test.ts`, `digest_test.go`, one v1 vector pinned in the Core, TS and Go |

| A fee-bearing Token-2022 transfer is judged, not refused | Round 20 (F-20-02): `state_diff::model_transfer_fees` against the mint's `TransferFeeConfig` (fetched by Graphite, `transfer_fee_mints_to_fetch`); `TransferFeeSchedule::fee` is Token-2022's `calculate_fee` | `tests/round20_transfer_fee.rs` (22, three of them through the pipeline over a mock RPC); `tests/mainnet_transfer_fee_live.rs` (real fee-bearing mints, ignored by default) |
| The fee payer's writable flag is not an escalation | Round 20 (F-20-03): `privilege_mismatch` skips only the writable direction, only for the fee payer read from the bytes | `privilege_mismatch::{the_fee_payers_writable_flag_is_not_a_privilege_escalation, the_fee_payer_exemption_is_only_its_writable_flag}`; 156 real mainnet transactions Blocked → Clear, no other verdict loosened |
| L4 observes what the transaction can write | Round 20 (F-20-04): `accounts_for_state_diff` — the union of the manifest's and the transaction's writable accounts | `round20_transfer_fee::pipeline::graphite_fetches_the_mints_schedule_and_models_the_fee` |
| A caller's diff is the caller's | Round 20 (F-20-01): a request's `state_diff` is re-marked `CallerSupplied` | `l4_state_diff_gate::a_caller_diff_that_claims_rpc_provenance_is_still_the_callers` |
| A fee-bearing transaction is replayed, not inferred | Round 21 (F-21-03): `verification::token2022_executed` (the transaction's Token-2022 instructions and the simulator's CPIs, in order) → `state_diff::replay_fee_mint`, exact against the post-state; both fields `serde(skip)` | `tests/round21_open_list.rs` (withdrawals, several transfers, send-and-receive, order, and every refusal); `pipeline::the_replay_runs_on_what_graphite_parsed` |
| The epoch decides the schedule | Round 21 (F-21-04): `getEpochInfo` → `FeeEpochContext`; `applicable_at`. Round 22 (F-22-01): a pending schedule is always judged — no landing margin is assumed | `with_the_epoch_read_only_that_epochs_schedule_is_accepted`, `a_pending_increase_is_disclosed_with_why_it_can_be_paid`, `a_pending_majority_fee_blocks`, `pipeline::graphite_reads_the_epoch_and_judges_the_pending_schedule` |
| A writable flag is not a write | Round 21 (F-21-01): sibling-declared writes explain it; otherwise deferred to Graphite's own diff (observed unchanged, or it blocks); the signer direction untouched | `round21_open_list::a_writable_flag_is_not_a_write` (5) |
| Manifests describe the programs as they run | Round 21 (F-21-02): account lists grounded in the on-chain IDLs and executed mainnet instructions; `account_layouts` for alternate layouts, chosen by exact count | `round21_open_list::manifests_match_the_programs` (5) |
| Token-2022 extensions are judged by what happened | Round 21 (F-21-06/07): `extension_judgement`, `permanent_delegate_exercises`; the mint of every extension-bearing account fetched | `round21_open_list::extensions_judged_by_what_happened` (7) |
| A self-refunding close is not a drain; read-only remaining accounts are not proliferation | Round 21 (F-21-08/09): `self_refund_closes` from the bytes (a sibling only when every close refunds); `writable_extra_accounts` | `round21_open_list::structural_checks_read_the_bytes` (7) |
| L4 measures the transaction at one slot, against the transaction | Round 21 (F-21-14/15/16): pre-state lamports from the simulation's `preBalances`; `StateDiff::transaction_accounts`; read-only accounts not diffed | `a_pre_state_read_a_slot_late_does_not_break_conservation`, `a_change_another_instruction_makes_is_not_a_diff_that_fails_to_correspond`, `a_read_only_account_is_not_diffed_for_skew_to_show_on` |
| A transfer hook is bounded by the bytes | Round 22 (F-22-02/11): `state_diff::transfer_hook_reach`, `transfer_hooks_bounded` over Graphite's executed Token-2022 list and `TransactionPrivileges`; `verification::invoked_only_by_token2022` | `round22_remaining` (hook rule, 11; pipeline, 2) |
| Privileges are the runtime's | Round 22 (F-22-05, F-22-13): `tx_artifact::runtime_writable` (agave's `is_maybe_writable` demotion over the unconditionally reserved keys); `header_writable` | `round22_remaining::runtime_writability` (4); `tools/runtime-oracle` (agave's `is_maybe_writable` on every accepted frame; reserved-keys pass) |
| Declared siblings are counted like the primary | Round 22 (F-22-12): a byte-keyed sibling's layout and writable extras from the message's privileges | `round22_remaining::sibling_writable_extras` (2) |
| An absent optional account is not a mismatch | Round 22 (F-22-04): `AccountRoleDef::optional` from IDLs and traffic; the program id in an optional slot resolves as a constant | `round22_remaining::manifests_match_the_programs` (5), `tensor_bids_absent_cosigner_is_not_an_unsigned_signer` |
| Native manifests match their interfaces | Round 22 (F-22-07/08/09): Stake and BPF Upgradeable Loader rebuilt; alternate layouts for `CreateAccountWithSeed` and the stake pool's SOL authorities | `round22_remaining::native_manifests` (4), `create_account_with_seed_has_its_two_account_layout` |
| Remaining-account interfaces are declared | Round 22 (F-22-06): `variable_accounts` on sixteen instructions whose own traffic passes variable account lists | `remaining_account_interfaces_are_declared_variable` |
| The priority fee is read | Round 21 (F-21-10): `tx_artifact::compute_budget_request` → `scope.compute_budget`; `ExcessivePriorityFee` | `round21_open_list::compute_budget` (3), `round19_v1_transactions::the_v1_header_is_the_compute_budget` |
| With an RPC, a failed or incomplete simulation refuses | Round 29 (audit H1): `SimulationFailed` (L3 Failed) and `VerificationIncomplete` risk findings; a simulation plugin's Block refuses | `tests/audit_2026_10_20_simulation_gate.rs` (`an_errored_simulation_is_refused`, `an_unobtainable_simulation_is_refused_as_incomplete`, `an_incomplete_simulation_response_is_refused`, `a_simulation_without_a_diff_is_refused`), `audit_2026_10_20_core_gates::a_simulation_plugin_block_refuses_the_verdict`; without an RPC the verdict is unchanged: `::without_an_rpc_client_an_artifact_verdict_is_unchanged` |
| A refusal does not train confidence | Round 29 (M1); Round 30 (R30-B-1): `ObservationPolicy::BuiltinFloor` — a simulation counts only when its verdict clears the weakest built-in bar on its own, never the request's profile; `GRAPHITE_LEARN_FROM_POLICY_REFUSALS` refuses startup | `audit_2026_10_20_simulation_gate::policy_refusals_teach_nothing_unless_the_operator_opts_in`, `tests/round30_trust_learning.rs` |
| The verdict's tier is the weakest program's | Round 29 (M2): every top-level program tiered by `program_trust_tier`; the minimum is the verdict's | `audit_2026_10_20_core_gates::{an_unmanifested_sibling_sets_the_verdicts_tier, an_earned_primary_tier_is_held_to_its_siblings}` |
| A misspelt nested field is refused, not dropped | Round 29: `deny_unknown_fields` on every nested request type | `audit_2026_10_20_core_gates::an_intent_with_an_unknown_field_is_refused`, `round29_state_diff::a_supplied_diff_with_an_unknown_field_is_refused` |
| L8 records what it saw | Round 29 (M4, M9): an `execution_check` row unless inclusion was seen at a cluster-backed commitment; `getTransaction` at the configured commitment; a contradicted citation is `caller_keys_disagree`, never a discrepancy | `server::tests::an_l8_check_that_saw_nothing_is_not_a_confirmation`, `round29_rpc_client::get_transaction_asks_at_the_configured_commitment`, `audit_2026_10_20_simulation_gate::a_cited_refusal_of_other_bytes_is_not_an_alarm` |
| A signer's undeclared lamport loss is Critical | Round 29: `UndeclaredSignerLamportDebit` beyond the fee and created accounts' rent under an interpretable no-debit manifest; Token-2022 padding, both-sides extensions, mint-scoped fee terms, `TokenLayoutUndecodable`, Multisig length, Vote V4 | `tests/round29_state_diff.rs` (17) |
| The RPC client fails closed on what it cannot read | Round 29: account `data` must be `[base64, "base64"]`; error text redacted; `Debug` never prints the endpoint | `tests/round29_rpc_client.rs` |
| The CLI decides as the server does | Round 29: `operator_boundary`, shared; `graphite execution` exit codes 0/1/3/4/5/6 | `audit_2026_10_20_cli_reproduces_server::{verify_applies_the_servers_boundary_settings, an_execution_check_that_cannot_run_is_not_a_pass}` |
| A configuration the server cannot honour refuses to start | Round 29: strict parsing of every `GRAPHITE_*` variable, CORS `*`, an unopenable events file, a corrupt registry state | `audit_2026_10_20_startup_refusals::configuration_the_server_cannot_honour_refuses_to_start` |
| The registry is a boundary against its submitters | Round 29 (M3): registry-owned corpus, lineage, domain-tagged signature over canonical JSON, full runtime validation, reviewer revocation, fixture integrity over the expected outcome | `manifest_registry::tests::{lineage_is_enforced_and_a_refused_version_stays_refused, a_signature_over_the_bare_hash_does_not_verify, the_content_hash_covers_canonical_json, a_submission_the_runtime_would_refuse_is_refused, a_revoked_reviewer_stops_counting, a_registry_acceptance_keeps_operator_evidence}`, `regression_engine::tests::an_edited_outcome_or_deprecation_is_refused_and_old_fixtures_migrate` |
| The System Program manifest is the runtime's | Round 29 (MED-4): `TransferWithSeed` layout corrected, `UpgradeNonceAccount` added | `tests/system_program_manifest.rs` |
| A swap is held to its route's own minimum | Round 29 (H2, H4), agent guard: `swap-instructions.ts` decodes six programs' exact-in instructions; `swap-economics.ts` holds the minimum to the simulated delivery, the slippage and a price floor; exact-output forms refused | `integrations/agent-guard/swap-instructions.test.ts`, `swap-economics.test.ts`, `guard-round29.test.ts` |
| A transfer request is one sentence the guard can parse | Round 29 (H3, M5): a positive grammar, anything else refused with the accepted form | `intent-grounding.test.ts` ("H3: the accepted form, and only it, is grounded") |
| A person sees the resolved transaction; the key leaves the environment | Round 29 (M7, M8): `confirm(summary)`; `SOLANA_PRIVATE_KEY` deleted once read; ES-private collaborators | `guard-round29.test.ts` (M7, M8 cases) |
| The documented numbers are the code's | Round 29: risk checks, the registry's size, the corpus size, mutations, residual codes and dashboard views derived and scanned in README, ARCHITECTURE, CURRENT, CONTRIBUTING, ROADMAP and two package READMEs; test counts allowed only on this page | `tests/docs_numbers_match_the_code.rs` |
| Only `executable_approved` permits signing | Round 30 (G-01): `ExecutionDecision`, `execution_decision(&VerificationResult)` at the one place a result is built; schema invariants; TS `isExecutable`, Go `IsExecutable`, the guard's `assertExecutableVerdict` recompute and refuse disagreement; CLI exit 3 for `analysis_only` | `tests/round30_execution_decision.rs`, `tests/round30_decision_fixtures.rs` (`examples/decisions/*.json`, read by all three languages), `sdk/typescript/src/execution-decision.test.ts`, `integrations/agent-guard/guard-round30.test.ts`, `residual-policy.test.ts` |
| A verify-key holder cannot raise a program's evidence | Round 30 (R30-B-1): `ObservationPolicy::BuiltinFloor`; 40 attacker-chosen requests across four profiles, sequential and 32 concurrent, add 0 samples | `tests/round30_trust_learning.rs` |
| A baseline cannot be walked; shapes learn apart; an upgrade withdraws evidence | Round 30 (R30-B-2, B-3): shape baselines, `BaselineAnchor`, `retire_program_evidence`, first-sighting slot check | `tests/round30_trust_learning.rs` (`a_slow_drip_cannot_walk_an_anchored_baseline`, `an_upgrade_withdraws_the_programs_evidence`, …) |
| No refusal class trains anything | Round 30 (R30-B-4) | `no_refusal_class_trains_any_accumulator` |
| An altered audit record breaks the chain; keyed, it cannot be re-sealed without the key | Round 30 (R30-C-1..3): `durable::chain`, `graphite audit verify` / `checkpoint`, the trail's writer lock | `durable::chain_trail_tests` (15), `tests/round30_audit_chain.rs` |
| L8 says what its answer rests on; high assurance withholds what one provider says | Round 30 (R30-D-1): `inclusion_assurance`, `rpc_client::witness_independence`, `GRAPHITE_L8_HIGH_ASSURANCE` | `tests/round30_l8_assurance.rs` |
| Each route answers only to its key; no metadata address is an RPC | Round 30 (R30-D-2..4) | `server::tests` route surface, `tests/round30_server_wire.rs` |
| A signer's loss under an unreadable declaration is Critical | Round 30 (R30-F-1): `DeclaredEffects::security_class`, `class_moves_value` | `tests/r30_declared_effects.rs`, `tests/r30_declared_effects_census.rs` |
| Every risk check and registry check is caught by a test of its own | Round 30 (R30-F-3): the checks no test caught when broken now have isolated tests | `tests/r30_detector_isolation.rs`, `tests/r30_registry_manifest_breaks.rs`, `tests/r30_token2022_both_sides.rs`, `tests/r30_low_decode_manifests.rs` |
| A grounded intent clears only its own instruction, paying its own signer | Round 30 (R30-G-1, G-2): `intent_grants` | `tests/round30_grounded_intents.rs` |

## What is NOT enforced (documented limitations)

- **Honest intents exist for 21 instructions, not for whole classes (Round 30,
  R-M14).** Since R2 an intent declares only the security classes
  `manifest::INTENT_DECLARES` lists. Round 30 added `withdraw`, `claim`, `burn`
  and `configure` (and widened `close`) for named Raydium, Meteora DLMM, Pump and
  SPL Token / Token-2022 instructions and one marketplace `update_offer`, each
  only when the transaction's own accounts show the funds stay with the signer.
  Every other withdrawal, claim, protocol close, mint and admin setter is still
  refused whatever label it carries (Round 24 measured 219 of 48,855 executed
  transactions; not re-measured, the sample is not in the repository); MMM
  `updatePool` stays refused (no IDL to ground it). **The Core does not judge a
  withdrawal's minimum outputs**: a granted withdrawal with zero minimums, paid
  to the owner, clears the Core, so a direct `/verify` caller carries the
  sandwich risk; the agent guard builds no withdrawals.
- **The Core does not bind amounts; the agent guard does.** `ExtractedParameters.amount`
  is carried, not compared, by the Core; lamports leaving the signer's wallet under a
  declared debit are disclosed (`SignerLamportsOutsideDeclaredDebit`), not refused (a
  signer's loss under a manifest that declares NO debit is Critical since Round 29). The
  agent guard binds a transfer to the amount and destination in the user's text, and a
  swap to the amount and both tokens in it, checked against a simulation of the exact
  bytes (Round 25); since Round 29 it also decodes the route's own minimum output and
  holds it to the simulated delivery, a slippage bound and a price floor; its spend cap
  bounds both. A direct `/verify` caller binds them itself. **Correction:** the Round 25
  report says the Core reads a route's minimum for the protocols it models. It reads
  none; the guard does. Swaps run only on six decoded programs, exact-in; wSOL wrapping
  and unwrapping are not supported (the Risk Engine refuses `CloseAccount`).
- **A lookup table's freshness and a registry record's signatures are not
  checked** (Round 24, W17-c, W11-c); see `SECURITY.md`.
- **The Token-2022 model replays what the simulator reports it executed.**
  With no `innerInstructions` in the simulation, or an index Graphite cannot
  place, the Round 20 diff-only rule decides and says it is arithmetic rather
  than attribution. A transfer hook the bytes do not bound (Round 22),
  confidential-transfer state that changed, an unknown extension and an unread
  mint still block — encrypted balances cannot be judged without the owner's
  key. An RPC without `getEpochInfo` leaves the Round 20 behaviour: either
  schedule, a pending one disclosed.
- **A write the diff did not observe still blocks.** The writable-flag rule
  passes an account only on Graphite's own observation; without an RPC, an
  over-privileged account blocks as before.
- **A caller-supplied state diff is the caller's.** Whatever `provenance` it
  claims, a diff from the request can fail L4 and never pass it (Round 20).
- **An accepted residual is the operator's decision.** Every `artifact_bound`
  verdict carries the two inherent residuals (`program_semantics`,
  `inner_instructions`); every other code refuses execution unless the
  operator names it in `GRAPHITE_ACCEPT_UNOBSERVED`. The bridge enforces the
  configuration; it does not second-guess it, and the outcome records what
  was accepted.
- **Pre-signature verification has a window.** The chain moves between
  verification and execution; the blockhash bounds that window to about a
  minute for ordinary transactions, and a permitted durable nonce removes the
  bound.
- **The manifest set covers a slice of the chain.** Measured 2026-09-27
  over three days: 84–87% of verified transactions call a primary program with
  no manifest; 71% of the drainer heuristic's refusals are of programs signed
  by five or fewer fee payers, none of them publishing an IDL. An unmanifested
  program declares no state changes, so the drainer heuristic blocks every
  call to one that touches three or more accounts — deliberately: for code
  Graphite does not describe, a simulation does not bind what it does at
  landing. That is the intended fail-closed direction — it refuses rather
  than guesses — but it means an agent working outside the manifested set
  is refused, not merely scored lower, and the honest description of
  today's coverage is "the protocols Graphite knows", not "Solana".
- **Single-tenant.** One verify key (plus an optional operator key for `/admin/*`), one profile pin, one trail, one semantic
  graph per process. Tenant isolation is process isolation.
- **An archive's index costs one read of the archive per process.** Every
  L8 and lifecycle lookup is indexed, in the active file and in each rotated
  archive (Round 28, R-M11); an archive's index is checked against the
  archive's SHA-256 once per process (1.8 s for three 64 MiB archives,
  done in the background at start), and an archive whose index cannot be
  written is scanned on each lookup.
- **L8's inclusion evidence is as independent as the RPCs it is given.** A
  `processed` status, a self-contradicting RPC or a malformed status draws no
  positive conclusion; with `GRAPHITE_RPC_WITNESS_URL` two independent
  endpoints must agree before an approval is reported executed, and either
  endpoint's sighting of a blocked transaction alarms (Round 12). Two RPCs
  behind one provider are two views of one answer; since Round 30 a witness on
  the same host, registrable domain or resolved address is labelled
  `witnessed_not_independent`, but independence is judged from URLs, DNS and the
  operator's own provider names (`GRAPHITE_RPC_PROVIDER`,
  `GRAPHITE_RPC_WITNESS_PROVIDER`) — two companies on one cloud are not detected,
  the registrable-domain check uses a short built-in suffix list, and behind an
  HTTPS proxy only the proxy's address is checked. A light-client inclusion proof
  is not built. Without a witness the reconciliation says
  `inclusion_witness: null`.
- **The runtime oracle covers what it generates.** Agave's `wincode` decode
  path is not a second oracle; the generator is seeded and structure-aware,
  not coverage-guided.
- **The agent guard's public API is still web3.js 1.x.** It builds legacy, v0
  (lookup tables, Round 22) and v1 (R-P8, compiled and signed through
  `@solana/kit`), but `GraphiteGuard`'s `Connection` and public types are
  web3.js 1.x, whose own RPC reads are not bounded the way the guard's raw
  JSON-RPC reads are (`readJsonBounded`, Round 25). Roadmap R-M15.
- **Manifests are grounded where programs were seen running.** 383 of the 3,195
  manifest instructions of the Round 22 registry have been observed executing (three block samples plus
  2,998 per-program transactions); the rest are grounded in their programs'
  published interfaces. Three published IDLs disagree with their own programs'
  executions and are not adopted — mintfx `transfer`, marginfi
  `lending_account_end_flashloan`, Coinflow's unnamed instruction — so those
  instructions block.
- **Without a diff, L4 is `Inconclusive`.** When the simulation failed or no
  RPC is attached, L4 runs a consistency check on the manifest prose and says
  so; a contradiction still fails the layer (Round 21).
- **The lifecycle-sequence check sees the active file and the newest
  archive.** A lifecycle across two rotations is checked against what it saw.
- **One server per data directory, enforced by a lock.** Two servers on one
  directory would each see half a trail; the second now refuses to start.
- **A body over the 1 MiB limit may be answered with a reset** rather than a
  readable 413; refusals below the limit are drained and readable.
- **Without the chain's bytes, L8 is only as exact as the caller's keys.** An
  RPC without `getTransaction`, a pruned ledger, or no RPC leaves attribution
  on `audit_trail_id` → `transaction_sha256` → `content_hash`; the last names
  every transaction carrying that instruction and the answer says so.
- **Rows written before Round 10 carry no `transaction_sha256`**; they are
  reachable by id and `content_hash` only.
- **A compromised process is out of scope.** Deep copies, private fields and
  digest checks defend against callers and plugins that behave like
  JavaScript; not against code that rewrites the bridge module.
- **Without RPC, L3 is Inconclusive and no approval is executable.** The verdict's
  scope carries `not_simulated` and, since Round 30, `decision: analysis_only`,
  `executable: false`. `approved` itself is still reachable — on trust the semantic
  graph has earned, or on evidence an operator seeded — and keeps its old meaning
  for compatibility: the pipeline did not refuse. It was never permission to sign;
  a consumer that reads `approved` instead of `executable` (or the SDKs'
  `isExecutable` / `IsExecutable`) signs what nothing simulated. (With an RPC
  attached, a failed or incomplete simulation refuses since Round 29.)
- **L3 does not flag deviations of 50% of the centre or less.** A signal is
  flagged only beyond 2.0 × max(spread, 0.25·|centre|, 1); the first 10
  RPC-verified observations are learned unclamped and decide nothing; L3 judges
  the whole transaction's compute. Since Round 30 a mature baseline is per
  transaction shape and anchored, so drift beyond 2σ of the anchor is flagged,
  and a program whose costs genuinely move past its anchor is flagged until an
  operator promotes its shadow. The false-positive effect of shapes and anchors
  on real RPC traffic has not been measured (the conformance set runs offline).
- **An upgrade sends a program back to the start (Round 30).** A detected
  redeploy or upgrade-authority change withdraws the program's baselines,
  counted identities and operator evidence (kept in `retired_evidence`); the
  program sits near 0.44 confidence, refused by every built-in profile, until an
  operator re-seeds it — a de facto quarantine whether or not
  `GRAPHITE_QUARANTINE_ON_UPGRADE` is set. An RPC that lies about deployments can
  therefore reset evidence (an availability risk inside the RPC trust boundary).
  Loader-v4 programs are flagged `ProgramUpgradeUntracked`, not read.
- **Without a witness, the primary RPC decides L8.** Without
  `GRAPHITE_RPC_WITNESS_URL` a hostile or broken primary can turn
  `BlockedButExecuted` into `BlockedAndNotExecuted`, `NotFound` or `Unavailable`;
  the reconciliation says `inclusion_assurance: single_provider` (Round 30).
- **The audit trail is tamper-evident only when keyed, and complete only against
  a checkpoint (Round 30).** Without `GRAPHITE_AUDIT_KEY_FILE` the chain is
  corruption-evident: a writer to the data directory can recompute it. Keyed, a
  rewrite needs the key — but neither mode shows that the newest records were
  dropped or an older backup restored; only a checkpoint kept where the server
  cannot rewrite it does (`graphite audit verify --checkpoint`). Graphite writes
  checkpoints; it cannot make their storage immutable.
- **155 unreadable declarations of value-moving instructions still only warn
  (Round 30, R30-F-1, owner decision).** A signer's loss under a silent or
  unreadable declaration is Critical unless the instruction's class moves value
  (transfer, withdraw, drain, stake, close, create, mint, unclassed); 155 shipped
  instructions of those classes — Orca `swapV2`, Phoenix `Swap`, Solend deposits
  among them — have placeholder prose, so a signer's loss there is a warning.
  The W19 rule (lamports leaving the signer's wallet under a debit declared for
  other, named accounts) likewise warns.
- **The guard's duplicate-send record holds for one guard process.** With
  `GRAPHITE_GUARD_STATE_FILE` it survives a restart; without it a restart forgets
  an unresolved submission. Two guard processes with the same key share nothing.
  A transfer's cap counts the amount, not the network fee (about 5,000 lamports).
- **The address-poisoning rule has a residual false positive (Round 29, R-4).**
  The Risk Engine stopped judging the signing authority of an SPL transfer and
  judges a destination at four trailing `1`s. Judging no source at all would have
  approved five documented address-poisoning sends in the holdout (from a
  phisher's vanity address to a victim), so a source is still judged at the
  pre-audit five. A user's own wallet ending in five or more `1`s — about one
  random address in 656 million — is refused when it sends.
- **`approve` is a recognised intent that never verifies anything.** A delegate
  grant is an authority change, which no intent declares, so Check 2 refuses every
  `Approve` / `ApproveChecked` under any label.
- **The measured `BattleTested` tier does not reach a verdict.** It is registry and
  display information (the verdict path caps every manifest at `OfficialManifest`);
  the bar behind it is thin — across the 113 records that carry it, 21 observed
  instructions at the least and 54 at the median, 70 records naming three or fewer
  distinct instructions, 30 at exactly 1,000 successes from one signature page,
  measured 2026-09-22 to 2026-10-03.
- **The holdout is 38 rows, and its one benign row is refused.** 37 real exploits,
  all refused (recall 1.0, 0 false negatives), and one real successful Jupiter
  swap, refused offline because its lookup tables cannot be resolved (1 false
  positive; precision 0.974). The exploits run descriptively on request evidence
  the engine ignores. Two rows the holdout used to score as benign had failed on
  chain and are no longer scored.
- **The benchmark is 24 hand-built descriptive cases** (7 safe, 15 malicious, 2
  unscored unknown-protocol), compared against an approve-all baseline. Its five
  REAL-RECONSTRUCTED cases take program ids, accounts and CPI targets from real
  exploits and reconstruct the rest; the Wormhole case is refused by the drainer
  ratio (Check 3), not by anything about the Wormhole exploit's mechanism. Its
  latency figure has no run artifact in the repository.
- **Lifecycle events reported by callers are attestations.** `POST
  /audit/event` records what the caller said with `reported_by`; Graphite
  cannot witness a signing it did not perform and does not claim to. What it
  does establish, on every row, is `verdict_on_record` — what its own trail
  said about the hash when the report arrived — and it counts and logs a
  report against a blocked verdict as the gate being bypassed.

## Not yet done

| Item | Status | Whose decision |
|---|---|---|
| Independent third-party audit | Not performed | Owner |
| External review R2/R3 (a declared intent clearing a dangerous instruction) | **Closed in Round 24**: reproduced on `eb17aa5`, fixed by one intent-to-class table read by L5 and the Risk Engine, and by the control-change rules; one more case (R3-b) found by the round's own mainnet re-measurement and fixed | — |
| Honest intents for withdrawals, claims and protocol closes | **Partly done (Round 30, R-M14/R-M13)**: 21 grounded grants (`src/intent_grants.rs`); the rest stays refused; the 219 / 9 measured costs not re-measured (sample not in the repository); MMM `updatePool` needs its IDL | Engineering |
| Protocol upgrade detection (ProgramData slot / upgrade authority watch) | **Done (Round 27; evidence reset Round 30)**: with an RPC, a manifested program redeployed or handed to a new upgrade authority since last seen is reported on the verdict (`program_upgrades`), on `/health` and in the metrics; `GRAPHITE_QUARANTINE_ON_UPGRADE=1` also quarantines it. Since Round 30 the upgrade withdraws the program's evidence and a first sighting whose deployment is newer than the evidence withdraws it too. Loader-v4 deployments are not read | — |
| Execution decision (approved ≠ permission to sign) | **Done (Round 30, G-01)**: `decision` / `executable` on every verdict, recomputed by every client | — |
| Tamper-evident audit trail | **Done when keyed (Round 30, G-07)**: hash chain + HMAC, `graphite audit verify` / `checkpoint`, anchor directory. Making the anchor storage immutable (WORM / object lock) and scheduling checkpoints is the operator's | Owner (deployment) |
| The 155 unreadable value-moving declarations that only warn (R30-F-1), and the W19 rule | Owner decision: tighten (refusing those instructions until their manifests say what they move) or keep the warning | Owner |
| Repository rulesets for `main` and release tags | **Prepared (Round 30)**: `.github/rulesets/main.json`, `main-review.json`, `release-tags.json`, `.github/CODEOWNERS`, steps in `docs/ops/branch-protection.md`; not applied | Owner |
| Dependabot majors deferred in Round 30 | #41 (graphite-core group: 13 new crates incl. a compression backend), #12 (sha2 0.11 in the oracle), TypeScript 7 in six packages (#14, #18, #21, #23, #27, #28), #22 (React 19), #26 (rust 1.99 image, with the CI toolchain) | Owner / Engineering |
| Rounds 15–16 findings | **Closed in Round 17** (every item, each with a regression test; see the Round 17 report and `SECURITY.md`) | — |
| Identity mismatches on declared slots | **Diagnosed and mostly closed (Round 20)**: the fee payer's structural writable flag was read as an escalation, blocking every self-paid token transfer. Over the 19,458-transaction sample, identity/privilege blocks fell from 1,355 to 519 and 156 executed transactions went from Blocked to Clear; no other verdict loosened. The remainder is mostly declared read-only slots the transaction marks writable (247) — writability is per message, so a program really can write them — and fixed-address mismatches (156). Measured, not loosened | Engineering |
| Manifests for the traffic that publishes no on-chain IDL | Measured (Round 22): the programs behind 71% of the drainer refusals are signed by five or fewer fee payers and publish no IDL — bots' own programs, not a wallet user's; the programs with an IDL and real users were already manifested and their refusals were fixed | Engineering |
| Manifests below the decode bar | Open: 13 records measure a decode rate under 90% after Round 29 recomputed every rate against the loaded manifests (Bubblegum, Light System Program, Coinflow, Pump Fees, Account Compression, Doorcash, Main, Merkle Distributor, Ocr2, Oridion, Rush, Timelock, Zeta). Metaplex Token Metadata reached 100% in Round 29. Each is recorded in `battle_tested_evidence.json` with the unnamed leading bytes. Round 30 re-counted every manifest from the files (137, 137 unique program ids, 3,541 instructions, 46 unclassed) and showed an undescribed instruction of each of the 13 refused under all four built-in profiles even with evidence seeded (`tests/r30_low_decode_manifests.rs`); no manifest data was invented | Engineering |
| Branch protection on `main` (required CI, no force-push) | **STOP-SHIP.** Absent; the rulesets above are ready to apply. Until they are, every CI gate is advisory | Owner |
| GitHub private vulnerability reporting | Not enabled; once it is, link it from `.github/ISSUE_TEMPLATE/config.yml` | Owner |
| Stale unprotected branches (`copilot/fix-rust-core-actions-job`, `phase2-development`) | Delete or protect them with the rulesets (K-14) | Owner |
| The crate's publish flag; tagging `0.3.0-beta`; deployment | Owner decisions, unchanged by Rounds 29–30 | Owner |
| The 2026-10-21 forensic brief (Round 30: G-01 … G-12, K-01 … K-20) | **Closed in Round 30** except the owner items in this table; see the Round 30 report and its findings registry ([`audit-r30/findings-registry.md`](audit-r30/findings-registry.md)) | — |
| The 2026-10-20 audit (4 HIGH, 16 MEDIUM, LOW and informational items by area) | **Closed in Round 29**: every finding fixed, documented above as a limitation, or listed here as an owner decision; see the Round 29 report and `AUDIT/01-findings.md` | — |
| Version-1 transaction format | **Done (Round 19)**: parsed, never looser than agave, 3,302 of 3,302 real mainnet v1 transactions read and bound; config values surfaced in `scope.compute_budget` (Round 21) | — |
| Token-2022 `TransferFee` modelling | **Done (Rounds 20–22)**: replayed exactly against the executed instructions (Round 21), a pending schedule always judged (Round 22) | — |
| Transfer hooks that run a program | **Done where the bytes bound them (Round 22)**; a hook handed a signer or another program's writable account blocks | — |
| `content_hash` → a name that says it is an instruction-level identifier | **Done in the result (Round 30, R-M10)**: `instruction_bind_key` carries the value, `content_hash` is deprecated for one minor version; lifecycle request bodies keep the `content_hash` wire name | Engineering (request bodies) |
| Runtime-decoder oracle over the mutation corpus | Done (Round 12: `tools/runtime-oracle`, in CI) | — |
| Coverage-guided fuzzing of `parse_transaction` | <!-- WS-E --> Pending the WS-E merge (Round 30) | Engineering |
| Scheduled mutation testing and a coverage floor (R-P12, R-P15) | <!-- WS-E --> Pending the WS-E merge (Round 30) | Engineering |
| A generated, test-pinned release evaluation (R-P1) | <!-- WS-E --> Pending the WS-E merge (Round 30) | Engineering |
| Persisted archive index for the L8 / lifecycle join | **Done (Round 28)**: a count over three 64 MiB archives went from 822 ms to 2.2 ms | — |
| Shared rate limiter for a horizontally deployed Graphite (single-instance today; 452 ns/check at one million buckets) | Open | Engineering |
| Second-source inclusion check for L8 | Done for an independent RPC (Round 12: `GRAPHITE_RPC_WITNESS_URL`); provider independence and a high-assurance mode (Round 30); light-client proof open | Engineering |

## Numbers (as of this page's commit)

**This is the one place the repository states test counts**; every other
document links here, and `tests/docs_numbers_match_the_code.rs` fails if a live
document states one elsewhere.

Rust, from the integrated runs of Round 30 on 2026-10-21/22 at `1f5fc1f` (release
builds, thin LTO off to fit the shared machine; logs kept outside the repository):

- all features: **2,224 Rust tests pass**, 0 failed, 13 ignored (network- or
  sample-dependent, plus two soak benchmarks, each named in
  `.github/test-allowlists/rust-ignored.txt`), across 159 test targets;
- the featureless library (`--no-default-features --lib`): **459 passed, 2 ignored**;
- the cli-only build (`--no-default-features --features cli`): **1,863 passed, 4 ignored**,
  across 159 test targets.

<!-- WS-E --> The WS-E merge (fuzz crate, `graphite benchmark --json`) adds tests; these counts are re-stated after it.

Clippy `-D warnings` (all three feature legs) and fmt clean at each workstream's
head; the integrated tree type-checks on all three legs.

TypeScript: agent guard 277; SolanaAgentKit adapter 9; MCP server 9; Vercel AI
adapter 11; TypeScript SDK 59 (55 hermetic, 4 against a live server — run in
CI's container job); dashboard 31, production build OK. Go SDK: 59 top-level
test functions pass (0 skipped), plus 5 behind the `liveserver` tag; `gofmt` and
`go vet` clean. Python: AI layer 50; `tools/mainnet-sample` 7 (at `29e4356`).
The runtime oracle: ~628,500 frames per CI seed, bincode and wincode, legacy,
v0 and v1, never looser than the runtime. The hosted CI run for the reference
commit `29e4356` (run 39610913297) passed all 10 jobs.

The holdout (`tests/regression_corpus.rs`): n = 38, 37 true positives, 1 false
positive, 0 false negatives — precision 0.974, recall 1.000. The committed
corpus: 13,013 fixtures (12,943 dev, 32 regression, 38 holdout).

Reproduced from `cargo test` / `npm test` / `go test` / `pytest` output on
2026-10-21/22, not estimated. CI for the commit is the GitHub Actions run for that
SHA — the runs endpoint, not the combined-status endpoint.

## Report index (newest first)

| Date | Report | What it records |
|---|---|---|
| 2026-10-22 | [`round30-forensic-audit-and-remediation-2026-10-22.md`](round30-forensic-audit-and-remediation-2026-10-22.md); findings: [`audit-r30/findings-registry.md`](audit-r30/findings-registry.md); ledger, architecture and history: [`audit-r30/README.md`](audit-r30/README.md) | A forensic whole-repository audit of `29e4356` (the Round 29 merge) answered in one round by eleven workstreams: every verdict says whether it permits signing (G-01); a verify-key holder's self-approved requests no longer train evidence, and the learning opt-in is retired (G-02, R30-B-1); per-shape, anchored baselines (G-03); an upgrade withdraws evidence (G-04); a hash-chained, keyed audit trail with `graphite audit verify` / `checkpoint` (G-07); L8 inclusion assurance and a high-assurance mode (G-08); a signer's loss under an unreadable declaration is Critical (R30-F-1); 21 grounded intents for withdrawals, claims, closes, burns and owner configuration (G-06); the guard executes only a decision it recomputes, keys repeats by effect and persists them; a read-only key; a CI that fails on missing tests; rulesets prepared for an owner to apply. Every Round 29 check never broken has now been broken and caught. Release blocked on owner and external items (branch protection, independent audit, deployment) |
| 2026-10-21 | [round29-the-audit-remediated-2026-10-21.md](round29-the-audit-remediated-2026-10-21.md) | A full-repository audit of `19a2974` (4 HIGH, 16 MEDIUM) answered in one round: with an RPC a failed or incomplete simulation now refuses (H1); the agent guard decodes six swap programs and holds a route's own minimum to the simulated delivery, a slippage bound and a price floor (H2, H4), and grounds a transfer in one grammar (H3); refusals no longer train confidence (M1); the verdict's tier is the weakest program's (M2); the registry owns its corpus and signs a domain-tagged message (M3); L8 writes an `execution_check` unless it saw inclusion (M4, M9); every adapter requires a cap and a person sees the resolved transaction (M6–M8); 16 risk checks; 3,541 instructions with corrected classes; an honest holdout (37/37 exploits refused, the one benign swap refused offline) and the mainnet pin moved on 3 of 2,277 rows, each attributed. Deliberate breaks run and caught for the core pipeline, server and CLI, RPC and state diff (28 failures on the reverted code), audit trail and parser, agent guard, SDKs and schema, dashboard, AI layer and contract gate; not run for the risk engine, registry, protocol data and attack suites |
| 2026-10-17 | [round28-archive-index-lifecycle-contract-2026-10-17.md](round28-archive-index-lifecycle-contract-2026-10-17.md) | Each rotated audit archive has a persisted index, checked against the archive's SHA-256, and a count over three 64 MiB archives went from 822 ms to 2.2 ms (R-M11, W10); every lifecycle event names its emitter in an exhaustive `match` a test drives end to end, and `operator_action` is now pinned as unforgeable (R-P14, R28-2); the published schemas are diffed against the last release tag, whose first run found two caller-side breaks since `v0.2.0-beta` under the same version, so the crate is `0.3.0-beta` (R-M2, R28-1) |
| 2026-10-16 | [round26-27-real-traffic-and-upgrades-2026-10-16.md](round26-27-real-traffic-and-upgrades-2026-10-16.md) | Two finalized mainnet blocks (2,284 executed transactions) committed and run through the whole pipeline on every `cargo test`, the verdict file's SHA-256 pinned and equal to the full measurement's (R-P2/R-P3); protocol upgrades noticed: with an RPC, a manifested program redeployed or handed to a new upgrade authority since last seen is reported on the verdict, on `/health` and in the metrics, and quarantined if the operator set `GRAPHITE_QUARANTINE_ON_UPGRADE` (R-M1); advisories published after Round 24 fixed (`quinn-proto`, `rustls`, three npm) |
| 2026-10-16 | [round25-the-swap-is-the-one-asked-for-2026-10-16.md](round25-the-swap-is-the-one-asked-for-2026-10-16.md) | A second external review (E1–E10): the guard grounded that a request asked for a swap, not which one — now the amount and both tokens come from the user's text and the simulated transaction is held to them; negated requests refused; the spend cap reads one simulation snapshot; the guard's RPC reads bounded and its lamports exact; L8 asks the witness for the bytes, so neither a primary without them nor one serving substituted bytes can silence a blocked transaction's alarm; more than 64 top-level instructions refused in every format. One item (the legacy 12-signature limit) not a finding |
| 2026-10-03 | [round24-the-intent-is-the-class-2026-10-03.md](round24-the-intent-is-the-class-2026-10-03.md) | External review R2/R3 reproduced on `eb17aa5` (a `transfer` label got L5 Passed and L7 Clear for Squads drains, Bubblegum `delegate`, `MintTo`/`Burn`) and fixed with one intent-to-class table; control changes by name, delegation, switch and admin signer; W11–W25 verified and fixed or documented; the Vercel AI SDK and MCP integrations; eight more manifests (137, then 3,504 instructions; 113 battle-tested). Four days of mainnet: 302 newly refused, 0 freed, 0 approved; one more P1 (R3-b) found by that measurement and fixed |
| 2026-10-01 | [round23-the-audit-closed-at-the-root-2026-09-30.md](round23-the-audit-closed-at-the-root-2026-09-30.md) | A six-area audit of the whole repository at `3327fcf` (`AUDIT/`): no P0, four P1s (a close with a trailing byte, hand-overs as primary and as sibling, quarantine of the primary only), 20 P2s and 54 P3s, each fixed at its root with a test that fails on `3327fcf`. A review of the fixes found what they broke (F1–F15), and the full suite and a native-manifest sweep found three more: staking refused as a hand-over (F16), a fixture without account names (F17), and a durable-nonce opt-in that could never approve (F18). Four days of mainnet against `3327fcf`: 461 transactions freed, 9 newly refused. Verdict in `AUDIT/FINAL.md`: a supervised pilot, not independently audited |
| 2026-09-27 | [round22-the-rest-of-the-list-2026-09-27.md](round22-the-rest-of-the-list-2026-09-27.md) | Round 21's open items, each measured first. A transfer hook that runs a program is bounded by the bytes (nothing Token-2022 can hand it signs; every writable one is its own) and no longer blocks on sight; the fee landing margin is removed — a pending schedule is always judged; privileges are the runtime's (agave's demotion); Anchor's absent optional accounts recognised (676 slots from IDLs and traffic); every manifest grounded in 2,998 of its programs' own transactions — Jupiter's token-account pins, a placeholder Stake manifest and a swapped BPF Loader layout rebuilt from their interfaces, sixteen remaining-account interfaces declared (45,253 of 45,282 executed instructions clean); declared siblings counted by their writable extras like the primary (live mainnet RPC: risk Clear 24 → 33 of 40). The bridge builds v0. 71% of drainer refusals are bots' own IDL-less programs; the heuristic stays. Three days of mainnet: 230 Blocked → Clear, 0 the other way |
| 2026-09-27 | [round21-what-happened-not-what-could-2026-09-27.md](round21-what-happened-not-what-could-2026-09-27.md) | The open list closed by observation. Graphite refused on what an account, flag or extension COULD do rather than what the transaction DID: the fee model now replays the executed Token-2022 instructions (withdrawals, several transfers, send-and-receive; 31 of 31 real transactions reproduced exactly) with the epoch read; a writable flag is judged by a sibling's declared write or Graphite's own diff; a null hook, untouched confidential state and unchanged issuer powers are inert and a permanent delegate's exercise is Critical; a self-refunding `CloseAccount` and read-only remaining accounts are no longer drains; the priority fee is read and bounded. 105 manifest instructions rebuilt or corrected where the programs' IDLs AND executed traffic agree. L4 measured at one slot and against the whole transaction (live L4 failures 10 → 2 of 40). Three days of mainnet (39,857 verified): 2,553 executed transactions Blocked → Clear on risk, 0 the other way. 25 of 25 deliberate breaks caught |
| 2026-09-25 | [round20-the-fee-is-modelled-2026-09-25.md](round20-the-fee-is-modelled-2026-09-25.md) | Token-2022 `TransferFee` modelled: the mint's schedule read by Graphite (a TransferChecked names its mint read-only, so it was never diffed), every withheld amount required to be Token-2022's exact fee on what arrived, value conserved, the fee and the arrival stated, a majority fee blocked; checked against the upstream arithmetic and against real fee-bearing mints (6 isolated real transfers, 0 mismatches). Building it exposed that every self-paid SPL / Token-2022 transfer was already refused — the fee payer's structural writable flag read as a privilege escalation (the cause of Round 18's undiagnosed identity cluster: 1,355 → 519 blocks, 156 real transactions Blocked → Clear, nothing else loosened) and left out of L4's diff — and that a request could label its own state diff as Graphite's |
| 2026-09-24 | [round19-what-one-observation-is-2026-09-24.md](round19-what-one-observation-is-2026-09-24.md) | An external review of `453dd01` checked and widened, every part of Graphite run live, v1 parsed. The baseline counted a fresh blockhash as a new observation — reproduced on the `a1db51f` release binary as a refused transfer **approved on its third ask** with nothing else changed — and simulated and certified descriptive requests; the reviewer's 256-key window forgot. Also: the CPI-trace rules never ran on real traffic; an undescribed instruction was diffed on one account; the verify key was the operator key; 40 trickling unauthenticated connections shed all traffic; the CLI wrote beside a running server and a corrupt snapshot lifted every quarantine; the reference bridge signed before the verdict (P0, client side). Version 1 parsed, never looser than agave, 3,302 of 3,302 real ones bound. 19,458 real mainnet transactions through the pipeline and 40 against the live mainnet RPC; two false-refusal classes found and fixed; 13 of 13 deliberate breaks caught; the release binary passes 22 of 22 live checks that `a1db51f` fails 17 of |
| 2026-09-23 | [round18-the-registry-is-measured-2026-09-23.md](round18-the-registry-is-measured-2026-09-23.md) | `trust_tier` was a string nothing checked: eight manifests declared `BattleTested` and the engine believed all eight. A mainnet measurement now backs every seed manifest (executable account; >=1,000 successful transactions over a stated window; >=90% of >=20 really-observed instructions named), and `load_seed_manifests` lowers an unsupported declaration. The registry went from 803 instructions in 33 manifests to 3,186 in 129 (106 of them battle-tested on the evidence), ranked by what mainnet runs and generated from each program's own on-chain Anchor IDL; 216 instructions merged into six manifests that had fallen behind. Running that registry against real blocks found two pre-existing defects blocking legitimate traffic — an undeclared extra account had a privilege to mismatch (1,036 blocks across four programs), and the Wormhole manifest named the wrong instruction for two bytes — plus one introduced and fixed in the round (PDAs grounded under the wrong program). Non-vote mainnet transactions whose primary program Graphite can name: 20.8% -> 44.0% on the same sample. 544 identity mismatches remain, measured and left open rather than loosened |
| 2026-09-22 | [round17-what-counts-as-evidence-2026-09-22.md](round17-what-counts-as-evidence-2026-09-22.md) | Every Round 15 and Round 16 finding closed, each with a regression test that fails on `e95857d`: pre-signed artifacts refused at `/verify` and L8 reporting `RecordedForDifferentBytes` (F-16-01) and `recorded_verdicts` (F-16-11); baseline eligibility — sound and risk-clear only, `err == null` part of completeness, one observation per artifact digest (F-16-03, F-15-01, F-15-02) — with a `simulation_failed` residual (F-16-04); a variance floor, a shadow accumulator, `/health.frozen_baselines` and `graphite evidence promote-shadow` (F-16-02); L2 fails on unresolved lookup positions (F-15-05); Check 10 keyed on the bytes (F-15-03); observed CPI targets judged (F-16-05); the PDA template grammar closed at load and at verify (F-16-06); blocking plugins fail closed on panic (F-16-07); `min_confidence > 1` a 400 and the tier axis clamped (F-16-08, F-15-07); framed `content_hash` v2 in all four implementations (F-16-09); http(s)-only manifest links (F-16-10); lifecycle merged across a rotation (F-15-09); the devnet demo through `executeBoundTransaction` and the Go doc with the residual check (F-16-12); `--locked` in CI, `go.mod` pinned (F-16-13/16); finite rate limit (F-16-15); mismatches by slot (F-16-14). Live-probed on a loopback Core; CI green |
| 2026-09-21 | [round16-signed-before-it-was-shown-2026-09-21.md](round16-signed-before-it-was-shown-2026-09-21.md) | The full 43-section forensic brief run against `e95857d` (code identical to `21c0a7b`), report only. The exact-byte boundary held under every mutation tried, and 2 of 2 deliberate breaks (L8 signature binding, sibling coverage) were caught. New: a pre-signed artifact is approved as `artifact_bound` but its refusal cannot be found by L8 when the chain's bytes are available — the stronger evidence path yields the weaker alarm (F-16-01); ten identical-CU requests, none of which need to be approved, freeze a program's baseline and refuse every honest transaction at any other CU (F-16-02/03); plus measured CPI targets, PDA template grammar, Risk-plugin panic semantics, a 500 on `min_confidence > 1`, unframed `content_hash`, console link schemes, last-wins L8 attribution, and `--locked` in CI. Round 15's three P2 findings re-measured and still open; twelve historical classes CONFIRMED CLOSED; 14 missing tests named |
| 2026-09-20 | [round15-earned-by-asking-2026-09-20.md](round15-earned-by-asking-2026-09-20.md) | A full forensic re-audit of `21c0a7b`, report only. The exact-byte boundary and all twelve historical classes re-checked and confirmed closed. Three new confirmed defects, none an approval bypass through the reference bridge: confidence is earned by repetition — the same refused request is approved under Gaming on its second call because the `SimulationMatch` signal is the baseline sample count (F-15-01); a failed simulation with non-zero compute units is recorded as trusted evidence and certified "integrity clean" by L3 (F-15-02); an empty caller label switches the manifest risk-class hard gate off for non-native programs while the confidence floor still refuses (F-15-03). Plus the unresolved-ALT approval path and the deactivating-table discrepancy (F-15-05), two digests for one artifact (F-15-04), two in-repo executors without the residual policy (F-15-06), and three hardening items. 1 of 1 deliberate break caught; 11 missing tests named |
| 2026-09-20 | [round14-the-prefix-and-the-pin-2026-09-20.md](round14-the-prefix-and-the-pin-2026-09-20.md) | A forensic re-audit of Round 13 found that re-keying the Risk Engine on the instruction's bytes while leaving every OTHER manifest lookup on the caller's label was itself a bypass (GFX-101, HIGH): a truthful four-byte PREFIX of a discriminator switched off PDA re-derivation, the fixed-address comparison and the privilege comparison together, taking an attacker's program in Jupiter route's pinned slot from Blocked to `approved: true, artifact_bound, inherent residuals only`. Four more of the same shape: the declared-effects lookup (GFX-102), declared siblings judged on their labels (GFX-106), sibling lookup-table positions as wildcards (GFX-107), and the empty-label spelling of the first fix (GFX-108). One `effective_discriminator` now keys every manifest lookup; 5 of 5 deliberate breaks caught |
| 2026-09-17 | [round13-the-label-and-the-bytes-2026-09-17.md](round13-the-label-and-the-bytes-2026-09-17.md) | The Risk Engine judged the caller's label rather than the instruction (GFX-001, HIGH): a real SetAuthority declared `ff` was approved where the same bytes declared `06` were Blocked; the self-consistency check now runs first for every protocol and the table is keyed on the instruction's own bytes, which also closes the truthful-but-truncated variant. L4 was blind to the SPL `owner` field, so a token account changing hands produced no findings (GFX-002, MEDIUM); three authority fields now watched. AuditBind refuses a mismatched declaration by rule rather than by accident |
| 2026-09-16 | [round12-runtime-truth-2026-09-16.md](round12-runtime-truth-2026-09-16.md) | The runtime oracle (parser accepted five frame classes the runtime refuses, R12-01); L8 commitment, self-consistency, malformed statuses, redirects, the inclusion witness (R12-02…05); one server per data directory (R12-06); RPC URL validation (R12-07); lifecycle sequence findings and signature shape (R12-08…10); the bridge's submission-report retry (R12-11) |
| 2026-09-15 | [round11-full-run-2026-09-15.md](round11-full-run-2026-09-15.md) | The full run: L8 chain bytes unbound to the signature (R11-01, P1) fixed; request path deep-copying state (100 ms → 1 ms); refusals reset the connection; parser signer-count rule; 32-character keys; L8 metrics; SDK live conformance in CI |
| 2026-09-13 | [round10-exact-attribution-2026-09-13.md](round10-exact-attribution-2026-09-13.md) | L8 and lifecycle joined on `content_hash` (R10-01, P1): now joined on the chain's bytes / exact keys; supply-chain pins; decompression and limiter measured |
| 2026-09-12 | [round9-next-surface-2026-09-12.md](round9-next-surface-2026-09-12.md) | Artifact without data bound uncompared (R9-01, P1); unparseable artifact fails L2; residual codes and the bridge's residual policy; packet-size bound; lifecycle bounds, `verdict_on_record`, the bridge's lifecycle reporting; CI/image pinning |
| 2026-09-12 | [round8-remaining-assumptions-2026-09-12.md](round8-remaining-assumptions-2026-09-12.md) | Audit durability, archive visibility, durable nonces, auth default, byte-level parser corpus |
| 2026-09-11 | [round7-adversarial-assurance-2026-09-11.md](round7-adversarial-assurance-2026-09-11.md) | BoundTransaction aliasing, Token-2022 malformed TLV fail-open (R7-01), ALT owner, cross-language corpus |
| 2026-09-11 | [round6-execution-boundary-2026-09-11.md](round6-execution-boundary-2026-09-11.md) | Exact final transaction binding; signing gate made unskippable |
| 2026-09-11 | [identity-boundary-campaign-2026-09-11.md](identity-boundary-campaign-2026-09-11.md) | ALT identity, privileges from the artifact, instruction-account identity |
| 2026-09-08 | [production-readiness-audit-2026-09-08.md](production-readiness-audit-2026-09-08.md) | Server, audit trail, CI, deployment |
| 2026-09-08 | [rpc-validation-campaign-2026-09-08.md](rpc-validation-campaign-2026-09-08.md) | RPC trust boundary, budget, provider precedence |
| 2026-09-06 | [adversarial-campaign-2026-09-06.md](adversarial-campaign-2026-09-06.md) | Early adversarial hardening |
| earlier | `phase1-internal-validation-report-2026-08.md` (formerly the root `GRAPHITE_FINAL_CERTIFICATION_REPORT.md`), `final-forensic-report.md`, `forensic-audit-report.md`, `clean-room-revalidation-C26.md`, `phase2-certification-report.md`, `release-evaluation-report.md`, `independent-gap-audit.md`, `p16-mainnet-benchmark.md`, `drift-kamino-onboarding-C27.md` (its Drift repository path is corrected in a note at its top) | Phase 1/2 milestones. Their descriptions of L8, benchmark sizes, test counts and protocol counts are **historical** and superseded here. |
| 2026-08-12 | [evidence/Graphite_Full_Colosseum_Copilot_Deep_Dive.pdf](evidence/Graphite_Full_Colosseum_Copilot_Deep_Dive.pdf) | **Historical, superseded.** A Colosseum Copilot "deep dive" prepared on 2026-08-12, when Graphite had 28 manifests, 11 risk patterns and 999 tests; its figures and its market claims describe that moment, not the code today. |

`phase2-plan.md`, `phase2-branch-strategy.md` and the grant proposal
(`solana-foundation-grant-proposal.md`) are plans and proposals, not status.

`docs/protocol-coverage.md` is generated by `graphite-core/scripts/render_coverage.py`
from the manifests, the evidence file and recorded measurements, and carries no
render date: the same inputs give the same page. Its transaction-version shares are
the 80-block census's (version 1: 15.8%); in the 10,617-transaction full-pipeline
sample version 1 is 17.2%.

## Language discipline

"Certified" in any report means: that commit's GitHub Actions run completed
successfully. It never means an external party certified anything. "Passed
N tests" is evidence that N specific reproductions run; it is not evidence of
security.
