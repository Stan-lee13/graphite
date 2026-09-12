# Round 7 — Adversarial Assurance

> **Historical record (2026-09-11).** This report describes the codebase as it was when it was written and is kept unedited as evidence. For what is true now, read [CURRENT.md](CURRENT.md).

**Ground truth at the start of the round.** HEAD `76d0ade`; parents `5c33ea0`,
`0284c24`, `f10e4ab`. All four have GitHub Actions runs that completed
**success** — verified from the Actions API, not from commit messages. rustc
1.98.1 (CI's `stable`), Node 24.1.0, `@solana/web3.js` 1.98.4, TypeScript 5.9.3.
Working tree clean apart from an untracked `.agents/`.

**Method.** Internal engineering work by Anthropic's Claude acting as this
project's engineering agent. **Not an independent third-party audit, not a
certification, not a penetration test by an external firm.** Every confirmed
finding was reproduced against running code before it was changed; the
reproduction is committed as a test.

**Boundaries observed.** No credentials in source, commits, logs or this report.
No network beyond loopback mocks and one read-only GitHub API call. Nothing
signed, sent, or submitted; no live user, wallet, protocol or funds touched.

---

## The invariant

> For every executable `artifact_bound` approval, the exact Solana MESSAGE
> Graphite approved is the exact MESSAGE contained in the bytes signed and
> submitted.

Not "the instructions look similar". Not AuditBind equality. Not matching
program ids. The message — everything after the signature array.

---

## Findings

### R7-01 — a malformed Token-2022 extension region looked like no extensions — **P1** — CONFIRMED, FIXED

**Affected:** `graphite-core/src/state_diff.rs`, `detect_token2022_extensions`,
`check_state_diff`.

**Threat model.** Any account whose data Graphite reads from the RPC — so an
RPC that returns corrupt bytes, or an account genuinely written that way.

**Reproduction.** A Token-2022 account, type byte `Account`, whose first TLV
entry is `TransferHook` (14) declaring 60,000 bytes that are not there. The walk
stopped at the bad length and returned an empty `Vec`. An account with no
extensions also returned an empty `Vec`. The probe test asserting the two
differ **failed**.

**Why existing defenses failed.** The Round 6 scanner "stopped rather than
guessed" — correct — but recorded nothing about having stopped. The state-diff
check then read an empty list as an account with nothing attached and raised no
finding. A transfer hook behind a corrupt length byte produced silence.

**Security impact.** Mechanism demonstrated. No end-to-end approval of a
materially different transfer was constructed, because the account would also
need to survive every other gate; **P1, not P0**, on that basis. It is a
regression class the Round 6 fix itself introduced, which is precisely what
this round was asked to look for.

**Fix.** `ExtensionScan { found, malformed: Option<String> }`. `is_clean()` is
true only when the region was read to its end. A `malformed` scan produces a
critical finding `Token2022ExtensionRegionUnreadable`, checked *first*, so a
corrupt header in front of a hook cannot turn the hook into silence. The
wrong-type-byte case and the trailing-bytes case are recorded as malformed too.

**Regression tests.** `token2022_extensions.rs` (15): the probe, now asserting
the two scans differ; malformed-first-entry; trailing bytes; unknown type byte;
duplicates; every named discriminant 1–23 with its classification, and 24 as
`Unknown`. `l4_state_diff_gate.rs` (+5), **through `verify`**: a transfer hook
fails L4 and blocks; a permanent delegate blocks; an unrecognised discriminant
blocks; an unreadable region blocks; and the control — `ImmutableOwner` is
named and does **not** block.

**Confidence.** High.

### R7-02 — `BoundTransaction` relied on detection alone against aliasing — **P2** — FIXED STRUCTURALLY

**Affected:** `integrations/solana-agent-kit/artifact.ts`.

**Threat model.** A caller, plugin or helper that kept a reference to an
instruction, an `AccountMeta` array, or a data `Buffer` before `build()`.

**Reproduction.** Round 6 already showed such mutations were *detected* by the
digest check. This round asks the stronger question: can they reach the
transaction at all? They could — `new TransactionInstruction` does not copy
`data`, so the caller and the transaction literally shared bytes.

**Fix.** `tx` is `private`, and `build` deep-copies every instruction: program
id and pubkeys through their bytes, data through a fresh `Buffer`, flags as
primitives. `instructions()` returns fresh copies; the bridge projects AuditBind
from those. The three alias tests now assert the **opposite** of Round 6: the
alias is mutated, the honest path signs, and the signed message is the approved
message — the alias touched an object the transaction no longer shares.

**What this does not claim.** TypeScript `private` is compile-time. Code that
reaches in with `as any` is a hostile in-process actor; the digest check remains
for exactly that case and is tested through `hostile(bound)`. Monkey-patching
`Transaction.prototype.serialize` is outside any reasonable threat model for
in-process JavaScript: a process that can do that can replace `signApproved`
itself. Stated as the boundary, not defended past it.

**Confidence.** High.

### R7-03 — lookup-table owner was not checked — **P2** — FIXED

**Affected:** `graphite-core/src/verification.rs` (table fetch).

**Threat model.** An RPC returning table-shaped bytes under the wrong owner —
misconfigured, partially honest, or serving attacker-chosen account data.

**Mechanism.** `resolve_lookups` took `HashMap<String, Vec<u8>>` — data only.
The runtime honours a table only under `AddressLookupTab1e…`; bytes at that
address under any other owner would be rejected at execution. Decoding them
resolved accounts the transaction cannot actually reach — an answer about a
transaction that will not run.

**Fix.** Owner checked before decoding; wrong owner is an unresolvable table,
reported by name.

**Regression test.** `alt_privilege.rs`: the same well-formed table served
under the System program resolves nothing, no privilege block fires, the scope
names the owner problem, and the verdict is not an approval.

**Confidence.** High. A *fully* malicious RPC can lie about the owner too; this
closes the confusion and misconfiguration cases, not RPC compromise, which the
trust-boundary work bounds elsewhere.

### R7-04 — the swap opt-out was enabled by `=1` and its result was not machine-readable — **P2** — FIXED

**Affected:** `graphite-sak-bridge.ts`.

**Threat model.** Operational: a `=1` copied from a README, inherited from a
shell profile, or left in a `.env` after a test.

**Fix.** The variable must equal the exact phrase
`I_ACCEPT_UNVERIFIED_SWAP_EXECUTION`. Every execute call returns
`ExecutionOutcome { executed, verifiedExecution, verification, signature?,
unverifiedReason? }`. `verifiedExecution` is true **only** when `signApproved`
signed the bytes Graphite hashed; false for a block; false with a named reason
for the opt-out. `executed: true` alone no longer distinguishes the two.

**Confidence.** High.

### R7-05 — cross-language agreement was tested on one shape — **COVERAGE GAP** — CLOSED

**Fix.** `emit-corpus.ts` emits ten shapes: single transfer, two signers, empty
data, shared-account privilege union, 900-byte data, twenty accounts, a
different blockhash, a different destination, reordered instructions, and a
**v0 message compiled by web3.js against a real mainnet lookup table**. Each
records the digest, the message slice, the required signers, the static keys,
the instruction count, the version, and the lookups. `sak_bridge_corpus.rs`
requires the Rust parser to reach every one of those conclusions from the bytes
alone, resolves the v0 entry against the real table and checks the instruction's
table-sourced accounts are the ones web3.js put there, and requires all ten
digests to be pairwise distinct. CI regenerates the corpus and fails on drift.

---

## NOT A FINDING

### Retry or rebuild after approval

Repository-wide sweep for `getLatestBlockhash`, `retry`, `resend`, `rebuild`,
`compileToV0Message`, `VersionedTransaction`, `TransactionMessage`,
`lastValidBlockHeight`. **No retry loop exists.** `getLatestBlockhash` is called
exactly once per execution, before `BoundTransaction.build`. Submission is
`sendRawTransaction` + `confirmTransaction` with no resend. Expiry throws and
the caller starts over from verification. This is the reviewer's model B by
construction — there is no rebuild code to bypass. `sendRawTransaction`'s
optional `maxRetries` resends identical raw bytes (model A) and is not used.

### A consumer gating on `approved` alone

Sweep of `sdk/`, `dashboard/`, `python-ai-layer/`, `integrations/` for
`.approved`, `isArtifactBound`, `artifact_bound`, `unobserved`. The TypeScript
and Go SDKs expose `isArtifactBound()` / `unobserved()` and execute nothing. The
dashboard displays. The bridge's only signing path, `signSubmitAndConfirm`,
requires `scope.kind == "artifact_bound"` and goes through `signApproved`; its
`verification.approved` check is a log line and an early return on block, not
the gate. `devnet-test.ts` was the one exception and was fixed in Round 6.

### Per-instruction privilege flags not covered by the digest

Retained from Round 6, still true: Solana's privileges are per-message,
web3.js unions the metas at compile time, and an unchanged compiled message is
unchanged execution.

### ALT reinterpretation after approval

Retained from Round 6 with the invariant named: `ExtendLookupTable` appends
only; the runtime rejects deactivated tables; a table address is a PDA over a
non-reusable slot. Encoded as a test. This round adds the owner check (R7-03),
which is the one runtime-state property the Round 6 argument did not cover.

---

## DOCUMENTED LIMITATIONS

- **The bridge surfaces `unobserved` and does not gate on its content.** Every
  `artifact_bound` verdict carries a non-empty residual by design. Which
  residuals a deployment accepts is a deployment decision; the bridge prints
  them and does not decide for the operator.
- **A compromised process is a compromised process.** `private`, deep copies
  and the digest check defend against callers, plugins and helpers that behave
  like JavaScript. They do not defend against code that rewrites this module.
- **Token-2022 remains classified, not modelled.** Fee-bearing mints are
  refused. Modelling `TransferFee` properly is the path to accepting them;
  lowering the classification is not.

---

## Evidence

Exact commands, exact outputs, this HEAD plus the working tree of this round:

```
cargo test --all-features                       1,399 passed, 0 failed, 10 ignored
cargo test --no-default-features --lib          295 passed
cargo test --no-default-features --features cli clean
cargo clippy --all-targets --all-features -- -D warnings   clean
cargo fmt --all -- --check                      clean
npm test  (integrations/solana-agent-kit)       69 passed, 0 failed
```

CI for `76d0ade`: **completed success** (Actions API). CI for `1830e7b`, the
commit carrying this round: **completed success** (Actions API, all seven jobs).

---

## Verdict

```
Graphite Security Status:       CONDITIONAL — security-hardened alpha
Final Transaction Identity:     PASS
ALT / v0:                       PASS
SAK Execution Boundary:         PASS
Semantic Coverage:              CONDITIONAL
Parser / Wire Safety:           PASS
CI Certification:               CERTIFIED — 1830e7b and 76d0ade both completed success

P0: none
P1: R7-01 (fixed)
P2: R7-02, R7-03, R7-04 (fixed)
COVERAGE GAP: R7-05 (closed)
```

### The question, answered per category

| Can this cause approve-A / execute-B? | Answer |
|---|---|
| malicious caller | Prevented by: digest re-check inside `signApproved`; deep-copied inputs |
| mutable transaction alias | Prevented by: deep copy at `build`; alias never reaches the transaction |
| malicious plugin (in-process, respects the type system) | Prevented by: private `tx`, copied accessors, digest check |
| malicious plugin (rewrites this module) | Not exploitable under the stated threat model because: a process that can do that can replace the gate itself; outside scope |
| malformed transaction | Prevented by: parser refuses; bounds and canonical encoding on both sides |
| parser disagreement | Prevented by: ten-shape corpus asserted equal in CI; drift fails the build |
| ALT mutation | Prevented by: append-only extension, runtime rejection of deactivated tables, non-reusable PDA slots |
| ALT resolution failure | Prevented by: all-or-nothing resolution; unresolved is unobserved, never empty |
| ALT wrong owner | Prevented by: owner checked before decoding (R7-03) |
| Token-2022 extension | Prevented by: classification blocks semantics/authority/unknown; unreadable region blocks (R7-01) |
| signer misuse | Prevented by: signer set derived from the message |
| retry path | Not exploitable because: no retry code exists |
| blockhash refresh | Prevented by: digest changes; refusal with instruction to re-verify |
| RPC poisoning | Bounded by: derivation over provider fields; owner checks; unreadable is never zero |
| descriptive scope | Prevented by: `signSubmitAndConfirm` requires `artifact_bound` |
| AuditBind substitution | Prevented by: one signing path; AuditBind runs before it and only adds refusals |
| stale approval | Prevented by: the digest is over the blockhash; a stale one no longer matches |
| alternate SDK / demo path | Prevented by: repository sweep; `devnet-test.ts` fixed; opt-out is explicit and machine-readable |
| callback / timing | Prevented by: check and sign are one synchronous call |
| serialization mismatch | Prevented by: corpus |
| malformed TLV | Prevented by: R7-01 |
| unsupported protocol feature | Blocked by: unknown extension discriminants block |

### Required before production

1. Independent third-party audit. Nothing here substitutes for one.
2. Branch protection on `main`. Still absent; still deferred to the owner for
   the reason given in Rounds 5 and 6.
3. A deployment decision on Token-2022 fee-bearing mints.

### Recommended after production

- Model `TransferFee` first among the Token-2022 extensions.
- Rename `content_hash` → `instruction_content_id`.
- Grow the corpus with mutations at the byte level in addition to the
  structural variants.
