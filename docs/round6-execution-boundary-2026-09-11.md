# Round 6 — Breaking the Final Transaction Identity Boundary

**Target.** `main` from `f10e4ab` to `5c33ea0`. The question: *can anything
anywhere in the application mutate, reconstruct, reinterpret, retry or replace
the approved transaction between Graphite approval and Solana submission?*

**Method.** Internal engineering work by Anthropic's Claude acting as this
project's engineering agent. **Not an independent third-party audit, not a
certification, not a penetration test by an external firm.** Every finding below
was reproduced against running code before it was changed.

**Boundaries observed.** No credentials, keys or RPC secrets in source, commits,
logs or this report. Mainnet read-only. Nothing signed, sent or submitted; no
live user, wallet, protocol or funds interacted with. Every hostile response
from a loopback mock. Attack fixtures use generated or test keys.

---

## The invariant, written down before testing

> If Graphite returns an executable `artifact_bound` approval, the exact Solana
> MESSAGE it approved must be the exact MESSAGE contained in the bytes that are
> signed and submitted.

The artifact carries empty signature slots and the submitted transaction carries
a real signature, so **whole-transaction byte equality is impossible by
construction** and any claim of it would be false. The message — everything
after the signature array, which is what Solana executes and what a signature
commits to — is the stable invariant. Signing may change the signature region
and nothing else.

---

## Findings

### R6-01 — `messageOf` accepted malformed compact-u16 — **P2** — FIXED

**Affected:** `integrations/solana-agent-kit/artifact.ts`, `messageOf`.

**Attack.** Three defects in a second implementation of Solana's compact-u16:

1. No `u16` bound — accepted up to 2,097,151.
2. Non-minimal encodings accepted (`[0x80,0x00]` = 0 in two bytes), which the
   Rust core rejects. Two parsers of one format had different acceptance
   languages.
3. Worst: with the continuation bit still set on the third byte, the loop fell
   out **without error** and carried on with a truncated count, reaching the
   bounds check by luck rather than by rule.

**Why it matters.** The dangerous outcome is not an exception, it is a *wrong
answer*: a mis-parsed count slices at the wrong offset and compares the wrong
range of one transaction against the right range of another.

**Exploitability.** Low. Both sides of the comparison are produced by
`@solana/web3.js`, which emits canonical encodings, so no path was found that
reaches `messageOf` with a malformed count. Classified P2 rather than P1 for
that reason.

**Fix.** The Rust reader's exact rules: at most three groups, the third must
terminate, minimal encoding required, `u16` bound.

**Regression test.** `execution-boundary-fuzz.test.ts` — boundaries 0/1/2/3/
127/128/129/255/256/65535, refusals at 65536 and 2,097,151, non-terminating and
non-minimal forms, truncated and empty input, and a sweep over 36,864 count
prefixes asserting that anything accepted slices at an offset the encoding
actually implies.

### R6-02 — signing was reachable without the digest check — **P2** — FIXED

**Affected:** `artifact.ts` (`BoundTransaction`), `graphite-sak-bridge.ts`.

**Attack.** `assertApproved` and `signAndFreeze` were separate public methods,
called adjacently. Nothing can run between two synchronous statements with no
`await` between them, so the sequence was safe — **by arrangement, not by
construction**. One refactor inserting an `await`, or one new caller, reopens it.

**Exploitability.** None demonstrated in the current code. Reported because the
property held for a reason that is not enforced.

**Fix.** Both private, behind `signApproved(digest, signers)`. There is no API
through which the object can be signed without its digest being checked.

### R6-03 — the signer set was unconstrained — **P2** — FIXED

**Attack.** `signAndFreeze(signers)` signed with whatever it was given. Graphite
never verifies signatures, so nothing downstream notices the wrong key, a
missing required signature, or an extra one. The first two produce a failed
transaction; the third passes unremarked.

**Fix.** Required signers are derived from the message —
`numRequiredSignatures` over the compiled account keys — and the supplied set
must match exactly.

**Regression test.** Wrong key, extra signer, empty set, one of two required,
and the complete set in either order.

### R6-04 — a demo submitted funds on a Descriptive verdict — **P2** — FIXED

**Affected:** `integrations/solana-agent-kit/devnet-test.ts`.

**Attack.** The script whose stated purpose is *"demonstrates the full
verification gate"* verified a description with no `signed_transaction` — a
Descriptive verdict constrains nothing about what gets signed — gated on
`approved` alone with no scope check, then built a **separate** transaction and
submitted real devnet funds with `sendAndConfirmTransaction`.

**Exploitability.** Not library code, so not attacker-reachable. Reported
because it is a live path from approval to submission with no artifact binding,
in the file an integrator is most likely to copy.

**Fix.** One `BoundTransaction`, the bytes sent for verification,
`scope.kind == artifact_bound` required, `unobserved` printed, and
`signApproved` used. `sendAndConfirmTransaction` no longer appears in it.

### R6-05 — ALT-sourced instruction positions were never compared — **P1** — FIXED

**Affected:** `graphite-core/src/tx_artifact.rs`,
`graphite-core/src/verification.rs` (L2).

**Attack.** `ArtifactInstruction.accounts` resolved an index past the static
keys to `None`, and `compare_instruction_accounts` skipped `None` positions. So
for a v0 transaction, the positional identity check covered the static accounts
and **skipped exactly the accounts a v0 transaction can reach without naming
them**. Every layer downstream reasons over the described list.

**Exploitability.** **UNCONFIRMED as an end-to-end bypass.** The mechanism is
demonstrated — those positions were not compared — but no full approval of a
materially different transaction was constructed, because the surrounding gates
(sibling correspondence, account universe, privilege derivation) would each need
to be satisfied simultaneously. P1 rather than P0 for that reason.

**Fix.** The parser keeps raw indexes; `runtime_account_list` rebuilds the
runtime's own numbering (static keys, then ALT writables in message order, then
readonlies); L2 compares every position. All-or-nothing: a partial list
renumbers everything after the gap, so an index would name a real account that
is the wrong one — worse than naming nothing, because it looks like an answer.

**Regression test.** `alt_real_v0.rs` — 81 instruction account positions across
three real mainnet transactions now resolve through lookup tables; a resolution
of the wrong size is refused; an unresolved message yields no list rather than a
short one.

### R6-06 — Token-2022 extensions were invisible — **P1** — now BLOCKS

**Affected:** `graphite-core/src/state_diff.rs`.

**Attack.** The decoder reads the base 165-byte layout Token and Token-2022
share. An extension changes what a transfer *does* without touching any field it
reads: `TransferFeeConfig`/`TransferFeeAmount` take a cut, `TransferHook` runs
arbitrary code, `PermanentDelegate` can move the balance, `NonTransferable`
forbids the transfer, `DefaultAccountState` can freeze it, `ConfidentialTransfer`
hides the amounts.

**Why it matters.** "The balances moved as described" is then a statement about
arithmetic, not behaviour — the bytes-understood-is-not-behaviour-understood
conflation.

**Exploitability.** **UNCONFIRMED as an end-to-end bypass.** No approval of a
materially different effect was constructed; the mechanism is the gap.

**Fix, stated precisely: classified, not modelled.** Extensions are detected
from the TLV region, named, and classified — `AltersTransferSemantics`,
`AltersAuthority`, `Informational`, `Unknown`. The first two and `Unknown`
**block**. Nothing claims to know what a hook does; it is claimed that one is
attached, and that Graphite cannot say what it does.

**Recorded tradeoff (P14).** Every token account of a fee-bearing mint carries
`TransferFeeAmount`, so ordinary transfers of those tokens are now refused
rather than approved-with-a-note. The alternative is approving a transfer whose
arriving amount Graphite cannot compute. Modelling a given extension properly is
how it stops blocking — not lowering the classification. `ImmutableOwner`, on
nearly every Token-2022 ATA, is `Informational` so the finding stays worth
reading.

---

## NOT A FINDING — investigated and disproven

### An ALT changing between approval and execution

The digest binds the table **address** and the **index**, not the address the
index resolves to, so a message digest alone does not answer this. Solana's own
rules do:

- `ExtendLookupTable` **appends**. No instruction in the Address Lookup Table
  program replaces an address at an index, so an index that resolves today
  resolves identically after any extension.
- Closing requires deactivation first, and the runtime **rejects** a transaction
  referencing a deactivated table — it fails rather than resolving differently.
  Graphite is stricter: it refuses to resolve a table that is merely
  deactivating.
- A table address is a PDA over `(authority, recent_slot)`, and a slot cannot be
  reused, so a closed table cannot be recreated holding different addresses.

Encoded rather than asserted: extending a real mainnet table by 32 entries
leaves every existing index resolving identically; reversing its entries — which
the ALT program cannot do — changes them.

### Per-instruction `isWritable` / `isSigner` not covered by the digest

Surfaced as a failing assertion in this campaign: lowering `isWritable` on one
of two instructions sharing an account did **not** change the digest. The first
reading is a hole; it is the opposite. Solana's privileges are **per-message**,
`@solana/web3.js` unions the metas at compile time, and the lowered flag is
discarded before the bytes exist. An unchanged compiled message is unchanged
execution, and refusing there would refuse a transaction byte-identical to the
approved one. The Core agrees for the same reason: it derives privileges from
the message header, the compiled view.

### `sakAgent.methods.swap` as a bypass

Reachable only with `GRAPHITE_SWAP_ALLOW_UNVERIFIED_EXECUTION=1`, behind a
warning that enumerates what was not observed, and deliberately **without** an
AuditBind call — a check that cannot fail reads as assurance and provides none.
Fail-closed by default and honestly labelled.

---

## Which binding is authoritative

Asked directly in the review, answered without defence-in-depth hand-waving.

| Mechanism | Binds | Size | Role |
|---|---|---|---|
| `scope.transaction_sha256` | the exact artifact bytes: fee payer, blockhash, version, header, every static key, every instruction, the lookup structure | 256 bits | **AUTHORITATIVE.** Checked inside `signApproved`; signing is not reachable without it |
| `AuditBind.transactionBinding` | program, discriminator, raw data, accounts, signer/writable flags, ordering and count | 256 bits | Secondary. Runs earlier and can only add refusals |
| `content_hash` | a projection of ONE instruction | 64 bits | Audit correlation and the AuditBind key. Not transaction identity |

**Can AuditBind become the gate while the digest is bypassed?** No.
`signSubmitAndConfirm` is the only signing path in the bridge; it requires
`scope.kind == "artifact_bound"` and calls `signApproved`, which checks the
256-bit digest before signing. AuditBind runs before it and cannot substitute
for it. Verified by the repository-wide sweep below.

---

## Repository-wide execution-path sweep

Every `sendTransaction`, `sendRawTransaction`, `sendAndConfirmTransaction`,
`signTransaction`, `signAllTransactions`, `partialSign` and `.sign(` in the
repository was enumerated. Results:

| Path | Status |
|---|---|
| `artifact.ts` → `tx.sign` → `sendRawTransaction` | The gate. Digest + signer set checked |
| `sakAgent.methods.swap` | Explicit opt-out only, loud warning, fail-closed default |
| `devnet-test.ts` | Was a bypass (R6-04). Now uses the gate |
| `cli.rs`, `manifest_registry.rs` `.sign(` | Manifest attestation signatures, not transactions |

---

## Evidence

- **1,384 Rust tests** pass (1,394 total, 10 network-ignored).
- **66 TypeScript tests** pass in the SAK integration.
- `cargo clippy --all-targets --all-features -- -D warnings`, `cargo fmt
  --check`, `cargo test --no-default-features --lib` and `--features cli` all
  clean on stable 1.98.1 — the toolchain CI resolves.
- **CI certified:** `f10e4ab`, `3368fc2` and `5c33ea0` completed **success** on GitHub
  Actions. `62e8a6a` shows *cancelled* because the workflow uses
  `cancel-in-progress` concurrency and a later push superseded it; its content is
  contained in `f10e4ab`, which passed.

**Test count is not evidence of security and is not offered as such.**

---

## Verdict

```
Graphite Security Status:       CONDITIONAL
Final Transaction Identity:     PASS
ALT / v0:                       PASS
SAK Execution Boundary:         PASS
Semantic Coverage:              CONDITIONAL
Parser / Wire Safety:           PASS
CI Certification:               CERTIFIED (f10e4ab and 5c33ea0 both green)

P0: none found
P1: R6-05 (fixed), R6-06 (fixed by classification, not by modelling)
P2: R6-01, R6-02, R6-03, R6-04 (all fixed)
P3: none outstanding
```

### The most important question, answered explicitly

> Can an attacker, malicious plugin, compromised caller, buggy integration,
> race, mutation, retry path, ALT change, serialization discrepancy, or
> alternate SAK execution path cause Graphite to APPROVE transaction A and cause
> the wallet/network to execute transaction B?

**No path was found, and here is which invariant prevents each class:**

- **Mutation after approval** — `signApproved` re-serializes the live object and
  requires the approved digest. Twelve structural mutations, two alias
  mutations, and a single-bit sweep are refused.
- **Race between check and sign** — they are one synchronous call; there is no
  API that separates them.
- **Signing altering the message** — the message is read back out of the signed
  bytes by slicing the signature array, not by recompiling the object.
- **Wrong or incomplete signers** — derived from the message and required to
  match.
- **Blockhash refresh** — a refusal with an instruction to rebuild and
  re-verify, not a substitution.
- **ALT reinterpretation** — append-only extension, runtime rejection of
  deactivated tables, non-reusable PDA slots.
- **Alternate execution paths** — one signing path in the bridge; the opt-out is
  explicit and fail-closed.
- **Serialization discrepancy** — the Node and Rust digests of the same artifact
  are asserted equal in CI, and drift fails the build.

**Still true and still stated:** an `artifact_bound` approval is not a claim of
full observation. `unobserved` is non-empty on every verdict by design, and a
consumer's rule is `approved && artifact_bound && the residual list is
acceptable` — not the first two alone.

### Required before production

1. Independent third-party audit. Nothing in this document substitutes for one.
2. Branch protection on `main` — still absent: no required review, no required
   status checks, force and direct pushes enabled. Deferred to the repository
   owner because "direct pushes disabled" conflicts with the standing
   instruction to push this work to `main`.
3. A decision on the Token-2022 tradeoff: fee-bearing mints are now refused. If
   that is too strict for the deployment, the fix is to model `TransferFee`
   properly, not to lower the classification.

### Recommended after production

- A cross-language serialization corpus beyond the single fixture shape
  (legacy, v0, ALT, multi-signer, empty data, unusual orderings).
- Renaming `content_hash` → `instruction_content_id` to make misuse harder.
- Modelling Token-2022 extensions one at a time, each moving from `BLOCKS` to
  `SUPPORTED + VERIFIED`.
