# Transaction Identity Boundary — Campaign Report, 2026-09-11

**Scope of this report.** `main` from `bed23c6` to `d2cd17a` (seven commits,
2026-09-09 to 2026-09-11). It answers one question: *can Graphite return an
executable approval for a transaction whose exact signed artifact contains
security-relevant behaviour Graphite never independently established?*

**Method.** Internal engineering work by Anthropic's Claude acting as this
project's engineering agent. **This is not an independent third-party audit, a
certification, or a penetration test by an external firm, and nothing in it
should be presented as one.** Every defect below was reproduced against running
code before it was changed, and the reproduction is committed as a test.

**Boundaries observed.** No credentials, keys or RPC secrets appear in source,
commits, logs or this report. Mainnet was used read-only (`getTransaction`,
`getMultipleAccounts`, `getSignaturesForAddress`) to capture real transactions
and lookup-table accounts; nothing was signed, sent, or submitted, and no live
user, wallet, protocol or funds were interacted with. Every hostile RPC response
came from a loopback mock. Attack fixtures that had to name an account use test
keys rather than real addresses.

---

## Executive summary

Seven defects were found and fixed. Six of them share one shape: **a
security-relevant property of the transaction was taken from the party
proposing the transaction, while the bytes that settle it were in the same
request.** The seventh (#5) is the same failure one layer out: the integration
never sent those bytes at all.

| # | What was asserted rather than established | Fixed in |
|---|---|---|
| 1 | Which accounts a lookup table resolves to | `f0db495` |
| 2 | Per-account signer/writable flags (`real_account_metas`) | `df3f580` |
| 3 | That the described accounts are the instruction's accounts | `df3f580` |
| 4 | That the transaction's other instructions were described | `0598057` |
| 5 | That the SAK integration verified bytes at all | `d50283f` |
| 6 | Which accounts the transaction reaches that nobody named | `095ba71` |
| 7 | Privileges of accounts arriving through a lookup table | `d2cd17a` |

One CI defect (`f0db495` turned `main` red on a clippy lint new in Rust 1.98)
and four CI supply-chain weaknesses were fixed in `bb36879`.

**The boundary is materially stronger and it is not closed.** §4 and §5 state
what remains, including one class — semantic completeness — that this campaign
did not address and does not claim to have.

---

## 1. What was tested

### 1.1 Against real serialized transactions

The standard applied throughout: *every successful attack must be reproduced
using a valid serialized Solana transaction, not an artificial byte array.*

- **Three real mainnet-beta v0 transactions** with one, three and four address
  lookup tables, captured read-only, together with **eight real lookup-table
  accounts** (7,608–8,248 bytes, 236–256 addresses each) and each transaction's
  `meta.loadedAddresses` — the runtime's own record of what those tables
  resolved to when Solana executed it.
  (`fixtures/artifacts/mainnet_v0_alt.json`, `tests/alt_real_v0.rs`)
- **Real devnet transactions** already in the repository: a System transfer, the
  same transfer with a System `assign` beside it, an amount substitution and its
  honest twin. (`fixtures/artifacts/devnet_transactions.json`)
- **Wire-format attack artifacts**, each produced by re-serializing one of the
  real mainnet transactions with exactly one field changed. The encoder was
  asserted byte-identical on the round trip *before* any mutation, so an attack
  artifact differs from a genuine mainnet transaction in the one named way and
  in no other.
- **The SAK bridge's own output**, serialized by `@solana/web3.js` and asserted
  against by the Rust suite. (`fixtures/artifacts/sak_bridge_artifact.json`)

### 1.2 The ground-truth check

`graphite_resolution_reproduces_the_runtimes_own_resolution` decodes the eight
real tables, applies Graphite's ordering rule, and requires the result to equal
what the chain recorded — same addresses, same order, same writable/readonly
split — for a one-table, a three-table and a four-table transaction. This is the
56-byte header offset and the cross-table ordering checked against Solana rather
than against a reading of the documentation.

### 1.3 Anti-vacuity: the tests were deliberately broken

A passing test proves nothing until it is shown to fail. Two genuine defects
were introduced on purpose and confirmed to be caught:

| Deliberate break | Result |
|---|---|
| Cross-table resolution order reversed | **FAILS** — `mainnet_v0_3_tables` writable set diverges from the chain's |
| `LOOKUP_TABLE_META_SIZE` 56 → 24 | **FAILS** — three tests, including the ground-truth comparison |
| Two resolution loops merged into one | **passes** — correctly: the two forms produce identical vectors |

The third is recorded because it is the honest outcome, not a gap: interleaving
per table still appends writables to the writable vector and readonlies to the
readonly vector in table order.

Every attack test in this campaign is paired with a control that must pass, and
several assert that two artifacts are *distinguishable* rather than that one is
blocked — because "blocked" can be true for unrelated reasons.

---

## 2. What was found, and what it cost before the fix

Each was reproduced before being changed.

### 2.1 ALT-resolved accounts were counted, never identified (`f0db495`)

A v0 transaction reaches accounts that appear nowhere in its static key list.
The pipeline knew how many; it could not say which. If the verified intent is
"user → vault A" and the table resolves to vault B, a check reasoning from
counts cannot tell the difference.

Fixed by keeping the table addresses and indexes the parser was discarding,
fetching the tables, and resolving indexes to addresses Graphite derived. The
load-bearing test substitutes one real mainnet table for another: same indexes,
identical counts, **zero** surviving accounts.

Refusal rather than partial decoding throughout — a missing table, an
out-of-range index, a ragged address array or a deactivating table resolves
NOTHING, because a partial address list mis-attributes every index after the gap
and looks like an answer.

### 2.2 Privileges came from the caller (`df3f580`)

`real_account_metas` is the caller's account of the transaction's header, and
the caller is the party a privilege check exists to constrain. Two artifacts
differing in **one header count** — a manifest-readonly account moved into the
writable section — produced byte-identical verdicts: same layers, same findings,
same 0.44 confidence.

Solana's privileges are entirely positional (three header counts plus key
order), both in the message. They are derived now; the caller's are used only
when nothing can be derived, and where the two disagree the header wins and L1
reports that the caller's description of these bytes is unreliable. Omitting the
metas no longer skips the check.

### 2.3 The described accounts were never checked against the instruction (`df3f580`)

L2 established that the transaction contained an instruction under the described
program carrying the described data. It never established that the instruction's
**accounts** were the accounts the rest of the verdict was about — and every
layer downstream reasons over the described list.

Reversing the two accounts of the real devnet transfer — the opposite-direction
payment, same set, same count, same program, every byte of data identical — was
approved. The comparison is positional now, because Solana passes accounts by
position. Reverse, substitute, drop and pad are four failures where they were
four approvals.

### 2.4 Declared siblings were ignored, making honesty the losing move (`0598057`)

L2 failed any artifact carrying an instruction the request did not describe.
Right rule, wrong source: `transaction_instructions` is where a caller describes
those siblings, and L2 never looked at it. A fully and honestly described
multi-instruction transaction could not pass — which is most of Solana, since a
ComputeBudget limit and price sit in front of nearly every real transaction.

The effect was not merely inconvenience. Supplying the artifact became the
losing move: send nothing, get a Descriptive verdict, keep the approval. A
control people route around protects nobody.

Declarations are now checked against the bytes in **both** directions: every
instruction in the artifact must be described (by program, discriminator prefix
and account list position by position), every declaration must match something
really present, and each declaration is spent once. An empty discriminator
matches nothing.

### 2.5 The SAK integration never sent the bytes (`d50283f`)

The bridge built the exact instructions it was about to execute, simulated them,
and sent Graphite three fields. Every verification through the flagship
integration ran in Descriptive mode while the artifact sat in a local variable
one line away. None of §2.1–§2.4 was reachable from there.

Both paths now serialize what they hold. The swap path uses a separate field so
it does not trigger a second simulation. The artifact is unsigned, with empty
signature slots — the shape Graphite is built for, being a pre-signature gate.

### 2.6 The account universe was a count (`095ba71`)

L4 compared how many accounts the simulator said the transaction touches against
how many the request describes. A request naming one address the transaction
does not contain restored the count while hiding one it does. This was pinned as
a known limit in a test that said closing it would need the artifact parsed.

The universe is read from the message's own static key list now and the finding
names the addresses. The new test makes the counts **agree** — simulator reports
three accounts, request describes three — while the key list holds a fourth the
request never names. A count-based check passes it.

Padding is dead by construction rather than by a rule against it: neither
`account_addresses` nor `transaction_instructions` can carry an address the
transaction does not contain (§2.3, §2.4).

### 2.7 ALT privileges were resolved too late to matter (`d2cd17a`)

§2.2 grounded privileges for accounts in the static key list. An ALT-resolved
account is not in that list; its privilege is which half of the lookup its index
sits in. Graphite resolved that inside the simulation block — after account
resolution had already compared the manifest against the caller's metas. Right
answer, too late to use, for precisely the accounts a v0 transaction can reach
without naming them.

Resolution moved ahead of account resolution. Two v0 artifacts differing only in
which half one index sits in now reach different verdicts.

Encoded as part of this: **a lookup table cannot supply a signer.** Solana
requires every signature to be over a static key, so an account appearing only
through a table is never one — evidence, not an absence of it.

### 2.8 CI (`bb36879`, and the clippy fix in `df3f580`)

- `main` was **red** at `f0db495`: clippy 1.98 rejects `chunks_exact` with a
  constant size. Reproduced by matching the local toolchain to CI's `stable`
  rather than guessing, then fixed.
- `npm ci || npm install` — the fallback silently downgrades to unpinned
  resolution exactly on the run where something is already wrong.
- `npx tsc` / `npx tsx` — job-time fetches inside the build of the component
  that is meant to be the trustworthy part of the stack. Both are already pinned
  devDependencies.
- The dashboard installed without its lockfile; `pip install pytest` took
  whatever was newest.
- CI named two of the three SAK test files by hand, so
  `toctou-signing-boundary.test.ts` sat in the repository looking like a gate
  without ever running in one.

---

## 3. Evidence

- **1,353 Rust tests pass**; `clippy --all-targets --all-features -D warnings`,
  `cargo fmt --check` and `cargo check --no-default-features` clean on stable
  1.98.1 — the same toolchain CI resolves.
- **33 TypeScript tests pass** in the SAK integration: 8 are new here, and
  another 10 (`toctou-signing-boundary.test.ts`) existed in the repository but
  had never run in CI before `bb36879`, because the workflow listed two of the
  three test files by hand.
- **CI verified green on GitHub** for `bb36879`, `d50283f`, `095ba71` and
  `d2cd17a` (all seven jobs each). `0598057` was superseded before completing
  and its content is contained in `d50283f`. `f0db495` is recorded as FAILED —
  see §2.8; it is the run that surfaced the clippy defect.
- Cross-language drift is now a CI failure: `emit-artifact-fixture.ts`
  regenerates the fixture the Rust suite asserts against, and any diff fails the
  job. Two implementations of one agreement drift silently otherwise, and the
  symptom of that drift is every transaction through the bridge being blocked.

**Test count is not evidence of security and is not offered as such.** It is
offered as evidence that the specific reproductions described above run.

---

## 4. What was NOT tested

- **Semantic completeness.** Graphite can now see every top-level instruction,
  every account identity, and every privilege. It still does not model what each
  instruction **does** beyond the manifests it holds. Identity is not semantics.
  This campaign did not address it and does not claim to have.
- **Inner instructions.** Only top-level instructions appear in a message.
  Anything a program invokes by CPI is visible through simulation effects, not
  through the artifact.
- **A real on-chain ALT under live mutation.** The mainnet tables were captured
  as a snapshot so the tests need no network. A table extended or closed between
  verification and execution was not exercised against a live cluster.
- **Signature validity.** Graphite is a pre-signature gate and never verifies a
  signature. Nothing here changes that, and no test asserts anything about one.
- **Sustained load, multi-tenant isolation, and long-running memory behaviour**
  were outside this campaign's question.

---

## 5. What remains outside the guarantee

Stated as limits a deployer must know, not as defects.

1. **Semantic completeness** (§4). The largest remaining gap in the boundary.
2. **`cpi_targets` are caller-declared and unverifiable from a message.** CPIs
   are not in the wire format. Under-declaring them avoids CPI-based risk rules;
   the scope says inner instructions are visible only through simulation.
3. **Table-resolved privileges depend on an RPC round trip.** A privilege read
   out of the header is established from the bytes alone; one read out of a
   table required a fetch to succeed. L1 distinguishes the two so a reader can
   weigh the check. When the table is unreachable the flags are reported as
   neither supplied nor derivable and the escalation is **not checked** — no
   block, and no pretence of one.
4. **`content_hash` is 64 bits** and is an audit-correlation identifier, not a
   security identity. `transaction_sha256` is the full-length execution binding.
5. **87.3% of protocol account slots are accepted in the position the caller
   supplied them**, because no manifest declares PDA seeds or a fixed address
   for them. That figure is from the 2026-09-08 production-readiness audit and
   was not re-measured here; nothing in this campaign changes it, and it is
   reported per verification in the L1 layer report. Note what it does and does
   not mean now: the account in a slot is still accepted by position, but it is
   no longer accepted without being IDENTIFIED — L2 requires it to be the
   instruction's own account at that position (§2.3), and its privileges are
   read from the transaction (§2.2, §2.7).
6. **A cooperative RPC can contribute to an approval**, by design: earned
   simulation evidence is part of the confidence score. A lying RPC still cannot
   overturn a deterministic finding.
7. **`main` has no branch protection** — no required review, no required status
   checks, force pushes and direct pushes enabled. Hardening CI matters less
   than it looks while a red run can be pushed past. This is deliberately **not**
   changed here: "direct pushes disabled" conflicts with the standing
   instruction to push this work to `main`, so it is the repository owner's call.

---

## 6. One incident worth recording

During §2.6 an edit appeared in the working tree that wrapped the new account-
identity computation in `None.or_else(…)` and shadowed it on the next line with
`let undescribed: Option<Vec<String>> = None;`. The computed value was discarded
and the pipeline silently fell back to the count comparison. It compiled, and
1,347 of 1,348 tests still passed.

What caught it was clippy reporting the real binding as unused, plus the single
test that asserts the check's **output** rather than the verdict.

The lesson generalises beyond its cause: *a security check that is computed and
then thrown away is indistinguishable from one that works*, unless something
asserts what the check produced. Tests that assert only on `approved` cannot see
this class of regression at all.
