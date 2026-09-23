# Round 14 — the prefix and the pin

> **Historical record.** This report describes the codebase at commit
> `eaee998` on 2026-09-20, and the fixes made on top of it. For the current
> state of Graphite see [`CURRENT.md`](CURRENT.md).

**Date:** 2026-09-20
**Trigger:** a forensic re-audit of the working tree, commissioned as an
adversarial review of Round 13 rather than a continuation of it.
**Audited state:** commit `eaee998` plus the uncommitted Round 13 change.

---

## Verdict in one paragraph

Round 13 re-keyed the Risk Engine on the instruction's own bytes and left every
other manifest lookup keyed on the caller's label. That split was the whole
finding. `manifest::discriminator_matches` is `input.starts_with(selector)`, so
a label SHORTER than a manifest selector misses it — and a short label is not a
contradiction, because it really is a prefix of the data, so Round 13's new
self-consistency check passes it and says so. The half still keyed on the label
was the half that checks account identity. Declaring `e517cb97` instead of
`e517cb977ae3ad2a` did not merely lower confidence: it switched off PDA
re-derivation, the fixed-address comparison and the privilege comparison
together, and a manifest-pinned account slot could then hold anything. Measured
against a running server, one artifact, one described account list, only the
declared label differing: an attacker-controlled program in Jupiter V6 `route`'s
account 0 — the slot the manifest pins to the two token programs — went from
`Blocked / AccountIdentityMismatch` to **`approved: true`, `risk: Clear`,
`scope: artifact_bound`, residuals `[program_semantics, inner_instructions]`**.
That last verdict carries only the two inherent residuals, so the reference
bridge's DEFAULT residual policy accepts it and `executeBoundTransaction` signs
it. Five defects, one root cause; all five are closed and each is pinned by a
test that fails when its control is removed.

---

## What was found

| ID | Severity | What | How it was found |
|---|---|---|---|
| **GFX-101** | HIGH | A truthful PREFIX of the discriminator suppresses PDA, fixed-address and privilege checks together | Reproduced end-to-end against the release binary |
| **GFX-102** | MEDIUM | The same miss replaces the manifest's declared effects with an uninterpretable string, downgrading L4 Criticals to Warnings, and widens `allowed_cpis` to the protocol-wide union | Code, then confirmed by verdict comparison |
| **GFX-106** | HIGH | Declared SIBLINGS were judged under the caller's label; a real System `Assign` declared `01`, or a real SPL `SetAuthority` declared `0`, drew Clear | Reproduced end-to-end |
| **GFX-107** | MEDIUM | A declared sibling's lookup-table positions were WILDCARDS — the primary resolves ALT accounts before comparing, siblings did not | Code, then reproduced by test with a mock RPC |
| **GFX-108** | HIGH | The first cut of the GFX-101 fix inherited the Risk Engine's `!is_empty()` gate, so an EMPTY discriminator kept the whole bypass | Found by probing my own fix |

GFX-108 is listed because it is the more useful half of the story: the fix was
written, the tests passed, and the bypass was still there under a different
spelling. It was caught by re-running the attack against the fixed binary rather
than by trusting the green suite.

---

## GFX-101 — a truthful prefix disables every manifest-grounded check

### What the code did

```rust
// Round 13, correct as far as it went:
let risk_discriminator = match input.instruction_data.as_deref() { … };   // BYTES

// …and, 400 lines earlier, untouched:
let resolution = resolve_accounts(&AccountResolutionInput {
    instruction_discriminator: input.instruction_discriminator.clone(),   // LABEL
    …
```

`resolve_accounts` looks the manifest instruction up by that label. On a miss it
returns `InstructionNotFound`, and the P12 arm inside `verify_async` synthesises
generic accounts:

```rust
identity: AccountIdentity::Unverified,
expected_address_mismatch: false,
pda_mismatch: false,
privilege_mismatch: false,
```

`identity_mismatches` filters on exactly those three booleans, so it is empty by
construction and `MaliciousAccountChange` never fires. L2 meanwhile returns
**Passed** — the "unknown instruction on a known protocol" P12 soft pass — and
L7's risk context resolves from the bytes, so neither of them objects either.

### Reproduction

Jupiter V6 `route`. Identical artifact, identical described accounts; only the
declared discriminator differs.

| declared | `instruction_name` | risk | approved | confidence | scope | residuals |
|---|---|---|---|---|---|---|
| `e517cb977ae3ad2a` | `route` | Blocked `AccountIdentityMismatch` | false | 0.64 | artifact_bound | — |
| `e517cb97` | `unknown_instruction` | **Clear** | **true** | 0.64 | artifact_bound | inherent only |

Confirmed independently on Raydium CPMM `close_permission_pda`, which pins both
a PDA slot and the System program: full label → 1 identity finding, four-byte
prefix → 0.

**Blast radius:** 312 of 803 shipped manifest instructions, across 13 of 33
manifests — Drift, Jupiter ×3, Kamino, Marinade, Meteora, OpenBook, Orca,
Raydium ×2, Squads, Switchboard — have both a discriminator long enough to
truncate and at least one pinned account slot.

**Preconditions.** A declared intent outside `{swap, bridge, withdraw, delegate,
mint}` (those make L5 `Failed` on an unknown instruction, which is a hard gate),
and a confidence clearing the profile threshold — 0.44 on a fresh core, 0.64
once the program's simulation baseline has warmed, against Gaming's 0.55. Both
states were measured.

### What changed

One value, computed before account resolution, used by every manifest lookup:

```rust
let effective_discriminator = match input.instruction_data.as_deref() {
    Some(data) if !data.is_empty() => hex::encode(&data[..data.len().min(8)]),
    _ => input.instruction_discriminator.clone(),
};
```

It now keys `resolve_accounts`, `verify_instruction`'s manifest lookup, the
`expected_state_changes` / `allowed_cpis` lookup, the plugin protocol-rules
lookup, the plugin context, and the primary's entry in the effective-instruction
list.

**Why this cannot refuse anything it did not refuse before.** L2's contradiction
check has already established that the label is a prefix of the data. Every
selector the label matched is therefore also a prefix of these bytes, so the
lookup can only become MORE specific — never less. And because manifest
discriminator ambiguity is rejected at load on both the seed and community
paths, at most one entry can match a given input, so "more specific" means
"exactly right" rather than "a different arbitrary entry".

The CONTRADICTION check deliberately keeps using the label. Comparing the label
against the bytes is its entire purpose.

---

## GFX-108 — the same bypass, spelled `""`

The first cut of the fix inherited Round 13's `!input.instruction_discriminator
.is_empty()` guard. `discriminator_matches` refuses an empty input, so the
lookup missed and the P12 arm suppressed the identity checks exactly as before.
Measured on that build: `e517cb97` → Blocked, `""` → Clear.

The guard exists for a real reason on the RISK path — Check 2 refuses a request
that named no instruction on a known-risky program, and deriving a discriminator
for it would turn "refused because you did not say" into "allowed because we
worked it out". So the two values were split:

```rust
// Manifest lookups: always the bytes.
let effective_discriminator = …;

// The Risk Engine: the same bytes, except that an EMPTY label stays empty.
let risk_discriminator = if input.instruction_discriminator.is_empty() {
    String::new()
} else {
    effective_discriminator.clone()
};
```

An empty label is a request that declined to say what it is calling. That is a
reason to judge its risk conservatively; it is not a reason to stop checking
whether its accounts are the accounts the protocol requires. Verified both ways:
an empty label on SPL Token is still Blocked, and an empty label on Jupiter now
produces the identity finding.

---

## GFX-106 — the sibling twin

`assess_secondary_instructions` fed `ix.instruction_discriminator` — a
caller-written label for a declared sibling — straight into the Risk Engine.
`declaration_describes` only requires that label to be a hex-STRING prefix of
the sibling's real data, and the known-risky table matches
`input.starts_with(selector)`, so a prefix shorter than the selector missed it.
`tx_pattern_analysis::disc_matches` is the same relation, so the AAT correlation
rules (Approve+Transfer, SetAuthority+Transfer, CloseAccount+Transfer) were
evaded by the same move.

Measured, on an artifact carrying a real dangerous sibling beside an honest
transfer:

| sibling | declared honestly | declared short |
|---|---|---|
| System `Assign` `01000000` | Blocked `AuthorityHijack` | `01` → **Clear**; `0100` → **Clear** |
| SPL `SetAuthority` `06` | Blocked `AuthorityHijack` | `0` → **Clear** |

A single hex nibble was enough, because the comparison is on the hex string
rather than on bytes — so even a one-byte selector was evadable.

### What changed

`sibling_coverage` now records which artifact instruction each declaration
matched, and `siblings_keyed_on_their_bytes` rewrites each matched declaration's
discriminator to that instruction's own leading bytes before the Risk Engine
sees it. A declaration that matched NOTHING is left exactly as written — L2 has
already failed the verification in that case, and rewriting it would be
inventing evidence. So is a declaration whose instruction carries no data, which
keeps `assess_secondary_instructions`' empty-discriminator fail-closed arm
reachable.

The same safety argument applies: the declaration's discriminator is already
required to be a prefix of that instruction's data.

---

## GFX-107 — a sibling's lookup-table accounts were wildcards

The PRIMARY instruction's account comparison resolves address-lookup-table
positions before comparing. A declared SIBLING's did not: `declaration_describes`
compared against `ArtifactInstruction::accounts`, the UNRESOLVED
`Vec<Option<String>>`, and `compare_instruction_accounts` reads an unresolved
position as neither a match nor a mismatch.

So every lookup position in a sibling accepted any address the caller cared to
write. That is worse than a weak comparison: declared accounts widen the set
`ArtifactAccountsNotDescribed` treats as named, so a fabricated address at a
lookup position could mask a real account from a Critical finding — the padding
`SiblingCoverage`'s own doc comment says is closed, still open at exactly the
positions a v0 transaction reaches without naming them.

`sibling_coverage` now takes the resolved lookups and compares siblings the same
way the primary is compared, falling back to the unresolved list when the tables
did not come back — which is the pre-existing behaviour and is disclosed by the
`lookup_tables_unresolved` residual rather than papered over.

This one was found by reading and was NOT reproduced against a server; it is
reproduced by `tests/sibling_lookup_accounts.rs`, which stands up a loopback
mock serving one lookup table.

---

## A label too short to identify anything (the descriptive half)

`disc_matches` fires when the input is at least as long as the selector. The
gap is the other direction: a declared discriminator that is a strict PREFIX of
a risky selector could be that instruction and could be something else, and
nothing downstream ever decides which. `03` (Transfer) and `06` (SetAuthority)
are both SPL Token instructions and both begin with `0`.

An artifact-bound request never reaches this — the discriminator is re-derived
from the instruction's own bytes, so it is never shorter than a selector. A
DESCRIPTIVE request has no bytes to re-derive from. Check 2 now refuses a
declaration that is a strict prefix of one of its program's risky selectors, for
the same reason its empty arm refuses: a declaration too short to identify the
instruction is not a declaration.

A complete selector is unaffected — `03` is not a prefix of `06`, `09` or `04`
— and the rule only reaches the three programs in `RISKY_PATTERNS`.

---

## Deliberate-break log

Each control removed in turn, the suite run, the file restored from a
byte-for-byte backup and the restore verified by SHA-256.

| # | Control removed | Caught | Which tests failed |
|---|---|---|---|
| B9 | the manifest lookup keyed on the bytes | **yes** | 5 — both truncated-label identity tests, the empty-label one, the same-manifest-entry one, the disclosure |
| B10 | siblings re-keyed on the artifact's bytes | **yes** | 1 — `a_truncated_high_risk_class_sibling_is_still_blocked` |
| B11 | the empty label resolving the instruction | **yes** | 1 — `an_empty_discriminator_does_not_hide_a_substituted_pinned_account` |
| B12 | siblings compared on resolved lookup accounts | **yes** | 1 — `a_sibling_that_misnames_its_lookup_account_is_refused` |
| B13 | the ambiguous-prefix rule | **yes** | 2 — the descriptive primary and the descriptive sibling |
| B14 | the unresolved-tables disclosure | **yes** | 1 — `a_fabricated_lookup_account_cannot_be_approved_when_the_table_never_resolves` |

Each break fails exactly the tests that exist for it and no others, which is
what makes the mapping between control and test legible rather than incidental.

**The first run of this campaign caught only 3 of 5**, and that is the most
useful thing in this report. B10 and B12 were MISSED — meaning two of the new
tests were vacuous:

- **B10** passed because the sibling tests were being caught by the *ambiguity
  rule* rather than by the re-keying. The re-keying's unique contribution is
  `manifest_risk_class` on programs that are NOT in `RISKY_PATTERNS`, where
  Check 10b is the only thing that blocks a high-risk sibling. A new test
  targets exactly that: a Raydium CPMM `close_permission_pda` sibling
  (`risk_class: "close"`) declared with half its discriminator.
- **B12** passed because GFX-107 had never been reproduced at all — the fix was
  written from code reading and nothing exercised it. `tests/sibling_lookup_accounts.rs`
  now does, with a mock RPC.

Both tests were added and the campaign re-run: **5 of 5 caught.**

**B14 was added afterwards, as a guard on this round's own fix.** GFX-107
made a sibling's account comparison depend on the lookup tables RESOLVING.
When they do not, `instruction_accounts_for_comparison` falls back to the
unresolved list and every lookup position is a wildcard again — GFX-107's
exact precondition, reachable through the RPC rather than through the
comparison. That fallback is intended, and is meant to be disclosed by the
`lookup_tables_unresolved` residual; nothing tested that it actually was.
The new test pins the property the disclosure exists to protect: a
fabricated address at an unresolvable lookup position cannot reach an
approved, artifact-bound verdict carrying only inherent residuals — the
shape a default `ResidualPolicy` signs. Removing the disclosure fails it
and nothing else. **6 of 6 caught.**

---

## What the CI mirror caught in this round's own work

Twice, and both times in the new material rather than in the engine:

1. **rustfmt drift in the untracked `mainnet_conformance.rs`** (Round 13's, not
   this round's). `cargo fmt --all -- --check` fails on it, so CI would have
   gone red on the tree as it stood before this round touched anything.
2. **`tests/sibling_lookup_accounts.rs` was missing `#![cfg(feature = "rpc")]`.**
   The file uses `rpc_client` and `attach_rpc_client`, neither of which exists
   without the `rpc` feature, and `cli` does not pull it
   (`cli = ["dep:clap", "dep:tokio"]`). Every one of the other fifteen RPC tests
   carries that gate; this one did not, so
   `cargo test --release --no-default-features --features cli` failed to compile
   with `E0432`/`E0599`. The local `cargo test` that "proved" the fix ran under
   default features, where `server` pulls `rpc` in — so a green local suite said
   nothing about the job that would actually break.

The second is the more useful lesson, and it is the same one as GFX-108: a
green run of the suite you happened to invoke is not evidence about the runs you
did not. Both are fixed.

---

## What was run

| Suite | Result |
|---|---|
| `cargo fmt --all -- --check` | clean (also fixed pre-existing drift in the untracked `mainnet_conformance.rs`, which would have failed CI as it stood) |
| `cargo clippy --all-targets --all-features -- -D warnings` | clean |
| `tests/truncated_discriminator.rs` (new) | 22 passed |
| `tests/sibling_lookup_accounts.rs` (new) | 3 passed |
| `tests/mislabelled_discriminator.rs` (Round 13) | 16 passed |
| `tests/described_siblings.rs`, `secondary_instruction_risk.rs`, `redteam_gate_bypass.rs` | 26 passed |
| Deliberate breaks | 6 of 6 caught |
| Live re-run of all five attack probes against the fixed binary | every one now refused |
| `cargo test --release --no-fail-fast` (full) | **1534 passed, 0 failed, 12 ignored** across 83 binaries |
| `cargo test --release --no-default-features --features cli` | passed (after the missing `rpc` gate was added) |
| CI mirror, 22 jobs | 22 green |
| Mainnet regression, 10,669 real transactions | **verdict file byte-identical to the Round 13 baseline** |

### The mainnet regression, stated precisely

`verdicts_r14.tsv` hashes to `fe89e0f5824c9c869ccc5b9fabe0ec7fd51bc5159ba3f7d536fae3603ea960c9`,
which is the same SHA-256 as the Round 13 baseline. Not one verdict moved.

What that does and does not establish. Of 10,669 sampled transactions: 875 are
version 1 and refused by design, 10 carry no usable instruction, and 9,784
verified — all of them artifact-bound, 0 parse failures, 0 `Err` returns. But
**9,053 of the 9,784 (92.5%) have no manifest for their primary program**, so
they never reach the lookup this round tightened. The tightened path is
exercised by the remaining **731**. Zero verdict changes across those 731 is
real evidence and not a large sample; it is enough to say this round introduced
no *observed* false positive on live traffic, and not enough to say it cannot.

The sample's own shape is worth keeping in view: 5,344 of the transactions are
Vote instructions, and the risk verdicts are dominated by the drainer heuristic
(2,569) and the known-risky discriminator table (949). Of the blocked cases,
**1,087 were blocked on a SIBLING rather than on the primary instruction** — the
surface GFX-106 and GFX-107 are about.

### A flaky assertion, reported rather than fixed

`server::tests::rate_limiter_at_its_bound_stays_cheap_per_check` asserts a
wall-clock bound (5 µs/check at capacity). It failed once at 5.135 µs — 2.7%
over — while the machine was running concurrent release builds at 98% disk, and
passed 3/3 re-runs once idle, plus again in the full suite. Nothing in this
round touches the rate limiter.

It is left exactly as it is. Loosening a bound so a run goes green is how a
performance guarantee quietly stops being one, and this test is not this round's
to relax. Recorded here as a CI-robustness decision for whoever owns that
suite: a wall-clock assertion on a shared runner will flake.

---


---

## What this round does NOT change

- **The confidence accumulator.** An identical request is judged differently
  after its program's simulation baseline has warmed (0.44 → 0.64, across
  Gaming's 0.55). That is documented in `SECURITY.md` and bounded by
  `tests/rpc_influence_bounds.rs`, and the re-audit confirmed both. It is
  recorded here only because it is what lifted GFX-101's verdict from refused to
  approved.
- **`content_hash`.** Still computed over the DECLARED discriminator, which is
  what keeps the Rust, TypeScript and Go projections byte-identical. L8
  attribution joins on the chain's bytes, not on the label.
- **The `transaction_builder` hex check.** Still applied to the caller's label,
  and still the reason an odd-length or non-hex discriminator never reaches a
  verdict.
- **Descriptive verdicts** remain refused at the execution boundary by the
  bridge's residual policy. The descriptive-mode hardening above matters for
  callers that gate on `approved` alone.
