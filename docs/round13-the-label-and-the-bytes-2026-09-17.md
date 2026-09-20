# Round 13 — The label and the bytes

> **Historical record.** This report describes the codebase at commit
> `eaee998` on 2026-09-17, and the fixes made on top of it. For the current
> state of Graphite see [`CURRENT.md`](CURRENT.md).

**Scope.** A full forensic audit of `main` at `eaee998` produced three
findings: one HIGH, one MEDIUM, one INFO. This round closes all three. Both
HIGH and MEDIUM were reproduced against running code before anything was
changed, each fix is pinned by a test, and each test was checked by reverting
its fix and confirming the test fails. This is internal engineering work by
the project's own agent; nothing here is an independent certification.

**Standing constraints, all kept.** No credentials in source, commits, logs or
output; no attack on any public RPC; nothing touched a live wallet, protocol
or fund.

---

## Verdict in one paragraph

Graphite's risk gate was keyed on a string the caller wrote rather than on the
instruction the caller supplied. `RiskAssessmentInput.instruction_discriminator`
was the request's `instruction_discriminator` field, and the one comparison
that would have caught a label contradicting its own `instruction_data` sat
*below* the manifest lookup in L2 — so it ran only on a manifest hit, and a
discriminator matching no manifest entry returned a P12 soft pass before the
comparison was reached. Declaring `ff` over a real SPL-Token `SetAuthority`
therefore produced `approved: true`, `risk: Clear`, `scope: artifact_bound`,
where declaring `06` over the identical bytes produced `Blocked
[AuthorityHijack]`. Auditing the fix surfaced a second, narrower variant the
contradiction check cannot reach at all: a label that is **true but short**.
System `Assign` is `01000000`, and `"01".starts_with("01000000")` is false, so
one byte of honesty bought the same silence the lie did. Both are closed, by
two independent mechanisms: the self-consistency comparison now runs first, for
every protocol, manifested or not; and the Risk Engine is handed the
instruction's own leading bytes instead of the label. Separately, L4's state
diff was blind to the SPL `owner` field — the token account's *authority*, as
distinct from its owning *program*, which `owner_change` already watched — so
a simulated hand-over of an account produced `findings: []`. Three authority
fields are now watched. The `AuditBind` bridge, which was shielded from the
Core-side bypass only by accident, now refuses a mismatched declaration by
rule.

---

## GFX-001 — the Risk Engine judged the label, not the instruction

**Severity: HIGH. Class: security vulnerability (gate bypass). Confirmed by
reproduction.**

### What the code did

`verify_instruction` (L2) looked the declared discriminator up in the
manifest, and on a miss returned:

```rust
None => {
    // P12: Unknown instruction on known protocol = soft pass (fail open).
    return PipelineLayerResult::new(layer_name, LayerStatus::Passed, ...);
}
```

Only *after* that arm did the function compare `instruction_data` against the
declared discriminator. A discriminator the manifest does not know never
reached the comparison. Meanwhile `verify_async` built the risk input from
the same unverified string:

```rust
instruction_discriminator: input.instruction_discriminator.clone(),
```

and the manifest lookup that supplies `manifest_risk_class` used it too, so on
a miss that field was `String::new()` and Check 10 — the fail-closed gate for
a high-risk manifest class — could not back the table up either.

### Reproduction, before the fix

Identical artifact bytes, identical `instruction_data`, `WalletProfile::Gaming`,
varying only the declared discriminator:

| Instruction actually present | Declared | Verdict |
|---|---|---|
| SPL Token `SetAuthority` (`06 …`) | `06` | `approved=false`, Blocked `[AuthorityHijack]`, confidence 0.270 |
| SPL Token `SetAuthority` (`06 …`) | `ff` | **`approved=true`**, `Clear`, confidence 0.640, `scope=artifact_bound` |
| SPL Token `SetAuthority` (`06 …`) | `10` | **`approved=true`**, `Clear`, confidence 0.640 |
| SPL Token `CloseAccount` (`09`) | `09` → `ff` | Blocked `[Drainer]` → **approved**, 0.640 |
| System `Assign` (`01000000 …`) | `01000000` → `ffffffff` | Blocked `[AuthorityHijack]` → **approved**, 0.640 |

The ceiling of 0.640 is what kept this at HIGH rather than CRITICAL: TradingBot
(0.80), Treasury (0.95) and Enterprise (0.99) reject on the threshold. Gaming
(0.55) does not, nor does the SAK bridge's shipped `Custom` default, and the
server clamps a caller-supplied `Custom` only to the weakest *built-in*
profile, which is Gaming's 0.55. The bridge's swap path was shielded — but
incidentally: `executeSwap` calls `AuditBind.verifyInstruction` without a
discriminator, so the projection is rebuilt from the data bytes and the
recomputed `content_hash` diverges from the one Graphite returned (which
hashed `ff`), aborting before signing. Nothing made that a rule. The Go SDK,
the TypeScript SDK, the Python layer and any direct HTTP caller had no such
shield.

This is the **primary**-instruction, non-empty variant of the class
`SECURITY.md` records as closed for caller-**declared secondary**
instructions in the 2026-09-05 red-team pass. That fix keyed on the
discriminator being *empty*; this one keys on it being *wrong*.

### The second variant, found while fixing the first

A label that is **true but short** contradicts nothing. System `Assign` is
`01000000`; a request declaring `01` over `01 00 00 00 …` has told the truth
as far as it goes, so the self-consistency comparison has nothing to catch —
and `disc_matches("01000000", "01")` is `"01".starts_with("01000000")`, which
is false. The known-risky table does not fire, the manifest lookup misses, and
`manifest_risk_class` is empty. One byte of honesty bought the same silence.

The contradiction check cannot close this. Only keying the engine on the bytes
can, which is why both halves of the fix are present rather than either alone.

### What changed

1. **`verification.rs`, `verify_instruction`.** The `instruction_data` /
   discriminator comparison is hoisted to the top of L2, above the manifest
   presence check and above the manifest lookup, in a named helper
   (`declared_discriminator_contradicts_data`). It now runs for every request
   that supplies both fields, on every program, manifested or not. Data
   *shorter* than the declared discriminator is a contradiction too — the old
   guard was `data.len() >= disc_bytes.len()`, which silently skipped exactly
   the padding move the Risk Engine's own `disc_matches` comment warns about,
   read from the other side. A genuine L2 `Failed` is already an unconditional
   hard gate (`structural_layer_failed`), so this is not a confidence penalty
   a trust tier can absorb.

2. **`verification.rs`, Step 3.** The Risk Engine and the manifest risk-context
   lookup are keyed on `risk_discriminator` — the hex of the instruction's own
   first eight bytes (the longest discriminator any shipped manifest declares;
   every consumer prefix-matches). Where an artifact was supplied those bytes
   are not a claim: `correspond` located the described instruction by exact
   data equality, so they are known to be in the message about to be signed.
   An **empty** declared discriminator is left exactly as it is, so Check 2's
   fail-closed arm still sees a request that named no instruction at all.

3. **`integrations/solana-agent-kit/auditbind.ts`.**
   `projectionFromInstruction` now refuses an explicit `discriminator` that is
   not a prefix of the data it claims to describe, instead of building the
   projection around the label. The swap path's protection stops being
   incidental.

### What did NOT need to change, and why

A discriminator that is not hex at all — `"setauthority"`, `"zzzz"`, `"06 "` —
never reaches a verdict: `transaction_builder` refuses it with
`InvalidDiscriminator` and `verify` returns `Err`. That predates this round and
is why the bypass needed a hex label. It is now pinned by test
(`a_discriminator_that_is_not_hex_never_reaches_a_verdict`) so that relaxing it
would be a deliberate act rather than an accident.

### Pinned by

`graphite-core/tests/mislabelled_discriminator.rs`, 16 tests: three honest
controls that must block for the **named** pattern (`AuthorityHijack`,
`Drainer`, `AuthorityHijack`), the non-hex refusal, five contradiction cases
(SetAuthority / CloseAccount / Assign under an unknown label, a manifested but
wrong label, an unmanifested program, a declaration longer than its data, and
descriptive mode without an artifact), the truncation case, and three
anti-vacuity controls — an ordinary SPL transfer and a System transfer must
still clear L2 and the Risk Engine and still resolve to `Transfer` by name.

---

## GFX-002 — L4 could not see a token account change hands

**Severity: MEDIUM. Class: trust-boundary limitation. Confirmed by
reproduction.**

### What the code did

`AccountDelta` exposed `owner_change`, `token_delta`, `supply_delta`,
`delegate_granted`, `close_authority_granted` and `was_frozen`. `owner_change`
compares `AccountSnapshot.owner` — the **owning program**. Nothing compared
`TokenAccountView.owner` — the SPL **authority**, who may move the balance.
Two different facts share a word, and only one of them was being watched.

`SetAuthority(AccountOwner)` leaves the Token program exactly where it was. It
moves no lamports, grants no delegate, sets no close authority, freezes
nothing and changes no supply. A diff whose only change was the token account's
owner `ALICE → MALLORY` returned `findings: []`, `blocked: false`, under both
generic and transfer prose. The same blindness covered `MintView.mint_authority`
and `MintView.freeze_authority`.

In the ordinary path an honest `SetAuthority` is blocked at L7 by its
discriminator, which is what kept this at MEDIUM. Combined with GFX-001,
neither layer saw the takeover even with an RPC attached.

### What changed

`state_diff.rs` gains `token_authority_change`, `mint_authority_change` and
`freeze_authority_change`, and three Critical findings:
`UndeclaredTokenAuthorityChange`, `UndeclaredMintAuthorityChange`,
`UndeclaredFreezeAuthorityChange`. Each is excused by a manifest that declares
an authority change (the freeze authority also by a declared freeze). The mint
authorities are compared as `Option`s, because absence is a real value on
chain: a revoked authority and a newly acquired one are both changes, and
requiring a key on both sides would report neither.

Initialization is not reported: `decode_token_account` refuses state 0, so a
pre-allocated account being initialized has no "before" authority to have
changed. That is a creation, and the creation checks own it.

### Pinned by

Seven tests in `state_diff::tests`: the hand-over is Critical; the same
hand-over under declared-authority prose is not a finding; an ordinary
balance-only transfer is not an authority change; initializing an account is
not an authority change; a mint authority change is Critical; a freeze
authority appearing from nothing is Critical; and a mint whose supply moves
while its authorities do not produces no authority finding.

---

## GFX-003 — no negative test covered a mislabelled risky instruction

**Severity: INFO. Class: test/assurance gap. Closed.**

No test supplied an artifact containing a real `06` / `09` / `04` /
`01000000` while declaring a non-matching discriminator. The nearest existing
case (`layers_test.rs`) used `deadbeef` with `instruction_data: None` and no
artifact — the benign shape, which cannot reach the contradiction at all. That
absence is why GFX-001 survived twelve hardening rounds. The 16 tests listed
above are the closure.

---

## Deliberate-break log

Each fix reverted one at a time, its test run, the file restored from a
byte-for-byte copy. A test that still passes with its fix removed is not
pinning anything.

| Break | Test | Result |
|---|---|---|
| L2's comparison moved back below the manifest lookup, where a manifest miss returns first | `a_set_authority_declared_as_an_unknown_discriminator_is_refused` | **FAILED as required** (`mislabelled_discriminator.rs:363`) |
| `RiskAssessmentInput.instruction_discriminator` and the manifest lookup handed `input.instruction_discriminator` again | `a_truthful_but_truncated_discriminator_does_not_hide_the_instruction` | **FAILED as required** (`mislabelled_discriminator.rs:513`) |
| The `token_authority_change` finding removed | `state_diff::tests::a_token_account_changing_hands_is_critical` | **FAILED as required** (`state_diff.rs:1827`) |

Note that break 1 and break 2 fail *different* tests: neither half of the
GFX-001 fix covers the other's case, which is why both are present.

---

## Against real mainnet traffic

Every corpus in this repository before this round was written by somebody who
already knew what the engine does. That is a blind spot with a specific shape:
**a check that wrongly refuses honest input passes every test written by the
person who wrote the check.** Round 13 made L2 stricter, so the question is not
whether the check catches the attack — `mislabelled_discriminator.rs` answers
that — but whether it refuses transactions that are fine, and the only corpus
large and varied enough to answer is the chain.

`tools/mainnet-sample/fetch_mainnet.py` pulls whole finalized mainnet blocks,
read-only, one request at a time, stopping rather than retrying on a 429.
`tests/mainnet_conformance.rs` runs every transaction in them through the full
pipeline in **artifact-bound** mode: the real serialized bytes, the real
instruction data, the accounts resolved against the block's own
`loadedAddresses`, every sibling declared, the discriminator derived from the
instruction's own leading bytes exactly as `AuditBind` and the Go SDK derive it.

**Sample:** 10,669 transactions, 8 finalized blocks, slots 447885495–447888295,
189 distinct programs. Nothing was submitted, no wallet, key, fund or live
protocol was touched, and no credential exists anywhere in the path.

| | |
|---|---|
| Parse failures | **0 of 9,794** |
| Reached a verdict, all artifact-bound | 9,784 |
| **L2 refusals for a discriminator contradiction** | **0** |
| **Known-risky-table blocks confirmed against the named instruction's real bytes** | **1,087 of 1,087** |
| …of those, the risky instruction was the primary | 0 |
| …a sibling | 1,087 |
| L2 passed | 9,378 (95.9%) |
| L2 failed — durable nonce refused (deliberate) | 315 |
| L2 failed — instruction not located in the artifact | 70 |
| L2 failed — sibling coverage incomplete | 21 |
| Risk Clear | 6,010 |

### The differential, which is the actual measurement

The same 10,669 transactions were then run against the **pre-Round-13** engine
— L2's comparison moved back below the manifest lookup, the Risk Engine handed
the caller's label again — rebuilt from source (1m40s, confirmed in the log,
not a stale binary) and restored from a byte-for-byte copy afterwards.

**All 9,784 verdicts are byte-identical.** L2 status, risk verdict, approval:
nothing moved.

That is the result the round needed and could not get from its own tests. Round
13 closes an attacker path and changes nothing about how Graphite treats honest
traffic — measured, not asserted. A fix that had started refusing real
transactions would have shown up here as a diff, and a fix that did nothing
would have shown up in the deliberate-break log as tests that still passed.
Both were checked; both came out the right way.

### Three things the chain said that the repository did not

None of these are Round 13 regressions. All three are facts about the world
that this probe is the first thing here to measure.

1. **Version-1 transactions are on mainnet.** 875 of 10,669 (8.2%), in every
   block sampled. `CURRENT.md` recorded v1 as live on devnet and due to be
   handled "before it reaches mainnet"; that deadline has passed. Graphite
   refuses v1 by name so nothing fails open, but the practical reach is wider
   than the doc implied: a client capped at `maxSupportedTransactionVersion: 0`
   is refused the **entire block** (`-32015`), not just the v1 transactions in
   it. Corrected in `CURRENT.md`, and the item is now overdue rather than
   time-sensitive.

2. **92.5% of sampled mainnet transactions call a program with no manifest**
   (9,053 of 9,784), and 189 distinct programs appeared in eight blocks against
   33 shipped manifests. This is what drives the 2,569 Check 3 drainer blocks:
   `detect_drainer_pattern` fires on three or more accounts with no declared
   state changes, and an unmanifested program never declares any. The
   fail-closed direction is right — it refuses rather than guessing — but the
   honest description of today's coverage is "the protocols Graphite knows",
   not "Solana". Recorded as a limitation in `CURRENT.md`.

3. **Routers are blocked for cleaning up after themselves.** All 1,087
   known-risky-table blocks landed on a **sibling**, never on the instruction
   being verified: pump.fun, Jupiter and others closing the temporary
   wrapped-SOL account they opened in the same transaction. `CloseAccount`
   blocking unconditionally regardless of intent is deliberate and documented;
   this is the first measurement of what it costs on live traffic, which is
   roughly 11% of it.

---

## What was run

| Suite | Result |
|---|---|
| `cargo test` (graphite-core, default features) | 80 binaries, 1,509 tests, 0 failed |
| `cargo test --release`, `--release --no-default-features --lib`, `--release --no-default-features --features cli` | 163 binaries, 3,151 tests, 0 failed |
| `cargo clippy --all-targets --all-features -- -D warnings` | clean |
| `cargo fmt --all -- --check` | clean |
| `graphite-core/tests/mislabelled_discriminator.rs` | 16 passed, 0 failed |
| `state_diff` unit tests (incl. 7 new) | 38 passed, 0 failed |
| `npm test` (SAK integration, TypeScript) | 100 passed, 0 failed |
| `npm run typecheck` (SAK) | clean |
| Corpus + artifact fixtures regenerated | byte-identical, no drift |
| `tests/mainnet_conformance.rs` over 10,669 real mainnet transactions | passed |
| The same 10,669 against the pre-Round-13 engine | 9,784 / 9,784 verdicts identical |

**A build note, not a result.** `cargo test --release` failed twice with
`LINK : fatal error LNK1104: cannot open file ...target\release\deps\*.rcgu.o`
on the same test binary. It is not a flake and it is not the code: this
checkout lives under OneDrive, which locks and dehydrates build intermediates,
and release linking touches far more of them than debug does. Setting
`CARGO_TARGET_DIR` outside OneDrive makes the matrix pass. Recorded because the
first instinct — retry, call it transient — is wrong and costs an hour.

---

## What this round does NOT change

- **Descriptive mode is still descriptive.** Without an artifact,
  `instruction_data` is the caller's own claim. A request that supplies no
  data and no artifact has given nothing to ground the discriminator against,
  and the verdict says so through `scope`.
- **`content_hash` is unchanged.** It is still computed over the *declared*
  discriminator, which is what keeps the Rust, TypeScript and Go projections
  byte-identical. It is an instruction-level identifier, not the authoritative
  binding; `scope.transaction_sha256` is.
- **Secondary declared instructions** were already grounded in artifact mode
  by `declaration_describes`, which requires each declaration's discriminator
  to be a prefix of a real instruction's data. Descriptive-mode secondary
  declarations remain as documented.
- **Nothing about the L7 ceiling changed.** Confidence 0.640 on an unknown
  instruction is still what it was; this round removes the reason a known
  instruction could be presented as an unknown one.
