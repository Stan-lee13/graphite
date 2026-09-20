# Round 15 — earned by asking

**Date:** 2026-09-20
**Trigger:** a forensic re-audit of the whole boundary, commissioned as an
adversarial review of every previous fix rather than a continuation of Round 14.
**Audited state:** commit `21c0a7bbc661cf1b9f1975958eb5af6303cdf7e2` (`main`,
verified with `git rev-parse HEAD`; working tree clean apart from untracked
`.agents/` and `.claude/`, which are not Graphite's).
**Method:** source, call graph and tests read in `graphite-core/src/*.rs`
(verification, tx_artifact, account_resolution, manifest, manifest_registry,
risk_engine, policy_engine, confidence_engine, state_diff, rpc_client,
simulation_integrity, semantic_graph_store, plugin_orchestrator, plugins/*,
durable, server, cli), the SAK bridge (`artifact.ts`, `graphite-sak-bridge.ts`,
`execution-lifecycle.ts`, `residual-policy.ts`, `devnet-test.ts`), the
TypeScript and Go SDKs, and 82 integration test files. Every claim below that is
marked CONFIRMED was reproduced against the release binary on a loopback Core
(`127.0.0.1:7651`, `GRAPHITE_DEV_MODE=1`) behind a controllable mock RPC
(`127.0.0.1:7650`). No public RPC was touched, no wallet, no funds, no key. This
is internal work and is not an independent certification.

> This file is a dated record. `docs/CURRENT.md` describes the codebase as it
> is now.

---

## 1. Executive summary

The exact-byte boundary holds. From `BoundTransaction.build` through
`signApproved` to `sendRawTransaction`, the reference bridge verifies, signs and
submits one object; the digest is recomputed over the live object immediately
before signing, the signer set is read from the message, and the submitted
message is compared byte-for-byte with the verified one. The Core's L2 locates
the described instruction by exact data equality at one position, requires
every sibling to be declared and matched, derives privileges from the header,
keys every manifest lookup on the instruction's own bytes, refuses durable
nonces by default, binds L8 chain bytes to the signature under the fee payer's
key, and takes no outbound destination from any request. All twelve historical
classes re-tested in §4 remain closed.

What this round found is not a hole in the boundary but three places where the
Core's **positive claims are cheaper to obtain than they are supposed to be**:

1. **Confidence is earned by asking.** The `SimulationMatch` signal (weight
   0.20) is the program's simulation-baseline `sample_count`, and every
   verification with a real RPC simulation increments it — including a
   verification that is refused. The same request, sent three times, goes
   0.507 → 0.573 → 0.640 and flips from **refused to approved under the
   Gaming profile** between the first and second call. Nothing about the
   transaction changed; only the fact that it had been asked before. The verdict
   is artifact-bound with inherent residuals only, so the reference bridge
   would sign the second one. (F-15-01, P2)
2. **A failed simulation is trusted evidence.** `rpc_sim_ok` checks compute
   units and the derived fields but never `err`. A simulation the RPC reports as
   failed (`InstructionError`) with non-zero units is recorded into the trusted
   baseline, feeds the pump above, and — past ten samples — draws
   **"Simulation integrity clean (RPC-verified)"** from L3 for a transaction that
   would not execute. Baseline poisoning therefore needs no valid transaction.
   (F-15-02, P2)
3. **An empty label switches a hard gate off.** `risk_discriminator` is kept
   empty on purpose so the Risk Engine's Check 2 refuses an unlabelled call to
   a known-risky program; but the manifest lookup for `risk_class`,
   `expected_account_count` and `variable_accounts` is keyed on that same empty
   string, so on every *other* manifested program it misses. Check 10 —
   "high-risk class with no declared intent" — blocks the full label and
   clears the empty one, same bytes. The confidence floor still refuses today
   (max 0.373), so this is a hard gate that has quietly become a soft one, not
   yet an approval. (F-15-03, P2, PARTIAL)

Beneath those: the verify-time `transaction_sha256` hashes raw bytes while L8
hashes signature-zeroed bytes, so a pre-signed artifact can be approved but never
joined to its execution by the chain's evidence (F-15-04); approval is not
conditioned on lookup-table resolution, and a table the runtime still honours
while deactivating is one Graphite refuses to read, so every such live v0
transaction lands in the "positions not compared" path with `approved: true`
and only the residual policy standing in the way (F-15-05); and two in-repo
execution examples — the Go SDK's documented pattern and `devnet-test.ts` —
sign on `approved` + `artifact_bound` without the residual policy (F-15-06).

Posture, from the code alone: the boundary that stops an unsafe transaction
being signed is intact **when the reference bridge is the executor**. The
Core's own `approved` is weaker than its layer reports imply for a caller
willing to ask more than once, and weaker than its documentation implies for
any executor that does not apply the residual policy.

---

## 2. Confirmed findings

| ID | Sev | Status | File | Function | Finding | Exploitability |
|---|---|---|---|---|---|---|
| F-15-01 | P2 | CONFIRMED | `verification.rs:6323`, `:5446` | `build_signals`, `verify_async` | Repeating a refused request raises its confidence by 0.0667 per real simulation (saturates at 3); Gaming floor crossed on the 2nd identical call | Caller with API access + reachable RPC; no chain effect; bridge signs the result |
| F-15-02 | P2 | CONFIRMED | `verification.rs:5077`, `rpc_client.rs:382` | `verify_async` (`rpc_sim_ok`), `parse_simulation_value` | `err != null` simulations with `unitsConsumed > 0` enter the baseline and, past `MIN_SAMPLES`, certify L3 "clean (RPC-verified)" | Same as above; also lets a poisoner use transactions that fail |
| F-15-03 | P2 | PARTIAL | `verification.rs:4343`, `risk_engine.rs:638` | `verify_async` (`risk_discriminator`), `assess` Check 10 | Empty label → `manifest_risk_class = ""` → Check 10 (and 3b) off for non-native manifested programs; full label Blocked, empty label Clear, same bytes | Hard gate defeated; policy floor still refuses (max 0.373 < 0.40) |
| F-15-04 | P3 | CONFIRMED | `verification.rs:1380` vs `tx_artifact.rs:353,381` | `verification_scope` vs `artifact_sha256_of_signed` | Verify-time digest is `SHA256(raw)`; L8 digest is `SHA256(zeroed slots)`; an artifact carrying a real signature is approved but unjoinable by chain evidence | Detective control (blocked-yet-executed alarm) blind for pre-signed artifacts |
| F-15-06 | P3 | CONFIRMED | `sdk/go/graphite.go:9-40`, `integrations/solana-agent-kit/devnet-test.ts:189-219` | package doc; `main` | Two in-repo execution patterns gate on `approved` + `artifact_bound` (+ AuditBind) and never consult `unobserved_codes` | Executes a `not_simulated` / `lookup_tables_unresolved` approval |
| F-15-08 | P3 | CONFIRMED | `manifest.rs:300-308`, `account_resolution.rs:354-414` | `validate`, `resolve_pda_seed_template` | Only `{`-without-`}` is refused at load; `{account_99}`, `{instruction_data:9:2}`, `0xZZ` load and become literal / empty / whole-data seeds | Fail-closed in effect (derived PDA mismatches → Blocked); a false "identity confirmed" needs the degenerate PDA the program itself would reject |

## 3. Partial findings and design weaknesses

| ID | Sev | Status | File | Function | Weakness |
|---|---|---|---|---|---|
| F-15-05 | P2 | DESIGN WEAKNESS | `verification.rs:4085-4100`, `:539-560`, `tx_artifact.rs:819-828` | L2 `Match { unresolved }` arm, `instruction_accounts_for_comparison`, `decode_lookup_table` | `approved` is not conditioned on lookup resolution: unresolved primary positions pass L2 as "not compared", sibling ALT positions are wildcards, identity checks run on the caller's addresses, and the verdict is `approved: true` + `lookup_tables_unresolved`. A **deactivating** table (`deactivation_slot != u64::MAX`) is refused by Graphite yet still resolved by the runtime for ~512 slots (agave `LookupTableMeta::is_active` treats Deactivating as active), so an executable transaction always takes this path |
| F-15-07 | P3 | DESIGN WEAKNESS | `server.rs:1332-1372`; `verification.rs:5752` | `enforce_wallet_profile`; `verify_async` | The unpinned clamp raises `min_confidence` to 0.55 but leaves `min_trust_tier: Unknown` untouched; library embedders receive no clamp at all. Not reachable to an approval today (an Unknown-tier program cannot exceed 0.20) |
| F-15-09 | P3 | DESIGN WEAKNESS (documented) | `durable.rs:1289` | `lifecycle_history` | The newest archive is consulted only when the active file holds *no* row for the key; a lifecycle with rows on both sides of a rotation is reconstructed from the active side only. Documented in Round 12; produces false sequence anomalies, never a false approval |

Category per the brief: F-15-01/02/03 are **B (security-property violation)**;
F-15-04 and F-15-09 are **D (operational)**; F-15-05 is **B with a C
consequence**; F-15-06 is **C (integration footgun)**; F-15-07/08 are
hardening. No finding in this round is category A: no path was found by which
an attacker causes the reference bridge to sign a transaction Graphite has
refused.

---

## 4. Closed findings, re-checked

| Class | Evidence at `21c0a7b` | Status |
|---|---|---|
| Caller-controlled discriminator prefix | `effective_discriminator` = first 8 data bytes (`verification.rs:3843`) keys `resolve_accounts`, `expected_state_changes`, plugin ctx, pattern analysis; label only used for the L2 contradiction check and the empty-arm of Check 2 | CONFIRMED CLOSED (but see F-15-03 for the residue) |
| Empty caller-declared discriminator | `effective_discriminator` not gated on non-empty; Check 2 empty arm blocks known-risky programs (`risk_engine.rs:349`) | CONFIRMED CLOSED for native programs; F-15-03 for manifested non-native |
| Secondary-instruction discriminator bypass | `siblings_keyed_on_their_bytes` (`verification.rs:664`) re-keys every matched sibling on its data; unmatched declarations fail L2 | CONFIRMED CLOSED |
| Wallet-profile threshold bypass | `enforce_wallet_profile` clamps confidence; `evaluate_policy` rejects NaN/∞/out-of-range; risk block first | CONFIRMED CLOSED (F-15-07 notes the tier axis) |
| FakeSwap / no-op | Check 8/9 in `assess`; L5 semantic; unchanged | CONFIRMED CLOSED |
| Intent synonym inconsistency | `canonical_intent` used in Checks 6a/6b/7 | CONFIRMED CLOSED |
| Sibling ALT wildcard | `instruction_accounts_for_comparison` resolves sibling positions when tables came back; still wildcard when they did not, disclosed by residual (F-15-05) | CLOSED as designed; design weakness stands |
| Signer mismatch | `assertSignersMatchTheMessage` reads `numRequiredSignatures` from the compiled message | CONFIRMED CLOSED |
| Exact artifact binding | `assertApproved` re-serializes; `signAndFreeze` compares `messageOf(raw)` to captured message; `isolate` deep-copies | CONFIRMED CLOSED |
| RPC returned-byte binding | `bound_artifact_sha256`: first slot equals signature, `verify_strict` under fee payer | CONFIRMED CLOSED |
| L2/L4/L5 hard gate | `structural_layer_failed` → `l6_passed = false` → `approved = false` (`verification.rs:5801-5851`) | CONFIRMED CLOSED |
| Simulation bootstrap dead path | recording runs during bootstrap (`:5446`) — and that is exactly what F-15-01/02 exploit | CLOSED; the fix created the new surface |
| SSRF / destination control | only `GRAPHITE_RPC_URL` / `GRAPHITE_RPC_WITNESS_URL` are dialled; `redirect::Policy::none()`; body capped | CONFIRMED CLOSED |
| Auth default-closed | `auth_posture`: no key → refuse unless `GRAPHITE_DEV_MODE=1` on loopback; ≥32 chars; `ct_eq` | CONFIRMED CLOSED |

---

## 5. Attack-path analysis

### 5.1 The strongest path found (F-15-01 + F-15-02)

```
compromised agent (holds the operator key, or reaches a dev-mode Core)
  → builds the transaction it wants signed; risk engine finds nothing
    (a plain transfer to the attacker, or any Clear-risk instruction)
  → POST /verify #1: confidence 0.507 < Gaming 0.55 → REFUSED
      (the RPC simulation runs; sample_count 0 → 1; nothing else changes)
  → POST /verify #2: identical body: confidence 0.573 → APPROVED,
      artifact_bound, residuals [program_semantics, inner_instructions]
  → bridge: residual policy accepts (inherent only) → signApproved → submitted
```

Measured on the loopback Core (release binary, mock RPC, System transfer,
Gaming profile):

```
#1 approved=False conf=0.507 policy=Rejected baseline_samples=1
#2 approved=True  conf=0.573 policy=Approved baseline_samples=2
#3 approved=True  conf=0.640 policy=Approved baseline_samples=3
```

What it defeats: `min_confidence` floors in (0.44, 0.64] for an
OfficialManifest program — the built-in Gaming profile and any Custom profile
in that band. What it does not defeat: any Risk Engine block, L2/L4/L5 hard
gates, the tier floors (Trading/Treasury/Enterprise stay out of reach because
the tier signal is capped at OfficialManifest). Preconditions: the ability to
call `/verify` (the agent's own credential) and an RPC the Core can simulate
against. Every one of the "pump" calls is a real `simulateTransaction` with no
chain effect and no cost beyond RPC quota.

With F-15-02 the pump does not even need a transaction that would succeed:
twelve failing simulations (`err: InstructionError`, 7,000 CU) recorded, and L3
reported **"Simulation integrity clean (RPC-verified): 7000 CU / 0 writes /
0 hops"** on the 13th.

### 5.2 The path that is closed by one layer (F-15-03)

```
agent → label "" + intent "" on Meteora claim_all_reward (risk_class withdraw)
  → Check 10 does not run (manifest_risk_class = "")   [full label: BLOCKED here]
  → risk Clear
  → confidence 0.173 (no intent alignment, L5 penalty) < every profile → REFUSED
```

Measured, same bytes, same accounts:

```
label=d0eb91df2bb27878 intent=<empty> approved=False risk=Blocked  [MaliciousAccountChange: high-risk class 'withdraw' but no intent]
label=<empty>          intent=<empty> approved=False risk=Clear    findings=[]
```

Ceiling with the F-15-01 pump: 0.373. Below the bridge's default 0.40 and
every built-in floor. So the hard gate is gone but the soft gate holds — for
now, and only because an empty intent also costs the intent-alignment signal.

### 5.3 Why the exact-byte boundary itself was not broken

Every mutation vector in the brief was tried against `artifact.ts`:

- blockhash / fee payer / signer / instruction / account-meta / data / order:
  all inside the message; `assertApproved` re-serializes and `signAndFreeze`
  compares `messageOf(raw)` with the captured message — any change fails;
- object aliasing: `isolate` copies program id, every pubkey and the data
  Buffer; `instructions()` returns fresh copies; `tx` is private;
- repeated signing / parallel execution: `tx.sign` twice yields the same bytes;
  the network deduplicates one signature;
- durable nonce: refused in `build` (instruction 0 = AdvanceNonceAccount) and
  at L2 unless opted in and verified on-chain;
- v0 / ALT: the bridge never builds a v0 transaction.

---

## 6. Security invariants

| Invariant | Enforced? | Evidence | Bypass? |
|---|---|---|---|
| Exact-byte binding (verified = signed = submitted message) | Yes, in the bridge | `artifact.ts` `signApproved` → `assertApproved` (recompute) → `signAndFreeze` (message equality) | None found |
| Signer binding | Yes | `assertSignersMatchTheMessage` from `numRequiredSignatures` | None found |
| Instruction identity | Yes for identity/effects; **partial for risk metadata** | `effective_discriminator` keys manifest, effects, plugins, patterns; `risk_discriminator` keeps an empty label empty | F-15-03: empty label drops `risk_class`/`expected_account_count` |
| Account identity | Yes when tables resolve; **delegated to residual policy when they do not** | L2 exact positional compare; `Match { unresolved }` passes with disclosure | F-15-05 |
| ALT identity | All-or-nothing resolution, owner checked, runtime numbering rebuilt | `resolve_lookups`, `runtime_account_list` | F-15-05 (deactivating tables always unresolved) |
| Residual enforcement | Yes in the bridge; **not in `approved`** | `ResidualPolicy.assertExecutable`; Go doc / devnet-test omit it | F-15-06 |
| Policy enforcement (confidence floor) | Enforced but **caller-drivable** | `evaluate_policy`; `SimulationMatch` = `sample_count` | F-15-01 |
| Risk hard gate | Yes | `approved = l6_passed && risk == Clear`; risk first in policy | F-15-03 removes one check from the gate |
| Simulation integrity | **Certifies failed simulations** | `rpc_sim_ok` ignores `err` | F-15-02 |
| State-diff integrity | Yes | errored / implausible / partial / oversized → `diff_unavailable`, `no_state_diff`; L4 fails on non-conservation | None found |
| Execution reconciliation | Yes for zero-slot artifacts | `bound_artifact_sha256` + `find_verification(TransactionSha256)` | F-15-04 for pre-signed artifacts |
| Audit integrity | Yes | `sync_data` per row, atomic rotation, whole-trail `find_verification` | F-15-09 (lifecycle across a rotation, documented) |

---

## 7. Finding detail

### F-15-01 — confidence earned by asking (P2, CONFIRMED, category B)

**Code.** `verify_async` records every complete RPC simulation into the
program's baseline (`verification.rs:5446`, gated only on `rpc_sim_ok &&
sim_flagged != Some(true)`), regardless of the verdict. `build_signals`
(`:6323`) turns `sample_count / SIMULATION_MATCH(3)` into the `SimulationMatch`
signal at weight 0.20. A refused verification therefore raises the confidence
of the next identical one.

**Invariant violated.** "The request body cannot mint confidence" (G4) is true
of a single request and false of a sequence of them; P2 determinism ("same
input → same verdict") is violated by design for the confidence axis, and the
design puts the caller in charge of the variable.

**Existing mitigation.** Risk hard gates; tier floors; the requirement that the
simulation be real. None addresses the confidence floor.

**Bridge can execute?** Yes — the approved verdict carries only inherent
residuals. **Other SDKs?** Yes.

**Repro.** `scratchpad/r15_probe.py t1` against `r15_harness.py` (mock RPC
returns a successful simulation with conserved lamports). Output in §5.1.

**Regression test required.** Two verifications of the same input with a
successful mock simulation must return the same `approved` (and, ideally, the
same `confidence`), or the second must not be higher than a documented,
operator-visible bound. A second test: `sample_count` must not grow from a
refused verification.

**Remediation.** Stop deriving a confidence signal from the accumulator's
`sample_count`; if "simulation evidence" is to count, count only observations
that (a) succeeded, (b) belong to an *approved* verdict, and (c) are distinct
transactions — or move the signal to operator seeding only. Rename it: today it
is `SimulationMatch` and measures "simulations run".

### F-15-02 — failed simulations are trusted evidence (P2, CONFIRMED, category B)

**Code.** `rpc_sim_ok = !implausible_units && units > 0 && account_writes.is_some()
&& cpi_hops.is_some()` (`verification.rs:5072-5078`). `sim_res.err` is parsed
(`rpc_client.rs:382`) and consulted by the L4 diff arm (`:5228`) but not here.
A failed simulation with non-zero units therefore (1) sets `rpc_sim_ok`, (2)
enters `record_simulation`, (3) after `MIN_SAMPLES` yields `sim_flagged =
Some(false)` and L3 `Passed` with the text "Simulation integrity clean
(RPC-verified)" (`:5981`).

**Invariant violated.** L3's positive claim ("integrity clean, RPC-verified")
is made about an execution that did not happen; the baseline that later flags
divergence is shaped by transactions that never ran to completion.

**Existing mitigation.** The state diff correctly refuses (`no_state_diff`,
"simulation did not execute"); an unknown program's confidence ceiling. The
existing test `an_errored_simulation_never_produces_a_diff` uses
`unitsConsumed: 0`, so it passes through the units gate and never exercises
this path.

**Repro.** `r15_probe.py t2`: 12 requests with `err: {"InstructionError":
[0,{"Custom":1}]}`, `unitsConsumed: 7000`; confidence 0.067 → 0.133 → 0.200;
L3 `passed`, reason "Simulation integrity clean (RPC-verified): 7000 CU / 0
writes / 0 hops".

**Regression test required.** An errored simulation with non-zero units must
leave `sample_count` unchanged, must not set `scope.simulated`'s positive
meaning without qualification, and L3 must read Inconclusive/Failed with the
error named.

**Remediation.** `&& sim_res.err.is_none()` in `rpc_sim_ok`; report the error
in the L3 reason; consider `scope.simulated = false` (or a distinct
`simulation_failed` field) when `err` is set.

### F-15-03 — an empty label switches Check 10 off (P2, PARTIAL, category B)

**Code.** `risk_discriminator` (`verification.rs:4343`) is `""` when the label is
empty, deliberately, so Check 2's empty arm (`risk_engine.rs:349`) can refuse an
unlabelled call to a *known-risky* program. But the manifest lookup that
supplies `expected_account_count`, `variable_accounts` and `manifest_risk_class`
(`:4353-4368`) is keyed on the same string, and `discriminator_matches("", …)`
is always false. Check 10 (`risk_engine.rs:638`) and Check 3b therefore never see
the manifest for an unlabelled instruction on any program outside
`RISKY_PATTERNS` (System, SPL Token, Token-2022, Jupiter V6, Kamino).

**Measured.** Meteora DLMM `claim_all_reward` (risk_class `withdraw`), empty
intent: full label → `Blocked / MaliciousAccountChange`; empty label →
`Clear`, no findings; L2 `passed` in both, instruction resolved as
`claim_all_reward` in both.

**Why still refused.** With an empty intent the `IntentAlignment` signal is 0
and L5 fails (penalty), so confidence tops out at 0.173, or 0.373 with the
F-15-01 pump — under the bridge's 0.40 and every built-in floor. That is a
second, weaker control doing the work the hard gate was written to do.

**Regression test required.** For every seed manifest instruction with a
high-risk `risk_class`: label `""` + intent `""` must draw the same risk
verdict as the full label + intent `""`.

**Remediation.** Key the risk-metadata lookup on `effective_discriminator`
(the bytes) while leaving Check 2's empty arm on the label — exactly the split
Round 14 applied to account resolution. Then an empty label can only add
refusals, never remove them.

### F-15-04 — two digests for one artifact (P3, CONFIRMED, category D)

**Code.** `verification_scope` hashes the raw supplied bytes
(`verification.rs:1380`). L8 hashes `unsigned_artifact(bytes)` — the same frame
with every signature slot zeroed (`tx_artifact.rs:353, 381`). They agree only
when the supplied artifact already had zeroed slots.

**Measured.** A transfer artifact with 64 × `0x11` in slot 0: `approved: true`,
`scope.transaction_sha256 = 23d4767c…` = `SHA256(raw)`; L8 would derive
`6f0e8d91…` from the chain's bytes for the same transaction.

**Consequence.** Multi-signer flows (a co-signer signs first), or any caller
that verifies after partial signing, get a verdict L8 cannot join by chain
evidence; the "BLOCKED yet executed" alarm then depends on caller-supplied
keys. Not an approval bypass. The bridge always sends zeroed slots.

**Remediation.** Hash `unsigned_artifact(bytes)` in `verification_scope` (one
canonical digest for every pre-signature state), or refuse artifacts with
non-zero signature slots at L2.

### F-15-05 — approval is not conditioned on lookup resolution (P2, DESIGN WEAKNESS)

**Code.** When tables did not resolve, the primary's comparison falls back to
the unresolved list and passes as `Match { unresolved }`
(`verification.rs:4085-4100`); sibling positions from tables are `None` and
therefore match anything (`:539-560`, documented in the function's own
comment); `resolve_accounts` runs on the caller's `account_addresses`; the
verdict can be `approved: true` with `lookup_tables_unresolved`. The design
relies on the executor's residual policy.

**The twist.** `decode_lookup_table` refuses any table whose
`deactivation_slot != u64::MAX` (`tx_artifact.rs:819-828`). The runtime treats a
deactivating table as active until its cooldown (~512 slots) has passed
(agave `LookupTableMeta::is_active`: Activated and Deactivating both load). So
a v0 transaction referencing a deactivating table is executable, and Graphite
will always say its accounts were "counted and not identified". The identity
checks that matter most for such a transaction are then the caller's word.

**Who executes it.** The reference bridge refuses (default residual policy;
and it never builds v0). The Go SDK's documented pattern and `devnet-test.ts`
would execute it (F-15-06). An operator who accepted `lookup_tables_unresolved`
by configuration would execute it through the bridge.

**Remediation.** For an artifact-bound request, an unresolved lookup position
in the primary or in any sibling should fail L2 (the property "the accounts
this verdict is about are the accounts the instruction acts on" is not
established), making `approved = false` rather than `approved = true +
residual`. Separately, mirror the runtime: treat Deactivating as resolvable and
apply `active_addresses_len`, so that the refusal is reserved for tables the
runtime would also refuse.

### F-15-06 — in-repo executors without the residual policy (P3, CONFIRMED, category C)

`sdk/go/graphite.go:9-40` presents "the complete pattern. Every step matters":
`Approved` → `IsArtifactBound` → `VerifyInstruction(content_hash)` → sign. It
never mentions `NonInherentUnobserved()` (which exists at `:336`) or
`transaction_sha256`. `devnet-test.ts:189-219` checks `approved` and
`scope.kind`, prints the residuals, and signs. Both would execute an approved
verdict carrying `not_simulated`, `no_state_diff`, `privileges_from_caller` or
`lookup_tables_unresolved`. The TypeScript SDK README does say "decide on
`scope.unobserved_codes`".

**Remediation.** Add the residual step to the Go package doc and a
`RequireInherentOnly()` helper; route `devnet-test.ts` through
`executeBoundTransaction`.

### F-15-07 — the profile clamp has one axis (P3, DESIGN WEAKNESS)

`enforce_wallet_profile` raises a Custom `min_confidence` below 0.55 to 0.55
but passes `min_trust_tier: Unknown` through; the weakest built-in tier floor
is HeuristicInferred. Library embedders calling `verify_async` directly get no
clamp. Not reachable to an approval today: an Unknown-tier program's confidence
cannot exceed 0.20. Documented as "never weaker than the weakest built-in
profile", which is true of one of the two thresholds.

### F-15-08 — malformed seed templates load (P3, CONFIRMED, hardening)

`validate` refuses only `{…` without `}`. `resolve_pda_seed_template` turns
`{account_99}` into the literal bytes of the template string,
`{instruction_data:9:2}` into an empty seed, `{account_1:x}` into the whole key,
`0xZZ` into literal bytes. Each derives a PDA that does not match an honest
account, so honest traffic is refused (fail-closed, but a silent manifest
authoring failure). A caller could supply the degenerate PDA and be told
"identity confirmed" for a slot the on-chain program would reject. Refuse
unknown template grammar at load.

### F-15-09 — lifecycle across a rotation (P3, documented)

`lifecycle_history` reads the newest archive only when the active file has no
row for the key. Signing before a rotation and submission after it yields a
history of one row and a sequence anomaly. Round 12 documented this; the
residual is that the docstring's "when the active file holds none" is exactly
the case a straddle does not satisfy.

---

## 8. Missing adversarial tests (would fail on the defects above)

1. **Same input, same verdict:** two `verify_async` calls with an identical
   input and a successful mock simulation must agree on `approved`
   (F-15-01).
2. **Refusals do not earn:** `sample_count` must not grow from a verification
   whose `approved == false` (F-15-01).
3. **Errored simulation with units:** `err != null`, `unitsConsumed > 0`,
   balances present → `sample_count` unchanged, L3 not `Passed`, reason names
   the error (F-15-02). The existing test uses `unitsConsumed: 0` and does not
   cover this.
4. **Empty label is never more permissive:** for every seed instruction with
   `risk_class ∈ {drain, authority, withdraw, mint, close}`, risk verdict with
   label `""` ≥ verdict with the full label, for intent `""` (F-15-03).
5. **One digest per artifact:** a supplied artifact with a non-zero signature
   slot must produce the same `scope.transaction_sha256` as its zeroed twin, or
   be refused (F-15-04).
6. **Unresolved ALT positions cannot approve:** a v0 artifact whose table the
   mock RPC returns as *deactivating* must not be `approved` (F-15-05); today
   only the residual is asserted (`sibling_lookup_accounts.rs`).
7. **Deactivating tables resolve:** a table with `deactivation_slot` within the
   cooldown must resolve as the runtime would (F-15-05).
8. **Go SDK residual helper in the documented pattern** — a compile-checked
   example (F-15-06).
9. **Profile clamp on both axes:** Custom `{0.55, Unknown}` unpinned must be
   raised to HeuristicInferred (F-15-07).
10. **Seed template grammar:** `{account_99}`, `{instruction_data:9:2}`,
    `0xZZ` must fail `validate` (F-15-08).
11. **Lifecycle straddle:** signing row before rotation, submission after →
    both rows returned (F-15-09).

---

## 9. Deliberate-break log

| Break | Test expected to catch it | Result |
|---|---|---|
| B1: drop `sim_res.err.is_none()` from the L4 diff arm (`verification.rs:5228`) | `rpc_trust_boundary::an_errored_simulation_never_produces_a_diff` | see §9.1 |

Only one break was run this round (each break is a ~3.5 minute release
rebuild of the lib on this machine, and the in-tree debug cache had to be
reclaimed for disk — 62 GB); the three confirmed defects have *no* test to
break, which is the finding. The
break was applied with a `cp` backup and restored; `verification.rs` digest
before and after: `177a62b0b34087fe6da91fc71256d20d7b52a4885c45e9b73ff1d74e250f89d0`.

### 9.1 B1 outcome

```
=== BROKEN  (sed: `&& sim_res.err.is_none()` removed at verification.rs:5228)
test an_errored_simulation_never_produces_a_diff ... FAILED
thread 'an_errored_simulation_never_produces_a_diff' panicked at testspc_trust_boundary.rs:636:5
test result: FAILED. 0 passed; 1 failed
=== RESTORED (cp from .r15bak; sha256 177a62b0…0f89d0 = pristine)
test an_errored_simulation_never_produces_a_diff ... ok
test result: ok. 1 passed; 0 failed
```

The pinned test catches the removal of the L4 diff gate. It does **not** cover
F-15-02, because its fixture reports `unitsConsumed: 0` and so never reaches
`rpc_sim_ok` — the same errored response with `unitsConsumed: 7000` passes
that gate today (§7, F-15-02). The first attempt at this break silently did
nothing: the release `graphite.exe` was still held open by the audit's own
loopback Core and cargo could not relink, so the "broken" test never ran. The
run above is the second attempt, with the Core stopped first.

---

## 10. Recommended remediation order

Ordered by exploitability × boundary impact ÷ prerequisites, not by preference:

1. **F-15-02** — one-line gate (`err.is_none()`), zero prerequisites for the
   attacker today, makes L3 state a falsehood and makes poisoning free.
   Smallest fix, removes the cheapest half of the pump.
2. **F-15-01** — the pump itself. Directly flips a Gaming-profile refusal to
   an approval the bridge will sign; needs only API access and an RPC. Fix is
   a design decision (what may count as simulation evidence), so it follows the
   one-liner rather than precedes it.
3. **F-15-05** — make `approved` false when an artifact-bound request has
   unresolved lookup positions, and align table activity with the runtime.
   Broad blast radius (every non-bridge executor), moderate prerequisites (v0 +
   an executor without residual policy).
4. **F-15-03** — key the risk-metadata lookup on the bytes. No approval today,
   but a hard gate that is caller-suppressible will not stay harmless once the
   confidence landscape moves.
5. **F-15-06** — documentation and one example; cheap; closes the executor
   that F-15-05 needs.
6. **F-15-04** — canonical digest at verify time; restores the detective
   control for pre-signed artifacts.
7. **F-15-08, F-15-07, F-15-09** — hardening; none reaches an approval.

---

## 11. What was not tested

- No live chain, no public RPC, no real wallet (standing rule).
- Concurrency was reasoned from the lock structure (`Arc<Mutex<SemanticGraphStore>>`,
  check-then-record under separate acquisitions — benign double-record, never a
  flagged record); no multi-threaded race harness was run this round.
- The Python AI layer was inspected only for its role (intent parsing; it
  produces no verdict and no bytes) — consistent with "AI never creates
  approval".
- The runtime's exact lookup-table activity rule (`is_active`) is cited from
  agave's implementation as understood by the auditor, not re-executed against
  a validator; the direction of the discrepancy (Graphite stricter than the
  runtime) is what matters for F-15-05 and does not depend on the cooldown
  length.
