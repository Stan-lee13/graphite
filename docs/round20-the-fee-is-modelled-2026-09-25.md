# Round 20 — the fee is modelled

> **Historical record.** This report describes the codebase at commit `b04e5bd`
> on 2026-09-25, and the changes made on top of it. For the current state of
> Graphite see [`CURRENT.md`](CURRENT.md).

**Date:** 2026-09-25
**Trigger:** "model token-2022 transfer fee next" — the item Round 19 left open
("Token-2022 `TransferFee` is not modelled; fee-bearing mints are refused").
**Starting state:** commit `b04e5bd` (`main`), CI green.
**Constraints kept:** no credentials or RPC secrets; mock RPCs on loopback; the
public mainnet RPC read-only and paced; nothing signed or sent. Internal
engineering work, not independent certification.

---

## 1. What was asked, and what it turned out to need

Every transaction touching a Token-2022 mint with the `TransferFee` extension
was refused at L4 (`Token2022ExtensionNotModelled`): the amount that arrives is
not the amount that was sent, and Graphite could not say what it was. The ask
was to model the fee so those transactions are judged rather than refused.

Modelling it turned out to require three other things, and building the model
is what exposed them:

1. **The mint's schedule was never available.** A `TransferChecked` names its
   mint read-only; L4 diffs only writable accounts; so the one account whose
   bytes say what a transfer costs was never read. Graphite now fetches it.
2. **Every self-paid token transfer was already refused, fee or no fee.** Run
   through the pipeline over a mock RPC, the first honest fee-bearing transfer
   was blocked twice over by defects that have nothing to do with fees: the
   authority is the fee payer, the fee payer is writable because it pays the
   fee, and Graphite read that as a privilege escalation (risk: `Blocked`) and
   left the fee payer out of the diff (L4: `ArtifactEffectsNotCovered`). This is
   the cause of Round 18's open item — "544 identity mismatches, mostly
   `kind=privilege` on slots the manifest DOES declare as signers … a
   hypothesis, and a blocking control is not loosened on one" — diagnosed here
   and measured on real traffic before it was changed (§5).
3. **A caller could label its own diff as Graphite's.** Reading how L4 chooses
   between Graphite's diff and the request's turned up that the request's diff
   kept whatever `provenance` it claimed.

## 2. The model

For every fee-bearing token account in the diff, Graphite reads
`TransferFeeAmount.withheld_amount` before and after; it takes the mint's
`TransferFeeConfig` from the diff or from its own pre-state fetch — never from
the caller — and it requires the observed movement to be exactly what
Token-2022 does:

| Requirement | If it does not hold |
|---|---|
| Every fee withheld at a destination is `TransferFee::calculate_fee` on ONE transfer of what arrived there (amount + withheld), under the mint's older or newer schedule | not modelled → blocks |
| Tokens arriving with nothing withheld are tokens the schedule does not charge (or a supply increase) | not modelled → blocks |
| Withheld fees leave an account only by being harvested into the mint's pool, exactly | not modelled → blocks ("withdrawal of withheld fees") |
| The mint's value is conserved over the accounts the diff covers: Σ amount + Σ withheld + mint pool changes by exactly the supply change | not modelled → blocks |
| Each withheld amount is read exactly (one entry, exactly 8 bytes; the config exactly 108 bytes, rates ≤ 100%) | not modelled → blocks |

On an account the model accounts for exactly, `TransferFeeConfig` and
`TransferFeeAmount` stop blocking and the verdict says what happened:

- `Token2022TransferFeeCharged` (warning) — gross, fee, what arrived, the
  schedule applied, and who can withdraw the fee;
- `Token2022TransferFeeMajority` (**critical**) — more is withheld than
  arrives: the transfer mostly pays the mint's withdraw authority;
- `Token2022TransferFeeRising` (warning) — the older schedule applied and a
  higher one is scheduled; the verdict states what would arrive if the
  transaction lands in that epoch;
- `Token2022TransferFeeConfigChanged` (**critical** unless the manifest
  declares an authority change) — the fee terms themselves changed;
- `Token2022WithheldFeesHarvested` (warning) — an exact harvest.

Every other extension that can alter a transfer — a hook, a confidential
transfer, a permanent delegate, an unknown type — still blocks, on the same
account, named on its own.

**The arithmetic is Token-2022's.** `TransferFeeSchedule::fee` is
`calculate_fee` from `spl-token-2022`'s
`interface/src/extension/transfer_fee/mod.rs`: ceiling division of
`amount × basis_points` by 10,000, capped at `maximum_fee`, zero for a zero rate
or amount; the upstream test vectors (`calculate_fee_max`, `_min`, `_zero`) are
reproduced in `tests/round20_transfer_fee.rs::the_fee_is_token_2022s_fee`. The
layouts (`TransferFeeConfig`, 108 bytes; `TransferFeeAmount`, 8) are the
upstream `#[repr(C)]` Pod structs.

**What the model does not do.** It does not read the epoch: when the two
schedules differ, the fee the simulator charged says which applied, and a
pending higher one is disclosed rather than judged. It does not attribute fees
per transfer when several fee-bearing transfers land in one account, nor model
withdrawals of withheld fees — both block, with the reason.

## 3. Findings

| ID | Finding | Severity | Reproduced | Fix | Regression test |
|---|---|---|---|---|---|
| **F-20-01** | A caller-supplied `state_diff` kept the `provenance` it claimed: a request with no artifact, or whose simulation failed, could send a fabricated diff marked `rpc_simulated` and L4 certified it — "State diff verified against the manifest" — while the account-shape check it displaced never ran. An existing test asserted exactly that | P2 | `l4_state_diff_gate` (the old test passed `approved: true` on a label) | A diff from the request is re-marked `CallerSupplied` whatever it claims | `l4_state_diff_gate::a_caller_diff_that_claims_rpc_provenance_is_still_the_callers` |
| **F-20-02** | Token-2022 `TransferFee` refused, not modelled | Coverage | Every fee-bearing transfer | The model above; the mint fetched by Graphite | `round20_transfer_fee` (22) |
| **F-20-03** | The fee payer's writable flag was read as a privilege escalation on any slot declared read-only — so every SPL / Token-2022 transfer whose authority also paid the fee was `Blocked` as an account-identity mismatch. The cause of Round 18's undiagnosed `kind=privilege` cluster | P2 (false refusal, fail-closed) | Mock-RPC pipeline test; 19,458 real transactions (§5) | The writable direction is not applied to the transaction's fee payer, read only from the bytes; its signer requirement and every other account are checked as before | `privilege_mismatch::the_fee_payers_writable_flag_is_not_a_privilege_escalation`, `::the_fee_payer_exemption_is_only_its_writable_flag` |
| **F-20-04** | L4 diffed the accounts the MANIFEST calls writable, not those the transaction makes writable: the fee payer signing as an authority was left out, and its fee then failed `ArtifactEffectsNotCovered` on every self-paid token transfer verified with an RPC | P2 (false refusal, fail-closed) | Mock-RPC pipeline test | L4 observes the union of the manifest's and the transaction's writable accounts | `round20_transfer_fee::pipeline::graphite_fetches_the_mints_schedule_and_models_the_fee` |
| **F-20-05** | `TransferCheckedWithFee` and the two withdrawals of withheld fees were not fund movements for the impersonation and unspendable-destination checks | P3 | Code read | `is_fund_movement` recognises 0x1a 0x01/02/03 on Token-2022 only | `round20_transfer_fee::the_fee_extension_transfers_are_fund_movements` |
| **F-20-06** | The Token-2022 manifest described none of the 0x1a instructions, though Round 18's own measurement had observed them unnamed on mainnet (harvest ×74, withdraw ×16, init ×3, `TransferCheckedWithFee` ×2): a harvest was judged by the drainer heuristic | P3 | Round 18 evidence; 2 real harvests (§5) | Six instructions added, each with its accounts, effects and risk class | registry tests; `docs/protocol-coverage.md` regenerated |
| F-20-07 | Double-encoded em dashes in two manifests (`kamino-lending.json`, `verified_program_ids.json`) | P3 (hygiene) | Byte scan | Repaired | — |

## 4. Where the fee model was checked

- **Unit and decode:** the upstream arithmetic vectors; exact-or-nothing
  decoding (wrong length, duplicate entry, impossible rate, the wrong account
  type); every accept and refuse path of §2 — 19 tests.
- **Through the pipeline over a loopback mock RPC:** an honest 1%/5,000-capped
  transfer of 1,000,000 — Graphite reads the mint itself, L4 states "995000
  arrived", no identity mismatch; the same transaction with the mint unreadable
  is refused with "was not available"; an RPC reporting a withheld amount the
  schedule does not charge is refused — 3 tests.
- **Against real fee-bearing mints** (`tests/mainnet_transfer_fee_live.rs`,
  new, ignored by default, read-only): every executed Token-2022
  `TransferChecked` / `TransferCheckedWithFee` in the 19,458-transaction sample,
  plus the recent history of each fee-bearing mint it contains, whose
  destination no other instruction in its transaction touches (so the balance
  change IS the arrival). The real mint is decoded with Graphite's decoder and
  the arrival recorded in the transaction's own token-balance metadata must be
  the amount minus Graphite's fee. Result: 3 fee-bearing mints, **6 real
  transfers checked, 3 charging a non-zero fee (one at 3%: 598,434,258,816
  withheld from 19,947,808,627,184), 0 mismatches.** Transfers into accounts
  that also sent the token in the same transaction — most swap legs — were
  skipped rather than guessed; the model itself refuses those.
- **Live against the public mainnet RPC:** 40 Token-2022 instructions from 8
  freshly fetched blocks, verified end to end one at a time. None involved a
  fee-bearing mint (4 distinct mints, none with a fee config), and 23 failed to
  simulate on state that had already moved; the run found 0 invariant
  violations. It is reported for what it is: a live run of the pipeline, not
  evidence about the fee model.

## 5. What the fee-payer fix did to real traffic

`tests/mainnet_conformance.rs` over the same 19,458 transactions, before
(`b04e5bd`) and after, verdict files diffed per transaction:

| | Before | After |
|---|---:|---:|
| risk Clear | 11,802 | **11,960** |
| blocked on account identity / privilege | 1,355 | **519** |
| verdicts changed | — | 588 of 19,440 |
| … of which Blocked → Clear | — | **156** |
| … of which still Blocked, the identity finding gone and another finding now named | — | 430 |
| … of which a real `HarvestWithheldTokensToMint` no longer judged by the drainer heuristic (F-20-06) | — | 2 |
| approvals (no RPC in this harness) | 0 | 0 |

In every changed verdict the only finding removed is the fee payer's
`AccountIdentityMismatch` (or, twice, the drainer finding on a now-described
harvest); no other check changed its answer. The 519 identity blocks that
remain are mostly declared read-only slots the transaction marks writable (247)
— writability is per message, so the program really can write them, and that is
left blocking — and fixed-address mismatches (156).

## 6. Deliberate breaks

Each fix was reverted in place from a byte copy, its regression test run, and
the file restored: **10 of 10 failed with the fix reverted.**

| Fix reverted | Test that failed |
|---|---|
| F-20-02 fee extensions stop blocking only on accounts the model accounted for | `an_honest_fee_bearing_transfer_is_modelled_and_stated` |
| F-20-02 the withheld amount must be the schedule's fee | `a_withheld_amount_that_is_not_the_schedules_fee_is_not_modelled` |
| F-20-02 the mint's value is conserved | `value_that_is_not_conserved_is_not_modelled` |
| F-20-02 withdrawals of withheld fees are not modelled | `a_withdrawal_of_withheld_fees_is_not_modelled` |
| F-20-02 a fee larger than the arrival blocks | `a_fee_larger_than_what_arrives_blocks` |
| F-20-02 Graphite fetches the fee mint itself | `pipeline::graphite_fetches_the_mints_schedule_and_models_the_fee` |
| F-20-01 a caller's diff is the caller's | `a_caller_diff_that_claims_rpc_provenance_is_still_the_callers` |
| F-20-03 the fee payer's writable flag | `the_fee_payers_writable_flag_is_not_a_privilege_escalation` |
| F-20-04 L4 observes what the transaction can write | `pipeline::graphite_fetches_the_mints_schedule_and_models_the_fee` |
| F-20-05 `TransferCheckedWithFee` moves value | `the_fee_extension_transfers_are_fund_movements` |

## 7. What was verified

The CI mirror, run locally against the Round 20 tree (`-j 4`,
`CARGO_INCREMENTAL=0`):

| Leg | Result |
|---|---|
| `cargo fmt --check` | clean |
| `cargo clippy -D warnings` — all features, featureless lib, cli-only | clean in all three |
| `cargo test --all-features` | **1,652 passed, 0 failed, 15 ignored** (was 1,628 / 14) |
| `cargo test --no-default-features --lib` | **327 passed, 0 failed, 1 ignored** |
| `cargo test --no-default-features --features cli` | **1,435 passed, 1 failed, 3 ignored** — see below |
| Deliberate breaks (§6) | 10 of 10 caught, no residue |
| Mainnet conformance, 19,458-transaction sample (§5) | 588 verdicts changed, every one accounted for; 0 approvals before and after |
| Real fee mints (§4) | 6 isolated transfers on 3 mints, 0 arithmetic mismatches |

The one cli-only failure is a timing assertion, not a verdict:
`round9_resource_bounds::an_artifact_larger_than_a_solana_packet_is_refused_before_it_is_parsed`
requires the refusal in under 500 ms and measured 1.28 s while the machine
was running the rest of the matrix and two background `git` processes. Run
alone on the same build it passes (345 ms; 5 of 5 in that binary). The refusal
itself is unchanged by this round — the size check is where Round 9 put it,
and Round 20 added nothing ahead of it. What the 345 ms is: the synchronous
`GraphiteCore::verify` builds a fresh multi-thread Tokio runtime on every call,
a fixed cost that both round9 tests show at the same ~345 ms regardless of
input size. It predates Round 20 and is recorded in §8 (P3).

The client suites (TypeScript SDK, SAK integration, Go, Python, dashboard) are
untouched by this round and run in CI.

## 8. Still open

- **Withdrawals of withheld fees** (`WithdrawWithheldTokensFromMint/Accounts`)
  and **several fee-bearing transfers into one account** are not modelled and
  block.
- **The epoch is not read**: a pending higher schedule is disclosed, not
  judged against the transaction's lifetime.
- **Other value-altering extensions** — transfer hooks, confidential
  transfers and their fee variant, permanent delegates — still block.
- **519 identity/privilege blocks** remain on the mainnet sample (§5),
  measured and not loosened.
- **Real fee-mint evidence is thin**: six isolated real transfers across three
  mints. The arithmetic matched every one; a larger sample needs an indexed
  source of fee-mint transfers.
- **The synchronous `verify` builds a multi-thread Tokio runtime per call**
  (~345 ms in a debug build). P3: no verdict depends on it, but it makes
  the Round 9 "refusal must cost nothing" timing bound flaky under load
  (§7). A shared or current-thread runtime is the fix; it changes how every
  synchronous call runs, so it gets its own round.
- Third-party audit and branch protection — owner decisions.

## 9. Files

New: `docs/round20-the-fee-is-modelled-2026-09-25.md`,
`graphite-core/tests/round20_transfer_fee.rs`,
`graphite-core/tests/mainnet_transfer_fee_live.rs`. Changed: `state_diff.rs`
(decoders, the model, the extension gate), `verification.rs` (mint fetch, L4
accounts, caller-diff provenance), `account_resolution.rs` (fee payer),
`risk_engine.rs` (fund movements), `protocols/token-2022.json` (+6
instructions), two manifests' text, `tests/mainnet_live_rpc.rs` (program
filter, fee tallies), `tests/l4_state_diff_gate.rs`, `tests/privilege_mismatch.rs`;
and `README.md`, `ARCHITECTURE.md`, `SECURITY.md`, `ROADMAP.md`,
`CONTRIBUTING.md`, `docs/CURRENT.md`, `docs/protocol-coverage.md`,
`graphite-core/{README,CHANGELOG}.md`.
