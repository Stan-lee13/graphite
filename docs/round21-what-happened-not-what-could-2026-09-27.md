# Round 21 — what happened, not what could

**Date:** 2026-09-27 · **Base:** `f47db5a` (Round 20) · **Scope:** the open
list Rounds 19 and 20 left, closed where it could be; and the root causes the
work turned up on the way.

Internal engineering work. Not an independent audit and not a
certification; the third-party audit remains the owner's decision.

## 1. What was asked, and what it turned out to need

The owner posted the open list: Token-2022 withheld-fee withdrawals, several
fee-bearing transfers into one account, the epoch not read, hooks /
confidential transfers / permanent delegates blocking, the identity and
privilege blocks on real traffic, the v1 compute budget not surfaced, the JSON
corpus builder skipping v1, L4's structural fallback reporting `Passed`, the
synchronous `verify` building a runtime per call, the thin real fee-mint
evidence and the one-day mainnet sample.

Most of those turned out to share one root: **Graphite refused on what an
account, a flag or an extension COULD do, instead of on what the transaction
DID with it.** A writable flag was read as a write; a transfer hook that names
no program was read as a hook; a mint's standing issuer powers were read as
their exercise; a `CloseAccount` that pays its own authority was read as a
drain; a read-only remaining account was read as account proliferation. Each
refused real, executed mainnet traffic. Each is now judged by an observation —
the transaction's own bytes, the simulator's executed instructions, or the
pre/post diff — and where that observation is not available, it blocks exactly
as before.

The second root was the manifests. Measured against the programs' own on-chain
IDLs and 16,414 executed mainnet instructions, 105 manifest instructions had
drifted, and several had the wrong account in the wrong slot — which is worse
than a false refusal, because a PDA or pinned-address check on the wrong slot
checks the wrong account.

A third turned up running the pipeline against the live chain: L4 measured
the transaction at two slots and judged a transaction-wide diff against one
instruction's accounts (§2.8).

## 2. What changed

### 2.1 The fee model replays what ran

Round 20 modelled a Token-2022 transfer fee from the diff alone: one transfer
per destination, withheld fees leaving an account only by harvest. That
refused withdrawals, several transfers into one account, and an account that
both sent and received — and, because the fee cap makes several transfers
look like one, it could state a per-transfer attribution it did not know.

The pipeline now builds the list of every Token-2022 instruction the simulator
executed — the transaction's own top-level instructions, then the CPIs the
simulation's `innerInstructions` report under each, resolved through the full
account list — and the model **replays** it from the pre-state: each transfer
charged its own schedule fee, each `WithdrawWithheldTokensFromMint` /
`FromAccounts` and harvest moving exactly the withheld amount it finds, mints
and burns moving supply. The replay must end at the observed post-state
exactly, for every account of the mint, the mint's withheld pool and its
supply. An instruction the replay does not know on an account of the mint, a
transfer through an account the diff did not observe, a `TransferCheckedWithFee`
stating a fee the schedule does not charge, a self-transfer, a withdrawal into
one of its own sources — each refuses, with the reason.

The executed list is `None`, not shorter, when the simulation reported no inner
instructions or an index cannot be placed; the Round 20 rule then decides, and
its statement now says it is the diff's arithmetic, not a per-transfer
attribution. Both new fields are `serde(skip)`: a request cannot tell the model
what ran.

### 2.2 The epoch is read

With a fee-bearing mint in the diff, Graphite asks the RPC `getEpochInfo`,
places the simulated slot in its epoch, and bounds the transaction's lifetime
from its bytes: a blockhash transaction can land within
`FEE_LANDING_MARGIN_SLOTS` (9,000 slots, about an hour — two orders of
magnitude past the network's worst sustained skip rate) of the simulation; a
durable-nonce transaction has no bound. Then:

- only the schedule `get_epoch_fee` selects for the simulated epoch is
  accepted (Round 20 accepted either);
- a pending schedule the transaction cannot reach says nothing; one it can
  reach — a durable nonce, or an epoch boundary inside the window — is
  reported with what would arrive, and a pending fee above half of a transfer
  blocks like a current one.

An RPC that cannot say the epoch leaves the Round 20 behaviour, stated as such.

### 2.3 A writable flag is not a write

Solana grants privileges per **message**: an account is writable in every
instruction that names it if any instruction needs it writable, and clients
mark accounts writable that nothing writes. "Declared read-only, writable in
the transaction" was a blocking identity mismatch. Measured on 16,414 executed
mainnet instructions: 4,331 such flags were the fee payer (exempt since Round
20), 451 were explained by another instruction of the same transaction whose
own manifest declares the write, and 342 by nothing — among them 85 SPL Token
`TransferChecked` authorities and 76 PumpSwap `global_volume_accumulator` PDAs.

The write direction is now decided by observation: a write another located
instruction's manifest declares explains the flag (and is judged on that
instruction); any other is **deferred** to the pre/post diff and passes only
if Graphite's own simulation observed the account and it did not change.
Changed, or unobserved (no RPC), it blocks as before, and the resolved
account's `privilege_mismatch` is restored. The signer direction — a declared
signer that does not sign — is untouched and blocks.

### 2.4 Manifests, grounded

A drift checker compared every manifest instruction with the program's cached
on-chain IDL; a grounding script compared every manifest with the executed
instructions of the 2026-09-23 sample. The IDL alone is not trusted: Orca's
on-chain IDL lists a trailing `whirlpool_program` that executed swaps do not
pass, and adopting it would have turned every Orca swap into an
account-count shortfall. The rule applied:

- where the account names disagree by position, the list is rebuilt from the
  IDL (pump.fun, Jupiter's v2 routes, Kamino's un-flattened composite groups,
  marginfi, Raydium CLMM limit orders, Squads `multisigCreate`);
- where the old list is a prefix of the IDL's, only the shared prefix's flags
  and pinned addresses are corrected and the IDL's extra trailing accounts are
  not added (Orca, parts of Kamino);
- pinned addresses come from the IDL's own `address` (Jupiter's event
  authority: 63 of 63 executed `route_v2`s carry it), except a token-program
  slot, which is pinned to both token programs whatever the IDL names — the
  program enforces which one it accepts, and the pin exists to stop an
  arbitrary program being substituted, not to guess the program's choice
  (Meteora's IDL narrows `swap` to classic SPL Token, and no executed `swap`
  in the sample could confirm it).

Two hand-written manifests were fixed from the runtime's layouts: System
`AdvanceNonceAccount` declared the nonce account a **signer** (371 of 371
executed advances had it unsigned), and Raydium AMM v4 swaps take 18 accounts
**or 17** — a new `account_layouts` field lets an instruction declare
alternate layouts, chosen only by an exact account count, validated like the
primary one, and refused at load when two share a length.

### 2.5 Token-2022 extensions, judged by what happened

A transfer hook whose mint names no hook program, confidential-transfer state
that is byte-for-byte unchanged with no confidential instruction executed on
the account, and a mint's permanent delegate or close authority that the
transaction does not change are now inert — stated, not refused. A hook that
runs a program, confidential state that changed, and an unread mint still
block, with the reason. Graphite fetches the mint of every extension-bearing
Token-2022 account for this (Round 20 fetched fee mints only).

It also sees what it did not before: a transfer or burn made by a mint's
**permanent delegate** out of an account it does not own is now a Critical
`Token2022PermanentDelegateExercised` — read from the executed instructions and
the mint Graphite fetched. With the mint read-only in a transfer, the
extension was never scanned, so the exercise was invisible.

### 2.6 Structural checks read the bytes

- **`CloseAccount`.** Check 2 blocked every token `CloseAccount` as a drain;
  1,367 rows of the sample name one, mostly the swap's own wrapped-SOL
  cleanup. A close whose destination IS its authority returns the account's
  lamports to the wallet closing it. It is exempt only when the pipeline read
  both positions from the bytes (static keys or resolved lookup tables); a
  declared sibling is exempt only when EVERY token `CloseAccount` in the
  message is such a refund, so a declaration cannot borrow another close's
  proof; a node of a caller-declared CPI trace never is. The exemption covers
  Check 10 too — a high-risk class with no declared intent, which every sibling
  lacks by construction and which otherwise undid it. The flag is
  `serde(skip)`.
- **Account proliferation.** Both account-count heuristics — Check 3's ratio
  and Check 3b's STMT count — counted every account past the manifest's list
  (tolerance 2). With privileges from the bytes they count the **writable**
  ones: a read-only account cannot lose anything, and a multi-transfer drain
  needs destinations it can write. PumpSwap's
  executed sells carry 2–3 accounts past the IDL's 21, mostly read-only fixed
  addresses.

### 2.7 The compute budget reaches the verdict

`scope.compute_budget` (artifact-bound verdicts) states the limit the
transaction sets and the one the runtime applies, the price, and the
**priority fee in lamports**, read from the v1 header or from Compute Budget
instructions (price × limit / 10⁶ rounded up, the default limit's upper bound
when none is set), plus anything the runtime would refuse (a duplicate or
malformed Compute Budget instruction, a heap outside its rules). A requested
priority fee above `MAX_PLAUSIBLE_FEE_LAMPORTS` is a blocking
`ExcessivePriorityFee` — before, only the simulator-reported fee was held to
that ceiling, and only with an RPC. The JSON schema, the TypeScript SDK and the
Go SDK carry the field.

### 2.8 L4 against live traffic

Running `tests/mainnet_live_rpc.rs` (40 real transactions, Graphite's own
simulation and state reads against the public mainnet RPC) with a new
`GRAPHITE_MAINNET_SHOW_L4=1` diagnostic named three more causes of L4 failing
on honest traffic, none of them introduced by this round:

- **Slot skew on lamports.** The pre-state is a `getMultipleAccounts` read;
  the post-state is the simulation's; the two land on different slots, and on
  a busy account lamports move in between — `LamportsNotConserved` on 4 of 40.
  The simulation reports every account's lamports before AND after at one
  slot (`preBalances` / `postBalances`); the pre-state lamports now come from
  there. It is the same RPC's word as the post-state, so nothing new is
  trusted, and the slot note says so.
- **The diff covers the transaction; the check covered one instruction.** L4
  compared the transaction-wide diff against the PRIMARY instruction's
  accounts, so every change another instruction made to its own accounts was
  `DiffAccountNotInInstruction` — 10 of 40. A diff Graphite built now carries
  the transaction's own account list (static keys plus the lookup addresses
  the simulator resolved, `serde(skip)`); a change outside it is still the
  diff failing to correspond, and every value movement is still judged.
- **Read-only accounts were diffed.** A declared sibling's accounts entered the
  diff whatever their privilege, and an account the transaction marks
  read-only "changed" between the two reads — a `WriteToReadonlyAccount` on
  an account the runtime forbids writing. Accounts the transaction marks
  read-only (from the bytes and the resolved tables) are no longer diffed.

Over the same 40 transactions, L4 failures fell from 10 to 2 and L4 passes rose
from 1 to 9 (most of the rest have no diff to judge: about 25 of the
historical transactions no longer simulate against today's state, which the
verdict states). The two left are correct: a request that does not name one of
the transaction's accounts, and a simulation that failed. An intermediate run
also showed an undescribed instruction moving tokens refused, and an extension
this build could not name — the next fix.

**Token-2022 extension types 24–28** (ConfidentialMintBurn, ScaledUiAmount,
Pausable, PausableAccount, PermissionedBurn) were unknown to this build and
blocked as unknowns; one live transaction carried `PausableAccount`. They are
now classified from the upstream enum: a confidential mint/burn configuration
with the other confidential extensions (inert only when untouched), the other
four as informational — none redirects value or changes an amount a transfer
moves, and a pause makes the transfer fail, which the simulation shows.

### 2.9 The rest of the list

- **L4 without a diff is `Inconclusive`.** The structural fallback — the
  manifest's prose against account flags — reported `Passed` when no state
  was observed. It now says "State not observed … a consistency check on the
  declarations, not a verification of state"; a structural contradiction still
  fails the layer. No verdict moves: only a `Failed` L4 ever entered the math,
  and the missing diff is its own residual.
- **The synchronous `verify`** drives one process-wide runtime built on first
  use (it built a multi-thread runtime per call: ~345 ms in a debug build,
  and an RPC client's pooled connections belonged to a runtime that was then
  dropped). Called inside an async runtime it now refuses with an error naming
  `verify_async` instead of panicking.
- **The JSON corpus builder reads v1.** Its layout was checked against a real
  mainnet response (slot 449805525, committed as
  `tests/fixtures/real_mainnet_v1.json`): the legacy shape plus
  `transactionConfig`, no lookup tables. A "v1" message carrying lookups is
  refused.
- **Real fee-mint evidence** gains a third phase: every fetched transaction of
  a fee-bearing mint — swaps included, which phases 1–2 must skip — is replayed
  whole by Graphite's own replay from the chain's pre-balances and must end at
  its post-balances for every account of the mint.

## 3. Findings

| ID | Finding | Severity | Reproduced | Fix | Regression test |
|---|---|---|---|---|---|
| **F-21-01** | The write direction of the privilege check read Solana's per-MESSAGE writability as an instruction-level escalation: 342 unexplained and 451 sibling-explained flags on 16,414 executed instructions, each a blocking `AccountIdentityMismatch` | P2 (false refusal, fail-closed) | Grounding script over the sample; mock-RPC pipeline tests | Sibling-declared writes explain the flag; any other is decided by the diff (observed and unchanged, or it blocks); the signer direction unchanged | `round21_open_list::a_writable_flag_is_not_a_write` (5) |
| **F-21-02** | 105 manifest instructions drifted from their programs' on-chain IDLs. Pump.fun buy/sell/v2 had the seller in slot 0 (58 executed trades refused as "signer does not sign"); Jupiter v2 routes pinned `destination_token_program` to Token-2022 only and two token-ACCOUNT slots to program ids (113 identity refusals); System `AdvanceNonceAccount` declared the nonce account a signer (371 of 371); Raydium AMM v4 swaps had one layout for two | P2 (false refusals; PDA and pinned-address checks on the wrong slot) | `r21_drift.py` against cached on-chain IDLs; `r21_ground.py` against executed instructions | Rebuilt where names disagree by position, prefix-corrected where the IDL only adds trailing accounts real traffic does not pass; `account_layouts` for alternate layouts | `round21_open_list::manifests_match_the_programs` (5) |
| **F-21-03** | Token-2022 withheld-fee withdrawals, several fee-bearing transfers into one account, and accounts that send and receive were refused | Coverage | Unit + mock-RPC tests | Replay of the executed Token-2022 instructions, exact against the post-state | `round21_open_list` (fee replay, 14) |
| **F-21-04** | The epoch was not read: either schedule was accepted, and a pending increase was disclosed whatever the transaction's lifetime | P3 | Unit tests | `getEpochInfo`, the exact schedule for the simulated epoch, the pending one judged against the landing window | `with_the_epoch_read_only_that_epochs_schedule_is_accepted`, `a_pending_increase_is_judged_against_the_transactions_lifetime`, `a_pending_majority_fee_blocks_only_when_it_can_be_paid`, `pipeline::graphite_reads_the_epoch_and_judges_the_pending_schedule` |
| **F-21-05** | The diff-only fee statement said "X was transferred into this account" — a per-transfer attribution the diff cannot know: with the fee cap, an account that received 1,000,000 and sent 300,000 read as one 700,000 transfer | P3 (a verdict saying more than it knew) | `an_account_that_sends_and_receives_is_replayed` | The statement says it is the diff's arithmetic | same; `round20_transfer_fee::an_honest_fee_bearing_transfer_is_modelled_and_stated` |
| **F-21-06** | A transfer hook naming no program, untouched confidential-transfer state, and a mint's unchanged standing powers blocked every transaction they appeared in | P2 (false refusal, fail-closed) | Unit tests | Judged by what happened; the mint of every extension-bearing account fetched | `extensions_judged_by_what_happened` (7) |
| **F-21-07** | A permanent delegate moving tokens out of an account it does not own was not detected when the mint was read-only in the transfer — the extension was never scanned | P3 | `a_permanent_delegate_moving_someone_elses_tokens_is_critical` | Critical `Token2022PermanentDelegateExercised`, from the executed instructions and the fetched mint | same |
| **F-21-08** | Check 2 blocked every token `CloseAccount`, including the swap's own self-refunding wrapped-SOL cleanup (1,367 rows of the sample name one) | P2 (false refusal, fail-closed) | `structural_checks_read_the_bytes` | Exempt from Check 2 and Check 10 only when both positions are read from the bytes and equal, and for a sibling only when every close in the message refunds | `a_close_that_refunds_its_own_authority_is_not_a_drain`, `a_close_that_pays_someone_else_still_blocks`, `one_draining_close_keeps_every_sibling_close_blocked`, `a_declaration_cannot_claim_a_refund_the_bytes_do_not_show` |
| **F-21-09** | Both account-count heuristics (Check 3's ratio, Check 3b's STMT count) counted read-only remaining accounts as account proliferation (443 PumpSwap blocks in one sample) | P2 (false refusal, fail-closed) | `structural_checks_read_the_bytes` | Writable extras counted by both when the privileges are the bytes' | `read_only_remaining_accounts_are_not_account_proliferation`, `writable_remaining_accounts_still_are` |
| **F-21-10** | A transaction's priority fee was not read: a v1 header's, or Compute Budget instructions', and nothing held a requested fee to the plausible ceiling without an RPC | P3 | `compute_budget` tests | `scope.compute_budget`; `ExcessivePriorityFee` | `compute_budget` (3), `round19_v1_transactions::the_v1_header_is_the_compute_budget` |
| **F-21-11** | L4's structural fallback reported `Passed` without observing any state | P3 (a layer saying more than it knew) | `plugin_framework`, `l4_without_a_diff` | `Inconclusive`, and says what it checked | `l4_without_a_diff::a_structural_check_without_a_diff_is_inconclusive_not_passed`; `plugin_framework::test_protocol_plugin_enables_l4_for_unknown_program` |
| **F-21-12** | The synchronous `verify` built a multi-thread runtime per call (~345 ms debug; the Round 9 timing bound flaked under load) and panicked inside an async runtime | P3 | `sync_verify` | One shared runtime; refuses inside a runtime | `sync_verify::inside_a_runtime_it_refuses_instead_of_panicking`, `::concurrent_callers_share_one_runtime` |
| **F-21-13** | The JSON corpus builder skipped v1 | Coverage | — | Layout checked against a real response, enabled | `live_corpus::tests::tx_to_input_reads_a_real_version_1_transaction` |
| **F-21-14** | L4's pre-state lamports came from a read at a different slot than the simulation: `LamportsNotConserved` on busy accounts (4 of 40 live transactions) | P2 (false refusal, fail-closed) | Live mainnet RPC run | Pre-state lamports from the simulation's own `preBalances` | `a_writable_flag_is_not_a_write::a_pre_state_read_a_slot_late_does_not_break_conservation` |
| **F-21-15** | L4 checked the transaction-wide diff against the primary instruction's accounts only: every sibling's own change was `DiffAccountNotInInstruction` (10 of 40 live) | P2 (false refusal, fail-closed) | Live mainnet RPC run | `StateDiff::transaction_accounts` from the bytes and the resolved tables | `a_change_another_instruction_makes_is_not_a_diff_that_fails_to_correspond` |
| **F-21-16** | Accounts the transaction marks read-only were diffed, and slot skew showed as a write to them | P2 (false refusal, fail-closed) | Live mainnet RPC run | Not diffed | `a_writable_flag_is_not_a_write::a_read_only_account_is_not_diffed_for_skew_to_show_on` |
| **F-21-17** | Token-2022 extension types 24–28 were unknown and blocked | Coverage | Live mainnet RPC run (`PausableAccount`) | Classified from the upstream enum | `token2022_extensions::every_named_discriminant_has_the_expected_classification` |
| NOT A FINDING | Orca's and part of Kamino's on-chain IDLs list trailing accounts executed transactions do not pass | — | `r21_ground.py`: 11-account executed Orca swaps against a 12-account IDL | The IDL is not adopted past what real traffic shows — the lower-level invariant is that a manifest describes the program AS IT RUNS | — |

## 4. Real traffic

Three samples of whole finalized mainnet blocks, from three days — the
2026-09-23 sample Rounds 19–20 used (19,458 transactions), one fetched
2026-09-25 (10,019) and one fetched for this round on 2026-09-27 (10,465):
**39,942 transactions, 39,857 verified**, every one artifact-bound through the
whole pipeline. Each sample was run against Round 20's code (`f47db5a`,
`git archive`'d into a separate tree) and this round's, and the verdict files
diffed row by row. The 2026-09-23 baseline reproduced Round 20's recorded
verdicts byte for byte. This harness attaches no RPC, so every rule that needs
an observation — the writable-flag rule's diff, the fee replay, the epoch —
takes its no-observation branch here, and nothing approves.

| | 2026-09-23 | 2026-09-25 | 2026-09-27 |
|---|---:|---:|---:|
| verified | 19,440 | 9,973 | 10,444 |
| parse failures / verify errors | 0 / 0 | 0 / 0 | 0 / 0 |
| risk Clear, Round 20 → 21 | 11,960 → **13,163** | 5,800 → **6,575** | 6,600 → **7,175** |
| identity / privilege blocks | 519 → **155** | 249 → **62** | 240 → **82** |
| Check 2 (risky-instruction table) | 1,370 → **72** | 833 → **48** | 678 → **54** |
| verdicts changed | 1,429 | 866 | 690 |
| … Blocked → Clear | **1,203** | **775** | **575** |
| … Clear → Blocked | **0** | **0** | **0** |
| approvals | 0 → 0 | 0 → 0 | 0 → 0 |

Every changed verdict is either Blocked → Clear (2,553) or Blocked → Blocked
with a different finding named (432). **No verdict became stricter, and none
moved without a named cause.** The 2,553 attributed to the finding that
disappeared:

| Finding removed | Transactions |
|---|---:|
| a self-refunding `CloseAccount` sibling (Check 2, then Check 10) — alone | 598 |
| … together with read-only remaining accounts (Check 3 / 3b) | 1,090 |
| … together with the writable-flag rule and read-only remaining accounts | 555 |
| the writable-flag rule / the manifest signer layout, alone or with the close | 142 |
| a pinned address or PDA on the wrong manifest slot, alone or with others | 158 |
| read-only remaining accounts alone | 10 |

Two refinements came out of this measurement and are part of the round: the
first run showed the `CloseAccount` exemption undone by Check 10 (every
sibling carries no intent, so a high-risk class blocked it anyway) and the
PumpSwap refusals moving from Check 3 to Check 3b's STMT count. Both now apply
the same observation, each with its own deliberate break (B21, B22).

The 155 / 62 / 82 identity-and-privilege blocks that remain are what this
harness cannot observe: an over-privileged account with no RPC diff to show
it unchanged, and pinned-address mismatches on programs whose manifests were
not grounded this round. With an RPC attached the first class is decided by
the diff.

### The fee model against the chain

`tests/mainnet_transfer_fee_live.rs` against the public mainnet RPC. The
2026-09-25 and 2026-09-27 samples happen to contain no fee-bearing mint; the
2026-09-23 sample contains three, and the test also reads each one's recent
history:

| | |
|---|---:|
| isolated transfers checked against the chain's own balances (phases 1–2) | 4 (3 charged a fee), 0 mismatches |
| **whole transactions replayed by Graphite's own replay (phase 3, new)** | **31** |
| … transfers in them | 40 |
| … transactions with several transfers of the fee mint — refused before this round | **8** |
| … ending exactly at the chain's post-balances for every account of the mint | **31 of 31** |
| refused as unrecordable (a CPI moved the mint through an account the chain's token-balance record does not list) | 3 |

Phase 3 is what the Round 20 evidence could not be: phases 1–2 must skip any
transfer whose destination another instruction touches — which is most of a
fee-bearing token's traffic, because it moves inside swaps. The replay takes
the transaction whole.

### Live RPC

`tests/mainnet_live_rpc.rs`, one transaction at a time against the public
mainnet RPC (Graphite's own simulation and state reads), 40 transactions of the
2026-09-27 sample, run four times as the L4 fixes of §2.8 landed:

| | first run | final run |
|---|---:|---:|
| invariant violations | 0 | **0** |
| L4 Failed | 10 | **2** |
| L4 Passed | 1 | **9** |
| L4 Inconclusive (no diff: 25 of the 40 no longer simulate against today's state) | 29 | 29 |
| approved | 0 | 0 |

The two left are correct refusals: a request that describes the transaction
without naming one of its accounts (`ArtifactAccountsNotDescribed`), and a
transaction whose simulation now fails. Which of the 40 still simulate depends
on the chain's state at the moment of the run, so the counts between runs are
not a controlled comparison — the per-cause disappearance in §2.8 is.

## 5. Deliberate breaks

Each fix reverted once in place (a byte copy restored afterwards), and the
test that pins it run against the broken build. A break is caught when that
test FAILS. **25 of 25 caught, no residue** (`graphite-r19-work/r21_breaks.py`
through `r21_breaks5.py`).

| Break | Test that failed |
|---|---|
| B01 the synchronous `verify` does not refuse inside a runtime | `sync_verify::inside_a_runtime_it_refuses_instead_of_panicking` |
| B02 L4's fallback says `Passed` | `l4_without_a_diff::a_structural_check_without_a_diff_is_inconclusive_not_passed` |
| B03 no replay | `several_transfers_into_one_account_are_replayed_and_stated` |
| B04 a withdrawal from the mint moves nothing | `a_withdrawal_from_the_mint_is_replayed_and_disclosed` |
| B05 the epoch ignored | `with_the_epoch_read_only_that_epochs_schedule_is_accepted` |
| B06 a pending schedule not bounded by the lifetime | `a_pending_increase_is_judged_against_the_transactions_lifetime` |
| B07 the executed list deserialisable from a request (first as `default` alone — refused by the compiler, the type has no `Deserialize`; then with the derive added) | `a_request_cannot_supply_the_executed_list_or_the_epoch` |
| B08 an over-privileged account observed CHANGED passes | `observed_changed_it_blocks` |
| B09 an unobserved over-privileged account passes | `unobserved_it_still_blocks` |
| B10 the signer direction deferred like the write direction | `a_declared_signer_that_does_not_sign_still_blocks` |
| B11 alternate layouts ignored | `a_17_account_raydium_swap_resolves_against_its_own_layout` |
| B12 the priority fee unchecked | `an_implausible_priority_fee_blocks_and_every_scope_states_the_budget` |
| B13 a hook naming no program not inert | `a_transfer_hook_that_names_no_program_is_inert` |
| B14 a permanent delegate's exercise unseen | `a_permanent_delegate_moving_someone_elses_tokens_is_critical` |
| B15 every close counted as refunding | `a_close_that_pays_someone_else_still_blocks` |
| B16 one refunding close exempts every sibling | `one_draining_close_keeps_every_sibling_close_blocked` |
| B17 writable remaining accounts uncounted (Check 3) | `writable_remaining_accounts_still_are` |
| B18 v1 JSON skipped again | `live_corpus::tests::tx_to_input_reads_a_real_version_1_transaction` |
| B19 pump.fun's manifest back to Round 20's | `pump_fun_buy_and_sell_are_the_programs_layouts` |
| B20 the diff-only statement claims a per-transfer attribution | `an_account_that_sends_and_receives_is_replayed` |
| B21 Check 10 blocks a self-refunding sibling close | `a_self_refunding_sibling_close_is_not_a_drain` |
| B22 Check 3b counts read-only remaining accounts | `read_only_remaining_accounts_are_not_account_proliferation` |
| B23 pre-state lamports not aligned to the simulation | `a_pre_state_read_a_slot_late_does_not_break_conservation` |
| B24 L4 correspondence against the primary instruction only | `a_change_another_instruction_makes_is_not_a_diff_that_fails_to_correspond` |
| B25 read-only accounts diffed again | `a_read_only_account_is_not_diffed_for_skew_to_show_on` |

Three tests were strengthened while writing the breaks, because the first
versions would have passed a broken build: the signer-direction test now makes
the unsigned authority writable and observed unchanged (so only the signer
rule can block it), and the close and drainer helpers now recognise Check 10's
and Check 3b's findings as well as Check 2's and Check 3's.

## 6. What was verified

| Leg | Result |
|---|---|
| `cargo fmt --check` | clean |
| `cargo clippy -D warnings` — all features, featureless lib, cli-only (`--locked`) | clean in all three |
| `cargo test --locked --all-features` | **1,707 passed, 0 failed, 15 ignored** (was 1,652 / 15) |
| `cargo test --locked --no-default-features --lib` | **328 passed, 0 failed, 1 ignored** (was 327) |
| `cargo test --locked --no-default-features --features cli` | **1,480 passed, 0 failed, 3 ignored** — Round 20's timing flake in this leg is gone with the shared runtime |
| SAK integration (TypeScript) | 119 passed; `tsc --noEmit` clean; the cross-language corpus re-emitted byte-identical |
| TypeScript SDK | 28 passed, 4 skipped (live-server tests, run in CI's container job); `tsc` clean |
| Go SDK | `go vet` and `go test` pass |
| Python layer | 30 passed (the wall-clock perf smoke deselected while cargo held the machine; it is unaffected by this round) |
| Deliberate breaks (§5) | **25 of 25 caught**, no residue |
| Mainnet, three days, Round 20 vs Round 21 (§4) | 39,857 verified; 0 parse failures, 0 verify errors; 2,553 Blocked → Clear, 0 Clear → Blocked; 0 approvals before and after (no RPC in that harness) |
| Live mainnet RPC, 40 transactions (§4) | 0 invariant violations; L4 failures 10 → 2, both correct |
| Real fee mints (§4) | 31 of 31 whole transactions replayed exactly (40 transfers, 8 with several of the mint); 4 isolated transfers, 0 mismatches |
| Manifest grounding (§2.4) | "declared signer not signed" 427 → 0 over 16,414 executed instructions; clean instructions 15,277 → 15,690; no new account-count shortfall |

Every public-RPC read was paced and read-only; nothing was signed or sent, and
no key, wallet or fund was touched. This is internal engineering work, not an
independent audit.

## 7. Still open

- **The drainer heuristic is still the coverage boundary.** 84–87% of verified
  transactions in the three samples call a primary program with no manifest,
  and an unmanifested program that touches three or more accounts is refused
  (Check 3: 5,748 / 3,146 / 2,997). That is the fail-closed posture the design
  chose at the edge of what Graphite knows; the way to move it is manifests,
  grounded as in §2.4, not a looser heuristic.
- **Manifests not grounded this round.** The drift checker compares against
  the cached on-chain IDLs of 108 programs; programs without an Anchor IDL
  (Raydium AMM v4, the SPL programs, System) were checked against the runtime
  only where the sample showed a refusal. Instructions the sample never
  executed — most of Kamino's rebuilt list, several Orca admin instructions —
  are grounded in their IDL alone.
- **The observation-based rules need an RPC.** Without one, an over-privileged
  account, a fee-bearing transfer and a pending fee schedule take the
  no-observation branch: they block, or state Round 20's arithmetic.
- **Transfer hooks that run a program, confidential transfers that move
  encrypted balances, and unknown extensions still block.** Encrypted balances
  are not modelled, and a hook program is arbitrary code.
- **The reference bridge builds legacy messages** (web3.js 1.x cannot
  represent v1). A client capability, not a Core property: v1 bytes from any
  other builder are verified.
- **The landing window is an assumption.** `FEE_LANDING_MARGIN_SLOTS` (9,000
  slots) bounds when a blockhash transaction can still land; a network stall
  longer than an hour near an epoch boundary is outside it.
- **Owner decisions:** the independent third-party audit and branch
  protection on `main`.

## 8. Files

- **Core:** `src/state_diff.rs` (replay, epoch, extension judgement, permanent-delegate exercise, `Token2022Powers`, `replay_fee_amounts`), `src/verification.rs` (executed-instruction list, epoch context, deferred write escalations, self-refunding closes, writable extras, shared sync runtime, L4 fallback status, the compute-budget block and scope field, mint fetch for every extension-bearing account), `src/risk_engine.rs` (Check 2 / Check 10 / Check 3 / Check 3b), `src/manifest.rs` + `src/manifest_registry.rs` + `src/account_resolution.rs` (`account_layouts`, `layout_for`, validation), `src/tx_artifact.rs` (`compute_budget_request`), `src/rpc_client.rs` (`getEpochInfo`), `src/live_corpus.rs` (v1 JSON), `src/cli.rs` (struct literal).
- **Manifests:** `protocols/{pump-fun,jupiter-v6,kamino-lending,marginfi-v2,meteora-dlmm,orca-whirlpools,raydium-clmm,squads-v4,raydium-amm-v4,system-program}.json`; the regression corpus regenerated from them (`fixtures/corpus/*`); `docs/protocol-coverage.md` re-rendered.
- **Tests:** `tests/round21_open_list.rs` (new, 50), `tests/fixtures/real_mainnet_v1.json` (new, a real mainnet v1 `getTransaction`), `tests/round19_v1_transactions.rs` (+1), `tests/mainnet_transfer_fee_live.rs` (whole-transaction replay phase), `tests/mainnet_live_rpc.rs` (`GRAPHITE_MAINNET_SHOW_L4`), `tests/token2022_extensions.rs` (types 24–28), `tests/plugin_framework.rs`, `tests/round20_transfer_fee.rs`, `tests/deep_extreme_tests.rs` and a Jupiter unit fixture (the fixtures now carry what the programs require), and struct-literal updates across the older suites.
- **Clients and schema:** `schemas/verification-result-v1.json`, `sdk/typescript/src/types.ts`, `sdk/go/graphite.go` (`compute_budget`).
- **Docs:** this report; `docs/CURRENT.md`, `README.md`, `SECURITY.md`, `ARCHITECTURE.md`, `ROADMAP.md`, `CONTRIBUTING.md`, `graphite-core/README.md`, `graphite-core/CHANGELOG.md`, `tools/mainnet-sample/README.md`.
- **Work-dir tooling (not shipped):** `r21_drift.py`, `r21_ground.py`, `r21_rebuild.py`, `r21_handfix.py`, `r21_breaks.py`, `r21_breaks2.py`, `r21_diff.py`, `fetch_sample_r21.py` and the three samples' verdict and reason files, in `C:\Users\Administrator\graphite-r19-work`.
