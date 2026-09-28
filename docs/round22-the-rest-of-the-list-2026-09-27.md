# Round 22 — the rest of the list

**Date:** 2026-09-27 (finished 2026-09-28) · **Base:** `9284385` (Round 21) · **Scope:** every item
Round 21 left open that code can close, measured against three days of mainnet,
per-program mainnet traffic and the live chain; and the root causes that work
turned up.

Internal engineering work. Not an independent audit and not a
certification; the third-party audit remains the owner's decision.

## 1. What was asked, and what it turned out to need

Round 21 ended with seven open items: the drainer heuristic at the coverage
boundary, manifests not grounded in traffic, the observation rules needing an
RPC, transfer hooks that run a program (and confidential transfers) blocking,
the reference bridge building legacy messages only, the fee model's landing
window being an assumption, and the owner's two decisions. The owner asked for
the remaining open issues to be closed.

Each was measured before it was touched, and the measurements changed what
"closing" meant:

- **The coverage boundary is mostly not a coverage problem.** 11,902 of the
  three samples' verdicts are refused by the drainer heuristic. **71% of them
  (8,462) come from programs that every transaction in three days was signed
  by five or fewer fee payers** — bots running their own programs, none with a
  published IDL, which no wallet user signs. The rest split into programs with
  no IDL (no manifest can be grounded), and about 490 refusals of programs
  Graphite DOES describe. Those 490 were root-caused one by one (§2.4–2.7), and
  none of them was the heuristic being wrong: each was a manifest or a
  privilege reading that did not describe what the program does. The heuristic
  itself stays: for code Graphite has no description of, a simulation does not
  bind what the code does at landing (§3, NOT A FINDING).
- **Grounding needed traffic the block samples do not have.** The samples hold
  whatever happened to land in 24 blocks; an instruction a program is rarely
  called with never appears. For every manifested program Graphite fetched its
  own recent executed transactions from the public RPC (paced, read-only) and
  grounded every manifest instruction that executed. That surfaced wrong
  manifests the samples never exercised — the Stake program's, the BPF
  Upgradeable Loader's — and a class of false refusal no sample had enough of to
  notice: Anchor's optional accounts.
- **A transfer hook's reach is not arbitrary.** Its code is; what it can touch
  is fixed by the bytes Token-2022 hands it. That is a proof Graphite can make
  from the transaction, at simulation and at landing alike (§2.1).
- **The landing window was an assumption with no sound replacement.** A
  blockhash lives 150 blocks; epochs are counted in slots; a skipped slot has
  no block. No count of slots bounds when a blockhash transaction lands. The
  assumption is removed rather than refined (§2.2).

## 2. What changed

### 2.1 A transfer hook is bounded by the bytes, not by its code

Round 21 made a transfer hook that names no program inert and left one that
runs a program blocking: "a hook program is arbitrary code". Its code is; what
it can reach is not. Token-2022 invokes the hook with the transfer's source,
mint, destination and authority **read-only and unsigned**
(`spl_transfer_hook_interface::instruction::execute`, checked against the
upstream source for this round), and appends the extra accounts its validation
list names — which it can only take from the accounts the transfer itself was
handed, at no more privilege than the transaction gives them, because the
runtime refuses a CPI that escalates. So, whatever the hook does — at
simulation or at landing — it can hold a signature only if one of those
accounts signs the transaction, and write only what the transaction marks
writable; and of those it can move value only out of accounts it owns, or with
a signature or a delegation over another program's account.

`state_diff::transfer_hook_reach` makes that proof per mint, from Graphite's
own observations:

- every executed Token-2022 instruction that can invoke the hook for the mint
  (`TransferChecked`, `TransferCheckedWithFee` — the plain `Transfer` fails
  for a hook account — and, conservatively, every account of a confidential
  transfer) is taken from the executed list Graphite builds from the bytes and
  `innerInstructions`;
- what Token-2022 can hand the hook is every account after the four transfer
  accounts (a multisig's signers ride there too, and fail the rule);
- none of those may sign the transaction (`TransactionPrivileges`, from the
  header and the resolved lookup tables); every one the transaction marks
  writable must be owned by the hook program in Graphite's own pre-state.

When that holds, the hook extension is inert, with the reason stated; when any
account breaks it, the extension blocks and names the account ("hands it
<wallet>, which signs this transaction — the hook would hold that signature").
Without the executed list, the privileges, or an account's observed owner, it
blocks as before. A hook program the simulator saw Token-2022 invoke — and only
Token-2022, established from `stackHeight` — is then a warning in the risk
layer ("a Token-2022 transfer hook, invoked only by Token-2022 — …"), not the
primary calling an unknown program; one whose caller cannot be established is
still judged as that call.

The executed Token-2022 list used to be built only when the diff involved a
transfer fee. It is now built whenever the bytes are readable, so the hook rule
and Round 21's untouched-confidential-state rule apply to every Token-2022
mint.

Honest scope: hook-bearing transfers are rare in the samples (one top-level
`TransferChecked` passing extra accounts in 39,942 transactions; hooked
transfers made by CPI are not visible without `innerInstructions`). The rule
is pinned by unit tests and by the pipeline over a loopback mock RPC, where a
hooked `TransferChecked` now clears risk and passes L4.

### 2.2 The landing window is not assumed

Round 21 read the epoch and judged a pending fee schedule only when the
transaction could still land in the epoch it starts — bounded by an assumed
`FEE_LANDING_MARGIN_SLOTS` (9,000 slots). A blockhash is valid for 150
**blocks**; epochs are counted in **slots**; a skipped slot has no block. No
count of slots bounds when a blockhash transaction can land, so the margin was
an assumption about the network, not a fact about the transaction. It is
removed: a pending schedule is always one the transaction can pay, and is
judged — disclosed, and blocking when it would take more than half of a
transfer, exactly as for a durable nonce. `FeeEpochContext` keeps the one
observation (the simulated epoch, which decides the schedule the simulation
paid) and whether the transaction advances a nonce, which only changes the
wording. The cost is a warning on transfers of mints whose issuer has
scheduled a fee change; a pending majority fee blocks them for the two epochs
before it takes effect.

### 2.3 What the runtime lets a message write

Graphite read an account's writability from the message header alone. The
runtime does not: agave's `is_maybe_writable` demotes a key the header marks
writable to read-only when it is a sysvar or a builtin program, or when an
instruction calls it as a program and the upgradeable loader is not among the
message's accounts. `tx_artifact::runtime_writable` now applies that rule when
a message is parsed — the always-demoted set (the builtin programs and sysvars
agave has demoted since before its reserved-key set; later, feature-gated
additions are deliberately left out, the stricter reading), and invoked
program ids unless the loader is present or lookup tables could hold it. Every
consumer of the message's privileges — L1's privilege check, the
writable-extras count of Checks 3/3b, the accounts L4 diffs, the hook proof —
reads what the runtime enforces. On the samples this removed the "declared
read-only, writable in the transaction" flags on invoked program ids that
Anchor passes for absent optional accounts (Meteora DLMM, DAMM v2, DBC).

### 2.4 Anchor's optional accounts

An Anchor program is told an optional account is **absent** by being passed its
own program id in that slot. Graphite's manifests had no notion of optional, so
an absent account was judged as a present one: a pinned slot holding the
program id was an expected-address mismatch (Jupiter's `token_2022_program`), a
declared signer holding it was "declared signer does not sign" (Tensor's `bid`
cosigner, the Perpetuals keeper, OrderBook's token authority). Manifest
accounts now carry `optional`, set from each program's own on-chain IDL where
the IDL says so and the names agree (667 accounts across 40 manifests), and —
where a legacy-format IDL does not record it — from executed traffic in which
the program ran successfully with its own id in the slot (9 slots of 7 instructions: Tensor
`bid.cosigner`, Jupiter DCA `transfer.intermediateAccount`, the swap
orchestrator's two destination slots, Bubblegum `bubblegumSigner` and
`collectionAuthorityRecordPda`, Limo's `pdaReferrer`, OpenBook
`consumeEventsAdmin`). Account resolution treats the program id in an optional
slot as that known constant (`role: "absent"`, identity `Constant`): nothing to
derive, nothing pinned to compare, nothing it could sign — its writable flag is
still compared. Any other address in an optional slot is checked exactly as
before, and the program id in a slot that is not optional is still a mismatch.

### 2.5 Manifests grounded in each program's own traffic

The block samples ground only what happened to land in them. For every
manifested program Graphite fetched that program's own recent successful
transactions (`getSignaturesForAddress` + `getTransaction`, one request at a
time, paced, read-only): **2,998 transactions of 128 programs**, grounded with
the three samples. Findings, each fixed and pinned:

- **Jupiter's shared-account routes** (`sharedAccountsRoute` and its four
  variants) and `claimToken` pinned their `program_*_token_account` slots —
  token ACCOUNTS — to the token PROGRAMS: every such route was an identity
  mismatch. Present since at least Round 18; Round 21 fixed the v2 routes and
  missed these (13 slots).
- **The Stake program's manifest was a placeholder.** Eleven of fifteen
  instructions carried the same two accounts (`user_authority` as a signer,
  `program_account`) and the state change "Stake Program instruction";
  `DelegateStake` declared the stake account a signer; `Withdraw` put the
  withdrawer where the recipient goes. Rebuilt from `solana-program/stake`'s
  interface: the sysvar-carrying layout executed traffic sends as primary, the
  current minimal layout as an alternate where the lengths do not collide,
  sysvar and config slots pinned, real state changes, and `MoveStake` /
  `MoveLamports` added. `GetMinimumDelegation`, which takes no accounts and
  only writes return data, is no longer described — an unknown instruction
  blocks. Three older synthetic tests that called a "legitimate" delegation or
  withdrawal with arbitrary addresses in the sysvar slots — transactions the
  program itself would reject — now use the real sysvars.
- **The BPF Upgradeable Loader's** `Close` had its authority and recipient
  swapped and `DeployWithMaxDataLen` an order the program does not use; rebuilt
  from `loader-v3-interface`, with optional trailing accounts as alternates and
  `ExtendProgram` / `SetAuthorityChecked` added.
- **System `CreateAccountWithSeed`** takes the base as a third account only
  when it is not the funding account (18 executed two-account calls); **SPL
  Stake Pool** `WithdrawSol` / `DepositSol` take their SOL authorities as
  optional trailing accounts. Alternate layouts added.
- **Sixteen instructions take a variable account list** — the swap
  orchestrator's and OKX's routes, Debot's router, Raydium CLMM `swap_v2` (tick
  arrays), Kamino `refreshObligation` (reserves) and vault
  `investWithMaxAmount`, pump.fun `distribute_fee_to_holders`, SAGE
  `fleetStateHandler`, TukTuk `run_task_v0`, Zap `zap_out`, and three oracle
  instructions (Doves, CC VRF, CCIP `commit_price_only`). The criterion is the
  program's own traffic: at least ten executions, the account count varies,
  and at least a quarter of them pass more than two writable accounts past the
  layout. They were refused as account proliferation; they are declared
  `variable_accounts`, like Jupiter's routes.

After the fixes, **45,253 of 45,282 executed manifest instructions resolve
clean**. The 29 that do not are named in §3 and §4. 383 of the 3,195 manifest
instructions have now been observed executing; the other 2,812 are grounded in
their programs' published interfaces alone, because nobody called them in the
traffic this round could read.

### 2.6 The coverage boundary, measured

| | three samples |
|---|---:|
| verdicts refused by the drainer heuristic (Round 21) | 11,902 |
| … from programs every transaction of which was signed by five or fewer fee payers | **8,462 (71%)** |
| … from other programs with no manifest | about 2,950 |
| … from programs with a manifest | about 490 |

The bot-signed programs publish no IDL (probed on-chain for the 30 largest).
Of the programs with a published IDL and real user diversity behind the
refusals — the swap orchestrator, OKX, Raydium LaunchLab, Tensor, Star Atlas —
all were already manifested: their refusals were the manifest and privilege
defects of §2.3–2.5, now fixed. The PumpSwap, LaunchLab and Tensor refusals
that remain in the conformance harness are lookup-table transactions judged
with no RPC: one extra account arrives through a table, its privilege cannot be
read without resolving the table, and the count rule falls back to the stricter
reading. Against the live chain, with the tables resolved, **10 of 12 real
PumpSwap trades are risk-Clear**; the other two are exactly the ones whose
tables could not be resolved (`LookupTablesUnresolved`) — the fail-closed
branch working.

### 2.7 The bridge builds v0

`BoundTransaction.build({ version: 0, addressLookupTables })` compiles a v0
message through tables the caller has fetched, and `executeSwap` does so when a
payload names `addressLookupTableAddresses` — aborting if any table cannot be
read. Every Round 16–19 guarantee holds for it: one object verified, signed and
submitted; the digest recomputed before signing; the signer set read from the
message; the signed bytes required to carry the verified message. The request
declares `uses_versioned_transaction` / `lookup_table_count` from the bytes.
Tables given for a legacy message are refused, not ignored. The bridge's v0
bytes are pinned byte-for-byte to the cross-language corpus entry the Rust
parser reads. Version 1 is not built — web3.js 1.x cannot compile it — and the
Core verifies v1 from any builder that can.

### 2.8 Declared siblings are counted like the primary

Round 21 taught the drainer and account-count checks to count only the
WRITABLE accounts past the primary instruction's layout, read from the bytes.
The declared siblings — the other top-level instructions of the same
transaction — were left on the raw count. The first live run of this round
showed what that cost: 8 of 40 real transactions whose primary was a
`SyncNative` were refused by the drainer heuristic on a pool-program
sibling's raw account count. A sibling that L2 has keyed to its instruction in
the bytes now gets the layout its account count selects and the writable
extras counted from the message's own privileges, exactly as the primary
does; the fee payer is not counted, and a node of a caller-declared CPI trace
— which has no bytes behind it — keeps the stricter raw count. Writable extras
still block: they are what a multi-transfer drain needs.

### 2.9 Diagnostics

`tests/mainnet_conformance.rs` gains `GRAPHITE_MAINNET_SHOW_DRAINER` (for each
account-count refusal: the layout length, how many extras arrived through a
lookup table, how many are writable) and `tests/mainnet_live_rpc.rs`
`GRAPHITE_MAINNET_SHOW_RISK` (every refused risk verdict's findings) — the two
readings that localised §2.3–2.6.

## 3. Findings

| ID | Finding | Severity | Reproduced | Fix | Regression test |
|---|---|---|---|---|---|
| **F-22-01** | The fee model stayed silent on a pending schedule whenever the epoch boundary was more than an assumed 9,000 slots away; a blockhash's lifetime is 150 blocks and no slot count bounds it | P3 (an assumption presented as a bound) | Unit tests | Margin removed; a pending schedule always judged | `round21_open_list::a_pending_increase_is_disclosed_with_why_it_can_be_paid`, `a_pending_majority_fee_blocks`, `pipeline::graphite_reads_the_epoch_and_judges_the_pending_schedule` |
| **F-22-02** | A Token-2022 transfer hook that runs a program blocked every transfer of its mint, whatever the transaction let it reach | P2 (false refusal, fail-closed) | Unit tests; mock-RPC pipeline | `transfer_hook_reach` from the executed list, the transaction's privileges and the observed owners; the Token-2022-invoked hook CPI a warning | `round22_remaining` hook tests (11), `pipeline::a_hook_token2022_invoked_and_the_bytes_bound_is_part_of_the_transfer`, `pipeline::a_hook_whose_caller_cannot_be_established_is_judged_as_a_call` |
| **F-22-03** | Jupiter's shared-account routes (five instructions) and `claimToken` pinned their `program_*_token_account` slots — token accounts — to the token programs: every such route was an `AccountIdentityMismatch`. Present since at least Round 18; Round 21 fixed only the v2 routes | P2 (false refusal; a pin on the wrong kind of account) | A real `sharedAccountsRoute` from mainnet slot 449807125 | 13 slots unpinned | `manifests_match_the_programs::the_real_shared_accounts_route_resolves_without_a_mismatch`, `no_token_account_slot_is_pinned_to_a_token_program` |
| **F-22-04** | Anchor's absent optional account (the program's own id in the slot) was judged as a present one: an expected-address mismatch in a pinned slot, "declared signer does not sign" in a signer slot | P2 (false refusal, fail-closed) | The same transaction; executed Tensor bids | `AccountRoleDef::optional` (667 from IDLs, 9 from traffic); the program id in an optional slot resolves as a constant | `manifests_match_the_programs` (5), `tensor_bids_absent_cosigner_is_not_an_unsigned_signer` |
| **F-22-05** | Writability was read from the header alone: invoked program ids, sysvars and builtins the runtime demotes to read-only were "writable in the transaction" | P2 (false refusal, fail-closed) | Mainnet sample (Meteora DLMM, DAMM v2, DBC) | `tx_artifact::runtime_writable` | `runtime_writability` (4) |
| **F-22-06** | Sixteen instructions whose own traffic passes a variable account list (routers, CLMM tick arrays, per-holder / per-feed accounts) were refused as account proliferation | P2 (false refusal, fail-closed) | `r22_remaining_accounts.py` over the samples and per-program traffic | `variable_accounts` where the traffic grounds it | `remaining_account_interfaces_are_declared_variable` |
| **F-22-07** | The Stake manifest was a placeholder on eleven of fifteen instructions and wrong on `DelegateStake` (stake account a signer) and `Withdraw` (withdrawer in the recipient's slot); `MoveStake` / `MoveLamports` missing | P2 (false refusals; checks on the wrong slot; a placeholder in a shipped manifest) | Executed stake instructions in the samples and traffic | Rebuilt from `solana-program/stake`'s interface, grounded in the executed layouts | `native_manifests::no_stake_instruction_is_a_placeholder`, `stake_layouts_are_the_programs` |
| **F-22-08** | The BPF Upgradeable Loader's `Close` swapped authority and recipient; `DeployWithMaxDataLen` was in an order the program does not use | P2 (false refusals; checks on the wrong slot) | Executed loader instructions | Rebuilt from `loader-v3-interface`; `ExtendProgram`, `SetAuthorityChecked` added | `native_manifests::loader_layouts_are_the_programs` |
| **F-22-09** | System `CreateAccountWithSeed` with the funder as base (two accounts) and a stake pool's `WithdrawSol` / `DepositSol` without their optional SOL authority were account-count shortfalls | P3 | Executed instructions | Alternate layouts | `create_account_with_seed_has_its_two_account_layout`, `native_manifests::stake_pool_sol_authorities_are_optional` |
| **F-22-10** | The reference bridge built legacy messages only, so a route needing lookup tables could not be bound | Coverage (client) | — | `BoundTransaction` v0; `executeSwap` reads lookup tables | `bound-transaction.test.ts` (10 v0 tests, one pinning the bytes to the Rust-parsed corpus entry) |
| **F-22-11** | The executed Token-2022 list was built only for diffs involving a transfer fee, so Round 21's untouched-confidential-state rule could never apply to a mint without one | P3 (a rule that could not run) | Code reading | Built for every readable artifact | `pipeline::a_hook_token2022_invoked_and_the_bytes_bound_is_part_of_the_transfer` (it depends on it) |
| **F-22-12** | Declared siblings were judged on the raw account count while the primary counted only writable extras from the bytes: a sibling passing read-only accounts past its layout was refused as a drain | P2 (false refusal, fail-closed) | Live mainnet RPC run (8 of 40 refused on a sibling) | The sibling's layout and writable extras from the bytes, as the primary's | `sibling_writable_extras::read_only_extras_on_a_sibling_are_not_a_drain`, `writable_extras_on_a_sibling_still_block` |
| NOT A FINDING | The drainer heuristic at the coverage boundary | — | 71% of its refusals are programs signed by five or fewer fee payers, none publishing an IDL | For code Graphite does not describe, a simulation does not bind what the code does at landing — the lower-level invariant the heuristic stands on. It stays | — |
| NOT A FINDING | PumpSwap / LaunchLab / Tensor account-count refusals in the conformance harness | — | Live mainnet RPC: 10 of 12 real PumpSwap trades risk-Clear; the 2 others are `LookupTablesUnresolved` | The harness has no RPC; a lookup-table account's privilege cannot be read without the table | — |
| DOCUMENTED LIMITATION | Three published IDLs disagree with their programs' executions: mintfx `transfer` (16 executions), marginfi `lending_account_end_flashloan` (4, one account), Coinflow's instruction `7bac2088…` (not in its IDL) | — | `r22_ground.py`, `r22_slots.py` | Not adopted without a source; those instructions block | — |

## 4. Real traffic

### Three days of mainnet, Round 21 against Round 22

The same three samples as Round 21 (2026-09-23, -25, -27; 39,942
transactions, 39,857 verified), run against Round 21's code (`9284385`,
`git archive`'d into a separate tree — its verdicts reproduced Round 21's
recorded files byte for byte) and against this round's, and the verdict files
diffed row by row, every changed row attributed to the findings that appeared
or went. The harness attaches no RPC.

| | 2026-09-23 | 2026-09-25 | 2026-09-27 |
|---|---:|---:|---:|
| verified | 19,440 | 9,973 | 10,444 |
| parse failures / verify errors | 0 / 0 | 0 / 0 | 0 / 0 |
| risk Clear, Round 21 → 22 | 13,163 → **13,260** | 6,575 → **6,650** | 7,175 → **7,233** |
| `AccountIdentityMismatch` verdicts | 145 → **131** | 57 → **50** | 74 → **66** |
| `Drainer` verdicts | 5,803 → **5,697** | 3,193 → **3,111** | 3,049 → **2,980** |
| verdicts changed | 122 | 89 | 77 |
| … Blocked → Clear | **97** | **75** | **58** |
| … Clear → Blocked | **0** | **0** | **0** |
| approvals | 0 → 0 | 0 → 0 | 0 → 0 |

**230 executed transactions moved Blocked → Clear, none the other way, and no
changed verdict gained a finding** — every one of the 288 changed rows only
lost findings. What they lost:

| Finding removed | Primary program of the refused row | Rows | Fixed by |
|---|---|---:|---|
| Drainer (account-to-change ratio) | swap orchestrator 160, OKX 30, SAGE 28, Jupiter 25 (an orchestrator or OKX sibling), Kamino vault, TukTuk, Zap 1 each | 246 | F-22-06 |
| STMT account count | SAGE 4, CC VRF 3, Perpetuals 1, Doves 1; one row's LaunchLab sibling 1 | 10 | F-22-06, F-22-05, F-22-12 |
| `AccountIdentityMismatch`, expected address | Jupiter shared-account routes | 15 | F-22-03, F-22-04 |
| `AccountIdentityMismatch`, privilege (declared signer unsigned) | Tensor `bid` | 6 | F-22-04 |
| `AccountIdentityMismatch`, privilege (writable flag on an invoked program id) | Meteora DLMM 4, DBC 2, DAMM v2 1 | 7 | F-22-05 |
| `AccountIdentityMismatch`, PDA and expected address on an absent optional account | GMSOL store | 1 | F-22-04 |

F-22-12 (declared siblings counted like the primary) landed after the first
comparison and moved no verdict in the three samples: it removed the
LaunchLab sibling's STMT finding from one row, and a duplicate sibling drainer
finding (LaunchLab or PumpSwap, alongside the same finding on the primary)
from 17 more, all of them still refused on an unmanifested primary. What it
changes in production shows in the live run below, where the siblings' lookup
tables are resolved.

The rest of the drainer refusals are the coverage boundary of §2.6. Of the
identity findings that remain, 268 are "declared read-only, writable in the
transaction, and no pre/post diff observed it" — the no-RPC branch of Round
21's writable-flag rule, which an RPC decides by observing the account — and 2
are PDA mismatches; no expected-address mismatch remains in the three samples.

### Per-program traffic

2,998 executed transactions of 128 manifested programs (the 129th, a program
with no successful recent traffic, returned none), 20–40 per program, fetched
one request at a time with a pause between requests. With the three block
samples that is 45,282 executed top-level instructions a manifest describes;
after the fixes 45,253 resolve with no short layout, no unsigned declared
signer and no demoted declared write. The 29 that do not are the three
drifted IDLs (§3) and two single executions (OpenBook `consume_events` with a
real admin, Wormhole `PostVAA` with an unsigned payer) left as they are.

### Live mainnet RPC

`tests/mainnet_live_rpc.rs` against the public endpoint:

- **PumpSwap** (`GRAPHITE_MAINNET_PROGRAM`, 12 transactions of the 2026-09-27
  sample, before this round's changes): 10 risk-Clear, 2 refused — exactly
  the two whose lookup tables could not be resolved. The conformance
  harness's PumpSwap refusals are its missing RPC, not a production refusal.
- **40 transactions of the 2026-09-27 sample, run twice on 2026-09-28**
  (`GRAPHITE_MAINNET_LIVE_LIMIT=40`, `GRAPHITE_MAINNET_SHOW_RISK=1`), both
  with 0 invariant violations and 0 approvals:

  | | before F-22-12 | the round's final build |
  |---|---:|---:|
  | risk Clear | 24 | **33** |
  | risk Blocked | 16 | **7** |
  | L2 Passed | 40 | 40 |
  | L4 Passed / Failed / Inconclusive | 6 / 3 / 31 | 5 / 3 / 32 |
  | `SimulationFailed` residual | 25 | 31 |

  Eight of the nine that moved are the `SyncNative` transactions refused on
  their PumpSwap (`pAMM…`) sibling's raw account count (F-22-12). The ninth is
  a `TransferChecked` refused in the first run under Round 21's writable-flag
  rule — a declared read-only account writable in the bytes, with no pre/post
  diff observing it — and Clear in the second. That rule depends on what the
  simulation observed, which changes between runs against a moving chain; the
  mechanism for this one transaction was not isolated. The seven still refused
  are a Token-2022 and two SPL Token `CloseAccount`s the bytes do not show
  paying their authority, a three-destination sweep, a SAGE `withdraw`
  sibling with no declared intent, and two drainer refusals of unmanifested
  programs at the coverage boundary (one the primary, one a
  `TransferChecked`'s sibling). The
  sample's transactions are a day old when replayed, so most simulations fail
  on moved state (`SimulationFailed`); the L4 differences between the runs are
  that drift, not a code change.

## 5. Deliberate breaks

Each break is one edit to the fixed code or manifest (a manifest break restores
the Round 21 file), applied, tested against the named test, and reverted. A
break is caught when the named test fails.

| Break | What it undoes | File | Caught by | Caught |
|---|---|---|---|---|
| B01 | a hook handed a signer passes | `src/state_diff.rs` | `a_hook_handed_a_signer_blocks_and_names_it` | yes |
| B02 | a hook's writable account passes whoever owns it | `src/state_diff.rs` | `a_hook_handed_a_writable_account_it_does_not_own_blocks` | yes |
| B03 | an unobserved writable account handed to a hook passes | `src/state_diff.rs` | `a_hook_handed_an_unobserved_writable_account_blocks` | yes |
| B04 | the hook's reach starts one account late (multisig signers skipped) | `src/state_diff.rs` | `a_multisig_signer_in_the_hook_slots_blocks` | yes |
| B05 | only the first transfer of the mint judged | `src/state_diff.rs` | `every_transfer_of_the_mint_is_judged` | yes |
| B06 | a later mint's `Ok` overwrites an earlier `Err` | `src/state_diff.rs` | `the_bounded_map_names_each_hook_program_once` | yes, after the test was strengthened (below) |
| B07 | a hook without a stack height counted as Token-2022's | `src/verification.rs` | `pipeline::a_hook_whose_caller_cannot_be_established_is_judged_as_a_call` | yes |
| B08 | bounded hooks not filtered from the observed callees | `src/verification.rs` | `pipeline::a_hook_token2022_invoked_and_the_bytes_bound_is_part_of_the_transfer` | yes |
| B09 | the executed Token-2022 list built only for a fee again | `src/verification.rs` | the same pipeline test | yes |
| B10 | a blockhash transaction silent on a pending schedule (Round 21's margin) | `src/state_diff.rs` | `round21_open_list::a_pending_increase_is_disclosed_with_why_it_can_be_paid` | yes |
| B11 | the program id is absent in ANY slot, optional or not | `src/account_resolution.rs` | `manifests_match_the_programs::the_program_id_in_a_required_slot_is_a_mismatch` | yes |
| B12 | any address in an optional slot is absent | `src/account_resolution.rs` | `manifests_match_the_programs::an_optional_slot_holding_another_address_is_still_checked` | yes |
| B13 | the absent rule removed | `src/account_resolution.rs` | `manifests_match_the_programs::the_real_shared_accounts_route_resolves_without_a_mismatch` | yes |
| B14 | Jupiter's token-account slots pinned to the token programs again | `protocols/jupiter-v6.json` | `manifests_match_the_programs::no_token_account_slot_is_pinned_to_a_token_program` | yes |
| B15 | `CreateAccountWithSeed`'s two-account layout removed | `protocols/system-program.json` | `create_account_with_seed_has_its_two_account_layout` | yes |
| B16 | Tensor `bid`'s cosigner not optional | `protocols/tcomp-tcmphj.json` | `tensor_bids_absent_cosigner_is_not_an_unsigned_signer` | yes |
| B17 | the swap orchestrator's routes not variable | `protocols/swap-orchestrator-df1ow4.json` | `remaining_account_interfaces_are_declared_variable` | yes |
| B18 | the header's writable flags taken as the runtime's | `src/tx_artifact.rs` | `runtime_writability::an_invoked_program_and_a_sysvar_are_not_writable` | yes |
| B19 | the upgradeable loader ignored | `src/tx_artifact.rs` | `runtime_writability::the_upgradeable_loader_keeps_an_invoked_program_writable` | yes |
| B20 | lookup tables assumed not to hold the loader | `src/tx_artifact.rs` | `runtime_writability::with_lookup_tables_an_invoked_program_stays_writable` | yes |
| B21 | the Stake manifest back to its placeholders | `protocols/stake-program.json` | `native_manifests::no_stake_instruction_is_a_placeholder` | yes |
| B22 | the loader manifest back to its swapped layouts | `protocols/bpf-loader-upgradeable.json` | `native_manifests::loader_layouts_are_the_programs` | yes |
| B23 | the stake pool's optional SOL authorities required | `protocols/spl-stake-pool.json` | `native_manifests::stake_pool_sol_authorities_are_optional` | yes |
| B24 | declared siblings back on the raw account count | `src/verification.rs` | `sibling_writable_extras::read_only_extras_on_a_sibling_are_not_a_drain` | yes |
| B25 | a sibling's read-only extras counted as writable | `src/verification.rs` | the same | yes |
| B26 | a sibling's writable extras not counted | `src/verification.rs` | `sibling_writable_extras::writable_extras_on_a_sibling_still_block` | yes |
| T01 | the v0 digest compared to a stored serialization | `artifact.ts` | `bound-transaction.test.ts` | yes |
| T02 | lookup tables given for a legacy message ignored | `artifact.ts` | `bound-transaction.test.ts` | yes |
| T03 | the v0 signer set read from nothing | `artifact.ts` | `bound-transaction.test.ts` | yes |
| T04 | `instructions()` returns the compiled objects | `artifact.ts` | `bound-transaction.test.ts` | yes |

**B06 was not caught at first.** The test's two mints happened to iterate with
the dirty transfer last, so a later `Ok` had nothing to overwrite. The test now
also runs the reverse order (the dirty mint sorting first), and catches it.

**One regression was caught by an older test, not a break.** The first cut of
the runtime-writability demotion made two frames differing only in the header's
writable count parse identically — `tx_artifact_real::every_byte_of_a_real_transaction_matters`
failed on byte 67. The parse now keeps the header's own statement
(`ArtifactMessage::header_writable`) beside the runtime's, so every byte of a
real transaction still changes the parse.

## 6. What was verified

| Leg | Result |
|---|---|
| `cargo fmt --check` | clean |
| `cargo clippy -D warnings` — all features, featureless lib, cli-only (`--locked`) | clean in all three |
| `cargo test --locked --all-features` | **1,738 passed, 0 failed, 15 ignored** (was 1,707 / 15) |
| `cargo test --locked --no-default-features --lib` | **328 passed, 0 failed, 1 ignored** |
| `cargo test --locked --no-default-features --features cli` | **1,509 passed, 0 failed, 3 ignored** on the final code (was 1,480). The rerun after a comment-only edit to a test file: 1,508 passed and the wall-clock unit test of §7 failed once (58.5 ms against 50 ms); it passed 4 of 5 isolated reruns |
| SAK integration (TypeScript) | 129 passed (was 119); `tsc --noEmit` clean |
| TypeScript SDK | 28 passed, 4 skipped (live-server tests, run in CI's container job); `tsc` clean |
| Go SDK | `go vet` and `go test` pass |
| Python layer | 30 passed; the wall-clock perf smoke (at least 10,000 parses/s) measured 5,152/s with this machine at 100% CPU from other applications. The Python layer is unchanged since Round 19, and CI runs this test |
| Deliberate breaks (§5) | **26 of 26 Rust and 4 of 4 TypeScript caught**, no residue |
| Mainnet, three days, Round 21 vs Round 22 (§4) | 39,857 verified; 0 parse failures, 0 verify errors; 230 Blocked → Clear, 0 Clear → Blocked; 288 changed rows, every one only losing findings; 0 approvals before and after (no RPC in that harness) |
| Live mainnet RPC, 40 transactions (§4) | 0 invariant violations; risk Clear 24 → 33 with F-22-12 |
| Manifest grounding (§2.5) | 45,253 of 45,282 executed manifest instructions resolve clean; 383 of 3,195 instructions observed executing |

The first full mirror of the final build failed one unit test the round's own
suite did not run: `manifest::tests::test_stake_program_discriminators_match_official_u32_le_layout`
still pinned `GetMinimumDelegation`, which this round removed from the Stake
manifest (it takes no accounts and only writes return data). The pin now
lists `MoveStake` and `MoveLamports` and asserts that `GetMinimumDelegation`
and the deprecated `Redelegate` are not described; the mirror was rerun.

Every public-RPC read was paced and read-only; nothing was signed or sent, and
no key, wallet or fund was touched. This is internal engineering work, not an
independent audit.

## 7. Still open

- **The coverage boundary stays where the design put it.** 84–87% of verified
  transactions in the three samples call a primary program with no manifest,
  and the drainer heuristic refuses those that touch three or more accounts.
  71% of those refusals are programs signed by five or fewer fee payers that
  publish no IDL. A manifest for a program with real users and no IDL needs a
  per-protocol source; the heuristic is not loosened, because a simulation of
  code Graphite does not describe does not bind what it does at landing.
- **2,812 of 3,195 manifest instructions have never been seen executing** in
  the traffic this round read (three block samples, 2,998 per-program
  transactions). They are grounded in their programs' published interfaces
  only.
- **Three published IDLs disagree with their own programs** — mintfx
  `transfer`, marginfi `lending_account_end_flashloan`, Coinflow's instruction
  `7bac2088…` — and are not adopted without a source; those instructions block.
- **The observation-based rules need an RPC.** Without one, an over-privileged
  account, a lookup-table account's privilege, a fee-bearing transfer, a hook
  and a pending schedule take the no-observation branch: they block, or state
  Round 20's arithmetic. That is the architecture — Graphite does not assume
  what it did not observe — not a gap to close.
- **Confidential transfers that move encrypted balances still block.** The
  amounts are ciphertexts; judging them needs the owner's decryption key, which
  a pre-signature gate does not hold.
- **The bridge does not build v1.** web3.js 1.x cannot compile it; the Core
  verifies v1 from any builder that can.
- **L8's verdict count is a scan (P3, found this round, not fixed).**
  `AuditLog::count_verifications` (Round 17) makes one substring pass over the
  active file and every archive for each L8 lookup that has a chain digest,
  so its cost grows with the trail (a full parse of a 64 MB active file takes
  1.3–2.7 s here; the substring pass is cheaper and was not timed on its
  own). It runs on the blocking pool
  behind the rate limiter, and a caller can trigger it only by citing a
  signature the chain reports as included. SECURITY.md said the join was
  indexed for the active file; it now says what this count costs. An index of
  per-key counts is the fix, left for its own round.
- **A wall-clock unit test is flaky under load (P3).**
  `durable::tests::last_verification_scans_a_full_active_file` asserts an
  indexed lookup under 50 ms right after writing a 64 MB file; it failed once
  in the final leg D (58.5 ms hit) and once in five isolated reruns (107 ms
  miss). A miss is index-only for the active file; the time is this machine's
  I/O and scheduling. The threshold is left as it is.
- **Owner decisions:** the independent third-party audit and branch
  protection on `main`.

## 8. Files

- **Core:** `src/state_diff.rs` (`transfer_hook_reach`, `transfer_hooks_bounded`, `TransactionPrivileges`, `StateDiff::transaction_privileges`, `FeeEpochContext { simulated_epoch, durable_nonce }`, the margin removed), `src/verification.rs` (`transaction_privileges`, `invoked_only_by_token2022`, the executed Token-2022 list for every readable artifact, the observed-hook filter, `fee_epoch_context`, the declared siblings' layout and writable extras), `src/tx_artifact.rs` (`runtime_writable`, `ALWAYS_DEMOTED_KEYS`, `header_writable`), `src/manifest.rs` (`AccountRoleDef::optional`), `src/account_resolution.rs` (the absent rule), `src/cli.rs` and `src/manifest_registry.rs` (struct literals).
- **Manifests:** `protocols/{stake-program,bpf-loader-upgradeable}.json` rebuilt; `jupiter-v6.json` (13 pins removed); `optional` in 40 manifests from on-chain IDLs and in `tcomp-tcmphj`, `jupiter-dca`, `swap-orchestrator-df1ow4`, `bubblegum-bgumap`, `limo-limom9`, `openbook-v2` from traffic; `variable_accounts` in `swap-orchestrator-df1ow4`, `okx-dex-router-provf4`, `debot-router-g7mvcm`, `raydium-clmm`, `kamino-lending`, `kamino-vault-kvaugm`, `pump-fun`, `sage-sage2h`, `tuktuk-tuktuk`, `zap-zapvx9`, `doves-dovesk`, `cc-vrf-ccvrfu`, `ccip-offramp-offqsm`; alternate layouts in `system-program.json` and `spl-stake-pool.json`; the regression corpus regenerated from them (`fixtures/corpus/*`); `docs/protocol-coverage.md` re-rendered (3,195 instructions).
- **Tests:** `tests/round22_remaining.rs` (new, 31), `tests/round21_open_list.rs` (the pending-schedule tests rewritten for F-22-01), `tests/mainnet_conformance.rs` (`GRAPHITE_MAINNET_SHOW_DRAINER`), `tests/mainnet_live_rpc.rs` (`GRAPHITE_MAINNET_SHOW_RISK`), struct-literal updates across the older suites.
- **Bridge:** `integrations/solana-agent-kit/artifact.ts` (`BoundTransaction` v0), `graphite-sak-bridge.ts` (`executeSwap` lookup tables, the version declared from the bytes), `bound-instruction.ts` (`addressLookupTableAddresses`), `bound-transaction.test.ts` (10 v0 tests), `README.md`.
- **Docs:** this report; `docs/CURRENT.md`, `README.md`, `SECURITY.md`, `ARCHITECTURE.md`, `ROADMAP.md`, `CONTRIBUTING.md`, `graphite-core/README.md`, `graphite-core/CHANGELOG.md`, `tools/mainnet-sample/README.md`, `docs/protocol-coverage.md`.
- **Work-dir tooling (not shipped), in `C:\Users\Administrator\graphite-r22-work`:** `fetch_program_traffic.py` (per-program traffic), `r22_remaining_accounts.py` (variable-account criterion), `r22_ground.py` (layout grounding over samples and traffic), `r22_absent.py` (program-id-in-slot finder), `r22_optional.py` (IDL optional flags, Jupiter unpins), `r22_stake.py`, `r22_loader.py`, `r22_variable.py`, `r22_diff.py`, `r22_breaks.py`, `r22_ts_breaks.py`, and the verdict / reason files of both runs.
