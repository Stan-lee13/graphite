# Round 38 — the Round 37 re-audit answered

> **Historical record.** This report describes the codebase at `8b3d8a4` (`main`, 2026-10-24) and
> the changes made on top of it on 2026-10-24. For the current state of Graphite see
> [`CURRENT.md`](CURRENT.md).

**Date:** 2026-10-24 · **Base:** `8b3d8a4` (Round 36 merged, plus the F-015 follow-up of PR
[#54](https://github.com/Stan-lee13/graphite/pull/54)) · **Branch:**
`claude/admiring-archimedes-lfhr7n` · **Scope:** the owner's Round 37 re-audit of `8b3d8a4`. It
reported 1 P0 candidate, 8 P1, 9 P2 and about 25 P3. Internal engineering work by the maintainer
and AI engineering agents. **This is not an independent third-party audit and not a
certification.**

## Decision

**RELEASE BLOCKED.** There are two reasons:

- The owner and external gates of Round 36 are unchanged (see §F).
- Most of Round 37 was not answered. The brief this round worked from ends partway through R37-7.
  The re-audit report (`docs/round37-re-audit-2026-10-24.md`) and its reproduction tests (the
  owner's `graphite-audit-work\r37` copy) were not available to this session. The P0 candidate,
  the eighth P1, the nine P2 and the P3 findings are therefore open, not dispositioned (§E).

What this round did answer, it reproduced first. Each fix was proven three ways:

- an end-to-end test through `verify_async` against a loopback mock RPC;
- the attack's decision recorded on the code before the fix;
- the fix reverted in an isolated worktree with its own build directory, to show the test fails.

**Two of the seven P1s were executable end to end on `main`.** These were R37-1, a swap or
withdrawal skimmed by a sibling, and R37-7, a creation funding the attacker's account. One more,
R37-6, was held back only by a heuristic.

| Finding | Severity (brief) | What `8b3d8a4` decided, end to end | After Round 38 |
|---|---|---|---|
| R37-1 swap output skimmed by a sibling | P1 / P0 candidate | `executable_approved` | refused (`IntentMismatch`, names the instruction and amount) |
| R37-1 withdrawal skimmed by a sibling | P1 / P0 candidate | `executable_approved` | refused (`WithdrawalUnderbounded`) |
| R37-1 swap input skimmed by a sibling | P1 | blocked by L4 (W19), not by the binding | blocked by L4 and by the binding |
| R37-2 forged legacy line at the top of a keyed trail | P1 | read by the keyed reader; `verify` exit 0 | not read; exit 4 unlisted, exit 1 before a keyed genesis |
| R37-3 unkeyed self-hashed forgery at the start of a file | P1 | returned by the keyed reader (`verify` exit 1) | never admitted once the trail is keyed |
| R37-4 a retired key extends the trail after rotation | P1 | `verify(&[K1,K2])` exit 0; the reader served it | a break (exit 1); never read; one-way rotation |
| R37-5 a genuine record copied to the end | P1 | the reader's newest verdict; L8 counted it twice | not read: a line is read only when it continues the last one |
| R37-6 an unscoped authority line excuses an effect on a signer's account | P1 | L4 **passed** it. A takeover beside an Orca `transferLockedPosition` was held back only by L7's "Drainer" heuristic (an account-to-change ratio the attacker controls) | L4 names it (`UndeclaredTokenAuthorityChange`, `UndeclaredDelegateGrant`, …) |
| R37-7 `create` funds a new account far beyond its rent | P1 | `executable_approved` (5 SOL into a zero-byte account the attacker's program owns) | refused (`IntentMismatch`, names the account and the excess) |

How to read "executable": the tests set confidence aside. With no L3 baseline, a test transaction
scores about 0.44, below the server's 0.55 floor. A program with a mature baseline scores higher
in production. The tests therefore use the bar `staking_withdrawal_destination.rs` uses
(`min_confidence: 0.40`), so the decision shows what the binding and the layers do. Read R37-1 and
R37-7 as P0 in substance: every gate but confidence passed them.

## A. What changed for an operator

- **Swaps and withdrawals** (`intent_binding::keeps_value`). Beside a swap or a granted withdrawal:
  - every top-level System, SPL Token or Token-2022 instruction that moves value under a signer's
    authority must send it to a signer's own account. This covers transfers, account creation and
    `CloseAccount`;
  - `Approve`, `SetAuthority` and `Burn` by a signer are mismatches;
  - no account outside the signers' own and the route's may gain lamports or a swapped mint in the
    simulated diff. This catches a skim done by CPI, which no top-level bytes show.

  A swap's spend is held to the route's decoded `amount_in`, not only to the request. A swap into
  SOL counts every lamport that reached the signer's own accounts. The owner's own unwrap is
  therefore bound; before, it read as "delivers none".
- **Creations** (`intent_binding::bind_create`). `create` was `NotApplicable`; it is now bound:
  - each account the transaction creates may hold at most its rent-exempt minimum, plus, in all,
    the SOL amount the request states;
  - nothing else that is not a signer's may gain lamports.

  Without a simulated diff, a creation is `intent_parameters` (never executable).
- **L4.** On an account a signer holds, a line that names no account no longer declares an owner
  change, closure, delegate, close authority, freeze or any authority change. "Holds" means:
  - a signer that held lamports before the transaction;
  - a token account a signer owns;
  - a native account, mint or Token-2022 extension whose recorded authority is a signer.

  Pool, vault and program accounts are judged as before.
- **Audit trail.** Every reader walks the chain the way `verify` does. See `docs/ops/keys.md`,
  rewritten this round:
  - **Rotation is one-way.** `GRAPHITE_AUDIT_PREVIOUS_KEY_FILE` is needed for the first start after
    a rotation only, and the server warns while it stays set.
  - **Records before Round 30 under a key.** Legacy records need a checked adoption record that
    lists them. Run `graphite audit adopt-key` once more on a trail adopted in Rounds 34–37; until
    then `verify` exits 4.
  - **Link version 2.** Links carry a trail id bound into the MAC. Upgrade every verifier before the
    server: a Round 30–37 binary cannot read v2 lines. v1 trails stay readable.
  - **Writer refusals.** The writer refuses to resume onto a legacy-only trail (run `adopt-key`), a
    head under a retired key, or a head the readers' walk does not reach.

## B. Findings

### R37-1 — a swap or a withdrawal skimmed by a sibling — FIXED

**Reproduced end to end** (`tests/round38_sibling_skims.rs`):
- **Output skim.** A Jupiter v6 `route` paying 100 of the output into the owner's account, beside a
  `TransferChecked` of 49.6 of it to someone else, with a minimum of 50: `executable_approved`.
- **Withdrawal skim.** A Raydium CLMM `decrease_liquidity_v2` paying 500 beside a `TransferChecked`
  of 96 (minimum 400): `executable_approved`.
- **Input skim.** The input skim was already caught by L4 (`SignerLamportsOutsideDeclaredDebit`).

Raydium CPMM, the brief's example, could not reproduce the skim. Its `swap_base_input` declares no
debit of its input account, so L4 refuses an honest CPMM swap (§E). Jupiter's `route` names its
debit, and that is where the skim reached `executable_approved`.

**The fix** is `keeps_value`, as in §A, and the spend held to `amount_in`.

**Tests:**
- `a_swap_output_skimmed_by_a_sibling_is_not_bound`;
- `a_swap_input_skimmed_by_a_sibling_is_not_bound`;
- `a_withdrawal_skimmed_by_a_sibling_is_not_bound`;
- `an_approval_or_a_cpi_skim_beside_a_swap_is_not_bound`.

**Controls:**
- `an_honest_swap_is_executable`;
- `a_swap_beside_a_memo_is_executable`;
- `an_honest_withdrawal_is_executable`;
- `the_owners_own_wrap_and_unwrap_are_bound`.

The wrap and unwrap control is bound but refused at L4 (§E).

### R37-2..R37-5 — audit-trail readers judged each line alone — FIXED

There was one root cause: the reader gate checked each line's bytes, hash and MAC, never its place
in the chain. Readers now carry the walk `verify` does across files, oldest first
(`chain::Cursor`), with the result cached per archive. The tests are in
`src/durable/chain_trail_tests.rs`:
- `a_forged_legacy_line_in_a_keyed_trail_is_neither_read_nor_verified` (R37-2);
- `an_unkeyed_forgery_is_never_admitted_after_the_trail_is_keyed`, both variants (R37-3);
- `a_retired_key_cannot_extend_the_trail_after_rotation` (R37-4);
- `a_copied_record_is_not_the_newest_verdict` (R37-5).

How each failed on the old code:
- **R37-2:** `TrailReport { integrity: TamperEvident, legacy_unchained_records: 1 }`, exit 0, and
  the keyed reader returned the forged legacy approval.
- **R37-3:** the keyed reader returned the unkeyed forgery `gr-forged`.
- **R37-4:** a reader holding both keys counted the record under the retired key, `(1, 0)`.
- **R37-5:** the running server counted the copied approval twice, `(2, 1)`.

What changed:
- **Legacy coverage.** `KeyAdoption.legacy` lists each file's legacy records (count and SHA-256),
  and after a prune the files left must be a suffix of that list.
- **Unkeyed lines** are refused once the chain is keyed. Under keys, one is read only when a checked
  adoption covers it through the hash chain.
- **Retired keys.** A record under a retired key is never read, and `verify` breaks on it.
  `switch_without_adoption` is accepted only before the first adoption record.
- **Continuity.** A chained line is read only when it continues the last admitted one (next `seq`,
  `prev` equal to its hash). Archive-index offsets are re-checked by walking.
- **Trail id.** Readers pin the newest record's trail id.

Re-pinned tests, with the reasons in their comments:
- `legacy_records_stay_readable_and_are_never_counted_as_tamper_evident`. A keyed writer starting at
  genesis after legacy records is indistinguishable from an insertion, so it now needs `adopt-key`.
- The keyless-reader part of the self-hashed-forgery test.
- `records_under_a_rotated_out_key_…`. A server holding only K2 now refuses to start when a vouched
  forgery displaces the genuine record.

### R37-6 — unscoped authority, delegate, close and owner lines — FIXED

**Census** with the real parser (`r30_declared_effects_census.rs`, pinned). 1,201 instructions
carry such a line:

| Effect | Instructions | Outside the `authority` class |
|---|---:|---:|
| authority | 1,057 | 12 |
| close | 144 | 137 |
| freeze | 4 | 3 |
| delegate | 1 | 1 |

The review's count of about 1,057 authority lines is confirmed. Two of the groups cannot reach an
executable verdict:
- An `authority`-class instruction is never executable: L5 refuses every intent for it, and the
  Risk Engine reports `AuthorityHijack`.
- No `close`-class instruction with such a line serves a `close` intent. The token programs,
  Jupiter DCA and the close grants all name the accounts they close.

The exposure is the 13 instructions in other classes. Orca's `transferLockedPosition` ("transfers a
locked position between owners", served by any `transfer` intent) is one of them.

**Reproduced** (`tests/round38_unscoped_authority.rs`):
- **At L4, on `f5a17a4` (before the fix):** a delegate, an owner change, a close authority and a
  closure on the signer's own token account, under "updates protocol configuration or authority"
  and under Orca's close line, all **passed**.
- **End to end:** the takeover beside `transferLockedPosition` passed L4. It was blocked only by L7
  calling the attacker's sibling a drainer, a heuristic on its account-to-change ratio.

**The fix** is in `state_diff::signer_holds`: the effect judgements ask `covers_by_name` for an
account a signer holds. Controls: the configuration change alone and the bundled position closing
pass L4, and a pool account's authority change under the same line still passes.

One existing test was re-pinned:
`round30_fuzz_findings::a_declared_allocation_of_another_account_is_still_excused`. A signer holding
5 SOL, handed to a program under "initialize account", is now critical. The excuse still stands
under a line naming the account, and for an account the transaction itself funded.

**Re-measured:** the regression corpus, the release evaluation and the mainnet conformance digest
pass unchanged, so nothing in them newly refuses.

### R37-7 — a creation funded far beyond its rent — FIXED

**Reproduced end to end** (`tests/round38_create_funding.rs`): a System `CreateAccount` of 5 SOL
into a zero-byte account owned by the attacker's program, under `create`, was
`executable_approved` on `2893461`.

**The fix** is `bind_create`, as in §A. The brief's own fix guidance for R37-7 was cut off; this
design is the round's own.

**Tests:**
- `an_account_funded_far_beyond_its_rent_is_not_executable`;
- `a_transfer_to_someone_else_beside_a_creation_is_not_executable`.

**Controls:**
- `an_account_funded_with_its_rent_is_executable`;
- `an_account_funded_with_the_amount_the_request_states_is_executable`. Its second half refuses 5
  SOL against a stated 1.

One existing test was re-pinned: `round36_intent_binding::stake_and_intents_that_state_nothing`.
`create` is now bound, not `NotApplicable`.

## C. Deliberate-break evidence

The breaks continue `AUDIT/01-findings.md`'s break log at B157. Each was built in a worktree
outside the working tree with its own `CARGO_TARGET_DIR`. A first R37-1 break run shared the main
build directory, and one result in it was stale, so every break was re-run in isolation.

| # | Finding | What was reverted | Caught by | Result |
|---|---|---|---|---|
| B157 | R37-1 | `keeps_value` returns `Ok(())` | `round38_sibling_skims`: output skim, withdrawal skim, approval/CPI skim | caught (3 of 8 fail; the controls pass) |
| B158 | R37-1 | B157 plus the SOL spend held to the request again | `…::a_swap_input_skimmed_by_a_sibling_is_not_bound` | caught |
| B159 | R37-6 | `state_diff.rs` at `f5a17a4` (no `signer_holds`) | `round38_unscoped_authority`: delegate, owner/close-authority/closure, close line, between-owners takeover | caught (5 fail; the controls pass) |
| B160 | R37-7 | `"create" => NotApplicable` | `round38_create_funding`: the 5 SOL creation, the transfer beside a creation, and 5 SOL against a stated 1 | caught (3 of 4 fail; the rent-only control passes) |
| B161 | R37-2 | the reader-side legacy check | `a_forged_legacy_line_in_a_keyed_trail_is_neither_read_nor_verified` | caught ("the keyed reader returned the forged legacy approval") |
| B162 | R37-3 | the keyed-gate unkeyed rule | `an_unkeyed_forgery_is_never_admitted_after_the_trail_is_keyed` | caught |
| B163 | R37-4 | the retired-key check alone | `a_retired_key_cannot_extend_the_trail_after_rotation` | **missed**: the switch-after-adoption rule also blocks it |
| B164 | R37-4 | the retired-key check and the switch-after-adoption rule | the same test | caught `(1, 0)` |
| B165 | R37-5 | the continuity check | `a_copied_record_is_not_the_newest_verdict` | caught `(2, 1)` |
| B166 | R37-5 | the trail-id pin | the same test, at the cross-trail top-insertion step | caught |

## D. What was run

FILLED_AFTER_VALIDATION

## E. Residuals and what this round did not do

- **Not in this session: the rest of Round 37.** That is the P0 candidate, the eighth P1, all nine
  P2 and about 25 P3 findings, and R37-7's own fix text. They are open. They are not fixed,
  dispositioned or owner-decided until the re-audit report is in hand.
- **Honest swaps refused at L4 (pre-existing, documented in `CURRENT.md`).** The declarations
  below name no debit of the input account, so an honest swap through them is
  `SignerTokenDebitUnderUnscopedDebit`:
  - Raydium CPMM `swap_base_input` and `swap_base_output`;
  - every Raydium CLMM and AMM v4 swap;
  - Meteora DLMM's swaps except `swap_2`;
  - Orca `swapV2` and `twoHopSwapV2`;
  - every Jupiter exact-out route.

  The fix is the Round 36 F-005 method: rewrite them from their IDLs. That is a manifest change
  for the owner to schedule.
- **Wrap and unwrap beside a swap (pre-existing).** L4 judges the whole diff against the primary's
  declaration, so it refuses the owner's own wSOL wrap and unwrap beside a Jupiter `route`. The
  binding holds both. `CURRENT.md` already listed wrapping as unsupported.
- **The live cost of these rules is unmeasured.** The live-mainnet workflow needs the owner's
  permission and was not run.
- **R37-6's reach.** It is closed for an account a signer holds. A line naming no account still
  covers pool and program accounts, by design.
- **Audit trail.**
  - Readers walk every archive at start-up. This costs HMAC per line and was not benchmarked.
  - Records under an old key that is no longer held are read on an adoption's word, not checked.
  - A foreign trail inserted at both the top and the end defeats the trail-id pin. Only a
    checkpoint catches it, as with wholesale replacement.
  - A line inserted mid-file stops readers admitting anything after it. That fails closed, but it
    costs availability.

## F. Owner and external gates (STOP-SHIP)

Unchanged from Round 36: rulesets and private vulnerability reporting, closing dependency PRs
#47/#48/#52, the nine medium-confidence declaration rewrites, deployment, WORM anchoring, RPC
independence, an authorized read-only live-mainnet replay, a larger holdout, the independent audit,
and the P12 and idempotency-key decisions.

New:
- **The Round 37 report.** It must be provided so the rest of Round 37 can be answered.
- **Upgrade order.** Upgrade `graphite audit verify` before the server: chain link v2 is unreadable
  by Round 30–37 binaries.
- **Re-adopt keyed trails.** Run `graphite audit adopt-key` on trails adopted in Rounds 34–37 that
  carry legacy records.
