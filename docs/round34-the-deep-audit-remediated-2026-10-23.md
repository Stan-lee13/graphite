# Round 34 — the Round 33 deep audit of `b473a31`, remediated

> **Historical record.** This report describes the codebase at commit `b473a31` (the Round 31–32
> merge) and the changes made on top of it on 2026-10-22/23. For the current state of Graphite
> see [`CURRENT.md`](CURRENT.md).

**Date:** 2026-10-22 to 2026-10-23 · **Base:** `b473a31` (main) · **Branch:**
`claude/admiring-archimedes-lfhr7n` · **Scope:** every finding of the Round 33 deep audit of
`b473a31`: 1 P0, 9 P1, 13 P2 and about 30 P3. Internal engineering work by the maintainer and AI
engineering agents. **This is not an independent third-party audit and not a certification.**

The Round 33 audit report (`docs/round33-deep-audit-2026-10-22.md` on the owner's machine) and its
scratch reproduction tests were not in the environment this round ran in. Every finding was
re-reproduced from the remediation brief's restatement of it: what is wrong, why, and how to fix
it. Each regression test below was written fresh, not ported, and was shown to fail on `b473a31`.

## A. What changed for an operator

- **A `stake` intent no longer declares any withdrawal (R33-1, P0).** Staking withdrawals are
  declared only by `withdraw`, and only when the value goes to the instruction's own signing key:
  - Stake `Withdraw`: `to` is the `withdrawer`;
  - Stake Pool `WithdrawSol` (and its slippage form): `destination` is the `user_transfer_authority`;
  - Stake Pool `WithdrawStake` (and its slippage form): `user_withdraw_authority` is the
    `user_transfer_authority`;
  - Marinade `liquidUnstake`: `transferSolTo` is `getMsolFromAuthority`.
  The advisory AI layer now labels "unstake" and "withdraw" text `withdraw`.
- **A debit line that names no account no longer excuses a signer's loss (R33-5, P0 by the
  brief's own test).** About 1,800 declarations read "transfers funds between the protocol and the
  involved accounts". Such a line is now unreadable *for the signer's judgement*: a signer's
  lamport or token loss beneath it is Critical (`SignerLamportsUnderUnscopedDebit`,
  `SignerTokenDebitUnderUnscopedDebit`), unless `GRAPHITE_ALLOW_UNREADABLE_VALUE_DECLARATIONS=1`
  and the class moves value. Pool and vault accounts keep the old "any account" reading.
- **Signer netting is per signer (R33-6, R33-7, R33-10).** One signer's gain never offsets
  another's loss. Value kept counts only toward the signer that holds it. Rent counts as the
  signer's cost only for an account the declaration names as created, owned by the located
  instruction's program, SPL Token or Token-2022. Payouts from vaults offset nothing.
- **Authorities written into a created stake, vote or nonce account must be signers' (R33-14):**
  `CreatedAccountAuthorityNotSigner`, Critical, with no opt-out.
- **A System `Transfer` or `CreateAccount` binds its stated amount (R33-15):**
  `SignerLamportsBeyondDeclaredAmount` when the wallet loses more. It is Critical, or a warning
  under the W19 opt-out.
- **An unbounded withdrawal is one with ANY zero minimum (R33-11),** not only all zeros.
- **The audit trail has one line grammar (R33-2, R33-3).** A chained line is a record only when
  its bytes are the canonical JSON of its content and its content recomputes its hash. The
  verifier and every reader use the same gate. With a key configured, readers also require a
  valid MAC, so a forged line is never returned as a verdict.
- **`graphite audit verify` has a new exit code 4:** keys were supplied but do not cover the trail
  (R33-4, R33-12). New commands:
  - `graphite audit adopt-key` (a keyed writer refuses an unkeyed head without it);
  - `graphite audit acknowledge-tear` (for a historic crash tear).
  `GRAPHITE_AUDIT_PREVIOUS_KEY_FILE` is needed for the restart after a key rotation (R33-13).
  See `docs/ops/keys.md`.
- **Backups carry a `.mac`.** `restore.sh` needs it and `--anchor-dir` (D-6); `rotate-keys.sh`
  keeps the secret files' owner (R33-19).
- **Releases need a signed tag on `main`** and a CI gate from a push run on `main` (R33-9), plus
  the owner steps R1–R4 in `docs/ops/production-checklist.md`.
- **The agent guard:**
  - its wallet lock lives in a runtime directory and is re-checked before every spend (R33-16);
  - stale-lock takeover is race-free (R33-17);
  - a closed guard refuses to sign (G-4);
  - it requires the Core's `decision` (G-5);
  - `verifyTransaction` is private (G-7, a public API change).

## B. Findings and their state

Every finding ends **fixed**, an **owner decision** (written in `docs/ops/production-checklist.md`
and here), or a **documented limitation** with its reason.

### P0 and P1

| ID | Finding | State | Regression test(s) |
|---|---|---|---|
| R33-1 (P0) | A stake intent executed a withdrawal of the user's stake to any account | **Fixed.** Stake row `["stake","transfer","create"]`; grounded staking withdrawals under `withdraw` | `tests/staking_withdrawal_destination.rs` (14 end-to-end tests over a loopback RPC; on `b473a31` the Stake Withdraw and Marinade attacks came back `ExecutableApproved`) |
| R33-2 | A forged line in the audit trail was read by L8 while `audit verify` exited 0 | **Fixed** | `durable::chain_trail_tests::{a_forged_unterminated_line_in_an_archive_breaks_the_chain_and_is_never_read, a_line_the_chain_cannot_parse_breaks_the_chain_and_is_never_read, a_forged_index_pointing_at_a_forged_line_is_never_an_answer, a_self_hashed_forgery_in_a_keyed_trail_is_never_read_by_a_reader_with_the_key}` |
| R33-3 | A duplicate JSON key hid a MAC'd record from every reader | **Fixed** | `a_duplicate_key_breaks_the_chain_and_the_record_stays_visible_or_is_named`, `verify_and_every_reader_agree_on_every_mutated_line` (11 mutations plus a missing newline, every file) |
| R33-4 | Stripping the MACs downgraded a keyed trail and verify exited 0 | **Fixed**: exit 4; the writer refuses an unkeyed head; `adopt-key` | `a_trail_rewritten_without_macs_does_not_verify_under_its_key`, `a_keyed_writer_refuses_to_resume_onto_an_unkeyed_head`, control `legitimate_key_adoption_via_the_marker_verifies`, `tests/round34_audit_adopt_key.rs` |
| R33-5 (P0) | A debit line naming no account switched W19 off for about half the registry | **Fixed** (signer judgements read it as unreadable). The end-to-end test settles the P0 question: a granted Raydium CLMM `decrease_liquidity_v2` plus a sibling sending 5 SOL to an attacker passed L4, L5 and L7 (risk Clear) on `b473a31`; only the offline confidence threshold refused it | `tests/signer_value_netting.rs`: `a_signers_wallet_drained_beside_a_withdrawal_that_names_no_account_is_refused`, the CPMM variant, a control; census `debit_lines_that_name_no_account_are_counted` |
| R33-6 | Rent paid into a created account another program owns was credited as the signer's | **Fixed** | `rent_paid_into_an_account_another_program_owns_is_the_signers_loss` and its no-debit variant |
| R33-7 | A co-signer's gain offset the user's loss | **Fixed**: per-signer losses | `a_fresh_cosigners_gain_does_not_offset_the_users_loss`, `a_relayers_gain_does_not_offset_the_users_loss`, control `two_signers_paying_only_the_fee_raise_no_lamport_finding` |
| R33-8 | `main` had no green CI: the Rust job timed out at 60 minutes | **Fixed in code**: `rust-lint` plus a `rust-test` matrix (default 90, lib 20, cli 45 minutes) under a `ci-test` profile. The wall time on a push to `main` is measured after the owner's push (§E) | `ci-scripts.test.sh` (the gate needs every job; leg floors; profile semantics) |
| R33-9 | Pushing a tag could publish a release | **Fixed in code**: `.github/scripts/release-gate.sh`. **Owner decision R1–R4**: apply the rulesets, create the protected `release` environment, add a key to `.github/allowed_signers` | `release-gate.test.sh` (30 cases; the old gate passed a PR-event check run) |

### P2

| ID | Finding | State | Test |
|---|---|---|---|
| R33-10 | W19 credited any wSOL arriving in a signer's account | **Fixed** (with R33-6, R33-7) | `state_diff::w19_scope_tests::a_vaults_payout_into_the_signers_account_does_not_offset_a_wallet_drain` |
| R33-11 | `UnboundedWithdrawal` fired only when every minimum was zero | **Fixed**: any zero minimum. A non-zero dust minimum is not judged (that needs the expected output, which the bytes do not carry); the DLMM grants carry no minimum (documented limitation) | `round30_grounded_intents::a_withdrawal_with_a_dust_minimum_is_not_bounded` |
| R33-12 | An unsigned checkpoint was Confirmed | **Fixed**: `UnsignedCheckpoint`, exit 4 | `an_unsigned_checkpoint_or_one_under_an_unknown_key_is_not_confirmed` |
| R33-13 | An invented key id looked like a rotation | **Fixed**: a chained key-adoption record; an unadopted key id is a break | `an_invented_key_id_is_a_break_not_a_rotation`, `a_keyed_writer_refuses_to_resume_onto_a_head_under_an_unknown_key` |
| R33-14 | Authorities written into a created native account were never judged | **Fixed** | `a_created_stake_account_authorised_to_a_non_signer_is_refused` (end to end) |
| R33-15 | A declared wallet debit excused any amount | **Fixed for System `Transfer`/`CreateAccount`**; token amounts and `TransferWithSeed` not bound (documented limitation) | `a_declared_wallet_debit_does_not_excuse_more_than_its_stated_amount` |
| R33-16 | The guard's wallet lock sat in a cleaned temp directory and was never re-checked | **Fixed** | `integrations/agent-guard/wallet-lock-integrity.test.ts` |
| R33-17 | Taking over a stale lock was a race | **Fixed** | the 1,000-round two-process takeover test (31 of 1,000 rounds double-acquired before) |
| R33-18 | The published attestation-verify commands accepted any workflow | **Fixed** in all 8 places | `.github/scripts/check-attestation-commands.py` (in CI) |
| R33-19 | `rotate-keys.sh` dropped the secret files' owner | **Fixed** | `deploy/tests/run.sh` (owner and mode checks) |
| R33-20 | Dependabot never saw the production images or the hand-pinned tools | **Fixed**: a `docker-compose` entry; `.github/pinned-tools.json` with a weekly check | `pinned-tools.py check-pins` (in CI) |
| R33-21 | Operator documents stated the wrong defaults | **Fixed** (§D) | `tests/docs_paths_resolve.rs` and `tests/docs_numbers_match_the_code.rs` now scan `docs/ops/`, the hand-off pack and the grant proposal |

### P3

| ID | State |
|---|---|
| S-3 | **Fixed**: a mature shape's baseline must also pass the program anchor (`a_shape_bootstrapped_at_the_program_edge_escapes_the_program_anchor`) |
| S-5 | **Fixed**: the simulator's `loadedAddresses` must match Graphite's own table resolution (`tests/simulator_loaded_addresses.rs`) |
| A-6 | **Fixed**: verify re-walks when the archive list changes, up to 20 times (`a_rotation_during_the_walk_is_walked_again`) |
| A-7 | **Fixed** (zeroize on drop, `a_dropped_key_is_wiped`); Windows ACLs **documented, not checked** (`docs/ops/keys.md`) |
| G-3 | **Fixed**: a private lock directory; `O_EXCL\|O_NOFOLLOW` temp files with random names |
| G-4 | **Fixed**: `GuardClosed` |
| G-5 | **Fixed**: the guard recomputes `executable_approved`, requires `decision`, and corrects its README |
| G-6 | **Fixed** in the SDK client (`DuplicateKeyError`); the guard's RPC and AI-layer readers still use `JSON.parse` (documented limitation) |
| G-7 | **Fixed**: `verifyTransaction` is private; the SAK adapter's delegate is removed (API change) |
| C-4 | **Fixed**: one `canonical_intent` (`intent_case_is_judged_identically_in_every_layer`) |
| C-5 | **Fixed**: plugins in a `BTreeMap` (`protocol_rules_come_in_one_order_in_every_orchestrator`) |
| C-6 | **Decision**: no `graphite verify --rpc-url`. The CLI opens its data directory read-only and cannot write the audit row an executable approval needs; the server stays the only path to signing |
| K-7 | **Fixed** for Orca `increaseLiquidityByTokenAmountsV2`. The new census compares 2,891 instructions with their on-chain IDLs and **pins 75 more mismatches, not fixed**: 64 Orca instructions without a trailing `whirlpool_program`, 10 Kamino admin instructions without `instructionSysvarAccount`. The evidence is ambiguous: Orca `swapV2` was checked against a real 15-account transaction. Round 32's "checked slot by slot" claim is corrected here |
| D-6 | **Fixed**: backup `.mac`; `restore.sh` requires it and `--anchor-dir` |
| D-7 | **Fixed**: a semver-major ignore for `@solana/web3.js`. **Owner**: PR #46 can be closed |
| D-8 | **Fixed in code**: the image ships build a's binary, checked by hash. Unproven until a release rehearsal |
| D-9 | **Fixed**: `set-rpc-env.sh` validates the URL and uses a random heredoc delimiter |
| DOC-5 … DOC-19 | **Fixed** (§D) |
| Local tooling | `.claude/agents/*.md` naming a retired model: not present in this checkout, so not checked; reported to the owner, config not edited |

## C. Pinned outputs, row by row

- **Mainnet conformance digest:** `bda80e69…` → `de8c8a6f…`. One of 2,277 rows changed: row 1273,
  a real Stake Withdraw. Its risk column went from Clear to PermissionEscalation (Check 9b refuses
  a stake label for a withdrawal). It was not approved before or after.
- **Regression corpus:** three Stake Withdraw rows labelled `stake` moved from approve to refuse:
  regression `dade3cea` (was `55c52f79`), dev canonical `94b985a3`, dev near-prefix `1624bd65`
  (R33-1). Two Orca fixtures gained the 16th slot (K-7); their labels are unchanged.
- **Release evaluation:** regression TP 21 → 22, TN 5 → 4; dev TP 11,802 → 11,804, TN 1,103 →
  1,101. These are the same three rows. Holdout and hand-built splits are unchanged.
- **Cross-language corpus** (`npm run emit:corpus`, `emit:artifact-fixture`): no drift.
- **No row moved from refused to approved.**
- **The L4 changes (R33-5/6/7/10/14/15) moved no committed row.** No committed corpus row carries a
  state diff (13,013 `state_diff` fields, all null), and the committed mainnet blocks run offline.
  Their false-refusal cost is therefore measured only by `.github/workflows/live-mainnet.yml` (§E).
- **Tests that pinned wrong behaviour as correct, re-pinned with the reason in each comment:**
  - `tests/regression_corpus.rs`: the stake Withdraw row;
  - `tests/p0_validation_attacks.rs::attack_check10_…`: now refused by Check 9b;
  - `tests/audit_review_r2_r3_intent_cannot_clear_danger.rs`: the honest-label entry, plus the new
    `a_stake_label_does_not_declare_a_stake_withdrawal`;
  - `l2_l4_l5_hard_gate::l5_refuses_an_intent_the_program_does_not_serve…`: moved to an instruction
    that no intent serves;
  - `rent_for_a_created_account_and_wrapped_sol_are_not_a_w19_loss`: relied on the loose rent rule;
  - `verification::tests::an_rpc_diff_without_balance_arrays_is_not_a_pass` and
    `round30_trust_learning::a_verify_key_holder_cannot_raise_a_programs_evidence`: fixtures the new
    rules read;
  - `a_rotated_key_verifies_with_both_keys_and_a_lost_key_cannot_continue_the_trail`: pinned the
    R33-13 hole;
  - `a_verdict_count_the_active_file_contradicts_is_recounted`;
  - the census pin (13 → 18 of 21 → 27 grants carry an unscoped debit line once the staking grants
    exist);
  - in TypeScript: `guard-round30` "a server that predates `decision`…" (pinned the G-5 gap) and the
    `guard-round32` lock-content assertion;
  - in Python: three AI-layer tests that labelled "unstake" `stake`.

## D. Documents corrected

- **R33-21:**
  - `AUDIT/FINAL.md` (W18/19-f);
  - `docs/CURRENT.md` (the minimum outputs and W19 limitations);
  - the hand-off pack's residual list (four Round 32 fixes had been listed as open; fuzzing is 30
    minutes per target);
  - `docs/ops/production-checklist.md` item 4.
- **DOC-5 … DOC-19:**
  - the `AUDIT/FINAL.md` header, break count, assurance status and verdict;
  - the Round 32 rows and break-log header in `AUDIT/01-findings.md`;
  - Rounds 31–34 in `ROADMAP.md` and `AUDIT/02-roadmap-gap.md` (R-P1 no longer both missing and done;
    R-M10 done; "CI green on each round's closing commit" corrected);
  - the stale `instruction_bind_key` lines;
  - the hand-off pack's floors, paths and reporting route;
  - the risk-pattern counts;
  - the Round 32 opt-outs in `ARCHITECTURE.md` and `graphite-core/README.md`;
  - the grant-relaxation wording in `install.md` and `.env.example`;
  - mutation scores now owned by `CURRENT.md`;
  - `SECURITY.md`'s "0 defects";
  - the grant proposal refreshed;
  - the MCP and SDK READMEs.
- **Tests now guard this class of drift:** both docs tests list `docs/ops/*`, the hand-off pack,
  `deploy/README.md` and the grant proposal.

## E. Test and build evidence

{EVIDENCE}

## F. Deliberate breaks (B128 onward)

Every Rust fix was reverted once, alone, in the integration tree with a fresh build target, and its
named test re-run. The fix was then restored and the tree checked unchanged. The harness is the
scratch `run_breaks.py`, outside the repository: exact text edits, validated before any edit,
restored byte for byte. During the round the workstreams' own breaks ran in worktrees that shared a
build directory. That can link another worktree's library into a test (found by workstream A). So
those local results were not relied on, and the breaks were re-run here.

{BREAKS}

The TypeScript, CI-script and deploy breaks ran in their workstreams. They are not affected by the
shared Rust target. All were caught; four first missed and were caught after their tests were
strengthened:
- the agent guard: E1–E15 and S1–S4 (E5 and E6 missed first);
- the release gate: L1–L6 and L18 (L1 missed first);
- the deploy kit: L8–L12 (L10 missed first);
- D-9: L13;
- the pinned tools: L14;
- the CI split: L15–L17;
- the audit-trail follow-ups: F1–F10.

## G. Owner decisions and residuals

- **Owner (`docs/ops/production-checklist.md`):**
  - branch protection and the three rulesets;
  - the protected `release` environment;
  - a signing key in `.github/allowed_signers`;
  - private vulnerability reporting;
  - an independent audit;
  - closing PR #46;
  - whether to run the live-mainnet workflow to measure the new L4 defaults (§E);
  - keeping or relaxing the refusal defaults.
- **Residuals (documented in `CURRENT.md`, `SECURITY.md` and the hand-off pack):**
  - *Withdrawal grants refused until their declarations are rewritten.* 18 of the 27 withdrawal
    grants carry a debit line that names no account. Under R33-5, an honest one that costs the
    signer value is refused until its declaration is rewritten from its IDL. That covers the new
    Stake Pool and Marinade grants: their pool-token or mSOL burn is a signer token debit. A manifest
    rewrite needs the manifest owner's sign-off. Honest CPMM and Pump AMM withdrawals were already
    refused at `b473a31` by `UndeclaredBurn`.
  - *Netting.*
    - A named created account owned by the primary program is credited up to its full rent.
    - Created lookup tables and loader buffers are not judged.
    - Rent paid into a recipient's associated token account (about 0.002 SOL) and Metaplex metadata
      rent are no longer credited.
  - *Amounts.* Token amounts and `TransferWithSeed` are not bound.
  - *Withdrawal minimums.* The seven DLMM remove and claim grants carry no minimum. A non-zero
    dust minimum is not judged.
  - *Staking (R33-1).*
    - Stake `Initialize` under `stake` takes the new account's authorities from its data. R33-14
      judges them when the account is created in the same transaction.
    - Marinade `claim`, `removeLiquidity`, `orderUnstake` and `withdrawStakeAccount` are refused
      under every intent.
    - Deposit receipts' destination is not checked.
  - *The audit trail.*
    - A reader holding only the new key admits records under a rotated-out key on the adoption
      record's word; keep the previous key configured to have them checked.
    - Legacy records written before Round 30 stay readable, unauthenticated.
  - *The agent guard.*
    - The lock is per OS user and per host.
    - A guard that loses its lock stops spending, but its spent allowance is not carried over.
  - *K-7.* 75 IDL slot-count mismatches are pinned, not fixed.

## H. What could not be proven here

{UNPROVEN}
