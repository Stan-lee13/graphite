# Round 38 — the Round 37 re-audit answered

> **Historical record.** This report describes the codebase at `8b3d8a4` (`main`, 2026-10-24) and
> the changes made on top of it on 2026-10-24. For the current state of Graphite see
> [`CURRENT.md`](CURRENT.md).

**Date:** 2026-10-24, second pass 2026-10-25 · **Base:** `8b3d8a4` (Round 36 merged, plus the F-015 follow-up of PR
[#54](https://github.com/Stan-lee13/graphite/pull/54)) · **Branch:**
`claude/admiring-archimedes-lfhr7n` · **Scope:** the owner's Round 37 re-audit of `8b3d8a4`. It
reported 1 P0 candidate, 8 P1, 9 P2 and about 25 P3. Internal engineering work by the maintainer
and AI engineering agents. **This is not an independent third-party audit and not a
certification.**

## Decision

**RELEASE BLOCKED on the owner and external gates (§F).** Every Round 37 finding now ends in one
of three states: fixed with a test; an owner decision, written down; or a documented limitation
with its reason (§B and §E list each).

The round ran in two passes. The first worked from a brief that ended partway through R37-7 and
answered R37-1 to R37-7. The second worked from the full re-audit report, which the owner then
supplied, and answered the rest: R37-7's residual, R37-8's code half, the nine P2s and the P3s.
The second pass also found a gap in the first pass's own R37-1 fix, executable end to end, and
closed it (R38-1, §B). The report itself and the owner's `graphite-audit-work\r37` reproduction
copy are not in the repository; the findings are answered by id.

Each fix was reproduced first. P0/P1 fixes in the pipeline were proven three ways:

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
| **R38-1** (this round's own gap) a Stake `Withdraw` to the owner beside the owner's transfer of 30 SOL to a stranger | P1 (found in pass 2) | `executable_approved` on the pass-1 fix, and on `8b3d8a4` | refused (`WithdrawalUnderbounded`), with or without `GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS` |
| R37-9 a relayer fee payer takes the owner's swap output | P2 | blocked by L4 (`ArtifactEffectsNotCovered`: the fee payer is not named); the binding said Bound | the binding names it too (`IntentMismatch`: two signers' tokens change) |
| R37-10 a transfer beside an unread program the owner signs | P2 | blocked by L6 (Unknown tier) and the Drainer heuristic; the binding said Bound | the binding leaves it unbound (`intent_parameters`) |

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

### Second pass (2026-10-25)

- **Startup refuses every `GRAPHITE_*` name no component reads** (R37-15), not only a near-miss
  of a Core name, and a name within two edits of a Core name outside the prefix
  (`GRAPHTIE_AUDIT_KEY_FILE`). The CLI checks too (V-2). Remove stray variables before upgrading.
- **A new residual, `program_deployments`** (R37-16): a manifested program's deployment that could
  not be read (failed, out of budget, or undecodable) withholds the executable decision instead
  of being a log line. Clients that predate it refuse the verdict as an unknown code, which fails
  closed; the TS and Go SDKs and the guard know it, and the guard refuses it by default.
- **Withdrawals.** What rides beside every granted withdrawal is held (R38-1), and
  `GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS` no longer waives that; it waives only the chain's bound
  on an amount. A native Stake `Withdraw` is held to the lamports the request states (B-6).
- **Transfers, approves and burns** beside a top-level instruction of a program other than System,
  the token programs, compute budget, memo or ATA creation are unbound (R37-10). A swap's effect
  is read on the one signer whose token accounts change (R37-9).
- **`graphite execution`** reads the trail with `GRAPHITE_AUDIT_KEY_FILE` (and the previous key)
  and refuses a keyed trail without it (T-11); it honours `GRAPHITE_L8_HIGH_ASSURANCE` and then
  needs a witness (V-3).
- **`graphite registry verify-records`** checks every acceptance record from its own contents
  (exit 0 / 1 failed / 2 unproven) (V-5).
- **Audit trail.**
  - Archive indexes are format 4, MAC'd under the trail key; an index that does not check is
    never used, the archive is walked instead (R37-12).
  - A record under a vouched key is read only where a checked adoption covers it (R37-13).
  - Pruning writes a chained prune record first; `verify` calls a first seq above 0 that no
    prune record names a break. A trail pruned before this round verifies once the operator has
    checked it and run `graphite audit acknowledge-prune` (R37-14). A Round 30–37 binary cannot
    read a prune record: upgrade verifiers first.
  - Lines are read with an 8 MiB bound (T-15). `audit checkpoint` signs only a covered head
    (T-13). Exit codes: a trail under none of the supplied keys is 4 (T-12); an unreadable input
    is 3, a usage error 64, a held writer lock 75 (T-14).
- **Backup and restore** (R37-11, T-9). The `.mac` is made and accepted under the current key
  only (`restore.sh --current-key-file`, else `GRAPHITE_AUDIT_KEY_FILE`, else the single
  `--key-file`); a backup taken before a key rotation is refused after it, so take a fresh backup
  after each rotation. The anchor is chosen by its content's highest `seq`, never by file name.
- **The agent guard.** One default lock directory per user, from the account database, not from
  `XDG_*` (R37-17); a swap's repeat key is its effect, not its route (G2-2); the verdict's age is
  checked again just before the send (G2-3); "not sent" only for a connect refusal or a DNS
  failure, and an expired outcome-unknown reservation is returned (G2-4); `intent_parameters` can
  never be accepted (G2-5); the dashboard reads at most 32 MiB per answer (G2-6). A rolling
  upgrade may run an old and a new guard on different lock directories.
- **Release integrity** (R37-8, code half). The gate also requires the tagged commit to descend
  from the commit that introduced the gate; `release-guard.yml` (main's copy) cancels a refused
  run and deletes its release; `ruleset-drift.yml` checks weekly that the rulesets and the
  `release` environment are applied, and is red until they are; the tag is re-checked right
  before `gh release create` (D2-3); revoked and expired signers are refused (D2-5). The real
  stop is still the owner's tag ruleset and environment.

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

### R38-1 — R37-1 missed every granted withdrawal without a minimum — FIXED (found in pass 2)

**Reproduced end to end** (`staking_withdrawal_destination::a_withdrawal_beside_a_transfer_to_a_stranger_is_not_executable`):
a Stake `Withdraw` paying the owner 40 SOL, beside the owner's own System `Transfer` of 30 SOL to a
stranger, was `executable_approved` on the pass-1 code. The owner's net is a gain, so L4 saw no
loss. The sibling rule (`keeps_value`) lived in `bind_withdrawal`, which ran only for the three
grants that carry a minimum output, and only with `GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS` off. The
docs workstream found the waiver half while documenting the waiver; the grants without a minimum
(Stake `Withdraw`, the four Stake Pool withdrawals, Marinade `liquidUnstake`) followed from it.

**Decision and fix:** every grounded `withdraw_to_owner` has what rides beside it held
(`intent_binding::withdrawal_keeps_value`), minimum or not, with or without the waiver. The
waiver covers the chain's bound on an amount, and nothing else.

**Tests:** the reproduction, the same with the waiver on, and the honest withdrawal with the waiver
on (executable). Break B180.

### R37-7 residual — the created account's rent counted twice — FIXED

L4 netted a declared creation's rent out of the wallet's loss, then compared what was left with
the located instruction's stated `data.lamports`, which already pay that rent. One more rent's
worth could leave unnamed. Reproduced at L4
(`a_created_accounts_rent_is_not_netted_on_top_of_the_stated_amount`: the wallet loses 2 × rent
against a stated 1 × rent, with the extra going to an account the transaction names, and L4
reported nothing). The comparison now adds the netted rent back (`SignerLoss.rent`). Break B170.

### R37-8 — release integrity — CODE HALF FIXED; OWNER HALF OPEN

- **Code** (`.github/scripts/release-gate.sh`, `.github/workflows/release-guard.yml`,
  `ruleset-drift.yml`): see §A. Re-pinned: `release-gate.test.sh:109`, which expected an older
  `main` commit to be releasable. It now expects a commit from before the gate to be refused,
  with the reason in its comment.
- **The limit, stated plainly:** a tag on a pre-gate commit (`99948c6`) runs that commit's own
  `release.yml`, which has no gate. No change on `main` can stop it. `release-guard.yml` is a
  second line: it does not see a workflow under another name, cannot revoke attestations or an
  image already pushed, and an admin can disable it.
- **Owner:** apply `main.json`, `release-tags.json` and `release-tags-create.json`; create the
  `release` environment with a reviewer and a `v*` policy; then run the drift check
  (`docs/ops/production-checklist.md`, R1–R5). GITHUB_TOKEN cannot read `bypass_actors`, so the
  bypass lists are checked by hand once (R5).
- **Docs:** `AUDIT/FINAL.md` and `CURRENT.md` no longer say "a release cannot be cut at all".

### P2 (R37-9 … R37-18)

| ID | State | What was done | Tests (break) |
|---|---|---|---|
| R37-9 | fixed | the swap's wallet is the one signer whose token accounts change; two signers' tokens changing, or a co-signer gaining lamports, is a mismatch. End to end a relayed transaction is refused by L4 anyway (`ArtifactEffectsNotCovered`: a fee payer the request does not name), which is a pre-existing false refusal of relayed swaps (§E) | `round38_sibling_skims`: relayed control, relayer takes output, relayer takes lamports (B171, B171b, B172) |
| R37-10 | fixed | a transfer, approve or burn beside any other top-level program is unbound; compute budget, memo and ATA `Create`/`CreateIdempotent` move nothing the Core does not read | `a_transfer_beside_an_unread_program_the_owner_signs_is_not_bound` (B173) |
| R37-11 | fixed | the `.mac` made and accepted under the current key only; a retired key's MAC is never accepted (nothing proves an archive predates a rotation) | `deploy/tests/backup-keys.test.sh`, 22 checks (B181) |
| R37-12 | fixed | index format 4 with an HMAC trailer; an index is trusted only under the reader's own key and only through the handle it was checked through | two `chain_trail_tests` (B182) |
| R37-13 | fixed | a vouched key's records are read only where a checked adoption covers them | one test plus the re-pinned rotation test (B183) |
| R37-14 | fixed | a chained prune record before any deletion; a start above seq 0 that none names is a break; legacy trails via `audit acknowledge-prune` | three tests (B184) |
| R37-15 | fixed | every unknown `GRAPHITE_*` name refuses; near-misses outside the prefix refuse. Re-pinned: `round36_env_names::known_and_unrelated_names_start` (it pinned "unknown names only warn") | `a_misspelled_protective_switch_refuses_to_start_however_far_off` (B175) |
| R37-16 | fixed | the `program_deployments` residual; one undecodable entry no longer fails the batch (`ProgramDeployment::Unreadable`). Two test harnesses' fixture programs were not real `Program` accounts and now are | `rm1_program_upgrade_detection`, two tests (B178) |
| R37-17 | fixed | one default lock directory per user from the account database; a home that is not absolute refuses to start | `guard-round38.test.ts` (B201) |
| R37-18 | fixed | `CURRENT.md` (dust minimums, grant and declaration counts, what binds an amount, live runs, readiness), `.env.example` and `install.md` on the waiver, `ARCHITECTURE.md:308`, the audit hand-off | `docs_numbers_match_the_code` caught one stale count during the round |

### P3

| ID | State | What was done |
|---|---|---|
| B-5 | documented limitation | a sibling inside the same transaction that moves the pool sets the simulated reference price. Two decoded swaps in one transaction are already unbound, and value leaving to an outsider is a mismatch (R37-1); a pool moved with an outsider's own funds through an unread program is not detected. Cost of a fix: a price oracle the Core does not have |
| B-6 | fixed; partly a limitation | a native Stake `Withdraw` is held to the request's amount (B174). The Stake Pool and Marinade withdrawals name pool tokens or mSOL, not the SOL a request names, and are not compared; they pay only the owner |
| B-7 | fixed | `le_u64`/`le_u32` check their end (B169) |
| B-8 | documented limitation (fails closed) | honest swaps refused: unwraps and CLMM fees at L4, as pass 1 recorded (§E) |
| T-6 | already fixed by pass 1; pinned | `an_archive_scanned_with_a_prefilter_walks_every_line` (B185) |
| T-9 | fixed | the restore anchor by content (B181) |
| T-11 | fixed | B186 |
| T-12 | fixed | `macs_not_covered`; exit 4 (B187) |
| T-13 | fixed | B188 |
| T-14 | fixed | exit 3 / 64 / 75 (B189) |
| T-15 | fixed | 8 MiB per line, 64 KiB per checkpoint (B190) |
| V-2 | fixed | B176 |
| V-3 | fixed | B177 |
| V-5 | fixed | `verify_offline` checks source, tier and distinct attesters; `registry verify-records` (B179) |
| V-6 | fixed | `SECURITY.md` |
| G2-2 … G2-5 | fixed | B202–B205 |
| G2-6 | dashboard fixed (B206); Windows a documented limitation | Node cannot read Windows ACLs without a native addon, and the guard loads none; the default directory is in the user's own profile, and the startup log says so |
| D2-3 … D2-7 | fixed | B194–B198 |
| D2-8 | partly fixed; the rest a limitation | `test-count.sh` counts and enforces per binary when given a floors file (B199). Rust CI passes none yet: the per-binary numbers need a CI run of each leg, which this container cannot read (the proxy blocks the log storage) |
| D-8 residual | fixed, not built here | the image's apt sources are one `snapshot.debian.org` timestamp, in `pinned-tools.json` (B200). Not built in this container (no Docker daemon, Debian hosts blocked); CI's container job is the first build |
| DOC2-6, DOC2-8 … DOC2-17 | fixed | `AUDIT/FINAL.md` after Round 38; the owner gates in the checklist (PRs #46, #47/#48/#52, the nine medium-confidence rewrites); `GRAPHITE_AUDIT_PREVIOUS_KEY_FILE` in `.env.example`; one risk-pattern count (13 detection patterns, 14 variants with `PluginBlock`, 16 checks); one readiness wording; Rounds 35–38 in the roadmaps; the grant proposal's §4; the README's real-traffic row (0 of 200); the cancelled run marked; F-006 and R36-D1 in the Round 36 severity table |
| DOC2-18 | fixed | a note where the Round 33 report and the Round 34 brief are first cited: they are not in the repository |

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

**Second pass: B169–B206**, recorded in full in `AUDIT/01-findings.md`. All caught. B171b, the
one-mover choice alone, is caught for the theft by the same fix's two-signers rule, and B172 is
also refused end to end by L4's W19.

## D. What was run

All on the integrated tree (`a3b9e73`), in this session's Linux container, debug profile without
debug info. Push and CI runs are recorded on the PR when the owner allows the push.

| Leg | Command | Result |
|---|---|---|
| fmt | `cargo fmt --all -- --check` | clean |
| clippy, three legs | `--all-targets --all-features`; `--lib --no-default-features`; `--all-targets --no-default-features --features cli`, each `-D warnings` | clean (the first run caught two lints in `intent_binding.rs`, fixed in `a3b9e73`) |
| Rust default | `cargo test --locked` | **2,387 passed**, 0 failed, 14 ignored, 171 targets (floor 2,363 → 2,387) |
| Rust lib | `cargo test --locked --no-default-features --lib` | **517 passed**, 0 failed, 3 ignored (floor 513 → 517) |
| Rust cli | `cargo test --locked --no-default-features --features cli` | **1,947 passed**, 0 failed, 5 ignored (floor 1,942 → 1,947) |
| release | `cargo build --locked --release --all-features` | builds |
| runtime oracle | `tools/runtime-oracle`, `--iterations 300000` | "Graphite is never looser than the runtime" |
| inner-instruction oracle | `tools/inner-instruction-oracle`, `--iterations 1000000`, Rust 1.99.1 (CI's) | "every rebuild round-trips through Agave's parser" |
| deploy kit | `deploy/tests/run.sh` against the release binary | 138 of 162: Caddy and promtool are not installed in this container, so the edge and promtool checks fail and the single-writer head check reads an empty trail. The keyed trail was then checked by hand against the release binary: written, verified (`tamper_evident`, a trail id), resumed after a restart under the same id. CI runs the whole kit |
| pinned outputs | `regression_corpus`, `release_evaluation`, `mainnet_conformance`, `r30_declared_effects_census` | unchanged, except the census's new pinned R37-6 row |

No TypeScript, Go or Python file changed in Round 38's commits. The F-001 test and the CI script
changes are PR #54's, green in CI run 40121939855.

## E. Residuals and what this round did not do

- **Every Round 37 finding is dispositioned** (§B). The documented limitations are B-5, the pool
  and Marinade half of B-6, B-8, G2-6 on Windows, the unwired half of D2-8 and the unbuilt image of
  D-8.
- **Relayed transactions are refused at L4 (pre-existing, found by R37-9's tests).** A fee payer
  the request does not name moves lamports (the fee) on an account the verification did not
  examine: `ArtifactEffectsNotCovered`. Honest relayed swaps are therefore refused; that fails
  closed. Naming the fee payer in the request is the way through; making L4 accept a fee-only
  change is a separate decision.
- **New behaviour that can refuse an honest deployment, by design:** a stray `GRAPHITE_*`
  variable (R37-15), an unreadable program deployment (R37-16, the new residual), a backup taken
  before a key rotation (R37-11), a trail pruned before this round until it is acknowledged
  (R37-14), and `graphite execution` without the audit key (T-11).
- **Audit trail, second pass.** Not measured: the cost of the index MAC and of the coverage walk
  after a rotation (one extra pass per process, and every index rebuilt once after a rotation). A
  same-length index rewrite inside one filesystem timestamp tick is not detected (the index is
  then still MAC-checked, so this matters only to the handle rule). Truncating the newest records,
  a prune record among them, is caught only by an anchored checkpoint, as before. A reader holding
  the first and third of three keys but not the second does not read the second's records (fails
  closed).
- **Not run here:** the new workflows (`release-guard.yml`, `ruleset-drift.yml`) are linted and
  structure-tested only; the image was not built (no Docker daemon); the deploy kit's Caddy and
  promtool checks need tools this container lacks (§D).
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
- **Release integrity (R37-8):** apply the three rulesets, create the `release` environment
  (reviewer, `v*` policy), run `ruleset-drift.yml`, read the bypass lists by hand
  (`docs/ops/production-checklist.md` R1–R5).
- **Confirm** that Dependabot PRs #46, #47, #48 and #52 are closed unmerged as intended, and sign
  off the nine medium-confidence declaration rewrites (checklist items 6 and 13).
- **Clean the environment** of `GRAPHITE_*` names no component reads before upgrading (R37-15).
- **Take a fresh backup after each key rotation** (R37-11), and acknowledge any trail pruned before
  this round after checking it (R37-14).
- **Upgrade order.** Upgrade `graphite audit verify` before the server: chain link v2 and prune
  records are unreadable by Round 30–37 binaries.
- **Re-adopt keyed trails.** Run `graphite audit adopt-key` on trails adopted in Rounds 34–37 that
  carry legacy records.
