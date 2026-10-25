# Round 39 — core-decision workstream

Internal review work, one workstream of Round 39. It is not an independent audit and not a
certification. Target `c087bfb`. Scope: the decision pipeline in `graphite-core/src/`.

Every attack below ran end to end through `verify_async` against a loopback mock RPC
(`127.0.0.1:0`, answering `getMultipleAccounts`, `getAccountInfo`, `getEpochInfo` and
`simulateTransaction`). No public RPC was contacted, and no live wallet or funds were touched.
The tests are in `graphite-core/tests/round39_decision_campaigns.rs`.

## 1. Scope read

| File | Read | Disposition |
|---|---|---|
| `verification.rs` | Read fully: 1–4000 and 4595–10958 (production). Skimmed: L8 `audit_execution` (4001–4595), which belongs to another workstream. | `verify_async`, scope and residuals, `execution_decision`, sibling coverage, CPI nesting, quarantine, binding call site, observation recording. **R39-CORE-DECISION-2 fixed here** (binding call site). |
| `intent_binding.rs` | Read fully (production 1–2032). | **R39-CORE-DECISION-1 fixed here** (`keeps_value`'s notion of "the signer's own"). |
| `intent_grants.rs` | Read fully (production 1–940). | `owner_key` added. No finding in the table itself. |
| `state_diff.rs` | Read in part: 480–700, 1012–1080, 1120–2100, 2283–2330, 3667–4800 (`check_state_diff_with` in full). Machine-validated: the Token-2022 model (`token2022_extensions`, `round20_transfer_fee`, `r30_token2022_both_sides`), the declaration parser (`r30_declared_effects_census`). | `lamports_kept_by` made `pub(crate)`. No finding in L4. |
| `risk_engine.rs` | Read fully (production 1–1782). | No finding. Check 3 (drainer) and Check 10 are re-verified in §3. |
| `policy_engine.rs` | Read fully. | No finding. |
| `confidence_engine.rs` | Read fully. | No finding. Fresh-instance floor confirmed (§3). |
| `simulation_integrity.rs` | Read fully (production 1–811). | No finding (campaign 8). |
| `semantic_graph_store.rs` | Read fully (production 1–1163). | No finding (campaign 8). |
| `tx_pattern_analysis.rs` | Read fully (production 1–873). | No finding. "No cumulative value cap" confirmed (§3). |
| `unknown_protocol_mode.rs` | Read fully. | No finding. |
| `plugin_orchestrator.rs` | Read fully. | **R39-CORE-DECISION-3 fixed here** (a crashing Simulation plugin lost its veto). |
| `plugins/{mod,event_logger,fake_rewards_drainer}.rs` | Read fully. | P3 observations only (§2). |
| `regression_engine.rs` | Read fully (production 1–524). | No finding. |
| `release_eval.rs` | Read fully (production 1–702). | No finding. It scores the core `approved` verdict, not `executable_approved`, and says so (`sample_bias`). |
| Tests | Read: `round36_intent_binding.rs`, `round38_{sibling_skims,create_funding,unscoped_authority}.rs`, `r30_declared_effects_census.rs`, the plugin unit tests. Run: the full default leg (§6). | One re-pin (R39-3, `test_panicking_blocking_plugin_fails_closed`) and one compile fix (`round36_intent_binding`: the new `WithdrawalContext.owner` field, set to the wallet; no assertion changed). |

## 2. Findings

Commits: `b3fdd7f` (R39-CORE-DECISION-1 and -2), `8f225d0` (R39-CORE-DECISION-3, campaigns 3
and 12, the false-refusal measurements). Severities use the brief's scale. "Reproduced" means
a test through `verify_async` failed on `c087bfb` (or under the deliberate break) and passes
after the fix.

### R39-CORE-DECISION-1 — the sibling rule called any signer "the owner's" — P0-class, FIXED

- **Where.** `intent_binding.rs`, `keeps_value` (the Round 38 R37-1/R38-1 sibling rule) and
  `bind_create`. Both used `signers_own`: an account was "the signer's own" if it was any
  signer, or a token account whose owner field was any signer.
- **Preconditions.** The owner signs a granted withdrawal, a swap or a creation that an attacker
  built. The attacker either co-signs, or adds a `CreateAccount` (whose new account signs), or
  pre-creates a token account whose owner field is the victim's and whose close authority is
  the attacker's. SPL `SetAuthority(AccountOwner)` keeps a non-native account's close
  authority, so this account is cheap to make.
- **Confidence precondition (applies to R39-1, -2 and -3).** On a fresh instance the confidence
  is 0.44, below every built-in profile's floor. The verdicts above were therefore reached with
  `Custom{0.40, OfficialManifest}`, the bar of the Round 38 harnesses. In production they need
  either a program whose L3 baseline lifts its confidence past the profile's floor, or an
  operator profile at or below 0.44. Every gate other than confidence passed them.
- **Impact.** Value leaves the owner and reaches executable_approved. On `c087bfb`, beside a
  granted Stake `Withdraw` of 40 SOL to its owner, 30 SOL of the owner's went to the attacker in
  three ways, each executable under the defaults (`Custom{0.40, OfficialManifest}`) **and**
  under every waiver:
  - (A) 30 SOL into the attacker-closable token account. The attacker closes it later.
  - (B) 30 SOL to a co-signing attacker.
  - (C) a `CreateAccount` of 30 SOL for the attacker's program.

  A swap of Y into SOL with 5 SOL into the attacker-closable account was executable with the
  waivers on. Under the defaults only L4 W19 held it, and the binding said Bound, because
  `-lamports_out` counted the account's lamports as delivered.
- **Fix.** `kept_by(account, keepers, diff)` asks `state_diff::lamports_kept_by`, L4's own
  predicate: the keeper must sign, the account must not be frozen, and its delegate and close
  authority must sign. It asks this of the wallet whose operation it is:
  - for a swap, the swapping wallet;
  - for a grant, the grant's owner role (`intent_grants::owner_key`);
  - for a creation, the fee payer.
- **Tests.**
  - `round39_what_keeps_value_calls_the_signers_own_beside_a_withdrawal`: A, B and C must name
    `WithdrawalUnderbounded`; D is a control that risk refuses.
  - `round39_sol_into_an_attacker_closable_account_beside_a_swap`.
  - `round39_what_rides_beside_a_creation_is_held_to_the_payer`.
  - The benign control is `round39_a_withdrawal_beside_the_owners_own_wrap_is_executable`.
- **Break B1** (`kept_by` back to `signers_own`): 3 tests fail.
  - `round39_what_keeps_value…`: A, B and C are executable under both configurations.
  - `round39_sol_into…`: Y→SOL with all waivers is executable.
  - `round39_what_rides_beside_a_creation…`: L4 still refused the co-signer case under the
    defaults (`SignerLamportsBeyondDeclaredAmount`), but the binding no longer named it.

  `round38_sibling_skims` and `round38_create_funding` still pass under B1, so before Round 39
  they did not cover this.
- **Confidence.** High. Reproduced.

### R39-CORE-DECISION-2 — claim, close and configure grants were not held — P0-class, FIXED

- **Where.** `verification.rs`, the binding call site. Round 38 ran `withdrawal_keeps_value`
  only for `WITHDRAW_TO_OWNER`. The other grounded classes (`CLAIM_TO_OWNER`, `CLOSE_TO_OWNER`,
  `OWNER_CONFIGURE`) went straight to `bind_request`, with nothing beside them held.
- **Impact on `c087bfb`.**
  - A Meteora DLMM `claim_fee` paying 500 X, with a `TransferChecked` of 300 X to the attacker:
    executable under the defaults and under the waivers.
  - The same claim with 3 SOL to a stranger: executable with the waivers.
  - A Raydium CLMM `close_position` refunding ~5.5M lamports, with 5,000,000 to a stranger:
    executable under the defaults.
  - The same close with 3 SOL to a stranger: executable with the waivers.
- **Fix.** `intent_binding::grant_keeps_value`:
  - the route is the grant's own program;
  - the keeper is the grant's owner;
  - every mint the owner holds is watched, together with the grant's minimum outputs' mints.

  A failure is `IntentMismatch`.
- **Tests.**
  - `campaign2_a_claim_close_or_configure_with_a_skim_beside_it_is_never_executable`: claim and
    close must name `IntentMismatch`.
  - The control is `campaign2_a_granted_claim_and_close_alone_are_executable`.
- **Break B2** (`grounded_owner_operation` forced false): `campaign2_a_claim_close…` fails.
- **Confidence.** High. Reproduced.

### R39-CORE-DECISION-3 — a crashing Simulation plugin lost its veto — P2, FIXED

- **Where.** `plugin_orchestrator.rs`, `run_family`. A panic in a Risk, Verifier or Policy
  plugin is a Block (Round 17, F-16-07). A panic in a Simulation plugin was a Note, "report-only".
  Since F11, though, a Simulation plugin's Block fails L3 and refuses the verdict, so the crash
  dropped a veto.
- **Preconditions.** An operator registers a Simulation plugin (library or embedder; no shipped
  plugin is Simulation-family), and an input makes it panic.
- **Impact.** On `c087bfb` an honest-looking swap with a panicking Simulation plugin was
  `ExecutableApproved`, under the defaults and under every waiver. The same plugin returning
  Block refuses.
- **Fix.** The Simulation family joins the fail-closed set. The module doc and the
  `simulation_verdicts` doc are corrected.
- **Re-pin.** `plugin_orchestrator::tests::test_panicking_blocking_plugin_fails_closed` asserted
  the Note. It now asserts `Block{pattern: "panic-sim:panicked"}`, and a comment gives the
  reason.
- **Tests.**
  - `round39_a_crashing_plugin_of_any_family_refuses`: 7 family/layer slots × 2 configurations,
    each refused and each naming "panicked".
  - The control is `campaign12_a_plugin_that_finds_nothing_leaves_an_honest_swap_executable`.
- **Break B3** (Simulation removed from the set): the unit test and
  `round39_a_crashing_plugin_of_any_family_refuses` fail.
- **Confidence.** High. Reproduced.

### R39-CORE-DECISION-4 — honest swaps refused by their declarations — P2 false refusal, OPEN (owner decision)

Measured in §4 (false refusals). Of 115 shipped swap and route instructions that a `swap` intent
describes, 101 refuse an honest swap by default because of their manifest text.

Committed IDLs exist for every program named in §4's table:
- `scripts/idls/raydium_cpmm.json`
- `scripts/idls/orca-whirlpools.json`
- `scripts/idls/jupiter.json`
- `scripts/out/onchain_idls/…`

So a rewrite in the style of Round 36's F-005 would be IDL-backed. No manifest was changed here.

**Confidence.** High. Reproduced end to end for 4 venues, census for the rest.

### R39-CORE-DECISION-5 — the marketplace `update_offer` configure grant can never pass — P3 false refusal, OPEN (owner decision)

**Line.** `CcmRKTuZ…` `update_offer` declares:
- "modifies writable accounts: buyer, offer, buyer_user_escrow_account,
  buyer_user_escrow_token_account, buyer_usdc_account";
- "updates protocol configuration or authority".

Neither line names a debit.

**Effect.** An honest update moving the buyer's USDC into escrow is refused by L4
`UndeclaredTokenDebit`, so the grant is dead. This is pinned in
`campaign2_a_granted_claim_and_close_alone_are_executable`.

**Confidence.** High. Reproduced.

### P3 observations (no change made)

- **No per-plugin timeout.** Plugins run synchronously on the request's worker. A plugin
  sleeping 300 ms delays the verdict by 300 ms
  (`campaign12_a_plugin_that_finds_nothing_leaves_an_honest_swap_executable`). Only in-tree
  plugins can be activated, and the server's request timeout bounds the wait. The same applies
  to the event logger's `FileSink` I/O.
- **The drainer plugin's reason echoes `raw_natural_language`.** It reaches the response only:
  the audit row carries no finding text, and the 1 MiB body limit bounds it.
- **The burn grant's CloseAccount rent sibling is not held.** It is rent-sized only.
- **A swap skim of SOL within `SWAP_SOL_OVERHEAD` (0.01 SOL) into a kept account is a
  residual.**
- **`withdrawal_keeps_value`'s route is every instruction of the grant's program.** A second
  Stake `Withdraw` to the attacker, or a Stake `Authorize`, is therefore exempt from the sibling
  rule. Both are refused end to end: the second withdraw by secondary-instruction risk
  (Check 10), and Authorize by L4 `UndeclaredNativeAuthorityChange` (test case D). This is a reliance on
  another layer, not a gap observed.
- **Honest swaps through Pump AMM, Meteora DAMM v1/v2 and every other undecoded venue stay
  unbound** (`intent_parameters`, analysis-only) under every waiver. `decode_swap` reads 6
  programs. Fail-closed by design.

## 3. Prior findings re-verified

| Item | Status at `8f225d0` | Evidence |
|---|---|---|
| R37-1 / R38-1 sibling rule beside a swap | Holds. **Widened**: keepers, not signers (R39-1). | `campaign1_a_swap_skimmed…` — output skim, Token-2022 skim, close-and-sweep, owner, close-authority and approve changes, CPI token and lamport skims, extra signer, relayer — all refused under the defaults **and** every waiver. `round38_sibling_skims` 12/12. |
| R37-1 / R38-1 beside every granted withdrawal | Holds for withdraw. It **did not hold** for claim, close and configure (R39-2, fixed). | `campaign2_a_withdrawal_with_anything_beside_it…` — stranger, closable, co-signer, create-funding, owner, close-authority and freeze changes, close, approve, burn, hidden CPI, second withdraw, Authorize — refused under both configurations. |
| R37-6 unscoped authority lines | Holds. | `round38_unscoped_authority` 7/7. The owner, close-authority and freeze variants beside a withdrawal are refused under all waivers. |
| R37-7 creation funded beyond rent, and the double count | Holds. | `round38_create_funding` 4/4. `round39_what_rides_beside_a_creation…`: the co-signer and closable variants. |
| R37-9 relayer / co-signer swap | Holds. Relayed swaps are refused end to end by L4 `ArtifactEffectsNotCovered` (a false-refusal class, below). | `a_relayed_swap_is_bound_to_the_wallet_that_swaps`, `a_relayer_taking_the_owners_*`. `Beside::RelayerTakes` under all waivers. |
| R37-10 transfer beside an unread program | Holds. | `a_transfer_beside_an_unread_program_the_owner_signs_is_not_bound`. |
| B-5 (pool moved by a sibling sets the reference price) | Documented limitation, unchanged. | Code-reviewed. |
| B-6 (Stake Withdraw held to the request's amount) | Holds. | `campaign2_an_honest_stake_withdrawal…` and the over-amount cases in `round36_intent_binding`. |
| B-7 (`le_u64`/`le_u32` bounds) | Holds. | §5: every `expect` is behind a length check. |
| B-8 (honest swaps refused: unwraps, CLMM fees) | Fails closed, still a limitation. Quantified for declarations in §4. | `the_owners_own_wrap_and_unwrap_are_bound`. |
| False refusal: declarations not naming the input | **Quantified** (R39-4). | §4. |
| False refusal: wrap/unwrap | The owner's own wrap beside a withdrawal is executable. | `round39_a_withdrawal_beside_the_owners_own_wrap_is_executable`. |
| False refusal: relayed fee payer | Refused end to end: L4 `ArtifactEffectsNotCovered`, the fee payer is not named. | `round38_sibling_skims`. Unchanged; owner decision. |
| `intent_parameters` residual | Correct. Never executable, under every waiver. It does not stop observation recording, which then still needs every other gate. | Pool-swap rows for Pump AMM and DAMM v2. `execution_decision` code-reviewed. |
| `program_deployments` residual | Correct. A non-inherent code makes the decision analysis-only. | `execution_decision` code-reviewed. |
| "No cumulative value cap" | Confirmed limitation. `assess_secondary_instructions` only warns on ≥3 repeated unmanifested secondary calls. | Code-reviewed (`risk_engine.rs`). |
| Confidence floor on a fresh instance | Confirmed: 0.20 manifest + 0.14 OfficialManifest + 0.10 L5 = **0.44**, below Gaming's 0.55. Under `BuiltinFloor` a fresh program never learns from traffic. | Every record line shows `Confidence: 0.4400`. `round30_trust_learning` 13/13. |
| Drainer heuristic as a coverage boundary | Confirmed: Check 3 reads the manifest's own list. Plugin rules never reach it (A3-05). | `campaign12_protocol_rules_for_an_unmanifested_program_approve_nothing`. |

## 4. Attack campaigns

Shared fixture: `tests/round39_decision_campaigns.rs`.
- The loopback mock RPC serves the pre- and post-states the test sets. `simulateTransaction`
  returns `err: null`, 40,000 CU and no inner instructions.
- `Waivers::None` is `GraphiteCore::new()` with `Custom{0.40, OfficialManifest}`.
- `Waivers::All` is `new_without_plugins` plus:
  - both `L4Relaxations` fields
    (`GRAPHITE_ALLOW_UNREADABLE_VALUE_DECLARATIONS`,
    `GRAPHITE_ALLOW_SIGNER_LAMPORTS_OUTSIDE_DECLARED_DEBIT`);
  - `set_allow_unbounded_withdrawals` (`GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS`);
  - `set_allow_durable_nonce` (`GRAPHITE_ALLOW_DURABLE_NONCE`);
  - `ObservationPolicy::OperatorBootstrap`;
  - `Custom{0.0, Unknown}` (the most that `GRAPHITE_ALLOW_PERMISSIVE_PROFILES` admits).

  `GRAPHITE_ALLOW_UNCAPPED` is a guard-side switch only; it does not reach the Core.
- Command:
  `CARGO_TARGET_DIR=/home/user/core-decision-target cargo test --locked -j 2 --test round39_decision_campaigns -- --nocapture`

| Campaign | Preconditions / fixture | Pre-fix (`c087bfb`) | Expected | Observed (`8f225d0`) | Test |
|---|---|---|---|---|---|
| 1 swap + something beside it | A Jupiter `route` Y→X and Y→SOL, with 14 `Beside` variants (§3 row 1). | Y→SOL plus SOL into a closable account was executable with the waivers (R39-1). The rest were refused. | Never executable, under any waiver. Honest controls executable. | As expected. | `campaign1_*`, `round39_sol_into_an_attacker_closable_account_beside_a_swap` |
| 2 granted withdrawal / claim / close / configure + something beside it | A Stake `Withdraw` of 40 SOL with 15 variants. DLMM `claim_fee`, CLMM `close_position` and marketplace `update_offer` with a token skim or a stranger. | A/B/C executable under both configurations (R39-1). Claim and close skims executable (R39-2). | Never executable under any waiver. The honest withdrawal, claim and close are executable. | As expected. `update_offer` is refused even when honest (R39-5). | `campaign2_*`, `round39_what_keeps_value_*`, `round39_a_withdrawal_beside_the_owners_own_wrap_is_executable` |
| 3 creation + something beside it | A System `CreateAccount` (165 B, rent only) with a co-signer, or with an attacker-closable account beside it. | Defaults: refused by L4 `SignerLamportsBeyondDeclaredAmount`, but the binding did not name it (B1). | Refused with `IntentMismatch` under both configurations. Rent-only creation executable. | As expected. | `round39_what_rides_beside_a_creation_is_held_to_the_payer`; `round38_create_funding` 4/4 |
| 6 Token-2022 | Transfer fee, extensions on both sides, a permanent delegate on an unread mint, signer value netting. | — | Refused unless modelled exactly. | Pass. | `token2022_extensions` 16, `round20_transfer_fee` 22, `r30_token2022_both_sides` 5, `audit_a2_permanent_delegate_unread_mint` 1, `signer_value_netting` 12. The `Token2022Skim` variant runs under all waivers. `mainnet_transfer_fee_live` is ignored: it needs a public RPC, which this workstream may not contact. |
| 8 baseline poisoning | Identical-request inflation, errored simulations, refused requests, variance ratchet, shadow accumulators. | — | No refused, errored or duplicate request trains a baseline. | Pass. | `round19_what_one_observation_is` 7, `round17_remediations` 10, `round30_trust_learning` 13, `audit_a2_shadow_takes_refused_requests` 2, `audit_2026_10_20_simulation_gate` 8, `audit_a2_baseline_variance_ratchet` 1. Code-reviewed: recording needs RPC simulation, a located instruction, nothing else refused, policy admission and risk Clear. |
| 12 plugins veto only | Test plugins in every family and layer: Risk at L7; Verifier at L2/L4/L5/L8; Policy at L6; Simulation at L3. Also a ProtocolPlugin. | Simulation panic → executable (R39-3). | Panic → refused. Block of any shape (proper, empty, `"warning"`) → refused. NoFinding or an "APPROVED … sign" Note never lifts a skim or an owner change. Protocol rules never approve an unmanifested program. A slow plugin delays the verdict (no timeout). | As expected. | `campaign12_*`, `round39_a_crashing_plugin_of_any_family_refuses` |

### False refusals: honest pool swaps (R39-CORE-DECISION-4)

`round39_honest_pool_swaps_and_the_declarations_that_refuse_them` runs eight venues end to end.
In each, the owner's input pays the pool, the pool pays the owner's output, and nothing rides
beside it. Instruction data is exactly the layout's length.

| Venue | Defaults | All waivers | Cause (manifest line) |
|---|---|---|---|
| Raydium CLMM `swap_v2` | executable | executable | — ("transfers the input tokens from accounts.input_token_account to accounts.input_vault") |
| Meteora DLMM `swap` | executable | executable | — |
| Raydium AMM v4 `SwapBaseIn` | executable | executable | — |
| Pump AMM `sell` | analysis-only | analysis-only | L4 passes. Not decoded by `decode_swap` → `intent_parameters`. |
| Raydium CPMM `swap_base_input` | **Blocked**, L4 `SignerTokenDebitUnderUnscopedDebit` | executable | `raydium-cpmm.json`: "credits the output token account with the received amount for the swap". The word *swap* declares a debit naming no account (R33-5). The other line, "modifies writable accounts: …", declares nothing. |
| Meteora DAMM v2 `swap` | **Blocked**, same finding | analysis-only (undecoded) | `cp-amm-cpamdp.json`: the same two lines. |
| Orca Whirlpools `swap` | **Blocked**, same finding | executable | `orca-whirlpools.json`: "debits user source token account" (names no `accounts.<x>`). |
| Orca Whirlpools `swapV2` | **Blocked**, same finding | executable | `orca-whirlpools.json`: "Orca Whirlpools instruction" plus "credits the output token account with the received amount for the swap". |

**Census.** `round39_swap_declaration_census` covers every shipped instruction named
`*swap*`/`*route*` that L5 accepts for `swap`. It uses the real parser and is pinned at
`[("b", 8), ("d", 93), ("e", 14)]`:

- **e (14)** name a user-side account as debited:
  - Raydium AMM V4 ×4;
  - Raydium CLMM `swap`, `swap_v2`;
  - Jupiter `route`, `sharedAccountsRoute`, `route_v2`, `shared_accounts_route_v2`;
  - Meteora DLMM `swap`, `swap2`;
  - Dynamic Bonding Curve `swap`, `swap2`.
- **d (93)** declare a debit naming no account, so an honest swap is refused by default, and
  is relaxable only by `GRAPHITE_ALLOW_UNREADABLE_VALUE_DECLARATIONS`. By program:
  - OKX DEX Router 16;
  - Jupiter 12 (the exact-out, token-ledger and account-compression variants);
  - Perpetuals 7;
  - Swap Orchestrator 6;
  - Meteora DLMM 5;
  - Orca Whirlpools 4;
  - Gmsol Store 4;
  - Gamma 3, Byreal CLMM 3, AMM V3 3;
  - Raydium CPMM 2, Cp AMM 2, Phoenix 2, Stable Swap 2, Tail Trade 2, Mintfx 2, Limo 2,
    Fusionamm 2, Debot Router 2, DEX (jupZ4m2G) 2;
  - nine others with 1 each, among them Raydium CLMM `swap_router_base_in`, Orca TokenSwap V2
    `Swap` and Meteora DAMM v1 `swap`.
- **b (8)** — Jupiter's `*RouteCheck` variants ("Jupiter V6 aggregator instruction") — declare
  no debit Graphite can read.

The user-side test is a name heuristic (`user_side`); the end-to-end rows above are the
evidence. Swap venues whose instruction names do not say *swap* or *route* (for example Pump
AMM `buy`/`sell`) are outside the census.

Real-traffic rates cannot be measured from committed fixtures. The committed mainnet blocks and
the holdout are verified without simulation, so L4 never runs on them. A measured rate needs
simulated diffs from an RPC, which this workstream may not contact (§6, BLOCKED).

## 5. Invariant evidence

| Invariant | Evidence |
|---|---|
| No waiver turns a sibling skim, or an authority, delegate, close or freeze change, into `executable_approved`. | `campaign1_*` and `campaign2_*` run every case under `Waivers::All`. `Outcomes` collects every executable case before asserting, and none remain. |
| A plugin can only veto. | `PluginVerdict` has no pass variant. `campaign12_no_plugin_output_lifts_a_refusal`. `campaign12_protocol_rules…`. Plugin rules go to L4's structural check only; the diff is compared with the manifest's own declaration (W15). |
| A plugin that can block, blocks when it cannot run. | `round39_a_crashing_plugin_of_any_family_refuses`: 14 cases. |
| A malformed plugin Block still blocks. | `campaign12_a_plugin_block_of_any_shape_refuses_under_any_waiver`: 42 cases. A Risk `"warning"` pattern is renamed `warning-block`. |
| Honest controls stay executable. | Swaps Y→X and Y→SOL, the stake withdrawal, the claim and close, the rent-only creation, every NoFinding plugin, CLMM, DLMM and AMM v4 pool swaps: under both configurations. |
| Panics in production code. | Classified below. |

**Panic, indexing and arithmetic inventory** (production parts of the in-scope files, by
`grep`; every site read in context):

- **`expect`.** All are safe.
  - `intent_binding` `le_u64`/`le_u32`/`Reader::u64`, `intent_grants` minimum outputs, and
    `state_diff` stake fields all slice-check before the `try_into`.
  - `verification::nest` `expect("peeked")` follows `peek()`.
  - `bounded_archive_scan` `expect("the scan semaphore is never closed")` holds because the
    semaphore is static and never closed.
  - `regression_engine::content_hash`: `VerificationInput` serializes infallibly.
  - `plugins::mod` `builtin_plugin(...).expect`: the names are constants.
- **`unreachable!`.** `bind_swap`'s sits after a filter to decoded programs. `largest.expect`
  in `bind_create` runs only when an excess exists.
- **`panic!`.** `with_data_dir` is deprecated and documented to panic; `try_with_data_dir` is
  the fallible form. `release_eval::wilson95`'s `assert!` is guarded by `Rate::new`'s zero
  check, and k ≤ n by construction.
- **Indexing.** 73 sites, all guarded:
  - by a length-equality check (`grounded` metas, described vs actual accounts, `sim_pre` vs
    keys);
  - by `position()` or `enumerate()` on the same slice (`message.instructions[idx]`, deferred
    escalations, `layout[slot]` after `check()` proved `layout.len() == accounts.len()`);
  - by an explicit `offset + 4 > len` check (the Token-2022 TLV walks);
  - by non-empty guards (`median`, `relevant[0]`);
  - by `char_indices` (`short_id`, A1-03).
- **Arithmetic.** Release builds have no overflow checks (`Cargo.toml`). Value sums are widened
  to `i128`/`u128` (`lamport_delta`, `gross`, the binding totals), and `Reader` uses
  `checked_add`. No unchecked u64 sum over attacker-controlled amounts was found.

## 6. Commands and counts

All runs used
`CARGO_TARGET_DIR=/home/user/core-decision-target CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0`
and `-j 2`, from `graphite-core/`.

| Command | At | Result |
|---|---|---|
| `cargo test --locked` (default features) | `b3fdd7f` | **2,424 passed**, 0 failed, 14 ignored, 174 targets (floor 2,414 + 10 new) |
| `cargo test --locked --test round39_decision_campaigns` | `8f225d0` | 18 passed |
| `cargo test --locked` (default features) | `8f225d0` | **2,432 passed**, 0 failed, 14 ignored, 174 targets (floor 2,414 + 18 new) |
| `cargo test --locked --lib -- plugin round39 campaign` | `8f225d0` | 38 passed (includes the re-pinned unit test) |
| `cargo test --locked --no-default-features --lib` | `8f225d0` | **529 passed**, 0 failed, 3 ignored (floor 529; the round39 tests are rpc-gated) |
| `cargo test --locked --no-default-features --features cli` | `8f225d0` | **1,967 passed**, 0 failed, 5 ignored, 174 targets (floor 1,967) |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | `8f225d0` | clean |
| `cargo clippy --locked --no-default-features --lib -- -D warnings` | `8f225d0` | clean |
| `cargo clippy --locked --all-targets --no-default-features --features cli -- -D warnings` | `8f225d0` | clean |
| `cargo fmt -- --check` | `8f225d0` | clean |

**Breaks.** Each ran in a copy at `/home/user/brk-core-decision-1`, with a hard-linked copy of
the target dir at `/home/user/brk-core-decision-1-target`. Both were deleted afterwards.

- **B1:** `kept_by` reverted to `signers_own`. 3 tests fail: `round39_what_keeps_value_*`,
  `round39_sol_into_*` and `round39_what_rides_beside_a_creation_*`. `round38_sibling_skims`
  (12) and `round38_create_funding` (4) pass.
- **B2:** `grounded_owner_operation` forced false. `campaign2_a_claim_close_or_configure_*`
  fails.
- **B3:** Simulation removed from the fail-closed set.
  `plugin_orchestrator::tests::test_panicking_blocking_plugin_fails_closed` and
  `round39_a_crashing_plugin_of_any_family_refuses` fail.

**BLOCKED or not run.**
- **Real-traffic false-refusal rates.** These need simulated diffs from a Solana RPC, for
  example `GRAPHITE_MAINNET_RPC_URL=… cargo test --test mainnet_transfer_fee_live -- --ignored`.
  The workstream rules forbid contacting a public RPC.
- **`round36_intent_binding` in the break copy.** It includes
  `../../integrations/agent-guard/swap-instructions.ts`, which lies outside the copied crate. It
  passes in the worktree (22/22).
