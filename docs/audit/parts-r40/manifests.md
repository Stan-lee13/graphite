# Round 40 — manifests workstream

This is internal review work for one Round 40 workstream. It is not an independent audit or a certification, and it does not make Graphite production ready.

- **Base:** `1ae2066` (Round 39).
- **Scope:** the seed manifests (`graphite-core/protocols/`), the declaration-rewrite records (`docs/audit-r36/`, `docs/audit-r40/`), and `graphite-core/scripts/validate_corpora.py`.
- **`src/` changes:**
  - the removal of one grant in `intent_grants.rs`, which decision 3 requires;
  - one doc-comment number in `state_diff.rs`.
  - No rule in `state_diff.rs` or `intent_binding.rs` changed.
- **Machine record:** `docs/audit-r40/declaration-rewrites.json`. The tables below come from it.

## 1. Decisions implemented

### R39-CORE-DECISION-4: swap and route declarations rewritten from the committed IDLs

Round 39's census (`round39_swap_declaration_census`) found that 93 shipped swap/route declarations have a debit line that names no account. Because of R33-5, L4 refuses an honest swap through any of them (`SignerTokenDebitUnderUnscopedDebit`).

Of the 93:

- **60 were rewritten** using the Round 36 F-005 method: 36 at `high` confidence, 24 at `medium`.
- **7 were removed**, because no committed IDL has them (see R39-SUPPLY-CHAIN-11 below).
- **26 were left unchanged**, each with a reason (§3.2).

How the new lines were written:

- They come from the IDL instruction named in each record.
- Each line names an account for every effect it declares.
- The user's input account is the only user-side account named as debited.
- The user's output, fee, referral, host, commission and beneficiary accounts are named as credited only.
- Where the IDL sets the direction with an argument (`a_to_b`, `xToY`, `swap0to1`, the Phoenix order side), both of the user's accounts are named as debited, each under its condition written in prose. L4 does not read that condition; this is a residual (§9).

Two further constraints:

- **Debit/credit words kept.** Each declaration still contains the words "debit"/"credit". L4's structural check without a diff (`verify_state`) and the opt-in fake-rewards-drainer plugin both read those words (see the B-R3 break below).
- **No declaration got shorter.** The drainer heuristic counts lines.

The validator and the new tests check these rules on every row.

### R39-SUPPLY-CHAIN-11: 23 instructions that no committed IDL has, removed

- **Removed:** 15 Jupiter v6 and 8 Meteora DLMM instructions.
  - Each discriminator was checked against every committed IDL of its program. It matched no instruction by discriminator or by name. DLMM's `swap_2` matched only the real `swap2`, whose discriminator is different.
  - No committed real transaction calls any of them:
    - the 2,284-row mainnet sample, with every legacy, v0 and v1 frame decoded: 0 calls;
    - `fixtures/artifacts`: 0 calls;
    - the battle-tested observations: 0.
  - The only places their hex appeared were their own generated synthetic corpus rows.
- **Kept:** Squads v4's 5 instructions (`transactionBuffer{Create,Close,Extend}`, `vaultTransactionCreateFromBuffer`, `proposalCancelV2`).
  - They *are* in a committed IDL: `scripts/squads_v4_idl.json`, version 2.1.0, with matching discriminators.
  - The on-chain IDL account is the stale one.
  - They are now pinned as "only in an IDL file" (`PINNED_NEWER_THAN_ONCHAIN_IDL = 5`).
  - A future instruction with no IDL is now a validator **error**, not a pinned gap.

### R39-CORE-DECISION-5: the `update_offer` configure grant, removed

The committed IDL (`out/onchain_idls/CcmRKTuZ….json`, instruction `update_offer`) does three things:

- names `buyer_usdc_account` (the buyer's USDC ATA);
- names `buyer_user_escrow_token_account`;
- takes one argument, `new_price`.

It has no docs. It does **not** say that USDC moves, in which direction (a lower price could refund), or by how much (`new_price` is a price, not an amount). A debit line written from it would be inferred, not read.

So the grant was removed. `update_offer` now falls under its manifest class, `authority`, and is refused at L5 under `configure`. The `configure` intent and the `owner_configure` class remain in the vocabulary, but no grant uses them, so a configure intent declares nothing and fails closed.

### R39-SUPPLY-CHAIN-12: label fixes, wherever the evidence is in the repository

- **ATA `CreateAssociatedTokenAccount{,Idempotent}`, slot 0:** role changed from `writable` to `signer`, which matches its flags.
- **ATA slot 1 (`pda` with no seeds): measured, then reverted, so it is left and listed.**
  - The evidence is in the repository: all 439 ATA creations in the committed mainnet sample derive as `[{account_2},{account_5},{account_3}]` (wallet, token program, mint) under the ATA program. I checked this with an independent Python derivation.
  - With those seeds, the benign "ATA CreateIdempotent (legitimate)" shape in `src/benchmark.rs` uses an address that is not derived and is refused. That breaks `benchmark::tests::the_benign_shapes_are_approved`, `regression_engine::tests::benchmark_seeded_corpus_replays_clean_and_promotes` and the release evaluation's hand-built split.
  - Fixing that fixture is a `src/` and benchmark-data change, outside this workstream. The seeds and the fixture should go in together (§9).
- **Kamino `depositAndWithdraw` and `repayAndWithdrawAndRedeem`:** each repeated account name now carries its IDL group as a prefix, e.g. `depositAccounts_owner`. Each layout was checked name for name against the IDL's flattened leaves.
- **Solend:** 11 names that the generator had cut at 48 characters (`build_manifests.py` `[:48]`) were restored from the committed `scripts/solend_sdk_layouts.json`, together with the "modifies writable accounts" lines that list them.
- **Left as is:** Solend `FlashLoan`'s repeated "Token program id". The SDK gives both slots the same text, so any distinguishing name would be invented.

### F-005: the nine medium-confidence rewrites

Seven were promoted to `high`. Each promotion carries a recorded evidence record, and the validator re-checks every one:

- **Marinade `liquidUnstake`** — checked against the committed `scripts/idls/marinade.json`. All 10 slots match by name, writable flag and signer flag. Every account the lines name is writable and not a signer.
- **Stake Pool `WithdrawStake` and `WithdrawStakeWithSlippage`** — checked against `solana-program/stake-pool` `program/src/instruction.rs` at `63705a2dd9e8647fcfba9bfe1c411b049c209e9c`:
  - lines L302–L338 and L662–L692;
  - all 13 slots match by name and role;
  - the enum tags (10, 24) match the discriminators `0a`/`18`.
- **Raydium AMM v4 `SwapBaseIn`, `SwapBaseOut`, `SwapBaseInV2`, `SwapBaseOutV2`** — checked against `raydium-io/raydium-amm` `program/src/instruction.rs` at `91739d8d9f5cf347e0ce14ebe4d2bb7069fb31b6`:
  - lines L242–L262, L269–L289, L303–L313 and L315–L325;
  - the 18- and 8-slot lists match;
  - the 17-slot layout is the source's list without the optional `amm_target_orders`, which the source's own builders comment out (L898, L1000);
  - the tags 9, 11, 16 and 17 match.

Two stay `medium`, with a `promotion_review` record:

- **Stake Pool `WithdrawSol` and `WithdrawSolWithSlippage`.** The source marks slot 12 (`sol_withdraw_authority`, optional) as `[s]`; the manifest does not flag it as a signer. That is not an exact match.

The validator accepts a promotion only if it has:

- a sign-off string;
- for an upstream source: a public GitHub repository, a full 40-hex commit, a URL equal to `repo/blob/commit/path#La-Lb`, a SHA-256 of the fetched file, the tag equal to the discriminator, and a per-slot account list matching every layout by name and role;
- for a committed IDL: a slot-for-slot comparison that the validator runs itself.

Anything less is an error.

## 2. Gap Hunter (before coding)

1. **A rewrite widens L4.**
   - Risk: naming an account excuses a debit of it, and L4 does not bound amounts.
   - Guard: only the user's input is named as debited. The record's `debit_named` lists, for every row, exactly which accounts are excused, and a test checks that list against the real parser.
2. **Direction-dependent venues.**
   - Risk: Orca and others name both owner accounts as debited.
   - Guard: on the decoded venues, the binding holds the requested mints and amounts. On the others, the swap stays unbound.
3. **Undecoded venues lose a refusal.**
   - Before: L4 refused every signer debit, honest or not.
   - After: honest swaps and skims alike are `approved` but `analysis_only` (unbound), so never executable.
   - Measured and pinned (§5, §9).
4. **Wording side effects.**
   - Risk: words such as "mint", "owner", "fee", "pay", "open" or "close" declare unintended effects; the structural check needs the debit/credit words; FakeSwap needs credit/output; the drainer and hidden-transfer heuristics count lines and references.
   - Guard: all checked. The value-words gap was found by the attack suite (§6, B-R3) and fixed.
5. **Removal of something real.** Every discriminator was searched in the committed IDLs, fixtures, corpora and the mainnet sample. Squads was kept.
6. **Grant removal.** A capability is lost, but it never worked. The Python AI layer still suggests `configure` → `update_offer`, which is advisory only (§10).
7. **ATA seeds cause false refusals.**
   - Risk: every swap bundle creates ATAs.
   - Measured: 439 of 439 real creations derive correctly, and no mainnet verdict moved. But a benign benchmark fixture uses an address that is not derived, so the seeds were reverted (§1).
8. **Corpus, census, release-evaluation and mainnet pins move.** Every row is attributed (§5).

## 3. Changes

### 3.1 Declarations rewritten (60)

`old` is the removed lines. `new` is the added lines. The "modifies writable accounts" lines and bare identifiers were kept.

| Manifest | Instruction | Old (removed) | New (added) | IDL file + instruction | Conf. |
|---|---|---|---|---|---|
| raydium-cpmm.json | `swap_base_input` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.input_token_account to accounts.input_vault<br>transfers the output tokens from accounts.output_vault to accounts.output_token_account<br>debits accounts.input_token_account by the input tokens<br>credits accounts.output_token_account with the output tokens | `idls/raydium_cpmm.json` `swap_base_input` | high |
| raydium-cpmm.json | `swap_base_output` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.input_token_account to accounts.input_vault<br>transfers the output tokens from accounts.output_vault to accounts.output_token_account<br>debits accounts.input_token_account by the input tokens<br>credits accounts.output_token_account with the output tokens | `idls/raydium_cpmm.json` `swap_base_output` | high |
| gamma-gamma7.json | `oracle_based_swap_base_input` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.input_token_account to accounts.input_vault<br>transfers the output tokens from accounts.output_vault to accounts.output_token_account<br>debits accounts.input_token_account by the input tokens<br>credits accounts.output_token_account with the output tokens | `onchain_idls/GAMMA7me….json` `oracle_based_swap_base_input` | high |
| gamma-gamma7.json | `swap_base_input` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.input_token_account to accounts.input_vault<br>transfers the output tokens from accounts.output_vault to accounts.output_token_account<br>debits accounts.input_token_account by the input tokens<br>credits accounts.output_token_account with the output tokens | `onchain_idls/GAMMA7me….json` `swap_base_input` | high |
| gamma-gamma7.json | `swap_base_output` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.input_token_account to accounts.input_vault<br>transfers the output tokens from accounts.output_vault to accounts.output_token_account<br>debits accounts.input_token_account by the input tokens<br>credits accounts.output_token_account with the output tokens | `onchain_idls/GAMMA7me….json` `swap_base_output` | high |
| amm-v3-hpnfyc.json | `swap` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.input_token_account to accounts.input_vault<br>transfers the output tokens from accounts.output_vault to accounts.output_token_account<br>debits accounts.input_token_account by the input tokens<br>credits accounts.output_token_account with the output tokens | `onchain_idls/HpNfyc2S….json` `swap` | high |
| amm-v3-hpnfyc.json | `swap_v2` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.input_token_account to accounts.input_vault<br>transfers the output tokens from accounts.output_vault to accounts.output_token_account<br>debits accounts.input_token_account by the input tokens<br>credits accounts.output_token_account with the output tokens | `onchain_idls/HpNfyc2S….json` `swap_v2` | high |
| byreal-clmm-realqq.json | `swap` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.input_token_account to accounts.input_vault<br>transfers the output tokens from accounts.output_vault to accounts.output_token_account<br>debits accounts.input_token_account by the input tokens<br>credits accounts.output_token_account with the output tokens | `onchain_idls/REALQqNE….json` `swap` | high |
| byreal-clmm-realqq.json | `swap_v2` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.input_token_account to accounts.input_vault<br>transfers the output tokens from accounts.output_vault to accounts.output_token_account<br>debits accounts.input_token_account by the input tokens<br>credits accounts.output_token_account with the output tokens | `onchain_idls/REALQqNE….json` `swap_v2` | high |
| byreal-clmm-realqq.json | `swap_v3_dyn` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.input_token_account to accounts.input_vault<br>transfers the output tokens from accounts.output_vault to accounts.output_token_account<br>debits accounts.input_token_account by the input tokens<br>credits accounts.output_token_account with the output tokens | `onchain_idls/REALQqNE….json` `swap_v3_dyn` | high |
| amm-routing-realp6.json | `smart_swap_v3` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.user_input_token_account to accounts.input_vault<br>transfers the output tokens from accounts.output_vault to accounts.user_output_token_account<br>debits accounts.user_input_token_account by the input tokens<br>credits accounts.user_output_token_account with the output tokens | `onchain_idls/REALp6iM….json` `smart_swap_v3` | high |
| raydium-clmm.json | `swap_router_base_in` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.input_token_account into the first pool of the path; the pools and the output account are remaining accounts<br>debits accounts.input_token_account by the input tokens | `onchain_idls/CAMMCzo5….json` `swap_router_base_in` | high |
| amm-v3-hpnfyc.json | `swap_router_base_in` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.input_token_account into the first pool of the path; the pools and the output account are remaining accounts<br>debits accounts.input_token_account by the input tokens | `onchain_idls/HpNfyc2S….json` `swap_router_base_in` | high |
| cp-amm-cpamdp.json | `swap` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.input_token_account to the pool's vault<br>transfers tokens into or out of accounts.token_a_vault<br>transfers tokens into or out of accounts.token_b_vault<br>transfers the output tokens from the pool's vault to accounts.output_token_account<br>credits accounts.referral_token_account with the referral share when it is passed<br>debits accounts.input_token_account by the input tokens | `onchain_idls/cpamdpZC….json` `swap` | high |
| cp-amm-cpamdp.json | `swap2` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.input_token_account to the pool's vault<br>transfers tokens into or out of accounts.token_a_vault<br>transfers tokens into or out of accounts.token_b_vault<br>transfers the output tokens from the pool's vault to accounts.output_token_account<br>credits accounts.referral_token_account with the referral share when it is passed<br>debits accounts.input_token_account by the input tokens | `onchain_idls/cpamdpZC….json` `swap2` | high |
| amm-eo7wjk.json | `swap` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.userSourceToken to the pool's vault<br>transfers tokens into or out of accounts.aTokenVault<br>transfers tokens into or out of accounts.bTokenVault<br>transfers the output tokens from the pool's vault to accounts.userDestinationToken<br>credits accounts.protocolTokenFee with the protocol's share of the input<br>mints vault LP of accounts.aVaultLpMint or accounts.bVaultLpMint for the side the input enters<br>burns vault LP of accounts.aVaultLpMint or accounts.bVaultLpMint for the side the output leaves<br>debits accounts.userSourceToken by the input tokens | `onchain_idls/Eo7WjKq6….json` `swap` | high |
| omnipair-omnixg.json | `swap` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.user_token_in_account to accounts.token_in_vault<br>transfers the output tokens from accounts.token_out_vault to accounts.user_token_out_account<br>debits accounts.user_token_in_account by the input tokens<br>credits accounts.user_token_out_account with the output tokens | `onchain_idls/omnixgS8….json` `swap` | high |
| stable-swap-swapny.json | `swap` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.user_token_in to accounts.vault_token_in<br>transfers the output tokens from accounts.vault_token_out to accounts.user_token_out<br>credits accounts.beneficiary_token_out with the beneficiary's share of the output<br>debits accounts.user_token_in by the input tokens | `onchain_idls/swapNyd8….json` `swap` | high |
| stable-swap-swapny.json | `swap_v2` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.user_token_in to accounts.vault_token_in<br>transfers the output tokens from accounts.vault_token_out to accounts.user_token_out<br>credits accounts.beneficiary_token_out with the beneficiary's share of the output<br>debits accounts.user_token_in by the input tokens | `onchain_idls/swapNyd8….json` `swap_v2` | high |
| stableswap-ghosty.json | `swap` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.user_token_account_in to accounts.token_vault_in<br>transfers the output tokens from accounts.token_vault_out to accounts.recipient_token_account_out<br>debits accounts.user_token_account_in by the input tokens<br>credits accounts.recipient_token_account_out with the output tokens | `onchain_idls/ghosty4Z….json` `swap` | high |
| tail-trade-j51h4g.json | `lpPoolSwap` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.userInTokenAccount to accounts.constituentInTokenAccount<br>transfers the output tokens from accounts.constituentOutTokenAccount to accounts.userOutTokenAccount<br>debits accounts.userInTokenAccount by the input tokens<br>credits accounts.userOutTokenAccount with the output tokens | `onchain_idls/J51H4gev….json` `lpPoolSwap` | high |
| meteora-dlmm.json | `swap_exact_out` | Meteora DLMM instruction<br>credits the output token account with the received amount for the swap | transfers the input tokens from accounts.user_token_in to the pair's reserve<br>transfers tokens into or out of accounts.reserve_x<br>transfers tokens into or out of accounts.reserve_y<br>transfers the output tokens from the pair's reserve to accounts.user_token_out<br>credits accounts.host_fee_in with the host's share when it is passed<br>debits accounts.user_token_in by the input tokens | `onchain_idls/LBUZKhRx….json` `swap_exact_out` | high |
| meteora-dlmm.json | `swap_exact_out2` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.user_token_in to the pair's reserve<br>transfers tokens into or out of accounts.reserve_x<br>transfers tokens into or out of accounts.reserve_y<br>transfers the output tokens from the pair's reserve to accounts.user_token_out<br>credits accounts.host_fee_in with the host's share when it is passed<br>debits accounts.user_token_in by the input tokens | `onchain_idls/LBUZKhRx….json` `swap_exact_out2` | high |
| meteora-dlmm.json | `swap_with_price_impact` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.user_token_in to the pair's reserve<br>transfers tokens into or out of accounts.reserve_x<br>transfers tokens into or out of accounts.reserve_y<br>transfers the output tokens from the pair's reserve to accounts.user_token_out<br>credits accounts.host_fee_in with the host's share when it is passed<br>debits accounts.user_token_in by the input tokens | `onchain_idls/LBUZKhRx….json` `swap_with_price_impact` | high |
| meteora-dlmm.json | `swap_with_price_impact2` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.user_token_in to the pair's reserve<br>transfers tokens into or out of accounts.reserve_x<br>transfers tokens into or out of accounts.reserve_y<br>transfers the output tokens from the pair's reserve to accounts.user_token_out<br>credits accounts.host_fee_in with the host's share when it is passed<br>debits accounts.user_token_in by the input tokens | `onchain_idls/LBUZKhRx….json` `swap_with_price_impact2` | high |
| jupiter-v6.json | `exactOutRoute` | Jupiter V6 aggregator instruction<br>credits the output token account with the received amount for the swap | debits accounts.user_source_token_account by the input the route needs for data.out_amount, swapped through the routed venues<br>credits accounts.user_destination_token_account with the routed output<br>credits accounts.destination_token_account with the routed output when it is passed<br>credits accounts.platform_fee_account with the platform's share when it is passed | `onchain_idls/JUP6LkbZ….json` `exact_out_route` | high |
| jupiter-v6.json | `exact_out_route_v2` | Jupiter V6 aggregator instruction<br>credits the output token account with the received amount for the swap | debits accounts.user_source_token_account by the input the route needs for data.out_amount, swapped through the routed venues<br>credits accounts.user_destination_token_account with the routed output<br>credits accounts.destination_token_account with the routed output when it is passed | `onchain_idls/JUP6LkbZ….json` `exact_out_route_v2` | high |
| jupiter-v6.json | `routeWithTokenLedger` | swaps tokens through routed DEX venues<br>debits user source token account<br>credits user destination token account | debits accounts.user_source_token_account by the amount the token ledger records, swapped through the routed venues<br>credits accounts.user_destination_token_account with the routed output<br>credits accounts.destination_token_account with the routed output when it is passed<br>credits accounts.platform_fee_account with the platform's share when it is passed | `onchain_idls/JUP6LkbZ….json` `route_with_token_ledger` | high |
| jupiter-v6.json | `sharedAccountsExactOutRoute` | Jupiter V6 aggregator instruction<br>credits the output token account with the received amount for the swap | debits accounts.source_token_account by the input the route needs for data.out_amount<br>transfers the input from accounts.source_token_account to accounts.program_source_token_account<br>swaps through the routed venues from accounts.program_source_token_account to accounts.program_destination_token_account<br>transfers the routed output from accounts.program_destination_token_account to accounts.destination_token_account<br>credits accounts.destination_token_account with the routed output<br>credits accounts.platform_fee_account with the platform's share when it is passed | `onchain_idls/JUP6LkbZ….json` `shared_accounts_exact_out_route` | high |
| jupiter-v6.json | `shared_accounts_exact_out_route_v2` | Jupiter V6 aggregator instruction<br>credits the output token account with the received amount for the swap | debits accounts.source_token_account by the input the route needs for data.out_amount<br>transfers the input from accounts.source_token_account to accounts.program_source_token_account<br>swaps through the routed venues from accounts.program_source_token_account to accounts.program_destination_token_account<br>transfers the routed output from accounts.program_destination_token_account to accounts.destination_token_account<br>credits accounts.destination_token_account with the routed output | `onchain_idls/JUP6LkbZ….json` `shared_accounts_exact_out_route_v2` | high |
| jupiter-v6.json | `sharedAccountsRouteWithTokenLedger` | swaps tokens through routed DEX venues with shared accounts<br>debits user source token account<br>credits user destination token account | debits accounts.source_token_account by the amount the token ledger records<br>transfers the input from accounts.source_token_account to accounts.program_source_token_account<br>swaps through the routed venues from accounts.program_source_token_account to accounts.program_destination_token_account<br>transfers the routed output from accounts.program_destination_token_account to accounts.destination_token_account<br>credits accounts.platform_fee_account with the platform's share when it is passed | `onchain_idls/JUP6LkbZ….json` `shared_accounts_route_with_token_ledger` | high |
| orca-whirlpools.json | `twoHopSwapV2` | whirlpool protocol state transition<br>credits the output token account with the received amount for the swap | transfers the input tokens from accounts.token_owner_account_input to accounts.token_vault_one_input<br>transfers tokens into or out of accounts.token_vault_one_intermediate<br>transfers tokens into or out of accounts.token_vault_two_intermediate<br>transfers the output tokens from accounts.token_vault_two_output to accounts.token_owner_account_output<br>debits accounts.token_owner_account_input by the input tokens<br>credits accounts.token_owner_account_output with the output tokens | `onchain_idls/whirLbMi….json` `two_hop_swap_v2` | high |
| fusionamm-fusion.json | `two_hop_swap` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.token_owner_account_input to accounts.token_vault_one_input<br>transfers tokens into or out of accounts.token_vault_one_intermediate<br>transfers tokens into or out of accounts.token_vault_two_intermediate<br>transfers the output tokens from accounts.token_vault_two_output to accounts.token_owner_account_output<br>debits accounts.token_owner_account_input by the input tokens<br>credits accounts.token_owner_account_output with the output tokens | `onchain_idls/fUSioN9Y….json` `two_hop_swap` | high |
| orca-whirlpools.json | `swap` | swaps tokens across concentrated liquidity pool<br>debits user source token account<br>credits user destination token account<br>updates whirlpool reserves and tick arrays | when data.a_to_b is true, transfers the input tokens from accounts.token_owner_account_a to accounts.token_vault_a<br>when data.a_to_b is true, transfers the output tokens from accounts.token_vault_b to accounts.token_owner_account_b<br>when data.a_to_b is false, transfers the input tokens from accounts.token_owner_account_b to accounts.token_vault_b<br>when data.a_to_b is false, transfers the output tokens from accounts.token_vault_a to accounts.token_owner_account_a<br>when data.a_to_b is true, debits accounts.token_owner_account_a by the input tokens<br>when data.a_to_b is false, debits accounts.token_owner_account_b by the input tokens<br>when data.a_to_b is true, credits accounts.token_owner_account_b with the output tokens<br>when data.a_to_b is false, credits accounts.token_owner_account_a with the output tokens | `onchain_idls/whirLbMi….json` `swap` | high |
| orca-whirlpools.json | `swapV2` | Orca Whirlpools instruction<br>credits the output token account with the received amount for the swap | when data.a_to_b is true, transfers the input tokens from accounts.token_owner_account_a to accounts.token_vault_a<br>when data.a_to_b is true, transfers the output tokens from accounts.token_vault_b to accounts.token_owner_account_b<br>when data.a_to_b is false, transfers the input tokens from accounts.token_owner_account_b to accounts.token_vault_b<br>when data.a_to_b is false, transfers the output tokens from accounts.token_vault_a to accounts.token_owner_account_a<br>when data.a_to_b is true, debits accounts.token_owner_account_a by the input tokens<br>when data.a_to_b is false, debits accounts.token_owner_account_b by the input tokens<br>when data.a_to_b is true, credits accounts.token_owner_account_b with the output tokens<br>when data.a_to_b is false, credits accounts.token_owner_account_a with the output tokens | `onchain_idls/whirLbMi….json` `swap_v2` | high |
| fusionamm-fusion.json | `swap` | credits the output token account with the received amount for the swap | when data.a_to_b is true, transfers the input tokens from accounts.token_owner_account_a to accounts.token_vault_a<br>when data.a_to_b is true, transfers the output tokens from accounts.token_vault_b to accounts.token_owner_account_b<br>when data.a_to_b is false, transfers the input tokens from accounts.token_owner_account_b to accounts.token_vault_b<br>when data.a_to_b is false, transfers the output tokens from accounts.token_vault_a to accounts.token_owner_account_a<br>when data.a_to_b is true, debits accounts.token_owner_account_a by the input tokens<br>when data.a_to_b is false, debits accounts.token_owner_account_b by the input tokens<br>when data.a_to_b is true, credits accounts.token_owner_account_b with the output tokens<br>when data.a_to_b is false, credits accounts.token_owner_account_a with the output tokens | `onchain_idls/fUSioN9Y….json` `swap` | high |
| bonkswap-bswp6b.json | `swap` | credits the output token account with the received amount for the swap | when data.xToY is true, transfers the input tokens from accounts.swapperXAccount to accounts.poolXAccount<br>when data.xToY is true, transfers the output tokens from accounts.poolYAccount to accounts.swapperYAccount<br>when data.xToY is false, transfers the input tokens from accounts.swapperYAccount to accounts.poolYAccount<br>when data.xToY is false, transfers the output tokens from accounts.poolXAccount to accounts.swapperXAccount<br>credits accounts.referrerXAccount or accounts.referrerYAccount with the referrer's share<br>when data.xToY is true, debits accounts.swapperXAccount by the input tokens<br>when data.xToY is false, debits accounts.swapperYAccount by the input tokens | `onchain_idls/BSwp6bEB….json` `swap` | medium |
| guacswap-gswppe.json | `swap` | credits the output token account with the received amount for the swap | when data.xToY is true, transfers the input tokens from accounts.swapperXAccount to accounts.poolXAccount<br>when data.xToY is true, transfers the output tokens from accounts.poolYAccount to accounts.swapperYAccount<br>when data.xToY is false, transfers the input tokens from accounts.swapperYAccount to accounts.poolYAccount<br>when data.xToY is false, transfers the output tokens from accounts.poolXAccount to accounts.swapperXAccount<br>credits accounts.referrerXAccount or accounts.referrerYAccount with the referrer's share<br>when data.xToY is true, debits accounts.swapperXAccount by the input tokens<br>when data.xToY is false, debits accounts.swapperYAccount by the input tokens | `onchain_idls/Gswppe6E….json` `swap` | medium |
| phoenix.json | `Swap` | moves user funds between token accounts<br>credits the output token account with the received amount for the swap | on a bid, transfers the input tokens from accounts.quoteAccount to accounts.quoteVault and the output tokens from accounts.baseVault to accounts.baseAccount<br>on an ask, transfers the input tokens from accounts.baseAccount to accounts.baseVault and the output tokens from accounts.quoteVault to accounts.quoteAccount<br>on a bid, debits accounts.quoteAccount by the input tokens<br>on an ask, debits accounts.baseAccount by the input tokens<br>on a bid, credits accounts.baseAccount with the output tokens<br>on an ask, credits accounts.quoteAccount with the output tokens | `phoenix_idl.json` `Swap` | medium |
| dex-jupz4m.json | `swap_in` | credits the output token account with the received amount for the swap | when data.swap0to1 is true, transfers the input tokens from accounts.user_token_0_account to accounts.token_0_vault<br>when data.swap0to1 is true, transfers the output tokens from accounts.token_1_vault to accounts.user_token_1_account, or to accounts.recipient_token_1_account when it is passed<br>when data.swap0to1 is false, transfers the input tokens from accounts.user_token_1_account to accounts.token_1_vault<br>when data.swap0to1 is false, transfers the output tokens from accounts.token_0_vault to accounts.user_token_0_account, or to accounts.recipient_token_0_account when it is passed<br>when data.swap0to1 is true, debits accounts.user_token_0_account by the input tokens<br>when data.swap0to1 is false, debits accounts.user_token_1_account by the input tokens<br>when data.swap0to1 is true, credits accounts.user_token_1_account with the output tokens<br>when data.swap0to1 is false, credits accounts.user_token_0_account with the output tokens | `onchain_idls/jupZ4m2G….json` `swap_in` | medium |
| dex-jupz4m.json | `swap_out` | credits the output token account with the received amount for the swap | when data.swap0to1 is true, transfers the input tokens from accounts.user_token_0_account to accounts.token_0_vault<br>when data.swap0to1 is true, transfers the output tokens from accounts.token_1_vault to accounts.user_token_1_account, or to accounts.recipient_token_1_account when it is passed<br>when data.swap0to1 is false, transfers the input tokens from accounts.user_token_1_account to accounts.token_1_vault<br>when data.swap0to1 is false, transfers the output tokens from accounts.token_0_vault to accounts.user_token_0_account, or to accounts.recipient_token_0_account when it is passed<br>when data.swap0to1 is true, debits accounts.user_token_0_account by the input tokens<br>when data.swap0to1 is false, debits accounts.user_token_1_account by the input tokens<br>when data.swap0to1 is true, credits accounts.user_token_1_account with the output tokens<br>when data.swap0to1 is false, credits accounts.user_token_0_account with the output tokens | `onchain_idls/jupZ4m2G….json` `swap_out` | medium |
| okx-dex-router-provf4.json | `swap` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.source_token_account into the routed venues (remaining accounts)<br>transfers the output tokens to accounts.destination_token_account from the routed venues<br>debits accounts.source_token_account by the input tokens<br>credits accounts.destination_token_account with the output tokens | `onchain_idls/proVF4pM….json` `swap` | medium |
| okx-dex-router-provf4.json | `proxy_swap` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.source_token_account into the routed venues (remaining accounts), or to accounts.source_token_sa when it is passed<br>transfers the output tokens to accounts.destination_token_account from the routed venues, or from accounts.destination_token_sa when it is passed<br>debits accounts.source_token_account by the input tokens<br>credits accounts.destination_token_account with the output tokens | `onchain_idls/proVF4pM….json` `proxy_swap` | medium |
| okx-dex-router-provf4.json | `swap_tob` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.source_token_account into the routed venues (remaining accounts), or to accounts.source_token_sa when it is passed<br>transfers the output tokens to accounts.destination_token_account from the routed venues, or from accounts.destination_token_sa when it is passed<br>credits accounts.commission_account with the commission share when it is passed<br>credits accounts.platform_fee_account with the platform's share when it is passed<br>debits accounts.source_token_account by the input tokens | `onchain_idls/proVF4pM….json` `swap_tob` | medium |
| okx-dex-router-provf4.json | `swap_tob_enhanced` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.source_token_account into the routed venues (remaining accounts), or to accounts.source_token_sa when it is passed<br>transfers the output tokens to accounts.destination_token_account from the routed venues, or from accounts.destination_token_sa when it is passed<br>credits accounts.commission_account with the commission share when it is passed<br>credits accounts.platform_fee_account with the platform's share when it is passed<br>debits accounts.source_token_account by the input tokens | `onchain_idls/proVF4pM….json` `swap_tob_enhanced` | medium |
| okx-dex-router-provf4.json | `swap_toc` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.source_token_account into the routed venues (remaining accounts), or to accounts.source_token_sa when it is passed<br>transfers the output tokens to accounts.destination_token_account from the routed venues, or from accounts.destination_token_sa when it is passed<br>credits accounts.commission_account with the commission share when it is passed<br>credits accounts.platform_fee_account with the platform's share when it is passed<br>debits accounts.source_token_account by the input tokens | `onchain_idls/proVF4pM….json` `swap_toc` | medium |
| okx-dex-router-provf4.json | `swap_tob_with_token_ledger` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.source_token_account into the routed venues (remaining accounts), or to accounts.source_token_sa when it is passed<br>transfers the output tokens to accounts.destination_token_account from the routed venues, or from accounts.destination_token_sa when it is passed<br>credits accounts.commission_account with the commission share when it is passed<br>credits accounts.platform_fee_account with the platform's share when it is passed<br>debits accounts.source_token_account by the input tokens | `onchain_idls/proVF4pM….json` `swap_tob_with_token_ledger` | medium |
| okx-dex-router-provf4.json | `swap_tob_v2` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.source_token_account into the routed venues (remaining accounts), or to accounts.source_token_sa when it is passed<br>transfers the output tokens to accounts.destination_token_account from the routed venues, or from accounts.destination_token_sa when it is passed<br>credits accounts.parent_commission_account with the commission share when it is passed<br>credits accounts.child_commission_account with the commission share when it is passed<br>credits accounts.platform_fee_account with the platform's share when it is passed<br>debits accounts.source_token_account by the input tokens | `onchain_idls/proVF4pM….json` `swap_tob_v2` | medium |
| okx-dex-router-provf4.json | `swap_toc_v2` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.source_token_account into the routed venues (remaining accounts), or to accounts.source_token_sa when it is passed<br>transfers the output tokens to accounts.destination_token_account from the routed venues, or from accounts.destination_token_sa when it is passed<br>credits accounts.parent_commission_account with the commission share when it is passed<br>credits accounts.child_commission_account with the commission share when it is passed<br>credits accounts.platform_fee_account with the platform's share when it is passed<br>debits accounts.source_token_account by the input tokens | `onchain_idls/proVF4pM….json` `swap_toc_v2` | medium |
| okx-dex-router-provf4.json | `swap_tob_v3` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.source_token_account into the routed venues (remaining accounts), or to accounts.source_token_sa when it is passed<br>transfers the output tokens to accounts.destination_token_account from the routed venues, or from accounts.destination_token_sa when it is passed<br>debits accounts.source_token_account by the input tokens<br>credits accounts.destination_token_account with the output tokens | `onchain_idls/proVF4pM….json` `swap_tob_v3` | medium |
| okx-dex-router-provf4.json | `swap_toc_v3` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.source_token_account into the routed venues (remaining accounts), or to accounts.source_token_sa when it is passed<br>transfers the output tokens to accounts.destination_token_account from the routed venues, or from accounts.destination_token_sa when it is passed<br>debits accounts.source_token_account by the input tokens<br>credits accounts.destination_token_account with the output tokens | `onchain_idls/proVF4pM….json` `swap_toc_v3` | medium |
| okx-dex-router-provf4.json | `swap_tob_with_token_ledger_v3` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.source_token_account into the routed venues (remaining accounts), or to accounts.source_token_sa when it is passed<br>transfers the output tokens to accounts.destination_token_account from the routed venues, or from accounts.destination_token_sa when it is passed<br>debits accounts.source_token_account by the input tokens<br>credits accounts.destination_token_account with the output tokens | `onchain_idls/proVF4pM….json` `swap_tob_with_token_ledger_v3` | medium |
| okx-dex-router-provf4.json | `swap_tob_with_receiver` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.source_token_account into the routed venues (remaining accounts), or to accounts.source_token_sa when it is passed<br>transfers the output tokens to accounts.destination_token_account from the routed venues, or from accounts.destination_token_sa when it is passed<br>credits accounts.commission_account with the commission share when it is passed<br>credits accounts.platform_fee_account with the platform's share when it is passed<br>credits accounts.sol_receiver with the unwrapped SOL output when it is passed<br>debits accounts.source_token_account by the input tokens | `onchain_idls/proVF4pM….json` `swap_tob_with_receiver` | medium |
| okx-dex-router-provf4.json | `swap_tob_with_receiver_token_ledger` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.source_token_account into the routed venues (remaining accounts), or to accounts.source_token_sa when it is passed<br>transfers the output tokens to accounts.destination_token_account from the routed venues, or from accounts.destination_token_sa when it is passed<br>credits accounts.commission_account with the commission share when it is passed<br>credits accounts.platform_fee_account with the platform's share when it is passed<br>credits accounts.sol_receiver with the unwrapped SOL output when it is passed<br>debits accounts.source_token_account by the input tokens | `onchain_idls/proVF4pM….json` `swap_tob_with_receiver_token_ledger` | medium |
| okx-dex-router-provf4.json | `swap_tob_with_receiver_v3` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.source_token_account into the routed venues (remaining accounts), or to accounts.source_token_sa when it is passed<br>transfers the output tokens to accounts.destination_token_account from the routed venues, or from accounts.destination_token_sa when it is passed<br>credits accounts.sol_receiver with the unwrapped SOL output when it is passed<br>debits accounts.source_token_account by the input tokens | `onchain_idls/proVF4pM….json` `swap_tob_with_receiver_v3` | medium |
| okx-dex-router-provf4.json | `swap_tob_with_receiver_token_ledger_v3` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.source_token_account into the routed venues (remaining accounts), or to accounts.source_token_sa when it is passed<br>transfers the output tokens to accounts.destination_token_account from the routed venues, or from accounts.destination_token_sa when it is passed<br>credits accounts.sol_receiver with the unwrapped SOL output when it is passed<br>debits accounts.source_token_account by the input tokens | `onchain_idls/proVF4pM….json` `swap_tob_with_receiver_token_ledger_v3` | medium |
| debot-router-g7mvcm.json | `swap` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.source_token_account into the routed venues (remaining accounts), or to accounts.source_token_sa when it is passed<br>transfers the output tokens to accounts.destination_token_account from the routed venues, or from accounts.destination_token_sa when it is passed<br>credits accounts.fee_account with the router's share when it is passed<br>debits accounts.source_token_account by the input tokens | `onchain_idls/G7MVcM9Y….json` `swap` | medium |
| debot-router-g7mvcm.json | `swap_compact` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.source_token_account into the routed venues (remaining accounts)<br>transfers the output tokens to accounts.destination_token_account from the routed venues<br>credits accounts.fee_account with the router's share when it is passed<br>debits accounts.source_token_account by the input tokens | `onchain_idls/G7MVcM9Y….json` `swap_compact` | medium |
| perpetuals-perphj.json | `swap2` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.fundingAccount to accounts.receivingCustodyTokenAccount<br>transfers the output tokens from accounts.dispensingCustodyTokenAccount to accounts.receivingAccount<br>debits accounts.fundingAccount by the input tokens<br>credits accounts.receivingAccount with the output tokens | `onchain_idls/PERPHjGB….json` `swap2` | medium |
| perpetuals-perphj.json | `swapWithTokenLedger` | credits the output token account with the received amount for the swap | transfers the input tokens from accounts.fundingAccount to accounts.receivingCustodyTokenAccount<br>transfers the output tokens from accounts.dispensingCustodyTokenAccount to accounts.receivingAccount<br>debits accounts.fundingAccount by the input tokens<br>credits accounts.receivingAccount with the output tokens | `onchain_idls/PERPHjGB….json` `swapWithTokenLedger` | medium |

### 3.2 `d` declarations left unchanged (26)

| Manifest | Instruction | Reason |
|---|---|---|
| orca-tokenswap-v2.json | `Swap` | no committed IDL for the program (9W959DqE...): nothing to read the accounts from |
| orca-whirlpools.json | `twoHopSwap` | the IDL names four owner accounts (one_a, one_b, two_a, two_b) and says only that token_authority withdraws from 'the input token account'; whether the intermediate leg moves through the owner's accounts is not stated, so naming them would excuse a debit the IDL does not state |
| swap-orchestrator-df1ow4.json | `swap` | Round 36 reason: the user's source and destination are remaining accounts (SwapParams.actions); no layout account holds the user's value |
| swap-orchestrator-df1ow4.json | `swap2` | as swap |
| swap-orchestrator-df1ow4.json | `swap_with_destination` | as swap; only the destination (a credit) is in the layout |
| swap-orchestrator-df1ow4.json | `swap2_with_destination` | as swap_with_destination |
| swap-orchestrator-df1ow4.json | `swap_with_destination_native` | as swap_with_destination |
| swap-orchestrator-df1ow4.json | `swap2_with_destination_native` | as swap_with_destination |
| mintfx-emiytj.json | `create_mint_swap_wallet` | sets up a wallet; the IDL's accounts hold no user token value to name |
| mintfx-emiytj.json | `mint_via_swap` | the input comes from input_wallet under input_wallet_authority (read-only, not a signer): no user-held input account in the IDL |
| gmsol-store-gmso1u.json | `create_virtual_inventory_for_swaps` | administration (creates a virtual inventory); no user swap |
| gmsol-store-gmso1u.json | `join_virtual_inventory_for_swaps` | administration; no token account |
| gmsol-store-gmso1u.json | `leave_virtual_inventory_for_swaps` | administration; no token account |
| gmsol-store-gmso1u.json | `execute_increase_or_swap_order_v2` | a keeper executes an order (IDL: 'Execute an increase/swap order by keepers'); the value is in escrows, not a user-signed input |
| limo-limom9.json | `assertUserSwapBalancesStart` | an assertion: inputTa/outputTa are read-only in the IDL; nothing to debit |
| limo-limom9.json | `assertUserSwapBalancesEnd` | an assertion: inputTa/outputTa are read-only in the IDL; nothing to debit |
| tail-trade-j51h4g.json | `viewLpPoolSwapFees` | a view: no user token account |
| raydium-launchpad-lanmv9.json | `migrate_to_cpswap` | administration (IDL: 'Only migrate_to_cpswap_wallet can migrate'); no user swap |
| zap-zapvx9.json | `update_ledger_balance_after_swap` | updates a ledger; token_account is read-only; nothing to debit |
| okx-dex-router-provf4.json | `claim_cashback_pumpswap` | a claim, not a swap: no user input account |
| perpetuals-perphj.json | `instantIncreasePositionPreSwap` | a pre-swap for a position; the IDL does not say whether receivingAccount is the owner's or the position's |
| perpetuals-perphj.json | `increasePositionPreSwap` | keeper-signed (keeper), position-request accounts: no user-signed input |
| perpetuals-perphj.json | `increasePositionWithInternalSwap` | keeper-signed; position accounts only |
| perpetuals-perphj.json | `decreasePositionWithInternalSwap` | keeper-signed; position accounts only |
| perpetuals-perphj.json | `decreasePositionWithTpslAndInternalSwap` | keeper-signed; position accounts only |
| phoenix.json | `SwapWithFreeFunds` | trades the seat's free funds: no trader token account in the IDL |

### 3.3 Instructions removed (23)

| Manifest | Instruction | Discriminator | Class | Declaration it carried |
|---|---|---|---|---|
| jupiter-v6.json | `accountCompressionRoute` | `f7f2b98c0dbbe4de` | (none) | Jupiter V6 aggregator instruction; credits the output token account with the received amount for the swap |
| jupiter-v6.json | `sharedAccountsAccountCompressionRoute` | `9e3abec4751725cb` | (none) | Jupiter V6 aggregator instruction; credits the output token account with the received amount for the swap |
| jupiter-v6.json | `exactOutAccountCompressionRoute` | `89e4fceca2814b80` | (none) | Jupiter V6 aggregator instruction; credits the output token account with the received amount for the swap |
| jupiter-v6.json | `sharedAccountsExactOutAccountCompressionRoute` | `e5a9985c25bf13c6` | (none) | Jupiter V6 aggregator instruction; credits the output token account with the received amount for the swap |
| jupiter-v6.json | `routeCheck` | `6d1f67e9df5fad2a` | (none) | Jupiter V6 aggregator instruction |
| jupiter-v6.json | `sharedAccountsRouteCheck` | `3f03a1891f36162e` | (none) | Jupiter V6 aggregator instruction |
| jupiter-v6.json | `exactOutRouteCheck` | `ad226402f63ee60f` | (none) | Jupiter V6 aggregator instruction |
| jupiter-v6.json | `sharedAccountsExactOutRouteCheck` | `dba89ef8801136ee` | (none) | Jupiter V6 aggregator instruction |
| jupiter-v6.json | `accountCompressionRouteCheck` | `a5fb304cc8ee6568` | (none) | Jupiter V6 aggregator instruction |
| jupiter-v6.json | `sharedAccountsAccountCompressionRouteCheck` | `94f00fdb38ef7eb0` | (none) | Jupiter V6 aggregator instruction |
| jupiter-v6.json | `exactOutAccountCompressionRouteCheck` | `945e8680ebfbe57d` | (none) | Jupiter V6 aggregator instruction |
| jupiter-v6.json | `sharedAccountsExactOutAccountCompressionRouteCheck` | `c8b81e3d70cf01f3` | (none) | Jupiter V6 aggregator instruction |
| jupiter-v6.json | `closeTokenLedger` | `f262cf8dd4cdc779` | close | Jupiter V6 aggregator instruction |
| jupiter-v6.json | `route_with_token_ledger_v2` | `980ca4794a67adcd` | (none) | swaps tokens through routed DEX venues; debits user source token account; credits user destination token account |
| jupiter-v6.json | `shared_accounts_route_with_token_ledger_v2` | `79f7e005d0ea42fc` | (none) | swaps tokens through routed DEX venues with shared accounts; debits user source token account; credits user destination token account |
| meteora-dlmm.json | `initialize_pool` | `5fb40aac54aee828` | create | Meteora DLMM instruction |
| meteora-dlmm.json | `initialize_pool_with_custom_curve` | `b1749ded8784548d` | create | Meteora DLMM instruction |
| meteora-dlmm.json | `add_pool_fee` | `ef8a4900dc212e75` | authority | Meteora DLMM instruction |
| meteora-dlmm.json | `remove_pool_fee` | `9dadd38ab65c94dd` | authority | Meteora DLMM instruction |
| meteora-dlmm.json | `remove_liquidity_by_strategy` | `ca8ef1e897a218c5` | withdraw | Meteora DLMM instruction |
| meteora-dlmm.json | `claim_all_reward` | `d0eb91df2bb27878` | withdraw | Meteora DLMM instruction |
| meteora-dlmm.json | `add_liquidity_single_side` | `7878638801f2a50e` | transfer | Meteora DLMM instruction |
| meteora-dlmm.json | `swap_2` | `df7e2d55564d1fc2` | (none) | swaps tokens using active bin arrays; debits user_token_in; credits user_token_out; updates reserve_x and reserve_y |

### 3.4 Census before and after

| Measure | Before (`1ae2066`) | After |
|---|---|---|
| `round39_swap_declaration_census` | b 8, d 93, e 14 (115) | d 26, e 74 (100) |
| `r30` classification (instructions, silent, unreadable, mixed, strict, relaxable) | 3541, 0, 366, 37, 227, 139 | 3518, 0, 350, 23, 225, 125 |
| `r30` unscoped debits (instructions, lines, with one, only unscoped, grants with one, grants) | 3541, 1780, 1767, 1767, 0, 27 | 3518, 1707, 1700, 1700, 0, 26 |
| Instructions / manifests | 3,541 / 137 | 3,518 / 137 |
| Regression corpus fixtures | 13,013 | 12,967 |
| `validate_corpora.py` pinned gaps | 63 | 52 |

### 3.5 Code and data changes (file: what changed — test — break)

- **`protocols/*.json`** (23 files): rewrites and removals.
  - Tests: `round40_swap_declarations.rs` (4 tests); `round39_decision_campaigns.rs` (honest pool swaps; `round40_a_rewritten_pool_swap_with_a_skim_is_never_executable`); census re-pins.
  - Breaks: B-R1, B-R3.
- **`src/intent_grants.rs` GRANTS:** the `update_offer` grant and its constant removed. Before: a configure grant that could never pass. After: no grant.
  - Tests: `round30_grounded_intents::an_owner_updating_its_own_offer_is_no_longer_granted`; `campaign2_a_granted_claim_and_close_alone_are_executable`, re-pinned to the L5 refusal.
  - Break: B-R2.
- **`protocols/ata-program.json`, `kamino-lending.json`, `solend.json`:** labels only.
  - The pipeline reads flags, not roles, and no declaration names the renamed accounts.
  - Checked by `validate_corpora.py`; no verdict, corpus row or mainnet row moved.
- **`scripts/validate_corpora.py`:**
  - `check_idls`: a discriminator found in no committed IDL is an error; one found only in an IDL file is pinned (5).
  - `check_rewrites`: reads both record files; adds `check_promotion` (evidence re-check); the Round 40 row checks (layout, IDL flags, kept lines plus added lines, no shorter declaration, FakeSwap words, value words); the medium pins (`PINNED_STILL_MEDIUM_R36`, `PINNED_MEDIUM_REWRITES_R40`); `left_unchanged` unchanged; removed instructions absent and not in any IDL.
  - Breaks: VB1–VB3.
- **`.github/scripts/ci-scripts.test.sh`:** copies `docs/audit-r40`. The liquidUnstake case was replaced by a WithdrawSol one (liquidUnstake is now promoted), and 9 new seeded faults were added. Result: 130 passed, 0 failed.
- **`docs/audit-r36/declaration-rewrites.json`:** 7 `promotion` records and 2 `promotion_review` records.
- **`docs/protocol-coverage.md`:** regenerated (`render_coverage.py`).
- **Tests re-pinned, with attribution in each:** `r30_declared_effects_census.rs`, `release_evaluation.rs`, `mainnet_conformance.rs`, `round39_decision_campaigns.rs`, `round30_grounded_intents.rs`.

## 4. Constitution check

- **P2:** determinism is unchanged; the manifests are data.
- **P3:** every refusal still names its layer. Explanations gained, because declarations now name accounts.
- **P5:** not touched.
- **P6 / P7:** no tier, confidence or evidence counter changed.
- **P10:** the corpus was regenerated on purpose. Every moved row is attributed, and none moved from refused to approved.
- **P11:** no change keyed by similarity.
- **P12:** an undecoded swap is analysis-only, which is fail-open with an explanation and never executable. The removed instructions are now unknown instructions, which go through the unknown-instruction path (refused for value).
- **P13:** this is a behaviour change that needs a CHANGELOG entry from the main session: 60 declarations, 23 instructions removed, one grant removed, the ATA identity check.
- **P14 tradeoffs, recorded:**
  1. On undecoded venues, the rewrite turns L4's blanket refusal into a pass. A skim beside the swap is then held only by the swap staying unbound (`intent_parameters`). I accepted this deliberately, because the old refusal also refused every honest swap. It is pinned by the new attack test, which requires those cases to remain unbound and not executable.
  2. The `configure` capability is removed rather than inferred from an undocumented IDL.

## 5. Pinned outputs that moved, and their attribution

- **`mainnet_conformance` `COMMITTED_VERDICTS_SHA256`:** `de8c8a6f…` → `96820ddc…`.
  - Method: diffed row by row against a copy of `1ae2066`.
  - Result: 1 of 2,277 rows changed. Row 1321, OKX `swap_tob_with_token_ledger`: the risk column went from Drainer to HiddenTransfer, because the declaration grew from 2 lines to 6.
  - L2 refuses that row both before and after ("durable nonce"). Approvals are 0 before and after.
  - The ATA and label fixes moved no row.
- **`release_evaluation` dev split:** (12,943; TP 11,804; TN 1,101) → (12,897; 11,761; 1,098). These are exactly the 46 synthetic rows of the removed instructions (43 TP, 3 TN). No other split moved.
- **Corpus:** 13,013 → 12,967.
  - Removed: 46 rows, the `canonical` and `no-intent` rows of the 23 removed instructions.
  - Regenerated with new synthetic addresses: the remaining Jupiter and DLMM rows. Their labels are unchanged; the generator seeds addresses by instruction position.
  - The 12 ATA rows now use the derived ATA in slot 1. Labels unchanged.
  - Holdout and regression splits: unchanged.
- **Censuses:** see §3.4. Attributed in the tests, and in `docs/audit-r40/declaration-rewrites.json` `census`.
- **Attack fixtures:** `real_exploit_tests`, `real_onchain_exploits`, `exploit_corpus_tests`, `novel_attacks` and `real_world_attacks` all pass unchanged.
  - While the work was in progress, three of them (`test_novel_cross_prog_012`/`017`, `test_real_fake_swap_045`) were still blocked but lost L4 as a cause. The Orca lines had dropped the "debit"/"credit" words that L4's no-diff structural check reads.
  - Fixed by adding named "debits …/credits …" lines. Now checked by the validator and the Round 40 test (B-R3).

## 6. Breaks (deliberate, in copies outside the worktree)

Each break ran in a copy outside the worktree, and every copy was deleted afterwards.

**Rust breaks.** These ran in `/home/user/brk-manifests-2`, a copy of `HEAD` (`fc6c0e0`), using its own target directory `/home/user/brk-manifests-2-target`. That directory started as a hard-linked copy, and graphite-core was cleaned and rebuilt in it.

- **B-R1 — a rewrite widened.** Added `debits accounts.output_token_account by the output tokens` to Raydium CPMM `swap_base_input`. Failing tests:
  - `every_round40_rewrite_excuses_exactly_the_debits_its_idl_names`;
  - `the_rewrites_name_the_input_and_never_the_output_alone`;
  - `round40_a_rewritten_pool_swap_with_a_skim_is_never_executable`. Here the CPMM both-sides debit passes L4. It is still refused by the binding, so only the test's L4 assertion catches the widening.
- **B-R2 — the `update_offer` grant restored.** Failing tests:
  - `an_owner_updating_its_own_offer_is_no_longer_granted`;
  - `campaign2_a_granted_claim_and_close_alone_are_executable`.
- **B-R3 — the "debits …/credits …" lines dropped from Orca `swap`** (the named transfer lines kept). Failing tests:
  - `test_novel_cross_prog_012`, `test_novel_cross_prog_017` and `test_real_fake_swap_045`. These are attack fixtures; each is still blocked, but no longer by L4's structural check.
  - `every_round40_rewrite_excuses_exactly_the_debits_its_idl_names`.

**Validator breaks.** These ran in `/home/user/brk-manifests-1`, a copy of the files the validator reads, with the validator code modified as described. Each seeded fault is an error under the real validator and passes under the broken one.

- **VB1 — `check_promotion` returns true.** Seeded fault: the Stake Pool `WithdrawStake` promotion pinned to the commit `main`. The real validator reports "commit 'main' is not a full 40-hex SHA" and the URL mismatch. The broken one reports no error.
- **VB2 — an instruction in no committed IDL pinned instead of errored.** Seeded fault: DLMM `ghost_ix`. The real validator reports an error; the broken one reports 51 pinned gaps and no error.
- **VB3 — the debit/credit-words check off.** Seeded fault: CPMM `swap_base_input`'s debit and credit lines removed from both the manifest and the record. The real validator reports an error; the broken one reports none.

**Measured, not a break: the ATA seeds.** I applied the seeds and ran the full suite.

- They refused `src/benchmark.rs`'s benign "ATA CreateIdempotent (legitimate)" shape, which uses an address that is not derived.
- Failing tests:
  - `benchmark::tests::the_benign_shapes_are_approved`;
  - `regression_engine::tests::benchmark_seeded_corpus_replays_clean_and_promotes`;
  - the release evaluation's hand-built split (TN 7 → 6, FP 0 → 1).
- No mainnet verdict moved.
- I reverted the seeds and left the item listed (§9), because the fix would edit benchmark data in `src/`.

**Base comparison.** `/home/user/base-manifests` was a copy of `1ae2066` with its own target directory, built to produce the base mainnet verdict table. It was deleted.

## 7. Verification

- **Backward compatibility:**
  - 60 declarations now pass L4 for honest swaps, where every honest swap was refused before.
  - 23 instructions are no longer recognised; none is called by any committed real transaction.
  - `configure` grants nothing.
  - The label fixes change no verdict.
- **Security:** no attack fixture moved. The new attack controls cover every rewritten venue class under both configurations: sibling skim, second owner account, both sides debited, output to a stranger. The test asserts which accounts each declaration excuses.
- **Explainability:** better. Declarations name accounts, records cite IDL files and lines, and the validator explains each failure.
- **Hidden assumptions:**
  - L4 does not read direction conditions (§9).
  - Names-only IDLs: the 24 rows with that evidence are `medium` and pinned.
  - The upstream sources were fetched on 2026-10-25 at pinned commits and are recorded by SHA-256; the repository does not carry them.
- **Architecture conflict:** none. The data and records follow the Round 36 schema, with additive fields: `idl_instruction`, `debit_named`, `credit_named`, `promotion`, `promotion_review`.

## 8. Commands and counts

All Rust runs used `CARGO_TARGET_DIR=/home/user/manifests-target CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0` with `-j 2`, from `graphite-core/`. "Final" means the tree at `fc6c0e0` (code) plus this report.

| Command | Result |
|---|---|
| `cargo test --locked --no-fail-fast` (default features, final) | **2,466 passed**, 3 failed, 15 ignored, 180 targets. The 3 failures are the docs-number tests that wait for README/CURRENT (§10): `docs_match_the_registry::the_readme_headline_counts_match_the_registry`, `docs_numbers_match_the_code::the_manifest_and_instruction_counts_are_the_registry`, `…::the_corpus_size_is_the_committed_corpus`. |
| `cargo test --locked --no-fail-fast --no-default-features --features cli` (final) | **1,981 passed**, 3 failed (the same three docs tests), 6 ignored, 180 targets |
| `cargo test --locked --no-default-features --lib` (final) | **530 passed**, 0 failed, 4 ignored |
| `cargo test --test round40_swap_declarations` | 3 passed (new file) |
| `cargo test --test round39_decision_campaigns` | 19 passed (18 Round 39 tests, one with re-pinned rows, plus the new `round40_a_rewritten_pool_swap_with_a_skim_is_never_executable`) |
| `real_exploit_tests`, `real_onchain_exploits`, `exploit_corpus_tests`, `novel_attacks`, `real_world_attacks` | 15, 17, 3, 102, 102 passed — unchanged |
| `round38_sibling_skims`, `round38_create_funding`, `round38_unscoped_authority` | 12, 4, 7 passed. Every other Round 38 suite also passes, in the full default run. |
| `GRAPHITE_REGENERATE_CORPUS=1 cargo test --test regression_corpus corpus_persists_and_reloads_identically` | corpus rewritten: 12,967 fixtures |
| `GRAPHITE_MAINNET_VERDICTS_OUT=… cargo test --test mainnet_conformance the_committed_mainnet_blocks…` on a copy of `1ae2066` and on this tree | 1 row differs (§5) |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | clean |
| `cargo clippy --locked --all-targets --no-default-features --features cli -- -D warnings` | clean |
| `cargo fmt --all -- --check` | clean |
| `python3 -I graphite-core/scripts/validate_corpora.py` | every section ran, no error. 52 pinned known gaps, down from 63: the 28 phantom pins are gone; 5 "only in an IDL file" pins were added; the 9 Round 36 medium pins became 2; 24 Round 40 medium pins were added; 2 ATA writable-on-signer pins, 2 Kamino repeated-name pins and the Solend stray-name pins were removed by the label fixes. |
| `bash .github/scripts/ci-scripts.test.sh` | 130 passed, 0 failed (121 before; 9 new seeded faults) |

**BLOCKED or not run:**
- No public RPC and no network beyond read-only fetches of public GitHub raw files.
- The two upstream `instruction.rs` files were fetched read-only from `raw.githubusercontent.com` at commits resolved with `git ls-remote`. They are recorded by SHA-256 and are not committed.
- `gh api` was refused for both repositories ("GitHub access … not enabled for this session").

## 9. Open, stated plainly

- **Direction conditions are prose.** For Orca `swap`/`swapV2`, Fusion `swap`, Bonkswap/Guacswap `swap`, DEX `swap_in`/`swap_out` and Phoenix `Swap`, L4 excuses a debit of either of the user's two accounts. Orca is decoded, so the binding holds it. The others are unbound.
- **Undecoded venues.** All rewritten venues except CPMM `swap_base_input` and Orca `swap`/`swapV2` are not read by `decode_swap`. An honest swap through them, and a skim beside one, are `approved` but `analysis_only`, never executable. Raising them to executable needs decoders, which belong to the core.
- **24 medium rows** (OKX ×15, Debot ×2, Perpetuals ×2, DEX ×2, Bonkswap, Guacswap, Phoenix) rest on account names, not docs. A promotion needs an evidence record.
- **26 `d` declarations remain** (§3.2). None of them is a user-signed swap with a nameable input, except Orca TokenSwap V2 `Swap` (there is no committed IDL; the source would be needed) and Orca `twoHopSwap` (the IDL does not say how the intermediate leg moves).
- **Stake Pool `WithdrawSol*` slot 12 is not flagged as a signer** in the manifest, while upstream marks it `[s]`. Not changed, because the evidence is upstream and not committed. Both rows stay medium.
- **Router outputs and venues are remaining accounts**, so they cannot be named.
- **ATA `associated_account_address` still has no seeds.** The seeds `[{account_2},{account_5},{account_3}]` are evidenced (439/439) and should land together with a `src/benchmark.rs` benign ATA shape that uses the derived address. That work belongs to the core/benchmark owner.
- **Solend `FlashLoan`'s repeated "Token program id"** stays, because it is the SDK's own text.

## 10. For the main session

- **Docs this tree does not edit:** `docs_numbers_match_the_code` and `docs_match_the_registry` fail until these strings change.
  - New totals: **137 manifests, 3,518 instructions** (was 3,541), still 113 BattleTested. **Corpus: 12,967 fixtures** (12,897 dev, 32 regression, 38 holdout; was 13,013 / 12,943).
  - Every live statement of the old numbers at `fc6c0e0`:
    - `README.md:66` "137 manifests, 3,541 instructions";
    - `README.md:180` "## Supported Protocols (137 Manifests / 3,541 Instructions)";
    - `README.md:261` "(3,541 instructions)";
    - `README.md:865` "137 protocol manifests / 3,541 instructions";
    - `README.md:869` "A 13,013-fixture committed regression corpus … 12,943 dev fixtures";
    - `ARCHITECTURE.md:8` "137 protocol manifests covering 3,541";
    - `ARCHITECTURE.md:433` "(3,541 instructions)";
    - `docs/CURRENT.md:102` "137 manifests / 3,541 instructions";
    - `docs/CURRENT.md:785` "1,767 of 3,541 instructions carry such a line", which is now "1,700 of 3,518";
    - `docs/CURRENT.md:987` "corpus: 13,013 fixtures (12,943 dev, …)";
    - `graphite-core/README.md:61` "3,541 instructions";
    - `docs/solana-foundation-grant-proposal.md:28` "covering 3,541 instructions".
    - Change each to 3,518, 12,967 and 12,897.
  - `docs/ops/production-checklist.md` item 13 says nine medium rewrites. It is now 2 from Round 36 and 24 from Round 40, and the validator lists them.
- **CURRENT, CHANGELOG and SECURITY should record:**
  - R39-CORE-DECISION-4: 60 rewritten, honest CPMM `swap_base_input` and Orca `swap`/`swapV2` are now executable, 26 left unchanged.
  - R39-SUPPLY-CHAIN-11: 23 removed; the Squads 5 are kept as IDL-file instructions.
  - R39-CORE-DECISION-5: grant removed.
  - R39-SUPPLY-CHAIN-12: the ATA role, Kamino and Solend labels; the ATA seeds measured and deferred, together with the benchmark fixture.
  - F-005: 7 promoted, 2 still medium, and the reason.
  - The P14 note on undecoded venues (§4).
  - The test counts below.
- **Python AI layer** (`python-ai-layer/intent_parser.py`): it still maps `configure` → marketplace `update_offer`, which the Core now refuses. This is advisory only; the clients workstream should drop or annotate it.
- **`docs/audit/EXHAUSTIVE_FILE_INVENTORY.csv`** needs regenerating for the new files: `docs/audit-r40/declaration-rewrites.json`, `graphite-core/tests/round40_swap_declarations.rs`, and this report.
