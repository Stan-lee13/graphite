# C27 — Drift + Kamino Lending on-boarding: official IDLs, live-verified discriminators, source-scoped PDA grounding

**Date:** 2026-08-09 · **Round Six** · Supersedes nothing; adds two BattleTested manifests.

## Scope

Add two of the highest-TVL protocols on Solana to the Graphite seed registry:

| Protocol | Program ID | Source of truth | Instructions |
|---|---|---|---|
| Drift Perpetuals Exchange | `dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH` | velocity-exchange/protocol-v2 `sdk/src/idl/drift.json` (the moved drift-labs/protocol-v2) | 249 |
| Kamino Lending | `KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD` | Kamino-Finance/klend-sdk `src/idl/klend.json` | 51 |

Both program IDs were **confirmed executable on mainnet** via `getAccountInfo` before anything was written (no fabricated addresses — the C1/C10/C15 memo bug class). Note: an earlier remembered address `dRiftyHA39MWEi3m9PKunc2doKF5GK2oB3xPfJCkEDg` does NOT exist on-chain; the SDK's actual constant was fetched and used instead.

## Discriminator derivation and live proof

Neither IDL embeds discriminator bytes (they are Anchor IDL v0.1-style, name-only). All 300 discriminators were therefore **derived** as the Anchor convention `sha256("global:" + snake_case_rust_fn_name)[0..8]` — the same derivation the deployed programs' own generated SDKs use — and then **proven on the deployed binaries** by an on-chain census (`scripts/census_drift_kamino.py`, base58-correct decode):

- **Drift** (210 txs): `placePerpOrder` ×128, `cancelOrdersByIds` ×41, `placeOrders` ×41 — all matched.
- **Kamino** (136 txs): `flashBorrowReserveLiquidity` ×136, `flashRepayReserveLiquidity` ×136, `refreshReserve` ×19, `refreshReservesBatch` ×13, `refreshObligation` ×8, `depositReserveLiquidityAndObligationCollateralV2` ×5, `borrowObligationLiquidityV2` ×3, `redeemReserveCollateral` ×3, `depositReserveLiquidity` ×2, `initUserMetadata` ×1, `initObligation` ×1 — all matched the derived values, **zero unmatched**.

A subtlety that mattered: the census initially appeared to fail against Drift because the naive check hashed the IDL's camelCase display names. The SDK uses the snake_case Rust fn names, and after that correction every observation matched exactly.

A second subtlety: the deployed Kamino `InitObligationArgs` carries **only** `tag` and `id` (the master-source `seed1`/`seed2` fields are a newer version). The observed initObligation tx has 10 bytes of instruction data (`disc[8] + tag + id`), consistent with the deployed IDL, and the obligation PDA re-derives with the system-program placeholder for the two seed accounts.

## PDA grounding — scoped to the deployed program's real constraints

The C26 principle is: **only ground a PDA where the deployed program's account struct seed-constrains it**; a wrong seed spec would flag legitimate transactions. During this round the acceptance test (`scripts/verify_dk_pdas.py`, manifest-driven) caught and corrected two near-misses:

1. **Kamino vaults**: The master-source `initReserve` PDA-creates `[reserve_liq_supply|fee_receiver|reserve_coll_mint|reserve_coll_supply, reserve]`. But runtime instructions (`deposit`, `withdraw`, `borrow`, `flashBorrow`, …) constrain vaults by `address = reserve.state.supply_vault/fee_vault` — **not** by PDA derivation (verified in the deployed handlers). Grounding the vaults globally would have false-flagged every real deposit/flash-borrow. Vault grounding is therefore limited to `initReserve` only. (An earlier brute-force run that seemed to show vaults not matching was itself a script bug — the base58 decoder lost the leading zeros of the System-program placeholder; with the corrected decoder, the `[const, reserve]` derivation is proven correct for the accounts that ARE PDAs.)

2. **Drift user_stats**: The program seed-constrains `user_stats = [user_stats, authority]` **only** in `initializeUserStats` (and `user = [user, authority, sub_account_id]` only in `initializeUser`). Every other instruction uses `has_one = authority` / `constraint = is_stats_for_user(&user, &user_stats)` — a consistency check, not a derivation. The generator initially grounded user_stats everywhere the SDK supplies it; that was scoped back to `initializeUserStats` so a valid-but-non-PDA user_stats isn't flagged.

Grounded PDAs (final):

- **Drift**: `initializeUser.user` = `[user, authority, sub_account_id_le]`; `initializeUserStats.userStats` = `[user_stats, authority]`; `deposit/withdraw/transferDeposit.spotMarketVault` = `[spot_market_vault, market_index_le]` (all three seed-constrained in user.rs); `withdraw.driftSigner` = `[drift_signer]` (the SDK PDA stored in state.signer).
- **Kamino**: `lendingMarketAuthority` = `[lma, lending_market]` in every instruction that carries it (it is the program's signing authority, seed-constrained in every handler — verified in deposit, flashBorrow, redeemFees, initReserve, …); `initReserve` vaults; `initUserMetadata.userMetadata` = `[user_meta, owner]`; `initObligation.obligation` = `[tag, id, owner, market, seed1, seed2]`.

**Live acceptance results** (all 5 live-observable grounds MATCH, 0 mismatches): Kamino `lma` in depositReserveLiquidity (bump 254), flashBorrow (bump 248), flashRepay (bump 248); `obligation` in initObligation (bump 255); `userMetadata` in initUserMetadata (bump 254). Drift's grounded instructions (initializeUser, initializeUserStats, deposit, withdraw, transferDeposit) had no occurrences in the recent on-chain surface sample — those are source-derived, which the acceptance script reports honestly.

## variable_accounts

Kamino `refreshReservesBatch` reads `(reserve, lending_market, …)` pairs from `remaining_accounts` (deployed handler `handler_refresh_reserves_batch.rs`) — the IDL declares zero accounts. It is marked `variable_accounts: true` so the drainer/STMT heuristics don't false-flag legitimate batch refreshes (same treatment Jupiter route instructions already had).

## Regression protection

New `test_c27_drift_kamino` module in `src/manifest.rs`:

- **Full-surface snake_case pin** (C18 bug class): all 300 discriminators must equal `sha256("global:"+snake_case)[0..8]` — any camelCase-hash regression fails immediately. The generator's digit+uppercase boundary (e.g. `V2Fulfillment` → `v2_fulfillment`) is mirrored in the test's snake_case.
- **9 chain-observed discriminators pinned** (Drift 3 + Kamino 6) — a drift from the deployed program fails.
- **PDA-grounding scope pin**: asserts the exact set of grounded accounts per instruction — e.g. `deposit.userStats` must be empty, `flashBorrow` grounds only `lendingMarketAuthority`, `initReserve` grounds all four vaults, `obligation` is grounded only in `initObligation` with the exact `[tag,id,owner,market,seed1,seed2]` template.
- **End-to-end obligation-PDA test**: resolves the real observed initObligation tx shape — the correct PDA passes with no mismatch, a spoofed key is flagged as a PDA mismatch.
- `protocols/verified_program_ids.json` extended (22 programs) with the two IDs; the bidirectional Rust pin test, the blessed-canonical set test, and the Python AI-layer manifest test all updated.

## Validation

- Rust: **869 tests, 0 failures** (all 24 test binaries), fmt clean, clippy clean.
- Python AI layer: all green (22 manifests verified; 49.5k parses/sec smoke unchanged).
- AuditBind: 9/9. TypeScript typecheck: clean. Go SDK untouched (no Go toolchain on this host; no Go changes made).

## Files

- `graphite-core/protocols/drift.json` (249 ix) — new
- `graphite-core/protocols/kamino-lending.json` (51 ix) — new
- `graphite-core/scripts/drift_idl.json`, `graphite-core/scripts/klend_idl.json` — committed IDLs (reproducibility)
- `graphite-core/scripts/rebuild_drift_kamino_manifest.py` — generator (discriminators + scoped PDA grounding + curated behavior)
- `graphite-core/scripts/census_drift_kamino.py` — on-chain census (base58-correct)
- `graphite-core/scripts/verify_dk_pdas.py` — manifest-driven live PDA acceptance test
- `graphite-core/src/manifest.rs` — seed registry entries + C27 test module
- `graphite-core/tests/protocol_expansion_tests.rs`, `graphite-core/tests/deep_extreme_tests.rs` — manifest-count + variable_accounts updates
- `graphite-core/protocols/verified_program_ids.json` — +2 verified IDs
- `python-ai-layer/test_intent_parser.py` — manifest set 20 → 22
