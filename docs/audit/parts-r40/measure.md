# Round 40 — measure

Workstream `measure` of Round 40, on `claude/admiring-archimedes-lfhr7n` (`050adbb`). Internal
engineering work: not an independent audit, not a certification, and nothing here says Graphite is
production ready. No public RPC was contacted by this workstream, nothing was signed or sent, no
workflow was triggered; every RPC used here is a loopback mock. Read-only fetches of public GitHub
files (Agave `v4.3.2` sources) were made to settle what `simulateTransaction`'s `fee` contains.

Input: the job log of live run **40280048548** (PR #55, `live-measure` label, so the seed step ran
with `--whole-census`), saved at
`/tmp/claude-0/-home-user-graphite/f2822178-bc53-556e-99d2-3fd4bf6ff8ab/scratchpad/live-run-40280048548.log`;
its report starts at log line 1160.

## 1. Decisions implemented, and why

| # | Brief item | Finding | What was done |
|---|---|---|---|
| 1 | Replay methodology cannot measure the approval path | Confirmed: 25 of 37 fresh-blockhash pairs fail simulation (log 1418), 33 of 200 had failed on chain (log 1170). A replay of other people's transactions measures the pipeline and the simulator, not approvals. | A new **honest-transfer pass** (`live_mainnet.py replay --honest N`, workflow input `honest_transfers`, default 40) — §3.2. The report now says what the replay measures and what it does not. |
| 2 | Typed L3 baselines | **L3 with no mature baseline does not prevent `executable_approved`.** Evidence: the committed fixture `examples/decisions/executable_approved.json` is an executable verdict whose L3 is `inconclusive` ("no trusted baseline"); `recomputed_decision` (the SDK rule) fails only a *failed* layer; `round40_honest_transfers_are_executable_after_the_import_and_not_before` and `round40_training_an_imported_program_opens_no_attack` (`tests/round39_decision_campaigns.rs`) make honest System / SPL Token transfers and twelve Stake withdrawals `executable_approved` from zero samples; `simulation_integrity.rs::check_simulation_integrity` returns `NoBaseline` below `MIN_SAMPLES` (10), which the verdict reports as inconclusive. The typed bands (System 150±30 CU, SPL Token 5000±1500 CU) caused every L3 FLAG on the seeded programs in run 40280048548: System `AdvanceNonceAccount` 450 CU at 8.00σ (log 1464, 1476, 1482), SPL Token `TransferChecked` 482 CU at −3.01σ (log 1465), `InitializeAccount` 413 / 150 CU at −3.06σ / −3.23σ (log 1477, 1483). No baseline is genuinely needed: confidence after the import is 0.59 ≥ Gaming's 0.55 without `SimulationMatch` (bootstrap part, §4). | `seed` no longer runs `graphite evidence baseline`; it imports the census only (§3.1). |
| 3 | "lose N lamports beyond the fee" (N = 1, 2640, 3815, 5000, 10000) | **Not a Core fee defect** (§4). The Core credits the fee the simulator reports, and Agave's simulate `fee` is the whole fee: every transaction and precompile signature × 5,000 plus the priority fee. What remains is value the transaction moved out of a signer: a sibling System transfer (a tip) or a transfer the primary program made by CPI, under a manifest that declares nothing for the instruction — the documented fail-closed class ("a declaration Graphite cannot read does not excuse a signer's loss"). | The report prints, for every such row, Graphite's figure, signatures (+ precompile), CU price × limit → priority fee, Agave's fee for them, the chain's fee and each signer's balance change (from the block's `meta`, which `fetch` now records), and every top-level instruction (§3.3). No `src/` change. |
| 4 | Report text after a whole-census import | The report said "seeded for System and SPL Token only" (log 1162) although the step ran `--whole-census` (log 1057, `EVENT: pull_request` log 1081). | `seed` records what `import-census` actually imported (its `IMPORT` lines, the `IMPORTED N` count, the census sha256); the report names the count, splits the replay's decisions by imported / not imported, and says no L3 baseline was typed (§3.1). |
| 5 | Honest swap | Not built: an honest Jupiter / Orca / Raydium CPMM swap needs a route or pool accounts and a quote the runner would have to invent (the sample's swaps are other people's, against pools whose state has moved). Said in the report. | — |

## 2. Gap Hunter (before coding)

| # | What could go wrong | Disposition |
|---|---|---|
| G-1 | Dropping the typed baselines removes L3 FLAG from the live measurement. | L3 flagging is covered offline (`l3_live_simulation.rs`, `simulation_integrity.rs` tests); the live run now shows L3 against what the Core *learned* during the run, which is the behaviour an operator gets. The Core's defaults are untouched. |
| G-2 | Learning during the run: a clean simulated verdict of an imported program trains its baseline (bootstrap G-13), so later verdicts are judged against what earlier ones taught. | The honest pass runs **first**, on the Core as the evidence step left it, so the replay's heterogeneous traffic cannot shape the baseline the honest transfers meet. The order is stated in the code and the report; a FLAG later in the replay against a learned baseline is real Core behaviour and is reported with its reason. |
| G-3 | A constructed transaction leaving the runner (signed, sent, or sent elsewhere). | The builder writes zeroed signature slots (`wire.build_legacy`); the Core refuses filled ones; `patch_blockhash` refuses a filled slot (tested); every request goes to `--core` only (tested: all calls are `http://core/...`). No signing key exists in the runner. |
| G-4 | The honest pass read as "Graphite's approval rate". | The report states it measures simple transfers only (System `Transfer`, SPL Token `TransferChecked`), of real wallets as they stand now, and does not measure swaps, other protocols or anything after signing. |
| G-5 | The builder orders accounts differently from wallets and the Core refuses or misreads it. | Tested byte for byte against four committed real mainnet transfers, and instruction-for-instruction (program, accounts, privileges, data, blockhash) against every committed simple transfer (legacy and v0 with lookups). Round trip through the Core's own parser and pipeline: §6b. |
| G-6 | A copied ATA `CreateIdempotent` makes the new transaction pay rent if the account is gone. | Copied only when its payer is the sender; idempotent (no-op when the account exists). If it does create, L4 judges it and the row shows why. A non-idempotent `Create` original is set aside. |
| G-7 | The fee table's chain figures come from the same provider as the simulation. | Stated in the report; the block's `meta` is the chain's record of the executed transaction, independent of the Core's simulation of today's state. |
| G-8 | `with_chain_meta` pairs a row with the wrong transaction's meta. | Rows are paired only when the counts and each base64 payload agree; otherwise nothing is recorded (tested). |
| G-9 | Seeding semantics: an import that skipped System or SPL Token read as seeded. | `seed` now fails when a named program was not imported (Round 36's rule: a seeding asked for and not in force fails the run). Stricter, never looser. |
| G-10 | More RPC load from 40 more /verify calls. | `getLatestBlockhash` is reused for 20 s; `pace_seconds` applies between honest calls; the default stays manual/labelled-PR only. |
| G-11 | The mock now charges a priority fee, changing dry runs of the devnet flow. | `effects` is the single source for simulate, `sendTransaction` and `getTransaction`, so they stay consistent with each other; the change makes them consistent with Agave too. |

## 3. Changes (commits `f595c3f` and the one adding this file)

### 3.1 `tools/live-measure/live_mainnet.py` — `seed`, report evidence text

- Before: `SEED_BASELINES` typed `graphite evidence baseline` for System (150±30) and SPL Token
  (5000±1500); the seed record listed those two as "seeded"; the report's Evidence paragraph named
  them "only" and said their L3 was judged against the seeded anchor.
- After: `seed` runs `import-census` (named programs, or `--whole-census`) and `show`; records
  `imported` (the `IMPORT` lines), `imported_count`, `census_sha256`, `whole_census`,
  `l3_baselines: none typed`; fails if System or SPL Token was not imported.
  `evidence_markdown` says "the measured census was imported for every program the committed census
  admits — N program(s) imported" (or "for System, SPL Token only"), that no L3 baseline was typed
  and what `no mature baseline` means; an old record that typed one is named as such.
  `decisions_by_evidence` splits the replay's decisions by imported / not imported program.
- Tests: `test_seeding_imports_the_census_and_types_no_baseline`,
  `test_a_census_import_that_skipped_a_named_program_fails_the_seeding`,
  `test_whole_census_seeding_imports_every_admitted_record`,
  `test_a_seeded_run_reports_the_census_programs_and_the_caveat`,
  `test_after_a_whole_census_import_the_report_does_not_say_two_programs` (regression: fails on the
  old text).

### 3.2 The honest-transfer pass — `simple_transfer`, `honest_candidates`, `honest_request`, `honest_pass`; `wire.message`, `wire.build_legacy`

From every row of the fetched sample (not only the 200 selected), `simple_transfer` takes an
executed transaction whose only value-moving instruction is a System `Transfer` or an SPL Token
`TransferChecked` (or a `Transfer` whose source's mint the block's token balances name — then built
as `TransferChecked`), beside nothing but Compute Budget (copied), an ATA `CreateIdempotent` paid by
the sender (copied) or a memo (dropped), not durable-nonce, sent by its own fee payer. Near misses are
counted by reason. `honest_request` builds a NEW unsigned legacy transaction: same sender → same
recipient, 1 lamport / 1 base unit (`min(1, original)`), the copied instructions, a fresh blockhash
(`getLatestBlockhash`, the same cached fetcher as the fresh pass), one zeroed signature slot; and
the request: intent `transfer`, `extracted_parameters` {amount in display units, destination,
asset (SOL or the mint)}, the siblings declared, profile Gaming (the harness's), the original's
on-chain CU as `compute_units`. Only fields `VerificationInput` accepts (it refuses unknown ones;
tested). `honest_pass` runs before the replay, verifies each, keeps its own 4xx tally, and adds any
defect (the same `defects_for` rules) to the run's. The report section *Honest transfers* gives the
counts (found, set aside by reason, constructed, verdicts), decisions per kind, L3 outcomes and a
row for every non-executable verdict with risk · policy · confidence, L3, L3/L4 reasons, findings
and the L4 reason.

`wire.message` parses a legacy / v0 / v1 frame to its last byte (header, keys, blockhash,
instructions, lookups, v1 config); `wire.privileges`; `wire.build_legacy` (fee payer first, then
writable signers, read-only signers, writable, read-only, first-appearance order).

Tests: `test_the_message_parser_agrees_with_layout_on_every_committed_frame` (all 2,284),
`test_the_builder_reproduces_real_wallet_transfers_byte_for_byte` (committed rows 443, 1070, 1115,
1387), `test_every_committed_simple_transfer_rebuilds_to_the_same_instructions`,
`test_a_built_transfer_checked_has_the_runtime_layout`,
`test_amounts_are_stated_in_display_units_exactly`,
`test_only_executed_simple_transfers_by_their_own_fee_payer_are_taken`,
`test_an_idempotent_ata_create_is_copied_and_declared_and_a_memo_is_dropped`,
`test_the_honest_request_is_a_new_unsigned_one_lamport_transfer_with_everything_stated`,
`test_a_token_transfer_is_taken_when_the_block_names_its_mint`,
`test_the_honest_pass_runs_first_and_reports_every_refusal`,
`test_without_a_fresh_blockhash_nothing_is_built`.

On the committed sample (2,284 transactions, two blocks of 2026-09-23) the pass finds 30 simple
transfers and builds 21 (20 System, 1 SPL Token; set aside: 4 token `Transfer` with no mint recorded
— the committed sample predates `fetch` recording token balances — 3 durable nonce, 1 Token-2022,
1 sender not the fee payer). A live run of ~1,000 transactions can be expected to yield about ten;
`blocks` raises it.

### 3.3 Signer debits beyond the fee — `fee_breakdown`, `fee_markdown`, `with_chain_meta`

`fetch` keeps each transaction's `meta.fee`, `preBalances`, `postBalances` and the mint/decimals of
`preTokenBalances` (extra fields; the conformance harness reads the rows as JSON values and ignores
them). Every watched verdict naming `UndeclaredSignerLamportDebit` or
`SignerLamportsOutsideDeclaredDebit` gets a row under *Signer debits beyond the fee*: Graphite's
figure (parsed from the L4 reason), signatures (+ precompile signatures, counted as Agave counts
them), CU price × limit → priority fee (the Core's own reading, `scope.compute_budget`), the fee
Agave's rule gives, the chain's fee, each signer's change on chain and what of it is beyond the fee,
and every top-level instruction (System transfers with amount and destination). Tests:
`test_a_signer_debit_row_carries_the_fee_and_what_the_chain_did`,
`test_a_row_the_sample_recorded_without_meta_says_so`,
`test_fetch_records_the_chains_fee_and_balances_beside_each_row`.

### 3.4 `tools/live-measure/mock_rpc.py`

`effects` charges Agave's fee (5,000 × signatures + ceil(price × limit / 10⁶), default limit
200,000 per non-Compute-Budget instruction) instead of 5,000 × signatures; `getBlock` carries
`fee`/`preBalances`/`postBalances` for frames it reads. Test:
`test_the_mock_charges_agaves_fee_every_signature_and_the_priority_fee`.

### 3.5 `.github/workflows/live-mainnet.yml`, `tools/live-measure/README.md`

Input `honest_transfers` (default "40") passed as `--honest`; the seed step renamed "Import the
measured census"; input descriptions and header comment updated. Unchanged: the RPC is masked and
scrubbed, the seed step's failure fails the run, nothing signs or sends, manual/labelled-PR only.

## 4. The fee question, settled from the code

What Graphite credits:

1. `rpc_client.rs` (`parse_simulation`, `fee: value.get("fee").and_then(|v| v.as_u64())`) reads the
   simulate response's `fee`.
2. `verification.rs` passes `sim_res.fee.unwrap_or(0)` to `build_rpc_state_diff`, which sets
   `StateDiff::fee_lamports`; the pre-state lamports are the simulator's own `preBalances`
   (`pre_lamports_from_the_simulation`), the post-state its `accounts`.
3. `state_diff.rs::signer_lamport_losses` subtracts that fee from the **fee payer's** loss only (the
   message's fee payer), clamped at `MAX_PLAUSIBLE_FEE_LAMPORTS`.

What the fee is (Agave `v4.3.2`, read-only from GitHub):

- `runtime/src/bank.rs` `simulate_transaction_unchecked`: `fee` is
  `Some(executed_tx.loaded_transaction.fee_details.total_fee())` (also for a fees-only result).
- `fee/src/lib.rs` `calculate_fee_details` / `calculate_signature_fee`: the signature fee counts
  transaction signatures **and** ed25519 / secp256k1 / secp256r1 precompile signatures, times
  `lamports_per_signature`; `total_fee` adds the prioritization fee.
- `svm/src/transaction_processor.rs` `validate_transaction_fee_payer` deducts `total_fee()` from the
  loaded fee payer; the balance collector records pre-balances from the account loader (pre-fee) and
  post-balances after execution — the ledger convention, pre − post = fee + transfers for the payer.

So the fee is credited in full (every signature's base fee and the priority fee) and to the right
account; what is left "beyond the fee" left the signer for another reason. In run 40280048548 the 13
`UndeclaredSignerLamportDebit` rows (log 1240) are all under manifests that declare no state change
for the instruction ("the manifest declares no state change for this instruction, and its security
class is not stated", log 1466–1485), and most carry a System-program sibling (log 1467, 1469, 1470,
1472, 1473, 1479, 1481, 1485: `11111111` in *programs invoked*) — the shape of a tip. The rows whose
only siblings are Compute Budget (`wMNFST…`, log 1466, 1478, 1484; `yoLovH…` with none, log 1468)
moved the lamports inside the primary program. Either way it is the documented fail-closed class.

What this does **not** prove: that every one of those 13 figures equals what the chain shows. The
log does not carry the chain's fee or balances, and this workstream may not query a public RPC. The
next run's *Signer debits beyond the fee* table settles each row: if Graphite's figure ever differs
from the chain's per-signer beyond-the-fee figure on an executed transaction, the fee question is
reopened as a Core defect. One fail-closed note: a provider that omits `fee` makes the Core credit 0
(`unwrap_or(0)`), so the whole fee would read as a signer debit — a refusal, never an approval.

No Core defect was found, so no `src/` change, no Rust test and no deliberate break were made for
this item.

## 5. Constitution check

- **P1** — no model in any decision path; the runner only reads verdicts.
- **P2** — the honest requests are deterministic given the sample and the blockhash; candidates are
  taken in sample order, one per (sender, recipient, asset).
- **P5** — simulation stays evidence: the runner adds no claim from it; the chain's own record is
  shown beside Graphite's figure rather than replacing it.
- **P7** — no evidence is typed any more: the census import (measured) is the only evidence; the
  typed L3 baseline was the last asserted input in the runner.
- **P12** — unchanged; unmanifested programs keep their capped, explained verdicts.
- **P14** — tradeoff recorded: removing the typed baseline removes an L3-FLAG demonstration from the
  live run. Explainability is not reduced (the report now says more); no Core check was weakened.
- **P16** — the numbers below are one live run's measurement, identified by run id and log line; they
  cannot be reproduced to the same value because mainnet moves. The committed-sample figures (§3.2)
  are reproducible with the pytest command below.

## 6. Verification

- **Backward compatibility**: a seed record from an older run (with `baseline`) is still read and
  named; `replay` without `--honest` behaves as before apart from report wording; the sample's new
  fields are additive.
- **Security**: nothing signs or sends; frames are unsigned; requests go to the local Core only;
  secrets handling and the seed-failure rule unchanged; seeding is stricter.
- **Explainability**: every non-executable honest verdict and every signer debit is printed with its
  reasons and the numbers needed to judge it.
- **Hidden assumptions**: Agave's fee semantics (cited); mainnet `lamports_per_signature` 5,000 (the
  Core's own comment in `state_diff.rs`); the precompile program ids.
- **Architecture conflict**: none; the Core is untouched.

## 6b. Loopback end-to-end run (real Core binary, mock RPC)

`graphite` built at `f595c3f` (`cargo build --release --locked --bin graphite`); `mock_rpc.py` on
127.0.0.1:18899 answering mainnet-beta's genesis hash, with a synthetic sample of 12 executed System
transfers (half with `SetComputeUnitLimit 600` + `SetComputeUnitPrice 250,000 µl`); `live_mainnet.py
seed --whole-census` against the real CLI; the server on 127.0.0.1:17331 with the mock attached;
`replay --honest 12` with an empty replay selection.

- Seeding read the real CLI's output: "census imported for 114 program(s)", census sha256
  `973e4d58…107138b`, System and SPL Token `imported=True`; the report's Evidence paragraph says
  "114 program(s) imported" and "No L3 baseline was typed".
- Honest pass: 12 constructed, 12 verified, **12 `executable_approved`**, no 4xx, no defect. L3:
  10 `no mature baseline`, then 2 `passed (shape baseline)` once 10 samples were learned; confidence
  0.59 → 0.66 → 0.72 … as the learned baseline fed `SimulationMatch` (bootstrap G-13). L4 "State diff
  verified against the manifest" on all 12, including the six that pay a priority fee. This is the
  builder's round trip through the Core's own parser and pipeline.
- Fee probe (`scratchpad/measure-work/fee_probe.py`, each a 1-lamport System transfer, CU price
  250,000 µl × limit 900 → priority fee 225 as the Core read it):
  A, one signature (fee 5,225): `executable_approved`, L4 passed.
  B, two signatures (fee 10,225; the second signer signs a 0-lamport sibling): L4 **passed** — the
  second signature's 5,000 and the priority fee were credited; refused only by `IntentMismatch` (the
  0-lamport sibling transfer to the co-signer is a movement the request did not state).
  C, as B plus a 10,000-lamport System transfer from the payer to a third account (a tip): L4 failed
  `SignerLamportsBeyondDeclaredAmount … so 10000 lamports more left than the instruction states` —
  exactly the tip, nothing of the fee.

The mock is not a validator; it shows that the Core credits a fee shaped as Agave reports it, not
what mainnet's RPC returned for any row of run 40280048548.

## 7. Commands and counts

- `python -m pytest -q -p no:cacheprovider tools/live-measure/test_live_measure.py` (venv from
  `python-ai-layer/requirements-lock.txt --require-hashes`, outside the repo): **83 passed** (61
  before; the 3 seeding tests that asserted the typed baselines replaced by 5, and 20 added).
- `bash .github/scripts/ci-scripts.test.sh`: **137 passed, 0 failed**.
- Rust: no `src/` change, so no Rust leg was required; the release binary was built once
  (`cargo build --release --locked --bin graphite`, own target dir) for the loopback run.

## 8. Pinned outputs moved

None. No manifest, corpus, census, fixture or verdict hash was touched.

## 9. Numbers from run 40280048548 a grant proposal can cite (log line in brackets)

All from one run on 2026-10 against `api.mainnet-beta.solana.com`, PR #55's merge commit; one
measurement, not a benchmark (P16).

- 1,003 transactions from slots 461563808 and 461563788 [952]; the offline conformance harness
  verified 1,001 of them [992], 694 (69.3%) with no manifest for their primary program [1013], and
  its invariants held [1500].
- 200 replayed through `/verify` with simulation, across 101 programs [1050]: 200 verdicts [1169],
  **0 server errors** [1173], **0 requests refused as malformed** [1172], 3 touched by a rate limit
  [1171]; latency p50 41.4 ms, p90 83.9 ms, p99 643.5 ms, max 867.7 ms [1174].
- Decisions: 0 `executable_approved`, 2 `analysis_only`, 0 `inconclusive`, 198 `blocked`
  [1180–1183] — of other people's transactions replayed against later state, 33 of which had failed
  on chain [1170]; 130 failed simulation [1219].
- Fresh-blockhash pass: 37 pairs compared, **0 outcomes changed** by a current blockhash [1409].
- L8: 10 executed transactions reconciled, 5 `BlockedButExecuted` (the alarm firing as designed),
  5 `BlockedAndNotExecuted` [1491–1492].
- No Graphite defect found [1504]; the Core shut down cleanly on SIGTERM (Verdict step).

Do **not** cite the replay's 0 `executable_approved` as an approval rate, nor any figure as a
false-positive rate: the run has no ground truth about intent, and the replay does not measure the
approval path. The next run's honest-transfer section is the first approval-path measurement.

## 10. What the next run should show

- *Evidence*: "imported for every program the committed census admits — N program(s)" with the
  census sha256; "No L3 baseline was typed".
- *Honest transfers*: roughly ten constructed System / SPL Token transfers. Expected
  `executable_approved` for System transfers whose sender holds the fee and whose recipient exists
  (the loopback run above shows the request shape is accepted end to end). Every one that is not
  executable is listed with its reasons; each is either a real Graphite false refusal to fix next
  round, or a state reason (a closed token account, an unfunded sender) to read in its row.
- *Replay*: no `failed: divergence from baseline` on System / SPL Token caused by typed bands; L3
  `no mature baseline` until a learned baseline matures; a FLAG after that is the Core's learning.
- *Signer debits beyond the fee*: every row with the chain's fee and per-signer change beside
  Graphite's figure; equal figures confirm §4 per row.

## 11. Open, stated plainly

- The 13 signer-debit refusals of run 40280048548 are a fail-closed policy refusal of executed
  transactions (tips and program-made transfers under manifests that declare nothing); whether to
  accept a bounded tip beside a declared instruction is a policy decision, not a measurement fix.
- `pAMMBay…` `buy_exact_quote_in` refused with `SignerLamportsOutsideDeclaredDebit` (log 1463): its
  siblings are ATA creates, System and Token instructions — the own-wrap shape listed as a known
  false refusal (bootstrap part, B-8). Not changed here.
- The honest pass covers simple transfers only; no honest swap is measured (§1, item 5).
- Learned baselines are per program: once System has learned 1-lamport transfers, a later
  `AdvanceNonceAccount` may FLAG against it. That is Core behaviour to be read in the next run,
  not hidden.
- For the main session: `docs/CURRENT.md` / CHANGELOG may record that the live runner no longer
  types L3 baselines and has an honest-transfer pass; the grant proposal should use §9's wording.

## 12. Deleted

The release target dir `/home/user/measure-target` (after the loopback run), the loopback data dir
and mock sample (`scratchpad/measure-e2e`) and the venv (`scratchpad/measure-venv`); the loopback
Core and mock were stopped (the Core logged its SIGTERM shutdown). No break copies were made: no
security fix, so no deliberate break applies.
