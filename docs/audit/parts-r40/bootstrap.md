# Round 40 — bootstrap workstream: `graphite evidence import-census`

Internal engineering work, one workstream of Round 40. It is not an independent audit and not a
certification, and nothing here says Graphite is production ready. Base `1ae2066`. Every RPC in
the tests is a loopback mock (`127.0.0.1:0`); no public endpoint was contacted, nothing was
signed or sent, no workflow was triggered.

## 1. The decision implemented, and why

A fresh Core approves nothing on the built-in profiles. The three evidence-derived confidence
signals (`SimulationMatch` 0.20, `HistoricalVolume` 0.15, `CommunityVerification` 0.15,
`verification.rs::build_signals`) read the Semantic Graph, which is empty, so a manifested
program scores 0.20 (manifest) + 0.14 (OfficialManifest × 0.20) + 0.10 (L5) = **0.44** against
Gaming's 0.55. The only way out was `graphite evidence seed --battle-tested N` with N typed by
the operator. The repository already commits a measured, reproducible census of that quantity
(`graphite-core/protocols/battle_tested_evidence.json`, 137 records, reproduced by
`scripts/battle_tested_census.py`).

The technical lead's decision, implemented: an explicit, audited operator command
`graphite evidence import-census` that seeds each program's `HistoricalVolume`
(`BehaviorEvidence::battle_tested_tx_count`) from the census. CLI-only; a fresh Core's defaults,
floors, ceilings, profile thresholds and tier rules are unchanged.

The lead's mid-task addition is implemented too: an import never re-seeds a program whose
observed deployment, or the deployment its evidence was retired for, is newer than the census
window, and the import binds the evidence to the census window so the existing upgrade watch
withdraws it (§3.3).

## 2. Gap Hunter (before coding)

| # | What could go wrong | Disposition |
|---|---|---|
| G-1 | **Downgrade.** `seed_behavior` appends a whole record; a census record with `has_signed_manifest: false` over a SimulationValidated / CommunityVerified record recomputes lower (Heuristic). | The import appends the record in force with only `battle_tested_tx_count` raised; every other field (signature flag, community and simulation counts, version, state changes) is carried. `compute_trust_tier` is monotone in each field, so the graph tier never drops; the verdict tier is `max(graph, manifest)` so it never drops either. Test `an_import_never_lowers_a_programs_evidence_or_tier`; break B4. |
| G-2 | **Asserting a signature.** Lifting a program to BattleTested needs `has_signed_manifest` or ≥2 attestations. | Never set by the import; carried from the record in force. On a fresh Core every imported program is HeuristicInferred in the graph and OfficialManifest on the verdict. |
| G-3 | **Tampered census.** The file's raw counts cannot be checked from the file. | The import uses the copy compiled into the binary; `--census <file>` must be byte-identical (SHA-256) to it. Schema, the stated bar and each record's verdict are checked too. Break B5, B8. |
| G-4 | **Importing below the bar** (or a program without manifest, not executable, absent). | Each axis checked per record with the decode rate recomputed against the LOADED manifest (the seed loader's gate); planned set equals `battle_tested_programs()`. Break B1. |
| G-5 | **Stale measurement after an upgrade.** Imported evidence is unbound to a slot, so a first sighting of a newer deployment keeps it ("cannot be dated"). | The import binds the evidence to the census window's oldest slot (`bind_evidence_to_slot`, only ever earlier); a program whose observed deployment or retired evidence's deployment is newer than that slot is skipped. Break B2, B3. |
| G-6 | **Re-import after an upgrade restores withdrawn evidence.** | Skipped: the observed deployment is newer than the census (`census predates the program's last observed deployment`). Test `an_upgrade_after_the_import_withdraws_it_and_a_reimport_does_not_restore_it`. |
| G-7 | **Not idempotent** (rows and records on every run). | A program already holding ≥ the census count is skipped; no record, no row. Break B7. |
| G-8 | **Lifting a quarantine sideways.** | A quarantined program is skipped (lifting is its own operator decision). Break B6. |
| G-9 | **Silent trail.** | One `operator_action` row per import naming source, hash, measurement time; the trail is opened before any change; a row that does not land fails the command with the imports in force listed (same contract as `evidence seed`). A keyed trail refuses an unkeyed import before any change. |
| G-10 | **HTTP reachability** (any caller minting evidence, G4). | Not referenced by `server.rs` (test `the_server_does_not_reach_the_import`). |
| G-11 | **The attacks Round 39 fixed become reachable.** R39-CORE-DECISION-1/-2 needed confidence above the floor; the import provides it under the defaults. | Every attack re-run in the imported state under Gaming (§5): all refused. No P0. |
| G-12 | **Cross-cluster use.** The census is mainnet-beta; a devnet Core importing it would credit code it never measured. | Not enforced in code (the CLI has no RPC). Printed on every run and documented; the devnet runner imports the System program only (a builtin, the same everywhere). Open, §9. |
| G-13 | **Learning switched on.** Under `BuiltinFloor` a simulation trains a baseline only when the verdict clears 0.55 on its own; at 0.44 nothing trained. After an import, an imported program's honest simulated verdicts train its baseline, so `SimulationMatch` rises to 0.20 and confidence to the OfficialManifest ceiling 0.75. | Intended consequence, recorded. Still below TradingBot (0.80, and its tier floor). Baseline poisoning is Round 30/39 campaign 8 territory (identity memory, anchors, refusals do not train); not re-run here. Open, §9. |
| G-14 | **Interaction with existing attestations.** A graph record that already holds `has_signed_manifest: true` (a registry acceptance of a signed submission, or an operator's `evidence seed --signed-manifest`) or ≥2 community attestations reaches BattleTested once the census volume is added (`compute_trust_tier`'s own rule), ceiling 1.0. With ≥2 attestations and a 3-sample baseline the confidence is 1.0, which admits Treasury and Enterprise. | P7-consistent (evidence, recomputed), and impossible on a fresh Core. Shown in `an_import_never_lowers_…` (Jupiter with a signed record → BattleTested). Flagged for the lead, §9. |
| G-15 | **What the volume means.** The census counts successful transactions that carry the address (not invocations; the decode axis shows use), sometimes over seconds (System: 1,456 in 1 s). | The command prints window and slots; the audit row carries them; documented. Not a claim that any request is safe. |

## 3. Changes

### 3.1 `graphite-core/src/census_import.rs` (new)

- `Census::{embedded, from_bytes, from_file_bytes}`, `verify_census_document`: schema (top-level
  fields; per record program id, manifest, name, `measured_at_unix > 0`, identity booleans,
  counts, window, decode rate in [0,1] or null, `oldest_slot ≤ newest_slot`), unique ids, the
  stated bar equals `battle_tested_bar`, `meets_battle_tested` equals its measurements; a file is
  held to the compiled-in copy's SHA-256 (`973e4d58…07138b` at this commit).
- `plan(core, census, only)` → `ImportPlan { imports, skipped, not_selected }`; per record, in
  order: loaded manifest; `identity.exists`; `identity.executable`; the three thresholds (decode
  rate via `manifest::recomputed_decode_rate`); observed deployment / retired evidence newer than
  `volume.oldest_slot` (`STALE_DEPLOYMENT`); quarantine; already held. Each skip carries its
  reason. Each planned import carries the record to append and the standing before/after.
- `apply`, `audit_detail`, `import_embedded_into` (no trail: tests and embedders).

### 3.2 `graphite-core/src/verification.rs`

- `program_trust_tier` → body moved to the free function `verdict_program_tier(manifest, record)`
  (no behaviour change; same three callers).
- `GraphiteCore::standalone_standing(program, record)` — the tier and confidence a verdict on the
  program alone carries (L5 passed, no penalty, no sibling), computed by `build_signals`,
  `compute_confidence` and the tier ceiling, i.e. the verdict path's own functions. The end-to-end
  test checks it equals the real verdict's confidence.
- `GraphiteCore::import_measured_evidence(behavior, slot)` — `append` (tier recomputed, P7) plus
  `bind_evidence_to_slot`, returning whether the snapshot reached disk.
- `GraphiteCore::observed_deployment(program)` — read accessor.

### 3.3 `graphite-core/src/semantic_graph_store.rs`

- `bind_evidence_to_slot(program, slot)` — sets `evidence_since_slot` to `min(existing, slot)`.
  Not a new record: the store already kept "the earliest slot the program's evidence describes"
  (`evidence_since_slot`, Round 30 G-04) and "the deployment last seen" (`deployments`), and the
  upgrade watch (`note_deployments`) withdraws evidence on a first sighting whose deploy slot is
  newer than it, and on any later redeploy. No new append-only record was needed; the import
  writes the binding the census's own window gives.

### 3.4 CLI — `graphite-core/src/cli.rs::run_import_census`, `src/bin/graphite.rs`

`graphite evidence import-census [--data-dir D] [--census FILE] [--program ID]... [--dry-run]`.
Dry run: read-only open (no lock), prints the plan, writes nothing. Import: takes the lock, opens
the trail before any change (`OperatorTrail::open`, same key handling as `evidence seed`), then
per program appends, persists (a failed persist stops the command, naming what is already on
disk) and writes one row (a failed row stops the command, the change in force, as `evidence
seed`). Row detail:
`evidence imported for <id> (census-measured, battle_tested_evidence.json sha256=<hash>,
measured_at <UTC> [unix N]): battle_tested <old> -> <new> (successful transactions over Ws,
slots a..b); evidence bound to slot a; graph tier recomputed to T; verdict tier V, standalone
confidence x -> y`.

### 3.5 Live runners — `tools/live-measure/{live_mainnet,live_devnet}.py`, workflows

Both seeded `graphite evidence seed --program P --simulation-matches 3` (typed). Now:
mainnet `graphite evidence import-census --program <System> --program <SPL Token>`; devnet
`--program <System>` only. The `evidence baseline` step (an L3 anchor, typed CU numbers) is kept:
the runners measure L3 flagging against it, and the report now says it also feeds
`SimulationMatch`. Never sign, never send: unchanged (these commands only write the data
directory). `test_live_measure.py`: the seed test asserts import-census replaces `evidence seed`
and an import failure fails seeding (60 passed). Workflow comments and input descriptions
updated; no step logic changed; nothing triggered.

### 3.6 Docs

`docs/ops/install.md` — new section "First start: import the measured census" (what it does,
what it does not do, how to run, how to verify) and a pointer from step 3. `docs/ops/keys.md` —
`import-census` named among the writing commands that take the server's key.
`tools/live-measure/README.md` updated.

## 4. Per-program confidence before and after import

A program alone (L5 passed, no penalty, no sibling), fresh Core, from
`the_standing_of_the_reported_programs_before_and_after_the_import` (and `--dry-run`):

| Program | Census successful txs (window) | Graph tier after | Verdict tier before → after | Confidence before → after | Clears Gaming's 0.55 floor before → after |
|---|---|---|---|---|---|
| System Program `1111…1111` | 1,456 (1 s) | HeuristicInferred | OfficialManifest → OfficialManifest | 0.4400 → 0.5900 | no → yes |
| SPL Token `Tokenkeg…` | 1,431 | HeuristicInferred | OfficialManifest → OfficialManifest | 0.4400 → 0.5900 | no → yes |
| Jupiter v6 `JUP6…` | 1,375 | HeuristicInferred | OfficialManifest → OfficialManifest | 0.4400 → 0.5900 | no → yes |
| Orca Whirlpools `whirL…` (pool) | 1,061 | HeuristicInferred | OfficialManifest → OfficialManifest | 0.4400 → 0.5900 | no → yes |
| Raydium CLMM `CAMM…` (pool) | 1,568 | HeuristicInferred | OfficialManifest → OfficialManifest | 0.4400 → 0.5900 | no → yes |
| Meteora DLMM `LBUZ…` (pool) | 1,191 | HeuristicInferred | OfficialManifest → OfficialManifest | 0.4400 → 0.5900 | no → yes |

0.59 = 0.20 + 0.14 + 0.15 (HistoricalVolume, normalised at 1,000) + 0.10. Clearing the floor is
not executability: every other gate still decides (Whirlpool's honest swaps stay refused by L4,
R39-4). TradingBot, Treasury and Enterprise still refuse: each requires a tier above OfficialManifest
(`round40_the_import_does_not_open_the_stricter_built_in_profiles`). End to end, the honest System
transfer and SPL Token `TransferChecked` are `executable_approved` at 0.5900 under the built-in
Gaming profile after the import and refused on confidence at 0.4400 against the same mock cluster
without it (`round40_honest_transfers_are_executable_after_the_import_and_not_before`).

Imported: 114 of 137 records (exactly `manifest::battle_tested_programs()`). Skipped, 23, each
with its reason: below 1,000 transactions (Escrow 399, Tarb 31, Store 253, Marginfi 503,
Legacy Memo 827, Switchboard 59, Tcomp 340, Ocr2 249, Oridion 217); decode rate below 0.90
(Doorcash 0.675, Bubblegum 0.057, Main 0.725, Coinflow 0.500, Merkle Distributor 0.489,
Rush 0.025, Light System 0.000, Zeta 0.670, Ocr2 0.000, Account Compression 0.000, Oridion 0.000,
Pump Fees 0.000, Timelock 0.776); no decode rate (three Memo programs, Switchboard, Drift);
fewer than 20 instructions observed (Switchboard 0, Drift 0).

## 5. Attack re-run in the imported state

Configuration `Imported`: `GraphiteCore::new()` (production defaults, default plugins), the
embedded census imported (`census_import::import_embedded_into`, the CLI's plan and append), the
**built-in Gaming profile** — no custom bar. Round 39 campaigns 1–3 and 12 gained this third
configuration (`Waivers::Imported`, `CONFIGS = [None, All, Imported]`); every test in
`round38_sibling_skims.rs`, `round38_create_funding.rs`, `round38_unscoped_authority.rs` and
`staking_withdrawal_destination.rs` gained a `round40_census_imported::<name>` twin
(`tests/round40_imported/mod.rs`), which fails if the imported state did not reach the Core the
body built. The original tests are unchanged and still run.

Results: `round39_decision_campaigns` 21/21 (18 Round 39 tests, now with the third configuration, and 3 Round 40 tests); the four other files 75/75 (37 originals and 38 twins).

Every `Imported` verdict was logged with its confidence (`--nocapture`; 92 in
`round39_decision_campaigns`). The 17 that were `executable_approved` are all honest controls.

| Campaign / file | Attacks refused in the imported state | Executable attacks | Refused attacks at confidence 0.59 (floor met) | Honest controls (imported, Gaming) |
|---|---|---|---|---|
| C1 swap + something beside it (11 `Beside` variants, wSOL skim, SOL into an attacker-closable account ×2) | 14 | **0** | 4: top-level output skim, Token-2022 output skim, delegate (Approve), wSOL skim | honest Y→X, Y→SOL executable at 0.59 |
| C2 stake withdrawal + 8 variants; **R39-1 A/B/C** + 2 D; DLMM claim / CLMM close / `update_offer` with a skim or stranger | 19 | **0** | **R39-1 A, B, C** (refused by the binding, `WithdrawalUnderbounded`), stranger transfer, second Withdraw, DLMM token skim, CLMM stranger-within-refund | honest withdrawal, own wrap, DLMM claim, CLMM close executable at 0.59; `update_offer` refused even honest (R39-5, unchanged) |
| C3 creation + co-signer / attacker-closable | 2 | **0** | — (0.44, `IntentMismatch` with the L4 penalty) | rent-only creation executable at 0.59 |
| C12 plugins: Block / BlockEmpty / BlockWarning / Panic × 7 families, Note/NoFinding beside a skim or owner change, protocol rules for an unmanifested program | 34 (30 blocked, 4 analysis_only: the L8 verifier family) | **0** | 14 (Simulation, Risk and Policy plugin blocks and crashes; Note/NoFinding beside an output skim) | NoFinding executable at 0.59 for all 7 families |
| Pool swaps (R39-4 false-refusal census) | — | — | — | DLMM, CLMM `swap_v2`, Raydium v4 `SwapBaseIn` executable at 0.59; Whirlpool `swap`/`swapV2`, CPMM, DAMM v2 refused (R39-4, unchanged); Pump AMM `sell` analysis_only (unbound) |
| `round38_sibling_skims` twins (12 tests) | 8 (input/output/withdrawal/CPI skims, approve, foreign sibling, relayer takes lamports/output) | **0** | output skim, withdrawal skim, approve | honest swap, swap beside memo ×2, transfer alone, honest withdrawal executable at 0.59; own wrap/unwrap and a relayed swap refused as before (B-8, relayed fee payer: known false refusals) |
| `round38_create_funding` twins (4) | 3 | **0** | 5 SOL into a zero-byte attacker-owned account; stated 1 SOL funded 5 | rent and stated-amount creations executable at 0.59 |
| `round38_unscoped_authority` twins (7) | 10 verdicts, all refused | **0** | — (≤ 0.30) | — (the tests assert L4 only) |
| `staking_withdrawal_destination` twins (14) | 13 verdicts refused (every `assert_refused` holds) | **0** | 2 | 7 Stake, 2 Stake Pool, 1 Marinade executable at 0.59 |

"Refused at 0.59" is the point of the exercise: those attacks cleared the confidence floor of
the built-in Gaming profile and were refused by the binding, L4 or the risk engine, the gates
Rounds 37–39 added. Across the Round 39 file, 25 refused attack verdicts sat at 0.59.

**No attack reached `executable_approved` in the imported state under the built-in profiles.
No P0.** Every Round 39 P0-class reproduction whose precondition was confidence (R39-1 A/B/C,
R39-2 claim/close skims) was re-run with that precondition met by the import under the
defaults, and refused by the gate Round 39 added. The stricter built-in profiles refuse even the
honest controls after the import, so they refuse every attack too.

## 6. Deliberate breaks (a copy at `/home/user/brk-bootstrap-1`, its own target dir)

Each break was applied to a fresh copy of `graphite-core` (`/home/user/brk-bootstrap-1`,
`CARGO_TARGET_DIR=/home/user/brk-bootstrap-target`) and the Round 40 tests run. Both were
deleted afterwards.

| Break | What was removed | Tests that fail |
|---|---|---|
| B1 | the threshold filter (`plan_one`: below-the-bar records planned) | `only_records_that_clear_every_threshold_are_planned`, `an_import_is_idempotent_and_leaves_a_quarantine_alone` (lib); `a_dry_run_reports_and_writes_nothing`, `an_import_records_each_program_once_and_a_rerun_imports_nothing` (CLI) — 4 |
| B2 | the census slot binding (`import_measured_evidence` without `bind_evidence_to_slot`) | `upgrades::a_first_sighting_newer_than_the_census_withdraws_the_import`, `the_standing_of_the_reported_programs_before_and_after_the_import` — 2 |
| B3 | the stale-deployment skip (observed deployment and retired evidence) | `upgrades::a_first_sighting_newer_…`, `upgrades::a_program_deployed_after_the_census_is_not_imported`, `upgrades::an_upgrade_after_the_import_withdraws_it_and_a_reimport_does_not_restore_it` — 3 |
| B4 | the merge with the record in force (a fresh evidence record appended) | `an_import_never_lowers_a_programs_evidence_or_tier` — 1 (System SimulationValidated → HeuristicInferred: the downgrade G-1 names) |
| B5 | the hash comparison of a `--census` file | `a_tampered_census_file_is_refused` (lib), `a_tampered_census_file_is_refused_and_nothing_is_written` (CLI) — 2 |
| B6 | the quarantine skip | `an_import_is_idempotent_and_leaves_a_quarantine_alone` — 1 |
| B7 | the idempotence check | `an_import_never_lowers_…` (Token, holding 50,000, is not skipped: 1,431 would be appended, a lowering), `an_import_is_idempotent_…`, `upgrades::an_upgrade_after_the_import_…` — 3 |
| B8 | the census self-consistency check (`meets_battle_tested` against its measurements) | `a_tampered_census_file_is_refused` — 1 (the edited file is then refused by the hash alone; the check is what guards a build whose compiled-in census is itself inconsistent) |
| B9 | **R39-CORE-DECISION-1 reverted in part** (`keeps_value` credits any signer, as before Round 39), to show what the imported configuration guards | `round39_what_keeps_value_calls_the_signers_own_beside_a_withdrawal`: B (30 SOL to a co-signer) and C (`CreateAccount` for the attacker's program) beside a granted Stake Withdraw are `executable_approved` under `None`, `All` **and `Imported` — the built-in Gaming profile with no custom bar, at 0.59**. Without Round 39's fix, the census import would have made that P0 reachable under the default profiles; the `Imported` rows are what would say so. |

## 7. Constitution check on the diff

- **P1** — no model call anywhere; the import is deterministic file reading.
- **P2** — a verdict is still a function of `(transaction, graph state)`; the import changes
  graph state through an operator action, recorded. The plan is deterministic (census order).
- **P3** — the breakdown is unchanged; `HistoricalVolume` now shows the census value.
- **P4** — append only: `SemanticGraphStore::append`; no record is mutated. `evidence_since_slot`
  is the baseline binding map, not a Behavior record, and only moves earlier.
- **P5** — untouched (simulation not involved).
- **P6** — ceilings unchanged; HeuristicInferred/OfficialManifest caps hold (0.59 < 0.75).
- **P7** — the import seeds evidence through `append`, which recomputes the tier; no tier is
  named anywhere in the import; no signature asserted. The `trust_tier` on the planned record is
  `compute_trust_tier` of its evidence and is recomputed again by `append`.
- **P8** — no plugin interface changed.
- **P9** — one `operator_action` row per import; a row that cannot land fails the command.
- **P10** — no promotion path touched.
- **P11** — keyed by exact `program_id` from the census record, matched to the registry by id.
- **P12** — unchanged; an unknown program is never imported (no manifest → skipped).
- **P13** — additive CLI subcommand; no schema change. CHANGELOG entry needed (main session).
- **P14** — no check removed. Trade-off recorded: the import moves a manifested program past the
  Gaming floor under the defaults (the decision taken), which also switches on baseline learning
  for it (G-13).
- **P16** — the per-program numbers above are confidence arithmetic and census counts at this
  commit, not performance claims.

## 8. Verification answers

- **Backward compatibility** — no default changes; a Core never running the command behaves as
  before; existing tests unchanged and green; `program_trust_tier` refactor is behaviour-neutral.
- **Security** — attacks re-run in the imported state: 0 executable (§5); tampered census refused;
  HTTP surface does not reach it; keyed trails refuse an unkeyed import.
- **Explainability** — every import and skip printed with its reason; audit row names source,
  hash, time, slots, old → new, tiers.
- **Hidden assumptions** — the census is mainnet-beta and current only to its measurement time;
  its count is address-mentions over a window; an RPC that lies about deployments can withdraw
  (not add) evidence (the existing RPC trust boundary).
- **Architecture conflict** — none: the census already backs the manifest-declared tier; this
  feeds the same measurement to the graph, through the existing operator-evidence path.

## 9. What remains open, stated plainly

1. ~~**Cross-cluster** (G-12)~~ — **closed in the second pass (§12.2)**: enforced by
   `--cluster mainnet-beta`, a mark in the graph and a server-start `getGenesisHash` check.
   Residual: a library embedder that attaches an RPC itself must call
   `GraphiteCore::confirm_evidence_cluster` (the server does; `graphite verify` attaches no RPC).
2. ~~**Learning after import** (G-13)~~ — **re-run in the second pass (§12.1)**: training stops at
   0.75 with the tier unchanged, and no attack becomes executable on a trained Core. Residual:
   any verify-key holder can now shape an imported program's baseline with honest-looking
   traffic (the first ten samples are learned unclamped). It buys nothing on the built-in
   profiles; on an operator `Custom` profile with a floor between 0.59 and 0.75 it would open
   that profile to the program, and a skewed first baseline can make L3 flag honest traffic
   (availability, recoverable with `evidence promote-shadow`).
3. **Existing attestations** (G-14): on a graph that already holds a signed manifest or ≥2
   community attestations for a program, the import completes `BattleTested`; with attestations
   and a baseline that admits Treasury/Enterprise. Not reachable on a fresh Core.
4. The L3 baseline in the live runners is still typed (kept deliberately, labelled).
5. The census counts address-mentions and is as old as its measurement (2026-09-22 to
   2026-10-03); re-measuring needs a public RPC (`scripts/battle_tested_census.py`).

## 10. What the main session needs to change (not edited here)

**README.md** (exact replacement text):

1. Line 70–71, in "What it is not, yet": replace "A fresh instance approves nothing on the
   built-in profiles until it has evidence — seeded by the operator, or earned from approved,
   simulated traffic; that is deliberate." with:

   > A fresh instance approves nothing on the built-in profiles until it has evidence; that is
   > deliberate. One explicit, audited operator command, `graphite evidence import-census`,
   > imports the measured mainnet census the repository commits
   > (`graphite-core/protocols/battle_tested_evidence.json`; 114 of its 137 records clear the bar)
   > as each program's transaction-volume evidence: a manifested program's verdict then reaches
   > 0.59 against the Gaming profile's 0.55, and the stricter profiles still refuse. Otherwise
   > evidence is seeded by the operator or earned from approved, simulated traffic.

2. Line 624, the callout: replace "On a fresh Core (no earned evidence) the achievable confidence
   for a known protocol is ~0.44, so this example returns **BLOCKED**" with "On a fresh Core (no
   evidence) the achievable confidence for a known protocol is ~0.44 — 0.59 after `graphite
   evidence import-census`, still short of TradingBot's 0.80 and its SimulationValidated tier
   floor — so this example returns **BLOCKED**", and in the same callout replace "and Behavior
   evidence the operator seeds" with "and Behavior evidence the operator seeds or imports from
   the measured census".

3. Lines 741–751, the Bootstrap block: replace the comment and the first command with:

   ```bash
   # Bootstrap: a fresh graph has no evidence, and the evidence-derived confidence
   # signals are half the total weight -- so a fresh instance refuses everything on
   # the built-in profiles (0.44 against Gaming's 0.55). Start from the measured
   # census: it imports each program's successful-transaction count from the
   # committed, reproducible protocols/battle_tested_evidence.json (114 of 137
   # records clear its bar; the rest are listed with the reason), recomputes the
   # tier from that evidence (no signature asserted), and writes one
   # operator_action row per program naming the census's sha256 and measurement
   # time. Re-running it imports nothing new. A manifested program then reaches
   # 0.59: Gaming only. Run it with the server stopped and the server's
   # GRAPHITE_AUDIT_KEY_FILE (docs/ops/install.md, "First start").
   graphite evidence import-census --cluster mainnet-beta --dry-run
   graphite evidence import-census --cluster mainnet-beta
   # Restore an exported graph, or vouch for evidence by hand (operator-asserted).
   # CLI-only: request-body evidence would let any caller mint an earned-looking
   # tier. Both take a base58 program id and write an operator_action row.
   graphite evidence seed --program <id> --signed-manifest --community-verified 2   --battle-tested 1500 --simulation-matches 100
   graphite evidence baseline --program <id> --mean-compute-units 150   --std-compute-units 12 --samples 50
   graphite evidence show --program <id>
   ```

4. Line 207 (optional, same fact): replace "whose transaction volume comes from the operator
   (`graphite evidence seed`): asserted, not earned at runtime." with "whose transaction volume
   comes from an operator command — `graphite evidence import-census` (this census's measured
   counts) or `graphite evidence seed` (asserted) — not from runtime observation."

**docs/CURRENT.md**: the header's "both need confidence above the profile's floor, which a fresh
instance (0.44) does not reach" — add "; after `graphite evidence import-census` (Round 40) a
fresh instance reaches 0.59 under Gaming, and every Round 39 attack was re-run in that state and
refused (`docs/audit/parts-r40/bootstrap.md` §5)". The "Trust tier a manifest declares" row ("a
verdict reaches BattleTested only through operator-seeded graph evidence") — add "or imported
census volume with a signature or attestations the graph already holds". The learning row (line
~190, "operator seeding is `graphite evidence seed` / `baseline`") — add `import-census`. The
"An upgrade sends a program back to the start" bullet — "until an operator re-seeds it" is still
true; add that a re-import skips a program whose deployment is newer than the census.

**CHANGELOG**: additive CLI subcommand `graphite evidence import-census`; library
`census_import`, `GraphiteCore::{standalone_standing, import_measured_evidence,
observed_deployment}`, `SemanticGraphStore::bind_evidence_to_slot`; no default changed.

**SECURITY.md**: under the threat model's G4 (confidence gaming): the census import is
operator-only, hash-pinned to the compiled-in census, and lifts HistoricalVolume only; its
residuals are §9 items 1–3.

**RESIDUAL_RISK_AND_OWNER_GATES.md** "Fresh-instance confidence" row: the precondition is now
met by one operator command; the row should say so and point here.

## 11. Commands run

All in `graphite-core/` with `CARGO_TARGET_DIR=/home/user/bootstrap-target CARGO_INCREMENTAL=0
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0`, `-j 2`.

| Command | Result |
|---|---|
| `cargo test --locked --test round40_census_import` | 11 passed |
| `cargo test --locked --test round40_import_census_cli` | 5 passed |
| `cargo test --locked --test round39_decision_campaigns -- --nocapture` | 21 passed (92 `Imported` verdicts logged) |
| `cargo test --locked --test round38_sibling_skims --test round38_create_funding --test round38_unscoped_authority --test staking_withdrawal_destination -- --nocapture` | 24 + 8 + 14 + 29 = 75 passed (38 of them twins) |
| `cargo test --locked --no-fail-fast` (default features, full leg) | 181 test binaries, **2,520 passed, 0 failed, 15 ignored** |
| `cargo test --locked --no-fail-fast --no-default-features --features cli` | 181 test binaries, **1,993 passed, 0 failed, 6 ignored** |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | clean |
| `cargo clippy --locked --all-targets --no-default-features --features cli -- -D warnings` | clean |
| `cargo fmt --all -- --check` | clean |
| `python -m pytest -q -p no:cacheprovider test_live_measure.py` (tools/live-measure; a scratch venv from `python-ai-layer/requirements-lock.txt`, hash-locked) | 60 passed (the CI floor is 60) |
| `bash .github/scripts/ci-scripts.test.sh` | 121 passed, 0 failed |
| `graphite evidence import-census --data-dir /tmp/graphite-bs-1 [--dry-run]` (debug binary, by hand) | dry run: 114 to import, 23 skipped, nothing written; import: 114 rows; re-run: 0 to import; `graphite audit verify`: exit 0 |
| breaks B1–B9 (§6) | each fails the tests named |

Not run: `validate_corpora.py` (no manifest or corpus touched); a public RPC (forbidden; the
census was not re-measured).

Pinned outputs: none moved. The census file, the manifests, the mainnet-sample verdict pins and
the swap-declaration census are unchanged. The only new pin is the census's SHA-256
(`973e4d58ab6306a67b53ad14e2c93e6ec6f53cab93ee090476eeb7e9e107138b`), which the code computes
from the compiled-in copy rather than storing, so a re-measured census changes it with no test
to re-pin.

Deleted: `/home/user/brk-bootstrap-1` and `/home/user/brk-bootstrap-target` (break copies),
`/tmp/graphite-bs-1`, `/tmp/graphite-r40-*`; `/home/user/bootstrap-target` and the scratch venv
at the end (reported in the hand-off).

## 12. Second pass (the lead's follow-ups, after merging `11f85c1` and then `22b8c5f`)

### 12.1 Learning and poisoning in the imported state

What the import changes for learning: under `ObservationPolicy::BuiltinFloor` (the default) a
simulation counts only when its verdict clears 0.55 / HeuristicInferred on its own. On a fresh
Core (0.44) nothing an imported program does trains; after the import (0.59) its honest,
simulated, risk-clear verdicts train its baseline, whoever sends them.

**Suites re-run in the imported state** (`imported_core_twins!`, tests/round40_imported/mod.rs:
every Core the test builds through its constructor is census-imported; the test's own profiles
are kept, since a request's profile is the lever a verify-key holder pulls):

| Suite | Twins | Not twinned, and why |
|---|---|---|
| `round30_trust_learning` | 6 | 4: two whose premise is "a fresh program is below Gaming" (`a_verify_key_holder_cannot_raise_…`, `concurrent_self_approvals_teach_nothing`), two whose premise is evidence that cannot be dated against the first deployment (imported evidence is dated; `round40_census_import::upgrades::*` covers the upgrade) |
| `audit_2026_10_20_simulation_gate` | 6 | 1: `policy_refusals_teach_nothing_…` (premise: fresh below Gaming) |
| `round17_remediations` | 9 | 1: `the_same_request_is_not_approved_on_the_second_call` (same premise; its TradingBot half passed) |
| `round19_what_one_observation_is` | 2 | 1: `a_fresh_blockhash_is_not_a_new_observation` (its sample assertion, five blockhashes = one observation, PASSED in the imported state; the approval-count premise did not) |
| `audit_a2_shadow_takes_refused_requests` | 2 | — |
| `evading_the_fixes` | 2 | 2 build no Core (RPC body parsing) |
| `round10_attribution` | 6 | 1: a temp dir named by the process id alone, which a twin would share |
| `round9_identity_requires_data` | 6 | — |
| `rpc_trust_boundary` | 11 | 5 build no Core (RPC parsing) |
| `simulation_integrity` unit tests (`alternating_outliers_cannot_widen_an_anchored_band`, `a_slow_drip_cannot_walk_an_anchored_baseline`), `audit_a2_baseline_variance_ratchet` | n/a | pure baseline functions on a `ComputeBaseline`; the import writes no baseline, so the imported state cannot change them. Run: pass |

Every twin passed. The premise-dependent tests are restated for the imported state in
`round30_trust_learning.rs`:

- `round40_after_the_import_requests_below_the_floor_still_teach_nothing` — forty requests
  refused by L4 (stated amount below what the simulation moves) under permissive, 0.40, Gaming
  and Treasury profiles, then thirty-two concurrently under the permissive one: 0 samples, 0
  shadow; the next honest verdict is still 0.59.
- `round40_after_the_import_one_request_repeated_is_one_observation` — six identical honest
  asks: one sample; confidence 0.59 then 0.6567 five times, never more by repetition.
- `round40_after_the_import_training_stops_at_the_ceiling_and_an_outlier_is_flagged` — eleven
  distinct honest transfers: 0.59 → 0.75 and no higher (OfficialManifest ceiling), tier
  OfficialManifest, TradingBot refuses; a 10× compute outlier is FLAGGED by L3, not executable,
  not a trusted sample.

**End-to-end campaign** (`round39_decision_campaigns::round40_training_an_imported_program_opens_no_attack`,
imported state, built-in Gaming, one Core across all requests):

1. Twelve honest-looking, distinct Stake withdrawals (40 SOL + i lamports): all
   `executable_approved`, twelve samples. Confidence by request:
   0.59, 0.6567, 0.7233, then 0.75 for every later one — SimulationMatch full at three samples,
   capped by the OfficialManifest ceiling.
2. What the training bought: an honest withdrawal at 0.75, tier OfficialManifest; TradingBot,
   Treasury and Enterprise refuse it (tier floors). That is what honest evidence justifies: the
   ceiling no traffic-earned evidence passes.
3. Thirteen attacks beside a granted Stake Withdraw on the trained Core — R39-1 A (closable
   account), B (co-signer), C (`CreateAccount` for the attacker's program), stranger transfer,
   owner / close-authority / freeze-authority change, close to attacker, approve, burn, hidden
   CPI, a second Withdraw to the attacker, Stake Authorize — and a withdrawal whose simulation
   used 10× the trained compute: **all refused**. Six sat at the trained 0.75 (A, B, C,
   stranger, second Withdraw, and the outlier); the outlier was FLAGGED by L3.
4. The refused requests taught nothing (samples unchanged at 13).

**No attack became executable. No P0.**

### 12.2 Wrong cluster: enforced

The Core had no notion of its cluster (nothing called `getGenesisHash`). The smallest enforced
design, implemented:

- `graphite evidence import-census` requires `--cluster mainnet-beta`; no flag, or any other
  name (`devnet`, `testnet`, `mainnet`, …), is refused before the data directory is touched.
- The census must say it was measured on `https://api.mainnet-beta.solana.com` (its `rpc`
  field); another is refused at the schema check.
- The import records the cluster in the graph snapshot:
  `SemanticGraphStore::evidence_genesis = 5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d`
  (mainnet-beta's genesis hash). Set once, never cleared; evidence of a second cluster in the
  same graph is refused (`SemanticGraphError::EvidenceCluster`) before anything is appended.
- At start, a server with `GRAPHITE_RPC_URL` calls `GraphiteCore::confirm_evidence_cluster`:
  when the graph holds the mark it asks the RPC `getGenesisHash`
  (`SolanaRpcClient::get_genesis_hash`, new) and **refuses to start** unless the answer is
  mainnet-beta's — or when the RPC cannot answer. A graph without the mark asks nothing and
  starts on any cluster, as before. Without an RPC nothing is simulated, so no verdict is
  executable, and the server starts.
- The live-devnet runner went back to `evidence seed` (operator-asserted): the census cannot
  be used on devnet or a local validator any more, by design. The live-mainnet runner passes
  `--cluster mainnet-beta`.

Tests: `round40_cluster_guard.rs` (the real binary against a loopback mock answering
`getGenesisHash`: the import without `--cluster` / with `devnet`, `testnet`, `mainnet` refused
and nothing written; a server over imported evidence refuses to start on a devnet genesis hash
and on an RPC that does not answer it, naming both hashes; the same data directory starts on a
mainnet-beta RPC; a data directory without imported evidence starts on a devnet RPC), and in
`round40_census_import.rs` `only_mainnet_beta_is_a_cluster_the_census_can_be_imported_into`,
`an_import_records_that_the_graphs_evidence_is_mainnet_betas` (the mark survives a reopen; a
second cluster is refused), `cluster::imported_evidence_is_refused_on_another_cluster_and_accepted_on_mainnet_beta`,
`cluster::a_graph_without_imported_evidence_asks_nothing`.

Trade-off (P14): a server on an imported data directory now depends on its RPC answering one
`getGenesisHash` at start; an RPC down at start means no start (fail closed, with the reason).

### 12.3 Deliberate breaks (second pass)

Same method (copy at `/home/user/brk-bootstrap-1`, own target dir, both deleted):

| Break | What was removed | Tests that fail |
|---|---|---|
| C1 | the server-start check (`confirm_evidence_cluster` not called) | `a_server_refuses_to_start_on_another_clusters_rpc_with_imported_evidence` |
| C2 | the genesis comparison | `cluster::imported_evidence_is_refused_on_another_cluster_and_accepted_on_mainnet_beta`, `a_server_refuses_to_start_…` |
| C3 | the `--cluster` name check | `the_import_names_mainnet_beta_or_does_nothing` |
| B9 again | R39-CORE-DECISION-1 reverted in part | `round40_training_an_imported_program_opens_no_attack`: R39-1 B and C are `executable_approved` on the trained Core at 0.75 under Gaming — the campaign catches it |

### 12.4 After merging `22b8c5f` (manifests workstream)

The merge was clean. The census file is unchanged (sha256 `973e4d58…07138b`); its decode
rates are recomputed against the manifests as loaded, and with the 23 phantom instructions
removed and 60 swap declarations rewritten the plan is still **114 imported, 23 skipped**, the
same records with the same reasons: the removed instructions were never observed by the census,
so no recomputed rate moved. No pin changed (`only_records_that_clear_every_threshold_are_planned`
still equals `battle_tested_programs()`, and every CLI count holds). The merged
`round39_decision_campaigns.rs` (the rewritten-venue attacks in all three configurations) and
this pass's campaign run together: 23 tests, all pass.

Floors (`.github/test-floors/`): default — `round40_census_import` 11 → 15,
`round30_trust_learning` 13 → 22, `round39_decision_campaigns` 22 → 23, new
`3 tests/round40_cluster_guard.rs`; cli — `round40_census_import` 8 → 10, and
`round40_cluster_guard.rs` excused (`cfg(feature = "server")`). Only raised, each to the count of
the run below.

### 12.5 Commands (second pass)

| Command | Result |
|---|---|
| `cargo test --locked --no-fail-fast` (default, after merging `22b8c5f`) | **2,590 passed, 0 failed, 15 ignored** |
| `cargo test --locked --no-fail-fast --no-default-features --features cli` | **2,000 passed, 0 failed, 6 ignored** |
| the nine learning suites with twins + `round39_decision_campaigns` + `audit_a2_baseline_variance_ratchet` | all pass (22, 14, 4, 9, 19, 7, 15, 12, 27, 23, 1) |
| `cargo test --lib simulation_integrity` (the anchored-band unit tests) | pass (in the default leg) |
| clippy `--all-targets --all-features` and `--all-targets --no-default-features --features cli`, `-D warnings` | clean |
| `cargo fmt --all -- --check` | clean |
| `bash .github/scripts/ci-scripts.test.sh` | 137 passed, 0 failed |
| `pytest -q test_live_measure.py` | 60 passed |
| breaks C1, C2, C3, B9 (§12.3) | each fails the tests named |

Deleted: the break copy and its target dir, `/tmp/graphite-r40-*`.
