# Round 35 — Round 34 on real traffic, and the CPI report a real RPC sends

> **Historical record.** This report describes the codebase at the Round 34 head (`9ad4dfc`) and
> the changes made on top of it on 2026-10-23. For the current state of Graphite see
> [`CURRENT.md`](CURRENT.md).

**Date:** 2026-10-23 · **Base:** `9ad4dfc` (Round 34, unmerged) · **Branch:**
`claude/admiring-archimedes-lfhr7n` (PR #51) · **Scope:** the owner asked for the live-mainnet
workflow to be run on Round 34's code, for every suite to be run and Graphite tested on real
mainnet transactions, and for any open issue found to be fixed and tested. Internal engineering
work by the maintainer and AI engineering agents. **This is not an independent third-party audit
and not a certification.**

## A. What changed for an operator

- **A transaction that makes a CPI can be approved on a real RPC.** Agave's `simulateTransaction`
  reports inner instructions only in parsed form. Graphite read only the compiled form, so every
  transaction with a cross-program call was refused as incomplete (R35-3, below). Graphite now
  reads Agave's forms; what it cannot rebuild exactly still fails closed.
- **Run the writing CLI commands with the server's audit key.** `graphite evidence seed`/`baseline`
  and the other trail-writing commands must see the same `GRAPHITE_AUDIT_KEY_FILE` as the server.
  Without it, a fresh data directory gets an unkeyed record and a keyed server refuses to start,
  as Round 34 designed (`docs/ops/keys.md`).
- **The live-mainnet workflow fetches enough blocks.** It keeps fetching, up to 8 blocks, until the
  sample holds 1,000 transactions.
- **CI has a new job, `inner-instruction-oracle`.** It checks Graphite's rebuild of parsed inner
  instructions against Agave's own parser on every push. Its lockfile is audited, and Dependabot
  watches it.

## B. What was run

| Run | Code | Result |
|---|---|---|
| Live mainnet, seeded ([run 39942543507](https://github.com/Stan-lee13/graphite/actions/runs/39942543507)) | `9ad4dfc` | **Failed:** the sample held 493 transactions; the harness needs more than 500 verdicts (R35-2) |
| Live mainnet, unseeded ([run 39942561752](https://github.com/Stan-lee13/graphite/actions/runs/39942561752)) | `9ad4dfc` | Passed: 517 transactions in the sample, 200 replayed, no defect |
| Live devnet ([run 39942586309](https://github.com/Stan-lee13/graphite/actions/runs/39942586309)) | `9ad4dfc` | **Failed:** the Core did not start (R35-1) |
| Live mainnet, seeded ([run 39945280060](https://github.com/Stan-lee13/graphite/actions/runs/39945280060)) | `6d9d296` | Passed: 1,137 transactions in the sample, 200 replayed, no defect |
| Live devnet ([run 39945275439](https://github.com/Stan-lee13/graphite/actions/runs/39945275439)) | `6d9d296` | Passed: the devnet faucet answered 429, so it fell back to a pinned local Agave 4.2.2 validator. The gated transfer was `executable_approved`, signed, submitted and reconciled, and `audit verify` exited 0 |
| CI on PR #51 | `9ad4dfc`, `6d9d296` | Green. The default Rust leg took 8 min 25 s, then 5 min 24 s; on `b473a31` it took 2,557 s. The whole CI run on `6d9d296` took about 6.5 min (R33-8). The wall time on `main` is measured after the merge |
| Every local suite | the Round 35 tree | See §E |

In the live mainnet runs, nothing executable was approved. The reasons:

- Of 200 replayed transactions, 23–25 were refused because the callee report was unreadable
  (R35-3).
- Most of the rest failed simulation against today's state (minutes-old transactions replayed),
  had no mature baseline, or were refused at L4.
- The L4 refusals of honest swaps (Jupiter `route_v2`, Pump AMM `sell`, Meteora DBC `swap2`) cite
  `SignerTokenDebitUnderUnscopedDebit` or `SignerLamportsUnderUnscopedDebit`. That is Round 34's
  R33-5 rule meeting declarations that name no account (§G).

## C. Findings

| ID | Finding | State | Test |
|---|---|---|---|
| R35-1 | `live-devnet`: the runner seeded operator evidence with the CLI and no audit key, so the trail's first records were unkeyed, and the keyed Core refused to start (R33-4's no-downgrade rule, working as designed) | **Fixed:** the seeding commands run with the server's `GRAPHITE_AUDIT_KEY_FILE`; `keys.md` says operators must do the same | `test_evidence_is_seeded_under_the_key_the_core_runs_with`; reproduced with the release binary (unkeyed seeding: the keyed server refuses; keyed seeding: `tamper_evident`, `audit verify` exit 0) |
| R35-2 | `live-mainnet`: two blocks held 493 transactions; the conformance harness requires more than 500 verdicts and failed the run | **Fixed:** `fetch` continues to `min_transactions` (1,000), at most 8 blocks; the harness's floor is unchanged | `test_fetch_keeps_going_until_the_sample_is_large_enough` |
| R35-3 | **Every transaction that made a CPI was unapprovable on a real RPC.** Agave's `simulateTransaction` sends inner instructions only in parsed form (`parse_ui_instruction`; confirmed in `solana-rpc` 4.3.2's source): `{program, programId, parsed, stackHeight}` for System, SPL Token, Token-2022, ATA, Memo, the loaders, Stake, Vote and lookup tables, and `{programId, accounts: [<address>…], data, stackHeight}` for everything else. Graphite read only the compiled form (`programIdIndex`), so `observed_cpi_programs` was unknown, and the audit-2026-10-20 H1 gate refused the verdict as `VerificationIncomplete` ("the simulator's report of the programs this transaction called could not be read"). This held in 23 of 200 (Round 34's code) and 24 of 200 (Round 32's) replayed transactions: every one that reached the gate with a CPI. It failed closed, so it never caused an unsafe approval, but it made Graphite unable to approve a swap, an ATA creation or any other CPI on mainnet. Every mock RPC in the test suite answered in the compiled form, so no test saw it. | **Fixed:** `src/parsed_inner.rs` rebuilds the accounts and data of parsed System (12 types), SPL Token / Token-2022 (31 types each) and ATA (3) instructions. The partially decoded form is read as sent. `SimulationResult::resolve_reported_inner` maps addresses to the transaction's account list before anything reads the report. Anything else stays unknown: Memo (its JSON drops the signer accounts), the loaders, Stake, Vote, lookup tables, the Token-2022 extension instructions, `batch`, `allocateWithSeed`/`assignWithSeed`, and any `info` with keys it does not expect. The callee is still known, but the CPI tree is not, and the verdict stays incomplete. | `tests/round35_parsed_inner_instructions.rs` (5); `parsed_inner::tests` (4); `tools/inner-instruction-oracle` in CI; `round29_rpc_client::parsed_inner_instructions_are_named_…` re-pinned |
| R35-4 | Two audit-trail CLI tests were flaky: `round30_audit_chain` failed 6 times in 200 parallel runs (0 in 200 serial), and Round 34's `round34_audit_adopt_key` failed 1 in 200. A `graphite` child spawned by one test holds a copy of every descriptor the test process has open from its fork to its exec, a sibling test's writer lock included. A writer that dropped its log and reopened it in that window was refused as a second writer. Found in this round's full run (2,330 passed, 1 failed). The product spawns no process (no `Command` in `src/`), so this is a harness race, not a product one | **Fixed:** both files serialize their forks and their writer lifetimes under one mutex. A test that must hold its writer across its own child (`adopt_key_refuses_…_a_running_writer`) holds the mutex over both. No assertion changed | the two files, each run 500 times in parallel (§E) |
| R34-I-1 | (Recorded in Round 34) the deploy kit's edge answered 502 to an oversized body | Fixed in Round 34 | `deploy/tests/run.sh` |

**How R35-3 is proven exact.** `tools/inner-instruction-oracle` depends on Agave's
`solana-transaction-status` 4.3.2, the version mainnet RPCs run. It generates random instructions
of every supported type, packed by the programs' own interface crates (`spl-token-2022-interface`,
`solana-system-interface`, the ATA encoding). It parses each with Agave's `parse_ui_instruction`,
rebuilds it with `parsed_inner`, and parses the rebuild again. It requires three things:

- the JSON round-trips;
- every canonical instruction comes back byte for byte and account for account;
- every supported type is rebuilt, and no supported type is ever refused.

A share of the cases (30% by default, 90% in the second seed) gets random data or extra
accounts; only the round trip is required of those. Runs in this round:

- 100,000 iterations: 87,212 parsed instructions, 0 failures;
- 1,000,000 iterations under seed 7: 0 failures;
- 300,000 iterations at 90% fuzz under seed 20260916: 0 failures.

The core's test suite carries 231 of the oracle's samples (all 77 program/type pairs) as a
fixture, so a change to `parsed_inner` is caught without Agave in the build.

**Why the rebuild is the instruction the program ran.** Agave's parsers decode with the programs'
own instruction types. Those types ignore trailing data bytes and accounts past the ones they
read, and Agave prints every account the program reads by position. So the rebuilt instruction is
the canonical encoding of what the program decoded. Accounts the program does not read are not in
the JSON and not in the rebuilt list: a System transfer's third account, a legacy ATA `Create`'s
rent sysvar, or the second account of `allocateWithSeed` (which is why that type is not rebuilt).

## D. Pinned outputs

- **No committed corpus row and no mainnet digest moved.** The committed mainnet blocks run
  offline, and the corpus carries no simulation responses.
- **One test pinned the old behaviour:**
  `round29_rpc_client::parsed_inner_instructions_are_named_as_the_reason_the_cpi_set_is_unknown`
  asserted that a parsed report leaves the callee set unknown and names "parsed (jsonParsed)
  form". It now asserts that the parsed instruction it carries (an empty `info`, so not rebuilt)
  is named as not rebuilt, its callee is known, and its instruction is not.

## E. Test and build evidence

Local runs are on one build target, in this environment (Linux, 4 cores): fmt and the three clippy legs are clean; the default leg (`ci-test`) passes **2,331, 0 failed, 14 ignored** across 167 targets; the library leg passes **509, 3 ignored**; the cli leg passes **1,933, 5 ignored**. The CI floors move to these counts (2,322 / 505 / 1,928 → 2,331 / 509 / 1,933). The first full run of this round failed one test (2,330 passed): R35-4 below. After its fix, `round30_audit_chain` and `round34_audit_adopt_key` failed 0 of 500 parallel runs each.

| Leg | Result |
|---|---|
| TypeScript (agent guard, SDK, Vercel AI, MCP, SAK, dashboard) | 301 / 62 (+4 live) / 11 / 9 / 9 / 31; no corpus drift |
| Go SDK | `vet` and tests pass |
| Python | AI layer 50; `tools/mainnet-sample` 7; `tools/live-measure` 57 (CI floor raised 55 → 57) |
| CI scripts, release gate, actionlint | 25/25, 30/30, clean |
| Deploy kit (as root, with caddy, promtool, shellcheck and the current binary) | 109 of 109 |
| Runtime oracle | both CI seeds pass |
| Inner-instruction oracle | fmt and clippy clean; 1,000,000 + 300,000 iterations pass; `cargo audit` reports only RUSTSEC-2025-0141 (bincode unmaintained), the runtime oracle's one named exception |

## F. Deliberate breaks (B153 onward)

| # | Finding | What was reverted | Caught by | Result |
|---|---|---|---|---|
| B153 | R35-3 | `parsed_inner`: a Token amount written big-endian | the oracle (`mintTo`: round trip differs); the fixture test | caught |
| B154 | R35-3 | `parsed_inner`: a multisig authority's signers dropped from the account list | the oracle (`closeAccount`, `setAuthority`: round trip differs); the fixture test | caught |
| B155 | R35-3 | `parsed_inner`: ATA `createIdempotent` written as `create` | the oracle (`createIdempotent`: round trip differs); the fixture test | caught |
| B156 | R35-3 | `verify_async`: the reported inner instructions not resolved (the call removed) | `round35_parsed_inner_instructions::a_sweep_reported_in_agave_forms_is_seen_by_the_cpi_trace_rules`, `::the_simulation_gate_reads_a_parsed_report_and_still_refuses_one_it_cannot_rebuild` | caught |

The Python fixes were each reverted against their test (L20: the devnet seeding without the key;
L21: the fetch top-up removed). Both were caught.

## G. Owner decisions and residuals

- **R33-5 on real swaps.** With R35-3 fixed, the binding refusal for an honest swap in the live
  runs becomes Round 34's R33-5: the swap program's declaration says "transfers funds between the
  protocol and the involved accounts", naming no account. A signer's token or lamport debit under
  such a line is refused. 1,802 of the registry's 3,541 instructions carry only such lines. That
  covers the top swap programs in today's traffic: Jupiter `route_v2`, Pump AMM `sell`/`buy`,
  Meteora DBC `swap2`. Rewriting those declarations to name the debited accounts from each IDL is a
  manifest change. It decides what Graphite approves, and it is put to the owner with the measured
  list (live run on the Round 35 head), not made silently.
- **Not rebuilt (fail closed):**
  - Memo CPIs, because Agave's JSON drops their signer accounts;
  - Token-2022 extension instructions (`transferCheckedWithFee` among them), `batch`,
    token-group and metadata instructions;
  - Stake, Vote, the loaders, lookup tables;
  - `allocateWithSeed`/`assignWithSeed`.

  A transaction whose simulation reports one of these is still `VerificationIncomplete`. Each can
  be added with an oracle case.
- **The Agave version.** The oracle pins `solana-transaction-status` 4.3.2. An RPC on another
  version that prints a field differently is refused as not rebuilt (fail closed), never misread:
  the reader is strict about the keys it accepts.

## H. What could not be proven here

- **Approval on live traffic.** The live runs on the Round 35 head (`1b04945`) were read; §I has
  their numbers. Every replayed transaction was still refused, for reasons that are designs or
  owner decisions, not defects. So the approval path itself is proven only on the local validator
  (live devnet) and in the end-to-end tests, not on mainnet traffic.
- **The CI wall time on `main`** is owed after the merge (the PR's runs are above).
- **Independence.** This is internal work. None of it is an independent audit or a certification.

## I. The live runs on the Round 35 head (`1b04945`)

| Run | Sample | Replayed | Defects | `callee report unreadable` | Decisions |
|---|---:|---:|---|---:|---|
| Live mainnet, seeded ([39950918074](https://github.com/Stan-lee13/graphite/actions/runs/39950918074)) | 1,737 | 200 | none | **0** (25 on `6d9d296`) | 200 `blocked` |
| Live mainnet, unseeded ([39950924519](https://github.com/Stan-lee13/graphite/actions/runs/39950924519)) | 1,240 | 200 | none | **0** (26 on `9ad4dfc`) | 200 `blocked` |
| Live devnet ([39950921567](https://github.com/Stan-lee13/graphite/actions/runs/39950921567)) | — | — | none | — | the gated transfer `executable_approved`, signed, submitted, reconciled; `audit verify` exit 0 |

No verdict is `inconclusive` any more. Before, every verdict whose callee report was unreadable
was. One row in 200 reports "CPI tree not rebuilt": a parsed CPI outside the rebuilt set, refused
as designed. What still refuses the 200:

- **Simulation failed** (134–139 rows per run). These are minutes-old transactions replayed against
  today's state, which no longer let them succeed (custom program errors). That is not a Graphite
  judgement.
- **No mature baseline** (56–62). A fresh Core has learned no evidence for the program, and L3
  refuses until it has, by design. The run seeds only System and SPL Token.
- **R33-5** on every honest swap that simulated: Pump AMM `sell`, Raydium CLMM `swap_v2`, Raydium
  AMM `SwapBaseIn`, DFlow `swap`/`swap_with_destination`, Meteora DLMM
  `add_liquidity_by_strategy2`, and Jupiter-routed swaps. Each declaration's debit names no
  account, so the signer's token debit is refused (`a declaration Graphite cannot read`). Each of
  these rows is also refused for its missing baseline. Both would have to be resolved before such
  a swap is approved.
- **The seeded System and SPL Token transfers** were flagged as diverging from the program
  baseline. The runner seeds a synthetic baseline of 150 CU, and a real wallet's transfer carries
  ComputeBudget instructions (450–600 CU for the whole transaction, against which the program
  baseline is compared; A2-08). That is an artifact of the measurement's seed, not a verdict on
  the transfers.
- **W19 / undeclared signer lamport debits** (8–18 per run) on unmanifested programs, as in
  Round 32.

**The decision this leaves to the owner.** Should the declarations of the highest-traffic swap
instructions be rewritten from their IDLs, to name the accounts they debit and credit? Each
rewrite decides what Graphite approves for that instruction and needs its own test. Graphite
approves none of these swaps on a fresh Core until it is done.
