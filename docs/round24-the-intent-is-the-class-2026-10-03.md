# Round 24 — the intent is the class

**Date:** 2026-10-01 to 2026-10-03 · **Base:** `eb17aa5` (R-P8 complete) · **Scope:** the external
review's R2 and R3, and its W11–W25, each re-verified here before anything changed; two more
agent-framework integrations; eight more manifests; four days of executed mainnet re-measured
under the labels used before and under honest ones.

Internal engineering work. Not an independent audit and not a certification.

The findings, each with its class, root cause, fix and test, are in
[`AUDIT/01-findings.md`](../AUDIT/01-findings.md) (external review section, Round 24 table);
the roadmap gap is [`AUDIT/02-roadmap-gap.md`](../AUDIT/02-roadmap-gap.md); the verdict is
[`AUDIT/FINAL.md`](../AUDIT/FINAL.md). This report is the narrative and the measurements.

## 1. What was asked

Resolve every open item, starting with the `@solana/kit` migration (finished in `eb17aa5`), then
R2 and R3 as far as they can be resolved. Add agent-framework integrations and more battle-tested
manifests. Leave no demo, placeholder, stub or mock in the shipped code. Make the repository
something a reviewer can run locally, from the tests, the dashboard or the binary, and get the
same answer every time.

## 2. The before-state, measured rather than taken from the review

R2 and R3 were reproduced on `eb17aa5`, built in its own target directory. An earlier attempt
that shared the build directory with the working tree measured the new code, and its result was
thrown away. Under a `transfer` intent:

- Squads `vaultTransactionExecute` and `batchExecuteTransaction` (the registry's two `drain`
  instructions), Bubblegum `delegate`, and SPL and Token-2022 `MintTo`, `MintToChecked`, `Burn` and
  `BurnChecked` got **L5 Passed and L7 Clear**;
- as declared siblings of a 0.001 SOL transfer, Phoenix `NameSuccessor`, Squads
  `multisigAddSpendingLimit`, `multisigSetTimeLock`, `multisigSetRentCollector`,
  `configTransactionExecute`, `spendingLimitUse`, `proposalApprove`, `batchAccountsClose`, the
  verifier's `rotate_block_submitter`, and Token-2022 CPI Guard `Disable`, `Reallocate` and
  `WithdrawExcessLamports` came back **Clear**.

`approved` was false in every probe, because the probe seeded no evidence or simulation. The
review's own recipe, which seeds both, reported `approved: true` for Bubblegum `delegate`. The
claim recorded here is the one measured: L5 Passed and L7 Clear on `eb17aa5`.

## 3. What changed

**The intent is compared with the class (R2).** L5 matched intent words against the instruction's
name and its manifest prose. The prose is boilerplate: the create, withdraw and close templates
all say "transfers", and "move" matched "remove". Meanwhile the Risk Engine accepted `transfer`
for every program. Now one table, `manifest::INTENT_DECLARES`, says which security classes each
intent can declare, and L5 and the Risk Engine's Check 9b both read it. Prose can only refuse.

**Control changes do not escape (R3, W14, R3-b).**

- The authority-name rule reads joined camelCase compounds and the missing powers (executor,
  submitter, successor and others).
- A delegation grant is a hand-over.
- An undescribed instruction of a described program is refused as a sibling.
- A described but unclassed sibling must be described by the transaction's own intent.
- What a sibling executed is judged by its own manifest.

The plumbing every transaction carries (Compute Budget, Memo, `SyncNative`, the read-only Token
queries, the nonce advance) is classed `inert`, so the sibling rule does not refuse it.

**Found by this round's own measurement (R3-b).** Re-measuring mainnet after the R2 fix turned
one refused verdict into a Clear one. Tensor AMM's `editPool`, newly manifested, had been classed
`transfer` by the IDL onboarding's default. The same default had classed 52 seed instructions
that switch or edit a setting, and 391 that need an admin's signature, as some class an intent
declares. Now:

- a name that opens by switching something (`enable`, `disable`, `toggle`, `pause`, `unpause`,
  `halt`, `unhalt`, `resume`) is a control change, whatever its tag;
- so is an instruction that needs an admin's signature;
- the generated `edit*`/`reset*` instructions are retagged, and the onboarding classifier tests
  those verbs first.

**The rest of the review.**

- W11/W12: registry signer and attestation rules; every upgrade replayed at its computed tier;
  atomic, locked registry writes; fixtures checked at load.
- W15: plugin rules do not reach the diff comparison.
- W16: RPC answers bounded by value count before parsing; an absent `err` is not a success.
- W17: v1 compute limit; the 64-lock account limit, confirmed against mainnet, where the largest
  executed transaction across 48,946 locks exactly 64.
- W18/W19: Token-2022 extension authorities and the pause flag; the remaining native
  authorities; effects scoped by role and polarity.
- W21: a quarantine lift, and a baseline observation, take effect only once recorded; a
  connection has a lifetime.
- W22: the spend cap bounds swaps by their simulated outflow; the SDK checks every field a caller
  decides on; the verdict names its message version.
- W23: Dependabot for Docker; pip-audit in CI; scoped npm allowlist entries; exact Python
  versions.
- W24: tests that could not fail now can.
- W25: errors are not counted as blocks; samples by slot list with SHA-256.

**Integrations and coverage.**

- The Vercel AI SDK and a Model Context Protocol server join SolanaAgentKit. All three sign only
  through `integrations/agent-guard`.
- Eight manifests were added from on-chain IDLs (Tensor AMM and TensorSwap, Jito tip payment and
  distribution, Mango v4, a token locker, a token launchpad (`MoonCVVN…`), Zeta). Seven measured
  `BattleTested`. Zeta stays `OfficialManifest`: 0.67 of its observed instructions decode,
  below the 0.90 bar.
- 137 manifests, 3,504 instructions, 113 `BattleTested` on the evidence.

## 4. Real traffic

Four days of finalized mainnet blocks (2026-09-23, -25, -27, -30), 48,855 executed transactions,
each pushed through the whole pipeline bound to its real bytes. The sample files' SHA-256 values
are in [`tools/mainnet-sample/SAMPLES.md`](../tools/mainnet-sample/SAMPLES.md), and the test
printed the same four hashes on every run below. 0 parse failures, 0 verify errors on every run.

| Comparison | Clear → Blocked | Blocked → Clear | Approved |
|---|---|---|---|
| `eb17aa5` vs. this round, the labels `eb17aa5` was measured with | 302 (0.62%) | 0 | 0 → 0 |
| the same, before R3-b | 302 | **1** (`editPool`) | 0 → 0 |
| R3-b alone | 1 (`editPool`) | 0 | 0 → 0 |
| `eb17aa5` with its labels vs. this round with honest labels | 219 | 40 | 0 → 0 |

Under the old labels, the 302 newly refused rows are transactions labelled `transfer` whose
instruction is a buy, a launchpad call, a close, a creation or a withdrawal. The R2 fix exists to
refuse exactly that.

Honest labels give every manifested instruction the intent that describes it, if one does. Under
them, the 219 newly refused transactions all have a manifested primary. This is what an honest
agent loses, and it is recorded as R2-c with roadmap item R-M14:

| Count | What | Why |
|---|---|---|
| 59 | Pump AMM `close_user_volume_accumulator` | `close` is served only by the token programs and Jupiter DCA |
| 41 | durable-nonce transactions whose first instruction the harness takes as the primary | no intent declares `inert`; Graphite's integrations describe the transfer and declare the advance as a sibling |
| 30 | Meteora DLMM liquidity calls | `add_liquidity*` is classed `create`; `initialize_bin_array` is unclassed |
| 29 | Pyth `updatePriceFeed` | a keeper's call no intent describes |
| 60 | withdrawals, fee claims, burns, oracle and fleet calls | no intent declares `withdraw` outside the stake programs, or `mint` |

The 40 transactions that move the other way are a labelling effect: the honest label describes
the instruction, where the old `transfer` label did not. None of these comparisons approves
anything, because approval needs earned evidence and a simulation, which this offline harness
does not provide.

R3-b was found by this measurement: one refused verdict became Clear when a newly manifested
`editPool` carried the onboarding's default class. That is why every manifest added now gets a
before/after verdict diff, not just a test.

## 5. Deliberate breaks

Every Round 24 fix was reverted once, alone, and its named test re-run:

- B60–B72 (R2 and R3): 13 of 13 caught. B62 was missed on its first run because it named a test
  that did not exercise the program rule; it was re-pointed to a test that does, and was caught.
- B73–B103 (W11–W25 and R3-b): 31 breaks, 30 caught on the first run. B99, the honest
  labeller's name step, was missed: every case its test named is labelled the same by the
  class step. The test now names a swap program's `transfer`-class `swap` (Orca Whirlpools,
  Raydium CPMM), which only the name step labels a swap, and B99 was re-run.
- TypeScript TSB1–TSB5 (the swap cap, the SDK result guard): 5 of 5 caught.

## 6. Still open

Recorded in `AUDIT/01-findings.md` and `AUDIT/02-roadmap-gap.md`:

- protocol upgrade detection (R-M1);
- owner configuration vs. protocol administration (R-M13);
- honest intents for withdrawals, claims and protocol closes (R-M14);
- per-instruction L3 baselines (A2-08);
- the documented limitations (signer lamports under a declared debit, lookup-table freshness,
  unsigned registry records, the holdout's own labels);
- the owner's items: an independent audit, branch protection, deployment.
