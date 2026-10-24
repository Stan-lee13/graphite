# AUDIT FINAL — verdict (2026-10-23, after Round 35)

**Scope:** the whole repository, audited in six areas at `3327fcf` ([`00-map.md`](00-map.md)) and
fixed in Round 23. An external review of the result followed (R1–R26 with W1–W26); its items were
re-verified one at a time and answered through `eb17aa5` and Round 24; a second external review
(E1–E10) was answered in Round 25; a full-repository audit of `19a2974` (2026-10-20: 4 HIGH,
16 MEDIUM, LOW and informational items by area) was answered in Round 29; a forensic whole-repository
audit of `29e4356` (2026-10-21: twelve leads G-01 … G-12, 0 P0, 6 P1, 14 P2, 36 P3) was answered in
Round 30 (`../docs/audit-r30/findings-registry.md`); Rounds 31–32 updated every dependency and
built the release, deployment and live-measurement path
(`../docs/round32-production-readiness-2026-10-22.md`); a deep audit of `b473a31` (Round 33: 1 P0,
9 P1, 13 P2, about 30 P3) was answered in Round 34
(`../docs/round34-the-deep-audit-remediated-2026-10-23.md`). **Internal engineering
work by the maintainer and AI engineering agents, plus external reviews answered here. Not an
independent third-party audit and not a certification.** The independent audit remains an owner
decision (R-M4).

## Verdict

**Release blocked on owner and external items; the code is ready for an independent audit.**
This is the same verdict `docs/CURRENT.md` states. Before Round 34 this page said "ready for a
supervised production pilot", which contradicted it. A supervised pilot needs, first:
- branch protection and the release rulesets applied;
- the protected `release` environment and a signing key (`docs/ops/production-checklist.md`, R1–R4);
- a real deployment with monitoring.
None of these can be done from the repository. The Round 33 audit also showed that the previous
round's confidence was too high: it found a P0 (R33-1) and a second exploitable path (R33-5) in code
three rounds of internal work had passed. That is the strongest argument for the independent audit.

Every finding this work raised is in one of three states:

- fixed at its root;
- recorded as an owner decision;
- recorded as a documented limitation, with its measured cost.

Through Round 28, every fix's test was shown to fail when the fix is taken away. Round 29's record
is partial: the RPC-client and state-diff fixes and the contract gate were reverted and caught; the
other areas' fixes have tests that pass with the fix, but no revert was run or recorded for them
(the Round 29 report lists which).

The two external-review items that bore most directly on this verdict were R2 and R3: whether a
declared intent could let a dangerous instruction through. Both were reproduced on `eb17aa5` and
are fixed. A third case of the same kind (R3-b) was found by this round's own mainnet
re-measurement and fixed the same day.

This audit claims no harmful transaction can be approved **only for what it examined**. It is not
a proof that nothing else exists. A fresh adversarial review by someone who did not write the
fixes is still the next thing that would raise confidence.

This is **not** a "0 issues" verdict.

## What was found and fixed

| | P0 | P1 | P2 | P3 | Other |
|---|---|---|---|---|---|
| Audit areas A1–A6 (Round 23) | 0 | 4 | 20 | 54 | 3 owner decisions, 3 coverage gaps |
| Review of the fixes and the suite (F1–F18) | 0 | 1 candidate (F3) | 5 | 9 | 2 test-quality, 2 nits, 1 rejected (F6) |
| External review R1–R12 and W1–W26 | 0 | 4 (R2; R3 and W14-a, which completes it; R3-b, from this round's measurement) | 15 (R1; 13 in Round 24, one disclosed rather than refused; R11 open) | 22 (21 fixed; W7 open) | R4–R10 fixed (documents, schemas, bridge); W24 test quality; 6 documented limitations; owner items |
| Second external review E1–E10 (Round 25) | 0 | 1 by mechanism (E1: a swap not held to the request) | 3 (E2, E3b, E4) | 5 (E3, E5, E6, E8, E9) and 1 documentation (E10) | E7 not a finding |

The full-repository audit of 2026-10-20 ranked on its own scale: **4 HIGH** (H1 a failed or
missing simulation approved; H2 a swap's output unbounded; H3 a transfer grounded without verb or
direction; H4 a swap's spend a one-simulation snapshot), **16 MEDIUM** (M1–M16) and LOW and
informational items by area, plus a documentation table. All closed in Round 29 — fixed, documented
as limitations, or recorded below as owner decisions
([round report](../docs/round29-the-audit-remediated-2026-10-21.md), `01-findings.md`). H1 is fixed
where an RPC client is attached; without one, nothing is simulated and the Core does not refuse for
that alone (a documented limitation; the agent guard refuses it).

- The R2 and R3 cases each got **L5 Passed and L7 Clear** on `eb17aa5`, measured in its own build.
  The review's recipe, with seeded evidence and a simulation, reported `approved: true` for one of
  them (Bubblegum `delegate`). Each case now has a test that fails on `eb17aa5`.
- R3-b: on four days of mainnet, the R2 fix turned one refused verdict into a Clear one. Tensor
  AMM's `editPool` carried the IDL onboarding's default `transfer` class. 52 switch/edit
  instructions, and 391 that need an admin's signature, were classed the same way. They are now
  control changes by rule, whatever their tag.

## Evidence

- **Tests:** the Rust (all three feature legs), TypeScript, Go and Python suites pass; their counts
  are kept in one place, [`docs/CURRENT.md`](../docs/CURRENT.md#numbers-as-of-this-pages-commit).
  Clippy `-D warnings` is clean on all three feature legs, and fmt is clean. The runtime oracle is
  never looser than the runtime on both CI seeds. Every fixed finding has a named test
  (`01-findings.md`); through Round 28 each was shown to fail before the fix.
- **Deliberate breaks:** 156 of 156 numbered Rust breaks caught. B153–B156 are Round 35's (the rebuild of Agave's parsed inner instructions). B128–B152 are Round 34's: one per Rust fix of the Round 33 findings, run in a clean integrated build, with B150 caught once its mis-aimed first run was re-pointed (`01-findings.md`). The earlier ones: B01–B59 from Round 23, B60–B103 from
  Round 24 (R2, R3, R3-b and W11–W25), B104–B107 from Round 25 (E3, E3b, E8), B108 from Round 26
  (the committed mainnet blocks catch a verdict change), B109–B111 from Round 27 (upgrade detection), B112–B125 from Round 28 (the archive index, the
  emission table, the contract gate). Round 29 adds B126 (the RPC-client and state-diff fixes
  reverted: 28 failures, every new test but its two controls) and B127 (the contract gate). Outside
  the numbered harness, each Round 29 area's own revert runs are listed in the round report
  (core pipeline, server and CLI, audit trail and parser, agent guard, SDKs and schema, dashboard
  and AI layer: caught). The risk engine and registry, and the protocol data and attack suites,
  were not break-tested in Round 29; Round 30 broke every one of their checks (62 mutants and six
  fix breaks, R30-F-3): nine were caught by no test or almost none, and each now has its own
  test, broken and caught. Every Round 30 fix was reverted against its own test; the records are
  in `../docs/audit-r30/findings-registry.md`. B62 and B99 were
  missed on their first run because their tests did not exercise the reverted rule; each test was
  corrected and the break caught. TypeScript: 11 of 11 caught (TSB1–TSB5 in Round 24, TSB6–TSB11
  in Round 25).
- **Real traffic:** 48,855 executed mainnet transactions from four days, with sample hashes
  recorded. Under the labels `eb17aa5` was measured with: 0 parse failures, 0 verify errors, 302
  newly refused (0.62%), **0 refused-to-Clear**, 0 approved before or after. Under honest labels,
  219 transactions with a manifested primary are newly refused (R2-c, below). The committed blocks
  were re-pinned in Round 29: 3 of 2,277 rows changed, each attributed, none from refused to
  approved, 0 approvals before and after.
- **Holdout (Round 29):** 37 real exploits, all refused; 1 real successful Jupiter swap, refused
  offline because its lookup tables cannot be resolved. Precision 0.974, recall 1.000 on n = 38.
- **Supply chain:** cargo-audit on both lockfiles; the npm gate keyed by advisory and package
  (scoped entries only), over six lockfiles, failing on any unlisted moderate, high or critical
  advisory; pip-audit on the Python lockfile; Dependabot for cargo, npm, pip, GitHub Actions and
  Docker.

## Still open

Recorded, not hidden. Each is in `01-findings.md` or `02-roadmap-gap.md` with its class.

**Owner decisions** (code cannot close them):

- branch protection on `main` (R-M5): until it is on, every CI gate is advisory;
- tagging `0.3.0-beta`: the contract gate found two caller-side schema breaks shipped under
  `v0.2.0-beta` (R28-1), so the crate's version is bumped and the CHANGELOG names both;
- the crate's publish flag (A6-15) and a disclosure mailbox for `SECURITY.md` (A6-36); enabling
  GitHub private vulnerability reporting, then linking it from `.github/ISSUE_TEMPLATE/config.yml`;
- an independent third-party audit (R-M4); deployment, TLS, DNS and monitoring (R-M6);
- release integrity (Round 34, R33-9): the three rulesets, the protected `release` environment and a
  key in `.github/allowed_signers` (R1–R4 in `docs/ops/production-checklist.md`). Until the owner
  applies the rulesets and the environment, anyone with write access can still publish a release
  with genuine provenance: the gate's empty signer list stops only the `release.yml` copies that
  contain the gate, while a tag on a branch commit runs that branch's own copy and a tag on a main
  commit older than the gate (`99948c6`) runs a copy with no gate at all (Round 37, R37-8; the
  Round 38 release guard cancels such a run from `main`, a second line, not the stop);
- whether to keep the Round 32–34 refusal defaults on the operator's traffic profile, after running
  `.github/workflows/live-mainnet.yml`.

**Documented limitations, with their measured cost where one exists:**

- **R2-c.** An honest agent has no intent for a withdrawal, a claim, or a close on a protocol
  program, so these are refused under any label: 219 of 48,855 executed transactions, mostly
  pump AMM accumulator closes, Meteora DLMM liquidity calls and fee claims (roadmap R-M14).
- **R-M13.** Owner configuration of one's own object is refused like protocol administration.
- **A2-08.** L3 baselines are per program, not per instruction.
- **W17-c.** A lookup table's freshness is not checked against the current slot.
- **W11-c.** Registry records keep no signatures.
- **W18/19-f.** Since Round 32, signer lamports leaving under a debit declared only for other
  accounts are refused by default (W19; opt-out `GRAPHITE_ALLOW_SIGNER_LAMPORTS_OUTSIDE_DECLARED_DEBIT`;
  1 of 200 live mainnet transactions, 0.5%). Graphite still binds no amounts in general, so the
  agent guard's cap does.
- **W25-d, revised in Round 29.** The holdout's benign label is now by provenance, but there is
  one benign row, and it is refused offline; the exploits run descriptively.
- **Round 29.** Without an RPC client nothing is simulated and the Core does not refuse for that
  alone; without a witness one primary RPC decides L8; the audit trail is corruption-evident, not
  tamper-evident; L3 does not flag deviations of 50% of the centre or less; a wallet ending in five
  or more `1`s is refused when it sends (R-4); the measured `BattleTested` tier does not reach
  verdicts and its bar is thin; wSOL wrapping is unsupported in the guard.
- **Coverage.** About 86% of verified mainnet transactions have a primary program with no
  manifest. There, the drainer heuristic is the coverage boundary.
- **Rounds 32–34 defaults.** A signer's loss under an unreadable declaration, under a debit line
  that names no account (R33-5: 1,802 instructions, 18 of the 27 withdrawal grants), or beyond a
  System transfer's stated amount is refused by default. An honest withdrawal under one of those 18
  grants is refused until its declaration is rewritten from its IDL. The cost on live traffic is
  measured by the live-mainnet workflow only: W19 refused 1 of 200 in Round 32. Round 35 ran it on
  Round 34's code: no defect, and honest swaps (Jupiter `route_v2`, Pump AMM `sell`, Meteora DBC
  `swap2`) are refused by R33-5 because their declarations name no account (an owner decision).
- **Withdrawal minimums.** Three grants carry a readable minimum (an unbounded or zero one is
  refused); the seven Meteora DLMM grants carry none; a non-zero dust minimum is not judged.
- **The agent guard's lock** reaches guards for one wallet under one OS user on one host.
- **Parsed inner instructions not rebuilt (Round 35).** Agave reports inner instructions only in
  parsed form; Memo, Token-2022 extension, `batch`, Stake, Vote, loader, lookup-table,
  `allocateWithSeed` and `assignWithSeed` CPIs are not rebuilt to their bytes, and a simulation
  reporting one is refused as incomplete.

**Open engineering:**

- the guard off `@solana/web3.js` 1.x (R-M15);
- mutation scores (R-P12): the fuzz and coverage jobs ran on the hosted runners in Round 32 (six
  targets × 30 minutes, 0 crashes; the 78 % line floor held), but the per-module mutation jobs
  approach the runners' 6-hour limit and the three provisional 0.60 floors are still unmeasured;
- 75 manifest instructions whose account count differs from their on-chain IDL (K-7), pinned, not
  fixed, because the evidence is ambiguous.

**Not measured:**

- the approval path on live traffic: offline, approval is unreachable by design;
- attack classes beyond the repository's suites, the 37 documented real exploits and the
  deliberate breaks;
- the two proptest suites under the Round 30 risk mutants; the CLI exit-code mapping on its own
  (tested through the decision rule).
- the per-shape, anchored L3 baselines (Round 30) against real RPC traffic: the conformance set
  runs offline.

## Bottom line

Graphite fails closed where this work looked, and Round 33 showed that "where this work looked"
was narrower than earlier rounds believed. Its fixes are pinned by tests that catch their own
reversal. Its cost on real mainnet traffic is measured and attributed where the committed data can
measure it; the rest is the live workflow's to measure. Release is blocked on the owner items above.
Since Round 30 only `executable: true` permits signing. It should not be described as
independently audited until it is.
