# AUDIT FINAL — verdict (2026-10-21, after Round 29)

**Scope:** the whole repository, audited in six areas at `3327fcf` ([`00-map.md`](00-map.md)) and
fixed in Round 23. An external review of the result followed (R1–R26 with W1–W26); its items were
re-verified one at a time and answered through `eb17aa5` and Round 24; a second external review
(E1–E10) was answered in Round 25; a full-repository audit of `19a2974` (2026-10-20: 4 HIGH,
16 MEDIUM, LOW and informational items by area) was answered in Round 29. **Internal engineering
work by the maintainer and AI engineering agents, plus external reviews answered here. Not an
independent third-party audit and not a certification.** The independent audit remains an owner
decision (R-M4).

## Verdict

**Ready for a supervised production pilot behind its documented operating conditions; not
independently assured.**

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
- **Deliberate breaks:** 125 of 125 Rust breaks caught: B01–B59 from Round 23, B60–B103 from
  Round 24 (R2, R3, R3-b and W11–W25), B104–B107 from Round 25 (E3, E3b, E8), B108 from Round 26
  (the committed mainnet blocks catch a verdict change), B109–B111 from Round 27 (upgrade detection), B112–B125 from Round 28 (the archive index, the
  emission table, the contract gate). Round 29 adds B126 (the RPC-client and state-diff fixes
  reverted: 28 failures, every new test but its two controls) and B127 (the contract gate), . Outside
  the numbered harness, each Round 29 area's own revert runs are listed in the round report
  (core pipeline, server and CLI, audit trail and parser, agent guard, SDKs and schema, dashboard
  and AI layer: caught); the risk engine and registry, and the protocol data and attack suites,
  were not break-tested. B62 and B99 were
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
- an independent third-party audit (R-M4); deployment, TLS, DNS and monitoring (R-M6).

**Documented limitations, with their measured cost where one exists:**

- **R2-c.** An honest agent has no intent for a withdrawal, a claim, or a close on a protocol
  program, so these are refused under any label: 219 of 48,855 executed transactions, mostly
  pump AMM accumulator closes, Meteora DLMM liquidity calls and fee claims (roadmap R-M14).
- **R-M13.** Owner configuration of one's own object is refused like protocol administration.
- **A2-08.** L3 baselines are per program, not per instruction.
- **W17-c.** A lookup table's freshness is not checked against the current slot.
- **W11-c.** Registry records keep no signatures.
- **W18/19-f.** Signer lamports under a declared debit are disclosed, not refused; Graphite does
  not bind amounts, so the agent guard's cap does.
- **W25-d, revised in Round 29.** The holdout's benign label is now by provenance, but there is
  one benign row, and it is refused offline; the exploits run descriptively.
- **Round 29.** Without an RPC client nothing is simulated and the Core does not refuse for that
  alone; without a witness one primary RPC decides L8; the audit trail is corruption-evident, not
  tamper-evident; L3 does not flag deviations of 50% of the centre or less; a wallet ending in five
  or more `1`s is refused when it sends (R-4); the measured `BattleTested` tier does not reach
  verdicts and its bar is thin; wSOL wrapping is unsupported in the guard.
- **Coverage.** About 86% of verified mainnet transactions have a primary program with no
  manifest. There, the drainer heuristic is the coverage boundary.

**Open engineering:**

- the guard off `@solana/web3.js` 1.x (R-M15);
- scheduled mutation, fuzz and coverage runs (R-P11/12/15). Rust coverage is not measured.

**Not measured:**

- the approval path on live traffic: offline, approval is unreachable by design;
- attack classes beyond the repository's suites, the 37 documented real exploits and the
  deliberate breaks;
- the Round 29 fixes outside the RPC client, the state diff and the contract gate, against their
  own reversal.

## Bottom line

Graphite fails closed where this work looked. Its fixes are pinned by tests that catch their own
reversal, and its cost on four days of real mainnet traffic is measured and attributed. It
should run as a supervised pilot with branch protection on first. It should not be described as
independently audited until it is.
