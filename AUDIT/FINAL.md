# AUDIT FINAL — verdict (2026-10-03, after Round 24)

**Scope:** the whole repository, audited in six areas at `3327fcf` ([`00-map.md`](00-map.md)) and
fixed in Round 23. An external review of the result followed (R1–R26 with W1–W26); its items were
re-verified one at a time and answered through `eb17aa5` and Round 24. **Internal engineering
work by the maintainer and AI engineering agents, plus one external review answered here. Not an
independent third-party audit and not a certification.** The independent audit remains an owner
decision (R-M4).

## Verdict

**Ready for a supervised production pilot behind its documented operating conditions; not
independently assured.**

Every finding this work raised is in one of three states:

- fixed at its root;
- recorded as an owner decision;
- recorded as a documented limitation, with its measured cost.

Every fix's test was shown to fail when the fix is taken away.

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

- The R2 and R3 cases each got **L5 Passed and L7 Clear** on `eb17aa5`, measured in its own build.
  The review's recipe, with seeded evidence and a simulation, reported `approved: true` for one of
  them (Bubblegum `delegate`). Each case now has a test that fails on `eb17aa5`.
- R3-b: on four days of mainnet, the R2 fix turned one refused verdict into a Clear one. Tensor
  AMM's `editPool` carried the IDL onboarding's default `transfer` class. 52 switch/edit
  instructions, and 391 that need an admin's signature, were classed the same way. They are now
  control changes by rule, whatever their tag.

## Evidence

- **Tests:** 1,908 Rust tests pass in the all-features suite (135 binaries, 12 ignored: network-
  or sample-dependent, plus one soak benchmark), 356 in the featureless library build and 1,641
  in the cli-only build. The TypeScript suites pass: 183 in the agent guard, 34 in the SDK (4 more
  need a live server), 7 in the Vercel AI adapter, 8 in the MCP server, 6 in the SolanaAgentKit
  adapter and 7 in the dashboard. Go passes 45 and Python 35. Clippy `-D warnings` is clean on
  all three feature legs, and fmt is clean. The runtime oracle is never looser than agave on
  both CI seeds. Every fixed finding has a named test that fails before the fix
  (`01-findings.md`).
- **Deliberate breaks:** 103 of 103 caught. B01–B59 are from Round 23; B60–B103 are from
  Round 24 (R2, R3, R3-b and W11–W25). B62 and B99 were missed on their first run because their
  tests did not exercise the reverted rule; each test was corrected and the break caught. The
  TypeScript breaks TSB1–TSB5 were 5 of 5 caught.
- **Real traffic:** 48,855 executed mainnet transactions from four days, with sample hashes
  recorded. Under the labels `eb17aa5` was measured with: 0 parse failures, 0 verify errors, 302
  newly refused (0.62%), **0 refused-to-Clear**, 0 approved before or after. Under honest labels,
  219 transactions with a manifested primary are newly refused (R2-c, below).
- **Supply chain:** cargo-audit on both lockfiles; the npm gate keyed by advisory and package
  (scoped entries only); pip-audit on the Python lockfile; Dependabot for cargo, npm, pip, GitHub
  Actions and Docker.

## Still open

Recorded, not hidden. Each is in `01-findings.md` or `02-roadmap-gap.md` with its class.

**Owner decisions** (code cannot close them):

- branch protection on `main` (R-M5): until it is on, every CI gate is advisory;
- the crate's publish flag (A6-15) and a disclosure mailbox for `SECURITY.md` (A6-36);
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
- **W25-d.** The holdout's benign labels are Graphite's own.
- **Coverage.** About 86% of verified mainnet transactions have a primary program with no
  manifest. There, the drainer heuristic is the coverage boundary.

**Open engineering:**

- protocol upgrade detection (R-M1);
- a persisted archive index (R-M11);
- a committed mainnet subset gated in CI (R-P2/R-P3);
- the guard off `@solana/web3.js` 1.x (R-M15);
- scheduled mutation, fuzz and coverage runs (R-P11/12/15). Rust coverage is not measured.

**Not measured:**

- the approval path on live traffic: offline, approval is unreachable by design;
- attack classes beyond the repository's suites, the 35 documented real exploits and the
  deliberate breaks.

## Bottom line

Graphite fails closed where this work looked. Its fixes are pinned by tests that catch their own
reversal, and its cost on four days of real mainnet traffic is measured and attributed. It
should run as a supervised pilot with branch protection on first. It should not be described as
independently audited until it is.
