# AUDIT FINAL — verdict (2026-10-01)

**Scope:** the whole repository at `3327fcf` (Round 22), audited in six areas
([`00-map.md`](00-map.md)), fixed, reviewed, and re-measured. **Internal engineering work by the
maintainer and sub-agents — not an independent third-party audit and not a certification.** The
independent audit remains an owner decision (R-M4).

## Verdict

**Ready for a supervised production pilot behind its documented operating conditions; not yet
ready to be called independently assured.** Every finding this audit raised is fixed at its root
or recorded as an owner decision or a documented limitation, and every fix's test was shown to
fail when the fix is taken away. That is a statement about what this audit looked for, not a
proof that nothing else exists. An external review of the result has since raised items that
are not yet verified, two of which (R2, R3) concern whether a declared intent can let a
dangerous instruction through; **until they are verified and, if real, fixed, this audit does
not claim that no harmful transaction can be approved.** The issues listed under "Still open"
are real, and a fresh adversarial review by someone who did not write the fixes is the next
thing that would raise confidence.

This is **not** a "0 issues" verdict.

## What was found and fixed

| | P0 | P1 | P2 | P3 | Other |
|---|---|---|---|---|---|
| Audit areas A1–A6 | 0 | 4 | 20 | 54 | 3 owner decisions, 3 coverage gaps |
| Review of the fixes and the suite (F1–F18) | 0 | 1 candidate (F3) | 5 (F1, F2, F4, F16 and F3's residual) | 9 | 2 test-quality, 2 nits, 1 rejected (F6) |
| External review, verified so far (R1) | 0 | 0 | 1 (R1) | 0 | R2–R26 being verified |

- The four P1s (A1-01, A3-01, A3-02, A3-03) each produced `approved: true` or a Clear risk verdict
  for a harmful transaction on `3327fcf`; each now has a test that fails on `3327fcf`.
- Two fixes introduced regressions that the process caught before release: F1 (from A2-01) by the
  independent review, F16 (from F3) by the existing suite. One pre-existing defect surfaced from
  the same sweep (F18: the durable-nonce opt-in could never approve).

## Evidence

- **Tests:** 1,849 Rust tests in the default leg (341 featureless, 1,594 CLI-only), 146 in the SAK
  bridge, 37 TypeScript SDK, 44 Go, 35 Python, 7 dashboard, all passing on the local mirror of CI;
  every fixed finding has a named test that fails before the fix (`01-findings.md`).
- **Deliberate breaks:** 59 of 59 caught — each fix reverted once and its test re-run. One test
  (B54, A4-11) was vacuous on its first run and was strengthened until it failed without the fix.
- **Real traffic:** 48,855 executed mainnet transactions from four days, `3327fcf` against this
  round, row by row: 0 parse failures, 0 verify errors; 461 durable-nonce transactions no longer
  refused for their nonce advance; 9 newly refused, each a protocol or pool configuration call or
  a program-upgrade hand-over (0.018%). The read-only live-RPC check was not repeated this round, so
  the L4 changes (F1, F2) are pinned by tests but not yet observed on live simulations.
- **Supply chain:** cargo-audit on both lockfiles; an npm advisory gate keyed by advisory and
  package on all three npm lockfiles (one allowlisted advisory: `bigint-buffer`, a native addon
  never built because installs run with `--ignore-scripts`); Dependabot.

## Still open

Recorded, not hidden. Each is in `01-findings.md` or `02-roadmap-gap.md` with its class.

**Owner decisions** (code cannot close them):
- branch protection on `main` (R-M5) — until it is on, every CI gate is advisory;
- the crate's publish flag (A6-15) and a disclosure mailbox for `SECURITY.md` (A6-36);
- an independent third-party audit (R-M4); deployment, TLS, DNS and monitoring (R-M6).

**Documented limitations:**
- L3 baselines are per program, not per instruction (A2-08), and winsorizing raises false
  `SimulationSpoofing` flags for heavy-tailed programs (F5) — a deliberate trade against a
  ratchet;
- a lifecycle append that completes after a request timed out leaves a row the client never saw
  (F9) — it fails closed for the client;
- the L8 deadline test is wall-clock;
- creating a token account with someone else's close authority stays blocked (F6). In the four
  mainnet samples 18 executed OKX router transactions carry it as a sibling; all 18 were already
  refused at `3327fcf` (Check 10: a `close` sibling with no declared intent), so no verdict
  changed;
- an agent wallet cannot change any configuration through Graphite. The IDL onboarding tags every
  `set_*`, `update*`, `change*` and `configure*` instruction `authority`, which covers protocol
  administration and also an owner configuring its own object (Magic Eden MMM `updatePool`, a
  marketplace's `update_offer`); since F3 both are refused under any intent. Measured cost on
  four days of mainnet: 9 newly refused of 48,855, the five owner ones all `updatePool`. Telling
  owner configuration from administration (by the IDL's signer account and the object's owner
  field) is roadmap item R-M13;
- 87% of verified mainnet transactions call a program with no manifest; the drainer heuristic is
  the coverage boundary there (Round 22), not a bug.

**External review items not yet verified:** R2–R26 of the 2026-10-01 external review are
being re-verified one at a time. Until an item is verified it is not counted here as a finding
or as a non-finding. R2 and R3 (how a declared intent and an instruction's name and class gate
dangerous instructions) are the ones that bear most directly on this verdict.

**Not measured this round:**
- the approval path on live traffic: offline, approval is unreachable by design (it needs an RPC
  simulation and earned evidence), so "valid transactions are approved" is shown only by the
  pipeline tests, not on mainnet traffic;
- attacks beyond the repository's own suites, the 35 documented real exploits (all refused) and the
  deliberate breaks — unknown attack classes are, by definition, not covered by a test;
- why two real benign transactions in the holdout (a Jupiter route and a PumpSwap trade) are
  refused; they are counted as false refusals until examined.

**Planned engineering:**
- the SAK bridge's migration to `@solana/kit` (R-P8), which also removes its last npm advisory;
- a persisted archive index for L8 lookups into rotated archives (R-M11);
- a committed mainnet subset gated in CI (R-P2/R-P3) and the release-evaluation report (R-P1);
- protocol upgrade detection (R-M1) and per-instruction L3 baselines (A2-08);
- scheduled mutation, fuzz and coverage runs (R-P11/12/15); Rust coverage is not measured.

## Bottom line

Graphite fails closed where this audit looked, its fixes are pinned by tests that were shown to
catch their own reversal, and its cost on four days of real mainnet traffic is measured and small.
It should run as a supervised pilot with branch protection turned on first, and it should not be
described as independently audited until it is.
