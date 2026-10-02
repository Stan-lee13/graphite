# Round 23 — the audit, closed at the root

**Date:** 2026-09-29 to 2026-10-01 · **Base:** `3327fcf` (Round 22) · **Scope:** a six-area audit of
the whole repository (Core, simulation and state diff, manifests and policy, server and audit
trail, the AI boundary with SDKs, bridge, dashboard and Python layer, and CI, supply chain and
container), the fixes, an independent review of the fixes, the full suite, and the before and
after measured on four days of executed mainnet traffic.

Internal engineering work. Not an independent audit and not a certification; the third-party
audit remains the owner's decision.

The findings, each with its class, root cause, fix and test, are in
[`AUDIT/01-findings.md`](../AUDIT/01-findings.md); the map of what was audited is
[`AUDIT/00-map.md`](../AUDIT/00-map.md); the roadmap gap is
[`AUDIT/02-roadmap-gap.md`](../AUDIT/02-roadmap-gap.md); the verdict is
[`AUDIT/FINAL.md`](../AUDIT/FINAL.md). This report is the narrative and the measurements.

## 1. What was asked

Make Graphite production-ready and hard to attack: run everything, test against live mainnet
data, fix what is found at its root, give every fix a test that fails before it and passes after
it, revert each fix once to prove the test catches it, update every document, and say honestly
what is still open.

## 2. What the audit found

| Area | P0 | P1 | P2 | P3 |
|---|---|---|---|---|
| A1 Parser and identity | 0 | 1 | 1 | 2 |
| A2 Simulation and state diff | 0 | 0 | 7 | 3 |
| A3 Manifests, risk, confidence, policy, plugins, registry | 0 | 3 | 2 | 6 |
| A4 RPC, server, audit log | 0 | 0 | 4 | 8 |
| A5 AI boundary, SDKs, bridge, dashboard, Python | 0 | 0 | 2 | 5 |
| A6 CI, supply chain, container, docs | 0 | 0 | 4 | 30 |

No P0. Four P1s, each shown by a test that produced `approved: true` or a Clear risk verdict for a
harmful transaction on `3327fcf`:

- **A1-01** — a token-account close with one trailing data byte escaped both close checks;
- **A3-01** — an authority or delegate hand-over passed as the primary instruction when its
  intent keyword appeared in the manifest's prose;
- **A3-02** — the same hand-over as a declared sibling was caught only if its manifest tagged it;
- **A3-03** — quarantine blocked only the primary instruction's program.

## 3. The review of the fixes, and what the suite found after it

A read-only review of the fixes hunted for defects the fixes introduced (F1–F15). Then the full
suite and a sweep of every native manifest found three more (F16–F18). Each is in
`AUDIT/01-findings.md`; the ones that changed behaviour on real traffic:

- **F1** (P2, a regression from A2-01): a declaration made only of account-name lists was called
  "unrecognised", which softened an undeclared token debit from Critical to a warning on 27 seed
  instructions and every memo. Fixed: a name list declares nothing, so the debit is Critical.
- **F2** (P2): a debit declared for one named account excused debiting any other. Fixed for
  token accounts a signer owns; program-owned vaults keep the transaction-wide rule, so swaps
  are not refused.
- **F3** (P1 candidate): the name rule missed control hand-overs (`grant_role`,
  `multisigAddMember`, `setOperator`, `set_treasury`, …), and an `authority`-tagged instruction
  was blocked only when no intent was declared. Fixed: the manifest's `authority` tag is a
  hand-over under any intent, and the name rule pairs a mutating verb with a power noun.
- **F16** (P2, a regression from F3, caught by two pre-existing suite tests): the hand-written
  Stake Program manifest tagged six routine staking operations `authority`, so delegating,
  deactivating, splitting, merging and moving stake were refused under any intent. None of them
  changes who controls a stake account. Fixed in the data: a `stake` class that still needs a
  declared intent; `Authorize*` and `SetLockup*` still block.
- **F18** (P3, pre-existing): `GRAPHITE_ALLOW_DURABLE_NONCE=1` could never produce an approval,
  because the System manifest tagged `AdvanceNonceAccount` — the first instruction of every
  durable-nonce transaction — `authority`. Fixed in the data; `AuthorizeNonceAccount` still
  blocks.

Runtime tests were also added for the four fixes that had been covered by review alone (A4-09,
A4-11, F9, F10).

### An external review, and R1

A second review of `0921647`, from outside, listed 26 items. Each is re-verified before it is
acted on. The first, R1, was confirmed: L8 reported `ApprovedAndExecuted` for an approved
record found only by a key the caller supplied, when `getTransaction` returned no bytes. A
positive conclusion about an approved record now needs the chain's own bytes, bound to the
signature; a blocked record still alarms on any sighting. Three existing tests had pinned the
weaker answer as correct. The remaining items (R2–R26) are being verified after this round's
commit; `AUDIT/01-findings.md` records each one only once it is verified.

## 4. Real traffic

### Four days of mainnet, `3327fcf` against this round

The executed mainnet transactions fetched on 2026-09-23, -25, -27 and -30 (48,855 verified,
artifact-bound, through the whole pipeline with no RPC attached), row by row:

| Sample | Verified | Risk Clear before → after | Blocked → Clear | Clear → Blocked |
|---|---|---|---|---|
| 2026-09-23 | 19,440 | 13,260 → 13,465 | 210 | 5 |
| 2026-09-25 | 9,973 | 6,650 → 6,758 | 108 | 0 |
| 2026-09-27 | 10,444 | 7,233 → 7,316 | 87 | 4 |
| 2026-09-30 | 8,998 | 6,928 → 6,984 | 56 | 0 |
| **Total** | **48,855** | **34,071 → 34,523** | **461** | **9** |

0 parse failures and 0 verify errors on either side.

- **All 461 Blocked → Clear** were refused at `3327fcf` only for a System Program sibling tagged
  `authority`: the nonce advance of a durable-nonce transaction (F18). L2 still refuses every
  durable-nonce transaction unless the operator opts in — 2,261 of the 48,855 (4.6%), the same
  rows before and after; what changed is that the risk verdict no longer refuses them for the
  advance, so an operator who opts in can get an answer about the rest of the transaction.
- **The 9 Clear → Blocked** are what F3 costs on real traffic: one BPF Upgradeable Loader
  `SetAuthority` (a program's upgrade authority handed to another key — caught, correctly), three
  protocol-admin configuration calls (Tail Trade `updatePrelaunchOracleParams`, Stableswap
  `update_pair`, Bo Sc `update_market_sigma`) and five Magic Eden MMM `updatePool` calls, a
  pool owner's pricing configuration. An agent wallet that is prompt-injected into re-pricing a
  pool loses through the trades that follow, so refusing pool configuration by default is the
  intended cost: 9 of 48,855 (0.018%).

### Live mainnet RPC

Not repeated this round. The read-only live-RPC check (`tests/mainnet_live_rpc.rs`: real
transactions simulated by a public endpoint, pre- and post-state read and diffed) last ran in
Round 21. The L4 changes of this round (F1, F2) are therefore pinned by unit tests and by the
corpus, and have not yet been observed on live simulations; that is the first thing the next
round should run.

## 5. Deliberate breaks

Every fix was reverted once, alone, and its named test re-run (`AUDIT/01-findings.md`,
§ Break log): **59 breaks, 59 caught.** One test was vacuous on its first run: with the A4-11
lock removed, the concurrent-report test still passed, because the audit log's own file mutex
leaves the race a window of microseconds. It now holds that window open for one dedicated trail
id under `cfg(test)`, fails without the lock, and the break was re-run. That is the campaign's
point: a green test proves nothing about a fix until the fix is taken away.

## 6. What was verified

The local mirror of CI on the code committed in `649dcac`:

| Job | Result |
|---|---|
| `cargo fmt --check` | clean |
| clippy, `-D warnings`, three feature sets | clean |
| `cargo test --all-features` | 1,843 passed, 1 failed (the stale lint test below; fixed, then 6/6 in its binary), 15 ignored |
| `--no-default-features --lib` | 341 passed, 0 failed |
| `--no-default-features --features cli` | 1,593 passed, 1 failed (the same lint test) |
| runtime oracle (300,000 frames, and the fixed seed) | never looser than agave |
| TypeScript SDK / dashboard / SAK | pass (37 / 7 / 146) |
| Go SDK (gofmt, vet, tests) / Python | pass (44 / 35) |
| npm advisory gate, all three lockfiles | pass (one allowlisted advisory, `bigint-buffer`) |

The final mirror, on the R1 commit (`378da27`) with the strengthened race test, passed every leg with 0 failures: 1,849 / 341 / 1,594, fmt and clippy clean on all three feature sets.

The first full run found five failures, all from this round's own changes, and each is
recorded in `AUDIT/01-findings.md`: two pre-existing staking tests (F16), three transfer-hook
tests whose fixture named no accounts (F17), and later one lint test holding a fifth copy of the
risk-class list.

## 7. Still open

See `AUDIT/FINAL.md` § Still open and `AUDIT/02-roadmap-gap.md`.

## 8. Files

- `AUDIT/00-map.md`, `AUDIT/01-findings.md`, `AUDIT/02-roadmap-gap.md`, `AUDIT/FINAL.md`
- Core: `src/manifest.rs`, `src/state_diff.rs`, `src/verification.rs`, `src/server.rs`,
  `src/simulation_integrity.rs`, `src/manifest_registry.rs`, `src/risk_engine.rs`;
  `protocols/stake-program.json`, `protocols/system-program.json`; regenerated
  `fixtures/corpus/*`
- Tests added: `tests/audit_review_f10_l8_bytes_keep_their_budget.rs`,
  `tests/docs_numbers_match_the_code.rs`, and unit tests in `manifest`, `state_diff`,
  `verification`, `simulation_integrity`, `server` and `manifest_registry`;
  `durable_nonce_rpc::a_permitted_nonce_advance_is_not_refused_as_a_hand_over`
- Outside the Core: `integrations/solana-agent-kit/intent-grounding.ts`,
  `python-ai-layer/intent_parser.py`, `.github/npm-audit/gate.mjs`,
  `.github/workflows/ci.yml`, SDK and dashboard lockfiles
