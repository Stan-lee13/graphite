# Rounds 26–27 — real traffic on every commit, and upgrades noticed

> **Historical record.** This report describes the codebase at commit `24f104b`
> on 2026-10-16, and the changes made on top of it. For the current state of
> Graphite see [`CURRENT.md`](CURRENT.md).

**Date:** 2026-10-16 · **Base:** `24f104b` (Round 25) · **Scope:** two open roadmap items that need
no owner decision — a committed mainnet subset gated in CI (R-P2/R-P3) and protocol upgrade
detection (R-M1) — and the dependency advisories CI's audit found published since Round 24.

Internal engineering work. Not an independent audit and not a certification.

## 1. Real traffic on every commit (Round 26, R-P2/R-P3)

The published mainnet numbers come from samples of 10–23 MB that are not committed. Anyone can
refetch them by slot list, and the conformance test prints the hash it measured, but CI could not
gate on them.

Two whole finalized blocks are now committed. They are the last two of the 2026-09-23 sample
(slots 449808325 and 449808725): 2,284 executed transactions, legacy, v0 and v1, 2.5 MB.

`tools/mainnet-sample/make_committed_subset.py` writes the file. It refuses a source whose
SHA-256 `SAMPLES.md` does not record, chooses whole blocks by position (never rows by content),
and writes the same bytes on every run.

`mainnet_conformance::the_committed_mainnet_blocks_give_the_recorded_verdicts_every_run` runs the
blocks through the whole pipeline on every `cargo test`, with no network and no `#[ignore]`. It
checks:

- the file's provenance (source hash, slots, row count);
- 0 parse failures and 0 verify errors;
- 0 approved, since nothing is earned offline;
- two runs identical;
- the SHA-256 of the verdict file, which is pinned.

The pin was cross-checked against the full-sample run of Round 24's final code: the same 2,277
rows hash to the same value, `ff1bcff8…`. The committed slice reproduces the published
measurement row for row.

A change to any verdict on these blocks fails CI until it is attributed in the round's report
and the pin is updated in the same commit. Break B108 turns off the drainer heuristic, and the
pin catches it.

## 2. Advisories published after Round 24

CI's dependency audit failed on `24f104b` for advisories published after Round 24's push, not for
anything Round 25 changed.

**Rust:**

- `quinn-proto` 0.11.17 → 0.11.19: RUSTSEC-2026-0338, -0340, -0343.
- `rustls` 0.23.45 → 0.23.46: RUSTSEC-2026-0346, -0347, -0348.

**npm overrides:**

- SAK adapter: `@modelcontextprotocol/sdk` 1.31.0 (GHSA-6qxp-vccf-f47h) and `proxy-addr` 2.0.8
  (GHSA-jqcg-44mw-7w3h), both through `solana-agent-kit`'s `@openai/agents`.
- Dashboard: `source-map-js` 1.2.2 (GHSA-68fv-2mgg-jv7q), through vite's postcss.

`cargo audit` passes on both Rust lockfiles; the npm gate and `pip-audit` pass on every package.

## 3. A protocol upgrade is noticed (Round 27, R-M1)

The external reviews (R11, W5, W6) noted that a protocol upgraded under its manifest was judged
by the old manifest until someone noticed.

With an RPC attached, Graphite now reads the deployment of every manifested program a
verification invokes from the BPF Upgradeable Loader. That is two batched header reads under the
RPC budget: the `Program` account's 36 bytes, then the `ProgramData` header's 45, never the
program binary. Each deployment is compared with the last one seen, which is persisted in the
semantic graph.

- **First sighting:** the baseline.
- **A redeploy or a new upgrade authority:** reported once.
  - On the verdict: `program_upgrades`, with both slots and both authorities, and a
    `ProgramUpgraded` warning in the summary.
  - On `/health` (`program_upgrades.detected`) and in the metrics
    (`graphite_program_upgrades_detected_total`).
- **An answer that cannot be read:** records nothing and changes nothing. It is neither a
  refusal nor an approval.

Withdrawing the program from trust is the operator's decision, not a default.
`GRAPHITE_QUARANTINE_ON_UPGRADE=1` quarantines an upgraded program through the ordinary, durable
quarantine, before the verdict's own quarantine gate, so that verdict is already blocked. Any
value other than `0`/`1`/`true`/`false` refuses to start. Protocols upgrade routinely, and
refusing all of them until someone reviews each one is an outage only the operator can choose.

Tests: `tests/rm1_program_upgrade_detection.rs` (six cases over a loopback loader), the decoder
unit test, and the `/health`/metrics and flag-parsing server tests. Breaks B109–B111 (a redeploy
not a change, the flag ignored, the header reads dropped): 3 of 3 caught.

What R-M1 does not do:

- An upgrade before Graphite first sees a program cannot be reported; the first sighting is the
  baseline.
- Evidence earned on the old code (simulation baselines, tiers) is not reset by an upgrade.
- A manifest is not re-measured against the new code automatically.

## 4. Verified

- **Rust:** 1,923 tests in the all-features suite (136 binaries, 0 failed, 12 ignored), 356
  featureless, 1,644 cli-only. Clippy `-D warnings` is clean on all three legs, and fmt is clean.
- **Runtime oracle:** never looser than agave on both CI seeds.
- **TypeScript:** SDK 34, plus 4 live-server tests skipped.
- **Go:** all pass.
- **Mainnet blocks:** the committed-blocks pin is unchanged by R-M1, since no RPC means no
  deployment reads.
- **Breaks:** B108–B111, 4 of 4 caught.

## 5. Still open

Recorded in `AUDIT/02-roadmap-gap.md`:

- per-instruction L3 baselines (A2-08);
- the archive index (R-M11);
- owner configuration (R-M13);
- honest intents for withdrawals and claims (R-M14);
- the guard's public API on web3.js 1.x (R-M15);
- the owner's items: an independent audit, branch protection, deployment.
