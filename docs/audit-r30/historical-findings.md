# Historical findings and open items: dispositions at `29e4356`

Two parts. The **regression matrix** (`historical-regression-matrix.md`, generated) takes every
finding ID in `AUDIT/*.md`, `docs/round*.md`, the other dated reports, `SECURITY.md` and
`docs/CURRENT.md`, collects the tests its records name, and reports whether those tests ran and
passed on this commit. It is mechanical by design. This page is the reviewed part: every item the
records leave **open, partial, a limitation or an owner decision**, plus the twelve leads of the
Round 30 brief (G-01 … G-12), each checked against the code at `29e4356`.

Status vocabulary (the brief's): confirmed fixed on current HEAD · fixed in code but not tested
here · still open · regressed · partially addressed · documentation-only · needs external proof ·
superseded.

## The twelve leads

| Lead | Status at `29e4356` | Evidence in the code | Owner of the fix (Round 30) |
|---|---|---|---|
| G-01 `approved: true` without a simulation | **still open** (design) | `approved = l6_passed && !simulation_layer_failed && risk_summary.status == "Clear"` (`verification.rs:9143`) never reads `scope`; without an RPC L3 is Inconclusive (`verification.rs:8980`) and the scope carries `not_simulated`. Only the agent guard's `ResidualPolicy` refuses (`residual-policy.ts:111-161`). The Go SDK's package doc still calls `Approved` "the only field carrying a DECISION" (`sdk/go/graphite.go:29-31`) | WS-A (`decision`/`executable`) |
| G-02 learning from policy refusals | **still open** (opt-in exists) | `OperatorPolicy.learn_from_policy_refusals` from `GRAPHITE_LEARN_FROM_POLICY_REFUSALS` (`operator_boundary.rs:267`), honoured at `verification.rs:9217-9222`; startup warns (`server.rs:1079-1082`); `.env.example:75-78` offers it | WS-B |
| G-03 program-level L3 baselines | **still open** (A2-08) | baselines keyed by program id; `CURRENT.md:446-449` states deviations up to 50% are never flagged | WS-B |
| G-04 first sighting is the baseline; evidence not reset on upgrade | **still open** | `note_deployments` (`verification.rs:3328-3390`): `DeploymentChange::First` stores silently; `Changed` counts, optionally quarantines, and reports — no baseline, observation or graph evidence is reset | WS-B |
| G-05 manifest coverage below the decode bar | **still open** (data) | the ledger re-validated all 137 manifests (3,541 instructions, unique program ids, unique discriminators and names, hex discriminators); the 13 sub-90% records are in `battle_tested_evidence.json` | WS-F |
| G-06 intent vocabulary refuses whole classes (R-M13, R-M14) | **still open** | `manifest::INTENT_DECLARES`; R2-c measured cost 219 / 48,855 | WS-G |
| G-07 audit trail not tamper-evident | **still open** | no MAC, chain or signature in `durable.rs` or `durable/archive_index.rs` (no occurrence of any); unkeyed SHA-256 only | WS-C |
| G-08 single-primary L8, no light client | **still open** | the witness is optional; nothing requires one or checks provider independence beyond `same_endpoint` URL normalisation | WS-D |
| G-09 no generated release evaluation; holdout 38 rows | **still open** | `docs/release-evaluation-report.md` is a dated Phase document; no `graphite benchmark --json` | WS-E |
| G-10 no fuzzing / mutation / coverage gates | **still open** | no `fuzz/` directory; no such job in `ci.yml` | WS-E |
| G-11 branch protection absent | **still open — owner action** | `main` reported `protected: false` by the GitHub branches API on 2026-10-21 (this pass). Two stale non-dependabot branches exist (`copilot/fix-rust-core-actions-job`, `phase2-development`) | Owner (STOP-SHIP) |
| G-12 operations and external decisions | **owner / external** | see the table below | Owner |

## Every open, partial, limitation or owner item in the records

| Item | Records | Status at `29e4356` | Evidence / note |
|---|---|---|---|
| A2-08 / W8 L3 per program, not per instruction | 01-findings, 02-roadmap-gap, CURRENT | still open | = G-03 |
| R2-c / R-M14 no honest intent for withdraw, claim, protocol close | 01-findings, CURRENT, FINAL | still open | = G-06 |
| W7 / R-M13 owner configuration refused like administration | 01-findings | still open | = G-06 |
| W17-c lookup-table freshness not checked | 01-findings, SECURITY | documentation-only (limitation) | refusal direction (the runtime fails such a transaction) |
| W11-c registry records keep no signatures | 01-findings, SECURITY | documentation-only (limitation) | a registry file cannot be re-verified offline |
| W18/19-f signer lamports under a declared debit disclosed, not refused | 01-findings, CURRENT | documentation-only (limitation) | the guard's cap bounds it |
| W25-d holdout benign label | 01-findings, FINAL | partially addressed (Round 29: provenance label, one benign row, refused offline) | = G-09 |
| R-M10 / W13 `content_hash` naming | 02-roadmap-gap, CURRENT | still open | WS-A |
| R-M15 guard public API on web3.js 1.x | 02-roadmap-gap, CURRENT | still open | four moderate advisories allowlisted in `agent-guard.allow` |
| R-M9 / W9 P12 vs the drainer heuristic | 02-roadmap-gap, SECURITY | owner decision | unchanged |
| R-M4 independent audit | all | needs external proof | — |
| R-M5 / A6-16 / M16 branch protection | all | owner action, open | = G-11 |
| R-M6 deployment, TLS, DNS, monitoring | 02-roadmap-gap | owner + spend | — |
| R-M7 / R-M8 third-party plugins, other frameworks, LLM parsing | 02-roadmap-gap | owner / external | — |
| R-M12 shared rate limiter | 02-roadmap-gap, CURRENT | still open (single replica assumed; the data-dir lock enforces one server per directory, not one replica per key) | — |
| R-P1 release-evaluation report | 02-roadmap-gap | still open | = G-09 |
| R-P6 reviewer independence, PR workflow | 02-roadmap-gap | partially addressed (Round 29 registry work) | — |
| R-P7 `sample_count ≥ 20` for tier-3+ | 02-roadmap-gap | needs external proof (a running deployment) | — |
| R-P10 self-healing quarantine threshold | 02-roadmap-gap | owner decision | — |
| R-P11 / R-P12 / R-P15 mutation, fuzz, coverage | 02-roadmap-gap | still open | = G-10 |
| R-P16 / R-P17 IDL-less traffic; manifests below the bar | 02-roadmap-gap ("five"), CURRENT ("13") | still open; the records disagree on the count (K-05) | = G-05 |
| R-P18 light-client proof | 02-roadmap-gap | needs external proof | = G-08 |
| R-M1 residual: first sighting / no evidence reset | 02-roadmap-gap, CURRENT | still open | = G-04 |
| A6-14 runtime apt packages unpinned | 01-findings, Dockerfile | documentation-only (accepted) | — |
| A6-15 crate publish flag; tagging `0.3.0-beta` | 01-findings, FINAL | owner decision | — |
| A6-36 disclosure mailbox / private vulnerability reporting | 01-findings, CURRENT | owner action | `SECURITY.md:9` names a personal mailbox |
| Round 29 §5: risk engine, registry, protocol data, attack suites not break-tested | round29 report, FINAL | still open (an assurance gap, not a defect) | WS-F |
| Without RPC the Core does not refuse (H1 residual) | round29, CURRENT | still open | = G-01 |
| `BattleTested` does not reach verdicts; thin bar (M14) | round29, CURRENT | documentation-only | — |
| wSOL wrapping unsupported in the guard | CURRENT | documentation-only; refused through `CloseAccount` | WS-H (state it as a capability refusal) |
| R-4 vanity-source false positive | round29, CURRENT | documentation-only (measured trade-off) | — |
| L3 does not flag ≤ 50% deviation | CURRENT | documentation-only | = G-03 |
| "Without a witness the primary decides L8" | CURRENT | documentation-only | = G-08 |

## What the regression run showed

See `historical-regression-matrix.md` for every finding and every named test's result here. The
summary and the commands that produced the runs are in this workstream's report; no named test
of a fixed finding failed on `29e4356` unless the matrix says **REGRESSED**.
