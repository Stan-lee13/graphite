# Round 30 audit records

Evidence produced by the Round 30 ledger, architecture and history workstream against `29e4356`
(tree `0aeac5a`, 894 files). Generated files say so in their first lines and are rebuilt by the
scripts in `tools/`; nothing generated is edited by hand.

| File | What it is | How it is made |
|---|---|---|
| `file-ledger.json` | Every tracked file: size, SHA-256, git blob, classification, system, the checks applied, problems found, audit depth | `tools/build_ledger.py <repo> <commit> docs/audit-r30` |
| `file-ledger-summary.md` | Counts by depth, classification and system; machine-check problems; anything not inspected | same |
| `tools/read-log.tsv` | Files a reviewer read, in full or in named sections, with a note. Only this file can mark a file "read" | kept by hand; other workstreams append their own rows |
| `tools/executed.tsv` | Test files that ran on this commit, with the run's counts | `tools/executed_from_logs.py <repo> <logs> docs/audit-r30/tools/executed.tsv` |
| `historical-regression-matrix.{json,md}` | Every historical finding ID in the audit records, the tests its records name, and whether they ran and passed here | `tools/regression_matrix.py <repo> <logs> docs/audit-r30` |
| `historical-findings.md` | Reviewed dispositions: the twelve leads (G-01 … G-12) and every open, partial, limitation or owner item in the records | by hand, from the code at `29e4356` |
| `architecture.md` | The system reconstructed from the code: components, trust boundaries, the pipeline and the approval rule, every sign/send sink, L8, persistence, credentials, CI | by hand |
| `new-defects.md` | Defects this pass found and did not fix (K-01 …) | by hand |
| `findings-registry.md` | Every Round 30 finding (R30-*, K-*, the twelve leads) with severity, class, status, regression test, break record and residual; the before/after counts | by hand, at the end of the round |
| `tools/vacuous_tests.py` | Lists Rust tests whose body contains no assertion form | run on demand |

## Audit depth, as the ledger uses it

- **read-full / read-sections** — a person read the file (or the named line ranges) and wrote a row
  in `read-log.tsv`.
- **reviewed-historical** — a dated report read for its findings, not re-audited line by line.
- **executed** — a test file that ran on this commit (`executed.tsv`).
- **automatically-validated** — a strict parser, schema, count, uniqueness, provenance or header
  check ran over the whole file (every record of every JSON file, every lockfile entry).
- **scanned** — the source pattern triage ran (panics, unwraps, `unsafe`, `as any`, skips, TODOs,
  swallowed errors, CI masking, secret patterns) and its counts are recorded per file.
- **not-inspected** — none of the above. The target is zero.

A file can carry several methods; its depth is the strongest one. "Scanned" is not "read": the
summary keeps them apart so a reader can see how much was read by a person.

## Logs

The test logs behind `executed.tsv` and the matrix are not committed (they are hundreds of
thousands of lines). The commands that produced them, with their exit codes, are in the
workstream report.
