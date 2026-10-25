# Round 40 — assurance

Workstream `assurance` of Round 40, on `1ae2066` (Round 39). Internal engineering work, not an
independent audit and not a certification. Six decisions of the technical lead, implemented as
taken. Commits: the five `Round 40 (assurance)` commits on top of `1ae2066` (`git log 1ae2066..`).

## 1. The decisions and why

| # | Decision | What was done |
|---|---|---|
| 1 | Drive the shared conformance corpus (`examples/decisions/conformance.json`) through the HTTP server, the CLI and the dashboard (matrix invariants 3 and 11) | `graphite-core/tests/round40_surface_conformance.rs` (4 tests) and `dashboard/src/conformance.test.ts` (3 tests) |
| 2 | R39-SUPPLY-CHAIN-6: a pinned actionlint, failing on any finding | `ci.yml` ci-scripts job: actionlint 1.7.11 release binary, sha256-checked before it runs; listed in `.github/pinned-tools.json`; seeded-fault cases in `ci-scripts.test.sh` |
| 3 | D2-8: per-binary Rust floors | `.github/test-floors/rust-{default,cli,lib}.txt` at the counts of full local runs of each leg; passed as `test-count.sh`'s 5th argument in `ci.yml` |
| 4 | Run the guard on Windows | `ci.yml` job `agent-guard-windows` (in `ci-gate.needs`); `posix-only.ts` (reasoned skips); `guard-round40.test.ts` (the Windows branches); one test fixed for the host platform, one un-skipped |
| 5 | `publish = false` | `graphite-core/Cargo.toml`; `docs/ops/production-checklist.md` 10c marked decided; a ci-scripts check |
| 6 | F-015: re-shard the mutation job so a shard fits its step | `assurance.yml`: 44 shards → 90 (≤ 20 mutants each), a `Plan` step that lists the shard before the build and fails at once past 24, `--sharding slice` named; floors, suites and `mutation_floor.py` unchanged |

**How each surface consumes a verdict (read before testing it).** Neither the server nor the CLI
reads a verdict: each *builds* one from a `VerificationInput` and serialises it (axum `Json` in
`server.rs` `verify_handler`; `serde_json::to_string_pretty` in `cli.rs`), and the CLI maps it to an
exit status with `cli::verify_exit_code`. The dashboard reads neither: it reads
`/api/confidence-history` rows that the server writes from its own result (`AuditRecord` in
`verify_handler` → `confidence_history_handler`), and decides green in `figures.ts`
`verdictKind`/`verdictTone` after `shape.ts` `checkHistory`. So, per the brief's fallback, each
surface's narrowest deciding function is driven with every corpus vector, and the real binary
reproduces each of the corpus's four bases end to end.

## 2. Gap Hunter (before coding)

1. A corpus test of the CLI that re-implements `verify_exit_code` would only test itself → the
   expected status is stated from the corpus (`expect.rust == executable` ⇔ 0), not from the
   function.
2. The CLI binary can never exit 0 from `verify`/`explain` (no RPC attached) → the 0 path is held
   on the function over the corpus; the binary is held to 3 and 1, and the server (with a loopback
   RPC) produces the executable base.
3. The server's clamp of a weak `Custom` profile would turn every base into a policy refusal →
   `GRAPHITE_ALLOW_PERMISSIVE_PROFILES=1` (the operator's documented single-tenant switch), only
   in the test's own child processes (`env_clear`).
4. The dashboard trusts the row's `decision`/`executable`; a raw forged verdict's row looks
   executable → measured, reported (§6), and the server half pinned (the row's `executable` is the
   Core's rule on a real verdict).
5. `verdictKind` reads `approved` by truthiness → the shape check in front of it is what refuses
   `approved: 1`; pinned by a test and a break (B2).
6. actionlint findings depend on the shellcheck version on the runner → measured clean with
   shellcheck 0.9.0 (Ubuntu 24.04's package) and 0.11.0; pyflakes disabled by name (no
   `shell: python` step; an unpinned pyflakes would decide silently whether it ran).
7. A config file or `-ignore` could silence actionlint → the ci-scripts check refuses both.
8. A checksum checked after the binary runs is no check → the structure test requires the
   `sha256sum --check` before `tar -x` and before the run.
9. Floors files that list only what exists today miss a new security suite → ci-scripts fails
   when a file matching the security patterns is in no leg's floors file and not excused with a
   reason.
10. A floor of 0 holds nothing → refused by the structure check; a suite cfg'd out of a leg is a
    `# not in this leg: <binary> (<cfg>)` line instead.
11. Windows skips could hide failures → every platform skip goes through `posixOnly("why")`; the
    Windows job allows exactly `grep -c '{ skip: posixOnly('` skips and requires that many; a
    test refuses any other `skip:` form in the package.
12. A Windows symlink needs a privilege the runner may lack → the link tests use junctions
    (no privilege; Node reports them as links), so the refusal is exercised either way.
13. CRLF checkouts on Windows would break raw-text corpus vectors → `.gitattributes` already
    forces LF on every OS.
14. Re-sharding could change what is scored, or let a killed shard pass → floors, suites and
    `mutation_floor.py` untouched; its INCOMPLETE cases still pass in ci-scripts.
15. Mutant counts grow with the code (state_diff 1,004 → 1,015 since run 40083338181) → the
    `Plan` step lists the shard and fails in seconds past 24 instead of being killed at 330 min.
16. `publish = false` could break the SBOM or release build → `release.yml` runs `cargo build`
    and `cargo cyclonedx` only; no workflow or doc runs `cargo publish`.

## 3. Changes

### 3.1 Conformance corpus through the server, the CLI and the dashboard

`graphite-core/tests/round40_surface_conformance.rs` (new, `#![cfg(feature = "cli")]`; the server
parts `cfg(feature = "server")`):

- `the_cli_exit_status_decides_every_corpus_verdict_as_the_corpus_says` — every vector the Core
  reads (73 of 102) through `verify_exit_code`: exit 0 for exactly the 21 the corpus marks
  executable, 1 for 9 refusals, 3 for 43 non-executable approvals; 29 unreadable never reach it;
  23 readable vectors still *say* `executable_approved`/`executable: true` and exit 1 or 3.
- `the_server_and_cli_json_of_every_corpus_verdict_reads_back_to_the_same_decision` — each
  readable vector through axum's `Json(..).into_response()` (status 200, `application/json`) and
  the CLI's `to_string_pretty`: `decision`/`executable`/`approved` on the wire as held, the Core's
  rule and the exit status unchanged on the re-read body, and the output a fixed point.
- `real_binary::the_real_server_reproduces_each_corpus_base_on_the_wire_and_on_the_dashboard_row`
  — `graphite server` (child process, dev mode, loopback) against the loopback cluster
  `round30_decision_fixtures.rs` produced the bases with (clean → `executable_approved`, errored
  simulation → `blocked`, RPC error → `inconclusive`, no RPC → `analysis_only`); `POST /verify`
  matches each committed base on decision, executable, approved, risk, policy and residual codes,
  and the Core's rule on the body is the corpus's answer; `GET /api/confidence-history`'s row
  carries the same decision and binding and `executable == is_executable()`.
- `real_binary::the_real_cli_reproduces_the_bases_it_can_produce_with_the_documented_exit_status`
  — `graphite verify` and `graphite explain` on the base's request: `analysis_only`, exit 3;
  under `Treasury`, `blocked`, exit 1.

`dashboard/src/conformance.test.ts` (new; the dashboard runs node:test under tsx, not vitest — the
repository's runner, so the CI job's TAP count reads it):

- every corpus vector → the row the server writes for it → `checkHistory` → `verdictKind` →
  `verdictTone`: green exactly when the row says approved, bound, `executable_approved`,
  `executable: true`; every corpus-executable vector green; every vector green but not
  corpus-executable carries exactly the executable base's row in those fields;
- each base's row drawn as the Core decided (executable / analysis / inconclusive / refused);
- rows that disagree with themselves are never green (executable false/absent/null, other
  decision strings and case, not approved, unbound, empty digest, `approved: 1`, `"true"`).

### 3.2 actionlint (R39-SUPPLY-CHAIN-6)

- `.github/workflows/ci.yml` ci-scripts: step "actionlint (pinned) over every workflow":
  `ACTIONLINT_VERSION: 1.7.11`, `ACTIONLINT_SHA256: 900919a8…1b0a` (the
  `actionlint_1.7.11_linux_amd64.tar.gz` digest; downloaded here and checked against both the
  release's `checksums.txt` and a local `sha256sum`), `sha256sum --check --strict` before
  unpacking, then `actionlint -shellcheck "$(command -v shellcheck)" -pyflakes ""` over every
  workflow; exports `ACTIONLINT` for the scripts' tests.
- `.github/pinned-tools.json`: `actionlint` 1.7.11 with `pinned_in` and `consistent` rules.
- `ci-scripts.test.sh`: the step's structure (pinned version and checksum, check before run,
  no `-ignore`/`-config-file`, no `.github/actionlint.y*ml`, before the tests); with
  `$ACTIONLINT`: the binary is 1.7.11, the committed workflows are clean, a seeded unknown
  `needs:` job is reported, a seeded unquoted `$VAR` in a `run:` block is reported, and its
  quoted control is clean. Locally without `$ACTIONLINT` these five say SKIP and are not counted;
  in GitHub Actions a missing `$ACTIONLINT` is a failure.

### 3.3 Per-binary Rust floors (D2-8)

- `.github/test-floors/rust-default.txt` (38 binaries), `rust-cli.txt`, `rust-lib.txt`
  (`unittests src/lib.rs`), at the counts of §7's runs. The security set: `round3*`, `round4*`,
  `ai_layer_isolation`, `docs_*`, `*exploit*`, `*attack*`, `mainnet_conformance`,
  `regression_corpus`, plus `unittests src/lib.rs`.
- `ci.yml` rust-test: `test-count.sh cargo … "../.github/test-floors/rust-$LEG.txt"`.
- `ci-scripts.test.sh`: the 5th argument is passed; each leg's file exists, parses, floors are ≥ 1,
  names only existing suites, floors the library, and lists (or, outside `default`, excuses with
  its cfg) every security suite.

### 3.4 The guard on Windows (R39-CLIENTS-6, G2-6)

- `ci.yml` job `agent-guard-windows` (`windows-2025`: a pinned image per the repository's A6-08
  rule rather than the moving `windows-latest`; checkout and setup-node at the SHAs every other
  job uses; Node 22.23.3): `npm ci --ignore-scripts`, `npm run typecheck`, `npm test` read by
  `test-count.sh tap … 345 <posixOnly uses>` and an exact skipped == marked check. Added to
  `ci-gate.needs`.
- `integrations/agent-guard/posix-only.ts`: `posixOnly(why)` — the reason on Windows, `false`
  elsewhere.
- Skips made reasoned (3): `wallet-lock-integrity` "lock dir: … not private" (mode 0755, foreign
  uid), `guard-round39` R39-CLIENTS-6 repro and control (chmod modes). Before: a bare
  `skip: process.platform === "win32"`.
- Un-skipped (1): `guard-round39` "crash: a guard SIGKILLed mid-submission …" — it needs no mode
  or uid; a killed process's locks and state file are what the Windows run is for.
- Fixed for the host (1): `guard-round38` R37-17 expected the POSIX default lock directory on
  every host; on Windows it is `<home>\AppData\Local\graphite-guard`.
- `guard-round40.test.ts` (5 tests, every platform): a junction or a file as the lock directory
  refuses and nothing is written through it; owner/access checked on POSIX and not on Windows,
  with the startup line saying so; a directory or a junction as the state file refuses, a regular
  file opens and re-opens; the state directory's owner checked on POSIX only; no bare platform
  skip in the package.
- `README.md` of the guard: the Windows paragraph names the job and the tests.

### 3.5 `publish = false`

`graphite-core/Cargo.toml`: `publish = false` with its reason (before: a comment saying it was the
owner's decision). `docs/ops/production-checklist.md` 10c: decided. `release.yml` never runs
`cargo publish` (it runs `cargo build` and `cargo cyclonedx`), nor does any workflow or document.
ci-scripts check: `package.publish is False` and no workflow says `cargo publish`.

### 3.6 Mutation shards (F-015)

From `docs/audit-r36/mutation-run-40083338181.md`: 6 to 9 minutes per mutant (one rebuild each,
`--in-place`), about 35 mutants fitting the 330-minute step, so its baseline was about 15 minutes;
shards of ~41 mutants; 18 of 44 killed. cargo-mutants 27.1.0's flags were read from the pinned
binary's `--help` (installed here): `--sharding slice|round-robin` (slice the default), `--list`,
`--shard`, `--baseline`, `--build-timeout`, `--profile`, `-j`.

- Mutant counts now (`cargo mutants --list --file`): risk_engine 235, simulation_integrity 199,
  tx_artifact 324, state_diff 1,015.
- Shards: 12 / 10 / 17 / 51 = 90 jobs, ceil(count/shards) = 20 each (checked with
  `--list --shard K/N --sharding slice`: e.g. state_diff 0/51 = 20, 50/51 = 15). Worst case
  15 + 20 × 9 = 195 of 330 minutes (135 to spare).
- `Plan (the shard fits the step)`: `cargo mutants --list --file F --shard K/N --sharding slice |
  wc -l`, before any build; fails at once for 0 or more than 24 (15 + 24 × 9 = 231 minutes).
- `Mutate`: `--sharding slice` named (the default at 27.1.0), so Plan and Mutate cannot split the
  file differently. `--in-place`, `--timeout 300`, the 330-minute step, the suites, the floors
  (0.90 / 0.60 / 0.60 / 0.60) and `mutation_floor.py` (counts from `mutants.json`, requires
  `end_time`) unchanged.
- Not used, deliberately: `--baseline skip` (a failing baseline would then score every mutant
  caught); `-j` (needs copies of the tree, not measured on a hosted runner); `--profile`
  (changes the code the tests run against; not measured).
- ci-scripts check: shards 0..N−1 once each per file, ≤ 256 jobs, Plan before Mutate, the same
  slicing, the cap ≤ 24, the Mutate limits and the floors unchanged, the floor step still runs.

**How to dispatch it (not dispatched here).** Actions → *Assurance* → *Run workflow* on the branch,
or `gh workflow run assurance.yml --ref <branch>`. `workflow_dispatch` runs all three jobs: the
fuzz long runs (6 × ~35 min), the coverage floor (≤ 120 min) and the 90 mutation shards. Each
shard: ~5 min to install cargo-mutants, ~15 min baseline, 20 (or fewer) × 6–9 min ⇒ about 2½ to
3½ hours. Runner time ≈ 1,773 mutants × 6–9 min + 90 × ~20 min ≈ 210–290 runner-hours. Wall
clock depends on the account's concurrent-job limit: at 20 concurrent jobs, 4½ waves ≈ 11–16
hours; at 40, about 6–8. A shard that still does not finish says INCOMPLETE and fails.

## 4. Deliberate breaks (copies outside the worktree, each deleted afterwards)

| # | Break (copy) | Tests that failed |
|---|---|---|
| B1 | `dashboard/src/figures.ts` `verdictKind`: green when `decision == executable_approved` **or** `executable == true` | conformance tests 1 and 3 (8 vectors named, e.g. "analysis_only with executable true") |
| B2 | `dashboard/src/shape.ts` `checkHistory`: `approved` no longer required boolean | conformance tests 1 and 3 ("approved as the number 1" drawn green) |
| B3 | `guard-state.ts` `assertPrivateDirectory`: `lstatSync` → `statSync` (follow the link) | `guard-round40` test 1 |
| B4 | `guard-state.ts` `assertPrivateStateLocation`: the file `lstatSync` → `statSync` | `guard-round40` test 3 |
| B5 | `assertPrivateDirectory` without its `win32` early return | not runnable here: only a Windows run takes that branch (test 2 there) — BLOCKED locally |
| B6 | `cli.rs` `verify_exit_code`: `ExecutableApproved => 0` without `if result.is_executable()` | `the_cli_exit_status_decides_every_corpus_verdict…`: 25 vectors exit 0 while not executable |
| B7 | `server.rs` `verify_handler` row: `executable: Some(result.approved)` (the pre-Round-30 reading) | `the_real_server_reproduces_each_corpus_base…`: "analysis_only: the row's executable is the Core's rule" |
| B8 | a default-leg log with `round39_decision_campaigns` 18 → 17 and the lib 734 → 735 | sum floor passes (2,468 ≥ 2,464); with the floors file: "17 passed, below its floor of 18" |
| B9 | seeded actionlint faults (ci-scripts cases) | unknown `needs:` job and unquoted `$VAR` reported (exit 1); controls clean |

## 5. Constitution check on the diff

- P1, P2, P4–P11: untouched (no decision code changed; only tests, CI, packaging).
- P3: no explanation field removed; the new tests assert `decision`/`executable` reach every wire.
- P9: the dashboard row's `executable` is now held to the Core's rule on a real verdict (B7).
- P12: unchanged; the Windows job and floors fail closed (a missing or shrunk suite, an unmarked
  skip, an unpinned or unverified linter all fail).
- P13: `publish = false` changes no API; a pre-existing `cargo publish` path is closed, recorded in
  the checklist.
- P14: two test skips changed form (bare → reasoned) and one skip removed; no check weakened. The
  Windows owner/access limitation (G2-6) stays a documented limitation, now executed.
- P16: no performance claim. The mutation-time estimate is arithmetic on a recorded run, stated
  as such; no score is claimed.

## 6. Verification

- **Backward compatibility:** no runtime code changed. `publish = false` only refuses `cargo
  publish`. The guard's tests on Linux are unchanged in outcome (348 pass, 0 skipped).
- **Security:** every new gate fails closed; no allowlist, floor or check lowered; the ci.yml
  numeric floors are untouched (§9 lists the ones that may now rise).
- **Explainability:** each skip on Windows prints its reason; the Plan step names the file to
  re-shard; floors files say where their numbers come from.
- **Hidden assumptions:** (a) the dashboard decides on two row fields it trusts — fed raw corpus
  verdicts, 41 vectors that are not executable to the Core (19 of them unreadable to it) would be
  green because what removes their permission (a residual, a failed layer, a refusal, a malformed
  field) is not on the row. The server never writes such a row from a verdict it built (B7's
  test); a row edited on the trail is the trail's integrity (invariant 9: MAC'd when keyed;
  an unkeyed trail can be rewritten anyway). Recorded, not changed. (b) `verdictKind` reads
  `approved` by truthiness; `checkHistory` in front of it refuses a non-boolean (B2). (c) the
  Windows job's first execution will be its first PR run.
- **Architecture conflict:** none. The Windows job is a new required job; the per-binary floors
  use the mechanism `test-count.sh` already had.

## 7. Commands run and counts

| Command | Result |
|---|---|
| `cargo test --locked --profile ci-test --no-fail-fast -j 2` (default leg) | 2,468 passed over 180 binaries, 0 failed (sum floor 2,464); +4 from `round40_surface_conformance` |
| `cargo test --locked --profile ci-test --no-fail-fast --no-default-features --features cli` | 1,981 passed over 180 binaries, 0 failed (sum floor 1,980); +1 (`round40` test 1; the rest is server-gated) |
| `cargo test --locked --profile ci-test --no-fail-fast --no-default-features --lib` | 530 passed (sum floor 530) |
| `test-count.sh cargo … rust-$LEG.txt` on each leg's log | default 38 binaries, cli 26 (12 named as not in this leg: cfg rpc/server), lib 1: all at their floors |
| `cargo clippy --locked --all-targets --all-features -- -D warnings`; `… --all-targets --no-default-features --features cli` | clean (both) |
| `cargo fmt --all -- --check` | clean |
| agent guard `npm run typecheck`; `npm test` (TAP) | typecheck clean; 348 tests, 348 pass, 0 skipped (was 343) |
| dashboard `npm test` (TAP) | 51 tests, 51 pass (was 48); `npm run typecheck` clean |
| `ACTIONLINT=<1.7.11> bash .github/scripts/ci-scripts.test.sh` | 131 passed, 0 failed (121 before) |
| `bash .github/scripts/ci-scripts.test.sh` (no `$ACTIONLINT`) | 126 passed, 0 failed; the 5 binary-dependent actionlint cases SKIP (not counted) |
| `bash .github/scripts/release-gate.test.sh` | 52 passed, 0 failed |
| `actionlint 1.7.11 -shellcheck <0.9.0 / 0.11.0> -pyflakes ""` over every workflow | clean with both shellcheck versions |
| `python3 -I .github/scripts/pinned-tools.py check-pins` | all 12 pins where the list says |
| `cargo mutants --list --file …` (27.1.0) | 235 / 199 / 324 / 1,015; per-shard maxima 20 |

## 8. Pinned outputs moved

None. No verdict hash, census, corpus or fixture changed (`git status` after every Rust leg showed
only this workstream's files). New pinned values, each with its source: the actionlint version and
digest (the release asset), the per-binary floors (the runs above), the 90-shard matrix (the
`--list` counts above).

## 9. BLOCKED, and what remains open

- **BLOCKED — Windows.** No Windows host here. `agent-guard-windows` has never run; B5 could not
  be run. Command to obtain it: open the PR (the job runs in CI). Risk areas if it fails on its
  first run, in order of likelihood: the 1,000-round two-process lock race and the 12,000-symlink
  temp-name test (`wallet-lock-integrity.test.ts`; Windows delete-pending and symlink privilege
  semantics), the un-skipped crash test, `npm test`'s `*.test.ts` glob reaching Node unexpanded
  through cmd.exe (Node 22 expands it). A failure there is evidence, and turns the CI gate red
  until it is understood; it must not be answered by a new skip without a reason.
- **BLOCKED — the actionlint step on a hosted runner.** The binary was downloaded and verified
  here, and runs clean; the step itself first runs in the PR's CI.
- **Mutation scores (F-015)** are still not measured: the re-sharded job has not been dispatched
  (§3.6 says how). No floor was raised.
- **Weekly pinned-tools report**: actionlint 1.7.12 exists upstream (a local source build reports
  v1.7.12), so `pinned-tools.yml` will report the 1.7.11 pin as behind until it is re-checked and
  bumped (the lead's decision was 1.7.11, the version measured clean).
- **The dashboard trusts the row** (§6 a). A console that recomputed executability would need the
  residuals on the row; not in this scope.
- **Floors in `ci.yml` that may rise** (main session's): ci-scripts 121 → 131 in CI (with
  `$ACTIONLINT`; 126 locally without), agent guard 343 → 348, dashboard 48 → 51, Rust sums
  default 2,464 → 2,468, cli 1,980 → 1,981 (lib 530 unchanged). None is required: each is a
  minimum, and the new tests already sit above it.
- `docs/audit/EXHAUSTIVE_FILE_INVENTORY.csv` does not list the new files (not enforced by CI).
