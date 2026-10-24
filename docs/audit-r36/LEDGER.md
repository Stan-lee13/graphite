# Round 36 file coverage ledger

This ledger covers base commit `214042762aa184d4994243b00d3674285dda41c5`, tree
`73a46bc71761f5493f6e3d497efd4aa9bb68d1c7`. It lists every tracked file and the
automated checks that ran on it. **It does not claim that any person or model
read any file.** Every record carries `"review": "not-claimed"`. A check named
in a record was run by `build_ledger.py` on the blob git holds for that path,
and no other check was run.

| File | What it is |
|---|---|
| `file-ledger.json` | One record per file: path, git blob, mode, size, sha256, line count, classification, kind, subsystem, `changed_since_r30_ledger`, `validation.{checks, results, problems}`, `review`. It also holds `aggregate`. |
| `scan-triage.json` | Every pattern hit with its line, its lexical context (code, comment or string), a disposition and the basis for that disposition. |
| `build_ledger.py` | The generator. It uses only the standard library and reads git objects, never the working tree. Regenerate with `python3 -I docs/audit-r36/build_ledger.py`. |

The generator ran twice and produced byte-identical output both times
(`file-ledger.json` sha256 `2eea694e…`, `scan-triage.json` sha256 `32d47f4d…`
at the time of writing). The Round 30 ledger (`docs/audit-r30/file-ledger.json`,
894 files) was not modified. This ledger is compared against it.

## Files

**1,082 files.** This count comes from both `git ls-tree -r` and `git ls-files`
at the commit. `git ls-files` is read through a throwaway index, so the state of
the caller's index does not affect it. The two listings have the same paths,
the same blobs and the same modes, and there are no non-blob entries. The
1,040 text files hold 2,193,757 lines in total. The other 42 files are binary.
All 1,040 text files are valid UTF-8. 1,030 of them use LF line endings and 10
contain no newline at all. No file uses CRLF.

Compared with the Round 30 ledger: **718 unchanged, 176 content-changed, 188 new**,
and 0 removed (718 + 176 = 894).

| Classification | Files | | Classification | Files |
|---|---:|---|---|---:|
| test | 244 | | ci | 30 |
| corpus/fixture data | 236 | | deployment | 20 |
| manifest | 152 | | config | 13 |
| generated | 121 | | lockfile | 12 |
| runtime-source | 96 | | asset/binary | 11 |
| historical-report | 60 | | schema | 4 |
| script | 48 | | documentation | 35 |

The `manifest` class holds three kinds of file: 137 protocol manifests, 2
protocol registry data files and 13 package manifests. `generated` holds 120
files under `graphite-core/scripts/out/` and one proptest-regressions file.
Thirteen paths have a classification set by an override in `OVERRIDES`
rather than by a path rule, and each override states its reason. Examples
are test-support TypeScript imported only by `*.test.ts`, hand-run harnesses
classed as `script`, and `src/durable/chain_trail_tests.rs`, which is
declared `#[cfg(test)] mod chain_trail_tests;`.

By subsystem: protocol-registry 139, regression-corpus 142, rust-core-tests 166,
protocol-data-generated 120, agent-guard 61, protocol-data-scripts 53,
fuzzing 52, docs 48, dashboard 46, ci-and-repo-policy 37, rust-core 35,
deploy-kit 20, sdk-typescript 19, sdk-go 18, audit-r30-record 15,
rust-core-test-fixtures 12, repo-root 12, solana-agent-kit-adapter 10, and
smaller groups listed in `aggregate.by_subsystem`.

## What ran

| Check | Files |
|---|---:|
| UTF-8 decode, line-ending scan, secret-pattern scan | 1,040 |
| strict JSON parse, rejecting duplicate keys and NaN/Infinity | 488 |
| JSONC parse (comments and trailing commas stripped by a string-aware stripper) | 2: `dashboard/tsconfig.json`, `sdk/typescript/tsconfig.build.json` |
| protocol-manifest schema check (keys, types, base58 program id, hex/even/unique discriminators, unique names, risk-class vocabulary) | 137, plus 5 fuzz-seed copies |
| regression-fixture check: keys and types; `content_hash` and `integrity_hash` **recomputed** with the algorithm in `regression_engine.rs`; duplicate and oversize scans | 141 corpus files |
| IDL shape (instruction names unique; `address` agrees with the file name) | 116 on-chain IDLs and 17 script IDLs |
| record counts and whole-record duplicate scans on other JSON data | every JSON array or listed collection |
| JSON-Schema shape (required ⊆ properties, recursively) | 4 |
| example top-level keys against the schema's `required` list (not a full JSON-Schema validation) | 6 |
| `tomllib` parse (a repeated key is a parse error) | 4 Cargo.toml + 4 Cargo.lock |
| npm lock: package count, integrity present, resolved host, install-script packages | 7 |
| Cargo.lock: package count, checksum on every registry package, git sources | 4 |
| pip lock: a hash on every pin | 1 |
| Python `ast.parse` | 47 |
| Rust lexer (comments, strings, raw strings, char literals) with a delimiter balance check | 208 |
| `#[cfg(test)]` / `#[test]` region scan | 35 `src` files |
| PNG signature, IHDR size and every chunk CRC; ICO directory; PDF header, `%%EOF` and active-content scan | 9 / 1 / 1 |
| systemd units read by `configparser`; dotenv KEY=VALUE format; TSV column counts; proptest-regressions format | 3 / 3 / 2 / 1 |
| markdown relative links resolved against the tree (203 links) | 90 |
| shebang present on every executable-mode file | 13 |

### What did NOT run

- **No manual line-by-line review of any file is claimed.** Nobody vouches for
  the code's behaviour. The scan-triage dispositions explain individual
  pattern hits. They do not review files.
- **YAML is not parsed.** The standard library has no YAML parser. All 13
  `.yml` files received only a line scan for tab indentation and repeated
  keys within one block mapping. Each is marked `yaml_not_parsed`.
- **166 files had lexical checks only**: 96 `.ts`, 13 `.tsx`, 16 `.go`, 12 `.sh`,
  4 `.mjs`, `.mts`, `.cjs`, CSS, HTML, the Dockerfile, the Caddyfile, `.gitignore`,
  `.allow` lists, CODEOWNERS, `allowed_signers`, LICENSE and two `.txt` files.
  No TypeScript, Go or shell parser ran on any of them.
- **37 fuzz seeds** have only their bytes recorded. A seed may be malformed on
  purpose. The 5 manifest-JSON seeds were parsed.
- No code was compiled or tested. `cargo`, `tsc`, `go vet` and the test suites
  did not run.
- JSON Schema was not run as a validator. Only the shape checks listed above
  ran.

## Protocol manifest census against docs/CURRENT.md

| Measure | Counted | CURRENT.md states | Match |
|---|---:|---:|---|
| protocol manifests | 137 | 137 ("137 manifests / 3,541 instructions"; Round 30 re-count) | yes |
| unique program ids | 137 (0 duplicates) | 137 | yes |
| instructions | 3,541 | 3,541 | yes |
| unclassed instructions (`risk_class == ""`) | 46 | 46 | yes |
| manifests declaring `BattleTested` | 113 (24 `OfficialManifest`) | 113 | yes |
| evidence records with a decode rate under 0.9 | 13 | 13 | yes |
| corpus fixtures (dev / regression / holdout) | 13,013 (12,943 / 32 / 38) | 13,013 (12,943 / 32 / 38) | yes |

Every number matches, and none differs from the docs. Other measurements:

- The manifests hold 26,351 account entries.
- Instructions by risk class: authority 1,342, transfer 1,011, create 482,
  withdraw 414, close 164, inert 49, mint 17, drain 9, stake 7, unclassed 46.
- `battle_tested_evidence.json` and `verified_program_ids.json` each list the
  same 137 program ids as the manifests.
- Every manifest file the evidence names exists.
- Every `declared_trust_tier` matches its manifest.

Corpus checks:

- Every one of the 13,013 fixtures recomputes both its `content_hash` and its
  `integrity_hash`.
- The scans found 0 duplicate hashes, 0 duplicate records, 0 malformed records
  and 0 oversized records. The largest record is 4,057 bytes and the threshold
  is 256 KiB.
- The 13,013 hashes in `meta/corpus_manifest.json` are exactly the corpus
  hashes.

## Problems the checks flagged (data observations, not defects established)

- **IDL `address` differs from the program id in the file name.** The IDL was
  fetched for one program and declares another:
  - `graphite-core/scripts/out/onchain_idls/61DFfeTKM7trxYcPQCM78bJ794ddZprZpAwAnLiwTpYH.json`
    declares `RderEngine111111111111111111111111111111112`.
  - `graphite-core/scripts/out/onchain_idls/cardWArqhdV5jeRXXjUti7cHAa4mj41Nj3Apc6RPZH2.json`
    declares `E7vM2tFMoHU49pqTgaoGDcCRAFGYs2w6rKPsRQJuukgA`.
- **Four corpus files have no manifest**: `3W2y8TuU…`, `8MjG72ZW…`, `9fhQBbum…`
  and `GaE1XtFQ…`. They appear in `aggregate.corpus.corpus_files_without_a_manifest`.
- **One empty discriminator in each of the three Memo manifests.** The Memo
  program has no instruction tag. This is recorded as a result, not flagged as
  a problem.

No check flagged anything else:

- duplicate JSON keys
- strict-parse failures outside the two JSONC files
- npm packages without integrity or resolved off registry.npmjs.org
- registry crates without a checksum, or git-sourced crates
- unhashed pip pins
- PNG CRC errors
- PDF active content
- broken relative markdown links
- secret-like strings
- executables without `#!`
- Rust files whose delimiters do not balance

Lockfiles: `graphite-core/Cargo.lock` 262 packages, `fuzz` 204,
`tools/runtime-oracle` 79, `tools/inner-instruction-oracle` 438; npm
`agent-guard` 157, `solana-agent-kit` 274, `mcp-server` 147, `vercel-ai` 63,
`sdk/typescript` 52, `dashboard` 99, `dashboard/e2e` 3;
`python-ai-layer/requirements-lock.txt` 6 hashed pins. `sdk/go/go.mod` has no
requirements, so the missing `go.sum` is expected.

## Scan triage

There are 1,899 hits. Five patterns have no hits at all: `todo!(`,
`unimplemented!(`, `continue-on-error` in workflows, Python test skips and
secret-like strings. The Rust keyword `unsafe` never appears in code. Its one
hit is the English word in a comment.

`.unwrap()` and `.expect(` occur 1,307 times in `graphite-core/src`. Of these,
1,285 are inside `#[cfg(test)]` or `#[test]` items, or inside
`chain_trail_tests.rs`. The other **22 are outside test code**, in these files:

| File | Hits outside test code |
|---|---:|
| `tx_artifact.rs` | 6 |
| `archive_index.rs` | 4 |
| `benchmark.rs` | 2 |
| `manifest_registry.rs` | 2 |
| `plugins/mod.rs` | 2 |
| `state_diff.rs` | 2 |
| `verification.rs` | 2 |
| `regression_engine.rs` | 1 |
| `server.rs` | 1 |

19 of the 22 have a stated basis:

- a slice whose width is computed from the line
- a `get(a..b)` or `take(n)` that returns exactly n bytes
- a peek-then-next
- a match that returns `Some`

`panic!(` outside test code occurs 4 times, and each has a cited basis.
`catch_unwind` is used for plugin panic isolation. The 14 `#[ignore]` attributes
in code are each checked against `.github/test-allowlists/rust-ignored.txt`,
and all 14 are listed there.

The words mock, fake, stub, demo and sample occur 293 times in runtime source
outside test code. A word-sense rule explains each one, for example:

- detector names such as `FakeSwap` and `FakeRewardsDrainer`
- the statistical sense of `sample`, as in `sample_count` and `MIN_SAMPLES`
- the committed mainnet sample
- `demote` and `demonstrated`
- 13 hits explained by reading their cited lines

None of these hits is placeholder data.

Dispositions that rest on reading the surrounding lines carry
`context-read:` and cite those lines. They come from the `CONTEXT` table in the
generator. Each entry is keyed by line number and by a substring of the line,
so an entry stops applying as soon as its line changes.

### needs-review (8)

| Where | Pattern | Why |
|---|---|---|
| `.github/workflows/live-mainnet.yml:170` | `set +e` | The seed step writes its exit status to `outputs.exit`, which nothing reads. The replay step sets `SEEDED` from `steps.seed.outcome` (line 200). The step's last command is an `echo`, so the outcome reads success even when seeding failed. |
| `graphite-core/src/benchmark.rs:104` | `.expect` | The call is `seed_simulation_baseline` with a literal baseline. It can return Err from `validate_baseline`, and this triage did not trace that path. This is the benchmark harness path, not the server. |
| `graphite-core/src/manifest_registry.rs:213` | `.expect` | `serde_json::to_value(ProtocolManifest)` cannot fail only if no nested type has a non-string map key or a failing `Serialize`. The type graph was not traced. |
| `graphite-core/src/regression_engine.rs:199` | `.expect` | The same question for `serde_json::to_string(VerificationInput)`. The code comment asserts it is infallible, but nothing here traced that. |
| `integrations/agent-guard/guard.ts:861` | `as any` | Any string the AI layer returns is asserted to the `intent_type` type without a check against the allowed set. |
| `integrations/agent-guard/guard.ts:996` | `as any` | The whole `VerificationInput` literal (lines 984–996) is asserted to `any`, so the compiler does not check its fields. |
| `integrations/agent-guard/guard.ts:1282` | `as any` | The grounded transfer intent class is asserted to `ProposedIntent.intent_type`. Nothing here showed that it always fits. |
| `integrations/agent-guard/guard.ts:1506` | `as any` | The same assertion for the grounded swap intent. |

## Note on the Round 30 ledger

`docs/audit-r30/tools/build_ledger.py` adds the method `scanned:doc-links` to
every markdown file but runs no link check. That method name therefore claims
a check that never ran. Its `read:*` depths come from a hand-kept
`read-log.tsv`. This ledger replaces both with checks that actually execute
(relative links resolved against the tree) and makes no reading claims.
