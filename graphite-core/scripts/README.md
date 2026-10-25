# graphite-core/scripts

Operator and onboarding tools. None of them runs in the server or in a verdict.

## Which RPC tools see version-1 transactions

Version-1 transactions are live on mainnet (about 17% of the 2026-09-23 sample), and an RPC
asked for `maxSupportedTransactionVersion: 0` refuses each one with an error instead of
returning it. A tool that asks for version 0 therefore measures a sample with v1 removed.

| Tool | Requests | Notes |
|---|---|---|
| `battle_tested_census.py` | version 1 | feeds the BattleTested evidence gate |
| `solana_inventory_census.py` | version 1 | ranks programs by real usage |
| `../../tools/mainnet-sample/fetch_mainnet.py` | version 1 | the mainnet conformance samples |
| `analyze_squads_tx.py`, `census_drift_kamino.py`, `census_metaplex.py`, `census_orca.py`, `fetch_discriminators.py`, `fetch_real_fixtures.py`, `live_revalidate.py`, `probe_dca_pda.py`, `verify_dk_pdas.py` | version 0 | one-off onboarding and census scripts; they read the `json` encoding, whose shape for v1 they do not parse. Their outputs exclude v1 transactions. |

The two TypeScript tools in `integrations/agent-guard` that fetch transactions
(`mainnet-benchmark.ts`, `build_exploit_corpus.mts`) request version 1 since R-P8 phase 4
(2026-10-02): `@solana/web3.js` 1.99 decodes v1 messages (`MessageV1`, with its
`transactionConfig`), checked live against mainnet transaction
`4mQher7pk669NTK78w8Zu4FD8fdWucUTDTL15DbajdkHNZTtRi3zaRF3FBuavQ73FfZvTD3Yy9e7n1YwUQ2Cxx5x`
(slot 449,808,725). Each reports how many v1 transactions it read, and
`env-names.test.ts` fails if either goes back to version 0.

**Rule:** a number that is published, or that gates anything, comes from a tool that requests
version 1. A version-0 tool may be used for onboarding a manifest, where its output is reviewed
by hand, but not to measure traffic.

## Editing shipped manifests (offline, no network)

These rewrite `protocols/*.json` in place through `manifest_json.py`, which keeps each
file's exact layout. They are idempotent, and each has a `--check` mode that changes
nothing and exits 1 when the tree is stale.

| Tool | What it does |
|---|---|
| `reclassify_manifests.py` | Re-applies the risk-class rules of `idl_to_manifest.classify()`/`refine()` (Round 29: authority before swap) to the shipped manifests, never lowering a class, plus the reviewed hand overrides it lists with `--list-overrides`. |
| `recompute_evidence.py` | Recomputes each `battle_tested_evidence.json` record's derived fields (names, decode rate, `meets_battle_tested`, `declared_trust_tier`) from its stored observations against the current manifests. `tests/battle_tested_evidence.rs` fails when a record is stale. |
| `apply_idl_optional_flags.py` | Marks the accounts a program's committed IDL declares optional as `optional` in its manifest (no `--check`; it reports what it marked). |

`build_manifests.py` (one level up) refuses to overwrite an existing manifest unless
`--force` is given.

## Rendering the coverage page

`render_coverage.py` writes `docs/protocol-coverage.md` from the manifests,
`protocols/battle_tested_evidence.json`, the program census in `out/` and the recorded
full-pipeline figures in `out/mainnet_sample_named.json`. Since Round 29 no figure in it is
a literal in the script and the page carries no render date, so the same inputs give the
same bytes; `tests/docs_match_the_registry.rs` compares its table with the loaded registry.
Two sentences on the page come from those data files and are known to be off — the
sample's registry is recorded as 131 manifests (`tools/mainnet-sample/README.md` says 129),
and the "transaction versions in the same sample" line is the 80-block census's — and
`docs/CURRENT.md` states the correct figures.

`fetch_onchain_idls.py` fetches a program's own on-chain Anchor IDL. The older
`fetch_idl.py` and its `verified_idls.json` output were removed in Round 29: the script
derived the IDL address with a wrong on-curve test and its output was empty.

## Assurance (Round 30)

| Tool | What it does |
|---|---|
| `mutation_floor.py` | Reads the outcomes file a `cargo mutants` run writes and fails below a mutation-score floor (caught + timeout over tested; unviable excluded; an empty run fails). The weekly job in `.github/workflows/assurance.yml` runs it. |
| `../fuzz/make_seeds.py` | Regenerates the committed fuzz seed corpora in `fuzz/seeds/` from the committed mainnet blocks, the shipped manifests and hand-built valid layouts. |

## Corpus validation (Round 39)

`validate_corpora.py` reads every JSON file the repository tracks with the right parser
(`tsconfig*.json` as JSONC) and checks, offline, what the corpora's consumers rely on: one
manifest per program and every one in `SEED_MANIFESTS` and `verified_program_ids.json`; base58
keys, hex discriminators without prefix collisions, the PDA seed grammar, the closed risk-class
and trust-tier vocabularies; evidence records equal to their own counts and a declared
BattleTested tier only with a record that meets it; each IDL's discriminators and slot counts
against its manifest; the regression corpus against its meta manifest (provenance included);
the artifacts' provenance labels and transaction versions read from their bytes; and the
medium-confidence declaration rewrites, listed and never promoted. It prints what the fixtures
cover, which is not a gate, and pins the known gaps (the 13 records under the decode bar, the 75
slot-count differences, the 9 medium rewrites) so that a change to one fails until it is looked
at. `ci-scripts.test.sh` runs it and seeds a fault per check. The schema section needs the
`jsonschema` package; without it the section is BLOCKED (exit 3), never passed.

The release evaluation is not a script: `graphite benchmark --json` (`src/release_eval.rs`)
scores every committed labelled input per split, and `tests/release_evaluation.rs` pins it.
