# Contributing to Graphite

Graphite is a transaction verification engine for Solana AI agents. Every contribution must maintain the security and honesty guarantees defined in the [Constitution](https://github.com/Stan-lee13/graphite-engineering-skill/blob/main/CONSTITUTION.md).

## Before You Contribute

1. Read the [Architecture Specification](ARCHITECTURE.md) — understand the 8-layer pipeline and subsystem design
2. Read the [Roadmap](ROADMAP.md) — understand what's in scope for the current phase
3. Check the [Engineering Skill](https://github.com/Stan-lee13/graphite-engineering-skill) — the canonical source for layer names, personas, and checklists

## Branch Rules

- `main` is the integration branch. Every commit on it must have a green GitHub Actions run — the run for the exact SHA, read from the Actions runs endpoint, not a commit message claiming it.
- Branch protection is not yet enabled (owner decision, tracked in `ROADMAP.md`), so the CI gate is a discipline rather than a mechanism today. Treat it as mandatory anyway: a red run is fixed before anything else lands.
- Security fixes ship with a reproduction test, and the fix is reverted once locally to show that test fails without it. Record the result in the round report under `docs/`.
- Historical phase branches (`phase2-development`) are closed; do not target them.

## Development Setup

```bash
# Clone
git clone https://github.com/Stan-lee13/graphite.git
cd graphite

# Rust core
cd graphite-core
cargo build --release
cargo test --release
cargo clippy --release -- -D warnings

# Python AI layer
cd ../python-ai-layer
python3 -m pytest test_intent_parser.py

# TypeScript SDK
cd ../sdk/typescript
npm ci && npm run build && npm test

# SAK integration (the execution boundary) — also regenerates the cross-language corpus
cd ../../integrations/solana-agent-kit
npm ci && npm run typecheck && npm test && npm run emit:corpus
git diff --exit-code -- ../../graphite-core/fixtures/artifacts/   # CI fails on drift

# Run the server locally without a key (loopback only)
cd ../../graphite-core
GRAPHITE_DEV_MODE=1 cargo run --release --bin graphite -- server
```

## Constitution Principles (Non-Negotiable)

Every PR must satisfy all 16 Constitution principles. The most commonly violated:

- **P1**: AI assists, never decides. No LLM output is the final authority on a transaction's safety.
- **P2**: Deterministic verification. Same inputs → same outputs. No timestamps, random numbers, or non-deterministic operations in the verification path.
- **P6**: Unknown protocol confidence cap (0.55). No evidence can override this.
- **P12**: Fail-closed on unknown. Unknown instructions on known protocols return BLOCKED, not an error. Anything Graphite cannot observe is disclosed in `scope.unobserved`, never assumed.
- **P5**: Simulation is evidence, not truth. RPC-derived values come only from canonical response fields and can lower or fail a verdict, never manufacture one.
- **P9**: The audit trail is append-only and synced before the response; a verdict that cannot be recorded is refused.
- **P16**: No public performance claim without a linked, reproducible benchmark run backing the exact number.

## PR Checklist

Every commit to `main` must pass the full CI gate (`.github/workflows/ci.yml`), which runs on every push:

- [ ] `cargo fmt --all -- --check` clean (0 diffs)
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes (0 warnings)
- [ ] `cargo test --release` passes (0 failures — currently 1,562 tests, 12 ignored; `--include-ignored` for the live RPC corpus)
- [ ] `cargo test --release --no-default-features --lib` (320) and `--no-default-features --features cli` (1,366) pass — the feature matrix is tested, not just checked
- [ ] `cargo audit --deny warnings` clean
- [ ] Container builds, boots, `/health` answers, `/data` is writable, unauthenticated `/verify` is `401`, and a keyless container refuses to start
- [ ] TypeScript SDK `npm run build` + `npm test`; SAK integration `npm run typecheck` + `npm test` (100) and the regenerated artifact fixture + corpus show no diff
- [ ] Go SDK `gofmt` / `go vet` / `go test ./...` pass
- [ ] Python AI layer `pytest` passes (27)
- [ ] Dashboard `npm run typecheck` + `npm run build`
- [ ] No new `unwrap()` or `panic!()` in the verification hot path
- [ ] Constitution principles checked (P1-P16)
- [ ] No public performance claim without reproducible benchmark (P16)
- [ ] Layer names match `graphite-engineering-skill/ARCHITECTURE.md` section 3.12
- [ ] Test count and metrics updated in README.md, `docs/CURRENT.md` and the round report if changed
- [ ] A security fix carries its reproduction as a test and a deliberate-break note (fix reverted → test fails)
- [ ] No new credential, RPC URL or key in source, fixtures, logs or reports; no attack against a public RPC — mock it on loopback

## Adding a Protocol Manifest

A manifest describes one program's instruction surface. It is a trust anchor:
once a program has one, Graphite judges its transactions against the manifest
instead of falling back to Unknown Protocol Mode. So the manifest must come
from the program, not from a guess about it.

**The instruction surface must have an authoritative source.** In order of
preference:

1. **The program's own on-chain Anchor IDL** — the account at
   `create_with_seed(find_program_address([], program), "anchor:idl", program)`,
   owned by the program itself. `scripts/fetch_onchain_idls.py` pulls it and
   `scripts/onboard_from_inventory.py` turns it into a manifest. This is how
   the 49 programs onboarded in Round 18 were built.
2. **The protocol's published IDL or program source**, with discriminators
   derived the way the program's own generated client derives them
   (`sha256("global:" + snake_case(name))[0..8]` for Anchor, the borsh variant
   index for a native program) and then **confirmed against real mainnet
   transactions** — see `scripts/census_drift_kamino.py` for the pattern.

Do not hand-write account lists from documentation. Do not invent PDA seed
templates: ground a PDA **only** where the deployed program actually
seed-constrains it, because a wrong template flags legitimate transactions
(the C26 failure mode, which caught two near-misses in C27 alone).

**Then:**

1. Put the file in `graphite-core/protocols/` and add its name to
   `SEED_MANIFESTS` in `manifest.rs`. The list is checked against the
   directory in both directions
   (`manifest::tests::test_every_protocol_file_is_a_seed_manifest`), so a file
   that is never loaded fails CI.
2. Add the program to `protocols/verified_program_ids.json` with provenance
   that says how the ID was confirmed executable on mainnet. The count is
   derived from `SEED_MANIFESTS`, and the two are compared by name and ID in
   both Rust and the Python AI layer.
3. Add the file to the manifest map in
   `python-ai-layer/test_intent_parser.py`.
4. Run `scripts/battle_tested_census.py <program_id> --merge` and commit the
   measurement. **Every seed manifest must have a record**
   (`tests/battle_tested_evidence.rs`), whatever the record says.
5. Regenerate the coverage page: `scripts/render_coverage.py`.
   `tests/docs_match_the_registry.rs` compares it to the loaded registry.

**Trust tier.** Write `OfficialManifest`. A manifest does not get to award
itself the top tier: the loader lowers a declared `BattleTested` to
`OfficialManifest` unless the measurement in
`protocols/battle_tested_evidence.json` shows the program is executable, that
at least 1,000 successful transactions invoked it over a stated window, and
that the manifest names at least 90% of the instructions actually observed on
chain. Write `BattleTested` only once the census says you may — and note that
the tier is a statement about **usage and description accuracy, not safety**.
A heavily used malicious program would clear the bar; what protects against it
is L4, L5 and L7, which run the same way at every tier.

**Trusted-CPI status is separate and is not granted by onboarding.**
`TRUSTED_COMPOSABILITY_PROGRAMS` in `risk_engine.rs` (aliased as
`TRUSTED_CPI_ROOTS` / `DEX_PROGRAMS`) *relaxes* CPI checks, so it stays
hand-curated: add a program there only with a deliberate argument for why its
CPI surface can be trusted wholesale. Declaring the CPI targets per
instruction in the manifest's `allowed_cpis` is the normal mechanism, and it
is the one a new protocol should use. Tagging `"category": "swap"`, by
contrast, makes Graphite *stricter* (FakeSwap), and `is_swap_program` now
reads that tag straight from the manifests, so there is no second list to
update.

## Reporting Issues

Use the appropriate issue template:
- [Bug Report](.github/ISSUE_TEMPLATE/bug_report.md)
- [Protocol Manifest Request](.github/ISSUE_TEMPLATE/protocol_manifest.md)
- [Security Report](.github/ISSUE_TEMPLATE/security_report.md) — or see [SECURITY.md](SECURITY.md) for private disclosure
