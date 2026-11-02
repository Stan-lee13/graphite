## Summary
Brief description of what this PR changes.

## Type
- [ ] Bug fix
- [ ] New protocol manifest
- [ ] Security improvement
- [ ] SDK / integration
- [ ] Documentation
- [ ] Performance

## Verification Checklist
- [ ] `cargo test --profile ci-test` (what CI runs: the release profile without LTO) or `cargo test --release` passes (0 failures), and so do `--no-default-features --lib` and `--no-default-features --features cli`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes (0 warnings); `cargo fmt --all -- --check` clean
- [ ] If TypeScript was touched: the agent guard's `npm test` passes and `npm run emit:artifact-fixture` + `npm run emit:corpus` show no fixture drift; the adapters (`vercel-ai`, `mcp-server`, `solana-agent-kit`) and the TypeScript SDK pass `npm test`
- [ ] A security fix carries its reproduction as a test that fails on the code before the fix (written first, or the fix reverted once to show it)
- [ ] No credential, RPC secret or key in source, fixtures, logs or this PR
- [ ] No new `unwrap()` or `panic!()` in hot path
- [ ] No test newly ignored or skipped unless listed in `.github/test-allowlists/` with a reason; no test floor in `ci.yml` or `.github/test-floors/` lowered without saying why; a new security suite has its line in `.github/test-floors/`
- [ ] Constitution principles checked (P1-P16)
- [ ] No public performance claim without reproducible benchmark (P16)
- [ ] If a protocol manifest was added or changed: it is listed in `SEED_MANIFESTS`, in
      `protocols/verified_program_ids.json` and in the Python cross-check map; a mainnet
      measurement is on record (`scripts/battle_tested_census.py`); `trust_tier` is
      `OfficialManifest` unless that measurement supports more; and
      `scripts/render_coverage.py` was re-run

## Test Evidence
```
# Paste test output here
```
