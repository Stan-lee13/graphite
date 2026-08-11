# Phase 2 — Public Beta Development Branch

## Phase 2 Branch Rules (non-negotiable)

1. **ALL Phase 2 work happens on `phase2-development`.** Feature branches (`feature/*`) merge into `phase2-development`; no direct commits to `main`.
2. **No direct pushes to `main` during Phase 2.** `main` is frozen at the v0.1.0-alpha + Phase 1.5 state unless a critical hotfix (`hotfix/*`) is required.
3. **`main` only receives Phase 2 work via PR after Phase 2 certification** — i.e., all Phase 2 exit criteria met, tagged as `v0.2.0-beta`.
4. **Before starting work:** `git checkout phase2-development && git pull origin phase2-development`. If it is behind `main`, rebase: `git rebase main`.
5. **After committing:** `git push origin phase2-development` (never `main`).
6. **Every merge to `phase2-development` must pass the full Testing Discipline gate below** (fmt, clippy, all test suites, SDKs, benchmark) and keep all existing tests green.

## Branch Strategy

```
main (stable, releasable)
│
├── v0.1.0-alpha (tag) ← Frozen Phase 1 + 1.5 (commit 0991d01)
│
├── hotfix/*                    Critical fixes only, merged to main + phase2
│
└── phase2-development          This branch — integrates completed Phase 2 features
    │
    ├── feature/manifest-registry
    ├── feature/plugin-framework
    ├── feature/policy-engine
    ├── feature/dashboard
    ├── feature/protocol-expansion
    ├── feature/regression-engine
    └── feature/go-sdk-parity
```

## Rules

1. **main is always releasable.** Nothing merges to main unless it passes the same certification bar as Phase 1+1.5 (full test suite, security audit, benchmark, Evolution Mode sign-off).
2. **All Phase 2 work happens on feature/* branches**, merged into phase2-development via PR.
3. **hotfix/*** branches patch critical bugs on main, then cherry-pick into phase2-development.
4. **phase2-development merges to main only when all Phase 2 exit criteria are met**, tagged as v0.2.0-beta.

## Phase 2 Exit Criteria (from ROADMAP.md)

- [ ] Protocol Manifest Registry accepts real, signed community submissions
- [ ] Plugin framework has 2+ real third-party plugins running in production
- [ ] Policy Engine 4 preset profiles in active use (Treasury/TradingBot/Gaming/Enterprise)
- [ ] Regression Engine has 1,000+ real historical fixtures
- [ ] Dashboard shows live Semantic Graph state, confidence history, policy violations

## Backlog (non-blocking items from Phase 1.5 certification)

### Go SDK Parity (feature/go-sdk-parity) ✅ COMPLETE (commit 86a13f3)
Added 3 missing Go types that the TypeScript SDK already had:
- `ResolvedAccount` (with `pda_mismatch` field — SECURITY SIGNAL)
- `BuiltTransaction` (with nested `BuiltAccountMeta`)
- `VerificationBreakdownItem` (confidence breakdown per signal)

**Result:** All 16 fields in Rust `VerificationResult` now have matching Go types.
JSON deserialization no longer silently drops data. 9 tests (up from 7),
including roundtrip fidelity test proving no data loss.

### FakeSwap Detection Scope (minor)
`detect_fake_swap()` only covers 3 hardcoded swap program IDs (Jupiter, Orca, Meteora). Custom/untracked swap programs bypass this heuristic. Downstream Unknown Protocol Mode and UnexpectedCPI blocks act as fallback. Expand in Phase 2 with the Manifest Registry.

## Testing Discipline

Every feature merge to phase2-development must pass:
- `cargo test` (all features)
- `cargo clippy` (0 warnings)
- `cargo fmt --check`
- Go SDK tests (`go test ./...`)
- TypeScript SDK (`tsc --noEmit`)
- Python AI Layer (`pytest`)
- Benchmark (`cargo run --release --bin graphite benchmark`)
- No regressions in existing 984 tests
