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
- [ ] `cargo test --release` passes (0 failures), and so do `--no-default-features --lib` and `--no-default-features --features cli`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes (0 warnings); `cargo fmt --all -- --check` clean
- [ ] SAK integration `npm test` passes and `npm run emit:corpus` shows no fixture drift (if TypeScript touched)
- [ ] A security fix carries its reproduction as a test, and the fix was reverted once to show the test fails without it
- [ ] No credential, RPC secret or key in source, fixtures, logs or this PR
- [ ] No new `unwrap()` or `panic!()` in hot path
- [ ] Constitution principles checked (P1-P16)
- [ ] No public performance claim without reproducible benchmark (P16)

## Test Evidence
```
# Paste test output here
```
