# Adversarial Hardening Campaign — 2026-09-06

Engineering record for the Docker-based adversarial pass against Graphite.
Every number here was measured on this machine on the date shown; nothing is
carried over from a prior report. Where something was not tested, it says so.

**This is an internal AI-agent engineering pass. It is not a third-party
security audit and must not be described as one.**

---

## 1. Environment actually used

| | |
|---|---|
| Container | `graphite-main-graphite-1`, image `graphite-main-graphite` |
| Runtime hardening | uid 10001, read-only rootfs, `cap_drop: ALL`, `no-new-privileges`, pids 256, 512 MB, 2 CPU |
| Exposure | `127.0.0.1:7331` only |
| Config | `GRAPHITE_API_KEY` set, `GRAPHITE_RATE_LIMIT=30`, `GRAPHITE_CORS_ORIGINS=` empty, **`GRAPHITE_RPC_URL=` empty** |
| Volume | `graphite-main_graphite-data` → `/data` |
| Health | healthy throughout, 0 restarts |

**First action was to rebuild the image.** The running container was built
`2026-09-05T16:42Z`, eight commits behind `HEAD` — proven by `POST
/admin/quarantine` returning 404 for a route that exists at HEAD. Everything
below was measured against a rebuilt image at current `HEAD`.

Because `GRAPHITE_RPC_URL` is empty, **L3 live simulation and L4 RPC-built state
diffing were not exercised through the container.** L3 was exercised against a
seeded baseline (below); L4's RPC path was not. That is a gap in this campaign,
not a claim about the code.

---

## 2. The finding that made the campaign possible

Measured on the shipped container: **20 combinations across 5 protocols and 4
wallet profiles produced 0 approvals**, with a ceiling of confidence 0.440
against a lowest built-in threshold of 0.55.

The three evidence-derived signals (SimulationMatch, HistoricalVolume,
CommunityVerification) are 0.50 of the total signal weight and all read the
semantic graph. Evidence is earned via RPC-verified simulation, observed volume,
or reviewer attestations — none of which can accrue with RPC unset.
`seed_behavior` and `seed_simulation_baseline` existed as operator APIs but
appeared in **no CLI and no HTTP route**.

Two consequences:

1. The deployment as configured blocks 100% of traffic, permanently. Fail-closed
   and the right direction, but not a state an operator can leave, and it was
   undocumented.
2. **Every adversarial result would have been vacuous.** On a graph where
   APPROVE is unreachable, an attack "holding" says nothing about the control
   being tested.

Fixed by adding `graphite evidence seed|baseline|show` (CLI-only — request-body
evidence is the G4 minting vector; P7 preserved because evidence is seeded, not
a tier, and `append` recomputes). Documented in SECURITY.md and README.

**After seeding a realistic graph, APPROVE was reachable at confidence 1.00 on
every profile including Enterprise (0.99).** Every "held" result below is
therefore a control holding, not an empty graph.

---

## 3. Defects found and fixed

Each was reproduced live before the fix, has a regression test, and the test was
verified to fail when the defect is reintroduced.

### 3.1 The audit trail reported a policy threshold the gate does not enforce

- **Severity** Medium (auditability / P3, P9). Not an approval bypass.
- **Subsystem** L6 policy reporting.
- **Reproduction** On one binary: the L6 layer report said `min_conf: 0.60` for
  the Gaming profile while `graphite profiles` said 0.55 and `evaluate_policy`
  enforced 0.55.
- **Root cause** The L6 reason built its threshold from a hardcoded copy of the
  profile table. C53 lowered Gaming 0.60 → 0.55 in the policy engine; the copy
  was never updated.
- **Impact** A transaction approved at 0.57 carried a permanent record stating
  the minimum was 0.60 — the audit trail contradicting its own approval, and
  wrong in the direction that *understates* how permissive the profile is.
- **Fix** Reads `WalletProfile::thresholds()`, the same call the policy engine
  makes.
- **Regression** `tests/layer_report_truthfulness.rs` — the reported threshold
  must equal the enforced one for every profile, and an approval must never be
  recorded beside a minimum higher than the confidence that passed it.

### 3.2 Malformed discriminator returned HTTP 500

- **Severity** Medium (availability / operability). Not an approval bypass; it
  failed closed.
- **Subsystem** `server::classify_error`.
- **Reproduction** `instruction_discriminator: "zzzz"`, `"abc"`, `"03 03"` — all
  HTTP 500 plus an ERROR log line and a `tower_http` failure line.
- **Root cause** Client-vs-server classification by substring-matching the error
  *text*. The matcher looked for `"invalid discriminator"`; the builder emitted
  `"instruction discriminator is invalid hex"`. Default was `Internal`.
- **Impact** Anyone reaching the port could manufacture 500s on demand — SLO
  alerting, on-call pages, and genuine faults buried in chosen noise.
- **Fix** `TransactionBuilderError` has exactly five variants and every one is
  caused by caller input; the builder is a pure function of the plan. The
  default was simply inverted — the whole class is now a client error, so a
  future builder error is a 400 by construction.
- **Regression** Every variant driven through the real builder and the real
  classifier, asserting 400.

### 3.3 Structured logging did not apply to the lines that matter

- **Severity** Low-Medium (operability). Documented behaviour was false.
- **Reproduction** Container runs with `GRAPHITE_LOG_FORMAT=json`; every
  verification line in `docker logs` was plain text.
- **Root cause** `tracing_log` was a bare `eprintln!`, bypassing the subscriber.
- **Impact** An operator shipping to Loki/ELK/Datadog got unparseable text for
  exactly the lines they need (verdict, program, confidence), and `RUST_LOG`
  could neither raise nor suppress them.
- **Fix** Routed through `tracing`. Verified: lines are now JSON with `level`
  and `target`.

### 3.4 Caller-caused rejects logged at ERROR

- **Severity** Low-Medium (availability). Same lever as 3.2, one level down.
- **Fix** Caller-caused rejects are WARN; Graphite's own faults stay ERROR —
  which is only worth paging on while a caller cannot manufacture one. The line
  is still emitted and the audit record still written; probing must leave a
  trail.

### 3.5 The audit trail was storage an attacker chose the size of

- **Severity** Medium-High (P9 integrity + disk exhaustion). Not an approval
  bypass.
- **Reproduction** A `program_id` of 100,000 characters was echoed verbatim into
  the HTTP response, the log line, and `/data/audit.jsonl`. Probing alone grew
  that file to 3.6 MB.
- **Root cause** Account count, instruction data and CPI target count were
  capped; **every string field was unbounded**.
- **Impact** At the configured 1 MB body limit and 30 req/s, a single client
  could write tens of megabytes per second of chosen bytes onto the operator's
  volume — burying real verifications and exhausting the disk the server refuses
  to boot without.
- **Fix** Two independent defences: entry-point length caps (a base58 pubkey is
  at most 44 chars, so longer is invalid on its face and refused in O(1), with
  the rejection reporting the *length* and never the value), and
  `AuditErrorRecord` bounding every caller-influenced field to 256 chars with
  truncation marked rather than silent.
- **Measured after fix, in the container** 2,000,000 bytes of payload across 20
  requests → 11,480 bytes written (0.57% through, down from ~100%; ~174×
  reduction).
- **Regression** `tests/audit_flooding.rs`, covering both defences separately,
  plus the two properties that make the bound safe: a real 43-44 char pubkey
  still verifies, and an ordinary short error is still stored verbatim.

---

## 4. Investigated and found NOT to be vulnerabilities

Recorded because the analysis is the useful part.

- **Account aliasing.** Graphite has no aliasing check, and `source ==
  destination` is approved at confidence 1.00. Investigated: those cases are
  legal on-chain no-ops, and the *dangerous* form — an attacker address
  occupying a fixed, well-known program slot — is caught
  (`AccountIdentityMismatch` + `MaliciousAccountChange`, blocked). Aliasing of
  caller-chosen slots is outside the trust boundary by design and already
  documented in SECURITY.md. A warning firing on legal self-transfers would be
  noise that trains operators to ignore warnings. **No change made.**
- **Program-id case sensitivity.** An early result looked like a bypass; it was
  a bad test — `"111…".upper()` is identical for an all-digit base58 address.
  Real case handling is correct: `TOKEN.upper()` → 400.
- **Rate limiting under Docker.** 200 concurrent requests produced 0 429s
  against the container — but they took 9.0 s (~22 req/s, under the 30/s limit).
  That is Docker Desktop's Windows port-forward throttling, not the limiter.
  Retested natively at a 5/s limit: **84% 429s, and 86% with a fresh spoofed
  `X-Forwarded-For` per request** — spoofing does not reset the bucket.

---

## 5. Attack rounds and outcomes

All against the seeded graph where APPROVE is reachable at confidence 1.00.

| Round | Focus | Attacks | Approval bypasses |
|---|---|---|---|
| 1 | Malformed / boundary input | 9 | 0 |
| 2 | Historical regressions | 7 | 0 |
| 3 | Combinatorial | 2 | 0 |
| 5 | Semantic (valid shape, malicious meaning) | 4 | 0 |
| 6 | Parser / encoding ambiguity | 5 | 0 |
| 7 | Transaction structure, multi-instruction, CPI | 9 | 0 |
| 8 | State / authority | 4 | 0 |
| 9 | Baseline poisoning | 300 requests | 0 |
| 10 | TOCTOU / AuditBind | 11 mutations | 0 |
| 11 | Attacks on the new controls | 5 | 0 |

Specifically confirmed blocking: empty and unknown discriminators, SetAuthority,
CloseAccount, System Assign, caller-supplied evidence (G4), caller-chosen
permissive profiles, discriminator-prefix ambiguity, uppercase/zero-padded
discriminator variants, intent/instruction mismatch, Approve+Transfer drain
pairs (both orderings), authority-hijack pairs, 12-way mass sweeps, sweeps
padded with benign instructions, unknown programs in the CPI tree, 20-wide
sibling CPI fan-out, vanity-impersonated CPI targets, dangerous secondary
instructions, privilege mismatch, and attacker addresses in fixed program slots.

**L3 simulation integrity, exercised for the first time end-to-end** against a
seeded baseline (mean 150 CU, sd 12, n=50): at baseline → approved and honestly
`Inconclusive` rather than `Passed`, because caller-supplied usage cannot
certify clean (P5); at +4σ, 0 CU, and 999999 CU → `Failed` with a
`SimulationSpoofing` risk finding, blocked.

**Baseline poisoning (Round 9):** 300 requests claiming 200 CU — 0 approved, and
the baseline afterwards was byte-identical (`mean 150.0 / sd 12.0 / n=50`). The
invariant "RPC failure cannot create trusted evidence" held.

**content_hash binding:** all 8 execution-affecting mutations changed the hash
(destination, source, extra account, reordering, discriminator, program,
instruction data, CPI targets); all 3 cosmetic fields did not (intent text,
wallet profile, compute units).

**AuditBind (Round 10):** all 11 mutation classes detected and aborted,
including both fail-closed guards (an `audit_trail_id` supplied in place of a
`content_hash`, and an empty hash). Verified wired into the execution path:
`executeTransfer` runs verify → approved check → bind → sign, and the swap
residual is explicitly fail-closed under `GRAPHITE_SWAP_STRICT=1`.

**Cross-language agreement:** the same transaction produced `afb61d8865b4cb68`
from the Rust core, the TypeScript SDK, the Go SDK, and AuditBind's independent
recomputation.

---

## 6. Operational surface (exercised, not just inspected)

- **Auth** 8 malformed authorization variants — no header, empty bearer, wrong
  key, no scheme, lowercase scheme, key+suffix, truncated key, extra space — all
  401. The correct key reached the handler (422 on an empty body), which is the
  anti-vacuity control. `/health` open, `/metrics` authenticated.
- **Body handling** empty, non-JSON, array, null, 200-deep nesting,
  unterminated, duplicate keys, wrong types, `1e999` confidence → all 422. 2 MB
  body → 413. CPI traces at depth 100/1000/5000 → 422 at the parser, no
  recursion into Graphite. 300 accounts → 400 (256 cap).
- **CORS** default-deny holds; no `Access-Control-Allow-Origin` for an unlisted
  origin.
- **Survivability** healthy with 0 restarts throughout every round.

---

## 7. Full validation — exact results, 2026-09-06

```
cargo test --all-features                 1203 passed, 0 failed
cargo clippy --all-features --all-targets -- -D warnings    0 findings
cargo fmt --all --check                   clean
cargo check --no-default-features --all-targets             0 errors
  ... --features cli / server / rpc       0 errors each
cargo audit --deny warnings               243 deps scanned, 0 advisories
sdk/typescript  npm run check / test / build                13 tests pass
integrations/solana-agent-kit  tsc --noEmit + tsx --test    15 tests pass
sdk/go          gofmt -l / go vet / go test                 clean, ok
python-ai-layer pytest                                      27 passed
dashboard       npm run typecheck && npm run build          clean
docker          compose build + up, healthcheck             healthy
```

**Not run:** `cargo test --release`. The local Windows GNU toolchain is missing
`dlltool.exe`, so release builds cannot link here. CI runs this on Linux; it was
not verified on this machine.

---

## 8. Residual risks and limitations

Accepted, and stated rather than hidden.

1. **L4 RPC state diffing was not exercised end-to-end.** `GRAPHITE_RPC_URL` is
   empty in this deployment, so the RPC-built diff path never ran. It has unit
   and integration coverage; it has not been validated against live RPC here.
2. **L8 execution verification was not exercised.** Same cause.
3. **The swap TOCTOU residual remains** when `executeSwap` is called with no
   payload: execution goes through SAK's internal builder, which is not
   guaranteed to submit the verified instruction. `GRAPHITE_SWAP_STRICT=1`
   refuses that path. Documented in SECURITY.md and warned at runtime.
4. **Aliasing of caller-chosen account slots is not checked** — by design, and
   analysed in §4.
5. **Seeded evidence is operator-asserted, not observed.** The bootstrap path is
   necessary and CLI-gated, but an operator who seeds inaccurate evidence gets
   inaccurate confidence. The command says so and the graph records it.
6. **The P10 first-submission gate bootstraps a baseline; it does not validate a
   new manifest.** A fixture recorded under a candidate and replayed under the
   same candidate agrees with itself by construction. Documented.
7. **No third-party audit.** Nothing here substitutes for one.
8. **Rate limiting could not be demonstrated through Docker on Windows** because
   the port forward throttles below the limit. Demonstrated natively instead.

---

## 9. Reproducing this

```bash
# 1. Build and run at current HEAD (the running image may be stale).
docker compose build && docker compose up -d
docker ps --filter name=graphite --format '{{.Status}}'

# 2. A fresh graph approves nothing. Seed a realistic one, or every
#    adversarial result is vacuous.
graphite evidence seed --data-dir <dir> --program 11111111111111111111111111111111 \
  --signed-manifest --community-verified 2 --battle-tested 1500 --simulation-matches 100
graphite evidence baseline --data-dir <dir> --program 11111111111111111111111111111111 \
  --mean-compute-units 150 --std-compute-units 12 --samples 50

# 3. Confirm APPROVE is reachable before attacking anything.
graphite explain --file examples/verify-input.json

# 4. Full suite.
cd graphite-core && cargo test --all-features \
  && cargo clippy --all-features --all-targets -- -D warnings \
  && cargo fmt --all --check
```
