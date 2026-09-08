# Production-Readiness Audit — 2026-09-08

**Method.** Internal engineering work by Anthropic's Claude acting as this
project's engineering agent, against `main` from `ed697ec` to `926ace0`. This is
not an independent third-party audit, a certification, or a penetration test by
an external firm, and nothing in it should be presented as one.

**Standard applied.** A subsystem counts as working only if it was exercised
through its real execution path. Compiling, passing unit tests, having an
endpoint, being wired into the repository, or being described in a README were
treated as evidence of nothing.

**Boundaries observed.** No credentials appear in source, commits, logs or this
report. Live traffic was read-only against public devnet using the project's own
already-funded devnet wallet as fee payer; nothing was signed and nothing was
submitted. Every hostile RPC response came from a loopback mock. No live user,
wallet, protocol or funds were interacted with.

---

## Executive verdict

**PRODUCTION READY WITH EXPLICIT LIMITATIONS.**

The deterministic security boundary holds under everything this audit threw at
it: no approval bypass was found, a lying RPC cannot overturn a deterministic
finding, advisory code cannot approve anything by construction, manifests cannot
be substituted at runtime, and transaction mutation before signing is now
detectable. All eight layers execute on real paths, L3/L4/L8 against a live
cluster.

It is not unqualified, for reasons stated in full in §5. The two that matter
most: **87.3% of protocol account slots are accepted in the position the caller
supplied them**, because no manifest pins them — Graphite now says so per
verification rather than implying otherwise; and **a cooperative RPC can create
an approval**, by design, because earned simulation evidence is 0.20 of the
confidence score. Neither is a defect. Both are limits a deployer must know
before trusting the gate with funds.

---

## 1. What was tested

Every subsystem, through its production path. The system map and the trace of a
transaction from intent to audit trail are in §7 and §8.

| Exercised live | How |
|---|---|
| L1–L7 | Real `/verify` calls against the container built from HEAD, live devnet RPC attached |
| L3, L4 | Live `simulateTransaction` + `getMultipleAccounts` against devnet; 7 fixtures built from real chain state |
| L8 | `POST /verify/execution` against mainnet signatures, read-only |
| RPC trust boundary | Loopback mocks returning hostile responses |
| Server controls | Auth, CORS, body limits, rate limiting, shedding, panics — over real HTTP |
| Concurrency | 50 truly-parallel verifications against the live container |
| Manifest registry | Real CLI submissions with real ed25519 keys |
| Intent parser | Adversarial and injection-style inputs, then the resulting transaction through the pipeline |
| SDKs | Go and TypeScript against the running server |
| SAK / AuditBind | Instruction mutation after approval, before signing |
| Docker | `--no-cache` build from HEAD, then runtime checks inside the container |

Not tested, and not claimed: any mainnet write path, adversarial testing against
a real RPC provider, soak/endurance runs, and the 2,000-transaction synthetic
corpus from the previous campaign (deliberately not re-run).

## 2. What was discovered

Seven defects. Each was reproduced against a running system before being fixed,
and each has a regression test that fails if the fix is reverted.

### 2.1 A single verification could run for 242 seconds (HIGH)

`server.rs` gives each request a 10-second `REQUEST_TIMEOUT` and attached an RPC
client built from `RpcConfig::default()` — 30 seconds per call, 3 retries,
backoff. The inner deadline could never expire before the outer one.

The damage is not latency, it is silence. The caller receives a bare `408` with
no verdict, no layer report and no reason, from a system whose premise is
fail-closed *with an explanation*. Nothing reaches the append-only audit trail,
because the verification never finished — so a request Graphite could not decide
leaves no trace, under the single most likely production degradation there is.
And an SDK reading `408` as "the server was slow" retries, which is the worst
available response to an overloaded RPC.

The first fix did not work, and the test said so at 242.8s: the budget covered
the simulation block while an earlier, unbudgeted `get_account` burned the whole
retry sequence. That call is decorative — it appends live account state to the
L3 report and informs no decision — yet it sat on the critical path of every
verification with an RPC attached.

**Fixed:** one shared deadline across the entire RPC phase, because bounding each
call separately does not bound the total; a fixed one-second slice for the
decorative fetch so it can never starve the calls that decide anything; and a
compile-time assertion in `server.rs` that the budget still fits inside
`REQUEST_TIMEOUT`. Verified: 242.8s → 2.03s for the whole suite.

### 2.2 Nothing bounded concurrent work (HIGH)

50 truly-concurrent verifications against a live devnet RPC: **33 answers, 17
bare `408`s, 26 seconds.** The per-request budget was in place; nothing bounded
how many requests could wait on the same upstream at once.

**Fixed:** in-flight verifications capped (`GRAPHITE_MAX_CONCURRENT`, default 32),
excess shed immediately with `503` + `Retry-After`. `try_acquire` rather than
`acquire` — queueing would only move the wait from the RPC to the semaphore and
still end at the timeout. Re-measured on the same container under the same load:
**32 answers, 18 immediate refusals, 12 seconds.**

`429` and `503` are kept distinct and counted separately at `/metrics`: one
caller asking too often is a different operational problem from an undersized
instance, and an invisible refusal is an outage nobody can diagnose.

### 2.3 Value could be sent to an address nobody can spend from (HIGH)

Found by attacking the intent parser and then following the transaction it
produced through the real pipeline. "send 1 SOL to
`11111111111111111111111111111111`" parsed at 0.99 confidence, and the
deterministic core answered **`approved: true, risk: Clear`** — a permanent,
unrecoverable burn, approved.

The system-account impersonation check — grounded in SolPhishHunter
(arXiv:2505.04094), which documents phishers grinding addresses ending in `11111`
so truncating wallet UIs display them as official — kept an `OFFICIAL` allowlist
and skipped every address on it, commented "official accounts that legitimately
appear in transfers". So it flagged addresses ground to *resemble* system
accounts and exempted the system accounts themselves.

**Fixed:** `RiskPattern::UnspendableDestination`, written as the invariant rather
than a signature — value must not move to an address that cannot spend it —
scoped to fund-movement discriminators whose account lists never legitimately
contain one. While correcting the list: `NativeLoader111111111111111111111111111111`
is 42 characters and base58-decodes to 31 bytes, so it was not a valid pubkey and
could never have matched anything.

### 2.4 AuditBind protected a copy, not the artifact that gets signed (HIGH)

The SAK bridge re-hashed its own local constants and a `transferData` snapshot
taken before verification, then signed `transferIx`. Two different objects.
Mutating the instruction after approval left the check printing `[AuditBind] Hash
verified` while the redirected instruction went to the signer.

The module already had the right primitive, `verifyInstruction`, which projects
from the live instruction. Nobody used it because of a second defect:
`projectionFromInstruction` derived the discriminator from the first 8 bytes of
instruction data — an Anchor convention wrong for every native program. For a
System transfer it yields `0200000040420f00` (the 4-byte discriminator plus half
the lamport amount), hashing to `030424ed4db245eb` where the core computes
`42bd6f2a33492dc2`. The check could never pass, so the bridge worked around it
with the snapshot.

**Fixed:** the discriminator is explicit, the bridge binds the live transaction,
and `transactionBinding` covers the whole instruction list — `content_hash`
cannot cover an instruction that did not exist at verification time, so an
appended drain passed a per-instruction check untouched. Verified against the
running server: the live-instruction projection reproduces the core's
`content_hash` exactly, and mutation aborts.

### 2.5 L4 claimed a pass whenever simulation failed outright (MEDIUM)

The `Err` arm of the simulation never set `diff_unavailable`, so the layer fell
through to its structural fallback and answered in the wording of a completed
diff — on every RPC outage, timeout and budget exhaustion. Sibling arms already
set it; this was the arm that fires when the RPC is down.

### 2.6 L1 never said how much of the account list it confirmed (MEDIUM)

"Resolved 2 account(s), manifest found" reads as two accounts checked. Measured
across the shipped manifests (34 manifests, 803 instructions, 5,010 account
slots):

| Identity | Slots | Share |
|---|---|---|
| PDA re-derived | 94 | 1.9% |
| Constant address matched | 542 | 10.8% |
| **Accepted by position** | **4,374** | **87.3%** |

28 of 34 manifests declare no PDA seeds at all. Most of that residue is
irreducible — which token account to debit and who the recipient is are
externally determined, and no manifest can pin them — and
`AccountIdentity::Unverified` was already computed per account and serialized in
`resolved_accounts` for exactly that reason. The defect was the summary, at the
layer named "Account Resolution", in wording that made no distinction between an
instruction whose accounts are all re-derived and one where none are. No test
pinned that string, which is why it went unnoticed.

### 2.7 Two panic paths reachable from the library API (LOW)

`regression_engine::content_hash` called `.expect("VerificationInput is always
serializable")` under a comment asserting the struct is plain data. It is not:
`confidence_of_parse` is an `f64` and serde_json refuses non-finite floats. The
HTTP boundary is safe — verified against the running server, `1e400` and `NaN`
are rejected with a `422` — but a Rust caller can set `f64::NAN` in memory and
take the host process down over a field Graphite deliberately never reads.

`load_seed_manifests` ended its match on the seed-path list with
`unreachable!()`, over two hand-maintained lists of the same literals. It now
fails closed naming the missing manifest.

### 2.8 Test integrity

Ten cases across three files used the SPL Token and Token-2022 **program ids** as
filler account addresses, which made them assert that a token transfer whose
authority is the Token Program is a "legitimate transfer" that "should be clear".
Values chosen because they were handy, encoding a claim about Solana that is
false. The TypeScript SDK's `test` script also ran a single file by name, so any
new suite in that package would not have run at all.

## 3. What was fixed

All seven, plus the fixture and test-runner problems above. Every fix has a
regression test; the ones worth naming: `tests/rpc_budget.rs` measures elapsed
wall-clock against the budget rather than checking that a number was configured,
and includes the case a per-call timeout cannot catch (several individually
prompt calls exceeding the total).

## 4. What remains — not fixed, deliberately

**L3 flags legitimate multi-instruction traffic.** The compute baseline is keyed
by `program_id` while `unitsConsumed` measures the whole transaction. One System
transfer is 150 CU, two is 300. Measured on the shipped container against live
devnet: a two-instruction transfer came back `approved: false` on
`SimulationSpoofing` alone at 2.45σ with L2, L4 and L5 all passing.

Every obvious repair re-keys the baseline — by instruction, by instruction count,
by shape — and each hands an attacker an evasion: append a no-op ComputeBudget
instruction, land in a bucket with no baseline, and the layer stops flagging.
Trading a visible false positive for a silent false negative on a blocking
control is the wrong direction. Fixing it properly means keeping an unobserved
shape from being a free pass, which is a design change rather than a patch.

**PDA coverage is thin because manifests do not declare seeds.** Re-derivation
works and is exercised (`find_program_address` on the production path), but only
6 of 34 manifests give it anything to check. Raising coverage is manifest
authoring work, not engine work.

## 5. Security-critical residual risks

1. **The RPC endpoint is inside the trusted computing base.** A *cooperative*
   RPC can create an approval by design: `SimulationMatch` is 0.20 of the
   confidence score and saturates after three earned observations. Measured on a
   System transfer under the Gaming profile: **0.4400 without an RPC, 0.6400 with
   one, `approved: false → true`** across the 0.55 threshold, and the evidence is
   per-*program*. The hard boundary holds — no amount of it overturns a
   deterministic finding, asserted from both directions — but point Graphite at
   an RPC you trust, over TLS.
2. **87.3% of account slots are positional.** Substituting an account in a slot
   no manifest pins is not detectable by L1. L4's observed state diff is the
   compensating control, and it requires an RPC and a signed transaction.
3. **`transaction_instructions` is caller-declared.** With a signed blob the
   simulator executes the whole transaction regardless of what the caller listed,
   so `covers_all_writable` and the single-instruction gate rest on the caller
   describing its own transaction honestly.
4. **ALT accounts are observed, not resolved.** Graphite reports which accounts
   arrived through a lookup table and which of them it did not examine; it does
   not fetch the table's contents.
5. **L8 is caller-driven.** Graphite does not watch the chain, so a bypass is
   only detected if someone reports the signature.

## 6. Scorecard

Scored against *production-hardened*, not against *exists*. 4 means production-capable; 5 means thoroughly hardened, with the failure modes measured rather than assumed.

| Subsystem | Score | Basis |
|---|---|---|
| L1 Account Resolution | 3 | Real PDA re-derivation, privilege grounding, honest coverage reporting — but 87.3% of slots positional and 28/34 manifests declare no seeds |
| L2 Instruction Verification | 4 | Discriminator width, padding and prefix attacks covered; hard gate on Failed |
| L3 Simulation | 3 | Live, grows its own baseline, provenance-tagged — but flags legitimate multi-instruction traffic (§4) |
| L4 State Verification | 4 | Real pre/post diff; caught an undeclared owner reassignment on live devnet that L1, L2 and L5 all passed |
| L5 Semantic Verification | 4 | Intent/instruction mismatch is a hard gate; full L5 vocabulary |
| L6 Policy | 5 | Single source of truth for thresholds; report and enforcement provably cannot disagree |
| L7 Risk | 4 | 14 checks, invariant-shaped after this audit; plugin vetoes named for what they are |
| L8 Execution | 4 | Reachable, reconciles against the append-only record, live-validated; caller-driven by design |
| RPC trust boundary | 5 | Six attacks closed, influence measured and bounded, budget enforced, failures fail closed |
| Risk engine | 4 | See L7 |
| Policy engine | 5 | See L6 |
| PDA verification | 3 | Mechanism correct and exercised; coverage limited by manifests |
| Manifest system | 5 | Compile-time baked; no HTTP write surface; NoEvidence → refused, unregistered signer → refused, registered signer without regression corpus → refused (all verified through the real CLI) |
| Protocol registry | 4 | Layered gates proven live; reviewer reputation and P10 replay enforced |
| Intent parser | 4 | Deterministic, no instruction-following surface to hijack; injection attempts failed |
| AI layer | 5 | Cannot approve *by construction* — `PluginVerdict` has no approving variant, asserted by exhaustive match; Python layer unreachable from the Rust core |
| SAK integration | 4 | TOCTOU gap closed and proven against the real server; binds the live transaction |
| AuditBind | 4 | Cross-language hash agreement verified live in Go, TypeScript and Rust |
| TypeScript SDK | 4 | Real-server conformance suite; every gate-relevant field asserted |
| Go SDK | 4 | Same |
| API / server | 4 | Auth, CORS, body limits, panics, shedding all verified over real HTTP |
| CLI | 4 | Registry, quarantine, evidence, explain, execution all exercised; correct exit codes |
| Docker | 5 | `--no-cache` build from HEAD; non-root, read-only rootfs, healthcheck, no secrets in cmdline or logs, state survives restart |
| Observability | 4 | Structured JSON, separate counters for every refusal class, audit health exported |
| Security posture | 4 | No approval bypass found; residual risks in §5 are stated rather than closed |
| Reliability | 4 | Bounded latency and bounded concurrency, both measured before and after |
| Test coverage / integrity | 4 | 1,272 tests, but this audit found ten that asserted something false |
| Documentation | 4 | Synced to implementation this cycle; limitations stated with measured numbers |

## 7. Full test results

```
graphite-core  cargo test --all-features            1,272 passed  0 failed  10 ignored
               cargo test --release --all-features  1,272 passed  0 failed  10 ignored
               cargo clippy --all-targets -D warnings          0
               cargo fmt --all --check                         clean
               cargo audit                          243 crates, no advisories
               feature matrix (5 combinations)                 0 errors
sdk/typescript npm test (incl. live server)         17 pass
sdk/go         go test ./...                        ok
               go test -tags liveserver             5 pass
integrations   SAK (incl. TOCTOU suite)             21 pass
python-ai-layer pytest                              27 passed
dashboard      npm run build                        built
docker         build --no-cache from HEAD           succeeded
```

**Environment limitation, stated rather than papered over:** the machine's
rustup had a directory override pinning `graphite-core` to
`stable-x86_64-pc-windows-gnu`, whose linker needs `dlltool.exe`, which is not
installed. A `cargo clean` build therefore failed on `parking_lot_core` and
`windows-sys`. The repository pins no toolchain; the override was machine-local
state and was removed, and everything above ran on `stable-x86_64-pc-windows-msvc`.
The authoritative clean build is the Docker one, which succeeded from HEAD with
`--no-cache`.

## 8. Exact commands

```bash
cargo test --all-features && cargo test --release --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all --check && cargo audit
docker build --no-cache -t graphite-clean-audit .
docker compose up -d --build
GRAPHITE_URL=http://127.0.0.1:7331 GRAPHITE_API_KEY=… go test -tags liveserver -run TestLive ./...
GRAPHITE_URL=http://127.0.0.1:7331 GRAPHITE_API_KEY=… npm test          # sdk/typescript
npx tsx --test toctou-signing-boundary.test.ts                          # integrations/solana-agent-kit
node rpc-fixtures.cjs                                                   # devnet fixtures, read-only
graphite registry submit --state … --manifest … --signer-key …
```

## 9. Commits

| Commit | Subject |
|---|---|
| `3fa8653` | Fix an inverted timeout budget, a TOCTOU gap at the signing boundary, and L1's silence |
| `f714f80` | Block value moving to an address nobody can spend from |
| `5baec3a` | Shed load instead of accepting work that dies at the deadline |
| `926ace0` | Close two panic paths, and test both SDKs against the real server |
