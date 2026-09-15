# Round 11 — The full run: holes Graphite made for itself

> **Historical record.** This report describes the codebase at commit
> `b75ce57` on 2026-09-15. For the current state of Graphite see
> [`CURRENT.md`](CURRENT.md).

**Scope.** Not a review round. The owner asked for Graphite to be run in full —
every suite, every live path, the binary as it ships — to find the holes,
errors and weaknesses the project has created for itself, and to make it work
*well*, not merely work. This is internal engineering work by the project's
own agent; nothing here is an independent certification.

**Standing constraints, all kept.** No credentials in source, commits, logs or
output; no attack on any public RPC (every adversarial RPC is a loopback mock);
public devnet used read-only; nothing touched a live wallet, protocol or fund.

---

## Verdict in one paragraph

Everything Graphite ships was run: the full Rust matrix, the TypeScript SDK and
SAK suites, Go, Python, the dashboard build, the corpus drift gate, the ignored
network tests against public devnet, and a 73-check live probe of the release
binary on loopback (startup refusals, auth, limits, determinism, concurrency,
L8 with honest, substituted and forged chain bytes, lifecycle, metrics, restart
persistence, the TS SDK's live conformance suite, the CLI). Ten self-made
holes were found and closed, one of them a fresh dependency advisory. The one that matters for security is **R11-01**:
Round 10 made "the chain decides" the rule for L8 attribution, but took the
RPC's word for what the chain's bytes were — a faulty or hostile RPC could
attribute any execution to any verification. The bytes are now bound to the
signature cryptographically. The one that matters for "works well" is
**R11-02**: every request deep-copied the whole manifest registry four times;
`/health` answered in ~100 ms and the server managed 21 verifications per
second in-process. It now answers in ~1 ms and manages 960.

---

## Findings

| # | Class | Finding | Status |
|---|---|---|---|
| R11-01 | **P1** | L8 accepted whatever bytes the RPC returned for a signature as "the chain's bytes"; nothing bound them to the signature. A substituting RPC could attribute an execution to any verification, or hand attribution back to the caller's keys. | **Fixed.** `bound_artifact_sha256`: first slot must equal the signature and verify (ed25519, strict) over the message under the fee payer's key. Rejected bytes → `Unavailable`, `chain_bytes_rejected`, no fallback. |
| R11-02 | P2 | `AppState` (the whole manifest registry, the community registry engine) was deep-copied on every `State` extraction and every middleware — four or more times per request. `/health`: ~100 ms. In-process storm: 21 verifies/s. | **Fixed.** `Arc<GraphiteCore>`, `Arc<ManifestRegistryEngine>`. `/health`: 1.1 ms. Storm: 960 verifies/s. Regression tests. |
| R11-03 | P2 | Early refusals (401, 429, 503) answered before the request body was read and then closed the connection; the kernel sent RST and a client still writing saw a reset instead of the status. | **Fixed.** `refuse_after_draining`: the (already size-capped) body is drained before the refusal is returned; 429 carries `Retry-After`. |
| R11-04 | P2 | `parse_transaction` accepted a signature array whose length differs from the header's signer count, and a header with no writable signer — frames the runtime's `sanitize` refuses. | **Fixed.** `ArtifactParseError::SignatureCountMismatch`; `ImpossibleHeader` when `num_readonly_signed >= num_required_signatures`. 12 new corpus mutations; web3.js agrees on all of them. |
| R11-05 | P2 | `GRAPHITE_API_KEY` of any non-empty length started the server; a five-character key is a guessable key. | **Fixed.** `MIN_API_KEY_CHARS = 32`; a shorter key refuses to start on every address, dev mode or not. |
| R11-06 | P3 | L8 reconciliation rows on the trail were truncated at 256 characters — the server's own detail lost the attribution and the rejection reason at the end of it — while `/audit/event` accepted 1024. | **Fixed.** One bound, `durable::MAX_LIFECYCLE_DETAIL_CHARS = 1024`, at the boundary and on disk. |
| R11-07 | P3 | No metric counted L8 discrepancies — the single most important event this system can record. | **Fixed.** `graphite_execution_checks_total`, `graphite_execution_discrepancies_total`, `graphite_execution_chain_bytes_rejected_total`. |
| R11-08 | COVERAGE GAP | The TypeScript SDK's live-server conformance tests skip without `GRAPHITE_URL`, and nothing in CI set one: the SDK and the server could disagree about a field with a green pipeline. | **Closed.** The container job runs `npm test` against the live container and fails if any test was skipped. |
| R11-09 | P3 | `graphite verify --profile custom --min-confidence 0.0` honoured the operator's number silently. | **Fixed.** A custom bar below the weakest built-in profile prints a WARNING on stderr; the server's clamp is unchanged. |
| R11-10 | P2 (supply chain) | `rustls 0.23.43` in `Cargo.lock` is subject to RUSTSEC-2026-0285 (TLS 1.3 handshake messages accepted across encryption-level boundaries, published the day before this run). Every RPC call Graphite makes goes through it. | **Fixed.** `rustls 0.23.45`; `cargo audit --deny warnings` clean. Found by running the audit, which is exactly what the CI job exists for. |
| — | DOCUMENTED LIMITATION | A body over the 1 MiB limit may be answered with a connection reset rather than a readable 413: hyper does not drain past the limit. Clients see "refused", not the status. | Recorded below. |
| — | DOCUMENTED LIMITATION | L8 still trusts the RPC for *inclusion* (`getSignatureStatuses`). The RPC can lie about whether a signature landed; it can no longer lie about which bytes it carried. | Recorded below. |

---

## R11-01 — the chain's bytes must be the signature's

**The invariant Round 10 relied on.** The bytes behind a signature, with their
signature slots zeroed, are the artifact Graphite was shown, so their digest is
the exact join key. True — *of the chain's bytes*. What `getTransaction`
returns is the RPC's claim about the chain's bytes, and Round 10 used that
claim unexamined.

**The attack.** A is the corpus transfer (approved); B is the same transfer
with an undeclared 100 SOL sibling (blocked). B executes under signature
`sig_B`. The RPC answers `getTransaction(sig_B)` with A's signed bytes.
Round 10 L8: digest of A → A's approval → `ApprovedAndExecuted`,
`attribution: chain` — the strongest label the system has, for a bypass.
Equally, an RPC returning garbage for `sig_B` made attribution fall back to
the caller's keys, so an RPC that could substitute bytes could also hand the
choice of verification to the caller.

**Reproduced** in `tests/round10_attribution.rs::an_rpc_that_substitutes_bytes_cannot_attribute_the_execution`
(a loopback mock cluster; the fee payer is a keypair the test holds, so
"signed" means signed) and in the live probe against the release binary
(`/verify/execution` with `sig_B` while the mock serves A's bytes).

**The fix.** `tx_artifact::bound_artifact_sha256(bytes, signature)`:

1. `signature` decodes (base58) to 64 bytes;
2. the frame parses in full (`parse_transaction`, so every declared slot is
   present, the array is as long as the header's signer count, and the header
   names a writable fee payer);
3. the first slot holds `signature` byte for byte;
4. `signature` verifies over the message bytes under the fee payer's key —
   `ed25519_dalek::VerifyingKey::verify_strict`, the runtime's own check;
5. only then is the artifact digest returned.

A transaction's id *is* its first signature, produced by the fee payer over
the message, so bytes that pass this are the transaction filed under that id;
forging them takes the fee payer's key. Bytes that fail are named for why
(`FirstSlotDiffers`, `SignatureDoesNotVerify`, `FeePayerKeyInvalid`,
`SignatureMalformed`, or the frame error) and the reconciliation is
`Unavailable` with that reason, `attribution: none`, `chain_bytes_rejected`
set, **no caller key consulted** — an RPC able to substitute bytes must not
also be able to choose the join. The server counts it
(`graphite_execution_chain_bytes_rejected_total`), logs it at ERROR, writes
it on the trail row, and the bridge logs `L8 REFUSED`.

**Honest bytes still bind.** `l8_live_mainnet.rs::l8_real_chain_bytes_are_bound_to_their_signature`
fetches a confirmed signature from public devnet, its bytes via
`getTransaction`, and asserts the binding holds and that the same bytes refuse
a different signature — real transactions nobody in this repository produced,
so the check speaks the runtime's signature language.

**Classification.** P1, not P0: L8 is post-execution detection, not the gate,
and the attacker needs the RPC. But the RPC is the same trust boundary L3 and
L4 already stand on, and Round 10 had labelled the RPC's word as the chain's.

---

## R11-02 — the request path deep-copied the state

Found by measurement, not by reading: `curl` against the release binary put
`/health` at 100 ms on loopback; a Go hello-world on the same machine answered
in 1–3 ms. Bisected in-process with `build_app`: a bare router answered in
1 ms, the three `from_fn_with_state` middlewares added ~50 ms, the full stack
~95 ms. `AppState` derives `Clone`, axum clones it for every `State`
extraction and every `from_fn_with_state` middleware, and `GraphiteCore`
carried the `ManifestRegistry` — a `BTreeMap` of every protocol manifest —
by value. Four deep copies per request.

`core` and `registry_engine` are now `Arc`s (every handler uses `&self`; the
mutable state inside `GraphiteCore` was already interior). Measured after:
`/health` 1.1 ms; the in-process storm test (8 workers × 25 verifies + 16
dashboard reads, with `fdatasync` on every audit append) went from 9,624 ms to
208 ms — 21 to 960 verifies/s. `/manifests` serializes from the registry's
references instead of cloning every manifest first. Two regression tests:
`app_state_clone_is_a_reference_count_not_a_deep_copy` (a thousand clones
under 250 ms; deep copies took fifteen seconds) and
`health_answers_in_milliseconds_on_loopback`.

---

## What was run

| Suite | Result |
|---|---|
| `cargo fmt --check`, `cargo check` (featureless, cli), `cargo clippy --all-targets --all-features -D warnings` | clean |
| `cargo test --release` | 1,460 passed, 0 failed, 11 ignored (network) |
| `cargo test --release --no-default-features --lib` | 305 passed, 0 failed |
| `cargo test --release --no-default-features --features cli` | 1,293 passed, 0 failed |
| `cargo audit --deny warnings` | **found RUSTSEC-2026-0285** (rustls 0.23.43, published 2026-09-14, medium); fixed by `cargo update -p rustls` → 0.23.45; clean after |
| Ignored network tests against public devnet (read-only): `live_transactions` (2), `l3_live_simulation` (3), `l8_live_mainnet` (4, incl. the new binding test), `rpc_client` live (1) | 10 / 10 passed, incl. `l8_real_chain_bytes_are_bound_to_their_signature` |
| TypeScript SDK: `npm run check`, `npm test`, `npm run build` | 17 tests (13 hermetic + 4 live, the live ones run in the probe and now in CI) |
| SAK integration: typecheck, `npm test`, fixture + corpus regeneration, drift diff | 97 tests; corpus 1,659 mutations, `both accept 765 / both reject 843`, Graphite stricter on 51, web3.js stricter on 0 |
| Go SDK: gofmt, vet, `go test -count=1` | 20 tests |
| Dashboard: typecheck, production build | clean |
| Python AI layer: `pytest` (hash-locked deps) | 27 tests |
| Live probe of the release binary (`r11_probe.py`, loopback, mock RPC) | 73 / 73 |
| Deliberate breaks (below) | 7 / 7 caught (one test rewritten to catch its break) |

### The live probe, in outline

Startup refusals: no key; dev mode off loopback; unparseable pinned profile;
unwritable data dir; 5-character key; 31-character key. Keyed server:
`/health` open, everything else 401 without or with the wrong key; malformed
JSON, empty body, bodies over the limit; a permissive `Custom` profile clamped
and disclosed; a 1233-byte artifact refused; an artifact without
`instruction_data` not approved; A approved after the baseline warms; the same
input twice yields the same hash, scope, verdict and layers with distinct
audit ids; B blocked at L2 with the sibling named; two signature slots under a
one-signer header refused; 120 concurrent verifies and 300 rapid GETs produce
only 200 and 429, never 5xx. L8: honest bytes of B → `BlockedButExecuted` by
`chain`; A's bytes for B's signature → refused, nothing attributed, caller's
keys not consulted; a forged first slot → refused (`does not verify`); honest
bytes of A → `ApprovedAndExecuted`; no chain bytes → `content_hash` labelled
ambiguous, a spoofed id not rescued. Lifecycle by exact key, contradicting keys
400, oversized detail 400. Metrics present and counted, including the three
new ones. Every read-only endpoint 200. Quarantine add → A blocked; lift → A
approved. Every audit line parses; verification rows carry the digest; L8 rows
carry the attribution and the rejection. The TS SDK's 17 tests all run against
this server. Restart: B's id and digest resolve from the re-indexed trail, chain
attribution still works, graph evidence persisted. CLI: `verify`, `explain`,
`profiles`, `manifests`, `execution` (exit 1 on the discrepancy; `REJECTED` on
substituted bytes), `manifest-verify`, `benchmark`, `healthcheck`.

### Deliberate breaks

Each break edits one line of production code, runs the test meant to catch it,
and is reverted. A break the tests do not catch is reported as such.

| Break (one line of production code) | Caught by |
|---|---|
| `bound_artifact_sha256` skips the ed25519 verification | `round10_attribution::an_rpc_that_substitutes_bytes_cannot_attribute_the_execution` (the forged-slot case) |
| `bound_artifact_sha256` skips the first-slot comparison | `round10_attribution::chain_bytes_are_accepted_only_when_bound_to_the_signature` |
| Rejected chain bytes fall back to the caller's keys | `round10_attribution::an_rpc_that_substitutes_bytes_cannot_attribute_the_execution` |
| `parse_transaction` accepts a signature-count mismatch | `sak_bridge_corpus::every_byte_level_mutation_is_read_the_same_way_on_both_sides` (web3.js refuses what Graphite now accepts) |
| `MIN_API_KEY_CHARS = 1` | `server::tests::auth_is_required_unless_dev_mode_is_named_and_the_bind_is_loopback` |
| Lifecycle `detail` bounded at 256 on disk again | `durable::tests::lifecycle_event_fields_are_bounded_on_disk` |
| Refusals drop the body instead of draining it | `server::request_path_cost::early_refusals_drain_the_body_so_the_status_is_readable` — **only after the test was rewritten**: the first version used a keep-alive client whose whole 900 KB body was in the kernel buffer before the server answered, so the reset never reached it and the break passed. The test now uploads from a raw socket in two parts with a pause between them, and the break fails it. Recorded because a vacuous test is worse than none. |

7 / 7 caught. The `Arc` regression cannot be broken in one line (restoring the deep copy is a type change); `app_state_clone_is_a_reference_count_not_a_deep_copy` asserts the reference count directly. The three new metrics are incremented in the handler and asserted by the live probe against the release binary, not by a unit test.

**A break of the process itself.** The first run of the break script reverted each broken file with `git checkout --`, which discards uncommitted work — and Round 11 was uncommitted. Every source edit in this round was re-applied from the saved patch scripts, re-verified (fmt, clippy, the targeted suites), and the script now restores from file copies. The commit under test is the re-applied tree.

---

## What was NOT tested, and what remains outside the guarantee

- **The RPC's account of inclusion.** `getSignatureStatuses` is still taken at
  its word: an RPC can claim a signature landed when it did not (a false
  discrepancy — the safe direction) or that it did not when it did (a hidden
  bypass). The bytes it can no longer forge; the fact of inclusion it can. A
  second, independent RPC or a light-client proof would close this; neither is
  built.
- **Oversized bodies get a reset.** Past 1 MiB the server answers 413 and
  closes without draining the remainder; a client mid-upload may see a
  connection reset rather than the status. Below the limit, refusals are now
  drained and readable.
- **The container job was not run locally** (no Docker daemon on this
  machine); it ran in CI for this commit, including the new SDK conformance
  step.
- **The demo (`demo.ts`) was not run**: it needs an OpenAI key, a funded
  keypair and a live cluster, all outside the standing constraints. The bridge
  it drives is covered by the 97 SAK tests and the live probe.
- **Timings are from one Windows machine**; the regression tests assert
  bounds two orders of magnitude wide, not the measured numbers.
- Everything in `CURRENT.md` under "What is NOT enforced" still holds.

---

## Evidence

CI for this commit: GitHub Actions run 35035499644 for `b75ce57` — all seven jobs (Rust core, CVE audit, Container incl. the new SDK live-conformance step, TypeScript SDK + SAK, Go, Dashboard, Python) completed with `success`. "Certified" here means exactly that and nothing more.
