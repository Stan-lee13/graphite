# Round 16 — signed before it was shown

**Date:** 2026-09-21
**Trigger:** the full 43-section forensic brief — exact transaction identity,
pre-signed artifacts, discriminator identity, manifest trust, PDA templates,
account identity, privileges, v0/ALT, simulation, baseline poisoning,
confidence, policy, risk, multi-instruction, state diff, RPC trust, plugins,
residual policy, SDKs, examples, L8, durability, concurrency, fail-open,
resource bounds, configuration, durable nonce, runtime oracle, test quality,
duplicate implementations, execution sinks, supply chain, dashboard.
**Audited state:** commit `e95857d4c0e1f1b3f801697acc727ca79dd96c25` (`main`,
`git rev-parse HEAD`; working tree clean apart from untracked `.agents/` and
`.claude/`, which are not Graphite's). `git diff --stat 21c0a7b e95857d` over
every code directory is empty: this is the same code Round 15 audited, plus
one report. Every source claim below therefore also holds for `21c0a7b`.
**Toolchain:** rustc 1.98.1 / cargo 1.98.1 (CI pins 1.98.1); node v24.1.0,
npm 11.3.0 (CI uses node 20); go 1.26.7 (CI uses 1.22.12, `go.mod` says 1.21);
Python 3.13.14 (CI uses 3.11).
**Method:** source and call graph read in every production module, the SAK
bridge, both SDKs, the Python layer, the runtime oracle, CI, Docker and the
console; 82 Rust integration test files and the bridge/SDK suites read for
what they actually assert. Every claim marked CONFIRMED was reproduced against
a debug build of this HEAD on a loopback Core (`127.0.0.1:7661`,
`GRAPHITE_DEV_MODE=1`, data dir in the scratchpad) behind a controllable mock
RPC (`127.0.0.1:7660`, `POST /__control`). No public RPC was touched, no
wallet, no funds, no key. Two deliberate breaks were applied to production
source and reverted; the file digests before and after are recorded in §11.
This is internal work and is not an independent certification.

> This file is a dated record. `docs/CURRENT.md` describes the codebase as it
> is now. Round 15's report (`round15-earned-by-asking-2026-09-20.md`) is the
> companion: its three P2 property violations are re-confirmed here with new
> evidence, and this round's new findings are numbered F-16-xx.

---

## 1. Executive summary

**The exact-byte boundary held again.** Every mutation tried against the
reference path — instruction data, account order, duplicate accounts, signer
and writable bits, fee payer, sibling instructions declared or undeclared,
truncated, empty, wrong, odd-length and non-hex labels, message-only frames,
v0-shaped bytes without a lookup section, two signature slots against a
one-signer header, a trailing byte — was refused before signing, in the Core
(L2 fails, `approved: false`) and independently in the bridge
(`assertApproved` recomputes the digest, `signAndFreeze` compares the message
slice). Both deliberate breaks of that boundary were caught by the existing
suite (§11).

**What did not hold is the layer that is supposed to notice when the boundary
was not used.** The Core accepts an artifact whose signature slots already hold
real signatures (`skip_signatures` never reads them), approves it as
`artifact_bound`, and records `scope.transaction_sha256 = SHA256(raw bytes)`.
L8 joins executions to verifications by `SHA256(bytes with slots zeroed)`, and
when the chain's bytes are available it consults **only** that key. Measured:
a pre-signed artifact **refused** under Treasury, then placed on the mock chain
under its own signature, reconciles as `NoVerificationOnRecord`,
`discrepancy: false`. The same query with the RPC unable to return the bytes
reconciles as `BlockedButExecuted`, `discrepancy: true`. The stronger evidence
path produces the weaker alarm (**F-16-01**, Medium, SECURITY PROPERTY
VIOLATION — it is Round 15's F-15-04 with its consequence now demonstrated).

**The trusted baseline can be frozen by anyone who can ask.** Ten requests with
identical compute — none of which need to be approved; requests that fail L2
and requests whose simulation *errors* both count — establish a zero-variance
baseline, after which every honest transaction of that program at any other
CU is refused with the risk finding `SimulationSpoofing` (measured: 450 CU
clean; 451, 460, 600 and 150 CU all Blocked). Flagged observations never enter
the accumulator, so the baseline never recovers without an operator reseed
(**F-16-02**, Medium, availability of the gate; **F-16-03** is the widened
eligibility that makes it cheap — a request refused at the structural gate
still trains the baseline).

**Everything else is design and hygiene**, listed in §4 and §5: CPI targets
are declared by the caller although the simulator's `innerInstructions` carry
the real ones (F-16-05); PDA seed templates fall back silently rather than
refusing (F-16-06); a panicking third-party Risk plugin loses its block
(F-16-07); a `min_confidence` above 1 is a 500 rather than a 400 (F-16-08);
`content_hash` is an unframed concatenation (F-16-09); the console renders a
manifest's `website`/`github` as an `href` without a scheme check (F-16-10);
L8 attribution by digest is last-wins (F-16-11); the devnet demo executes
without the residual policy and teaches a permissive profile (F-16-12,
= F-15-06); the CI test job runs `cargo test` without `--locked` (F-16-13).

No finding in this round lets a caller make the **reference bridge** sign a
transaction Graphite did not approve. Two findings (F-16-01, F-16-11) let a
caller shape what the audit trail says about a transaction afterwards; two
(F-16-02, F-16-03) let a caller decide what the gate will refuse for everyone
else. The twelve historical bypass classes re-checked in Round 15 were
re-checked here on identical code and remain CLOSED (§8).

Counts: 40,713 lines of Rust production source in 26 modules and 39,902 lines
in 82 Rust test files were in scope; 27 bridge files, 11 SDK files, 2 Python
files, 12 console files, the oracle, CI, Docker and compose were read. 3
confirmed property violations (one new in consequence, two new in reach), 1
confirmed availability finding, 9 design weaknesses / hygiene items, 1
integration footgun (standing), 12 historical classes CONFIRMED CLOSED, 2/2
deliberate breaks caught, 14 missing adversarial tests named.

---

## 2. Repository state

| Item | Value |
|---|---|
| Branch / HEAD | `main` / `e95857d4c0e1f1b3f801697acc727ca79dd96c25` |
| Uncommitted | none tracked; untracked `.agents/`, `.claude/` (tooling, not Graphite) |
| Last 10 commits | `e95857d` R15 report · `21c0a7b` console two anatomies · `3b18717` console Supabase idiom · `7cb55bd` Rounds 13–14 · `eaee998` R12 CI record · `97c1250` R12 pin · `1e521ba` Round 12 · `6957f3d` R11 CI record · `b75ce57` Round 11 · `63fc068` R10 CI record |
| Code identical to | `21c0a7b` (Round 15's audited commit) — `git diff --stat` over graphite-core, sdk, integrations, dashboard, python-ai-layer, tools, .github, Dockerfile, compose is empty |
| Tracked files | 385: 109 `.rs`, 30 `.ts`, 5 `.go`, 19 `.py`, 131 `.json`, 46 `.md` |

Inventory (tracked paths):

| Category | Where | Count / size |
|---|---|---|
| Rust production | `graphite-core/src/*.rs`, `src/plugins/*.rs`, `src/bin/graphite.rs` | 26 files, 40,713 lines (`verification.rs` 7,292; `server.rs` 5,627; `durable.rs` 2,670; `state_diff.rs` 2,546; `cli.rs` 2,407; `manifest.rs` 2,011; `risk_engine.rs` 1,940; `rpc_client.rs` 1,686; `manifest_registry.rs` 1,627; `tx_pattern_analysis.rs` 1,434; `benchmark.rs` 1,355; `account_resolution.rs` 1,245; `tx_artifact.rs` 1,156; `plugin_orchestrator.rs` 1,146; `simulation_integrity.rs` 991; `live_corpus.rs` 988; `semantic_graph_store.rs` 970; `regression_engine.rs` 684; `confidence_engine.rs` 491; `event_logger.rs` 390; `policy_engine.rs` 388; `solana_types.rs` 329; `fake_rewards_drainer.rs` 257; `transaction_builder.rs` 249; `lib.rs` 85; `plugins/mod.rs` 67; `unknown_protocol_mode.rs` 20) |
| Rust tests | `graphite-core/tests/*.rs` (+8 JSON fixtures) | 82 files, 39,902 lines |
| Rust binaries | `src/bin/graphite.rs` (server, healthcheck, verify, registry, graph, execution…) | 1 |
| TypeScript production | `integrations/solana-agent-kit/{artifact,auditbind,bound-instruction,execution-lifecycle,graphite-sak-bridge,residual-policy}.ts`; `sdk/typescript/src/{auditbind,client,index,types}.ts`; `dashboard/src/**` | 6 + 4 + 12 |
| TypeScript tests | 9 `*.test.ts` in the bridge, 2 in the SDK | 11 |
| TypeScript tooling / demos | `demo.ts`, `devnet-test.ts`, `emit-artifact-fixture.ts`, `emit-corpus.ts`, `build_exploit_corpus.mts`, `mainnet-benchmark.ts`, `rpc-fixtures.cjs`, `scripts/patch-rpc-websockets.cjs` | 8 |
| Go SDK | `sdk/go/{graphite,auditbind}.go` + 3 test files | 2 + 3 |
| Python | `python-ai-layer/intent_parser.py` (+ test), `tools/mainnet-sample/fetch_mainnet.py`, 17 manifest-building scripts under `graphite-core/scripts/` | 20 |
| Runtime oracle | `tools/runtime-oracle/src/main.rs` (own workspace + lockfile) | 711 lines |
| Manifests / fixtures | `graphite-core/protocols/*.json` (34), `fixtures/corpus` (40), `fixtures/artifacts` (7), `e2e-scratch/idls` (7), `tests/fixtures` (8) | 96 |
| Schemas | `schemas/{proposed-intent-v1,verification-result-v1}.json` | 2 |
| CI / build | `.github/workflows/ci.yml` (340 lines, 7 jobs), `Dockerfile`, `docker-compose.yml`, `.dockerignore`, `.env.example` | 5 |
| Docs | `docs/*.md` (28), root `*.md` (7) | 35 |

---

## 3. Architecture reconstruction — what the code actually does

The pipeline as implemented (file:function), and for each boundary the
authoritative representation and what the caller controls.

| Stage | Where | Authoritative | Caller-controlled | Notes |
|---|---|---|---|---|
| Intent | `python-ai-layer/intent_parser.py` → `proposed_intent` | nothing | everything | Advisory. `confidence_of_parse` 99.0 and −5.0 produced identical approval (measured). Only `intent_type` words reach a decision: Check 7/8/9, L5 semantic, the FakeRewards plugin, IntentAlignment (0.10 weight) |
| Request | `server.rs:verify_handler` → `VerificationInput` | JSON schema (serde, deny-unknown for enums) | all fields | 1 MB body, 10 s timeout, 32 in flight, 30 req/s/IP, ≥32-char Bearer key or loopback dev mode; 256 accounts, 256 declared instructions, 32 CPI targets, 1232-byte artifact, all measured |
| Label → identity | `verification.rs:3843` `effective_discriminator` | first 8 bytes of `instruction_data` | label only | Label is checked to be a prefix of the data (L2) and drives Check 2's empty arm and `risk_discriminator` (`:4343`) |
| Manifest lookup | `manifest.rs:find_instruction` (prefix match on selector) | keyed on the bytes | none | Ambiguous prefixes refused at load |
| Account resolution | `account_resolution.rs:156 resolve_accounts` | manifest roles + artifact metas | `account_addresses` (must equal the artifact's at the located position or L2 fails) | PDA re-derivation, constant pins, privilege compare. Mismatches collected by address (F-16-14) |
| Artifact | `tx_artifact.rs:parse_transaction` | the bytes | the bytes | Legacy + v0; runtime-strict framing; signature slot *contents never read* (F-16-01) |
| Correspondence | `verification.rs:3954` L2 | artifact instruction at located index | description | Program, exact data, accounts per position; every sibling matched or L2 fails (`SiblingCoverage::complete`, break B3 caught) |
| ALT | `tx_artifact.rs:930 resolve_lookups`, `:819 decode_lookup_table` | fetched tables | table addresses inside the bytes | Unresolved positions pass L2 as "not compared" and surface as `lookup_tables_unresolved`; approval not conditioned on resolution (F-15-05 stands) |
| Privileges | header + key order (+ tables) | artifact | `real_account_metas` compared, never trusted | Lying/short/absent metas had no effect (measured) |
| Simulation | `rpc_client.rs:987/1101`, `parse_simulation_value` | RPC response, derived fields only | none | `accountWrites`/`cpiHops` derived from balances / innerInstructions; provider-named fields only compared. `err` **not** part of `rpc_sim_ok` (F-15-02) |
| Baseline | `semantic_graph_store.rs:355 record_simulation` ← `verification.rs:5446` | accumulator | indirectly: every RPC-simulated request trains it, approved or not (F-16-03) | Zero-variance freeze (F-16-02) |
| State diff | `verification.rs:164 build_rpc_state_diff` ← `:5228` | pre (`getMultipleAccounts`) / post (`simulateTransaction.accounts`) | none | Missing pre or post entry is `None` → created/deleted → conservation fails (fail-closed); `err != null` → no diff, `no_state_diff` residual, L4 structural pass |
| Risk | `risk_engine.rs:assess` ← `verification.rs:4366` | mixed | `cpi_targets` (Check 1), `intent_type` (7/8/9), `account_addresses` (bound by L2 when artifact present) | Checks 2/3/5/10 keyed on `risk_discriminator`; identity mismatches → `MaliciousAccountChange`; plugin blocks → `PluginBlock` |
| Confidence | `confidence_engine.rs` ← `verification.rs:5665` | manifest tier (capped OfficialManifest), graph counters | none directly | `SimulationMatch = sample_count/3` (F-15-01) |
| Policy | `policy_engine.rs:evaluate_policy` ← `server.rs:1332 enforce_wallet_profile` | server clamp ≥0.55 unless permissive/pinned | `wallet_profile` | NaN/∞/unknown → 422; >1.0 → 500 (F-16-08); <0.55 raised with disclosure |
| Approval | `verification.rs:5801-5851` | `structural_layer_failed`, `l6_passed`, risk `Clear` | — | `approved = l6_passed && risk Clear`, L2/L4/L5 hard gate |
| Scope | `verification.rs:1258 verification_scope` | `SHA256(raw bytes)` + residual codes | the bytes (including their signature slots) | F-16-01 |
| Audit | `durable.rs:append` (fdatasync), `server.rs:1504` | append-only JSONL, indexed | — | Audit write failure → verdict withheld (503 `AuditWriteFailed`) |
| Bridge | `artifact.ts:BoundTransaction`, `execution-lifecycle.ts:executeBoundTransaction` | the private `Transaction` object, re-serialized | — | approved → `ResidualPolicy.assertExecutable` → `signApproved` → signing event (must resolve by `audit_trail_id`, approved) → `sendRawTransaction` → submission event (retried) → confirm → L8 |
| L8 | `verification.rs:2193 verify_execution` | chain bytes bound to the signature (`bound_artifact_sha256`, break B2 caught) | keys, used only when chain bytes are absent | Chain digest lookup is exclusive when present (F-16-01) and last-wins (F-16-11) |

---

## 4. Confirmed findings

Categories: **A** direct approval bypass · **B** trust/evidence poisoning ·
**C** integration footgun · **D** transaction identity / attribution ·
**E** RPC trust · **F** reliability/hygiene.

### F-16-01 — an artifact signed before it was shown is approved, and then cannot be found (Medium, CONFIRMED, SECURITY PROPERTY VIOLATION, category D)

- **Location.** `graphite-core/src/tx_artifact.rs:323 skip_signatures` (contents
  never read); `graphite-core/src/verification.rs:1380`
  (`transaction_sha256: hex::encode(Sha256::digest(bytes))`);
  `verification.rs:2258-2340` (`chain_transaction_sha256` computed via
  `artifact_sha256_of_signed` = zeroed slots; when `Some`, it is the *only*
  key consulted: `if let Some(digest) = &chain_transaction_sha256 { … } else if
  let Some(id) = keys.audit_trail_id { … }`).
- **Root cause.** Two digests for one artifact (F-15-04) plus an exclusive
  lookup order. `parse_transaction` accepts any 64 bytes per slot; the API
  contract stated in `sdk/typescript/README.md:28` ("signature slots empty")
  and `sdk/go/graphite.go:179` is not enforced anywhere.
- **Preconditions.** A caller with API access who signs before verifying (or
  verifies a transaction fetched from the chain).
- **Attack path.** (1) Sign the transaction; (2) `POST /verify` with the
  signed bytes → `approved` (or refused — it does not matter),
  `scope.kind = artifact_bound`, `transaction_sha256 = SHA256(signed)`;
  (3) submit; (4) any later `POST /verify/execution` for that signature with a
  reachable RPC computes `SHA256(zeroed)` from the chain's bytes, finds no
  record under it, and returns `NoVerificationOnRecord`, `discrepancy: false`.
  The refused verification is on the trail but is never reached.
- **Reproduction (measured, loopback Core `7661`, mock RPC `7660`).**

  | Artifact | Verify | L8 with chain bytes | L8 with `getTransaction: null` |
  |---|---|---|---|
  | unsigned (zeroed slots), Gaming | approved, `05c0bccb…` | `ApprovedAndExecuted`, attribution `chain` | — |
  | same bytes, real ed25519 signature in slot 0, Gaming | approved, `153949903a…` | resolves to the *unsigned* verification of the same bytes (`caller_keys_disagree` lists both keys) | — |
  | pre-signed only, Gaming (2,000,001 lamports) | approved, `53f222c4…` | **`NoVerificationOnRecord`**, `recorded_approved: null`, `caller_keys_disagree: ["transaction_sha256 53f2… was supplied; the chain's bytes for this signature digest to 520a49f1…"]` | `ApprovedAndExecuted` by `audit_trail_id` |
  | pre-signed only, **Treasury → refused** (3,000,001 lamports) | approved: false, `c41c8476…` | **`NoVerificationOnRecord`, `discrepancy: false`** | **`BlockedButExecuted`, `discrepancy: true`** |
  | 64 × `0xff` in slot 0 | approved, `4dd81317…` | (not on chain; would be `FirstSlotDiffers` if it were) | — |

- **Invariant violated.** "Every execution of a verified transaction is
  attributable to its verification by evidence the caller does not control."
  Here the caller's choice of slot contents decides whether the chain evidence
  can join, and the honest RPC path is the one that loses the join.
- **Impact.** The blocked-but-executed alarm — the one detective control for a
  caller who signs around the gate — is blind for pre-signed artifacts even
  though the Core accepted them as `artifact_bound`; an honest operator who
  verifies signed transactions (e.g. a relayer, or a re-verification of chain
  bytes) sees every one of them as unverified. Also a documentation mismatch:
  the SDK READMEs promise a contract the Core does not check.
- **Existing mitigations.** The bridge always sends zeroed slots (`artifact()`
  serializes with `requireAllSignatures: false`), so the reference path is
  unaffected. When the RPC cannot return bytes, L8 falls back to the exact
  `audit_trail_id` and alarms correctly. Both verifications are on the trail.
- **Why insufficient.** L8's purpose is precisely the caller who does *not* use
  the bridge. A detector that only fires when the RPC is degraded is not a
  detector.
- **Affected.** Core (`/verify`, `/verify/execution`), console (shows the
  reconciliation), TS/Go SDK docs. Bridge: not exploitable through it.
- **Fix.** (a) In `verification_scope` (or `parse_transaction` when called from
  `/verify`), require every signature slot to be zero; refuse with a new
  `ArtifactParseError::SignaturesNotEmpty` (400, `hint: "serialize before
  signing"`). (b) Independently, compute `transaction_sha256` as
  `SHA256(unsigned_artifact(bytes))` so the two digests can never differ.
  (c) In L8, when the chain digest finds no record and the caller supplied an
  `audit_trail_id`, look that up too and report a new
  `ExecutionReconciliation::RecordedForDifferentBytes { recorded, chain }`
  — still `discrepancy: true` when the record is refused.
- **Regression test.** `tests/presigned_artifact.rs`:
  `a_presigned_artifact_is_refused_at_verify` (real signature in slot 0 → 400
  / L2 `ArtifactUnparsed`, never `artifact_bound`);
  `a_refused_presigned_artifact_on_chain_is_blocked_but_executed` (mock RPC
  returns the signed bytes; expect `BlockedButExecuted`).
- **Bridge-executable?** No. **Other SDK-executable?** Yes — any caller of
  `/verify` that signs first.

### F-16-02 — ten identical requests freeze a program's baseline (Medium, CONFIRMED, OPERATIONAL/AVAILABILITY of a security gate, category B)

- **Location.** `graphite-core/src/simulation_integrity.rs` (`check_simulation_integrity`,
  zero-variance rule), `verification.rs:5365-5446` (check-then-record; flagged
  observations never recorded), `semantic_graph_store.rs:355`.
- **Root cause.** A baseline of ≥10 samples with `std == 0` treats *any*
  deviation as maximal divergence (documented in the code as intentional), the
  flagged observation is never recorded, and every RPC-simulated request is
  eligible to be one of the ten (F-16-03).
- **Preconditions.** API access and a reachable RPC; nothing on chain.
- **Reproduction (measured).** Once the System program's baseline held ten or
  more samples, every one at 450 CU (the first ten included five refused
  requests: four at L2, one by policy), honest transfers:

  | CU | approved | L3 | L7 |
  |---|---|---|---|
  | 450 | true | clean (RPC-verified) | passed |
  | 451 | **false** | FLAGGED ">1000σ vs baseline" | Blocked `SimulationSpoofing` |
  | 460 | false | FLAGGED | Blocked |
  | 600 | false | FLAGGED | Blocked |
  | 150 | false | FLAGGED | Blocked |

  Real System transfers cost 150 CU; every other System instruction, and every
  DEX route, costs something else. On a Core whose first ten Jupiter samples
  were one attacker's identical route, every real swap is refused.
- **Invariant violated.** "A caller cannot decide what the gate refuses for
  other callers."
- **Impact.** Denial of the gate for one program per Core, permanent until an
  operator reseeds (`graphite graph seed`), with an accusatory finding
  (`SimulationSpoofing`) on every honest refusal. Fail-closed, so no theft.
- **Existing mitigations.** The direction is refusal; `graph seed` exists;
  `MIN_SAMPLES = 10` bounds nothing here (it is the attacker's budget).
- **Fix.** Eligibility first (F-16-03). Then a variance floor: treat
  `std < max(ε, k·mean)` as `k·mean` (e.g. 5 %) so a zero-variance history is a
  narrow band rather than a point; record flagged-but-`err == null`
  observations into a *shadow* accumulator that an operator can promote;
  report the frozen state on `/health` (`degraded_reasons`).
- **Regression test.** `tests/baseline_freeze.rs`:
  `ten_identical_samples_do_not_refuse_the_eleventh_at_plus_one_cu`.

### F-16-03 — requests refused at the structural gate still train the baseline (Medium, CONFIRMED, category B; widens F-15-01)

- **Location.** `verification.rs:5446` — `if rpc_sim_ok && sim_flagged != Some(true) { record_simulation }`.
  Neither L2's result, nor L4's, nor the risk verdict, nor the policy verdict is
  consulted.
- **Reproduction (measured).** Fresh data dir. Three requests whose
  `transaction_instructions` declared a sibling that did not exist (L2
  **failed**, L4 failed, approved: false) → L3 reads "3 of 10 samples needed";
  an honest fourth → "4 of 10", confidence already 0.64. A wrong-label request
  (`03000000` on `02000000` bytes; L2 failed) → L3 "clean", sample recorded.
  Simulations with `err: {"InstructionError":[0,{"Custom":1}]}` and
  `err: "BlockhashNotFound"` → sample recorded, L3 "clean (RPC-verified)",
  **approved: true** with `no_state_diff` residual (F-15-02 re-confirmed).
- **Invariant violated.** "Only observations Graphite would have acted on are
  evidence."
- **Fix.** Record only when `sim_res.err.is_none() && !structural_layer_failed
  && risk == Clear` (the observation of a transaction the gate approved), and
  never from a request the server answered with 4xx/5xx (today a
  `PolicyEvaluation` 500 still records — F-16-08).
- **Regression test.** `tests/baseline_eligibility.rs`:
  `an_l2_refused_request_does_not_grow_the_baseline`,
  `an_errored_simulation_does_not_grow_the_baseline_even_with_units`.

### F-16-04 — the existing residual for a failed simulation does not say it failed (Low, CONFIRMED, category F; part of F-15-02)

- **Location.** `verification.rs:1275-1280` — `NoStateDiff` prose: "the
  transaction was simulated but no pre/post state diff was built".
- **Measured.** `err: {"InstructionError":…}` → `unobserved_codes =
  ["no_state_diff","program_semantics","inner_instructions"]`; L3 "Simulation
  integrity clean (RPC-verified)"; L4 "State verification passed … NOTE: …
  simulation did not execute". The only place the error appears is inside L4's
  reason string.
- **Fix.** A distinct `UnobservedCode::SimulationFailed` carrying the error;
  L3 must not report "clean" when `sim_res.err.is_some()`.

### F-16-05 — CPI targets are declared, not measured (Design weakness, Low–Medium, category E)

- **Location.** `verification.rs:4366` (`cpi_targets: input.cpi_targets.clone()`
  into `RiskAssessmentInput`); `rpc_client.rs:parse_simulation_value` reads
  `innerInstructions` only to *count* hops.
- **Why it matters.** Check 1 (unexpected CPI) and Check 4 (compositional
  drain) consume the caller's list; omitting it disables them. The response
  the Core already parses carries each inner instruction's `programIdIndex`
  against the loaded account keys, so the real CPI target set is available
  and unused. The inherent `inner_instructions` residual discloses this, and
  the bridge refuses nothing on it because it is inherent.
- **Fix.** Derive `cpi_targets_observed` from `innerInstructions[*].instructions[*].programIdIndex`
  mapped through the message's static keys + `loadedAddresses`; feed Check 1
  with the union and fail on a declared list that omits an observed target;
  drop `inner_instructions` from the inherent set once measured.

### F-16-06 — PDA seed templates fall back instead of refusing (Design weakness, Low; = F-15-08, re-derived from source)

- **Location.** `account_resolution.rs:354-414 resolve_pda_seed_template`,
  `:416-434 parse_slice_template`, `manifest.rs:300-308 validate`.
- **Behaviour.** `{account_99}` → the literal bytes `{account_99}`;
  `{account_0:0:8}` with no such account → empty seed; `{instruction_data:8:10}`
  with short or absent data → empty seed; reversed range → empty; `{foo}` →
  literal; `0xZZ` → literal `0xZZ`; malformed slice → whole data. Only
  `{`-without-`}` is refused at load. All 34 shipped manifests were checked
  programmatically: every `{account_N}` index is within its instruction's
  declared account count, no self-references, every `{instruction_data:a:b}`
  has `a < b` and starts past the discriminator, every `0x…` seed is valid hex.
- **Consequence.** A wrongly derived PDA never matches the real account, so the
  slot is flagged `pda_mismatch` → Blocked (fail-closed for honest input). A
  false "identity confirmed" needs the caller to place the degenerate PDA in
  the slot — an address only the program itself could have created. No
  execution path found. Unsupported syntax is still silently accepted, which
  the brief rightly names as a manifest-authoring hazard.
- **Fix.** Return `Result` from the resolver; refuse verification (L2 fails,
  `AccountResolutionError::UnsupportedSeedTemplate`) on any template outside
  the grammar `{program_id} | {instruction_data} | {instruction_data:a[:b]} |
  {account_N} | {account_N:a[:b]} | 0x<even hex> | literal-without-braces`;
  validate the same grammar at manifest load and reject `a >= b` and
  out-of-range `N`.

### F-16-07 — a panicking Risk plugin loses its block (Design weakness, Low)

- **Location.** `plugin_orchestrator.rs:557-570 run_family` — `catch_unwind`
  → `PluginVerdict::Note("… panicked and was isolated (no verdict applied)")`;
  `:619 risk_outcome` treats a Note as a warning.
- **Assessment.** The only shipped blocking plugin (`fake_rewards_drainer.rs`)
  has no panic site reachable from input (`to_lowercase`, `contains`, `iter`
  only) and is triggered solely by caller-declared intent words, so it is not
  an adversarial control. For a third-party Risk plugin loaded from
  `GRAPHITE_PLUGINS_DIR`, an input that panics it turns its block into a
  warning: fail-open for that plugin's check. The module header calls this
  "core verdict preserved"; the core verdict without the plugin is a pass.
- **Fix.** For `PluginFamily::Risk` and `Verifier`, a panic becomes
  `Block { pattern: "<name>:panicked" }`; keep Note semantics for
  Simulation/Analytics families. Also: `GRAPHITE_PLUGINS_DIR` load failure
  logs and continues (`server.rs:592-600`) — make it a startup error.

### F-16-08 — `min_confidence` above 1.0 is a 500 (Low, CONFIRMED, category F)

- **Location.** `server.rs:1353-1372 enforce_wallet_profile` clamps only
  `!is_finite() || < 0.55`; `policy_engine.rs:141-152` then rejects `> 1.0`
  with an error the handler maps to 500 `PolicyEvaluation`.
- **Measured.** `{"Custom":{"min_confidence":2.0,…}}` and `1.0000001` → HTTP 500
  "internal verification error — the request was not approved". By code
  order `record_simulation` (`:5446`) precedes L6, so such a request still
  trains the baseline (F-16-03; inferred from source, not separately measured). NaN, ±∞,
  `"NaN"`, unknown tier, `"Bogus"`, `{}`, `null` → 422 (correct).
- **Fix.** Validate `0.0..=1.0` in `enforce_wallet_profile` (400), before the
  pipeline runs.

### F-16-09 — `content_hash` is an unframed concatenation (Design weakness, Low, category D)

- **Location.** `verification.rs:6405-6420` (`program_id || discriminator ||
  addr… || data || cpi_targets`, SHA-256, first 16 hex); mirrored byte-for-byte
  in `sdk/typescript/src/auditbind.ts:61-73`, `integrations/solana-agent-kit/auditbind.ts`,
  `sdk/go/auditbind.go:66-78` (three reimplementations, all pinned to the
  vector `afb61d8865b4cb68` — parity confirmed).
- **Consequence.** Boundary-shift collisions are trivial: `accounts [A, B],
  data = ∅` and `accounts [A], data = bytes(B)` hash identically. `content_hash`
  is the coarsest L8 key and the AuditBind TOCTOU key; both are already
  documented as weaker than `audit_trail_id`/`transaction_sha256`, and the
  bridge signs only after the exact-id resolution. No exploit path found.
- **Fix.** Length-prefix each field and add a domain tag (`"graphite-ch-v2"`);
  bump the pinned vectors in all four places together.

### F-16-10 — the console renders manifest URLs as links without a scheme check (Low, DASHBOARD, Suspected-exploitable)

- **Location.** `dashboard/src/views/ProgramsView.tsx:200-206` — `<a href={manifest.protocol.website} target="_blank" rel="noreferrer noopener">`;
  `manifest.rs:274 validate` does not constrain `website`/`github`.
- **Preconditions.** A community manifest carrying `"website":"javascript:…"`
  accepted through the CLI review gate (`graphite registry submit/accept`),
  then merged into the served registry, then an operator clicks. Modern
  browsers refuse `javascript:` navigations for `noopener` new windows, which
  is why this is Suspected rather than Confirmed; `data:` top-level navigation
  is blocked outright.
- **Fix.** Render the link only when `URL(...).protocol` is `http:`/`https:`;
  validate the same at manifest load. Everything else the console renders is
  React text (no `dangerouslySetInnerHTML`, no `innerHTML`; all internal
  `href`s are `hrefFor()` hash routes).

### F-16-11 — L8 attribution by digest is last-wins (Design weakness, Low, category D)

- **Location.** `durable.rs:1145 find_verification` — the index stores the
  *latest* offset per key; archives searched newest-first, last match wins.
- **Consequence.** The same bytes verified twice — refused under Treasury,
  then approved under Gaming (the profile is caller-chosen unless
  `GRAPHITE_WALLET_PROFILE` pins it) — reconcile as `ApprovedAndExecuted`. The
  refusal is on the trail but the reconciliation does not mention it.
- **Fix.** When several verifications exist for the chain digest, report the
  count and whether any was refused (`recorded_verdicts: {approved: n,
  refused: m}`); pin the profile in deployments that care.

### F-16-12 — the devnet demo executes without the residual policy and teaches a permissive profile (Integration footgun, Low, category C; = F-15-06, standing)

- **Location.** `integrations/solana-agent-kit/devnet-test.ts:173` (`wallet_profile: { Custom: { min_confidence: 0.0, min_trust_tier: "Unknown" } }`),
  `:189-219` (gates on `approved` + `scope.kind === "artifact_bound"`, then
  `signApproved` → `sendRawTransaction`; no `ResidualPolicy`, no signing or
  submission lifecycle event, no L8). `sdk/go/graphite.go:9-40` package doc
  gates on `Approved` + `IsArtifactBound` + AuditBind only.
- **Consequence.** Copy-paste of the file "most likely to be copied" (its own
  comment) yields an executor that signs a `not_simulated` or
  `lookup_tables_unresolved` approval and never records the signing.
- **Fix.** Route the demo through `executeBoundTransaction`; drop the
  permissive profile (the server clamps it to 0.55 anyway and discloses the
  override); add the residual check to the Go doc example.

### F-16-13 — CI runs `cargo test` without `--locked` (Supply chain, Informational)

- **Location.** `.github/workflows/ci.yml:46-84` (`cargo fmt`, `cargo check`,
  `cargo clippy`, `cargo test --release`, none with `--locked`); the Docker
  build (`Dockerfile:40,50`) and the oracle job (`ci.yml:128,131`) do use it.
- **Consequence.** A `Cargo.lock` that drifts from `Cargo.toml` would be
  silently re-resolved in the test job rather than failing; the image build
  would catch it later, but the tests that passed would have run against
  different dependency versions than the image ships.
- **Everything else checked is pinned:** every action by commit SHA with a
  version comment, toolchain 1.98.1, `cargo install cargo-audit --locked
  --version 0.22.2`, base images by digest, `npm ci` only (the `|| npm install`
  fallback was removed), `pip install --require-hashes`, `permissions:
  contents: read`, read-only `GITHUB_TOKEN`. Only `apt-get install
  ca-certificates` in the runtime image is version-floating.
- **Fix.** Add `--locked` to the four cargo invocations.

### Hygiene items (Informational)

- **F-16-14** `account_resolution.rs:201-283` collects `pda_mismatches` and
  `expected_address_mismatches` **by address** and re-derives the flag with
  `contains(&pk)`. Direction is over-flagging (a matching slot that shares an
  address with a mismatching slot is also flagged), never under-flagging; a
  mismatched slot is always in the list. Collect by slot index anyway.
- **F-16-15** `GRAPHITE_RATE_LIMIT=inf` disables rate limiting (`per_second.max(0.1)`
  admits ∞); `NaN` becomes 0.1 req/s. Operator-only; reject non-finite.
- **F-16-16** The Go CI job uses go 1.22.12 while `go.mod` declares 1.21 and
  the local toolchain is 1.26.7; the console CI uses node 20 against a local
  v24. No behavioural consequence found; pin `go.mod` to the CI version.

---

## 5. Finding matrix

| ID | Severity | Status | Category | Component | Exploitable by reference bridge? |
|---|---|---|---|---|---|
| F-16-01 | Medium | CONFIRMED (property violation) | D | Core `/verify`, `/verify/execution` | No (bridge sends zeroed slots); yes for any other `/verify` caller |
| F-16-02 | Medium | CONFIRMED (availability) | B | Core L3/L7 | Affects the bridge's users (their honest requests refused) |
| F-16-03 | Medium | CONFIRMED (widens F-15-01) | B | Core `record_simulation` eligibility | Indirect (confidence pumping; F-15-01) |
| F-16-04 | Low | CONFIRMED | F | Core scope/L3 wording | — |
| F-16-05 | Low–Medium | DESIGN WEAKNESS | E | Core risk Check 1/4 | Disclosed by inherent residual; not refused |
| F-16-06 | Low | DESIGN WEAKNESS (= F-15-08) | — | Core account resolution / manifest load | No |
| F-16-07 | Low | DESIGN WEAKNESS | — | Plugin orchestrator | No shipped plugin affected |
| F-16-08 | Low | CONFIRMED | F | Server profile validation | No |
| F-16-09 | Low | DESIGN WEAKNESS | D | Core + 3 SDK reimplementations | No |
| F-16-10 | Low | SUSPECTED | dashboard | Console | No |
| F-16-11 | Low | DESIGN WEAKNESS | D | L8 / durable index | No |
| F-16-12 | Low | INTEGRATION FOOTGUN (= F-15-06) | C | devnet demo, Go doc | Not the bridge; a copy of the demo |
| F-16-13 | Info | SUPPLY CHAIN | — | CI | — |
| F-16-14/15/16 | Info | HYGIENE | — | account resolution, server env, CI toolchains | — |
| F-15-01 | P2 | CONFIRMED OPEN (re-measured) | B | Core confidence | Yes — bridge signs the pumped approval |
| F-15-02 | P2 | CONFIRMED OPEN (re-measured) | B/E | Core L3 | Refused by bridge via `no_state_diff` |
| F-15-03 | P2 | PARTIAL, OPEN | B | Core Check 10 | Policy floor still refuses |
| F-15-05 | P2 | DESIGN WEAKNESS, OPEN | A/D | Core ALT | Refused by bridge via `lookup_tables_unresolved` |
| F-15-07/09 | P3 | OPEN (documented) | — | server clamp axis; lifecycle across rotation | No |

---

## 6. Attack paths

### 6.1 Sign first, verify second, never be seen (F-16-01)

Attacker holds the agent's key and a Core API key. Builds a drain, signs it,
verifies the signed bytes (so the trail shows an `artifact_bound` verdict —
refused or approved, it does not matter), submits. An operator's L8 sweep with
a healthy RPC returns `NoVerificationOnRecord` for the signature. The refusal
exists on the trail under a digest no chain evidence can produce. Only an
operator who greps the trail for the raw-bytes digest, or whose RPC happens to
fail `getTransaction`, learns the gate said no. Cost: one extra 64-byte field.

### 6.2 Freeze the gate for everyone (F-16-02 + F-16-03)

Attacker with API access sends ten requests for program P whose simulation
consumes exactly N CU (a fixed simple route, or any deterministic instruction).
None needs to pass L2 — a bogus declared sibling is fine — and the simulation
may even error. From the eleventh request onward every transaction of P at
CU ≠ N is Blocked with `SimulationSpoofing`. On a shared Core this is a denial
of every honest agent's swaps on P until an operator notices `degraded` is
still `false` (F-16-02's fix asks for it to be reported) and reseeds. Cost: ten
HTTP requests; nothing on chain.

### 6.3 Earn the approval by asking (F-15-01 + F-16-03, re-measured)

Refused at 0.507 under Gaming on the first call; the same bytes approved on
the second call at 0.573 (Round 15's numbers). This round shows the samples can
be earned with requests that fail L2 outright, so the pumping traffic never
needs to describe a real transaction. The bridge signs the second answer. This
remains the strongest confirmed path to a *bridge-executed* approval the gate
would have refused a minute earlier; it is not a bypass of the byte boundary
— the bytes signed are the bytes approved — it is the approval itself being
cheap.

### 6.4 Paths that are closed (measured this round)

Wrong/short/empty/odd/non-hex label; swapped, duplicated or substituted
accounts; unsigned "from" account with and without lying metas; short or
absent metas; undeclared, mis-declared, empty-labelled, one-byte-labelled and
double-declared drain siblings; message-only, v0-shaped, two-slot and
trailing-byte frames; empty artifact (descriptive, refused by the bridge);
artifact without data; data disagreeing with the bytes; `min_confidence` −1/0
(clamped, approved only because the real confidence was 0.64); NaN/∞/unknown
profiles; `confidence_of_parse` 99/−5; 5,000-deep JSON; 1.1 MB body; 4,000
declared siblings; 300 accounts; 20,000-byte data; 5,000 CPI targets;
1,300-byte artifact; 40 concurrent identical requests; L8 with a garbage slot,
another transaction's bytes, a slot contradiction, a status/meta contradiction,
processed-only commitment, no keys, content-hash-only, unknown signature.

---

## 7. Security invariants — enforced or not

| Invariant | Where enforced | Verdict |
|---|---|---|
| The message approved is the message signed and submitted (bridge) | `assertApproved` re-serialize + `signAndFreeze` message compare + private `tx` (`artifact.ts`) | ENFORCED (break B3 of the Core side caught; bridge tests `toctou-signing-boundary`, `execution-boundary-fuzz`) |
| The described instruction is in the bytes at one position with exact data and accounts | L2 `verification.rs:3954` | ENFORCED (measured) |
| Every instruction in the artifact is described and every description matches one | `SiblingCoverage::complete` | ENFORCED (break B3 caught by 6 tests) |
| Privileges come from the artifact, never the caller | `PrivilegeSource::Artifact*`; metas compared only | ENFORCED (measured) |
| Manifest lookups key on the instruction's bytes | `effective_discriminator` | ENFORCED; residue F-15-03 for Check 10 |
| Chain bytes are attributed only when bound to the signature | `bound_artifact_sha256` | ENFORCED (break B2 caught by 2 tests) |
| Every verified execution is attributable by evidence the caller does not control | L8 chain digest | **NOT ENFORCED for pre-signed artifacts (F-16-01)** |
| Only observations of transactions the gate would act on become evidence | `record_simulation` gate | **NOT ENFORCED (F-16-03; F-15-01/02)** |
| A caller cannot decide what the gate refuses for others | baseline | **NOT ENFORCED (F-16-02)** |
| Missing state is never "no change" | `parse_account_value` (mandatory lamports/owner), `None` deltas, conservation | ENFORCED (source; `LamportsNotConserved` hit when fee unknown in Round 15) |
| `err != null` never becomes trusted evidence | — | **NOT ENFORCED (F-15-02)**; L4 diff correctly refuses it |
| Caller-supplied thresholds cannot weaken policy | `enforce_wallet_profile` | ENFORCED (confidence axis); tier axis F-15-07; >1.0 → 500 (F-16-08) |
| Parser confidence cannot influence approval | no consumer | ENFORCED (measured) |
| Approval is conditioned on lookup resolution | — | NOT ENFORCED by design (F-15-05); disclosed and refused by the bridge |
| Durable nonce refused by default; verified on-chain when permitted | `durable_nonce`/`check_durable_nonce` | ENFORCED (instruction-0 rule matches the runtime) |
| Audit write failure withholds the verdict | `server.rs:1559` | ENFORCED |
| Signing is on the trail before submission; the trail's verdict must be `approved` by exact id | `execution-lifecycle.ts:153-190` | ENFORCED (bridge) |
| Only env-configured RPC/witness URLs are dialled | `rpc_client.rs` | ENFORCED |
| Auth default-closed, ≥32 chars, constant-time | `auth_posture`, `ct_eq` | ENFORCED |
| Manifest-declared high-risk class blocks without declared intent | Check 10 | PARTIAL (F-15-03) |
| Unsupported manifest syntax is refused, never reinterpreted | — | NOT ENFORCED (F-16-06); fail-closed in effect |

---

## 8. Historical findings, re-checked on identical code

The twelve classes in Round 15 §4 were re-read at the same line numbers (the
code is byte-identical): caller-controlled prefix, empty label, secondary
instruction discriminator, wallet-profile threshold, FakeSwap/no-op, intent
synonyms, sibling ALT wildcard, signer mismatch, exact artifact binding,
RPC-returned-byte binding, L2/L4/L5 hard gate, simulation bootstrap dead path,
SSRF/destination control, auth default-closed — all **CONFIRMED CLOSED**
(sibling ALT wildcard: CLOSED as designed, F-15-05 stands; bootstrap: CLOSED,
with F-15-01/02/F-16-02/03 as its cost). Additionally re-verified against a
running Core this round: label variants (§6.4), privilege contradiction,
sibling declarations, resource bounds, L8 substitution and contradiction.

Round 15's own findings: F-15-01 OPEN (re-measured), F-15-02 OPEN
(re-measured, now with the approved-with-residual detail), F-15-03 OPEN
(source), F-15-04 OPEN → **escalated to F-16-01**, F-15-05 OPEN (source),
F-15-06 OPEN → F-16-12, F-15-07 OPEN, F-15-08 OPEN → F-16-06, F-15-09 OPEN
(documented).

Suspects A–H from the brief: **A** confirmed (F-15-01 + F-16-03 + F-16-02);
**B** confirmed (F-15-02 / F-16-04 — `rpc_sim_ok == true` with `err != null`
measured); **C** partial (F-15-03; the empty-label arm of Check 2 refuses
native programs, and an empty label does not switch off identity checks —
measured: an unsigned "from" slot is Blocked under the full label
(`MaliciousAccountChange`), a one-byte label and an empty label
(`AuthorityHijack` + `AccountIdentityMismatch`)); **D** confirmed (F-16-01);
**E** no bypass found — every real execution path in the repository is in the
sink table below; **F** design weakness confirmed from source (F-15-05), not
re-measured (no v0 builder in this round's harness); **G** design limitation
(F-16-07), no shipped plugin affected; **H** design weakness (F-16-06),
fail-closed in effect, unsupported syntax accepted.

---

## 9. Integration and execution-sink matrix

Every signing or submission sink in tracked files (`sendRawTransaction`,
`sendAndConfirmTransaction`, `sendTransaction(`, `signTransaction`,
`signAllTransactions`, `.sign(`, `partialSign`, `signAndSend`):

| Sink | File | Caller | Approval | Artifact binding | Residual policy | Additional binding |
|---|---|---|---|---|---|---|
| `connection.sendRawTransaction(raw)` | `execution-lifecycle.ts:193` | `executeBoundTransaction` ← `graphite-sak-bridge.ts:473` (transfer, swap) | required | required (`assertArtifactBound`) | **required** (`assertExecutable`) | `signApproved`, signing event by exact id, submission event, confirm, L8 |
| `this.tx.sign(...signers)` | `artifact.ts:386` | `signAndFreeze` ← `signApproved` only | (caller's) | digest re-check | (caller's) | signer set = header; message slice equality |
| `connection.sendRawTransaction(raw)` | `devnet-test.ts:218` | demo `main` | required | required | **absent** | `signApproved`; no lifecycle, no L8 (F-16-12) |
| `connection.sendRawTransaction(raw)` | `README.md:380` (example) | — | required | required | present | signing event, submission, L8 — correct pattern |
| `signing.sign(hash)` | `cli.rs:1662`, `manifest_registry.rs:610` | registry reviewer signature | n/a (not a transaction) | — | — | — |
| `payer().sign(message_bytes)` | `tests/round10_attribution.rs:163`, `round12_rpc_equivocation.rs:89` | tests | — | — | — | — |
| SAK's own builder (`sendAndConfirmTransaction`) | not imported (`graphite-sak-bridge.ts:32`) | swap fallback | only with `GRAPHITE_SWAP_ALLOW_UNVERIFIED_EXECUTION=<exact phrase>` and not `GRAPHITE_SWAP_STRICT=1` | none | none | loudly labelled unverified |

Component matrix:

| Component | Safe path | Unsafe path | Residual enforcement | Artifact binding |
|---|---|---|---|---|
| Core | `/verify` + `/audit/event` + `/verify/execution` | accepts pre-signed artifacts (F-16-01) | codes emitted, not enforced (by design) | `scope.transaction_sha256` (raw bytes) |
| SAK bridge | `executeBoundTransaction` | unverified-swap opt-in (explicit phrase) | `ResidualPolicy` default refuses all non-inherent | `BoundTransaction` |
| TS SDK | `verify`, `recordLifecycleEvent`, `verifyExecution`, `unobservedCodes()` | none (no signing) | documented, helper provided | documented |
| Go SDK | `Verify`, `IsArtifactBound`, AuditBind | doc example omits residuals (F-16-12) | constants exported, not enforced | `IsArtifactBound` |
| Python layer | intent labelling only | none | n/a | n/a |
| CLI | `verify` (no execution), `execution` (L8 read), registry | `--profile custom` below 0.55 warns, no clamp (documented) | n/a | n/a |
| devnet demo | — | executes on `approved && artifact_bound` (F-16-12) | absent | `signApproved` |
| Console | read-only GETs, key in localStorage, hash routes | external `href` from manifest (F-16-10) | n/a | n/a |
| Examples (`examples/*.json`) | request/response samples | none | — | — |

---

## 10. Test gaps (adversarial tests that do not exist and would fail today)

1. `a_presigned_artifact_is_refused_at_verify` — F-16-01.
2. `a_refused_presigned_artifact_on_chain_is_blocked_but_executed` — F-16-01.
3. `an_l2_refused_request_does_not_grow_the_baseline` — F-16-03.
4. `an_errored_simulation_with_units_does_not_grow_the_baseline` — F-15-02
   (the existing `an_errored_simulation_never_produces_a_diff` uses
   `unitsConsumed: 0`, so `rpc_sim_ok` is false for a different reason).
5. `an_errored_simulation_never_reports_l3_clean` — F-16-04.
6. `ten_identical_samples_do_not_refuse_the_eleventh_at_plus_one_cu` — F-16-02.
7. `the_same_request_is_not_approved_on_the_second_call` — F-15-01.
8. `an_observed_cpi_target_the_caller_omitted_fails_check_1` — F-16-05.
9. `an_unsupported_seed_template_refuses_verification` — F-16-06 (today it
   derives a PDA from the literal string).
10. `a_panicking_risk_plugin_blocks` — F-16-07 (today
    `test_panicking_plugin_is_isolated_and_core_verdict_survives` asserts the
    opposite, deliberately).
11. `min_confidence_above_one_is_a_400_before_the_pipeline_runs` — F-16-08.
12. `l8_reports_every_verdict_recorded_for_the_chain_digest` — F-16-11.
13. `content_hash_is_injective_over_field_boundaries` — F-16-09 (would fail).
14. `a_manifest_website_with_a_non_http_scheme_is_refused_at_load` — F-16-10.

From Round 15 §8 the eleven tests named there are still missing; items 3–7
above overlap with four of them.

---

## 11. Deliberate-break log and recommendations

Two breaks were applied to production source, each with a `cp` backup, run
against pre-built test binaries in a separate target directory, and reverted;
digests were recorded before and after.

| Break | Change (temporary) | Tests run | Outcome |
|---|---|---|---|
| **B2** — L8 signature binding | `tx_artifact.rs:bound_artifact_sha256`: removed `key.verify_strict(...)?` (first-slot equality kept) | `round10_attribution`, `l8_execution_reconciliation` | **CAUGHT** — `round10_attribution`: 2 failed (`chain_bytes_are_accepted_only_when_bound_to_the_signature`, `an_rpc_that_substitutes_bytes_cannot_attribute_the_execution`); `l8_execution_reconciliation` 9/9 passed (does not cover binding) |
| **B3** — sibling coverage | `verification.rs:SiblingCoverage::complete` → `true` | `described_siblings`, `artifact_binding` | **CAUGHT** — `described_siblings`: 6 of 8 failed; `artifact_binding` 16/16 passed (does not cover siblings) |

Digests: `verification.rs` `177a62b0b34087fe6da91fc71256d20d7b52a4885c45e9b73ff1d74e250f89d0`
and `tx_artifact.rs` `503531bca326b48991a506a490f57be336166ce9a338186258d78e553ccb2f25`
before each break and after each restore; `git status --porcelain` shows only
the untracked tooling directories. Baseline (unbroken) runs: `described_siblings`
8/8, `l8_execution_reconciliation` 9/9, `round10_attribution` 9/9,
`artifact_binding` 16/16. Round 15's B1 (`rpc_sim_ok` without `err`) stands as
caught.

Recommended deliberate breaks for the remaining critical invariants (each
should turn at least one test red):

- L2 exact-data compare (`instruction_data` equality at the located index) →
  `round9_identity_requires_data`, `artifact_binding`.
- `PrivilegeSource::Artifact` derivation → `privilege_from_artifact`,
  `alt_privilege`.
- `enforce_wallet_profile` clamp → `server.rs` unit tests (lib test build).
- `structural_layer_failed` hard gate → `l2_l4_l5_hard_gate`.
- `ResidualPolicy.assertExecutable` unknown-code refusal →
  `residual-policy.test.ts`.
- `assertSignersMatchTheMessage` → `bound-transaction.test.ts`.
- Once added: the F-16-01 zero-slot check, and the F-16-03 eligibility gate.

---

## 12. Remediation plan

Ordered by the brief's priorities (direct approval bypass → evidence
poisoning → identity → residuals → RPC trust → footguns → reliability →
compatibility → polish). No item requires a protocol change; three change
wire semantics and need the pinned vectors regenerated together.

1. **Evidence eligibility (F-16-03, F-15-01, F-15-02).** Record a simulation
   only when `err.is_none()`, no structural layer failed, risk Clear, and the
   response is a 200. Add tests 3, 4, 7. Then decide what `SimulationMatch`
   should measure (Round 15 §10): distinct approved transactions, not calls.
2. **Baseline freeze (F-16-02).** Variance floor; shadow accumulator for
   flagged-but-successful observations; expose a frozen baseline on `/health`.
   Test 6.
3. **Pre-signed artifacts (F-16-01).** Refuse non-zero slots at `/verify`;
   hash the zeroed frame; L8 reports `RecordedForDifferentBytes`. Tests 1, 2.
   Update `sdk/typescript/README.md` and `sdk/go/graphite.go` to state the
   enforced contract.
4. **ALT approval (F-15-05).** Fail L2 on unresolved primary positions; mirror
   the runtime's `is_active` (Deactivating is active).
5. **Check 10 keying (F-15-03).** Key risk metadata on
   `effective_discriminator`; keep the empty-label refusal for native programs.
6. **Measured CPI targets (F-16-05).** Derive from `innerInstructions`; fail on
   omission. Test 8.
7. **Residual wording (F-16-04)** — `simulation_failed` code; L3 never "clean"
   on `err`. Test 5.
8. **Footguns (F-16-12).** Route the demo through `executeBoundTransaction`;
   fix the Go doc; drop the permissive profile from the demo.
9. **Reliability/hygiene.** F-16-08 (400 before pipeline), F-16-07 (Risk
   plugin panic = block; plugins dir load failure = startup error), F-16-11
   (multi-verdict reporting), F-16-13 (`--locked`), F-16-15 (finite rate
   limit), F-16-14 (mismatches by slot).
10. **Compatibility/polish.** F-16-06 (template grammar, `Result` resolver),
    F-16-09 (framed `content_hash` v2 with coordinated vector bump), F-16-10
    (scheme allowlist at load and in the console), F-16-16 (`go.mod` version).

---

## 13. Final assessment

**Proven (reproduced on this HEAD, loopback, no chain):**
the byte boundary refuses every representation-level mutation tried; the
bridge's execution path requires approval, artifact binding, a residual policy
that refuses by default, a signing event resolved by exact id, and reconciles
by chain-bound bytes; pre-signed artifacts are accepted and unjoinable by chain
evidence (F-16-01); ten identical simulations freeze a program's baseline
(F-16-02); refused and errored requests train the baseline (F-16-03, F-15-02);
repeated requests raise confidence (F-15-01); malformed profiles are 422, a
profile above 1.0 is a 500; resource bounds hold at the documented numbers;
L8 rejects substituted bytes, garbage slots, and RPC self-contradiction.

**Strongly supported (from source, not re-measured this round):** F-15-03
(empty label and Check 10), F-15-05 (unresolved ALT approval, deactivating
tables), the durable-nonce rule, the fail-closed handling of missing account
state, the plugin panic semantics, the PDA template fallbacks (grammar checked
against all 34 shipped manifests), the console's rendering surface, CI and
image pinning.

**Uncertain:** whether any browser still executes a `javascript:` href under
`noopener` (F-16-10 is Suspected); whether real programs' CU distributions
make F-16-02 trip on honest first-ten samples without an attacker (likely for
System transfers, unknown for DEXes); the lifecycle-across-rotation behaviour
under real rotation volumes (F-15-09).

**Requires live-chain testing:** the deactivating-table window (F-15-05)
against a real ALT; L8 against real `getTransaction` responses at each
commitment; the devnet demo after remediation; simulation CU variance of the
shipped protocols to calibrate the F-16-02 floor.

**Requires independent audit:** the whole of the above. This round, like the
fifteen before it, was performed by the same party that wrote the fixes, with
the code's own tests as the oracle for two of its own breaks. It reproduces
what it claims and it changed no production code, but it is not a
certification and should not be cited as one.

The answer to the brief's central question — *can a malicious caller cause
Graphite or one of its official execution paths to sign and submit a
transaction whose security-relevant behaviour Graphite did not actually
authorise?* — is: **through the reference bridge, no path was found; the
approval itself can be made cheap (F-15-01/F-16-03) and the record of it can
be made unfindable (F-16-01), and both are cheaper than the boundary they sit
beside.**

---

## Appendix — what was run

- Core: debug build of `e95857d` (`cargo build --bin graphite`,
  `CARGO_TARGET_DIR` in `%TEMP%`), `graphite server --port 7661`,
  `GRAPHITE_DEV_MODE=1`, `GRAPHITE_RPC_URL=http://127.0.0.1:7660`,
  `GRAPHITE_DATA_DIR` in the session scratchpad (fresh).
- Mock RPC: `mock_rpc.py` — `simulateTransaction` (with `accounts`),
  `getMultipleAccounts`, `getAccountInfo`, `getSignatureStatuses`,
  `getTransaction`, `getSlot`, `getLatestBlockhash`; `POST /__control` sets
  `err`, `units`, `fee`, `pre/post` balances, post-state accounts, chain bytes
  and statuses per signature.
- Transactions: `txlib.py` — legacy message builder, compact-u16, System
  transfer data, ed25519 via `cryptography` on throwaway keys derived from
  fixed seeds (`alice-r16`, `bob-r16`, `mallory-r16`); nothing funded, nothing
  broadcast.
- Probes: `p1_presigned.py`/`p1c.py`/`p1d.py` (F-16-01), `p2_baseline.py`/`p2b.py`
  (F-16-03/F-15-02), `p3_labels_policy.py`/`p3b.py` (labels, profiles,
  intent), `p5_priv_sibling.py` (privileges, siblings), `p7_freeze.py`
  (F-16-02), `p8_dos.py`/`p8b.py` (bounds, concurrency), `p9_l8.py` (L8),
  `p10_misc.py` (artifact shapes), `p11_emptylabel_identity.py` (identity under
  short/empty labels).
- Tests: `cargo test --test round10_attribution --test l8_execution_reconciliation
  --test described_siblings --test artifact_binding --test policy_profiles`
  in `%TEMP%\graphite-target-tests` (baseline, B2, B3).
- Not touched: any public RPC, any wallet or key with funds, any GitHub
  secret, the console preview.
