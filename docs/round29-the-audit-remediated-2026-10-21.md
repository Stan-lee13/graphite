# Round 29 — the audit of 2026-10-20, remediated

> **Historical record.** This report describes the codebase at commit `19a2974`
> on 2026-10-20/21, and the changes made on top of it. For the current state of
> Graphite see [`CURRENT.md`](CURRENT.md).

**Date:** 2026-10-20 to 2026-10-21 · **Base:** `19a2974` (Round 28) · **Scope:** a full-repository
audit of `19a2974` — every source file read, the most consequential findings re-checked by hand,
every suite run — and the remediation of every finding it raised, in nine areas worked in parallel
and merged here.

Internal engineering work. Not an independent audit and not a certification.

## 1. What the audit found

The audit ranked its findings on the security and correctness of the gate as shipped. It found no
way to sign bytes other than the ones approved, and it found the places where "approved" meant less
than the documents said.

| Area | HIGH | MEDIUM | LOW and informational (selected) |
|---|---|---|---|
| Core pipeline | H1: the Core approved a transaction whose simulation failed or never ran | M1: any verify-key holder could raise a program's confidence for every caller; M2: confidence and tier read the primary program only | nested request objects dropped unknown fields; `audit_trail_id` sequence restarted at 0; `with_data_dir` failed open; L5 read the raw intent |
| Agent guard and adapters | H2: a swap's delivered amount was never bounded; H3: a transfer was grounded without a verb or a direction; H4: a swap's spend was a single-simulation snapshot | M5: units and currency ignored; M6: no cap required by the SAK adapter, no aggregate; M7: approval opt-in (Vercel), elicitation before resolution (MCP); M8: the key and the decision collaborators reachable from the same process | 1-byte selectors aborted after approval; an ambiguous send could double-pay; `SOLANA_RPC_URL` had no https rule |
| Registry | — | M3: the promotion gate was no boundary against a malicious reviewer (submitter-supplied corpus, unhashed outcome, unchecked lineage, no domain separation, no revocation) | — |
| L8, server, CLI | — | M4: `/verify/execution` wrote a Graphite-attested `confirmation` for nothing seen; M9: chain-byte attribution only after finalization; M12: verification permits starved by dashboard calls | CORS `*` panicked; `/health` behind the limiter; lax environment parsing; `graphite execution` exited 0 on `Unavailable`; CLI `verify` ignored the server's boundary settings |
| Manifest data | — | M10: System `TransferWithSeed` layout wrong; admin setters classed `transfer`; 562 unclassed instructions; M14: the `BattleTested` evidence had no effect on verdicts, contrary to the README | category errors |
| RPC and state diff | — | M11: Token-2022 padded accounts falsely blocked | unreadable account data read as empty; error text unredacted; a closure-ending debit not a debit; Vote V4 unread |
| Tests | — | M13: four attack suites mapped any error to "blocked"; two of three "successful" holdout transactions had failed on chain; no approved-path guard test; the contract gate vacuous in a shallow clone | the corpus test wrote ~30 MB into `fixtures/` |
| Dashboard | — | M15: capped windows shown as totals; a failed `/metrics` read hid the bypass band | — |
| Governance | — | M16: no branch protection on `main` | — |
| Documentation | — | — | test counts stated four ways; "23 risk checks"; "simulation failure → block"; the BattleTested paragraph; the corpus size; "19-field parity"; Quick Start `curl` calls without the key; rounds 21–28 without the banner `CURRENT.md` promised |

In all: 4 HIGH, 16 MEDIUM, and LOW and informational items grouped by area (audit trail, server,
CLI, Core, RPC, simulation integrity, state diff, parser, risk engine, guard, SDKs, infrastructure,
the Python layer, scripts) plus a documentation-versus-reality table.

## 2. What changed

### Core pipeline

- **H1.** With an RPC client and an artifact, a simulation that errored is a `SimulationFailed`
  finding and L3 `Failed`; one that could not be obtained or is incomplete — an RPC error, a
  timeout, the budget, an implausible or incomplete response, an unreadable callee report, a CPI
  tree that cannot be rebuilt, a missing pre/post diff — is `VerificationIncomplete`. Both refuse.
  A simulation plugin's Block refuses too. **Without an RPC client nothing changed:** L3 is
  `Inconclusive`, the verdict carries `not_simulated`, and the agent guard's `ResidualPolicy` is what
  refuses it. That is a documented limitation, not a fix.
- **M1.** A request refused only by the confidence or tier threshold no longer trains the
  `SimulationMatch` baseline. `GRAPHITE_LEARN_FROM_POLICY_REFUSALS=1` (strict `0`/`1`/`true`/`false`,
  logged at startup) restores it, with the risk named: any verify-key holder can then lift an
  `OfficialManifest` program from 0.44 (0.20 + 0.14 + 0.10 on a fresh core) to 0.64 for every
  caller. Approved verdicts still train.
- **M2.** The verdict's trust tier is the minimum over every top-level program the transaction
  invokes — the primary, declared siblings and artifact instructions, each tiered like the primary.
  An unmanifested sibling makes it `Unknown`. The evidence signals stay the primary's.
- Every nested request type refuses unknown fields. L8: a caller-cited record whose bytes the chain
  contradicts is `NoVerificationOnRecord` with a `caller_keys_disagree` entry, never a discrepancy;
  `getTransaction` asks at the configured commitment; a check that did not see inclusion at a
  cluster-backed commitment writes an `execution_check` row, never a `confirmation` (M4, M9).
  `audit_trail_id` sequences start at a random offset; `with_data_dir` panics on a corrupt snapshot
  (`try_with_data_dir` returns the error); the witness may not be the primary in either attach
  order; L2 on an undescribed instruction is `Inconclusive`; L5's high-risk check uses the canonical
  intent.

### L3, L4 and the RPC client

- L3: robust windows store winsorized values and judge the newest 256; an invalid threshold flags.
  The detection floor is documented, not changed: flagged only beyond
  2.0 × max(spread, 0.25·|centre|, 1), so a deviation of 50% of the centre or less is never
  flagged, and the first 10 observations are learned unclamped and decide nothing.
- L4: a signer's net lamport loss beyond the fee and the rent-exempt minimum of accounts it created,
  under an interpretable manifest that declares no debit, is Critical
  (`UndeclaredSignerLamportDebit`; `UnexplainedLamportOutflow` stays the gross figure). Token-2022:
  a short all-zero or zero-type tail is padding (M11); extensions judged on both sides; a fee-terms
  change needs an authority declaration scoped to the mint; an undecodable base layout blocks for
  both token programs (`TokenLayoutUndecodable`); a 355-byte account is a Multisig; a debit that
  ends in closure is a debit. Vote V4 withdrawer and revenue collectors watched, collector offsets
  per SIMD-0185; unknown vote versions compared by data hash.
- RPC: account `data` must be a `[base64, "base64"]` pair; JSON-RPC error text is redacted as well as
  bounded; parsed-form inner instructions are named as the reason the CPI set is unknown; `Debug`
  never prints the endpoint; loopback includes IPv4-mapped addresses and `localhost.`.

### Audit trail and parser

- An archive's name stamp is the later of the wall clock and the newest stamp plus one; only exact
  generated names count as archives. A failed append is truncated away, and if that fails appends
  are refused until it succeeds; a rotation that cannot reopen refuses appends;
  `GRAPHITE_AUDIT_ROTATE_BYTES=0` warns that the active file and its indexes are unbounded. Index
  counts are cross-checked against the record they point at.
- The trail and its archive indexes are corruption-evident, not tamper-evident (unkeyed hashes, no
  hash chain). `SECURITY.md` now says the data directory must be writable only by Graphite.
- Legacy (version 0) nonce accounts are refused, as the runtime refuses them. PDA derivation tries
  bumps 255..1, as Solana does; `create_program_address` added. `transaction_builder` produces a
  validated summary, not wire bytes, and now says so.
- The runtime oracle uses the Anza SDK crates (`solana-transaction`, `solana-message`), adds a
  limits pass (frames either side of 64 instructions, 64 locks and 256 accounts) and a cross-check of
  the 32 reserved ids, and guards five of its own functions against panics.

### Risk engine

- `CHECKED_PATTERNS` is 16. Check 7 is gone: Check 2 refuses every `Approve` / `ApproveChecked`
  under any intent first, so no input reached it; the impersonation block is now 10a. 13
  `RiskPattern` variants: 12 detectors and `PluginBlock`.
- Discriminators normalised once (optional `0x`, case); one value-movement table, which now counts
  System `TransferWithSeed` and `WithdrawNonceAccount`; fan-out groups every transfer kind per
  parent, with a split across parents a whole-tree warning; depth is structural; the
  compositional-drain rule runs on the simulator's executed callees, repeats kept; the pipeline reads
  the loaded registry, so an accepted community swap manifest gets swap semantics.
- Impersonation (R-4) judges a fund movement's destination at four trailing `1`s (or a `Compu`
  prefix) and its source at five, and the signing authority of an SPL transfer not at all.
  `UnspendableDestination` covers every sysvar, the lookup-table, Config, Feature and ZK programs,
  the precompiles and the loaders.

### Manifests, registry and protocol data

- 137 manifests, 3,541 instructions (from 3,504), 113 applied `BattleTested` (114 records meet the
  bar; Metaplex Token Metadata declares `OfficialManifest`). System Program 13 instructions
  (`TransferWithSeed` corrected, `UpgradeNonceAccount` added), Token-2022 63, SPL Token 26, Metaplex
  8 (decode 100%).
- Classes: authority 1,342; transfer 1,011; create 482; withdraw 414; close 164; inert 49; mint 17;
  drain 9; stake 7; unclassed 46 (3 `Revoke`s and 43 swaps, by rule: a swap-family instruction on a
  swap program is declared only by the swap intent). 128 admin setters moved from `transfer` to
  `authority`; 95 hand overrides (`reclassify_manifests.py --list-overrides`). Categories corrected;
  41 swap-category programs.
- Manifests refuse unknown fields; a second load of a program is refused; seed templates are checked
  against runtime PDA limits; graph tiers are recomputed on snapshot restore; evidence decode rates
  are recomputed at load against the loaded manifest.
- Registry (M3): it owns its regression corpus (a submission adds fixtures and cannot remove them;
  `graphite registry deprecate-fixture` is the operator's); lineage is enforced
  (`previous_version_ref` must name the head; a refused version is never retaken); the signed
  message is domain-tagged (`graphite-manifest-registry-v1\0 ‖ program_id ‖ 0 ‖ content_hash`) over
  canonical JSON; every submission is fully validated; reviewer keys must be valid ed25519;
  `graphite registry revoke-reviewer` is permanent and recomputes tiers; the fixture integrity hash
  covers the expected outcome and the deprecated flag (unkeyed: evident, not prevented).
- Scripts: `fetch_idl.py` and `verified_idls.json` removed (`fetch_onchain_idls.py` replaces them);
  `build_manifests.py` refuses to overwrite without `--force`; `render_coverage.py` reads its figures
  from `scripts/out/mainnet_sample_named.json` and stamps no date; the regression corpus test is
  hermetic (`GRAPHITE_REGENERATE_CORPUS=1` rewrites it).

### Server and CLI

- Strict environment parsing: a value that does not parse refuses to start. New or newly documented:
  `GRAPHITE_LEARN_FROM_POLICY_REFUSALS` and `GRAPHITE_CONNECTION_LIFETIME_SECS` (120 s). CORS `*`
  refused; an events file that cannot be opened, or a corrupt registry state, refuses to start.
- `/health` is exempt from rate limiting and load shedding, reports `frozen_baseline_count`
  (the list moved to the authenticated `GET /api/frozen-baselines`) and the
  `simulation_baseline_frozen` degraded reason. 13 paths, 14 handlers, 28 Prometheus series.
  Verifications use the `GRAPHITE_MAX_CONCURRENT` permits and every other route a fixed pool of 16
  (M12). Keyless dev mode answers 421 to a non-loopback `Host`; a /48 may hold at most four times the
  per-/64 connection cap; a malformed or short `X-Forwarded-For` goes to one shared "unattributed"
  bucket; 422 text is bounded to 256 characters.
- The CLI applies the server's boundary rules through the shared `operator_boundary` module;
  `graphite execution` exits 0 clean, 1 discrepancy, 3 unavailable or misconfigured, 4 chain bytes
  rejected, 5 RPC inconsistent, 6 witness disagrees; evidence and quarantine commands take base58
  ids and write `operator_action` rows. The `server` feature no longer enables `cli`. tower 0.5,
  base64 0.22, thiserror 2, `rust-version` 1.89; `rustls-webpki` 0.103.16 and `webpki-roots` 1.0.10
  (RUSTSEC-2026-0382, RUSTSEC-2026-0381).

### Agent guard and adapters

- H3, M5: a transfer must match
  `[please] (send|transfer|pay) <ASCII amount, ≤ 9 decimals> SOL to <address>[.!]`; anything else is
  refused with the accepted form. The swap grammar is positive and anchored and may carry "for at
  least N TOKEN" and "with N% slippage".
- H2, H4: swaps only on six decoded programs, exact-in only — Jupiter v6 `route` /
  `shared_accounts_route`, Orca Whirlpools `swap` / `swapV2`, Raydium CPMM `swap_base_input`,
  Raydium CLMM `swap` / `swap_v2`, Raydium AMM v4 `SwapBaseIn`, Meteora DLMM `swap` / `swap2`
  (`route_v2` excluded: no committed IDL with the deployed layout). Amount in ≤ the request; minimum
  out > 0 and ≤ the simulated delivery; minimum out ≥ simulated × (1 − slippage), stated or
  `GRAPHITE_SWAP_MAX_SLIPPAGE_BPS` (default 100, at most 500); a price floor unless
  `GRAPHITE_SWAP_ALLOW_UNPRICED=1`. The Round 25 report said the Core reads a route's minimum; it
  does not, and `CURRENT.md` records the correction.
- M6: a per-transaction cap required by the guard in every adapter unless
  `GRAPHITE_ALLOW_UNCAPPED=1`; the policy logged at startup; a rolling aggregate
  (`GRAPHITE_MAX_TOTAL_LAMPORTS` per `GRAPHITE_SPEND_WINDOW_SECONDS`, default 3600, in memory, per
  process). Optional compute budget (priority fee ≤ 0.005 SOL) and idempotent output ATA. wSOL
  wrapping and unwrapping are not supported.
- M7: `confirm(summary)` right before signing; a decline signs nothing (`ConfirmationDeclined`). MCP
  elicits through it, after the verdict, with resolved values; Vercel's fund-moving tools carry
  `needsApproval: true` by default, and the README documents `experimental_toolApprovalSecret`.
- M8: `SOLANA_PRIVATE_KEY` deleted from `process.env` once read; decision collaborators ES-private,
  the instance frozen; `getGraphiteClient()` returns a read-only `{health, listManifests}`.
  `SOLANA_RPC_URL` must be https or loopback http, with no redirects. A failed send records a
  submission attempt and throws `SubmissionOutcomeUnknown(signature)`; a repeat is refused while the
  first can still land. MCP SDK 1.32.1 (GHSA-22jm-h49p-29qw); the MCP `bin` entry removed.

### SDKs, schemas and the npm gate

- Go: `Verify` validates like TypeScript (`DecodeVerificationResult`, refusing case-variant and
  duplicate keys); `IsArtifactBound` requires a lowercase 64-hex digest; zero-value input serialises
  as serde accepts; `CustomWalletProfile`; a nil `HTTPClient` gets a 30 s no-redirect client;
  context variants; `RecordLifecycleEvent` and `VerifyExecution`; bounded bodies.
- TypeScript: every response validated; only `timeoutMs: 0` disables the timeout; bytes must be
  0..255; the API key ES-private. Both SDKs allow plain http only to loopback.
- The schema requires what the Core always emits (`scope`, `layers`, …), closes objects the Core
  never extends, and states approved ⇒ Clear and "Approved". The v1 schema requires `scope`, so an
  absent one is no longer "an older server". `VerificationResult` has 21 fields, at full parity
  across Rust, the schema, TypeScript and Go. The example result was regenerated from the CLI.
- The npm gate fails on unlisted moderate, high and critical advisories across six lockfiles.

### Dashboard, Python layer, tools, CI

- Dashboard (M15): whole-trail totals; window figures labelled "last N"; a failed `/metrics` read
  shown as unknown; 15 s fetch deadline; freshness shown; last good data kept under a banner; an
  error boundary; the key kept per tab by default; a strict CSP; no production source maps.
- AI layer: 400 / 408 / 413 / 415 / 403 status codes, a 15 s whole-request deadline, at most 32
  connections; codes `MULTIPLE_INTENTS`, `NEGATED_INTENT`, `WITHDRAWAL_UNMODELED`. Throughput is
  machine-dependent: about 12k parses/s measured under load here.
- `tools/mainnet-sample`: `--slots` fails on a missing slot; `verify_sample.py` compares a refetch
  row by row.
- CI: pushes run for `main` and `v*` tags (pull requests for branches); the compose file is
  validated and smoke-tested in the container job; the contract gate compares against a committed
  snapshot of `v0.2.0-beta`, so it runs in any checkout; the image sets
  `GRAPHITE_REGISTRY_STATE=/data/registry_state.json` and `WORKDIR /data`.

### Documentation

Every row of the audit's documentation table was reconciled. Rounds 21–28 now carry the historical
banner. `tests/docs_numbers_match_the_code.rs` gained three tests: the registry's size wherever a
live document states it as "N manifests / M instructions", the committed corpus size, and a rule that
test counts appear in `docs/CURRENT.md` and nowhere else; CONTRIBUTING and ROADMAP are now scanned
too.

## 3. What was measured

- **Tests.** The counts are in [`CURRENT.md`](CURRENT.md), "Numbers". The final all-features run
  reported four failures: three Round 21/22 tests that expected an injected field to be dropped
  rather than refused (updated in `d766a85`), and the documentation test that found ARCHITECTURE's
  stale "23 risk checks" — that is, the scan the audit asked for caught the drift the audit found.
- **Real traffic.** `mainnet_conformance` re-pinned on 2026-10-21: 3 of 2,277 rows changed against
  `19a2974`, each attributed in the test's comment to the manifest reclassification — Jupiter
  `e517cb97…` (Kamino's flash-loan siblings now classed: the first finding is
  `MaliciousAccountChange` instead of the W14 `PermissionEscalation`; still refused), the Pyth push
  oracle `1c095d96…` (`updatePriceFeed` classed; the Wormhole sibling's high-risk `close` still
  refuses it), and the BPF Upgradeable Loader `Write` (now `create`, which a transfer intent cannot
  declare; refused by policy before and after). None went from refused to approved; 0 approvals
  before and after.
- **The holdout.** 38 rows: 37 real exploits, all refused (37 true positives, 0 false negatives),
  and 1 real successful Jupiter swap, refused because offline its address lookup tables cannot be
  resolved and the gate fails closed (1 false positive). Precision 0.974, recall 1.000, F1 0.987.
  Two rows the holdout used to score as benign had failed on chain and are no longer scored;
  replacements could not be fetched (the build environment could not reach the mainnet RPC).
- **The corpus.** 13,013 fixtures: 12,943 dev, 32 regression, 38 holdout.

## 4. The R-4 trade-off, stated plainly

Round 29 stopped judging the signing authority of an SPL transfer and lowered the destination
threshold to four trailing `1`s. Judging no source at all would have approved five documented
address-poisoning sends in the holdout — transfers from a phisher's vanity address to a victim. So
the source is still judged, at the pre-audit five `1`s. The residual false positive: a user's own
wallet ending in five or more `1`s (about one random address in 656 million) is refused when it
sends.

## 5. Deliberate breaks

Until Round 28 every fix was reverted once to show its test fails. This round's record is
complete for most areas and missing for two; each area's own run is stated, not inferred. The
results below were reported by the run that made them; where no artifact survives beyond that
report, it says so.

- **Core pipeline.** H1, M1, M2, F5, F10, F11 and F14 were disabled together and the 16 new tests
  in `audit_2026_10_20_core_gates` and `audit_2026_10_20_simulation_gate` run: 12 failed — all
  but the F4 and F9 tests (which do not depend on the disabled code) and the two controls (no-RPC
  and clean simulation), which passed as they should.
- **Server and CLI.** The M12 permit split, the L1 X-Forwarded-For parsing and the L3 `/health`
  exemption were each reverted; their new tests failed.
- **RPC client and state diff.** `src/state_diff.rs` and `src/rpc_client.rs` reverted together:
  `round29_rpc_client` failed 11 of 11 (in the run kept), `round29_state_diff` 15 of 17 (its two
  controls passed), and the new `token2022_extensions` padding test and the updated `round20`
  fee-terms test failed — 28 failures. The S1 and S5 simulation-integrity tests failed with their
  fixes reverted.
- **Audit trail and parser.** Every new durable test was run against its reverted fix (archive
  ordering, archive names, the failed-append undo and its refusal, the bounded statistics, the
  forged index, the detached handle, the retried index, the per-key bound) and failed; so did the
  legacy-nonce and lookup-split tests in `tx_artifact`. The bump-0 change has no failing test: no
  seed is known whose bumps 255..1 are all on the curve.
- **Agent guard and adapters.** Reverted and caught: the transfer grammar (H3/M5), the swap
  minimum and price floor (H2), both AuditBind selector cases (L1), the key walk (M8), the
  ambiguous-send record (L2), the confirmation hook (M7, guard and Vercel), the required cap (M6)
  and the `.env.example` check.
- **SDKs and schema.** The Go verdict validation (20 of its 22 malformed bodies passed without
  it), the Go wire inputs, the TS timeout and byte checks and the schema's invariants were each
  reverted and their tests failed.
- **Dashboard and AI layer.** The dashboard's fetch deadline test hangs and fails without the
  abort signal; the AI layer's new tests fail against the previous parser (9 failed, 35 passed).
- **Contract gate.** Removing `raw_natural_language` from `proposed-intent-v1.json` fails the gate
  in a checkout with no tags.
- **Not run: the risk engine, manifests and registry**, whose revert runs were refused by the
  environment's permission check — their tests were written against the behaviour each finding
  describes, which is weaker evidence; **and the protocol data and attack suites**, where a
  rebuild per detector was not run.

## 6. Still open

**Owner actions:** branch protection on `main` (until it is on, every CI gate is advisory); enabling
GitHub private vulnerability reporting and then linking it from
`.github/ISSUE_TEMPLATE/config.yml`; the crate's publish flag and tagging `0.3.0-beta`; an
independent third-party audit; deployment.

**Documented limitations:** without an RPC client nothing is simulated and the Core does not refuse
for that alone; without a witness, one primary RPC decides L8; the trail is corruption-evident, not
tamper-evident; L3 does not flag deviations of 50% or less; the R-4 residual false positive; wSOL
unsupported in the guard; the measured `BattleTested` tier does not reach verdicts and its bar is
thin; 13 manifests measure below the decode bar; the holdout is 38 rows and its one benign row is
refused offline; the benchmark is hand-built and descriptive.

**Open engineering:** honest intents for withdrawals, claims and protocol closes (R-M14); owner
configuration versus protocol administration (R-M13); per-instruction L3 baselines (A2-08); the
guard's public API on web3.js 1.x (R-M15); scheduled mutation, fuzz and coverage runs
(R-P11/12/15); renaming `content_hash` (R-M10); the release-evaluation report (R-P1).

**Two figures corrected after the documentation pass** (`716462c`): `docs/protocol-coverage.md`
named the 10,617-transaction sample's registry as 131 manifests (the Round 18 report records 129),
and labelled the 80-block census's transaction versions as "the same sample". The data file and the
renderer were corrected and the page re-rendered.
