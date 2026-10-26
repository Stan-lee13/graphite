# Round 40 — boundary workstream

Internal engineering work, not an independent audit. Base `1ae2066` (Round 39). Six decisions taken
by the technical lead, each implemented with tests, a deliberate break and its result. Background:
`docs/audit/parts/core-boundary.md` (R39-CB-8, -13, -14, -15), `core-identity.md`
(R39-CORE-IDENTITY-7), `core-decision.md` (P3 "No per-plugin timeout").

Commits (oldest first): `6229edb` CB-8, `e46f10a` CB-13, `3e4d968` CB-14, `f1c1f80` CB-15,
`0afbe72` plugin deadline, `7476682` IDENTITY-7, then this report and the merge of the main branch.

## 1. Decisions implemented, and why

| Item | Decision | Why |
|---|---|---|
| R39-CB-8 | `GRAPHITE_TRUSTED_PROXIES` (addresses / CIDR ranges). Forwarded headers are believed only on a connection whose peer is listed; any other peer is keyed by its own address. A hop count with the list unset or empty refuses to start, so does a malformed entry. | A hop count alone was honoured from any peer: campaign 10 MISCONFIG rows, 8 of 8 spoofed requests answered 200. In the production compose file the `ai` container could choose its bucket. |
| R39-CB-13 | `.no_proxy()` on the RPC/witness client; RPC egress documented as direct. | Through `HTTP(S)_PROXY` the connect-time guard judged only the proxy's address, and the proxy resolved the provider's host itself. |
| R39-CB-14 | The signer key file gets the audit key file's group/other refusal, same words. | It was read with no check. |
| R39-CB-15 | Every caller-supplied string a CLI subcommand prints goes through `terminal_safe`; JSON through `json_for_terminal`. | `explain` printed request text raw (the drainer finding quotes `raw_natural_language`). |
| core-decision P3 | A 250 ms deadline per plugin run, on a thread of its own; a run past it is a panicking run (R39-CORE-DECISION-3 path); abandoned runs bounded at 16, refused at the bound. | A slow plugin held the verdict for as long as it took. |
| R39-CORE-IDENTITY-7 | Option 4: a first manifest (and any version whose replay validated nothing independent) earns `HeuristicInferred` at most, computed from a flag on the registry evidence in `compute_trust_tier_for`; lifted by an upgrade replayed against earlier pinned fixtures, or by measured volume at the `BattleTested` threshold. | A first submission's fixtures agree with it by construction; its signature earned `OfficialManifest`, two attestations `CommunityVerified`. |

## 2. Gap Hunter (before coding)

R39-CB-8
- G1 A list too wide (a /16 that includes the AI container) brings the bug back → documented, and
  `0.0.0.0/0` / `::/0` refused; the compose check requires exactly Caddy's address.
- G2 IPv4 peer on a dual-stack listener appears as `::ffff:a.b.c.d` → peers and entries are
  canonicalised before matching (unit test).
- G3 A listed proxy whose list misses its real address keys every client into the proxy's bucket
  (a false refusal, never an approval) → a throttled warning names the ignored peer; install.md
  explains the Docker bridge case.
- G4 Docker could hand Caddy's address to another container → `ip_range` excludes it; run.sh
  checks it.
- G5 The per-peer connection cap defaulted off behind a proxy for every peer → it now exempts only
  a listed proxy; an explicit value still applies to all peers (no weaker than before).
- G6 Every existing deployment with `GRAPHITE_TRUST_PROXY>=1` refuses to start until the list is
  set (compat break, deliberate, fail-closed, message names both variables).
- G7 Misspelled name (`GRAPHITE_TRUSTED_PROXY`, `..._PROXIE`) → refused by `check_env_names`.

R39-CB-13
- G8 reqwest might bypass proxies for loopback anyway, making the test vacuous → the break showed
  it does not (see §4).
- G9 Operators who need an egress proxy lose RPC → documented: allow the providers' addresses
  through the firewall; not supported.

R39-CB-14
- G10 A key file that is a directory or symlink → `metadata` follows the link (as the audit key
  does via canonicalize); not a file is refused. Windows ACLs not inspected (as for the audit key).

R39-CB-15
- G11 Escaping changes ordinary output → only the listed characters are touched; benign control
  asserts an ordinary `explain` is byte-for-byte as before on the intent line.
- G12 Escaping inside JSON must not change the document → `\uXXXX` escapes, re-parsed equal (test).
- G13 Other paths: `audit verify` (file names, break reasons from a directory whoever writes the data
  dir controls), `execution` (RPC answers), `protocol status/diff` (community manifest text the
  reviewer attests from) → all covered.

Plugin deadline
- G14 A plugin that hangs on every input leaks a thread per request → abandoned runs counted and
  bounded; at the bound nothing more starts and its run is refused.
- G15 The bound is shared with tests running concurrently → the bounded-run machinery takes its
  gate as a parameter; the unit test uses its own.
- G16 Analytics observers (the event logger's file sink) overrunning would fill the verdict gate and
  refuse every request → analytics have a gate of their own; an overrun there is logged only.
- G17 P2: a deadline is a wall-clock input to the verdict → tradeoff recorded in §5; direction is
  refusal only.
- G18 A plugin borrowing request data could outlive the request → it runs against an owned copy.
- G19 A slow panic hook (backtrace printing) can push a panicking run past the deadline → it is then
  a timed-out run; same refusal.

R39-CORE-IDENTITY-7
- G20 Capping in the registry but not in the graph: the verdict takes `max(graph tier, manifest
  tier)`, so an uncapped graph record lifts it back → the cap is in the store's tier computation,
  and the integration test checks the verdict with the graph record present.
- G21 An operator seed after a first submission would clear a flag stored on the record → every
  non-registry append carries the flag forward; only the registry's independent replay clears it.
- G22 A head resubmitted with more attesters would lift it → its flag is inherited (refused as a
  replay while capped).
- G23 An upgrade whose earlier fixtures were all retired validated nothing → still capped.
- G24 Seed manifests → not registry submissions; unaffected (test). A community first submission
  for a seed program cannot drag the seed's tier down (test).
- G25 Records written before Round 40 have no flag → they keep their tier (open, §8).

## 3. Changes

### R39-CB-8 — `6229edb`

- `server.rs`: new `ProxyTrust { hops, proxies }`, `IpNet` (address or CIDR, IPv4/IPv6,
  canonicalised), `proxy_trust_from(hops, GRAPHITE_TRUSTED_PROXIES)`, `client_key_ip` (forwarded
  client only when `ProxyTrust::believes(peer)`; otherwise the peer; a throttled warning once a
  minute when a header is ignored). `AppState.trust_proxy_hops: u8` → `proxy_trust:
  Arc<ProxyTrust>`. `rate_limit` keys by `client_key_ip`. `Limits` gains `max_per_proxy`; the
  accept loop takes `PeerCaps` (cap per peer: listed proxy → `max_per_proxy`, default none;
  any other → `GRAPHITE_MAX_CONNECTIONS_PER_IP`, default 64). Startup logs the trusted list.
  Before: header believed from any peer when hops ≥ 1; per-peer cap off for every peer behind a
  proxy. After: as above.
- `operator_boundary.rs`: `GRAPHITE_TRUSTED_PROXIES` in `CORE_ENV_NAMES`.
- Deploy kit: `docker-compose.prod.yml` (backend `10.73.31.0/24`, `ip_range 10.73.31.128/25`,
  Caddy `ipv4_address 10.73.31.2`, Core `GRAPHITE_TRUSTED_PROXIES: "10.73.31.2"`);
  `systemd/graphite.service` (`127.0.0.1,::1`), `graphite.env.example`, `Caddyfile` comment,
  `deploy/README.md`; `deploy/tests/run.sh` (compose `proxy` audit; two start refusals; the test
  Core started with the list); `.env.example`; `docs/ops/install.md`.
- Tests: `tests/round40_trusted_proxies.rs` (campaign-10 style at 0.1 req/s: not-listed peer with a
  spoofed entry per request → 200 then 7 × 429; listed proxy → 8 × 200 and the control 429; one
  server, 127.0.0.1 listed, 127.0.0.2 beside it → neighbour refused, proxy's clients untouched);
  `server::route_surface::{a_forwarded_header_from_a_peer_that_is_not_a_listed_proxy_is_ignored,
  trusted_proxies_parse_strictly, the_connection_cap_exempts_only_a_listed_proxy}`;
  `audit_2026_10_20_startup_refusals.rs` (+5 cases); `round36_env_names.rs` (+4 misspellings);
  `audit_a4_xff_multiple_header_lines.rs` now lists 127.0.0.1 (its client is the proxy).
- Re-pin: `server::tests::settings_that_do_not_parse_refuse_to_start` asserted "behind a proxy the
  default is no per-peer cap"; it now asserts the default exempts only a listed proxy and an
  explicit cap applies to every peer.

### R39-CB-13 — `e46f10a`

- `rpc_client.rs` `SolanaRpcClient::new`: `.no_proxy()`. No other outbound client in `src/`
  (healthcheck already had it, R39-CB-3; `server.rs` uses reqwest in tests only).
- `docs/ops/install.md`: RPC egress is direct, and why.
- Test: `tests/round40_rpc_no_proxy.rs` — every proxy variable (upper and lower case) names a
  loopback proxy that answers a valid JSON-RPC reply of its own, `NO_PROXY` removed; `get_slot`
  answers 42 from the mock RPC and the proxy sees 0 connections.

### R39-CB-14 — `3e4d968`

- `cli.rs` `read_signer_key_file` (mode & 0o077 ≠ 0 → "signer key file … is readable or writable
  by group or others (mode 644); chmod 600 it"; not a file refused; contents zeroised);
  `bin/graphite.rs` uses it for `--signer-key-file` and `GRAPHITE_SIGNER_KEY_FILE`.
  `docs/ops/keys.md`, `.env.example`.
- Tests: `tests/round40_signer_key_mode.rs` — modes 644/640/604/602/660/666 refused through the
  binary by flag and by env, naming the mode; 600 and 400 read (trimmed) and the command goes on.

### R39-CB-15 — `f1c1f80`

- `cli.rs` `terminal_safe` (C0/C1/DEL/ESC, U+061C, U+200B–U+200F, U+2028–U+202E, U+2060–U+2069,
  U+FEFF → `\u{..}`), `json_for_terminal` (the same set minus C0, which serde_json escapes, →
  `\uXXXX`). Applied to `explain` (every string), `verify` (JSON + the policy note), `execution`
  (every string and Debug value), `audit verify` (text and `--json`), `audit checkpoint` (stdout),
  `audit adopt-key` break line, `audit acknowledge-tear`, `unreadable`/`writer_refused`
  messages, `protocol status`, `protocol diff`.
- Finding while testing: the Core refuses non-printable-ASCII in `intent_type`, addresses and the
  discriminator; `raw_natural_language` is the free-text field, and the drainer plugin's finding
  quotes it. `explain` printed that finding raw.
- Tests: `cli::tests::caller_text_reaches_the_terminal_escaped`;
  `tests/round40_terminal_escapes.rs` (ESC sequences, U+202E, BEL, NEL, U+2066 arrive escaped in
  `explain`; an ordinary request prints as before; `verify` JSON carries `\u001b`/`‮`, no raw
  control, and parses to the original text).

### Plugin deadline — `0afbe72`

- `plugin_orchestrator.rs`: `PLUGIN_DEADLINE` = 250 ms, `MAX_OVERRUN_PLUGIN_RUNS` = 16,
  `run_bounded(gate, deadline, work)` (own thread, `catch_unwind` there, `recv_timeout`; abandoned
  runs counted on the gate until they finish), `failed_plugin_verdict` (the R39-CORE-DECISION-3
  mapping, now for `Panicked` / `TimedOut` / `Saturated`: blocking families → `Block
  <name>:panicked|timed-out|not-run`, others → Note), `OwnedPluginContext`. `run_family`,
  `protocol_rules` (failure → `UNDESCRIBED_INSTRUCTION_EFFECTS`, the strict reading) and
  `run_analytics` (own gate; logged) use it. No new env variable; no process.
- Tests: `plugin_orchestrator::tests::{a_plugin_that_cannot_reach_a_verdict_blocks_or_notes_by_family,
  a_risk_plugin_past_its_deadline_is_a_block_at_the_deadline, abandoned_runs_are_bounded_and_released}`;
  `round39_decision_campaigns::round40_a_plugin_past_its_deadline_refuses_at_the_deadline` (3 s
  plugin, all 7 family/layer slots: refused, named, answered in [250 ms, 2.5 s)).
- The "note family" case: since Round 39 no verdict family is non-blocking, so a Note is reached
  only through `failed_plugin_verdict` (unit-tested with the Protocol and Analytics families);
  Protocol and Analytics plugins keep their own fallbacks.
- Re-pin: `campaign12_a_plugin_that_finds_nothing_leaves_an_honest_swap_executable` — `Act::Slow`
  slept 300 ms to show there was no timeout; it now sleeps 50 ms (inside the deadline) and the swap
  stays executable.

### R39-CORE-IDENTITY-7 — `7476682`

How tier maps today (read first): the registry computes a record's tier from its evidence
(`compute_trust_tier`); `manifests_in_force` writes `tier_in_force` into each merged manifest; the
graph's `append_registry_evidence` → `append` recomputes the graph record's tier from its evidence;
the verdict's tier is `program_trust_tier` = `max(graph record tier, manifest tier capped at
OfficialManifest)`. So the cap has to be in both computations, and it is put in the one function
both use.

- `semantic_graph_store.rs`: `Behavior.first_manifest_unvalidated` (serde default, skipped when
  false — snapshots without it are byte-identical); `compute_trust_tier_for(evidence, flag)` =
  `compute_trust_tier`, capped at `HeuristicInferred` while the flag holds and
  `battle_tested_tx_count < BATTLE_TESTED_TX`; used by `append`, snapshot load, quarantine lift and
  redeploy retirement. `append` carries the flag forward from the previous record;
  `append_registry_evidence` lets the registry set it.
- `manifest_registry.rs`: `RegistryRecord.first_manifest_unvalidated`; `submit` sets it for a first
  version, inherits it for a head resubmission, and for an upgrade sets it only when no
  non-deprecated registry fixture for the program was replayed; the record's tier, the replay
  tier, `tier_in_force` and the graph record use `compute_trust_tier_for`; revocation keeps the
  head's flag; `verify_offline` refuses a flagged record claiming more than `HeuristicInferred`.
  Module doc updated.
- Every `Behavior` literal in `src/` and `tests/` gained `first_manifest_unvalidated: false`.
- `cli.rs` `registry record-fixture`: a note on stderr when it records above HeuristicInferred — the
  gate replays a first version at HeuristicInferred, a fixture recorded at a higher declared tier
  can fail that replay, and a refused version is never taken again.
- Tests: `manifest_registry::tests::a_first_manifest_is_capped_until_independent_evidence_lifts_it`
  (signer + 2 attesters → HeuristicInferred in record, in force and in the graph; offline-verifiable;
  a tampered claim refused; operator seeds of signatures/attestations/sim matches/999 tx do not
  lift; 1,000 tx does; state files keep the cap; an upgrade with every earlier fixture retired stays
  capped; the upgrade replayed against v1.0's fixture → CommunityVerified, flag cleared);
  `tests/round40_first_manifest_cap.rs` (verdict tier HeuristicInferred with and without the
  graph record, OfficialManifest after the validated upgrade; seed manifests not registry
  submissions, a community first submission for the System program leaves its verdict tier
  OfficialManifest).
- Re-pins (each a first submission that earned a tier from a self-consistent replay):
  `valid_registered_reviewer_signature_earns_official_manifest` (now: v1.0 capped, v1.1 upgrade
  earns OfficialManifest), `p10_gate_allows_promotion_when_engine_replay_passes` (Official →
  Heuristic), `self_asserted_trust_tier_in_manifest_is_ignored_p7` (Official → Heuristic),
  `cli::tests::registry_cli_register_and_submit_persists` (Official → Heuristic, flag persisted).
  Tests whose subject is evidence counting now prime a first version so the submission under test
  is a validated upgrade and keep their original tiers: `g5_attestations_count_only_distinct_registered_reviewers`,
  `the_signer_does_not_attest_its_own_submission`, `a_revoked_reviewer_stops_counting`,
  `the_head_may_be_resubmitted_only_to_raise_its_tier` (plus: an unvalidated head resubmitted with
  two attesters is refused as a replay). No assertion moved from refused to approved: every moved
  tier moved down.

## 4. Deliberate breaks

Each break was made in a copy outside the worktree (`/home/user/brk-boundary`, from `git archive
HEAD`, its own `CARGO_TARGET_DIR=/home/user/brk-boundary-target`), one at a time, and reverted;
both were deleted afterwards. Control: the copy with every break reverted passed the same tests.

| Break | What was reverted | Tests that failed |
|---|---|---|
| B-CB-8a | `ProxyTrust::believes` = `hops > 0` (the allowlist check removed) | `round40_trusted_proxies::only_a_listed_proxy_chooses_the_rate_limit_key`; `route_surface::a_forwarded_header_from_a_peer_that_is_not_a_listed_proxy_is_ignored`, `the_connection_cap_exempts_only_a_listed_proxy` |
| B-CB-8b | the "hop count with no list" refusal disabled | `route_surface::trusted_proxies_parse_strictly`; `audit_2026_10_20_startup_refusals` (the server STARTED with `GRAPHITE_TRUST_PROXY=1` alone) |
| B-CB-13 | `.no_proxy()` removed | `round40_rpc_no_proxy::the_rpc_client_ignores_environment_proxies` (the request went to the proxy: reqwest does not bypass loopback by itself, so the test is not vacuous) |
| B-CB-14 | the signer key mode check disabled | `round40_signer_key_mode::a_signer_key_file_others_can_read_is_refused` |
| B-CB-15 | `terminal_safe` returns its input | `cli::tests::caller_text_reaches_the_terminal_escaped`; `round40_terminal_escapes::explain_prints_a_requests_escape_sequences_escaped` |
| B-DL-1 | the deadline removed (`run_bounded` runs the work inline and waits for it) | `plugin_orchestrator::tests::a_risk_plugin_past_its_deadline_is_a_block_at_the_deadline`; `round39_decision_campaigns::round40_a_plugin_past_its_deadline_refuses_at_the_deadline`; `abandoned_runs_are_bounded_and_released` hangs (killed by a 120 s timeout) |
| B-DL-2 | the overrun bound removed | `plugin_orchestrator::tests::abandoned_runs_are_bounded_and_released` |
| B-ID7-1 | the cap removed in `compute_trust_tier_for` | 9 `manifest_registry` tests (the new one and the eight re-pinned/primed ones, among them `an_accepted_record_verifies_offline_and_a_tampered_one_does_not`); both `round40_first_manifest_cap` tests |
| B-ID7-2 | the registry never flags the graph record (record and manifest in force still capped) | `a_first_manifest_is_capped_until_independent_evidence_lifts_it`; both `round40_first_manifest_cap` tests (the uncapped graph record lifted the verdict back to OfficialManifest) |
| B-ID7-3 | `append` does not carry the flag forward | `a_first_manifest_is_capped_until_independent_evidence_lifts_it` (an operator seed cleared the cap) |

The deploy-kit check was broken too, on copies of the compose file: a trusted list widened to the
subnet, and Caddy's address moved inside the dynamic range — the `proxy` audit failed on each.

## 5. Constitution check on the diff

- P2 (determinism): the plugin deadline makes a verdict depend on whether a plugin answered within
  250 ms. **P14 tradeoff note:** recorded here and in `PLUGIN_DEADLINE`'s doc. Accepted because the
  only verdicts it can change are towards refusal (a run that did not answer cannot approve
  anything), the shipped plugins answer in microseconds, and the alternative was an unbounded
  request. Every other change is deterministic.
- P3 (explained): every new refusal names its cause (`<plugin>:timed-out`, `not-run`; the startup
  refusals name both variables; the first-manifest cap is visible as the record's flag and tier).
- P6/P7: the cap is computed from evidence (a flag the registry derives from its own replay), never
  set; `compute_trust_tier` is unchanged for every record without the flag. No tier rises.
- P8: plugins still see only their context (an owned copy of the same fields); the orchestrator
  stays the sole caller.
- P9: no audit write removed.
- P10: the gate is unchanged; IDENTITY-7 makes the tier depend on what the gate actually proved.
- P11: unchanged (exact program id).
- P12: unknown protocols unaffected. The proxy refusals are startup configuration errors, the same
  class as the existing refusals.
- P13: two deliberate behaviour changes needing a CHANGELOG entry (main session): a hop count now
  requires `GRAPHITE_TRUSTED_PROXIES` (deployments refuse to start until set); a first registry
  manifest earns `HeuristicInferred` at most.
- P14: no check, log or explanation removed. The per-peer connection default changed shape (it now
  applies to non-proxy peers behind a proxy, where it was off) — stronger, not weaker.

## 6. Verification

- Backward compatibility: deployments with `GRAPHITE_TRUST_PROXY>=1` must add
  `GRAPHITE_TRUSTED_PROXIES` (refusal says so); operators behind an RPC egress proxy must allow
  direct egress; group/other-readable signer key files are refused; first registry manifests are
  capped (registry states written before Round 40 keep their tiers).
- Security: no refusal becomes an approval; every moved pinned value moved toward refusal or a
  lower tier.
- Explainability: every new outcome is named in the verdict, the log or the startup error.
- Hidden assumptions: the plugin deadline assumes in-tree plugins are fast on a loaded host
  (250 ms); the proxy list assumes the operator names the address the proxy connects from (the
  warning surfaces a miss); the cap assumes the census path seeds volume through an append (which
  carries the flag) — any path that appends evidence carries it.
- Architecture conflict: plugins now run on short-lived threads; `tests/ai_layer_isolation.rs`
  (no process spawning) still passes.

## 7. Pinned outputs moved

No verdict hash, census or corpus count is pinned by these changes. Assertions that moved, all
attributed in §3:

- `server::tests::settings_that_do_not_parse_refuse_to_start` — the per-peer default behind a proxy
  (CB-8): stronger (a cap on non-proxy peers where there was none).
- `round39_decision_campaigns::campaign12_a_plugin_that_finds_nothing_leaves_an_honest_swap_executable`
  — the slow plugin's sleep 300 → 50 ms (deadline). Still executable.
- First-submission tiers (IDENTITY-7): `valid_registered_reviewer_signature_earns_official_manifest`,
  `p10_gate_allows_promotion_when_engine_replay_passes`, `self_asserted_trust_tier_in_manifest_is_ignored_p7`,
  `cli::tests::registry_cli_register_and_submit_persists` — OfficialManifest → HeuristicInferred.
  Four evidence tests primed with a first version (original tiers kept).
- `round39_registry_gate_dilution.rs` — fixtures recorded at the tier the gate now replays at
  (HeuristicInferred for v1 and for the upgrade with every fixture retired), and the pinned input's
  profile (0.40, OfficialManifest) → (0.30, HeuristicInferred) so its outcomes still turn on the
  instruction class (at HeuristicInferred the old floor refused everything; confidence there is
  0.36). Its four attack assertions are unchanged and still block; `a_retired_refusal…` now also
  asserts the capped tier.

No attack fixture moved from refused to approved; every moved tier moved down.

## 8. Commands run

All with `CARGO_TARGET_DIR=/home/user/boundary-target CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0
CARGO_PROFILE_TEST_DEBUG=0 -j 2`, in `graphite-core/`:

- `cargo test --locked --no-fail-fast` (default leg), after all six items: 2,478 passed, 3 failed
  (`round39_registry_gate_dilution`, fixed as in §7, then 6/6), 15 ignored, 184 binaries.
- `cargo test --locked --no-fail-fast --no-default-features --features cli`: 1,991 passed, 0
  failed, 6 ignored, 184 binaries.
- `cargo clippy --all-targets --all-features -- -D warnings`: clean.
  `cargo clippy --all-targets --no-default-features --features cli -- -D warnings`: clean.
  `cargo fmt --all -- --check`: clean.
- Targeted runs while iterating (each new and re-pinned suite), the breaks in §4.
- `shellcheck deploy/tests/run.sh`, `bash -n deploy/tests/run.sh`: clean. Compose audits from
  run.sh: 5/5 pass. `docker compose -f deploy/compose/docker-compose.prod.yml --profile ai config
  --quiet`: exit 0.
- After merging `claude/admiring-archimedes-lfhr7n` (`f0581de`; no textual conflicts): the census
  import's `Behavior` literal (and its test's) gained the field, and its plan computes the graph
  tier with `compute_trust_tier_for` so it shows the tier `append` will produce for a capped
  record. Then: default leg 2,546 passed, 0 failed, 15 ignored; cli leg 2,009 passed, 0 failed, 6
  ignored; lib leg (`--no-default-features --lib`) 533 passed; both clippy legs and fmt clean;
  `bash .github/scripts/ci-scripts.test.sh` 137 passed, 0 failed (one case SKIPs without
  ACTIONLINT, not counted). Per-binary floors added to `.github/test-floors/rust-{default,cli}.txt`
  for the five new suites (the two server/rpc-gated ones named "not in this leg" in cli), the
  library's floors raised to the merged counts (742 / 600 / 533) and
  `round39_decision_campaigns` to 23.

New tests: 8 lib unit tests, 9 integration tests (`round40_trusted_proxies` 1, `round40_rpc_no_proxy`
1, `round40_signer_key_mode` 2, `round40_terminal_escapes` 2, `round40_first_manifest_cap` 2,
`round39_decision_campaigns` +1), plus 5 startup-refusal cases and 4 env-name cases inside
existing tests.

Deleted: `/home/user/boundary-target` (before the breaks, for disk), `/home/user/brk-boundary`,
`/home/user/brk-boundary-target`, `/tmp/graphite-r40-*`.

## 9. BLOCKED

- `deploy/tests/run.sh` end to end: needs `caddy` and `promtool` (`command -v caddy promtool`
  finds neither here). Run: `GRAPHITE_BIN=… bash deploy/tests/run.sh`. Run here: `bash -n`,
  `shellcheck` (clean), its compose audits extracted and run (all pass; the `proxy` audit fails on
  two break copies: a list widened to the subnet, and Caddy inside the dynamic range), and
  `docker compose -f deploy/compose/docker-compose.prod.yml --profile ai config --quiet` (exit 0).

## 10. Open, stated plainly

- `registry record-fixture` records at the manifest's DECLARED tier while the gate replays at the
  COMPUTED one (true before Round 40 too; more often now, since a signed first version computes to
  HeuristicInferred). An honest submitter who declares a higher tier can see their first version
  refused, permanently (MR-2). Mitigated by the stderr note; not fixed (record-fixture does not know
  the registry state).
- Registry states written before Round 40: their first manifests carry no flag and keep the tier
  they were accepted at (the graph records too). Re-submitting is not possible (a version is
  accepted once); an operator would have to re-accept through an upgrade.
- The plugin deadline is per run, not per request: N slow plugins hold a request up to N × 250 ms
  (N is the number of registered in-tree plugins).
- A plugin run past its deadline keeps running on its thread until it returns; a plugin that never
  returns holds one thread for good, up to the bound, after which every request that would run a
  plugin of that gate is refused.
- `GRAPHITE_TRUSTED_PROXIES` trusts the proxy itself; a compromised proxy still chooses buckets.
- Windows: neither key file's ACL is inspected.
