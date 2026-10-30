# Round 39 — core-boundary workstream

Internal audit work of Round 39 on the Core's system boundary: the durable
audit trail, the HTTP server, the CLI, the RPC client and the deployment
scripts. It is not an independent audit or a certification, and nothing
here says Graphite is production ready.

Base: `c087bfb` (the Round 38 merge). Commits of this workstream:
`291ee80`, `4c9391e`, `b322d74`, `895ba8c`, `50cce22`, `100b4f7`.

Evidence types used below: **reproduced** means a test or a harness run
showed the behaviour against a real binary or the library; **code-reviewed**
means it was read from the code and not executed.

## 1. Scope read

| File | Lines | How | Disposition |
|---|---|---|---|
| `graphite-core/src/durable.rs` | 6464 | production code (1–4049) read fully; in-file test module read in part (the tests touching gate, rotation, prune, index and append-failure paths) | R39-CB-1, R39-CB-4 (doc), R39-CB-5 fixed here |
| `graphite-core/src/durable/chain.rs` | 2946 | read fully | R39-CB-1, R39-CB-5 fixed here |
| `graphite-core/src/durable/archive_index.rs` | 623 | read fully | no finding; v4 format with HMAC trailer re-checked (R37-12) |
| `graphite-core/src/durable/chain_trail_tests.rs` | 3121 | read fully | 1 test added, 1 test step re-pinned, 1 ignored measurement added |
| `graphite-core/src/server.rs` | 10053 | production code (1–4961) read fully; `tests`, `request_path_cost` and `route_surface` modules read in part (auth, body, quarantine, metrics, audit-failure tests) | R39-CB-2, CB-4, CB-7 fixed; CB-8, CB-10 recorded |
| `graphite-core/src/cli.rs` | 4303 | production code (1–3274) read fully; tests read in part (audit, healthcheck, manifest diff) | R39-CB-3, CB-6, CB-12 fixed; CB-14, CB-15 recorded |
| `graphite-core/src/bin/graphite.rs` | 965 | read fully | CB-14 recorded (signer key file read without a mode check) |
| `graphite-core/src/rpc_client.rs` | 3022 | production code (1–2598) read fully; tests read in part | CB-13 recorded; campaign 7 passes |
| `graphite-core/src/operator_boundary.rs` | 515 | read fully | V-2 / R37-15 re-verified; no finding |
| `graphite-core/src/live_corpus.rs` | 1191 | production code (1–621) read fully | offline tooling; no finding |
| `graphite-core/src/benchmark.rs` | 1580 | production code (1–1308) read fully | offline tooling; two `expect`s on static data (section 2, classification) |
| `graphite-core/src/lib.rs` | 99 | read fully | no finding |
| `deploy/scripts/backup.sh` | 253 | read fully; shellcheck | CB-9 recorded |
| `deploy/scripts/restore.sh` | 275 | read fully; shellcheck | wrong round in one comment fixed (`b322d74`) |
| `deploy/scripts/rotate-keys.sh` | 128 | read fully; shellcheck | no finding |
| `deploy/tests/backup-keys.test.sh` | — | run (22/22) | re-verifies R37-11 / T-9 |
| `deploy/tests/run.sh` | — | read; not run | BLOCKED (section 6) |
| `deploy/compose/docker-compose.prod.yml` | — | read in part (networks, replicas, container names) | single-replica evidence; CB-8 context |
| `graphite-core/tests/*.rs` (22 suites touching this scope) | — | run; the boundary suites read in part | all pass |

## 2. Findings

| Id | Severity | One line | Status |
|---|---|---|---|
| R39-CB-1 | P1 | A record of another trail under the same key, appended at the end, became the trail's pin: a restarted server resumed onto the other trail and every genuine record read as foreign | fixed with tests, break caught |
| R39-CB-2 | P2 | With stdout and stderr both unwritable the server panicked at its first log line (exit 101) | fixed with test, break caught |
| R39-CB-3 | P3 | `graphite healthcheck --strict` followed redirects (and env proxies) and passed on another host's answer | fixed with test, break caught |
| R39-CB-4 | P3 | 413 / 408 / caught-panic 500 were not counted anywhere; a doc comment said an oversized body leaves an audit row | fixed with test, break caught |
| R39-CB-5 | P2 | A keyed reader's coverage set grew with the adopted unkeyed/legacy history (~146 MiB peak RSS at 1,000,000 records) | partly fixed (~59 MiB); residual is an accepted limitation |
| R39-CB-6 | P3 | `graphite audit verify` of a directory holding no trail exited 2 ("unproven") instead of 3 (nothing could be read) | fixed with test, break caught |
| R39-CB-7 | P3 | A quarantine lift whose request was cut off while its append waited stayed in force, unrecorded | fixed with test, break caught |
| R39-CB-8 | P2 | `GRAPHITE_TRUST_PROXY` trusts `X-Forwarded-For` from any peer; behind a proxy the per-peer cap defaults off; the production compose backend network lets other containers reach the Core directly | owner decision |
| R39-CB-9 | P3 | A hot backup can copy the bytes of an append that is later truncated as failed | accepted limitation (documented here) |
| R39-CB-10 | P3 | `refuse_after_draining` buffers up to 1 MiB per refused connection for up to 1 s | accepted (bounded) |
| R39-CB-11 | P3 | A front-truncated trail, or one whose first record is tampered, still starts and is read; only `audit verify` reports it | accepted, by design and documented |
| R39-CB-12 | P2 | `graphite protocol diff` ignored role, PDA seeds, expected address, optional, alternative layouts and risk rules | fixed with test, break caught |
| R39-CB-13 | P3 | The RPC client honours `HTTP(S)_PROXY`; the connect-time guard then judges only the proxy's address | owner decision |
| R39-CB-14 | P3 | `registry submit` reads the signer key file without the mode check the audit key file gets | recorded, not fixed |
| R39-CB-15 | P3 | `graphite explain` prints caller-supplied strings to the terminal unescaped | recorded, not fixed |

### R39-CB-1 — another trail's record at the end becomes the trail (P1)

- **Where:** `durable/chain.rs` `RecordGate::accept` (line 1515), `resume_head`;
  `durable.rs` `open_read_only_with` (line 1877). The readers pin the trail id of
  the newest record; the gate then refuses every record of another trail.
- **Preconditions:** write access to the data directory (the trail threat model)
  and one record of another trail under the same key (a second deployment, a
  staging copy, an old backup of another host using the shared key file).
- **Impact:** a foreign record appended at EOF became the pin. Every genuine
  record then read as the other trail's: on a five-record trail one record
  stayed readable, the L8 join answered with the foreign approval, and a
  restarted server resumed onto the other trail with its own history gone from
  every reader. `audit verify` did report a break (exit 1), but nothing stopped
  the server.
- **Fix:** the gate records `Cursor::other_trail` when a record of another
  trail verifies under a key the reader holds (`genuine_to_this_reader`, line
  1620); a forged record that does not verify does not set it. Writers
  (`resume_head`) and keyed readers (`open_read_only_keyed`, used by
  `graphite execution`) refuse with `other_trail_refusal()` (line 2028).
  Unkeyed `open_read_only` keeps reading (no MAC can tell the trails apart).
- **Reproduction:** `durable::chain_trail_tests::a_record_of_another_trail_at_the_end_does_not_become_the_trail`
  (pre-fix: the victim's verdict came back as the foreign approval, 1 of 5 genuine
  records readable); `round39_core_boundary::a_server_does_not_resume_onto_another_trails_record`
  (real binary: `verify` exit 1, server does not come up, log names "another
  trail"; benign control: the genuine trail starts). Campaign 9 row V7 failed
  on `c087bfb` (server started) and passes now.
- **Re-pinned:** the top-insertion step of `a_copied_record_is_not_the_newest_verdict`
  pinned "the keyed reader still reads the trail" for a foreign record at the
  top. That trail holds two trails under one key; it now expects the refusal
  (reason in the test comment).
- **Breaks:** B-CB-1 (refusal in `resume_head` and the keyed open removed) and
  B-CB-1b (the flag never set): each failed 3 tests (the two above and the
  re-pinned step).
- **Confidence:** high. Reproduced.

### R39-CB-2 — a log the server cannot write crashed it (P2)

- **Where:** `server.rs` `init_tracing` (line 772). `tracing-subscriber`
  reports a write error with `eprintln!`, which panics when stderr cannot be
  written either.
- **Preconditions:** stdout and stderr both unwritable (a full log volume, a
  closed pipe, `/dev/full`). Found when the campaign 9 disk-full run placed the
  server log on the full tmpfs.
- **Impact:** exit 101 at the first log line (wait status 25856); once running,
  every request that logged lost its connection without a response.
- **Fix:** `.log_internal_errors(false)` on both subscriber branches.
- **Reproduction:** `round39_core_boundary::a_server_whose_log_cannot_be_written_still_starts_and_answers`
  (stdout and stderr on `/dev/full`; `/verify` answers 200 and the trail holds
  one record). Pre-fix the `c087bfb` binary exited 101.
- **Break:** B-CB-2 (the option removed): the test fails ("did not come up …
  exited 101").
- **Confidence:** high. Reproduced.

### R39-CB-3 — healthcheck followed a redirect (P3)

- **Where:** `cli.rs` healthcheck client (line 1328).
- **Impact:** a container whose port answered with a redirect passed
  `--strict` on another host's `/health`; an `HTTP_PROXY` in the environment
  carried the probe elsewhere too.
- **Fix:** `redirect::Policy::none()` and `.no_proxy()`.
- **Reproduction:** `round39_core_boundary::healthcheck_does_not_follow_a_redirect`
  (benign control: the same answer at the port itself passes). Campaign 10 last
  row failed on `c087bfb` (exit 0).
- **Break:** B-CB-3 (policy removed): the test fails.
- **Confidence:** high. Reproduced.

### R39-CB-4 — transport refusals were invisible (P3)

- **Where:** `server.rs` `build_app`, `Metrics`, `/metrics`.
- **Impact:** 413 (body over 1 MiB), 408 (body timeout) and the caught-panic
  500 left no audit row (by design: they are refused before a handler runs)
  and were counted nowhere, while the `AuditErrorRecord` doc comment said an
  oversized body is recorded.
- **Fix:** `graphite_payload_too_large_total`, `graphite_request_timeouts_total`,
  `graphite_handler_panics_total` (an outer `MapResponseLayer` and the
  `CatchPanicLayer` closure); the doc comment corrected.
- **Reproduction:** `server::route_surface::refusals_of_the_transport_are_counted_and_never_on_the_trail`
  (two 413s, one 408, 0 panics, no trail rows).
- **Break:** B-CB-4 (counter increment removed): value 0, test fails.
- **Confidence:** high. Reproduced.

### R39-CB-5 — keyed reader memory grew with the adopted history (P2)

- **Where:** `durable/chain.rs` `TrailFacts::covered`, `AdoptionFacts::legacy`,
  `RecordGate` coverage (now `RecordSet`, line 1183).
- **Preconditions:** a trail with a long unkeyed or legacy history before a
  checked adoption.
- **Impact:** every covered record was held in a hash set. `graphite execution`
  over 1,000,000 covered records peaked at 146 MiB RSS on `c087bfb`.
- **Fix:** a sorted, de-duplicated `Vec<(u64, [u8; 16])>` with binary search,
  built by moving rather than copying: 59 MiB peak, about 27 bytes retained per
  record.
- **Residual (accepted limitation):** memory still scales with the covered
  history. Mitigation: adopt a key early, prune old history.
- **Measurement:** `durable::chain_trail_tests::keyed_reader_memory_for_an_adopted_unkeyed_history`
  (ignored; re-runs itself in a child process via `CB5_OPEN` so the RSS is the
  reader's alone). No break run: this is a resource bound, not a gate.
- **Confidence:** high for the numbers on this host. Reproduced.

### R39-CB-6 — `audit verify` of no trail (P3)

- **Where:** `cli.rs` audit verify (around line 555).
- **Impact:** a typo in `--data-dir` exited 2, the code for "a trail that cannot
  be proven", which a script can treat as a soft warning.
- **Fix:** no `audit.jsonl` and no `audit.jsonl.*` exits 3 ("nothing could be read").
- **Reproduction:** `round39_core_boundary::audit_verify_of_a_directory_without_a_trail_is_unreadable`
  (empty and missing directories exit 3; benign control: a trail exits 0).
  Harness `t14` row failed on `c087bfb`.
- **Break:** B-CB-6 (check removed): the test fails (exit 2).
- **Confidence:** high. Reproduced.

### R39-CB-7 — a lift cut off mid-append (P3)

- **Where:** `server.rs` `quarantine` (line 3821).
- **Preconditions:** a quarantine lift whose append waits (the trail lock held,
  a slow disk) and whose request is cut off by the timeout or the client.
- **Impact:** the lift had been applied before the append; when the append
  failed after the handler was dropped, the restore-on-failure never ran, so
  the lift stayed in force with no record.
- **Fix:** the append and the restore run together inside the same
  `off_runtime` closure, so cancelling the request cannot separate them; the
  response says whether the quarantine was restored.
- **Reproduction:** `server::tests::a_lift_cut_off_while_its_append_waits_is_still_not_applied`
  (multi-threaded runtime; a read-only file handle swapped in so the append
  fails, the lock held 600 ms, a 150 ms timeout on the lift; the program is
  quarantined afterwards).
- **Break:** B-CB-7 (the restore moved back after the await): the test fails;
  the benign lift test still passes under the break.
- **Confidence:** high. Reproduced.

### R39-CB-8 — trusted-proxy hops from any peer (P2, owner decision)

- **Where:** `server.rs` `trust_proxy_hops_from` (line 1008) and the client-key
  derivation; `deploy/compose/docker-compose.prod.yml` backend network.
- **Preconditions:** `GRAPHITE_TRUST_PROXY >= 1` and a peer that can reach the
  Core without passing the proxy.
- **Impact:** that peer chooses its own rate-limit bucket per request
  (campaign 10 MISCONFIG rows: 8 of 8 requests with spoofed entries answered
  200, where the same peer without the header was refused 429 from its third
  request). The per-peer connection cap defaults to 0 behind a proxy. In the
  production compose file the `ai` service shares the `backend`
  network with the Core and Caddy, with `GRAPHITE_TRUST_PROXY: "1"`, so the AI layer can reach the Core directly and pick its own bucket.
- **Recommendation:** trust `X-Forwarded-For` only from configured proxy
  addresses, or put the Core on a network only the proxy joins. Both need an
  owner decision (a new configuration name); no name is invented in docs.
- **Confidence:** high. Reproduced (harness), deployment part code-reviewed.

### R39-CB-9 — hot backup and a failed append (P3, accepted)

`deploy/scripts/backup.sh` copies a running trail. An append that fails is
truncated back by the writer; a copy taken between the write and the truncate
holds those bytes. If they form a whole record, a trail restored from that
backup holds a verdict whose request was answered 503 (over-recording, not a
lost approval); if they are partial, the restored trail ends in a torn line,
which `audit verify` reports. Narrow window; code-reviewed only.

### R39-CB-10 — draining refused connections (P3, accepted)

`server.rs` `refuse_after_draining` (line 2005) reads up to 1 MiB for up to 1 s
per refused connection before closing, so a client sees the refusal instead of
a reset. Bounded by the connection caps. Code-reviewed.

### R39-CB-11 — front truncation and a tampered first record (P3, accepted)

A trail whose oldest records are removed, or whose first record is altered,
still starts and is read: nothing in the remaining records can tell (campaign
9 V6, V2c; `docs/ops/keys.md` "Readers are unaffected"). Only `audit verify`
reports it, and a checkpoint kept elsewhere detects truncation (V6 with
checkpoint: exit 1 Truncated). Reproduced; documented limitation.

### R39-CB-12 — the reviewer's diff missed slot constraints (P2)

- **Where:** `cli.rs` `instruction_changes` / new `slot_changes`.
- **Impact:** `graphite protocol diff` compared a slot by name, signer and
  writable only. A candidate manifest that dropped a token-program slot's
  expected address (the P0-1 positional-trust constraint), changed PDA seeds or
  role, made a slot optional, or changed an alternative layout or a risk rule
  printed "no instruction-level changes" to the reviewer whose attestation
  earns the trust tier. The loader would accept the weaker manifest; only the
  reviewer stands between.
- **Fix:** one slot comparison for the main layout and each alternative
  layout, reporting role, PDA seeds, expected address and optional; risk rules
  compared. Existing lines unchanged. README line updated.
- **Reproduction:** `cli::tests::the_diff_surfaces_every_field_the_runtime_judges_an_account_by`
  (eight edits, both directions; benign control: identical manifests diff to
  nothing). Failed before the fix ("a change of expected address read as no
  change").
- **Break:** B-CB-12 (expected-address comparison disabled): the test fails
  with the same message.
- **Confidence:** high. Reproduced.

### R39-CB-13 — the RPC client and environment proxies (P3, owner decision)

`rpc_client.rs` (line 1841) builds its client with redirects off and the
`GuardedResolver`, but does not call `.no_proxy()`. With `HTTPS_PROXY` set,
the guard judges the proxy's address only; the RPC URL itself is still checked
by `validate_endpoint` at start-up, so a forbidden literal address is still
refused, but a host name is resolved by the proxy. Whether an operator may
route RPC through a proxy is an owner decision. Code-reviewed.

### R39-CB-14 — signer key file mode (P3)

`bin/graphite.rs` (line 699) reads `--signer-key-file` / `GRAPHITE_SIGNER_KEY_FILE`
without the group/other-readable refusal the audit key file has (`t14`: exit 3
for a 0644 audit key). Code-reviewed.

### R39-CB-15 — explain output (P3)

`graphite explain` prints caller-supplied text (intent strings) to the terminal
as given; control characters in an input file reach the terminal. Local tool,
the caller supplies the file. Code-reviewed.

### Classification of panics, unwraps and allocations (production code)

| Site | Kind | Disposition |
|---|---|---|
| `server.rs:1972` | `Response::builder().unwrap()` with a static status, header and body | infallible |
| `server.rs:4654`, `4672` | `panic!` on a non-panic `JoinError` of an audit scan | only on runtime shutdown; caught by `CatchPanicLayer` (500, counted by R39-CB-4) |
| `durable/chain.rs:560`, `978`, `1041` | `unreachable!` after building or checking a JSON object | infallible |
| `durable/archive_index.rs:346`, `347`, `459`, `486` | `try_into().unwrap()` on fixed-width slices of length-checked buffers | infallible |
| `benchmark.rs:104`, `289` | `expect` on built-in static data | offline tool; a failure is a build defect |
| `durable/chain.rs:1698` | buffer of the tail window | at most 4 x 8 MiB (`MAX_LINE_BYTES`) before a forward scan takes over |
| `durable.rs:3422`, `3515` | rows of one key's history | bounded by `bound_history` |
| `durable.rs` per-program / active indexes | grow with the active file | bounded by rotation; unbounded with rotation 0, which warns at start-up |
| `archive_index.rs:236`, `248`, `260` | index build | proportional to one archive, itself bounded by rotation |
| `rpc_client.rs:2070`, `2121` | one slot per requested key | sized by the caller's key list (bounded by the transaction); answers bounded at 32 MiB and 1,000,000 JSON values |
| `server.rs:514` rate-limit buckets | `MAX_BUCKETS` | bounded |
| `operator_boundary.rs:170` | edit-distance row over a variable name | bounded by environment name length |
| Arithmetic | `saturating_*` on lengths and offsets in the trail readers; counters are `AtomicU64` | no unchecked arithmetic on attacker-sized values found |

## 3. Prior findings re-verified

| Id | Status now | Evidence |
|---|---|---|
| R37-2 legacy line before keyed genesis | holds | campaign 9 V1: verify exit 1, server starts on the genuine head, the forged approval not read, L8 join not found |
| R37-3 unkeyed self-hashed forgery | holds | V2a (EOF: verify 1, server refuses), V2b (invented key: refuses), V2c (top: not read, every genuine record read) |
| R37-4 retired key extends the trail | holds | V3: verify exit 1, server refuses |
| R37-5 copied record at EOF | holds | V4: verify exit 1, server refuses; V5 mid-file copy not counted twice |
| R37-11 / T-9 backup and restore under keys | holds | `deploy/tests/backup-keys.test.sh` 22/22 |
| R37-12 index forgery | holds | V8: every index corrupted, server rebuilds, archived verdict still found |
| R37-13 vouched key coverage | holds | its unit test passes; code re-read with R39-CB-5's change |
| R37-14 prune records | holds | V10: pruned trail verifies; an archive deleted beyond the prune is `pruned_without_record` |
| R37-15 / V-2 unknown `GRAPHITE_*` names | holds, server and CLI | campaign 10: server refuses `GRAPHITE_AUDIT_KEY` and the near-miss `GRAPHTIE_AUDIT_KEY_FILE`; the CLI refuses `GRAPHITE_RPC_URLL` |
| R37-16 program deployments | holds | code-reviewed: one undecodable entry becomes `ProgramDeployment::Unreadable` |
| T-6 prefiltered archive scan | holds | code-reviewed: every line still passes the gate |
| T-11 | holds | its unit test passes |
| T-12 exit 4 | holds | `t14`: a trail under none of the keys exits 4 |
| T-13 checkpoint without the key | holds | `t14`: refused with verify's code (2) |
| T-14 exit codes 3 / 64 / 75 | holds | `t14`: 75 beside a running server, 3 unreadable / 0644 key / unreadable checkpoint, 64 usage |
| T-15 line and checkpoint caps | holds | code-reviewed (8 MiB per line, 64 KiB per checkpoint) and existing tests |
| V-3 | holds | code-reviewed in `run_execution` |
| V-5 | holds (registry workstream owns the depth) | code-reviewed `verify_offline` |
| V-6 | not in this scope (`SECURITY.md`) | — |
| T-7, T-8, T-10, V-4 | no record of these ids in the repository | — |
| Truncation and old-backup limitation | holds as documented | V6: exit 0 without a checkpoint, exit 1 Truncated with one; a restored old backup is a rollback only a checkpoint detects |
| Link v2 / prune compatibility docs | present | `docs/ops/keys.md`: upgrade verifiers first; a Round 30–37 binary cannot read a pruned trail |
| Single-replica enforcement | holds on one host | compose `container_name` and `replicas: 1`; the data-dir and trail locks (V13: a second server and a CLI writer refused). Not enforceable across hosts sharing a volume; documented |

## 4. Attack campaigns

All runs on loopback. Harnesses (scratchpad, not committed) drove the real
binary: the `c087bfb` release binary for "pre", the worktree build for "post".

### Campaign 7 — RPC SSRF and redirects (38 checks; pre 38/39, post 38/38)

- **Preconditions:** the server started with `GRAPHITE_RPC_URL` pointing at a
  loopback mock or a forbidden address; no public host contacted.
- **Start-up URL policy:** 19 forms refused at start: link-local metadata in
  dotted, IPv4-mapped, hex-mapped, decimal, hex, octal, two-part and
  trailing-dot forms; IPv6 link-local; AWS IPv6 metadata; Alibaba metadata;
  unspecified v4/v6; multicast v4/v6; broadcast; `file:`; `gopher:`; a
  fragment. (The pre run's one failure was a harness case, `http:///nohost`,
  which parses as host `nohost`; removed.)
- **L8 through a mock:** 307 redirect to another loopback port (not followed,
  the second mock never hit), 500 and 429 (retried, then Unavailable), 418,
  non-JSON, wrong response id, a 40 MiB body, 1.2 million JSON values, a body
  trickling past the per-call timeout: every one Unavailable, never a
  conclusion, within 12 s.
- **DNS rebinding:** tested with an `/etc/hosts` stub (not by reasoning alone):
  `cb-r39-ok.test` pointed at 127.0.0.1 starts and is asked; re-pointed to
  169.254.77.77, a fresh server still starts (names are judged at connect time)
  and the connection is refused by `GuardedResolver`, nothing posted.
  `/etc/hosts` restored in a `finally`.
- **Witness independence:** high assurance refuses a witness that is loopback
  twice, an address and its IPv4-mapped form, an address and its decimal form,
  one host differing in case and trailing dot, and one registrable domain
  under `co.uk`.

### Campaign 9 — audit-trail forgery (44 checks; pre 43/44, post 44/44)

- **Preconditions:** a keyed trail written by the real server; tamper by
  editing files with the server stopped; judge with `graphite audit verify`,
  a restart, and the read endpoints.
- **Rows:** V1 legacy line before keyed genesis; V2a/b/c self-hashed and
  invented-key forgeries; V3 retired key; V4 copied record at EOF; V5 mid-file
  insertion; V6 truncation with and without a checkpoint; V7 a record of
  another trail under the same key at seq+1 (**pre: the server started on
  it — R39-CB-1**); rotation with K2 + previous K1; V11 old key missing (exit 2,
  records still read through the checked adoption), V11b only the retired key
  (exit 4); V12 current key mismatch (refused); V8 every archive index
  corrupted (rebuilt, verdict found); V9 archive tamper (verify 1, server
  refuses); V10 prune and a deleted archive beyond it; V13 a CLI writer and a
  second server beside a running one (refused), 80 concurrent verifications
  (one unbroken chain, verify 0).
- **Disk full (9 checks, pre 9/9, post 9/9):** a real 4 MiB tmpfs (not a fault
  injector) holding the data directory: verdicts and lifecycle reports refused
  503 `AuditWriteFailed` once no byte fits; `/health` degraded with
  `audit_writes_failed`; a 422 still answers 422; space back, the next verdict
  is recorded; readers count exactly the acknowledged verdicts; verify 0; the
  server restarts on it. The first attempt put the server log on the same
  tmpfs and found R39-CB-2.

### Campaign 10 — auth and transport boundary (60 checks; pre 59/60, post 60/60)

- **Start refusals:** admin = verify key, read = verify or admin key, a
  31-character key, no key without dev mode, a CORS wildcard,
  `GRAPHITE_TRUST_PROXY=yes`, an unknown `GRAPHITE_` name, a near-miss outside
  the prefix, dev mode on a non-loopback bind; the CLI's unknown-name refusal.
- **Key separation:** 401 without or with a wrong key; read key cannot verify
  or record; admin key cannot verify; verify and read keys cannot reach
  `/admin`; six path spellings of `/admin/quarantine` under the verify key all
  404; two `Authorization` headers 401; a lower-case scheme is not the key; a
  trailing space is stripped (RFC 9110); `HEAD /metrics` under the read key is
  401 (GET-only scope, noted); `/health` names no key; `/metrics` and the log
  carry no secret.
- **Malformed input:** malformed JSON, non-JSON content type and deep nesting
  422; non-ASCII program id and impossible profile 400; the five shape
  refusals each left an audit row.
- **Body and connection:** a declared and a chunked body over 1 MiB 413; a
  stalled body 408; 401/413/408 leave no audit row (now counted, R39-CB-4); a
  request head that never completes cut at 5 s; a peer's 65th+ connection
  closed at accept; a request abandoned mid-flight leaves the server serving;
  the trail verifies afterwards.
- **Proxy hops:** duplicate XFF lines and comma-joined XFF are keyed by the
  right-most (proxy) entry; no XFF keyed by the peer; fewer entries than hops
  share the unattributed bucket; two MISCONFIG rows (hops set with no proxy, or
  too many hops) let the client rotate buckets (R39-CB-8).
- **CORS:** the allowed origin only; `null`, a suffix-extended host and the
  http scheme refused; no `Access-Control-Allow-Credentials`.
- **Redirect to a hostile host:** `graphite healthcheck --strict` (**pre: exit
  0 — R39-CB-3**).
- **Cancellation and audit append failure:** R39-CB-7 (unit test), the disk-full
  run above, and the existing append-failure tests.
- **Refusal paths that fail to record:** the 422 under a full disk answers 422
  while its error row fails quietly (by design: the verdict path is the one
  that must fail closed, and does, 503).

### Exit codes (`t14`, 11 checks; pre 10/11, post 11/11)

The pre failure is R39-CB-6.

### Test paths

`graphite-core/tests/round39_core_boundary.rs` (4 tests),
`graphite-core/src/durable/chain_trail_tests.rs` (1 test, 1 re-pinned step,
1 ignored measurement), `graphite-core/src/server.rs` (`route_surface` 1,
`tests` 1), `graphite-core/src/cli.rs` (1).

## 5. Invariant evidence

| Invariant | Implementation | Tests | Gap |
|---|---|---|---|
| Audit trail integrity: one grammar for readers and writers | `RecordGate` in `durable/chain.rs`, used by `resume_head`, every reader and `verify` | `chain_trail_tests` (all), campaign 9 | cross-host rollback only detectable with a checkpoint kept elsewhere (R39-CB-11) |
| Cross-trail insertion | `other_trail` refusal (R39-CB-1) | the new trail test and binary test | an unkeyed trail cannot tell trails apart (no MAC) |
| Truncation | checkpoints, prune records | V6, V10 | front truncation without a checkpoint is invisible (documented) |
| Fail closed on audit append failure | 503 `AuditWriteFailed`, `/health` degraded | disk-full campaign, R39-CB-7 test | refusal rows (422) may be lost under a full disk |
| Operational: secrets never logged | key values never formatted; `/metrics` has none | campaign 10 log and metrics rows | — |
| Operational: auth boundary | route layers, key separation | campaign 10 | R39-CB-8 (proxy trust from any peer) |
| Operational: resource use bounded | body 1 MiB, header 5 s, connection caps, RPC 32 MiB / 1M values, `MAX_BUCKETS` | campaigns 7 and 10, R39-CB-5 measurement | coverage memory scales with adopted history (R39-CB-5 residual); rotation 0 is unbounded (warned) |
| No redirect-based trust bypass | RPC and healthcheck clients do not follow redirects | campaign 7, R39-CB-3 test | env proxies for the RPC client (R39-CB-13) |
| Fail closed on RPC failure | `Unavailable` for every transport and decoding failure | campaign 7 | — |
| Evidence integrity (manifest upgrades reviewed) | `protocol diff` shows every judged field (R39-CB-12) | the new diff test | — |
| Deployment and restore documented truthfully | `backup.sh`, `restore.sh`, `rotate-keys.sh` | `backup-keys.test.sh` 22/22 | `deploy/tests/run.sh` BLOCKED |

## 6. Commands run

All Rust commands with `CARGO_TARGET_DIR=/home/user/core-boundary-target
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0` and `-j 2`, from `graphite-core/`.

| Command | Result |
|---|---|
| `cargo test --lib` | 734 passed, 4 ignored (`c087bfb`: 730 passed, 3 ignored) |
| `cargo test --test <suite>` for the 22 suites touching this scope, including `round39_core_boundary` | 121 passed, 0 failed |
| `cargo test --test docs_numbers_match_the_code --test docs_paths_resolve --test docs_match_the_registry` | 8 + 1 + 2 passed |
| `cargo fmt --check` | clean |
| `cargo clippy --lib --bins --tests -- -D warnings` | clean |
| `shellcheck deploy/scripts/*.sh deploy/tests/*.sh` | clean |
| `deploy/tests/backup-keys.test.sh` | 22/22 |
| campaign 7 / 9 / 9-disk-full / 10 / t14 harnesses | see section 4 |
| break copies `/home/user/brk-core-boundary-{1,2,3}` (own target dirs) | B-CB-1 and B-CB-1b separately; B-CB-2, 3, 4 in one copy; B-CB-6, 7 in one copy; B-CB-12 alone. Every break caught by its test; copies deleted |

BLOCKED:

- `deploy/tests/run.sh`: needs a Docker daemon, Caddy and `promtool`, none
  available here.
- `docker build .`: no Docker daemon.
- The full `cargo test` of every suite: not run for disk space; the 22 suites
  touching this scope were run instead.
- `cargo audit`: not run in this workstream (supply-chain workstream).
- Fuzzing of the trail parser: not run (no `cargo fuzz` toolchain set up here).
