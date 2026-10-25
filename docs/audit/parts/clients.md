# Round 39 — clients (brief Phase D; campaigns 11 and 14)

Internal engineering work on `c087bfb`, not an independent audit. Scope: `sdk/typescript/`,
`sdk/go/`, `integrations/agent-guard/`, `integrations/solana-agent-kit/`,
`integrations/mcp-server/`, `integrations/vercel-ai/`, `python-ai-layer/`, `tools/live-measure/`,
`tools/mainnet-sample/`, `examples/`, `schemas/`.

Commits (on top of `c087bfb`): `6fcf8eb`, `0ad3fa7`, `5a04dc7`, `b3859bd`, `f7b7c01`, `8dcf2cb`,
`c0f7d33`, and this report.

## 1. Scope read

152 tracked files. "Read fully" means every line of code end to end (long comment blocks
skimmed where they restate the code). Tests are "read in part": every test name, every
harness and fake, and the assertions of the tests this round depends on.

### TypeScript SDK (`sdk/typescript/`)
| File | Read | Disposition |
|---|---|---|
| `src/types.ts` | fully | R39-CLIENTS-1 fixed (`isExecutable`) |
| `src/client.ts` | fully | R39-CLIENTS-3 fixed (integer spelling and u32 bounds) |
| `src/auditbind.ts` | fully | framed v2 parity confirmed by the corpus |
| `src/transaction-digest.ts` | fully | legacy and v1 parity confirmed by the corpus; v1 frames not parsed (by design, see §4) |
| `src/index.ts` | fully | no finding |
| `src/*.test.ts` (10 files) | in part | `execution-decision.test.ts` re-pinned (R39-CLIENTS-1); `conformance.test.ts` added |
| `README.md` | fully | updated (R39-CLIENTS-1, -3, corpus) |
| `package.json`, `tsconfig*.json` | fully | no finding |
| `package-lock.json` | machine-validated (`npm ci`, `npm audit` + gate) | no finding |

### Go SDK (`sdk/go/`)
| File | Read | Disposition |
|---|---|---|
| `graphite.go` | fully | R39-CLIENTS-1 fixed (`IsExecutable`) |
| `validate.go` | fully | comment updated; strict duplicate/folded-key checks confirmed |
| `digest.go`, `auditbind.go`, `intents.go`, `lifecycle.go` | fully | no finding; parity confirmed by the corpus |
| `*_test.go` (11 files), `testdata/wire_inputs.json` | in part | `decision_test.go` re-pinned; `conformance_test.go` added |
| `go.mod` | fully | `go 1.26`, no dependencies |

### Agent guard (`integrations/agent-guard/`)
| File | Read | Disposition |
|---|---|---|
| `guard.ts` | fully | R39-CLIENTS-7 fixed (swap repeat key) |
| `guard-state.ts` | fully | R39-CLIENTS-6 fixed (state file location) |
| `artifact.ts` | fully | R39-CLIENTS-4 fixed (signatures verified) |
| `execution-lifecycle.ts`, `residual-policy.ts`, `rpc-transport.ts`, `rpc-simulator.ts`, `spend-policy.ts`, `intent-grounding.ts`, `swap-instructions.ts`, `swap-economics.ts`, `swap-envelope.ts`, `swap-programs.ts`, `bound-instruction.ts`, `capabilities.ts`, `tool-results.ts`, `env-names.ts`, `parsed-discriminators.ts`, `cli.ts` | fully | no finding |
| `auditbind.ts` | fully | R39-CLIENTS-9 fixed (non-byte refused) |
| `fees.ts`, `kit-artifact.ts` | fully (code), comments skimmed | no finding |
| `loopback-mocks.ts`, `rpc-fixtures.cjs`, `swap-fixtures.ts`, `wallet-lock-race-child.ts` | in part (the parts the tests here use) | test infrastructure |
| `devnet-test.ts`, `mainnet-benchmark.ts`, `emit-corpus.ts`, `emit-artifact-fixture.ts`, `build_exploit_corpus.mts` | in part (key handling, cluster check, what they write) | dev scripts; `emit:*` re-run, fixtures unchanged |
| `*.test.ts` (26 files) | in part | `guard-round39.test.ts`, `conformance.test.ts`, `guard-crash-child.ts` added |
| `README.md` | in part (every section this round touches) | updated |
| `package.json`, `tsconfig.json`, `package-lock.json` | fully / machine-validated | no finding |

### Framework adapters
| File | Read | Disposition |
|---|---|---|
| `integrations/mcp-server/graphite-mcp.ts`, `server.ts` | fully | no finding; two tests added (injection, approval) |
| `integrations/mcp-server/graphite-mcp.test.ts` | fully | extended |
| `integrations/vercel-ai/graphite-tools.ts` | fully | no finding |
| `integrations/vercel-ai/graphite-tools.test.ts` | in part | no change |
| `integrations/solana-agent-kit/graphite-sak-bridge.ts`, `gated-wallet.ts` | fully | no finding |
| `integrations/solana-agent-kit/*.test.ts` | in part | `zod-override.test.ts` added (R39-CLIENTS-2) |
| `integrations/solana-agent-kit/package.json` | fully | R39-CLIENTS-2 (override across a major, now stated) |
| `integrations/solana-agent-kit/.env.example`, `README.md` | fully | updated |
| `*/README.md`, `*/tsconfig.json`, `*/package.json` (MCP, Vercel AI) | fully | no finding |
| `*/package-lock.json` (MCP, Vercel AI, SAK) | machine-validated | Zod 4.6.7 in all three trees (`npm ls zod`) |

### Python
| File | Read | Disposition |
|---|---|---|
| `python-ai-layer/intent_parser.py` | fully | R39-CLIENTS-5 fixed (burn amount ASCII) |
| `python-ai-layer/test_intent_parser.py` | in part | test added |
| `python-ai-layer/README.md`, `requirements*.txt` | fully | no finding |
| `tools/live-measure/live_mainnet.py` | in part (judging, transport, replay) | R39-CLIENTS-8 fixed |
| `tools/live-measure/solrpc.py`, `wire.py`, `mock_rpc.py`, `live_devnet.py` | in part (transport, frame parsing, key handling) | no finding (see §2, notes) |
| `tools/live-measure/test_live_measure.py`, `README.md` | in part | test added |
| `tools/mainnet-sample/*.py`, `README.md`, `SAMPLES.md` | in part (transport and what is written) | no finding |

### `examples/`, `schemas/`
| File | Read | Disposition |
|---|---|---|
| `examples/decisions/*.json` (4) | fully | the corpus's bases; unchanged |
| `examples/decisions/conformance.json` | written here | campaign 14 corpus |
| `examples/sample-*.json`, `verify-*.json` | fully | no finding |
| `schemas/verification-result-v1.json`, `proposed-intent-v1.json` | fully (machine-checked enums) | both SDKs now pinned to every enum |

## 2. Findings

| ID | Sev | Where | One line | Status | Break |
|---|---|---|---|---|---|
| R39-CLIENTS-1 | P2 | `sdk/typescript/src/types.ts` `isExecutable`; `sdk/go/graphite.go` `IsExecutable` | a verdict with no `decision` was judged by recomputation alone and called executable; the Core and the guard refuse it | fixed with test | B1, B1g, B2 caught |
| R39-CLIENTS-2 | P3 | `integrations/solana-agent-kit/package.json` overrides; `.github/npm-audit/solana-agent-kit.allow` | the Zod 4.6.7 override crosses a major line for SAK (`zod ^3`) and breaks SAK's `createOpenAITools`; the allowlist said every override stayed in its major | documented limitation, pinned by test | n/a (a pin) |
| R39-CLIENTS-3 | P3 | `sdk/typescript/src/client.ts` validators | an integer field spelled `215.0` / `2.15e2`, or a u32 limit past 2^32, was read; serde and Go refuse it | fixed with test | B3, B3b caught |
| R39-CLIENTS-4 | P3 | `integrations/agent-guard/artifact.ts` `signApproved` | a signer whose key pair halves belong to two keys passed the signer-set check; the lifecycle recorded and sent an unverifiable transaction | fixed with test | B4 caught |
| R39-CLIENTS-5 | P3 | `python-ai-layer/intent_parser.py` `_RX["burn"]` | the burn amount used `\d` (any Unicode digit); masked by the NON_ASCII_DIGITS refusal | fixed with test | B5 caught |
| R39-CLIENTS-6 | P3 | `integrations/agent-guard/guard-state.ts` `GuardState.open` | the state file's directory and file were never checked; a writable-by-others location let the file be swapped before a restart | fixed with test | B6 caught |
| R39-CLIENTS-7 | P3 (residual of G2-2) | `integrations/agent-guard/guard.ts` `swapRequestKey` | the swap repeat key named the route's amount in; after an outcome-unknown swap the same request through a route spending one base unit less was sent again | fixed with test | B7 caught |
| R39-CLIENTS-8 | P3 | `tools/live-measure/live_mainnet.py` `recomputed_decision` | the live-measure defect check read missing codes as none and prose without a code as nothing | fixed with test | B8 caught |
| R39-CLIENTS-9 | P3 | `integrations/agent-guard/auditbind.ts` `computeHash` | the guard's AuditBind hashed `[256]` as `[0]` (Buffer.from wraps); the SDK and serde refuse it | fixed with test | B9 caught |

### R39-CLIENTS-1 — the SDKs executed a decision-less verdict (P2)
- **Where:** `isExecutable` (TS, `types.ts`) and `IsExecutable` (Go, `graphite.go`):
  `decision === undefined && executable === undefined` returned the local recomputation.
- **Preconditions:** a verdict without `decision`/`executable` — a server older than Round 30, a
  proxy or cache that strips unknown fields, or a verdict re-serialized by a consumer's own type.
- **Impact:** the SDKs called it executable while the Core's own `is_executable` (serde default
  `blocked`) and the agent guard (Round 34) refuse it. A Round 30-era server predates
  `intent_parameters`, `program_deployments`, the sibling and creation rules; recomputing the
  rule over its fields is looser than the current Core. The guard was not affected.
- **Reproduction:** corpus vector "missing: decision and executable (a server before Round 30)";
  `sdk/typescript/src/conformance.test.ts`, `sdk/go/conformance_test.go`; the guard's
  "signs exactly what isExecutable calls executable" also fails on the old SDK.
- **Fix:** both SDKs require the reported decision; the verdict stays readable.
  `computeExecutionDecision` is unchanged. Re-pinned:
  `execution-decision.test.ts` "a server older than Round 30 is readable, and never executable"
  (was "…judged by the recomputation alone", asserting executable) and
  `TestAServerOlderThanRound30DecodesAndIsNeverExecutable` (was `…IsJudgedByTheRecomputation`).
- **Compatibility:** a deployment that executes against a pre-Round-30 Core through the SDKs now
  refuses every verdict; upgrade the Core (the guard has required it since Round 34).
- **Confidence:** high; reproduced.

### R39-CLIENTS-2 — a dependency override that hid an incompatibility (P3)
`solana-agent-kit` 2.0.10 declares `zod ^3.24.1` and reads Zod 3 internals (`_def.typeName`,
`z.ZodEffects`); the package's override forces `zod` 4.6.7 (past GHSA-mrhx-c7xc-m3w5, every Zod
below 4.6.6; no patched Zod 3 exists). Under it SAK's `createOpenAITools` throws
`TypeError: Right-hand side of 'instanceof' is not an object` (reproduced). Nothing shipped loads
SAK (pinned since Round 36); the SAK tests never reach its tool adapters, so every test was
green. `@openai/zod` (declared `npm:zod@^3.25.40`) is forced to the same 4.6.7; the OpenAI agents
SDK imports only `@openai/zod/v3`, which Zod 4 still ships, so that one is compatible.
Status: stated in the allowlist comment, the SAK README and `zod-override.test.ts`, which fails
once SAK reads Zod 4. Owner decision only if the dev tree should carry SAK's tool adapters.

### R39-CLIENTS-3 — integer spellings and widths in the TS validator (P3)
`JSON.parse` turns `215.0` and `2.15e2` into 215; the validator's `isCount` accepted them for
`transaction_bytes`, every `transaction.*` count, compute-budget fields, slots and receipt counts;
and it held the four u32 compute-budget fields to 2^53. serde (the Core) and Go refuse all of
these. The reviver's `context.source` (Node 22) now records number spellings in
`parseJsonStrict`, and `countAt` refuses a fraction or exponent spelling and a u32 field past
4,294,967,295. Float fields (`confidence`, `raw_value`) are unaffected (a control vector spells
`confidence` with an exponent). No decision field is numeric, so this was never a signing
bypass; it made TS looser than the Core, which the corpus forbids. Reproduced by the corpus.

### R39-CLIENTS-4 — signatures were never checked after signing (P3)
`assertSignersMatchTheMessage` compares each signer's `publicKey` with the message; kit's
`signTransaction` signs with `keyPair.privateKey`. A `{ publicKey: P, keyPair: { publicKey: P',
privateKey: K } }` with P' = P and K another key passed both: `signApproved` returned bytes whose
fee-payer signature verifies under no key the message names (reproduced:
`crypto.subtle.verify` false), and `executeBoundTransaction` recorded "signing" on the trail and
sent them. Nothing could move (no validator accepts the transaction), but the trail recorded a
signing that did not happen, and the guard kept an outcome-unknown submission under an id that
names nothing, holding back the same request until its blockhash expired. The guard's own signer
is checked at import (`createKeyPairFromBytes` signs and verifies), so this needs a caller of the
exported `executeBoundTransaction` / `BoundTransaction` with a wrong or hostile key store. Fix:
every slot must verify over the approved message under the address the message names, before
the bytes are returned. Tests: `guard-round39.test.ts` (repro at `signApproved` and through
`executeBoundTransaction`: nothing recorded, nothing sent; control with a web3.js `Keypair` and a
non-extractable WebCrypto pair).

### R39-CLIENTS-6 — the state file's location (P3)
The wallet-lock directory must be private (Round 34); the state file's directory never was
checked. In a directory another user can write (group-writable, or `/tmp`-like without the
owner's protection), that user can rename the state file away and plant one without the
reservations or unresolved submissions; the running guard keeps its own copy, but the next start
replays the planted one: the allowance back in full, and a request whose earlier submission may
still land built again. Fix: `assertPrivateStateLocation` — the directory owned by this user and
not group/other-writable, an existing file a regular file (not a symbolic link) of this user's
that no one else can write; on Windows only the kinds (as G2-6). Tests: refusal for 0770, 0777,
1777 directories, a 0666 file and a symlinked file; controls for 0700 and 0755. Compatibility: a
deployment keeping its state file in `/tmp` or a shared-group directory now refuses to start
(the README and `.env.example` say so).

### R39-CLIENTS-7 — a swap's repeat was keyed by the route's amount (P3, residual of G2-2)
Round 38 keyed a swap by wallet, input mint, output mint and the route's decoded `amountIn`. The
route chooses that amount and may set it below what the request allows (`decoded.amountIn <=
requested` is all `assertSwapEconomics` requires). Reproduced: after an outcome-unknown
"Swap 1 SOL for USDC" through a route spending 1,000,000,000 lamports, the same request through a
route spending 999,999,999 was a new key and was built, verified and sent — two swaps for one
request, bounded only by the caps. Fix: the key is the request's own amount
(`swap:v3:<wallet>:<in>:<out>:<canonical decimal>`; "1", "1.0" and "01.00" are one amount); a
`swap:v2` record (Round 38) and the Round 30–37 route form still hold back the swap they name.
Control: "Swap 2 SOL for USDC" is another request and executes (under the old key it was held
back by the 1 SOL record because both routes spent 1 SOL).

### R39-CLIENTS-5, -8, -9 (P3)
- **-5:** `_RX["burn"]` used `\d`; every other amount has been ASCII since Round 30. The
  whole-text NON_ASCII_DIGITS refusal ran first, so no label carried a non-ASCII amount; the new
  test holds every amount pattern to ASCII on its own. Code-reviewed; regex-level repro.
- **-8:** `recomputed_decision` (the live-measure defect detector) read missing
  `unobserved_codes` as none, prose without a code as nothing and needed no digest, so a Core
  verdict executable over an unnamed residual would not have been reported as a defect.
- **-9:** `AuditBind.computeHash` (the guard's copy, re-exported by the SAK adapter) hashed
  `[256]` as `[0]`. The guard's own callers pass real bytes; an external caller could have bound
  a projection of different bytes. Reproduced by the guard's corpus test.

### Reviewed, no finding (what was attacked)
- **Unknown enums / residuals:** both SDKs refuse an unknown decision, residual code, layer
  status, risk status, policy, identity, trust tier, scope kind and message version at the
  validator; the guard refuses unknown codes and decisions again. Corpus: 102 vectors.
- **Exact bytes:** `BoundTransaction` keeps the transaction in an ES private field, re-encodes
  and re-hashes immediately before signing (no await between), checks the signed message equals
  the verified one, signs once (`#consumed`, set before the first await), and the lifecycle sends
  only the bytes `signApproved` returned. The SDK digest zeroes slots as `unsigned_artifact` does.
- **Stale verdict:** checked before signing and again before the send (G2-3), monotonic clock.
- **Concurrency / duplicates:** per-request in-flight claim (synchronous), aggregate reservation
  synchronous, `RequestInFlight`, and an outcome-unknown submission recorded before the send.
- **Transport:** every RPC request through `boundedRpcFetch` (only the configured URL, no
  redirects, deadline over headers and body, 32 MiB); Core 16 MiB; AI layer 64 KiB; http only to
  loopback for all three; `globalThis.fetch` captured at load.
- **MCP:** confirmation by elicitation after the verdict (only a boolean `true` approves, new
  test); the injected-instruction test; input bounds (500-char request, 64 accounts, 4,096 data
  bytes, 8 tables, hex selector); F-001 bound re-verified.
- **Vercel AI:** `needsApproval: true` and a required `confirm` hook (K-01); same bounds.
- **SAK:** the gated wallet holds no secret; importing the adapter loads no SAK and no Zod.
- **Python:** deterministic (sorted manifest listing, no randomness, no network), advisory only
  (the guard reads four strings, the label and nothing else, and re-grounds them); the HTTP
  server is bounded (body, per-read and whole-request deadlines, 32 connections, Origin and Host
  checks, JSON only, duplicate keys refused).
- **Tools:** `live_devnet.py` refuses any cluster but devnet or a loopback validator by genesis
  hash; `live_mainnet.py` sends only unsigned bytes to a local Core. `urllib` follows redirects
  and would re-send an `Authorization` header on a GET to the tool's own loopback Core; accepted
  (a child process on loopback, a throwaway key).

## 3. Prior findings re-verified (against the code at `c087bfb`, then this round)

| ID | Status now | Evidence |
|---|---|---|
| R37-17 | holds | `defaultWalletLockDir` reads `os.userInfo().homedir` only; a non-absolute home refuses; `guard-round38.test.ts` (SSH vs cron, account-derived default) pass |
| G2-2 | holds, with a residual fixed here | route-independent key confirmed; the key still named the route's amount — R39-CLIENTS-7 |
| G2-3 | holds | `assertFresh(true)` after the signing record, nothing awaited before `beforeSubmit` and the send; tests pass |
| G2-4 | holds | `neverConnectedCode` (ECONNREFUSED / ENOTFOUND / EAI_AGAIN, cause chain, AggregateError all-of); `#cannotLand` asks again after reading the height; tests pass |
| G2-5 | holds | `NEVER_ACCEPTABLE` refuses `intent_parameters` in the constructor and in `assertExecutable`; corpus: `guard_accepting_all` refuses it |
| G2-6 | guard half holds (Windows a documented limitation); dashboard half not in this scope | README and startup log; `assertPrivateDirectory` skips owner/mode on win32 |
| F-001 | holds | Zod 4.6.7 in the MCP, Vercel AI and SAK trees; `.max` bounds on every collection; the 2,000,000-element tests pass in MCP and Vercel AI; the SAK adapter's module graph has no Zod. New: the SAK dev tree's override is a cross-major one (R39-CLIENTS-2) |
| F-014, F-017 (guard) | hold | `rpc-transport.ts`; `resolveMaxVerdictAgeMs`; tests pass |
| R37-16 / F-003 consumers | hold | both SDKs, the guard and the schema list `program_deployments` and `intent_parameters`; now pinned to the schema enum in both SDKs |
| G-5 / G-01 (guard decision) | holds | `assertExecutableVerdict` requires `decision`; corpus: the guard signs exactly what `isExecutable` calls executable |

## 4. Attack campaigns

### Campaign 14 — cross-language disagreements
- **Preconditions:** none; static data.
- **Fixture:** `examples/decisions/conformance.json` (extends `examples/decisions/`, whose four
  real Core verdicts are the bases). 102 verdict vectors: the four decisions; 5 unknown or new
  decision values; 8 invalid decision/executable/approved combinations; 13 missing fields; every
  one of the 15 non-inherent residual codes twice (still claiming executable, and as an honest
  `analysis_only`); 4 unknown codes; 4 more residual vectors (prose without a code, a code
  without prose, an inherent code twice, a descriptive verdict); 7 binding vectors (digest case
  and length, simulated false, unknown kind, descriptive with a digest, bind-key mismatch,
  message version); 10 schema-field vectors; 12 integer-boundary vectors (0, -1, 2^53+1,
  u64::MAX, u64::MAX+1, float and exponent spellings and a float field's control, u32 limits, a
  non-finite float); 5 duplicate,
  escaped and case-folded key vectors. 8 content-hash vectors (framed v2, computed independently
  in Python when the corpus was written, including the committed verdict's own key and the
  boundary-shift pair). 13 digest vectors (legacy and v1, signed and unsigned, malformed frames).
- **Commands:** `cargo test --no-default-features --features cli --test round39_conformance_corpus`
  (3 tests); `sdk/typescript` `npm test` (`src/conformance.test.ts`, 6 tests); `sdk/go`
  `go test` (`conformance_test.go`, 4 tests); `integrations/agent-guard` `npm test`
  (`conformance.test.ts`, 4 tests).
- **Pre-fix behaviour:** TS and Go executable on "missing: decision and executable" (Rust and the
  guard: not); TS executable on `215.0`, `2.15e2` and `compute_unit_limit: 4294967296` (Rust and
  Go: unreadable); the guard's AuditBind hashed `[256]`.
- **Expected / observed now:** every language gives the corpus outcome; no client is executable
  where the Core's rule is not; every vector on which executable-ness differs carries a note.
  Where clients are stricter than the Core's type (it defaults an absent `layers`, mismatch flag
  or `unobserved_codes`, holds the digest, tier and message version as strings, and does not
  range-check `confidence` or `transaction_bytes`) the Core never writes such a verdict; recorded
  for the Core workstream, not a client defect.
- **Digests:** where the Core computes a digest the SDKs compute the same or refuse. The SDKs
  refuse a legacy frame with no signature (the Core's pre-parse digest reads it), and compute a
  digest for a v1 frame with an unknown mask bit, which the Core refuses: the SDKs zero the
  trailing slots without parsing a v1 message (documented in `transaction-digest.ts`); the Core
  never approved such a frame, so no digest of it can match an approval.
- **Not done here:** the dashboard's rendering of the corpus (Phase E workstream) and the API/CLI
  output for each vector (the Rust column is the Core's type and rule, not a server round trip).

### Campaign 11 — agent guard
| Attack | Preconditions | Fixture / test | Pre-fix | Now |
|---|---|---|---|---|
| exact-byte TOCTOU, mutation after approval | foothold in the process | `bound-transaction.test.ts`, `toctou-signing-boundary.test.ts`, `execution-boundary-fuzz.test.ts` | refused | refused (re-run) |
| stale verdict | slow confirm / slow trail | `guard-round35`, `guard-round38` (F-017, G2-3) | refused | refused |
| duplicate sign | concurrent `signApproved` | `bound-transaction.test.ts` "two concurrent signings" | once | once |
| signer swap | wrong signer set | `bound-transaction`, `execution-boundary-fuzz` | refused | refused |
| malicious wallet adapter / key store | a signer whose private half is another key's | `guard-round39.test.ts` R39-CLIENTS-4 | **signed and sent unverifiable bytes** | refused before anything is recorded |
| unknown residual, new enum | newer Core | corpus (guard columns), `residual-policy.test.ts` | refused | refused |
| RPC failure | refused connect, timeout, trickle, 429, oversize | `guard-round35`, `guard-round38` (F-014, G2-4) | handled | handled |
| redirect | RPC / Core / AI layer 3xx | `guard-round35` F-014; SDK `redirect: "error"`; Go `CheckRedirect` | refused | refused |
| concurrent requests | parallel calls | `guard-round35` "eight parallel transfers" | bounded | bounded |
| duplicate request | outcome-unknown then retry | `guard-round39` R39-CLIENTS-7 | **sent twice through a route one base unit cheaper** | refused |
| lock-directory manipulation | a writable lock or state directory, deleted / replaced lock | `wallet-lock-integrity.test.ts`; `guard-round39` R39-CLIENTS-6 | state directory unchecked | refused |
| process crash | SIGKILL after the submission was recorded unresolved | `guard-round39` "crash", `guard-crash-child.ts` (a real child, killed with SIGKILL) | — | the next guard takes the dead locks, counts the reservation, refuses the repeat |
| Windows path / permission | Windows host | reasoned, not run (Linux container) | — | see below |

**Windows, reasoned.** (1) No uid/mode: the lock directory's and the state file's owner and access
are not checked (G2-6, now also R39-CLIENTS-6); the default lock directory is in the user's
profile. (2) `O_NOFOLLOW` is 0 on Windows: a symbolic link at a lock path would be followed by the
reads; planting one needs the directory (private by default) and, for a file symlink, a
privilege. (3) Case-insensitive file names: `wallet-<base58>.lock` for two keys whose base58
differs only in case would collide — a second guard refuses to start (fail closed); grinding a
case-variant of a given key is a preimage search. (4) pid reuse is more frequent; a stale lock
whose pid is live refuses to start (fail closed). (5) Reserved names cannot occur (`wallet-` and
base58). (6) `rename` of an open file: libuv opens with `FILE_SHARE_DELETE`; the state file is
compacted before its descriptor is opened. None of these is a bypass; (1) is the known limitation.

## 5. Invariant evidence

| Invariant | Implementation | Tests | Gap |
|---|---|---|---|
| Executable is stricter than approved | SDK `isExecutable` / `IsExecutable` (decision required, rule recomputed); guard `assertExecutableVerdict` | corpus (102 vectors × 4 implementations); `execution-decision.test.ts`; `decision_test.go`; `residual-policy.test.ts` | none known in clients |
| Unknown enums / residuals refuse | SDK validators; guard `KNOWN` check | corpus; schema-enum tests (both SDKs) | — |
| Cross-language parity | one corpus | `round39_conformance_corpus.rs`, `conformance.test.ts` ×2, `conformance_test.go` | the dashboard and the HTTP/CLI output are not run over the corpus |
| Exact artifact binding / no TOCTOU | `BoundTransaction`; SDK `verifyTransactionDigest` | listed in campaign 11 | — |
| Signatures are the message's | `assertEverySignatureVerifies` (new) | `guard-round39.test.ts` | — |
| AI non-authority | guard grounding; Python label advisory; the Core never reads `confidence_of_parse` | `intent-grounding.test.ts`; MCP injection test | — |
| Bounded resources | SDK 16 MiB, guard RPC 32 MiB + deadline, AI 64 KiB, Zod bounds, Python server bounds | `execution-decision.test.ts` K-03, `guard-round35`, MCP/Vercel F-001, Python server tests | — |
| Fail closed on persistence | state written before the step it protects; locks re-checked; location checked (new) | `guard-round30/32/38/39`, `wallet-lock-integrity` | Windows ACLs (documented) |

## 6. Commands run (this container, Linux; Node 22.22.0, Go 1.26.10 and 1.27.3, Python 3.13.16, pytest 9.1.1)

Every leg as `.github/workflows/ci.yml` runs it (`npm ci --ignore-scripts`, `NODE_OPTIONS=--test-reporter=tap`, `test-count.sh`).

| Leg | Baseline (`c087bfb`) | After this round |
|---|---|---|
| TS SDK `npm run check`, `npm test`, `npm run build` | clean; 62 passed, 4 skipped (live); builds | clean; 68 passed, 4 skipped (live); builds |
| TS SDK live-server tests against `/home/user/bin/graphite-c087bfb` on 127.0.0.1 | — | 71 / 71 (the 4 live tests included), with this round's SDK at `f7b7c01` |
| agent guard `npm run typecheck`, `npm test`; `emit:artifact-fixture`, `emit:corpus`, `git diff --exit-code` on the two fixtures | clean; 330 passed; fixtures unchanged | clean; 343 passed; fixtures unchanged |
| Vercel AI typecheck + tests | clean; 12 | clean; 12 |
| MCP server typecheck + tests | clean; 10 | clean; 12 |
| SAK adapter typecheck + tests | clean; 10 | clean; 11 |
| Go `gofmt -l`, `go vet`, `go test -count=1 -v` on 1.26.10 and 1.27.3 | clean; 62 / 62 | clean; 66 / 66 |
| Go live-server tests (`-tags liveserver`) against the c087bfb binary | — | 5 / 5 `TestLive*` |
| pytest `python-ai-layer` / `tools/mainnet-sample` / `tools/live-measure` | 50 / 7 / 57 | 51 / 7 / 60 |
| `node --test .github/npm-audit/gate.test.mjs` | 10 / 10 | 10 / 10 |
| npm audit + `gate.mjs`, six packages | all pass (agent-guard 4 moderate listed; SAK 5 listed) | all pass (unchanged) |
| Rust `cargo test --locked --no-default-features --features cli --test round39_conformance_corpus` | — | 3 / 3 |
| `cargo clippy --no-default-features --features cli --test round39_conformance_corpus -- -D warnings`; `rustfmt --check` | — | clean |
| Deliberate breaks B1–B9 (copy at `/home/user/brk-clients-1`) | — | all caught (§2) |

Not run here: the Rust default and lib legs (the new test is not feature-gated except its
content-hash test, which needs a runtime; CI's default and cli legs both compile it), the
dashboard (another workstream), and the Windows behaviour (reasoned, §4).

## 7. For the main session
- **CI floors** (minimums; the counts here are higher): TS SDK 62 → 68, guard 330 →
  343, MCP 10 → 12, SAK 10 → 11, Go 59 → 66, pytest AI 50 → 51,
  live-measure 57 → 60. Raising them is the CI workstream's edit.
- **CURRENT / CHANGELOG / SECURITY:** R39-CLIENTS-1 changes SDK behaviour (a verdict without
  `decision` is never executable) and R39-CLIENTS-6 can refuse a deployment whose state file sits
  in `/tmp` or a shared directory; both belong in the operator-facing notes. R39-CLIENTS-7 changes
  the guard's state-file key format (`swap:v3`); old records are still honoured.
- **Break log:** B1–B9 above, continuing the log.
- **For the Core workstream (informational):** the Core's `VerificationResult` type defaults an
  absent `layers`, `privilege_mismatch` and `unobserved_codes`, holds the digest, trust tier and
  message version as strings and does not range-check `confidence`; the corpus records each with
  a note. No Core code path reads a verdict it did not write, so none is a defect today.
