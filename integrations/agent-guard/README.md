# Graphite Agent Guard

The verification gate between an AI agent and a Solana signing key, independent of any
agent framework. Every integration in this repository signs only through
`GraphiteGuard`; the [Solana Agent Kit adapter](../solana-agent-kit/README.md) is a thin
layer over it. Status is the project's:
security-hardened alpha, no independent third-party audit yet
([docs/CURRENT.md](../../docs/CURRENT.md)).

It depends on `@solana/kit`, `@solana/web3.js` and `bs58` only. It does not depend on
`solana-agent-kit` (R-P8 phase 3, 2026-10-02), so the gated `bigint-buffer` advisory
that package's `@solana/spl-token` 0.4 tree carries is not in it; its lockfile has no
high or critical npm advisory, and CI fails if one appears
(`.github/npm-audit/agent-guard.allow`).

## Architecture

```
user's request ─▶ AI layer (advisory parse) ─▶ grounding in the user's own text
               ─▶ ONE transaction built (legacy, v0 or v1) ─▶ RPC simulation, unsigned
               ─▶ Graphite Core verifies those exact bytes ─▶ residual policy
               ─▶ the approved bytes signed ─▶ signing on the audit trail ─▶ submitted
               ─▶ submission on the trail ─▶ confirmed ─▶ L8 reconciles what landed
```

Constitution P1 (AI assists, never decides): the AI layer only proposes a reading of
the request, and the guard accepts it only where it matches the user's own words.
Graphite Core's deterministic engine makes every security decision; the guard signs
only on its approval.

## Prerequisites

1. **Graphite Core** running:
   ```bash
   cd graphite-core
   GRAPHITE_API_KEY=$(openssl rand -hex 32) cargo run --release -- server
   # or GRAPHITE_DEV_MODE=1 for an unauthenticated loopback-only instance
   ```

2. **Python AI layer** running:
   ```bash
   cd python-ai-layer
   python3 intent_parser.py --serve
   ```

3. **Environment** (or the same fields in `GraphiteGuard.create({...})`):
   ```bash
   export SOLANA_PRIVATE_KEY="<base58 secret key of the agent's wallet>"
   export SOLANA_RPC_URL="https://api.devnet.solana.com"
   export GRAPHITE_CORE_URL="http://127.0.0.1:7331"
   export GRAPHITE_API_KEY="<the Core's key>"
   export GRAPHITE_MAX_TRANSFER_LAMPORTS=100000000   # required (Round 29): 0.1 SOL per transaction
   ```
   Every variable the guard reads is listed in
   [`../solana-agent-kit/.env.example`](../solana-agent-kit/.env.example).

## Installation

```bash
cd integrations/agent-guard
npm ci --ignore-scripts
```

## What the guard guarantees

The guard is the reference execution boundary for Graphite. Its invariant, attacked in
Rounds 6–9 (`docs/round6-execution-boundary-2026-09-11.md` onward): **the exact
message Graphite approved is the exact message in the bytes that are signed and
submitted — and nothing is signed under a residual the operator has not accepted.**

- Both `executeTransfer` and `executeSwap` build **one** `BoundTransaction`
  (`artifact.ts`) *before* verification, from deep-copied instructions, and send its
  bytes as `signed_transaction`. No alias to the transaction exists outside it.
- Execution requires `scope.kind === "artifact_bound"`. A descriptive verdict never
  executes.
- **Residual policy (Round 9).** Every verdict names what Graphite did not observe as
  codes (`scope.unobserved_codes`). Two are inherent to every artifact-bound verdict
  (`program_semantics`, `inner_instructions`). Every other code — `no_state_diff`,
  `simulation_failed`, `not_simulated`, `privileges_from_caller`, `privileges_absent`,
  `lookup_tables_unresolved`, `artifact_unparsed`, `account_identity_unparsed`,
  `instruction_not_located`, `intent_parameters` (Round 36) — **refuses execution** unless the operator names it in
  `GRAPHITE_ACCEPT_UNOBSERVED` (comma-separated) or `create({ acceptUnobserved })`. A
  typo in that list is a startup error; a Core that reports no codes (pre-Round-9) is
  refused. `intent_parameters` cannot be named at all (Round 38, G2-5): it says the Core
  could not tie the request's amount, recipient or asset to the bytes, and accepting it
  switched that binding (F-003) off for every request of the deployment. Naming it refuses
  to start, before anything is contacted. The codes accepted for an execution are recorded on
  `outcome.lifecycle.acceptedUnobserved`. See `residual-policy.ts`.
- **The lifecycle is on Graphite's trail, in order, under the exact keys (Rounds 9–10).**
  `execution-lifecycle.ts` is the only path from verdict to network: policy →
  `signApproved` → `POST /audit/event` `signing` → submit → `POST /audit/event`
  `submission` → confirm → `POST /verify/execution` (L8). Every call carries
  `audit_trail_id` and `transaction_sha256` with the `content_hash`. A signing that
  cannot be recorded, whose `verdict_on_record` is not `approved`, or that the server
  resolved by any key other than `audit_trail_id`, aborts *before* submission; after
  submission every failure is reported on `outcome.lifecycle` and none is hidden. L8's
  `reconciliation` comes with `attribution` (`chain` when Graphite joined on the bytes
  behind the signature itself, checked to be that signature's) and
  `caller_keys_disagree`; a `chain_bytes_rejected` answer is logged as `L8 REFUSED`
  and is never read as a pass.
- `bound.signApproved(scope.transaction_sha256, [wallet])` is the only signing path: it
  recomputes the digest of the exact bytes, derives the required signer set from the
  compiled message, refuses any mismatch, and returns the only bytes that go to
  `sendRawTransaction`. A refreshed blockhash, changed fee payer, appended instruction,
  rewritten amount or flipped flag after approval is refused.
- `executeSwap` requires the built payload (program id, discriminator, accounts with
  real flags, data). Without it there is nothing to bind and the bridge aborts. The
  unverified-swap opt-out (`GRAPHITE_SWAP_ALLOW_UNVERIFIED_EXECUTION`) was **retired in
  Round 19** (F-19-C2): it executed through SAK's own builder with the key SAK held, and
  SAK no longer holds a key that can sign. Setting it now changes nothing, and the
  abort message says so by name.
- **SolanaAgentKit never holds a signing key (Round 19, F-19-C2).** SAK is constructed
  with `VerificationGatedWallet` (`gated-wallet.ts`): the public key, and every signing
  method (`signTransaction`, `signAllTransactions`, `signAndSendTransaction`,
  `signMessage`) throws `UngatedSigningRefused` naming the verified path. SAK's read-only
  tools keep working; anything that would sign outside `signApproved` cannot.
- **Nothing is signed before the verdict (Round 19, F-19-C1).** The pre-verdict RPC
  simulation (`rpc-simulator.ts`) compiles an unsigned `VersionedTransaction` from the
  fee payer's PUBLIC key and simulates it with `sigVerify: false` and
  `replaceRecentBlockhash: true`; every signature slot is read back from the serialized
  bytes and must be zero, or nothing is sent. Before Round 19 web3.js's
  `simulateTransaction(tx, [keypair])` signed the transfer on a live blockhash and handed
  a broadcastable transaction to the RPC before Graphite had answered.
- **The intent check is grounded in the user's words (Round 19, F-19-C5).** The AI layer
  is advisory; `intent-grounding.ts` re-derives the amount and destination of a transfer
  deterministically from the natural-language text and refuses a parse that disagrees
  (`IntentGroundingError`), and the parse must echo the text it was given. The intent
  sent to the Core is the grounded one, so the Core's transaction-versus-intent check no
  longer compares the AI's output with itself.
- **A swap is grounded the same way, and then held to it (Round 25, second external
  review).** `groundSwapRequest` reads the amount and both tokens from the user's text
  ("swap <amount> <token> for <token>" or "buy <token> with <amount> <token>"; one amount;
  symbols from `KNOWN_TOKEN_MINTS`, any other token by its mint address) and the AI layer's
  reading must agree on all three. The exact transaction is then simulated and must spend no
  more than the requested amount of the requested token (plus 0.01 SOL for fees and rent),
  spend no other token, and deliver the requested token (`assertSwapEffectMatches`), before
  the Core is asked. A request that says what it receives but not what it spends is refused.
  Since Round 36 (F-003) the swap intent sent to the Core names the grounded MINTS
  (`"SOL"` for the native mint), not the symbols as written: the Core binds the stated
  amount and tokens to the bytes, reads a token only as `"SOL"` or a base58 mint, and
  names whatever it could not bind `intent_parameters` — a non-inherent residual the
  residual policy always refuses (since Round 38 no operator can accept it).
- **A request that negates or cancels what it names is refused** (`assertAffirmative`):
  "Don't send 1 SOL to …", "Never swap …", "Cancel the transfer …", "Hold off …", "Please
  refrain …". Grounding establishes what a request names; this establishes that it asks
  for it. Rephrase to act.
- **Only the accepted form is acted on (Round 29, audit 2026-10-20, H3/M5).** A transfer
  is built only from a request that is, as a whole, `[please] send|transfer|pay <amount>
  SOL to <address>` (ASCII decimal amount, at most 9 decimal places, optionally ending
  with "." or "!"). Grounding used to check one address, one number and the word SOL, so
  "Receive 5 SOL from A", "A owes me 5 SOL", "What would happen if I sent 5 SOL to A?",
  "Tomorrow, send …", "Do n0t send …" were transfers TO A, and "5000 lamports of SOL",
  "$20 of SOL", "-5 SOL" and "5 mSOL" were that many SOL. Questions, conditions,
  deferrals, other units, currencies, signs, non-ASCII digits and extra words are now
  refused with the accepted form named. Swaps have the same positive grammar ("swap
  <amount> <token> for <token>" / "buy <token> with <amount> <token>", optionally "for at
  least <amount> <token>" and "with <n>% slippage"). The class sent to the Core is the
  method's (`transfer` / `swap`), never the AI layer's label, and only grounded values
  travel in `proposed_intent`.
- **A swap is held to its own minimum (Round 29, H2/H4).** The Core does not read a
  route's minimum output; the guard does. A swap is built only from an exact-in
  instruction whose data `swap-instructions.ts` decodes, every byte, from the IDLs
  committed under `graphite-core/scripts`: Jupiter v6 `route` / `shared_accounts_route`
  (platform fee 0), Orca Whirlpools `swap` / `swapV2`, Raydium CPMM `swap_base_input`,
  Raydium CLMM `swap` / `swap_v2`, Raydium AMM v4 `SwapBaseIn`, Meteora DLMM `swap` /
  `swap2` — `SWAP_PROGRAM_IDS` is exactly these programs (it used to be 46, DCA, limit
  orders, perps, a bridge and lockers among them). Exact-out forms are refused by name;
  Jupiter `route_v2` is refused because no committed IDL carries its deployed layout. The
  route may spend no more than the request names; its minimum must be above zero, at most
  what the simulation delivered, and within the allowed slippage of it (the request's
  "with n% slippage", else `GRAPHITE_SWAP_MAX_SLIPPAGE_BPS`, default 100, never above
  500); and it must meet a price floor — the request's "for at least …" or the operator's
  `GRAPHITE_SWAP_MIN_RATES` ("SOL/USDC=100", output units per input unit). With neither,
  the swap is refused unless `GRAPHITE_SWAP_ALLOW_UNPRICED=1`, logged at startup as an
  accepted risk (`swap-economics.ts`).
- **The envelope around a swap is the guard's (Round 29, L4).** Optionally a ComputeBudget
  limit and price (`GRAPHITE_SWAP_COMPUTE_UNIT_LIMIT`, `GRAPHITE_SWAP_COMPUTE_UNIT_PRICE`;
  at most 0.005 SOL of priority fee, added to the measured outflow) and an idempotent
  creation of the wallet's own associated account for the output mint
  (`GRAPHITE_SWAP_CREATE_OUTPUT_ATA=1`, only when the route writes to it). Built from
  configuration and the wallet's key, never from the payload, and declared to the Core as
  siblings. Wrapping and unwrapping SOL is not built: the Core's risk engine refuses SPL
  Token CloseAccount outright, so an unwrap would block every SOL-output swap
  (`swap-envelope.ts`).
- Durable-nonce shapes are refused at build: `lastValidBlockHeight` does not bound them.
- **The operator's spend limits (`spend-policy.ts`, Round 24).** Graphite cannot know
  whether a person wanted a request; the amount bounds the damage when a model was talked
  into it. `GRAPHITE_MAX_TRANSFER_LAMPORTS` caps one transaction and
  `GRAPHITE_ALLOWED_DESTINATIONS` lists where a transfer may go; a malformed value is a
  startup error. A transfer is checked on its grounded amount and destination before
  anything is built. A swap is checked on what the exact transaction takes out of the
  wallet, from ONE simulation of its bytes (`measureWalletEffect`: the simulation's own pre-
  and post-balances, lamports including the fee and wrapped SOL, and every token account the
  wallet owns; Round 25 replaced a separate account read that a concurrent deposit could
  mask): over the cap is refused, a
  swap that spends any other token is refused because a lamport cap cannot price it, and
  with an allowlist but no cap every swap is refused, because a swap has no destination
  to check. Limits only narrow; nothing here can make a refused transaction executable.
  Since Round 29 (M6) the guard **refuses to start without a per-transaction cap** unless
  `GRAPHITE_ALLOW_UNCAPPED=1`, logs the policy in force at startup, and can bound a
  rolling window: `GRAPHITE_MAX_TOTAL_LAMPORTS` per `GRAPHITE_SPEND_WINDOW_SECONDS`
  (default 3600) across executed transactions — reserved before signing, kept once the
  bytes may have left, per guard process. Since Round 38 (G2-4) a reservation kept for a
  submission whose outcome was unknown is returned once that submission provably did not
  land and cannot (see the ambiguous-submission item below), not only when the window ends. Since Round 30 the reservations are written to
  `GRAPHITE_GUARD_STATE_FILE` (or `stateFile`) before signing when it is set, so a restart
  inside the window still counts them; without it they are in memory, and the startup log
  says a restart forgets them.
- **A last say before signing (Round 29, M7).** `executeTransfer(request, { confirm })`
  and `executeSwap(request, payload, { confirm })` call `confirm(summary)` after
  grounding, the spend policy, the build, the simulation, Graphite's verdict and the
  residual policy, immediately before signing. The summary is the resolved transaction:
  destination and lamports (or the route's decoded amount in, minimum out, simulated out,
  slippage and floor), the program, the simulated wallet effect and the verdict. Anything
  but `true` throws `ConfirmationDeclined`; nothing is signed or sent. The MCP server
  elicits here, and since Round 30 the Vercel AI tools require a hook here too. Round 30:
  the summary also names `transactionSha256`, the digest of exactly the bytes that will be
  signed; it is frozen (a hook that edits it fails); only the value `true` confirms; and
  a hook that has not answered within `confirmTimeoutMs` (default 120 s) is a decline.
- **Only the Core's executable decision is signed, recomputed (Round 30, G-01; Round 34,
  G-5).** `approved` alone never was the gate. The Core must report `decision` and
  `executable`, and the guard recomputes the whole of the Core's rule with the SDK's
  `computeExecutionDecision` — risk `Clear`, policy `Approved`, an artifact-bound scope
  with its digest that was simulated, every unobserved code inherent, layers reported and
  none failed — and requires the two to agree. A residual the operator accepted by name
  (`GRAPHITE_ACCEPT_UNOBSERVED`) makes the verdict `analysis_only`, and the guard signs it
  only when everything else in the rule holds: an accepted residual excuses itself (an
  accepted `not_simulated` or `simulation_failed` excuses the missing simulation), nothing
  more. A decision this guard does not know, `blocked` or `inconclusive` on an approval,
  an `executable` that contradicts the decision, and (since Round 34) a response without
  `decision` — a Core older than Round 30, which was judged by the residual codes alone —
  are refused.
- **An ambiguous submission is not retried blind (Round 29, L2; Round 30; Round 38).** The
  transaction id is computed from the signed bytes before sending, and since Round 30 the
  submission is recorded as unresolved BEFORE the bytes are handed to the RPC and resolved
  only once it is seen confirmed. If `sendRawTransaction` fails, the attempt is recorded on
  the trail with that signature and `SubmissionOutcomeUnknown` carries it; a send whose
  confirmation did not complete stays unresolved too. A repeat of the same request — the
  same destination and lamports, or the same wallet, mints and amount of a swap through
  any route, however it is worded — is refused (`PriorSubmissionUnresolved`, naming the
  signature) while that signature can still land, and refused once, naming it, if it did.
  With `GRAPHITE_GUARD_STATE_FILE` this survives a restart. A second call for a request
  already running (a model's double call, a missing `await`, a confirmation hook calling
  back in) is refused with `RequestInFlight` before anything is built.
  - *Route-independent (Round 38, G2-2).* A swap's key named its route program, so after a
    Jupiter swap failed ambiguously the same swap through Raydium was a new request and both
    could land. The key is now the wallet, input mint, output mint and amount in. An
    unresolved swap a state file holds under the older route-specific key still holds back
    the same swap on any route.
  - *Not sent (Round 38, G2-4).* Only one send failure proves nothing left the process: the
    connection was refused, or the RPC's host name did not resolve (`ECONNREFUSED`,
    `ENOTFOUND`, `EAI_AGAIN`, read from the error's code, never its message). That is
    `SubmissionNotSent`: the signed bytes are dropped, the reservation returned, nothing is
    left unresolved and the trail gets no submission event. Every other failure — a reset, a
    broken pipe, a timeout, an HTTP or JSON-RPC error, a preflight failure — can follow bytes
    the RPC received and forwarded, and stays `SubmissionOutcomeUnknown`.
  - *Its reservation comes back once the chain says so (Round 38, G2-4).* An unresolved
    submission records the reservation that pays for it. It is returned when the RPC knows
    no status for the signature, the confirmed block height is past its last valid height,
    and the RPC still knows none when asked again after that height was read. The guard
    asks on a repeat of the same request, and before the aggregate limit would refuse
    another one. An RPC that cannot answer keeps it counted; one that landed keeps it. A
    record written before Round 38 names no reservation, and its spend counts until the
    window ends.
- **One guard per wallet (Round 32; Round 34).** The aggregate cap and the repeat record
  are kept per guard, so two guards signing for one key would each spend the whole
  allowance. Every guard takes a lock named for its wallet's public key in a directory its
  user's guards on a host share, and a second guard for the same wallet refuses to start
  while the first runs. `GRAPHITE_GUARD_ALLOW_SHARED_WALLET=1` lets it start, logged as
  limits that hold per guard. The network fee counts toward the aggregate cap.
  - *Where (Round 34; Round 38).* `GRAPHITE_GUARD_LOCK_DIR` (or `walletLockDir`), else one
    directory per user, derived from the account alone:
    `<home>/.local/state/graphite-guard` (Windows: `<profile>\AppData\Local\graphite-guard`),
    where `<home>` is the home directory of the guard's user as the user database holds it
    (`os.userInfo()`), not `$HOME`. Until Round 38 (R37-17) the default followed the
    session's variables (`$XDG_RUNTIME_DIR`, else `/run`, else `$XDG_STATE_HOME`): an SSH
    login sets `XDG_RUNTIME_DIR` and cron does not, so a guard started from each, for one
    wallet and one user, took two locks and each spent the whole aggregate allowance. No
    session variable moves the default now. An account with no absolute home directory
    refuses to start and asks for `GRAPHITE_GUARD_LOCK_DIR`; a directory the operator names
    is the operator's to name the same way for every guard of the wallet. Before Round 34 it
    was `<tmpdir>/graphite-guard`, which systemd-tmpfiles, macOS and Storage Sense empty. The
    directory is created 0700 and must be a real directory (not a symbolic link) owned by the
    guard's user with mode 0700, an existing one included, or the guard refuses to start. A
    lock under `~/.local/state` survives a reboot: if a crash left one whose pid now belongs
    to another process, the guard refuses to start naming the file, and the operator removes
    it.
  - *Windows (a limitation, Round 38, G2-6).* The directory's owner and access are not
    checked on Windows: it has no uid or mode bits, its ACLs cannot be read from Node without
    a native addon, and the guard loads none. The default sits in the user's own profile,
    whose ACL admits the user, SYSTEM and the Administrators only; a `GRAPHITE_GUARD_LOCK_DIR`
    named on Windows must be kept private by the operator. The startup log says so.
  - *Held, not just taken (Round 34).* Node cannot hold an flock/fcntl/LockFileEx lock
    without a native addon, so the lock is a file holding the owner's pid and a random
    token. The guard remembers its inode and re-reads it before every reservation, before
    signing and immediately before the signed bytes are sent. A lock that is gone, is
    another file, or holds anything else refuses the spend (`GuardStateError`, "is no
    longer this guard's"): a second guard may already hold the wallet with its own
    allowance, and the first one stops spending until it is restarted. What one guard spent
    before its lock disappeared is not known to the next.
  - *Stale locks (Round 34).* A crashed guard's lock is moved aside under a unique name
    and removed only if it is still the same file with the same content; anything else is
    put back. Two guards that found the same stale lock could each delete the other's
    fresh one and both start (31–428 of 1,000 rounds in the regression test, before).
  - *Scope.* The lock sees only guards of the same OS user that share the directory and a
    pid namespace: guards for one wallet under two users, on two hosts or in two
    containers are not seen by each other, and one guard per wallet across them is the
    operator's to arrange. The state file's own lock (`<state file>.lock`) is taken and
    re-checked the same way, and every file the lock and state code create is opened
    O_EXCL|O_NOFOLLOW under a random name.
- **A closed guard spends nothing (Round 34).** `close()` releases both locks and marks
  the guard closed; `executeTransfer` and `executeSwap` then refuse with `GuardClosed`
  before anything is asked, and an execution already running (a confirmation still open)
  refuses before signing. Without a state file nothing else stopped a closed guard from
  signing.
- **Same-process integrity (Round 29, M8; Round 30).** Every collaborator that takes part
  in a decision (Core client, RPC connection and simulator, residual, spend and swap
  policies, AI layer URL, wallet profile) is an ES private field; the instance and its
  prototype are frozen; `SOLANA_PRIVATE_KEY` is deleted from `process.env` once read; and
  `getGraphiteClient()` returns the Core's read-only endpoints, not the client and its key.
  Round 34: the method that asks the Core about a transaction (`verifyTransaction`, which
  writes a verification to the trail under the deployment's key) is private too; only
  `executeTransfer` and `executeSwap` call it, about the transaction they built.
  Round 30: the key is imported into a NON-EXTRACTABLE WebCrypto key pair and its decoded
  bytes zeroed, so the guard holds no secret-key bytes; `BoundTransaction`,
  `ResidualPolicy`, `SpendLedger`, `RpcSimulator` and `GuardState` are frozen, so no method
  on the signing path can be replaced; the guard's RPC and AI-layer requests use the
  `fetch` captured when the module loaded; `getConnection()` returns a separate
  connection, not the one the guard decides on; and an unknown `GuardConfig` key refuses to
  start. Code loaded into the process BEFORE the guard, or that owns the process, is
  outside what any of this can stop: isolating the key from it takes a separate signing
  process.
- **What it does not build is data (Round 30).** `GUARD_CAPABILITIES` (also
  `guard.capabilities`, and the `graphite_wallet` tool of both adapters) lists the
  operations and message versions; unsupported ones are refused by name
  (`UnsupportedCapability`: `wrap_sol`, …). A SOL-input swap spends wrapped SOL the
  wallet already holds — the guard does not wrap — and a SOL-output swap delivers wrapped
  SOL and leaves it wrapped (`deliveredAs: "wrapped_sol"` in the confirmation summary).
- **Transport (Round 29, M3).** `SOLANA_RPC_URL` is held to the Core's rule (https://, or
  http:// to loopback), and no RPC request follows a redirect. The AI layer's answer is
  read through a 64 KiB bound.
  - *Every RPC request is bounded (Round 36, F-014).* The guard's raw JSON-RPC reads were
    bounded since Round 25, but web3.js's `Connection` — blockhashes, lookup tables, the
    advisory simulation, `sendRawTransaction` and the confirmation and repeat-check polls —
    called `fetch` with no deadline and read the answer whole: an RPC that never answered
    held `executeTransfer` open indefinitely (a hung send never reached the
    outcome-unknown path), any answer size was accepted, and a 429 was retried five times
    inside one call. Every request now goes through `boundedRpcFetch` (`rpc-transport.ts`):
    the configured URL only, no redirect, one deadline over the headers and the whole body
    (`GRAPHITE_RPC_TIMEOUT_MS` / `rpcTimeoutMs`, default 30 s, at most 120 s; a malformed
    value refuses to start), 32 MiB at most, no 429 retry. A send that times out is
    `SubmissionOutcomeUnknown`: its reservation is kept and the repeat waits for it (until
    the chain says it cannot land; Round 38).
  - *No websocket (Round 36, F-014).* web3.js opens `ws(s)://<host>:<port + 1>` for every
    subscription and for its own `confirmTransaction` — an endpoint the transport rule never
    checked. The guard has confirmed by polling over HTTP since Round 29; the connection
    `getConnection()` hands out is now a `BoundedConnection` too: its `confirmTransaction`
    polls `getSignatureStatuses` / `getBlockHeight` through the bounded transport (same
    signature and answer), and every subscription method (`onSignature`, `onAccountChange`,
    `onLogs`, …) throws `RpcTransportRefusal` before a socket exists. It is still a
    web3.js 1.x `Connection` (R-M15 is not a migration off web3.js); a caller who needs
    subscriptions builds its own, outside the guard's policy.
- **A verdict is signed and sent young (Round 36, F-017; Round 38, G2-3).** Immediately
  before the digest is recomputed and the bytes signed, a verdict older than
  `GRAPHITE_MAX_VERDICT_AGE_MS` / `maxVerdictAgeMs` (default 150 s, at most 600 s), counted
  on a monotonic clock from before the verification was asked for, is refused with
  `StaleVerdict`: nothing signed, the reservation returned. Since Round 38 the age is checked
  again immediately before the send, after the signing is recorded on the trail (a round
  trip to the Core), with nothing awaited in between: a verdict that aged past the bound
  there is `StaleVerdict` with `signed: true` — the signed bytes are dropped, nothing is
  sent, the reservation returned. A confirmation hook slower than the bound is answered too late
  to sign (the guard warns at startup when `confirmTimeoutMs` is not below it). The guard
  never builds a durable-nonce transaction whatever the Core permits
  (`GRAPHITE_ALLOW_DURABLE_NONCE` is the Core's), so this bound and the blockhash both
  hold for everything it signs.
- **Version 0 through lookup tables (Round 22).** `BoundTransaction.build({ version: 0,
  addressLookupTables })` compiles a v0 message reading accounts through tables the
  caller has already fetched; `executeSwap` does so when the payload names
  `addressLookupTableAddresses`, and aborts if any table cannot be read. Every
  guarantee above holds for it — one object verified, signed and submitted, the digest
  checked before signing, the signed bytes carrying the verified message — and the
  verification request declares `uses_versioned_transaction` / `lookup_table_count`
  from the bytes. Tables given for a legacy message are refused, not ignored. The bridge's
  v0 bytes are pinned byte-for-byte to the cross-language corpus entry the Rust parser
  reads (`bound-transaction.test.ts`).
- **Version 1 (SIMD-0385; R-P8 phase 2).** Set `transactionVersion: 1` (or
  `GRAPHITE_TRANSACTION_VERSION=1`; anything but `legacy` or `1` refuses to start) and
  the bridge builds v1 messages through `@solana/kit`. In v1 an unset compute or
  loaded-data limit is ZERO, so the bridge first measures both with an UNSIGNED v1 draft
  at the runtime maxima (`RpcSimulator.estimateV1Limits`: base64, `sigVerify: false`,
  placeholder blockhash) and builds the verified message with the measurement plus 20%
  compute headroom and the next 32 KiB data page. Refused at build: a v1 message without
  limits, out-of-range limits or heap, any ComputeBudget instruction (a no-op in v1),
  lookup tables (v1 carries up to 64 addresses inline in 4,096 bytes), and anything
  `messageOf` refuses — a port of the Core's `parse_v1`, rule for rule. Signatures trail a
  v1 message; every helper that slices a frame dispatches on the leading `0x81`. The two
  v1 shapes the bridge builds are in the cross-language corpus, read by the Rust Core.
- **The transaction id is read from the signed bytes.** The submission, the audit trail
  and L8 use the fee payer's signature as this process signed it; an RPC answering
  `sendTransaction` with another id is logged and kept as `lifecycle.rpcReportedSignature`,
  never used. Since Round 30 the disagreement is also written on the trail (the
  `submission` event's detail) and reported as an anomaly in the tool result.
- `scope.unobserved` is printed for every verdict; which residuals a deployment
  accepts is the deployment's decision, made in configuration and enforced by the
  residual policy above.
- `content_hash` / AuditBind (`auditbind.ts`) remains as a secondary instruction-level
  check and the audit/L8 join key; the digest is the authoritative binding.

## Usage

### Run one request from a terminal

```bash
npx tsx cli.ts transfer "Transfer 0.05 SOL to <address>"
npx tsx cli.ts swap "Swap 0.1 SOL for USDC" route.json   # route.json: the exact route instruction
```

This is the guard's real path: when the Core approves, the transaction is signed and
submitted on whatever cluster `SOLANA_RPC_URL` names. Exit status 0 is a verified
execution, 2 a refusal by Graphite, 1 an error or a refusal before the Core was asked.

### Use the guard in your own code

```typescript
import { GraphiteGuard } from "./guard.js";

const guard = await GraphiteGuard.create({
  // or SOLANA_PRIVATE_KEY / SOLANA_RPC_URL / GRAPHITE_CORE_URL / GRAPHITE_API_KEY /
  // GRAPHITE_AI_LAYER_URL / GRAPHITE_WALLET_PROFILE / GRAPHITE_TRANSACTION_VERSION /
  // GRAPHITE_MAX_TRANSFER_LAMPORTS / GRAPHITE_SWAP_MIN_RATES / …
  graphiteCoreUrl: "http://127.0.0.1:7331",
  graphiteApiKey: process.env.GRAPHITE_API_KEY,
  transactionVersion: 1, // or "legacy" (the default)
  spendPolicy: { maxTransferLamports: 100_000_000n }, // required
});

// The transaction is built once, verified as those exact bytes, and signed only on an
// artifact_bound approval whose digest matches — and, here, a person's yes.
const outcome = await guard.executeTransfer("Transfer 0.05 SOL to <address>", {
  confirm: async (summary) => askAPerson(summary), // destination, lamports, effect, verdict
});

if (!outcome.verifiedExecution) {
  console.log("Blocked by Graphite:", outcome.verification.risk_verdict.findings);
} else {
  console.log("Verified execution:", outcome.signature);
}
```

A swap is `guard.executeSwap(request, payload)`, where `payload` is the exact route
instruction (program, accounts with their signer/writable flags, data, and any lookup
tables); without a payload a swap is refused.

`ExecutionOutcome` is `{ executed, verifiedExecution, verification, signature?,
unverifiedReason?, lifecycle? }`. Gate on `verifiedExecution`. Since Round 19 there is no
unverified path, so `executed` and `verifiedExecution` agree and `unverifiedReason` is
never set; both stay on the type so existing callers compile. `lifecycle` (every
verified execution) is
`{ signature, rpcReportedSignature?, acceptedUnobserved, signingRecorded, verdictOnRecordAtSigning,
submissionRecorded, submissionRecordError?, confirmed, confirmationError?,
reconciliation?, reconciliationError? }` — read `reconciliation.discrepancy` for L8's
verdict on what actually landed.

### Tests and the cross-language corpus

```bash
npm run typecheck
npm test                 # (counts: docs/CURRENT.md) the guard end to end (incl. an APPROVED transfer and swap
                         # driven through the whole lifecycle against a loopback Core that
                         # approves with the real digests), its CLI, BoundTransaction gate
                         # (legacy, v0, v1), execution-boundary fuzz, TOCTOU signing boundary,
                         # AuditBind, artifact, nonces, residual policy, execution lifecycle,
                         # grounding grammars, swap decoders (checked against the committed
                         # IDLs), swap economics, spend policy and aggregate, envelope
npm run emit:corpus      # regenerates graphite-core/fixtures/artifacts/sak_bridge_corpus.json
                         # (15 shapes incl. two v1 + 2,897 byte-level mutations); CI fails on drift
npm run emit:artifact-fixture
```

## What Graphite Verifies

Before the guard signs anything, Graphite checks:

- **L1 Account Resolution**: accounts, PDAs and fixed constants; signer/writable privileges read from the transaction's own header and resolved lookup tables
- **L2 Instruction Verification**: the described instruction is in the bytes, positionally, every sibling is declared, and the transaction is not durable-nonce based
- **L3 Simulation Integrity**: the Core's own simulation of the exact bytes, against earned baselines (live with `GRAPHITE_RPC_URL`; `Inconclusive` without). A baseline is earned only by distinct transactions: the same message under a fresh blockhash is one observation (Round 19)
- **L4 State Verification**: Graphite's own pre/post diff against the manifest; Token-2022 extensions classified
- **L5 Semantic Verification**: intent ↔ instruction alignment
- **L6 Policy Verification**: confidence against the wallet profile threshold
- **L7 Risk Verification**: drainers, authority hijacks, fake swaps, impersonation, multi-instruction patterns, and CPI-trace patterns run on the call tree the simulator actually executed (Round 19), not only on one the caller declares

If any hard gate fails, the transaction is NOT signed. After submission, `POST
/verify/execution` reconciles the signature against the recorded verdict (L8).

## Wallet Profiles

Graphite enforces different confidence thresholds per wallet profile:

| Profile | Min Confidence | Min Trust Tier |
|---------|---------------|----------------|
| Treasury | 95% | CommunityVerified |
| TradingBot | 80% | SimulationValidated |
| Gaming | 55% | HeuristicInferred |
| Enterprise | 99% | BattleTested |

Set via `GRAPHITE_WALLET_PROFILE` (or `config.walletProfile`). When the Core pins a
profile server-side with its own `GRAPHITE_WALLET_PROFILE`, the request's profile is
ignored — the operator's policy wins over the agent's.

**Fresh-core calibration:** the evidence-derived confidence signals read the Core's
semantic graph, so on a fresh core (no earned evidence, no RPC) the highest reachable
confidence for a known, clean, intent-aligned protocol is **~0.44** and every built-in
profile blocks. The guard defaults to `Custom { min_confidence: 0.40, min_trust_tier:
OfficialManifest }`, and the Core clamps any `Custom` profile weaker than the weakest
built-in up to Gaming's (0.55, HeuristicInferred) and says so in the verdict — so the
default approves nothing until evidence is earned. Only an operator can lower the bar,
with `GRAPHITE_ALLOW_PERMISSIVE_PROFILES=1` on the Core. The
engine's confidence score is always the honest number; the profile is the operator's
policy choice.
