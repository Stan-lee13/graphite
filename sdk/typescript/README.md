# @graphite/sdk

Thin TypeScript SDK for calling a Graphite verification service.

The client calls a Graphite Core: `POST /verify` takes a `VerificationInput` (the
`ProposedIntent` is one field of it, `proposed_intent`, beside the program id,
discriminator, accounts, wallet profile and — to bind the verdict — the unsigned
transaction bytes) and returns a `VerificationResult`. It also wraps
`POST /audit/event` (`recordLifecycleEvent`), `POST /verify/execution`
(`verifyExecution`), `GET /health` and `GET /manifests`.

Every 2xx answer is checked before it is returned: a body that is not JSON, or not
the shape its route answers with, is thrown — never returned typed as the answer.
`timeoutMs` defaults to 30000; only `0` disables it, and any other value that is
not a whole number of milliseconds is refused at construction. The API key is held
in an ES private field and is not a readable property of the client.

## Trust boundary (GAP-2026-08-06-8)

This SDK is a **thin client** — a view, not a verifier. The Graphite Rust Core
is the source of truth, and its append-only audit trail (`audit.jsonl`) is the
authoritative record of every verification.

- **Transport integrity:** responses are validated structurally at runtime
  (`validateVerificationResult`, and a validator per route) so a truncated or mis-shaped payload fails
  loudly instead of flowing through typed as a `VerificationResult`. That is
  defense-in-depth, not integrity. **Deploy Graphite behind TLS** — over plain
  HTTP a network attacker can mutate any field (including `approved`) before
  it reaches this client, and no client-side shape check can detect a
  well-formed lie.
- **Who to trust:** trust the server you pointed `baseUrl` at. If you need to
  detect a compromised/mitm'd server, pin the server's TLS certificate or
  verify the returned `audit_trail_id`/`content_hash` against a separately
  queried audit record.

## Sign only on `isExecutable(result)` (Round 30)

`approved` says whether the pipeline refused the transaction; it never said the
transaction may be signed. A Core without `GRAPHITE_RPC_URL` simulates nothing, and its
approvals carry `not_simulated`; a verdict without transaction bytes binds to nothing. Every
verdict now carries `decision` — `executable_approved`, `analysis_only`, `inconclusive` or
`blocked` — and `executable`. Gate signing on one call:

```ts
import { GraphiteClient, isExecutable, verifyTransactionDigest } from "@graphite/sdk";

const result = await client.verify(input); // input.signed_transaction = the unsigned bytes
if (!isExecutable(result)) {
  throw new Error(`not executable: ${result.decision ?? "no decision"} — ${result.summary}`);
}
verifyTransactionDigest(bytes, result); // the bytes you sign are the bytes it verified
```

`isExecutable` recomputes the Core's rule from the verdict's own fields
(`computeExecutionDecision`) and requires the server to agree: an approval that is not
artifact-bound and simulated, carries a residual beyond `program_semantics` and
`inner_instructions`, or reports a failed layer is not executable whatever `decision` says;
a `decision` this SDK does not know is not executable; a server older than Round 30 (no
`decision`) is judged by the recomputation alone. `verify` refuses a response whose
`executable: true` its own fields contradict. An operator who has deliberately accepted a
residual (the agent guard's `ResidualPolicy`) makes that decision in their own code, by
name, and logs it — `isExecutable` never does.

`instruction_bind_key` (Round 30) is `content_hash` under a name that says what it is: a
64-bit key for the described instruction, which audit and lifecycle records bind to. The
transaction's identity is `scope.transaction_sha256`. `content_hash` is deprecated and
stays for one minor version; `instructionBindKey(result)` reads either.

## Send the bytes, require `artifact_bound`

`VerificationInput.signed_transaction` carries the serialized transaction with its
signature slots EMPTY — the Core refuses an artifact whose slots already hold
signatures (HTTP 400), because a transaction signed before it was shown is one
whose verdict L8 could never join to the chain's bytes. With it, the verdict's `scope.kind` is `artifact_bound` and
`scope.transaction_sha256` is the SHA-256 of those exact bytes; without it the verdict is
`descriptive` and constrains nothing about what is signed. An executor must require
`artifact_bound`, sign exactly the bytes it sent, and recompute the digest before
signing — the reference implementation is `BoundTransaction.signApproved` in
`integrations/agent-guard/artifact.ts`.

**`verifyTransactionDigest(bytes, result)` (Round 19)** is that check for any executor
that is not the reference bridge: it throws unless `result` is an approval, its scope is
`artifact_bound`, and `scope.transaction_sha256` is the SHA-256 of `bytes` (signed or
unsigned — signature slots are zeroed before hashing, as the Core does). Call it on the
exact bytes immediately before signing or submitting. `transactionDigest(bytes)` and
`readSignatureCount(bytes)` are exported for callers that need the pieces; the Go SDK
has the same three as `VerifyTransactionDigest`, `TransactionDigest` and
`ReadSignatureCount`.

**Transport.** `baseUrl` must be `https://`, or `http://` to a loopback host
(localhost, 127.0.0.0/8, [::1], or 127.0.0.0/8 as an IPv4-mapped address such as
`[::ffff:127.0.0.1]`); anything else is refused at construction so the API key
is never sent in cleartext (Round 19). Go's `CheckBaseURL` enforces the same rule.

`verifyInstruction` / `content_hash` in this SDK re-hash one instruction's projection.
For a native program (System, SPL Token, …) pass `discriminator` exactly as it was sent
to Graphite; the projection checks it is a prefix of the data rather than guessing an
eight-byte Anchor selector (Round 19).
That is a secondary, instruction-level check and the audit/L8 join key; it cannot see
the fee payer, blockhash, signer set or sibling instructions, so it is not a substitute
for the digest.

Read `scope.unobserved` on every verdict: it names what Graphite did not establish and
is never empty. Decide on `scope.unobserved_codes`, not on the prose: `unobservedCodes(result)`
returns the stable `UnobservedCode` naming each entry. `verify` refuses a verdict without
`scope` or without `unobserved_codes` (a server older than 2026-09-12); for a result that
reached you some other way, `undefined` is unknown, not clear. `INHERENT_UNOBSERVED` holds the two codes
every artifact-bound verdict carries; every other code names an observation that was
possible and did not happen, and an executor must refuse it unless the operator has
accepted it by name — the reference is `ResidualPolicy` in
`integrations/agent-guard/residual-policy.ts`.

## Send the bytes you sent to the trail, too

`recordLifecycleEvent({ event_type: "signing" | "submission" | "confirmation" |
"finalization", content_hash, audit_trail_id, transaction_sha256, ... })` puts a stage
the caller performed on Graphite's append-only trail (`POST /audit/event`); it resolves
only on `recorded: true` and returns `verdict_on_record` — what the trail says about the
verification the event names — with `verdict_on_record_key`, the key it was resolved by.
Send the exact keys: `content_hash` alone names every transaction carrying that
instruction. Record `signing` before you submit and refuse to submit if it is not
recorded, if the verdict on record is not `approved`, or if it was not resolved by
`audit_trail_id`. `verifyExecution({ signature, content_hash, transaction_sha256,
audit_trail_id })` runs L8 after submission and returns the reconciliation with
`attribution` (`chain` when L8 joined on the bytes behind the signature) and
`caller_keys_disagree`; `discrepancy: true` is `BlockedButExecuted`;
`chain_bytes_rejected` (Round 11) is set when the RPC returned bytes for the
signature that are not bound to it — nothing was attributed and your keys were
not consulted in their place, so treat it as "the RPC is wrong", not as a
verdict. Round 12 adds `chain_bytes_unavailable` (the status said "included"
but no bytes came back, so the attribution is by your keys, not the chain's),
`chain_inconsistent` (the RPC's two answers about the signature disagree; no
positive conclusion), and `inclusion_witness` (a second RPC's account when the
server has one; `agrees: false` withholds `ApprovedAndExecuted`). `chain_status`
now carries `commitment`; a `processed`-only status is `Unavailable` for an
approved transaction and still `BlockedButExecuted` for a blocked one.
`recordLifecycleEvent` returns `sequence_anomalies` — a retried `submission`
comes back as `duplicate: …` and is harmless; `signature conflict: …` means a
different signature is already on record for that transaction. From
`submission` onward, `transaction_signature` is required and must be a real
signature. The
reference sequence is `executeBoundTransaction` in
`integrations/agent-guard/execution-lifecycle.ts`.
