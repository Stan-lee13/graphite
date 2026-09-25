# @graphite/sdk

Thin TypeScript SDK for calling a Graphite verification service.

The client expects a `POST /verify` endpoint that accepts a `ProposedIntent`
payload and returns a `VerificationResult`.

## Trust boundary (GAP-2026-08-06-8)

This SDK is a **thin client** — a view, not a verifier. The Graphite Rust Core
is the source of truth, and its append-only audit trail (`audit.jsonl`) is the
authoritative record of every verification.

- **Transport integrity:** responses are validated structurally at runtime
  (`validateVerificationResult`) so a truncated or mis-shaped payload fails
  loudly instead of flowing through typed as a `VerificationResult`. That is
  defense-in-depth, not integrity. **Deploy Graphite behind TLS** — over plain
  HTTP a network attacker can mutate any field (including `approved`) before
  it reaches this client, and no client-side shape check can detect a
  well-formed lie.
- **Who to trust:** trust the server you pointed `baseUrl` at. If you need to
  detect a compromised/mitm'd server, pin the server's TLS certificate or
  verify the returned `audit_trail_id`/`content_hash` against a separately
  queried audit record.

## Send the bytes, require `artifact_bound`

`VerificationInput.signed_transaction` carries the serialized transaction with its
signature slots EMPTY — the Core refuses an artifact whose slots already hold
signatures (HTTP 400), because a transaction signed before it was shown is one
whose verdict L8 could never join to the chain's bytes. With it, the verdict's `scope.kind` is `artifact_bound` and
`scope.transaction_sha256` is the SHA-256 of those exact bytes; without it the verdict is
`descriptive` and constrains nothing about what is signed. An executor must require
`artifact_bound`, sign exactly the bytes it sent, and recompute the digest before
signing — the reference implementation is `BoundTransaction.signApproved` in
`integrations/solana-agent-kit/artifact.ts`.

**`verifyTransactionDigest(bytes, result)` (Round 19)** is that check for any executor
that is not the reference bridge: it throws unless `result` is an approval, its scope is
`artifact_bound`, and `scope.transaction_sha256` is the SHA-256 of `bytes` (signed or
unsigned — signature slots are zeroed before hashing, as the Core does). Call it on the
exact bytes immediately before signing or submitting. `transactionDigest(bytes)` and
`readSignatureCount(bytes)` are exported for callers that need the pieces; the Go SDK
has the same three as `VerifyTransactionDigest`, `TransactionDigest` and
`ReadSignatureCount`.

**Transport.** `baseUrl` must be `https://`, or `http://` to a loopback host
(localhost, 127.0.0.0/8, [::1]); anything else is refused at construction so the API key
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
returns the stable `UnobservedCode` naming each entry (or `undefined` for a server older
than 2026-09-12, which is unknown, not clear). `INHERENT_UNOBSERVED` holds the two codes
every artifact-bound verdict carries; every other code names an observation that was
possible and did not happen, and an executor must refuse it unless the operator has
accepted it by name — the reference is `ResidualPolicy` in
`integrations/solana-agent-kit/residual-policy.ts`.

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
`integrations/solana-agent-kit/execution-lifecycle.ts`.
