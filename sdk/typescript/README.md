# @graphite/sdk

Thin TypeScript SDK starter for calling a Graphite verification service.

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

`VerificationInput.signed_transaction` carries the serialized transaction (signature
slots empty). With it, the verdict's `scope.kind` is `artifact_bound` and
`scope.transaction_sha256` is the SHA-256 of those exact bytes; without it the verdict is
`descriptive` and constrains nothing about what is signed. An executor must require
`artifact_bound`, sign exactly the bytes it sent, and recompute the digest before
signing — the reference implementation is `BoundTransaction.signApproved` in
`integrations/solana-agent-kit/artifact.ts`.

`verifyInstruction` / `content_hash` in this SDK re-hash one instruction's projection.
That is a secondary, instruction-level check and the audit/L8 join key; it cannot see
the fee payer, blockhash, signer set or sibling instructions, so it is not a substitute
for the digest.

Read `scope.unobserved` on every verdict: it names what Graphite did not establish and
is never empty.
