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
