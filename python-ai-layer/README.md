# Graphite AI Layer — Advisory Intent Labeler (v2)

**This is the canonical AI layer for Graphite.** There is no other `ai-layer/` directory.

## What this is

A deterministic, pure-stdlib, **no-LLM** advisory intent labeler that runs as a
**separate process** from the Rust Core. It labels natural-language intent text
into the JSON schema that Graphite Core's `verify()` endpoint expects.

**Constitution P1: AI assists, never decides.** This module only LABELS intent —
it does not verify, approve, or execute. The Core verification engine makes all
security decisions. A wrong label can never weaken a decision: a bad suggestion
simply fails to match and the verification blocks (fail-closed).

## v2 (C21) — what changed

The v1 parser recognized 4 intent classes with hardcoded confidence. v2 is a
full advisory labeler:

- **Full Core vocabulary.** Emits exactly the intents the Core's semantic layer
  (L5) understands: `swap|trade|exchange`, `transfer|send`, `stake|delegate`,
  `close|close_account`, `create|create_account`, `approve|revoke`, plus
  `unknown` as the honest fallback. `mint`/`bridge`/`lend` are detected and
  surfaced as **advisory warnings** but labeled `unknown` (fail-closed), because
  the Core has no semantic class for them.
- **Manifest-grounded suggestions.** At load time the labeler reads the verified
  manifest registry (`../graphite-core/protocols/`); `suggested_program_id` /
  `suggested_discriminator` / `protocol_candidates` are derived from the real
  manifests (e.g. swap → Jupiter `route_v2` `bb64facc31c4af14`, the deployed
  entrypoint), with an embedded fallback table for standalone deployments.
- **Risk-hint warnings (advisory).** Impersonation-vanity destinations
  (`…11111`, `Compu…`), authority changes, approve-delegate escalation, close
  rent recovery, unmodeled intents, unknown token symbols, large amounts.
- **Per-signal confidence.** `confidence_of_parse` is computed from
  phrase/parameters/token/protocol signals with a `confidence_components`
  breakdown instead of a hardcoded number.
- **Fast & deterministic.** Precompiled regexes, no network, no randomness.
  Throughput depends heavily on the machine and its load, so treat any
  figure as that machine's: ~47,000 parses/sec, p50 ~21 µs on 2026-08-08
  (Windows, CPython 3.13, the parser before Round 29); 12,000–17,000
  parses/sec, p50 ~31–41 µs on 2026-10-20 on a shared 4-core Linux build box
  under load (CPython 3.13), where Round 29's clause detection made the
  parser about a quarter slower than the one before it on the same box. Run
  `--bench` on your own hardware. The test suite's floor is 500 parses/sec.

## Round 29 (audit 2026-10-20) — labels that say what was asked

- **One action per label.** A text that asks for two things ("Swap 1 SOL for
  USDC then send 2 SOL to X") is labelled `unknown` with a
  `MULTIPLE_INTENTS` warning; it used to come back as just the transfer.
- **Negation.** "Don't send 5 SOL to X" is `unknown` with `NEGATED_INTENT`;
  it used to be a transfer with no warning.
- **"delegate" as a noun.** "Revoke the delegate authority" is `revoke`; it
  used to be `stake`.
- **Not every withdrawal is a stake withdrawal.** "claim rewards", "withdraw
  liquidity from Orca", withdrawing fees or collateral: `unknown` with
  `WITHDRAWAL_UNMODELED`. "Unstake 3 SOL" and "Withdraw 1 jitoSOL" stay
  `stake`.
- **Stop words are not tokens.** "stake my SOL" extracts `SOL` (it extracted
  `my`); "Approve the transaction" extracts no token (it extracted `the`);
  "Approve spending of 500 USDC" extracts amount `500` and token `USDC` (it
  extracted the token `500`).

## Usage

```bash
# Run as HTTP server on 127.0.0.1:8081 (loopback only; set
# GRAPHITE_AI_LAYER_HOST to bind elsewhere, e.g. inside a container)
python3 intent_parser.py --serve

# Label a single intent
python3 intent_parser.py "Swap 1 SOL for USDC"

# Micro-benchmark 20k parses
python3 intent_parser.py --bench 20000
```

## Output schema

```json
{
  "intent_type": "swap",
  "raw_natural_language": "Swap 1 SOL for USDC",
  "confidence_of_parse": 0.99,
  "confidence_components": {"phrase": 1.0, "parameters": 1.0, "token": 1.0, "protocol": 1.0},
  "extracted_parameters": {"input_token": "SOL", "output_token": "USDC", "amount": "1"},
  "suggested_program_id": "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
  "suggested_discriminator": "bb64facc31c4af14",
  "protocol_candidates": [
    {"manifest": "jupiter-v6.json", "program_id": "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4", "name": "Jupiter V6 Aggregator", "instruction": "route"}
  ],
  "advisory_warnings": [],
  "matched_kind": "swap",
  "parse_version": "2"
}
```

The `confidence_of_parse` field measures how confident the labeler is that it
understood the user — this is NOT the same as Graphite Core's verification
confidence score. Conflating these two numbers is a Constitution P1 violation.

## Security invariants (unchanged)

- Advisory only: suggestions and warnings can never weaken a decision.
- No private key, no wallet address history, no telemetry: input text leaves
  the process only as the JSON response.
- Server hardening: 64 KiB body cap and robust Content-Length parsing, never
  an unbounded read — 413 only when the declared length is over the cap;
  400 for a non-integer or negative Content-Length, a body shorter than
  declared, a non-JSON body or one without a `text` field; 408 when the body
  does not arrive in time (Round 29: every failure but the timeout used to
  answer 413).
- Round 29 (PY1): a whole-request deadline (15 s, accept to response) on top
  of the 10 s per-read timeout — a client dribbling a byte every few seconds
  no longer keeps its thread — and at most 32 connections served at once;
  the 33rd is answered `503` immediately and closed.
- Round 29 (PY2): `POST` requires `Content-Type: application/json` (415
  otherwise — a web page cannot send JSON cross-origin without a preflight);
  a request carrying an `Origin` header (a browser) is refused with 403
  unless that origin is listed in `GRAPHITE_AI_LAYER_ALLOWED_ORIGINS`
  (comma-separated); and while bound to loopback, a `Host` header that does
  not name loopback (`localhost`, `127.x.x.x`, `[::1]`) is refused with 403,
  which defeats DNS rebinding. Bound elsewhere (`GRAPHITE_AI_LAYER_HOST`),
  the Host check is off; the Origin and Content-Type checks stay.
- Round 19 (F-19-C5): binds `127.0.0.1` by default (it used to bind `0.0.0.0`,
  exposing an unauthenticated service whose answer feeds transfer construction);
  one thread per request (`ThreadingHTTPServer`) and a 10 s socket timeout, so
  a client that declares a body and never sends it cannot stall every other
  caller. The bridge no longer trusts this service's parse for a transfer: it
  re-derives amount and destination from the user's own text and refuses a
  parse that disagrees (`integrations/agent-guard/intent-grounding.ts`).

## Tests

```bash
python3 -m pytest test_intent_parser.py -v
# or, with nothing but the standard library:
python3 test_intent_parser.py
```

44 tests: every intent class, parameter extraction, risk hints, confidence
components, manifest grounding (no fabricated IDs), determinism, the P1
invariant, the Round 29 label cases, the server's status codes, header
checks, deadline and connection cap, and a performance smoke test (must
exceed 500 parses/sec, with every socket connect refused while it parses).
