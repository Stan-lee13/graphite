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
- **Fast & deterministic.** Precompiled regexes, single pass, no network, no
  randomness. Micro-benchmark: ~47,000 parses/sec, p50 ~21 µs (measured
  2026-08-08, Windows, CPython 3.13).

## Usage

```bash
# Run as HTTP server on :8081
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
- Server hardening: 64 KiB body cap, robust Content-Length parsing (413/400,
  never an unbounded read), non-dict bodies rejected.

## Tests

```bash
python3 -m pytest test_intent_parser.py -v
# or
python3 test_intent_parser.py
```

27 tests: every intent class, parameter extraction, risk hints, confidence
components, manifest grounding (no fabricated IDs), determinism, the P1
invariant, and a performance smoke test (must exceed 10k parses/sec).
