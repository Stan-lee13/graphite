# Graphite AI Layer — Advisory Intent Parser

**This is the canonical AI layer for Graphite.** There is no other `ai-layer/` directory.

## What this is

An advisory-only natural language intent parser that runs as a **separate process**
from the Rust Core. It parses user intent text into the JSON schema that Graphite
Core's `verify()` endpoint expects.

**Constitution P1: AI assists, never decides.** This module only PARSES intent —
it does not verify, approve, or execute. The Core verification engine makes all
security decisions.

## Usage

```bash
# Run as HTTP server on :8081
python3 intent_parser.py --serve

# Parse a single intent
python3 intent_parser.py "Swap 1 SOL for USDC"
```

## Output schema

The parser outputs Graphite's `ProposedIntent` JSON:

```json
{
  "intent_type": "swap",
  "raw_natural_language": "Swap 1 SOL for USDC",
  "confidence_of_parse": 0.85,
  "extracted_parameters": {
    "input_token": "SOL",
    "output_token": "USDC",
    "amount": "1"
  }
}
```

The `confidence_of_parse` field measures how confident the parser is that it
understood the user — this is NOT the same as Graphite Core's verification
confidence score. Conflating these two numbers is a Constitution P1 violation.

## Tests

```bash
python3 -m pytest test_intent_parser.py -v
# or
python3 test_intent_parser.py
```
