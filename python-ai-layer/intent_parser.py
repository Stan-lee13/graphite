#!/usr/bin/env python3
"""
Graphite AI Layer — Advisory Intent Parser

This module runs as a SEPARATE PROCESS from the Rust Core.
It parses natural language transaction intents into the JSON schema
that Graphite Core's verify() endpoint expects.

Constitution P1: AI assists, never decides.
This module only PARSES intent — it does not verify, approve, or execute.
The Core verification engine makes all security decisions.

Usage:
    python3 intent_parser.py --serve         # Run as HTTP server on :8081
    python3 intent_parser.py "Swap 1 SOL for USDC"  # Parse single intent
"""

import json
import re
import sys
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional, Dict, Any

# Intent patterns — these are heuristics, not security decisions
INTENT_PATTERNS = {
    "transfer": [
        r"transfer\s+(\d+\.?\d*)\s+(\w+)\s+to\s+([\w\s]+)",
        r"send\s+(\d+\.?\d*)\s+(\w+)\s+to\s+([\w\s]+)",
    ],
    "swap": [
        r"swap\s+(\d+\.?\d*)\s+(\w+)\s+for\s+(\w+)",
        r"exchange\s+(\d+\.?\d*)\s+(\w+)\s+for\s+(\w+)",
    ],
    "stake": [
        r"stake\s+(\d+\.?\d*)\s+(\w+)",
        r"delegate\s+(\d+\.?\d*)\s+(\w+)",
    ],
    "close": [
        r"close\s+(\w+)\s+account",
        r"close\s+account",
    ],
}

# Known program IDs for intent→program mapping
PROGRAM_IDS = {
    "transfer": "11111111111111111111111111111111",  # System Program
    "swap": "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",  # Jupiter V6
    "stake": "Stake11111111111111111111111111111111111111",  # Stake Program
    "close": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",  # SPL Token
}

# Instruction discriminators for known programs
DISCRIMINATORS = {
    ("transfer", "11111111111111111111111111111111"): "02000000",
    ("swap", "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"): "e517cb977ae3ad2a",
    ("stake", "Stake11111111111111111111111111111111111111"): "02000000",
    ("close", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"): "09",
}


def parse_intent(natural_language: str) -> Dict[str, Any]:
    """
    Parse natural language into Graphite's ProposedIntent schema.
    
    Returns a dict with:
        - intent_type: "transfer" | "swap" | "stake" | "close" | "unknown"
        - raw_natural_language: the original text
        - confidence_of_parse: 0.0-1.0 (how confident the parser is)
        - extracted_parameters: token/amount data if extractable
        - suggested_program_id: mapped program ID
        - suggested_discriminator: mapped discriminator
    
    This is ADVISORY ONLY. The Core verification engine makes all decisions.
    """
    text = natural_language.lower().strip()
    
    for intent_type, patterns in INTENT_PATTERNS.items():
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                params: Dict[str, Any] = {}
                
                if intent_type in ("transfer", "swap"):
                    if len(match.groups()) >= 3:
                        params["amount"] = match.group(1)
                        params["input_token"] = match.group(2)
                        if intent_type == "swap":
                            params["output_token"] = match.group(3)
                elif intent_type == "stake":
                    if len(match.groups()) >= 2:
                        params["amount"] = match.group(1)
                        params["input_token"] = match.group(2)
                
                program_id = PROGRAM_IDS.get(intent_type, "")
                disc_key = (intent_type, program_id)
                discriminator = DISCRIMINATORS.get(disc_key, "")
                
                return {
                    "intent_type": intent_type,
                    "raw_natural_language": natural_language,
                    "confidence_of_parse": 0.9,
                    "extracted_parameters": params if params else None,
                    "suggested_program_id": program_id,
                    "suggested_discriminator": discriminator,
                }
    
    # Unknown intent
    return {
        "intent_type": "unknown",
        "raw_natural_language": natural_language,
        "confidence_of_parse": 0.3,
        "extracted_parameters": None,
        "suggested_program_id": "",
        "suggested_discriminator": "",
    }


class IntentParserHandler(BaseHTTPRequestHandler):
    """HTTP handler for intent parsing requests."""
    
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8")
        
        try:
            request = json.loads(body)
            text = request.get("text", "")
            result = parse_intent(text)
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
        except Exception as e:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())
    
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok", "service": "graphite-ai-layer"}).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        print(f"[AI Layer] {args[0]}")


def main():
    parser = argparse.ArgumentParser(description="Graphite AI Intent Parser")
    parser.add_argument("--serve", action="store_true", help="Run as HTTP server on port 8081")
    parser.add_argument("--port", type=int, default=8081, help="Port for HTTP server")
    parser.add_argument("text", nargs="?", help="Intent text to parse")
    
    args = parser.parse_args()
    
    if args.serve:
        server = HTTPServer(("0.0.0.0", args.port), IntentParserHandler)
        print(f"Graphite AI Layer running on port {args.port}")
        print("Advisory-only intent parser (P1: AI assists, never decides)")
        server.serve_forever()
    elif args.text:
        result = parse_intent(args.text)
        print(json.dumps(result, indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
