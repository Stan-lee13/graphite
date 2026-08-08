#!/usr/bin/env python3
"""
Graphite AI Layer — Advisory Intent Labeler (v2)

This module runs as a SEPARATE PROCESS from the Rust Core.
It labels natural-language transaction intents into the JSON schema
that Graphite Core's verify() endpoint expects.

Constitution P1: AI assists, never decides.
This module only LABELS intent — it does not verify, approve, or execute.
The Core verification engine makes all security decisions.

v2 design (C21):
  * Deterministic, pure-stdlib, zero network — no LLM, no external calls.
  * Emits the FULL intent vocabulary the Core's semantic layer understands
    (swap|trade|exchange, transfer|send, stake|delegate, close|close_account,
    create|create_account, approve|revoke) so labels never trip the
    "unknown intent type" fail-closed path by accident.
  * Protocol candidates and discriminator suggestions are GROUNDED in the
    verified manifest registry (graphite-core/protocols) at load time, with
    an embedded fallback table so the layer keeps working standalone.
  * Per-signal confidence (phrase / parameters / token / protocol) instead of
    a hardcoded number, plus explainable advisory_warnings.
  * Precompiled regexes, single pass, microseconds per call.

Security invariants (unchanged):
  * Advisory only: suggested_program_id / suggested_discriminator /
    advisory_warnings can NEVER weaken a decision. A wrong suggestion
    simply fails to match and the verification blocks.
  * No private key, no wallet address history, no telemetry: input text
    leaves the process only as the JSON response.

Usage:
    python3 intent_parser.py --serve         # Run as HTTP server on :8081
    python3 intent_parser.py "Swap 1 SOL for USDC"  # Label single intent
    python3 intent_parser.py --bench 20000   # Micro-benchmark 20k parses
"""

import json
import os
import re
import sys
import argparse
import statistics
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Intent vocabulary — ALIGNED WITH Graphite Core (verification.rs semantic
# layer). Emitting an intent outside this vocabulary makes the Core fail
# closed ("Unknown intent type"), which is safe but not useful; so the
# labeler only emits these, plus "unknown" as the honest fallback.
# ---------------------------------------------------------------------------
CORE_INTENTS = ("swap", "transfer", "stake", "close", "create", "approve", "revoke")

# Canonical intent -> display label used in advisory output.
INTENT_LABELS = {
    "swap": "swap/exchange",
    "transfer": "transfer/send",
    "stake": "stake/delegate",
    "close": "close account",
    "create": "create/initialize account",
    "approve": "approve delegate",
    "revoke": "revoke delegate",
    "unknown": "unknown",
}

# ---------------------------------------------------------------------------
# Precompiled regex bank. All patterns are case-insensitive, compiled once at
# import time (single pass, no per-call compilation). Group names are
# amount / token / output_token / destination / slippage.
# ---------------------------------------------------------------------------
_RX = {
    "transfer": re.compile(
        r"\b(?:transfer|send|pay)\s+"
        r"(?:(?P<amount_all>all|entire|my)\s+(?:my\s+)?|(?P<amount>\d+(?:\.\d+)?)\s+)"
        r"(?P<token>[A-Za-z0-9]+)"
        r"(?:\s+(?:to|into)\s+(?P<destination>[1-9A-HJ-NP-Za-km-z]{32,44}))?",
        re.IGNORECASE,
    ),
    "swap": re.compile(
        r"\b(?:swap|exchange|trade|convert|sell)\s+"
        r"(?:(?P<amount>\d+(?:\.\d+)?)\s+)?"
        r"(?P<token>[A-Za-z0-9]+)\s+(?:for|into|to)\s+"
        r"(?P<output_token>[A-Za-z0-9]+)",
        re.IGNORECASE,
    ),
    "buy": re.compile(
        r"\bbuy\s+(?:(?P<amount>\d+(?:\.\d+)?)\s+)?"
        r"(?P<output_token>[A-Za-z0-9]+)\s+with\s+(?P<token>[A-Za-z0-9]+)",
        re.IGNORECASE,
    ),
    "stake": re.compile(
        r"\b(?:stake|delegate)\s+(?:(?P<amount>\d+(?:\.\d+)?)\s+)?"
        r"(?P<token>[A-Za-z0-9]+)?",
        re.IGNORECASE,
    ),
    "withdraw": re.compile(
        r"\b(?:unstake|withdraw|claim)\s+(?:(?P<amount>\d+(?:\.\d+)?)\s+)?"
        r"(?P<token>[A-Za-z0-9]+)?",
        re.IGNORECASE,
    ),
    "close": re.compile(
        r"\bclose\s+(?:the\s+)?(?:my\s+)?(?P<token>[A-Za-z0-9]+)?\s*account",
        re.IGNORECASE,
    ),
    "create": re.compile(
        r"\b(?:create|open|initialize)\s+(?:an?\s+)?(?:new\s+)?"
        r"(?P<token>[A-Za-z0-9]+)?\s*account",
        re.IGNORECASE,
    ),
    "approve": re.compile(
        r"\bapprove\s+(?:spending\s+)?(?:of\s+)?(?P<token>[A-Za-z0-9]+)?",
        re.IGNORECASE,
    ),
    "revoke": re.compile(r"\brevoke\b", re.IGNORECASE),
    # Unmodeled-but-detectable intents -> label "unknown" + advisory warning.
    "mint": re.compile(
        r"\bmint\s+(?:(?P<amount>\d+(?:\.\d+)?)\s+)?(?P<token>[A-Za-z0-9]+)",
        re.IGNORECASE,
    ),
    "bridge": re.compile(
        r"\bbridge\s+(?:(?P<amount>\d+(?:\.\d+)?)\s+)?(?P<token>[A-Za-z0-9]+)",
        re.IGNORECASE,
    ),
    "lending": re.compile(r"\b(?:lend|borrow|liquidat|supply)\b", re.IGNORECASE),
    "slippage": re.compile(r"with\s+(\d+(?:\.\d+)?)\s*%\s*slippage", re.IGNORECASE),
    "authority_change": re.compile(
        r"\b(?:set|change|update|transfer)\s+(?:the\s+)?(?:token\s+)?authority\b"
        r"|\bchange\s+owner\b",
        re.IGNORECASE,
    ),
}

# ---------------------------------------------------------------------------
# Token knowledge base (advisory only — symbols, never decisions).
# ---------------------------------------------------------------------------
KNOWN_TOKENS = {
    "SOL", "WSOL", "USDC", "USDT", "USDS", "PYUSD", "MSOL", "JITOSOL", "STSOL",
    "BSOL", "BONK", "JUP", "RAY", "ORCA", "WIF", "SAMO", "FIDA", "HNT",
}


def _norm_token(tok: Optional[str]) -> Optional[str]:
    if not tok:
        return None
    return tok.upper()


# ---------------------------------------------------------------------------
# Embedded fallback tables (used only when the manifest registry is not
# readable at load time). Values are cross-checked against the manifests by
# test_intent_parser.py::test_program_ids_match_manifests.
# ---------------------------------------------------------------------------
FALLBACK_CANONICAL = {
    # intent -> (manifest filename, program_id, instruction name)
    "transfer": ("system-program.json", "11111111111111111111111111111111", "Transfer"),
    "swap": ("jupiter-v6.json", "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4", "route_v2"),
    "stake": ("stake-program.json", "Stake11111111111111111111111111111111111111", "DelegateStake"),
    "close": ("spl-token.json", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "CloseAccount"),
    "create": ("ata-program.json", "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", "CreateAssociatedTokenAccount"),
    "approve": ("spl-token.json", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "Approve"),
    "revoke": ("spl-token.json", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "Revoke"),
}

# intent -> instruction-name keywords used to derive protocol candidates
# from the manifest registry (advisory).
INTENT_KEYWORDS = {
    "transfer": ("transfer", "send"),
    "swap": ("swap", "route", "trade", "exchange", "buy", "sell"),
    "stake": ("stake", "delegate", "withdraw", "deactivate"),
    "close": ("close",),
    "create": ("create", "initialize", "allocate", "assign", "open"),
    "approve": ("approve",),
    "revoke": ("revoke",),
}

# ---------------------------------------------------------------------------
# Manifest registry grounding. Loaded once at import; any failure falls back
# to the embedded table (the layer must never crash because the registry is
# not present in a deployed environment).
# ---------------------------------------------------------------------------
_MANIFEST_DIR = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "graphite-core", "protocols")
)


def _load_manifests() -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, str]]]:
    """Load manifests -> {intent: {filename: {program_id, name, discriminator}}}.

    Returns (grounded, loaded_registry) where grounded is a map from intent to
    candidate manifests, and loaded_registry a map from program_id -> name.
    """
    grounded: Dict[str, Dict[str, Dict[str, Any]]] = {}
    loaded_registry: Dict[str, str] = {}
    try:
        for fn in os.listdir(_MANIFEST_DIR):
            if not fn.endswith(".json") or fn == "verified_program_ids.json":
                continue
            with open(os.path.join(_MANIFEST_DIR, fn), encoding="utf-8") as f:
                manifest = json.load(f)
            program_id = manifest.get("protocol", {}).get("program_id", "")
            name = manifest.get("protocol", {}).get("name", fn)
            if not program_id:
                continue
            loaded_registry[program_id] = name
            for instr in manifest.get("instructions", []):
                iname = str(instr.get("name", ""))
                for intent, kws in INTENT_KEYWORDS.items():
                    if any(kw.lower() in iname.lower() for kw in kws):
                        grounded.setdefault(intent, {}).setdefault(fn, []).append({
                            "program_id": program_id,
                            "name": name,
                            "instruction": iname,
                            "discriminator": str(instr.get("discriminator", "")),
                        })
    except (OSError, json.JSONDecodeError):
        # Registry unavailable (standalone deployment) — embedded fallback.
        for intent, (fn, pid, instr) in FALLBACK_CANONICAL.items():
            grounded.setdefault(intent, {})[fn] = {
                "program_id": pid,
                "name": fn,
                "instruction": instr,
                "discriminator": "",
            }
    return grounded, loaded_registry


_GROUNDED, _REGISTRY = _load_manifests()


def _canonical_for(intent: str) -> Tuple[str, str, str, bool]:
    """Return (program_id, discriminator, protocol_name, grounded) for intent.

    Prefers the manifest registry (deployed surface); falls back to the
    embedded table. `grounded=False` means the suggestion is embedded-only.
    """
    entry = FALLBACK_CANONICAL.get(intent)
    if not entry:
        return ("", "", "", False)
    fn, pid, instr = entry
    grounded = False
    disc = ""
    name = fn
    # Prefer the instruction whose name EXACTLY matches the canonical one
    # (e.g. "route_v2" over "sharedAccountsRouteWithTokenLedger";
    # "DelegateStake" over "DeactivateDelinquent"; "Approve" over
    # "ApproveChecked"). Falls back to the first keyword match otherwise.
    candidates = _GROUNDED.get(intent, {}).get(fn, [])
    if candidates:
        grounded = True
        picked = next(
            (c for c in candidates if c["instruction"].lower() == instr.lower()),
            candidates[0],
        )
        pid = picked["program_id"]
        disc = picked["discriminator"]
        name = picked["name"]
    return (pid, disc, name, grounded)


# ---------------------------------------------------------------------------
# Risk-hint extraction (advisory warnings). These are heuristics surfaced to
# the operator/agent; they are NEVER decisions.
# ---------------------------------------------------------------------------
_VANITY_SUFFIX = re.compile(r"11111$")
_VANITY_PREFIX = re.compile(r"^(Compu|Sysvar|Token|Stake|Memo|Jup|Raydium|Orca)", re.IGNORECASE)

LARGE_AMOUNT_THRESHOLD = 10_000.0


def _risk_hints(intent: str, params: Dict[str, Any], text: str) -> List[Dict[str, Any]]:
    warnings: List[Dict[str, Any]] = []
    dest = params.get("destination")
    if dest:
        if _VANITY_SUFFIX.search(dest) or _VANITY_PREFIX.search(dest):
            warnings.append({
                "code": "IMPERSONATION_VANITY",
                "severity": "high",
                "message": (
                    f"destination {dest[:8]}…{dest[-6:]} looks like it impersonates an "
                    "official/system account (vanity suffix or reserved prefix) — "
                    "verify the recipient before signing"
                ),
            })
    if intent == "transfer" and not dest:
        warnings.append({
            "code": "NO_DESTINATION",
            "severity": "medium",
            "message": "transfer intent without an explicit destination address — the "
                       "resulting instruction may not be executable as stated",
        })
    tokens = [params.get("input_token"), params.get("output_token")]
    for tok in tokens:
        if tok and _norm_token(tok) not in KNOWN_TOKENS:
            warnings.append({
                "code": "UNKNOWN_TOKEN",
                "severity": "low",
                "message": f"token symbol '{tok}' is not in the advisory knowledge base — "
                           "verify the mint address rather than trusting the symbol",
            })
    if intent == "approve":
        warnings.append({
            "code": "APPROVE_DELEGATE",
            "severity": "medium",
            "message": "approve grants delegate spending authority over the token account "
                       "until revoked — this is a permission escalation primitive",
        })
    if intent == "close":
        warnings.append({
            "code": "CLOSE_ACCOUNT",
            "severity": "low",
            "message": "closing an account removes it and recovers rent — the account "
                       "cannot be reused without re-initializing",
        })
    if _RX["authority_change"].search(text):
        warnings.append({
            "code": "AUTHORITY_CHANGE",
            "severity": "high",
            "message": "the text requests an authority/owner change — this is a sensitive "
                       "ownership transfer; confirm the new authority is correct",
        })
    amount = params.get("amount")
    if amount and amount != "all":
        try:
            if float(amount) >= LARGE_AMOUNT_THRESHOLD:
                warnings.append({
                    "code": "LARGE_AMOUNT",
                    "severity": "medium",
                    "message": f"large amount detected ({amount}) — consider a manual review",
                })
        except ValueError:
            pass
    # Unmodeled intents that are detectably NOT in the core vocabulary.
    if _RX["mint"].search(text):
        warnings.append({
            "code": "MINT_UNMODELED",
            "severity": "medium",
            "message": "'mint' is not a modeled intent class in the Core — the verification "
                       "will treat it as unknown intent and fail closed",
        })
    if _RX["bridge"].search(text):
        warnings.append({
            "code": "BRIDGE_UNMODELED",
            "severity": "medium",
            "message": "'bridge' is not a modeled intent class in the Core — the verification "
                       "will treat it as unknown intent and fail closed; bridge transfers are "
                       "irreversible on the target chain",
        })
    if _RX["lending"].search(text):
        warnings.append({
            "code": "LENDING_UNMODELED",
            "severity": "medium",
            "message": "'lend/borrow/supply' is not a modeled intent class in the Core — the "
                       "verification will treat it as unknown intent and fail closed",
        })
    return warnings


# ---------------------------------------------------------------------------
# Core labeler entrypoint.
# ---------------------------------------------------------------------------
def parse_intent(natural_language: str) -> Dict[str, Any]:
    """
    Label natural language into Graphite's ProposedIntent schema.

    Returns a dict with:
        - intent_type: one of the Core's vocabulary or "unknown"
        - raw_natural_language: the original text
        - confidence_of_parse: 0.0-1.0 computed from per-signal components
        - confidence_components: phrase/parameters/token/protocol breakdown
        - extracted_parameters: token/amount/destination/slippage if extractable
        - suggested_program_id / suggested_discriminator: manifest-grounded
        - protocol_candidates: manifest-grounded candidate programs for intent
        - advisory_warnings: risk hints (advisory only, never decisions)
        - parse_version: "2"

    This is ADVISORY ONLY. The Core verification engine makes all decisions.
    """
    text = (natural_language or "").strip()
    if not text:
        return _unknown_result(natural_language)

    params: Dict[str, Any] = {}
    intent = "unknown"
    phrase_strength = 0.2
    matched_kind = "unknown"

    m = _RX["transfer"].search(text)
    if m:
        intent = "transfer"
        matched_kind = "transfer"
        phrase_strength = 1.0
        if m.group("amount"):
            params["amount"] = m.group("amount")
        elif m.group("amount_all"):
            params["amount"] = "all"
        if m.group("token"):
            params["input_token"] = m.group("token")
        if m.group("destination"):
            params["destination"] = m.group("destination")
    else:
        m = _RX["buy"].search(text)
        if m:
            # "buy 1 SOL with USDC" -> input USDC, output SOL.
            intent = "swap"
            matched_kind = "buy"
            phrase_strength = 1.0
            if m.group("amount"):
                params["amount"] = m.group("amount")
            if m.group("token"):
                params["input_token"] = m.group("token")
            if m.group("output_token"):
                params["output_token"] = m.group("output_token")
        else:
            m = _RX["swap"].search(text)
            if m:
                intent = "swap"
                matched_kind = "swap"
                phrase_strength = 1.0
                if m.group("amount"):
                    params["amount"] = m.group("amount")
                if m.group("token"):
                    params["input_token"] = m.group("token")
                if m.group("output_token"):
                    params["output_token"] = m.group("output_token")
            else:
                m = _RX["withdraw"].search(text)
                if m:
                    # Unstake/withdraw is classified under the stake class
                    # (the Core's stake keywords include withdraw).
                    intent = "stake"
                    matched_kind = "withdraw"
                    phrase_strength = 1.0
                    if m.group("amount"):
                        params["amount"] = m.group("amount")
                    if m.group("token"):
                        params["input_token"] = m.group("token")
                else:
                    m = _RX["stake"].search(text)
                    if m:
                        intent = "stake"
                        matched_kind = "stake"
                        phrase_strength = 1.0
                        if m.group("amount"):
                            params["amount"] = m.group("amount")
                        if m.group("token"):
                            params["input_token"] = m.group("token")
                    else:
                        m = _RX["close"].search(text)
                        if m:
                            intent = "close"
                            matched_kind = "close"
                            phrase_strength = 1.0
                            if m.group("token"):
                                params["account_type"] = m.group("token")
                        else:
                            m = _RX["create"].search(text)
                            if m:
                                intent = "create"
                                matched_kind = "create"
                                phrase_strength = 1.0
                                if m.group("token"):
                                    params["account_type"] = m.group("token")
                            else:
                                m = _RX["approve"].search(text)
                                if m:
                                    intent = "approve"
                                    matched_kind = "approve"
                                    phrase_strength = 1.0
                                    if m.group("token"):
                                        params["input_token"] = m.group("token")
                                elif _RX["revoke"].search(text):
                                    intent = "revoke"
                                    matched_kind = "revoke"
                                    phrase_strength = 1.0

    sm = _RX["slippage"].search(text)
    if sm:
        try:
            params["slippage_bps"] = int(round(float(sm.group(1)) * 100))
        except (ValueError, TypeError):
            pass

    if intent == "unknown":
        return _unknown_result(natural_language)

    # --- protocol grounding (advisory) ---
    program_id, disc, protocol_name, grounded = _canonical_for(intent)

    candidates = []
    for fn, cand_list in sorted(_GROUNDED.get(intent, {}).items()):
        for cand in cand_list[:1]:  # one representative instruction per manifest
            candidates.append({
                "manifest": fn,
                "program_id": cand["program_id"],
                "name": cand["name"],
                "instruction": cand["instruction"],
            })

    # --- confidence (per-signal, deterministic) ---
    # phrase: 1.0 strong match, 0.6 partial (withdraw-as-stake still strong),
    #        0.2 unknown. Here any matched intent is a strong phrase match.
    phrase_signal = 1.0
    # parameters: fraction of the intent's expected fields present.
    if intent == "transfer":
        expected = 3  # amount, input_token, destination
        present = sum(
            1 for k in ("amount", "input_token", "destination") if params.get(k)
        )
    elif intent in ("swap",):
        expected = 3  # amount, input_token, output_token
        present = sum(
            1 for k in ("amount", "input_token", "output_token") if params.get(k)
        )
    elif intent == "stake":
        expected = 2  # amount, input_token
        present = sum(1 for k in ("amount", "input_token") if params.get(k))
    else:
        expected = 1
        present = 1
    param_signal = present / expected if expected else 1.0
    # token: all extracted symbols recognized -> 1.0, unknown symbol -> 0.5.
    tokens = [params.get("input_token"), params.get("output_token")]
    tokens = [t for t in tokens if t]
    if tokens and any(_norm_token(t) not in KNOWN_TOKENS for t in tokens):
        token_signal = 0.5
    else:
        token_signal = 1.0
    # protocol: grounded in registry -> 1.0, embedded-only -> 0.7.
    protocol_signal = 1.0 if grounded else 0.7

    confidence = round(
        0.45 * phrase_signal
        + 0.30 * param_signal
        + 0.15 * token_signal
        + 0.10 * protocol_signal,
        3,
    )
    confidence = max(0.0, min(0.99, confidence))

    return {
        "intent_type": intent,
        "raw_natural_language": natural_language,
        "confidence_of_parse": confidence,
        "confidence_components": {
            "phrase": round(phrase_signal, 3),
            "parameters": round(param_signal, 3),
            "token": round(token_signal, 3),
            "protocol": round(protocol_signal, 3),
        },
        "extracted_parameters": params if params else None,
        "suggested_program_id": program_id,
        "suggested_discriminator": disc,
        "protocol_candidates": candidates,
        "advisory_warnings": _risk_hints(intent, params, text),
        "matched_kind": matched_kind,
        "parse_version": "2",
    }


def _unknown_result(natural_language: str) -> Dict[str, Any]:
    text = (natural_language or "").strip()
    warnings = _risk_hints("unknown", {}, text)
    return {
        "intent_type": "unknown",
        "raw_natural_language": natural_language,
        "confidence_of_parse": 0.2,
        "confidence_components": {
            "phrase": 0.2,
            "parameters": 0.0,
            "token": 0.0,
            "protocol": 0.0,
        },
        "extracted_parameters": None,
        "suggested_program_id": "",
        "suggested_discriminator": "",
        "protocol_candidates": [],
        "advisory_warnings": warnings,
        "matched_kind": "unknown",
        "parse_version": "2",
    }


# ---------------------------------------------------------------------------
# HTTP server (bounded body, robust Content-Length — hardened in C20).
# ---------------------------------------------------------------------------
MAX_BODY_BYTES = 64 * 1024


class IntentParserHandler(BaseHTTPRequestHandler):
    """HTTP handler for intent labeling requests."""

    def _read_bounded_body(self) -> Optional[bytes]:
        """Read the request body with a hard size cap and robust
        Content-Length parsing. Malformed or oversized requests return None
        (caller answers 413/400) instead of raising or trusting the header."""
        raw = self.headers.get("Content-Length", "0")
        try:
            length = int(raw)
        except ValueError:
            return None
        if length < 0 or length > MAX_BODY_BYTES:
            return None
        return self.rfile.read(length)

    def do_POST(self):
        body = self._read_bounded_body()
        if body is None:
            self.send_response(413)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps({"error": "request body too large or malformed Content-Length"}).encode()
            )
            return

        try:
            request = json.loads(body.decode("utf-8"))
            if not isinstance(request, dict) or "text" not in request:
                raise ValueError("request must be a JSON object with a 'text' field")
            result = parse_intent(request.get("text", ""))

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


# ---------------------------------------------------------------------------
# Benchmark mode — prove the "fast" claim with real numbers.
# ---------------------------------------------------------------------------
_BENCH_CORPUS = [
    "Transfer 1 SOL to 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
    "Swap 1 SOL for USDC",
    "Swap 100 USDC for JUP with 1% slippage",
    "Buy 5 SOL with USDT",
    "Sell 50 JUP for SOL",
    "Stake 10 SOL",
    "Delegate 2.5 mSOL",
    "Unstake 3 SOL",
    "Withdraw 1 jitoSOL",
    "Close my account",
    "Close the USDC account",
    "Create a new account",
    "Open a token account",
    "Approve spending of 500 USDC",
    "Revoke the delegate",
    "Send all my SOL to 4vJ9JU1b6wXjA6E6Sf9W9f9f9f9f9f9f9f9f9f9f9f9f9",
    "Bridge 2 ETH from Solana to Ethereum",
    "Mint 1000 BONK",
    "do something random and weird",
    "",
]


def _benchmark(n: int) -> None:
    import time

    corpus = _BENCH_CORPUS
    latencies = []
    start = time.perf_counter()
    for i in range(n):
        text = corpus[i % len(corpus)]
        t0 = time.perf_counter()
        parse_intent(text)
        latencies.append((time.perf_counter() - t0) * 1e6)
    elapsed = time.perf_counter() - start
    latencies.sort()
    p50 = latencies[len(latencies) // 2]
    p99 = latencies[int(len(latencies) * 0.99) - 1]
    print(f"parsed {n} intents in {elapsed:.3f}s "
          f"({n / elapsed:,.0f} parses/sec)")
    print(f"latency  p50={p50:.1f}us  p99={p99:.1f}us  max={latencies[-1]:.1f}us")


def main():
    parser = argparse.ArgumentParser(description="Graphite AI Advisory Intent Labeler")
    parser.add_argument("--serve", action="store_true", help="Run as HTTP server on port 8081")
    parser.add_argument("--port", type=int, default=8081, help="Port for HTTP server")
    parser.add_argument("--bench", type=int, metavar="N", help="Run N-parse micro-benchmark")
    parser.add_argument("text", nargs="?", help="Intent text to label")

    args = parser.parse_args()

    if args.bench:
        _benchmark(args.bench)
    elif args.serve:
        server = HTTPServer(("0.0.0.0", args.port), IntentParserHandler)
        print(f"Graphite AI Layer running on port {args.port}")
        print("Advisory-only intent labeler (P1: AI assists, never decides)")
        print(f"manifest registry grounded: {len(_REGISTRY)} program IDs loaded")
        server.serve_forever()
    elif args.text:
        result = parse_intent(args.text)
        print(json.dumps(result, indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
