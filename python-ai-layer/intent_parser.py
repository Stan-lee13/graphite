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
  * Precompiled regexes, no per-call compilation, microseconds per call.

Security invariants (unchanged):
  * Advisory only: suggested_program_id / suggested_discriminator /
    advisory_warnings can NEVER weaken a decision. A wrong suggestion
    simply fails to match and the verification blocks.
  * No private key, no wallet address history, no telemetry: input text
    leaves the process only as the JSON response.

Usage:
    python3 intent_parser.py --serve         # Run as HTTP server on 127.0.0.1:8081
                                             # (GRAPHITE_AI_LAYER_HOST overrides the bind)
    python3 intent_parser.py "Swap 1 SOL for USDC"  # Label single intent
    python3 intent_parser.py --bench 20000   # Micro-benchmark 20k parses
"""

import json
import os
import re
import socket
import threading
import argparse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Intent vocabulary — ALIGNED WITH Graphite Core (verification.rs semantic
# layer). Emitting an intent outside this vocabulary makes the Core fail
# closed ("Unknown intent type"), which is safe but not useful; so the
# labeler only emits these, plus "unknown" as the honest fallback.
# ---------------------------------------------------------------------------
#
# Round 30 (roadmap R-M14): withdraw, claim, burn and configure. The Core
# declares each only for the instructions a grounded grant names
# (graphite-core/src/intent_grants.rs) — a liquidity withdrawal paid to the
# signer's own token accounts, a fee claim, a burn from the signer's own
# account, an owner updating its own offer — and refuses the rest. The label
# is still only a label.
CORE_INTENTS = ("swap", "transfer", "stake", "close", "create", "approve", "revoke",
                "withdraw", "claim", "burn", "configure")

# Canonical intent -> display label used in advisory output.
INTENT_LABELS = {
    "swap": "swap/exchange",
    "transfer": "transfer/send",
    "stake": "stake/delegate",
    "close": "close account",
    "create": "create/initialize account",
    "approve": "approve delegate",
    "revoke": "revoke delegate",
    "withdraw": "withdraw liquidity",
    "claim": "claim fees/rewards",
    "burn": "burn own tokens",
    "configure": "update own offer/configuration",
    "unknown": "unknown",
}

# ---------------------------------------------------------------------------
# Precompiled regex bank. All patterns are case-insensitive, compiled once at
# import time (no per-call compilation). Group names are
# amount / token / output_token / destination / slippage.
# ---------------------------------------------------------------------------
# Words that may sit between a verb and its amount/token without being either.
_DETERMINERS = r"(?:(?:all|of|my|the|a|an|your|our|some|this|that)\s+)*"

_RX = {
    # A5-02 (2026-09-29 audit): the destination must be the whole word — after
    # it, only trailing sentence punctuation, then whitespace or the end of the
    # text (the same rule as the bridge's intent-grounding.ts). Without the
    # lookahead, a non-base58 character inside or at the end of an address
    # ('0', a Cyrillic homoglyph, '-', '.', '_') stopped the group short, and
    # the prefix — at 43 characters usually a valid key nobody holds — came
    # back as the destination. Such a word now yields no destination at all.
    "transfer": re.compile(
        r"\b(?:transfer|send|pay)\s+"
        r"(?:(?P<amount_all>all|entire|my)\s+(?:my\s+)?|(?P<amount>\d+(?:\.\d+)?)\s+)"
        r"(?P<token>[A-Za-z0-9]+)"
        r"(?:\s+(?:to|into)\s+(?P<destination>(?-i:[1-9A-HJ-NP-Za-km-z]{32,44}))"
        r"(?=[.,;:!?)\]'\"]*(?:\s|$)))?",
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
    # Round 29 (audit 2026-10-20, PY3): determiners between the verb and the
    # amount/token are skipped ("stake my SOL" took "my" as the token).
    "stake": re.compile(
        r"\b(?:stake|delegate)\s+" + _DETERMINERS +
        r"(?:(?P<amount>\d+(?:\.\d+)?)\s+)?"
        r"(?P<token>[A-Za-z0-9]+)?",
        re.IGNORECASE,
    ),
    "withdraw": re.compile(
        r"\b(?P<verb>unstake|withdraw|claim)\s+" + _DETERMINERS +
        r"(?:(?P<amount>\d+(?:\.\d+)?)\s+)?"
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
    # Round 29 (PY3): "Approve spending of 500 USDC" took "500" as the token
    # and "Approve the transaction" took "the".
    "approve": re.compile(
        r"\bapprove\s+(?:spending\s+)?(?:of\s+)?" + _DETERMINERS +
        r"(?:(?P<amount>\d+(?:\.\d+)?)\s+)?"
        r"(?P<token>[A-Za-z0-9]+)?",
        re.IGNORECASE,
    ),
    "revoke": re.compile(r"\brevoke\b", re.IGNORECASE),
    # Round 30: burning the signer's own tokens.
    "burn": re.compile(
        r"\bburn\s+" + _DETERMINERS +
        r"(?:(?P<amount>\d+(?:\.\d+)?)\s+)?"
        r"(?P<token>[A-Za-z0-9]+)?",
        re.IGNORECASE,
    ),
    # Round 30 (R-M13): an owner changing its own offer, bid or listing.
    # Changing an authority or an owner is NOT this (authority_change below).
    "configure": re.compile(
        r"\b(?:update|edit|modify|change|reprice)\s+(?:my\s+|our\s+|the\s+)?(?:own\s+)?"
        r"(?P<object>offer|bid|listing)\b",
        re.IGNORECASE,
    ),
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
    # Round 29 (audit 2026-10-20, PY3): "Don't send 5 SOL to <addr>" was
    # labelled a transfer with no warning. A negation ahead of the verb makes
    # the label "unknown".
    "negation": re.compile(
        r"\b(?:don['\u2019]?t|do\s+not|does\s+not|doesn['\u2019]?t|never|not|cancel|stop)\b",
        re.IGNORECASE,
    ),
    # "the delegate", "revoke delegate authority": delegate as a noun.
    "delegate_noun": re.compile(
        r"\b(?:the|a|an|my|your|this|that|revoke|approve)\s+$",
        re.IGNORECASE,
    ),
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


# Round 29 (audit 2026-10-20, PY3): words a token group can capture that are
# not token symbols. "Approve the transaction" reported the token "the";
# "stake my SOL", "my".
_NOT_A_TOKEN = frozenset({
    "a", "an", "the", "my", "your", "our", "all", "of", "some", "this", "that", "it", "its",
    "these", "those", "me", "us", "to", "for", "from", "with", "and", "then", "please",
    "transaction", "transactions", "tx", "account", "accounts", "delegate", "authority", "stake",
    "rewards", "reward", "liquidity", "lp", "fees", "fee", "collateral", "position", "yield",
})

# Objects of withdraw/claim that are not a stake withdrawal: claiming rewards
# or fees and withdrawing liquidity or collateral are different operations on
# different programs. Round 30: they are the Core's `claim` and `withdraw`
# intents (declared only for granted instructions); the name is kept for
# the objects that make a withdrawal one of those.
_UNMODELED_WITHDRAWAL_OBJECTS = frozenset({
    "rewards", "reward", "liquidity", "lp", "fees", "fee", "collateral", "position", "yield",
})
# Of those, the ones whose withdrawal is a claim of accrued value, not of
# principal.
_CLAIMED_OBJECTS = frozenset({"rewards", "reward", "fees", "fee", "yield"})


def _token(m: "re.Match[str]", group: str = "token") -> Optional[str]:
    """The captured token, unless the word captured is not a token."""
    tok = m.group(group)
    if not tok or tok.lower() in _NOT_A_TOKEN:
        return None
    return tok


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
    # Round 30: one granted instruction per new intent (intent_grants.rs).
    "withdraw": ("meteora-dlmm.json", "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo", "remove_liquidity"),
    "claim": ("meteora-dlmm.json", "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo", "claim_fee"),
    "burn": ("spl-token.json", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "Burn"),
    "configure": ("marketplace-ccmrkt.json", "CcmRKTuZCGJBWQwMHvDYApBRvSZNHqGJXkznqpDTSQUr", "update_offer"),
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
    # Round 30: the names of the granted instructions (intent_grants.rs), not
    # every instruction named "withdraw" — the Core refuses the rest.
    "withdraw": ("remove_liquidity", "remove_all_liquidity", "decrease_liquidity_v2"),
    "claim": ("claim_fee",),
    "burn": ("burn",),
    "configure": ("update_offer",),
}

# ---------------------------------------------------------------------------
# Manifest registry grounding. Loaded once at import; any failure falls back
# to the embedded table (the layer must never crash because the registry is
# not present in a deployed environment).
# ---------------------------------------------------------------------------
_MANIFEST_DIR = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "graphite-core", "protocols")
)


# A manifest that cannot be read or does not have the expected shape.
# UnicodeDecodeError and json.JSONDecodeError are both ValueErrors; a
# non-object document fails on `.get` (AttributeError) or on iteration
# (TypeError).
_MANIFEST_LOAD_ERRORS = (OSError, ValueError, AttributeError, TypeError)


def _load_one_manifest(fn: str) -> Tuple[str, str, Dict[str, List[Dict[str, Any]]]]:
    """Read one manifest -> (program_id, name, {intent: [candidate, ...]}).

    Everything is built before anything is returned, so a manifest that fails
    halfway contributes nothing rather than a partial candidate list.
    """
    with open(os.path.join(_MANIFEST_DIR, fn), encoding="utf-8") as f:
        manifest = json.load(f)
    protocol = manifest.get("protocol", {})
    program_id = str(protocol.get("program_id", ""))
    name = str(protocol.get("name", fn))
    by_intent: Dict[str, List[Dict[str, Any]]] = {}
    for instr in manifest.get("instructions", []):
        iname = str(instr.get("name", ""))
        for intent, kws in INTENT_KEYWORDS.items():
            if any(kw.lower() in iname.lower() for kw in kws):
                by_intent.setdefault(intent, []).append({
                    "program_id": program_id,
                    "name": name,
                    "instruction": iname,
                    "discriminator": str(instr.get("discriminator", "")),
                })
    return program_id, name, by_intent


def _load_manifests() -> Tuple[Dict[str, Dict[str, List[Dict[str, Any]]]], Dict[str, str]]:
    """Load manifests -> {intent: {filename: [{program_id, name, instruction, discriminator}]}}.

    Returns (grounded, loaded_registry) where grounded is a map from intent to
    candidate manifests, and loaded_registry a map from program_id -> name.

    A5-05 (2026-09-29 audit): the fallback used to store a DICT per manifest
    while every reader indexes a LIST, so a standalone deployment crashed on
    every modelled intent (`candidates[0]` -> KeyError: 0). It also caught
    only OSError/JSONDecodeError around the whole directory, so one
    non-UTF-8 or non-object manifest killed the import. Each manifest is now
    loaded on its own, and every intent whose canonical manifest did not load
    gets the embedded entry — in the same list shape, marked `embedded` so
    `_canonical_for` reports it as not grounded.
    """
    grounded: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
    loaded_registry: Dict[str, str] = {}
    try:
        names = sorted(os.listdir(_MANIFEST_DIR))
    except OSError:
        names = []  # registry unavailable (standalone deployment)
    for fn in names:
        if not fn.endswith(".json") or fn == "verified_program_ids.json":
            continue
        try:
            program_id, name, by_intent = _load_one_manifest(fn)
        except _MANIFEST_LOAD_ERRORS:
            continue  # this manifest only; the rest still ground
        if not program_id:
            continue
        loaded_registry[program_id] = name
        for intent, cands in by_intent.items():
            grounded.setdefault(intent, {})[fn] = cands
    # Embedded fallback, per intent, for whatever the registry did not supply.
    for intent, (fn, pid, instr) in FALLBACK_CANONICAL.items():
        if fn not in grounded.get(intent, {}):
            grounded.setdefault(intent, {})[fn] = [{
                "program_id": pid,
                "name": fn,
                "instruction": instr,
                "discriminator": "",
                "embedded": True,
            }]
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
        picked = next(
            (c for c in candidates if c["instruction"].lower() == instr.lower()),
            candidates[0],
        )
        # The embedded table is not the registry: a suggestion taken from it
        # is embedded-only (protocol signal 0.7), never "grounded".
        grounded = not picked.get("embedded", False)
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
    if intent in ("withdraw", "claim", "burn", "configure"):
        warnings.append({
            "code": "GRANT_SCOPED_INTENT",
            "severity": "medium",
            "message": f"the Core declares a '{intent}' only for the instructions a grounded "
                       "grant names, when the transaction's own accounts show the operation is "
                       "the signer's own (proceeds to the signer's associated token accounts, "
                       "rent to the signer, an object seeded by the signer) — anything else is "
                       "refused",
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
# Clause detection.
# ---------------------------------------------------------------------------
# Regex kind -> Core intent. Order is the tie-break when two kinds match at
# the same position.
_KIND_TO_INTENT = {
    "transfer": "transfer",
    "buy": "swap",
    "swap": "swap",
    "withdraw": "stake",
    "stake": "stake",
    "close": "close",
    "create": "create",
    "approve": "approve",
    "revoke": "revoke",
    "burn": "burn",
    "configure": "configure",
}


def _clauses(text: str) -> List[Tuple[int, int, str, "re.Match[str]"]]:
    """Every intent clause in `text`, in order: (start, end, kind, match).

    A match that starts inside an earlier one is part of it ("withdraw stake
    from ..." is one withdrawal, not a withdrawal and a stake). "delegate"
    used as a noun ("revoke the delegate authority") is not a stake verb —
    Round 29 (audit 2026-10-20, PY3): that text was labelled stake.
    """
    found = []
    for rank, kind in enumerate(_KIND_TO_INTENT):
        for m in _RX[kind].finditer(text):
            if kind == "stake" and m.group(0)[:8].lower() == "delegate" and \
                    _RX["delegate_noun"].search(text[max(0, m.start() - 16):m.start()]):
                continue
            found.append((m.start(), rank, m.end(), kind, m))
    found.sort(key=lambda f: (f[0], f[1]))
    accepted: List[Tuple[int, int, str, "re.Match[str]"]] = []
    for start, _rank, end, kind, m in found:
        if accepted and start < accepted[-1][1]:
            continue
        accepted.append((start, end, kind, m))
    return accepted


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

    # Round 29 (audit 2026-10-20, PY3): every clause the text contains, not
    # the first class that matched anywhere. "Swap 1 SOL for USDC then send
    # 2 SOL to X" used to come back as a transfer of 2 SOL with no word about
    # the swap; a text that asks for two things is now "unknown" with a
    # warning, because one label cannot describe it.
    clauses = _clauses(text)
    if not clauses:
        return _unknown_result(natural_language)
    if len(clauses) > 1:
        kinds = ", ".join(k for _s, _e, k, _m in clauses)
        return _unknown_result(natural_language, [{
            "code": "MULTIPLE_INTENTS",
            "severity": "high",
            "message": f"the text asks for more than one action ({kinds}) — one intent label "
                       "cannot describe it; split it into one request per action",
        }])
    start_at, _end, matched_kind, m = clauses[0]
    negation = _RX["negation"].search(text, 0, start_at)
    if negation:
        return _unknown_result(natural_language, [{
            "code": "NEGATED_INTENT",
            "severity": "high",
            "message": f"the text negates the action ('{negation.group(0)}' before "
                       f"'{m.group(0).split()[0]}') — it is not labelled as that action",
        }])

    intent = _KIND_TO_INTENT[matched_kind]
    phrase_strength = 1.0
    if matched_kind == "transfer":
        if m.group("amount"):
            params["amount"] = m.group("amount")
        elif m.group("amount_all"):
            params["amount"] = "all"
        if _token(m):
            params["input_token"] = _token(m)
        if m.group("destination"):
            params["destination"] = m.group("destination")
    elif matched_kind in ("buy", "swap"):
        # "buy 1 SOL with USDC" -> input USDC, output SOL; the regex groups
        # are already named that way round.
        if m.group("amount"):
            params["amount"] = m.group("amount")
        if _token(m):
            params["input_token"] = _token(m)
        if _token(m, "output_token"):
            params["output_token"] = _token(m, "output_token")
    elif matched_kind == "withdraw":
        # Unstake / withdraw <amount> <token> is classified under the stake
        # class (the Core's stake keywords include withdraw). Claiming, and
        # withdrawing liquidity, rewards, fees or collateral, are not stake
        # withdrawals (Round 29, PY3: "claim rewards" and "withdraw liquidity
        # from Orca" were labelled stake). Since Round 30 the Core has the
        # `withdraw` and `claim` intents for them: a claim (of fees or
        # rewards, whatever the verb) is `claim`, a withdrawal of liquidity,
        # a position or collateral is `withdraw`. The Core declares either
        # only for the instructions a grounded grant names.
        obj = (m.group("token") or "").lower()
        verb = m.group("verb").lower()
        if verb == "claim" or obj in _CLAIMED_OBJECTS:
            intent = "claim"
        elif obj in _UNMODELED_WITHDRAWAL_OBJECTS:
            intent = "withdraw"
        if intent != "stake" and obj:
            params["account_type"] = obj
        if m.group("amount"):
            params["amount"] = m.group("amount")
        if _token(m):
            params["input_token"] = _token(m)
    elif matched_kind == "burn":
        if m.group("amount"):
            params["amount"] = m.group("amount")
        if _token(m):
            params["input_token"] = _token(m)
    elif matched_kind == "configure":
        params["account_type"] = m.group("object").lower()
    elif matched_kind in ("stake", "approve"):
        if m.group("amount"):
            params["amount"] = m.group("amount")
        if _token(m):
            params["input_token"] = _token(m)
    elif matched_kind in ("close", "create"):
        if _token(m):
            params["account_type"] = _token(m)
    # revoke: no parameters.

    sm = _RX["slippage"].search(text)
    if sm:
        try:
            params["slippage_bps"] = int(round(float(sm.group(1)) * 100))
        except (ValueError, TypeError):
            pass

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
    # phrase: 1.0 strong match, 0.2 unknown. The branch that matched set it;
    # an unknown intent returned above, so every intent here matched a phrase.
    phrase_signal = phrase_strength
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


def _unknown_result(natural_language: str, why: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    text = (natural_language or "").strip()
    warnings = list(why or []) + _risk_hints("unknown", {}, text)
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
# HTTP server (bounded body, robust Content-Length — hardened in C20; bound to
# loopback, threaded and time-limited — Round 19, F-19-C5).
# ---------------------------------------------------------------------------
MAX_BODY_BYTES = 64 * 1024

# Seconds a connection may sit idle mid-request before it is dropped. Round 19
# (F-19-C5): the server was a single-threaded HTTPServer with no socket
# timeout, and `rfile.read(length)` trusted Content-Length — a client that
# declared 100 bytes and sent 10 held the ONLY thread forever, and every other
# caller (the bridge included) hung behind it.
REQUEST_TIMEOUT_SECONDS = 10.0

# Seconds a whole request may take, from accept to response. Round 29 (audit
# 2026-10-20, PY1): the per-read timeout above bounds each read, not the
# request — a client dribbling one byte every nine seconds kept its thread
# for as long as it liked, and with one unbounded thread per connection a
# few hundred such clients exhausted the process. A watchdog now ends every
# connection at this deadline whatever it is doing.
REQUEST_DEADLINE_SECONDS = 15.0

# Connections served at once. Round 29 (PY1): ThreadingHTTPServer starts one
# thread per connection with no limit. Past this many, a new connection is
# answered 503 at once and closed, so slow clients cost a bounded number of
# threads and an honest caller is refused quickly rather than hung.
MAX_CONCURRENT_CONNECTIONS = 32

# Browser origins allowed to POST. Round 29 (PY2): the service has no secret,
# so any web page the operator visited could POST to it (and, by DNS
# rebinding, read the answer). Requests carrying an Origin header are
# refused unless the origin is listed here (comma-separated, exact match).
ALLOWED_ORIGINS_ENV = "GRAPHITE_AI_LAYER_ALLOWED_ORIGINS"

_LOOPBACK_HOST_NAMES = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})

# Where --serve binds unless GRAPHITE_AI_LAYER_HOST says otherwise. Round 19
# (F-19-C5): it bound 0.0.0.0, putting an unauthenticated service whose answer
# feeds the bridge's transfer construction on every interface of the host.
DEFAULT_BIND_HOST = "127.0.0.1"
BIND_HOST_ENV = "GRAPHITE_AI_LAYER_HOST"


def allowed_origins(environ=None) -> frozenset:
    env = os.environ if environ is None else environ
    raw = env.get(ALLOWED_ORIGINS_ENV) or ""
    return frozenset(o.strip().rstrip("/") for o in raw.split(",") if o.strip())


def _is_loopback_name(host: str) -> bool:
    """`host` is a loopback address or the name localhost (no port)."""
    h = host.strip().lower()
    if h in _LOOPBACK_HOST_NAMES:
        return True
    m = re.fullmatch(r"127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})", h)
    return bool(m) and all(int(o) <= 255 for o in m.groups())


def _host_without_port(value: str) -> str:
    v = value.strip()
    if v.startswith("["):  # [::1]:8081
        return v[: v.find("]") + 1] if "]" in v else v
    return v.rsplit(":", 1)[0] if v.count(":") == 1 else v


def resolve_bind_host(environ=None) -> str:
    """The address to bind: loopback, unless the operator explicitly set
    GRAPHITE_AI_LAYER_HOST (e.g. 0.0.0.0 inside a container whose port is
    published only to a private network)."""
    env = os.environ if environ is None else environ
    value = (env.get(BIND_HOST_ENV) or "").strip()
    return value or DEFAULT_BIND_HOST


class IntentParserHandler(BaseHTTPRequestHandler):
    """HTTP handler for intent labeling requests."""

    # StreamRequestHandler applies this to the socket in setup(): every read —
    # the request line, the headers, the body — gives up after this long
    # instead of blocking its thread indefinitely.
    timeout = REQUEST_TIMEOUT_SECONDS
    # The whole request, whatever the reads are doing (Round 29, PY1).
    deadline = REQUEST_DEADLINE_SECONDS

    def setup(self):
        super().setup()
        self._deadline_hit = False
        self._watchdog = threading.Timer(self.deadline, self._expire)
        self._watchdog.daemon = True
        self._watchdog.start()

    def _expire(self):
        """The deadline passed: end every read on this connection now. Reads
        see end-of-stream; the response (a 408) can still be written."""
        self._deadline_hit = True
        try:
            self.connection.shutdown(socket.SHUT_RD)
        except OSError:
            pass

    def finish(self):
        self._watchdog.cancel()
        super().finish()

    def _read_bounded_body(self) -> Optional[bytes]:
        """Read the request body with a hard size cap and robust
        Content-Length parsing. On failure return None and leave the status
        to answer in `self._body_error`: 413 when the declared length is over
        the cap, 400 when Content-Length is not a non-negative integer or the
        body is shorter than declared, 408 when the client went quiet or the
        request outlived its deadline. Never raises, never trusts the header.

        Round 29 (audit 2026-10-20, PY4): every failure but the timeout used
        to answer 413, so a malformed request was reported as "too large".
        """
        raw = self.headers.get("Content-Length", "0")
        try:
            length = int(str(raw).strip())
        except ValueError:
            self._body_error = (400, "Content-Length is not an integer")
            return None
        if length < 0:
            self._body_error = (400, "Content-Length is negative")
            return None
        if length > MAX_BODY_BYTES:
            self._body_error = (413, f"request body over {MAX_BODY_BYTES} bytes")
            return None
        try:
            body = self.rfile.read(length)
        except (TimeoutError, OSError):
            # The client declared more than it sent and then went quiet.
            # Round 19 (F-19-C5): this used to block the server's only thread.
            self._body_error = (408, "request body not received in time")
            self.close_connection = True
            return None
        if len(body) != length:
            self.close_connection = True
            if getattr(self, "_deadline_hit", False):
                self._body_error = (408, "request not completed in time")
            else:
                # Fewer bytes than declared, then EOF: not the request it claimed.
                self._body_error = (400, "request body shorter than its Content-Length")
            return None
        return body

    def _refusal_for_headers(self) -> Optional[Tuple[int, str]]:
        """Round 29 (audit 2026-10-20, PY2): who may ask. The service has no
        secret, so a web page could POST to it; and by DNS rebinding (a name
        the attacker controls, re-pointed at 127.0.0.1) read the answer too.
          * an Origin header means a browser: refused unless the origin is
            listed in GRAPHITE_AI_LAYER_ALLOWED_ORIGINS;
          * bound to loopback, the Host header must name loopback — a
            rebinding page's requests carry the attacker's host name.
        """
        origin = self.headers.get("Origin")
        if origin is not None and origin.strip().rstrip("/") not in allowed_origins():
            return (403, f"browser origin {origin!r} is not allowed (set {ALLOWED_ORIGINS_ENV})")
        bound = str(self.server.server_address[0]) if hasattr(self, "server") else ""
        host = self.headers.get("Host")
        if _is_loopback_name(bound) and host is not None and not _is_loopback_name(_host_without_port(host)):
            return (403, f"Host {host!r} does not name this loopback service")
        return None

    def _send_json(self, status: int, payload: Dict[str, Any], close: bool = False) -> None:
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            if close:
                self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(json.dumps(payload).encode())
        except OSError:
            pass  # the client is gone; nothing to tell it

    def do_POST(self):
        refusal = self._refusal_for_headers()
        if refusal is not None:
            self.close_connection = True
            self._send_json(refusal[0], {"error": refusal[1]}, close=True)
            return

        # The declared length is judged before the media type, so an
        # oversized body is refused from its header alone.
        body = self._read_bounded_body()
        if body is None:
            status, message = getattr(self, "_body_error", (400, "malformed request body"))
            self._send_json(status, {"error": message}, close=True)
            return

        # Round 29 (PY2): JSON only. A browser can send text/plain or a form
        # cross-origin without a preflight; it cannot send application/json.
        ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if ctype != "application/json":
            self._send_json(415, {"error": "Content-Type must be application/json"}, close=True)
            return

        try:
            request = json.loads(body.decode("utf-8"))
            if not isinstance(request, dict) or "text" not in request:
                raise ValueError("request must be a JSON object with a 'text' field")
            result = parse_intent(request.get("text", ""))
        except Exception as e:
            self._send_json(400, {"error": str(e)})
            return
        self._send_json(200, result)

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


class IntentParserServer(ThreadingHTTPServer):
    """One thread per connection, so a slow client costs its own thread and
    nobody else's (Round 19, F-19-C5) — and at most MAX_CONCURRENT_CONNECTIONS
    of them (Round 29, PY1). Daemon threads: a stuck connection never keeps
    the process alive at shutdown."""

    daemon_threads = True
    max_connections = MAX_CONCURRENT_CONNECTIONS

    def server_activate(self):
        super().server_activate()
        self._slots = threading.BoundedSemaphore(self.max_connections)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self._refuse_busy(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def _refuse_busy(self, request):
        """Answer 503 on the accept thread without reading anything, then
        close. The send is bounded so a client that never reads cannot hold
        the accept loop."""
        body = b'{"error": "too many connections; retry shortly"}'
        try:
            request.settimeout(1.0)
            request.sendall(
                b"HTTP/1.0 503 Service Unavailable\r\nContent-Type: application/json\r\n"
                b"Retry-After: 1\r\nConnection: close\r\n"
                + f"Content-Length: {len(body)}\r\n\r\n".encode() + body
            )
        except OSError:
            pass
        self.shutdown_request(request)


def make_server(host: str, port: int) -> IntentParserServer:
    return IntentParserServer((host, port), IntentParserHandler)


def main():
    parser = argparse.ArgumentParser(description="Graphite AI Advisory Intent Labeler")
    parser.add_argument("--serve", action="store_true",
                        help="Run as HTTP server on 127.0.0.1:8081 (GRAPHITE_AI_LAYER_HOST overrides the bind)")
    parser.add_argument("--port", type=int, default=8081, help="Port for HTTP server")
    parser.add_argument("--bench", type=int, metavar="N", help="Run N-parse micro-benchmark")
    parser.add_argument("text", nargs="?", help="Intent text to label")

    args = parser.parse_args()

    if args.bench:
        _benchmark(args.bench)
    elif args.serve:
        host = resolve_bind_host()
        server = make_server(host, args.port)
        print(f"Graphite AI Layer running on {host}:{args.port}")
        if host != DEFAULT_BIND_HOST:
            print(f"WARNING: bound to {host} via {BIND_HOST_ENV}; this service is unauthenticated")
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
