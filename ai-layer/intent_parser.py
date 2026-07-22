"""AI Layer — advisory-only natural language intent parser.

Restored 2026-07-06 (production-readiness sweep): this file existed
previously but was deleted when `reference/` was restructured into a real
Cargo crate (Rust's `src/`/`tests/` convention doesn't apply to this file,
since it's deliberately a SEPARATE PROCESS in a SEPARATE LANGUAGE — see the
language-split decision in `../memory/decisions-log.md`, 2026-07-06 entry,
and `../ARCHITECTURE.md` section 3.18). It lives here at the top level of
`reference/`, a sibling to `Cargo.toml`, not inside `src/` — it is not, and
must never become, part of the Rust crate's module graph.

ARCHITECTURE.md section 5 (AI Layer) and Constitution P1 govern this file:
AI proposes, deterministic code verifies. Nothing in this module is ever
trusted as ground truth by Core (the Rust crate in this repo, or any real
Graphite implementation). Its only output type, `ProposedIntent`, carries a
`confidence_of_parse` field that is explicitly NOT the same thing as the
Rust crate's `ConfidenceResult` (see `confidence_engine.rs`) — one measures
"how confident is the AI Layer that it understood the user," the other
measures "how confident is the deterministic verification pipeline that
this transaction is safe." Conflating these two numbers anywhere (in code,
in logs, in a UI) is a Constitution P1 violation regardless of how the
conflation is framed.

Known simplifications (tracked in ../memory/known-gaps-log.md):
- Pattern matching here is regex/keyword-based, not a real LLM call — this
  is a reference SHAPE demonstrating the parser's contract (inputs, outputs,
  advisory-only framing, garbage-input handling), not a production NLU
  implementation. A real implementation would call an actual language model
  and would need addtional handling for streaming responses, timeouts, and
  model-specific prompt formatting — all out of scope for this reference.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class IntentAction(str, Enum):
    """Coarse action category the parser believes the user is requesting.

    This is intentionally a small, closed set — anything that doesn't map
    cleanly to one of these is UNKNOWN, never guessed into the nearest
    category. Guessing wrong here is exactly the failure mode the
    garbage-input test (see module docstring and tests below) exists to
    catch.
    """

    SWAP = "swap"
    TRANSFER = "transfer"
    STAKE = "stake"
    UNSTAKE = "unstake"
    UNKNOWN = "unknown"


@dataclass
class ProposedIntent:
    """The AI Layer's advisory output — NEVER a verified, binding intent.

    Every field here is a PROPOSAL for Core's Account Resolution and
    Verification pipeline to independently resolve and verify. Nothing in
    this dataclass short-circuits any layer of the 8-layer verification
    pipeline (Constitution P1, P8) — it is purely an input suggestion.
    """

    action: IntentAction
    source_token_hint: Optional[str] = None
    destination_token_hint: Optional[str] = None
    amount_hint: Optional[str] = None
    # The AI Layer's own confidence in its PARSE of the user's natural
    # language — NOT a verification confidence. See module docstring.
    # Deliberately named differently from Core's `confidence` field
    # (`ConfidenceResult.confidence` in confidence_engine.rs) so the two
    # can never be assigned to each other by an accidental type match in a
    # language (like a dynamically-typed glue script) that wouldn't catch
    # the mistake at compile time the way Rust would.
    confidence_of_parse: float = 0.0
    raw_input: str = ""
    unrecognized_fragments: list[str] = field(default_factory=list)

    def is_advisory_only(self) -> bool:
        """Always true. Exists as a explicit, greppable assertion point —
        any code that calls this and checks for `False` has misunderstood
        this class's entire purpose."""
        return True


# Deliberately simple, explicit patterns — not a catch-all regex — so every
# match is individually reviewable and the "what did NOT match" case (the
# most important case, per the garbage-input test) stays large and honest
# rather than being swallowed by an overly permissive pattern.
_SWAP_PATTERN = re.compile(
    r"\b(swap|sell|exchange|trade)\b.*?\b(?:for|into|to)\b", re.IGNORECASE
)
_TRANSFER_PATTERN = re.compile(r"\b(send|transfer|pay)\b", re.IGNORECASE)
_STAKE_PATTERN = re.compile(r"\bstake\b(?!.*unstake)", re.IGNORECASE)
_UNSTAKE_PATTERN = re.compile(r"\bunstake\b", re.IGNORECASE)

_TOKEN_HINT_PATTERN = re.compile(r"\b([A-Z]{2,10})\b")
_AMOUNT_HINT_PATTERN = re.compile(r"\b(\d+(?:\.\d+)?|all|everything|half)\b", re.IGNORECASE)

# Hard cap on input length before any pattern matching runs.
#
# Found via actually running this module's own test suite (2026-07-06,
# production-readiness sweep) — NOT found by reading the regex source: an
# input like "swap " repeated 10,000 times (no legitimate real request looks
# like this, but nothing stopped a caller from sending it) took 14+ seconds
# to parse, versus ~0.02s for a normal, even much longer, well-formed
# request. `_SWAP_PATTERN`'s `.*?\b(?:for|into|to)\b` lazy-quantifier
# construct re-scans from every "swap" occurrence when no terminating
# keyword is ever found — classic catastrophic-backtracking-adjacent
# behavior for adversarial or degenerate input. No legitimate user request
# to an AI Layer parser is anywhere near this length; capping it is both a
# direct fix for this specific pattern AND a general defense-in-depth
# practice any NLU-adjacent parser should have regardless of which specific
# regex is implicated today.
MAX_INPUT_LENGTH = 500


def parse_intent(raw_input: str) -> ProposedIntent:
    """Parse a natural-language request into a `ProposedIntent`.

    Contract (verified by this module's own test suite below):
    - NEVER raises on malformed, empty, or adversarial input — always
      returns a `ProposedIntent`, with `action=IntentAction.UNKNOWN` and a
      low `confidence_of_parse` when nothing recognizable is found. Raising
      an exception here would push a failure mode into whatever orchestrates
      this AI Layer process that a plain "I don't know" return value handles
      more gracefully.
    - NEVER returns a `confidence_of_parse` of 1.0 for anything containing
      unrecognized fragments — even a confidently-matched action with
      leftover unparsed text should reflect that incompleteness in the score.
    - The returned object's `action` is always one of the small closed set
      in `IntentAction` — never a free-form guess at a token/action not in
      that enum.
    """
    if not raw_input or not raw_input.strip():
        return ProposedIntent(
            action=IntentAction.UNKNOWN,
            confidence_of_parse=0.0,
            raw_input=raw_input,
            unrecognized_fragments=[raw_input] if raw_input else [],
        )

    if len(raw_input) > MAX_INPUT_LENGTH:
        # Reject outright rather than silently truncating — truncation could
        # quietly drop the part of the request that actually mattered (e.g.
        # the destination token), which is worse than an honest "I didn't
        # parse this" signal.
        return ProposedIntent(
            action=IntentAction.UNKNOWN,
            confidence_of_parse=0.0,
            raw_input=raw_input[:MAX_INPUT_LENGTH] + "...(truncated for storage, rejected for parsing)",
            unrecognized_fragments=["input exceeded MAX_INPUT_LENGTH, rejected before pattern matching"],
        )

    text = raw_input.strip()

    action = IntentAction.UNKNOWN
    base_confidence = 0.0

    if _SWAP_PATTERN.search(text):
        action = IntentAction.SWAP
        base_confidence = 0.7
    elif _UNSTAKE_PATTERN.search(text):
        action = IntentAction.UNSTAKE
        base_confidence = 0.75
    elif _STAKE_PATTERN.search(text):
        action = IntentAction.STAKE
        base_confidence = 0.75
    elif _TRANSFER_PATTERN.search(text):
        action = IntentAction.TRANSFER
        base_confidence = 0.65

    token_hints = _TOKEN_HINT_PATTERN.findall(text)
    amount_match = _AMOUNT_HINT_PATTERN.search(text)
    amount_hint = amount_match.group(1) if amount_match else None

    source_hint = token_hints[0] if len(token_hints) >= 1 else None
    destination_hint = token_hints[1] if len(token_hints) >= 2 else None

    # Anything not consumed by a recognized action keyword, a token hint, or
    # an amount hint is tracked as an unrecognized fragment — this is what
    # keeps `confidence_of_parse` honest about partial understanding rather
    # than reporting high confidence just because SOME of the input matched.
    consumed_spans: list[str] = []
    for pattern in (_SWAP_PATTERN, _TRANSFER_PATTERN, _STAKE_PATTERN, _UNSTAKE_PATTERN):
        m = pattern.search(text)
        if m:
            consumed_spans.append(m.group(0))
    remainder = text
    for span in consumed_spans + token_hints + ([amount_hint] if amount_hint else []):
        remainder = remainder.replace(span, "", 1)
    unrecognized = [frag for frag in re.split(r"\s+", remainder.strip()) if frag]

    # Confidence penalty for leftover, unrecognized fragments — never let a
    # partially-understood request report the same confidence as a fully
    # understood one.
    if action == IntentAction.UNKNOWN:
        confidence = 0.0
    else:
        penalty = min(0.4, 0.05 * len(unrecognized))
        confidence = max(0.1, base_confidence - penalty)

    return ProposedIntent(
        action=action,
        source_token_hint=source_hint,
        destination_token_hint=destination_hint,
        amount_hint=amount_hint,
        confidence_of_parse=round(confidence, 2),
        raw_input=raw_input,
        unrecognized_fragments=unrecognized,
    )


if __name__ == "__main__":
    import sys

    for line in sys.stdin:
        result = parse_intent(line)
        print(result)
