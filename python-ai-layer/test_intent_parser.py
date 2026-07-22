#!/usr/bin/env python3
"""Tests for the Graphite AI Layer intent parser."""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from intent_parser import parse_intent


def test_transfer_intent():
    result = parse_intent("Transfer 1 SOL to my friend")
    assert result["intent_type"] == "transfer"
    assert result["confidence_of_parse"] > 0.0
    assert "raw_natural_language" in result
    print("✓ test_transfer_intent passed")


def test_swap_intent():
    result = parse_intent("Swap 1 SOL for USDC")
    assert result["intent_type"] == "swap"
    assert result["confidence_of_parse"] > 0.0
    print("✓ test_swap_intent passed")


def test_stake_intent():
    result = parse_intent("Stake 5 SOL")
    assert result["intent_type"] == "stake"
    print("✓ test_stake_intent passed")


def test_unknown_intent():
    result = parse_intent("do something random and weird")
    assert result["intent_type"] == "unknown"
    print("✓ test_unknown_intent passed")


def test_garbage_input():
    result = parse_intent("")
    assert result is not None
    assert "intent_type" in result
    print("✓ test_garbage_input passed")


def test_confidence_of_parse_not_verification():
    """Ensure confidence_of_parse is not conflated with verification confidence."""
    result = parse_intent("Transfer 1 SOL")
    assert "confidence_of_parse" in result
    # confidence_of_parse should be 0.0-1.0
    assert 0.0 <= result["confidence_of_parse"] <= 1.0
    print("✓ test_confidence_of_parse_not_verification passed")


if __name__ == "__main__":
    test_transfer_intent()
    test_swap_intent()
    test_stake_intent()
    test_unknown_intent()
    test_garbage_input()
    test_confidence_of_parse_not_verification()
    print("\n✅ All AI layer tests passed.")
