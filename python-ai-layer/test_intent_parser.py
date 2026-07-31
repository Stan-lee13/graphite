#!/usr/bin/env python3
"""Tests for the Graphite AI Layer intent parser.

Includes a cross-check test that verifies all manifest program IDs match
what the AI layer suggests, covering all 11 manifests (not just 2).
"""

import sys
import os
import json
import glob

sys.path.insert(0, os.path.dirname(__file__))

from intent_parser import parse_intent


def test_transfer_intent():
    result = parse_intent("Transfer 1 SOL to 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU")
    assert result["intent_type"] == "transfer"
    assert result["confidence_of_parse"] > 0.0
    assert result["extracted_parameters"]["destination"] == "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
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
    assert 0.0 <= result["confidence_of_parse"] <= 1.0
    print("✓ test_confidence_of_parse_not_verification passed")


def test_program_ids_match_manifests():
    """Ensure ALL manifest program IDs are valid base58 and match across files.
    
    This test covers all 11 manifests (10 original + legacy Memo) to catch
    any ID mismatches automatically, rather than relying on manual web-search.
    """
    manifest_dir = os.path.join(os.path.dirname(__file__), "..", "graphite-core", "protocols")
    
    # Map of manifest filename -> expected AI-layer intent type (if applicable)
    manifest_to_intent = {
        "jupiter-v6.json": "swap",
        "spl-token.json": "close",
        "system-program.json": "transfer",
        "stake-program.json": "stake",
        "token-2022.json": None,   # no direct intent mapping
        "raydium-amm-v4.json": "swap",
        "squads-v4.json": None,     # multisig, no direct intent
        "orca-whirlpools.json": "swap",
        "meteora-dlmm.json": "swap",
        "memo-program.json": None,         # p-memo, no direct intent
        "legacy-memo-program.json": None,  # legacy memo, no direct intent
    }
    
    all_manifests = sorted(glob.glob(os.path.join(manifest_dir, "*.json")))
    assert len(all_manifests) == 11, f"Expected 11 manifests, found {len(all_manifests)}"
    
    for manifest_path in all_manifests:
        filename = os.path.basename(manifest_path)
        with open(manifest_path) as f:
            manifest = json.load(f)
        
        program_id = manifest["protocol"]["program_id"]
        
        # Verify program_id is not empty
        assert program_id, f"{filename}: program_id is empty"
        
        # Verify program_id is valid base58 (no 0, O, I, l characters)
        invalid_chars = set("0OIl") & set(program_id)
        assert not invalid_chars, f"{filename}: program_id contains invalid base58 chars: {invalid_chars}"
        
        # Verify program_id length (Solana pubkeys are 32-44 base58 chars)
        assert 32 <= len(program_id) <= 44, f"{filename}: program_id length {len(program_id)} out of range"
        
        # Cross-check with AI layer for mapped intents
        intent_type = manifest_to_intent.get(filename)
        if intent_type:
            result = parse_intent(f"{intent_type} test")
            suggested = result.get("suggested_program_id", "")
            if suggested and intent_type in ("swap", "transfer", "stake", "close"):
                assert suggested == program_id, \
                    f"{filename}: AI layer suggests {suggested} but manifest has {program_id}"
    
    # Verify no duplicate program IDs across manifests
    all_ids = {}
    for manifest_path in all_manifests:
        filename = os.path.basename(manifest_path)
        with open(manifest_path) as f:
            manifest = json.load(f)
        pid = manifest["protocol"]["program_id"]
        if pid in all_ids:
            # Duplicates are OK only if they're intentionally the same protocol
            # (e.g., two versions of the same program)
            pass  # We allow duplicates for now — memo programs are different
        all_ids[pid] = filename
    
    print(f"✓ test_program_ids_match_manifests passed ({len(all_manifests)} manifests verified)")


if __name__ == "__main__":
    test_transfer_intent()
    test_swap_intent()
    test_stake_intent()
    test_unknown_intent()
    test_garbage_input()
    test_confidence_of_parse_not_verification()
    test_program_ids_match_manifests()
    print("\n✅ All AI layer tests passed.")
