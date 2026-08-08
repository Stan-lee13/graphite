#!/usr/bin/env python3
"""Tests for the Graphite AI Layer intent parser.

Includes a cross-check test that verifies all manifest program IDs are valid
base58 and that the AI layer's canonical intent→program suggestions are backed
by a real manifest, covering all 20 manifests.
"""

import sys
import os
import json
import glob

sys.path.insert(0, os.path.dirname(__file__))

from intent_parser import parse_intent, IntentParserHandler


def _bounded_body(cl_value):
    """A minimal stand-in for the handler's request object."""
    class Req:
        def __init__(self):
            self.headers = {"Content-Length": cl_value}
            self.rfile = None
    return Req()


def test_bounded_body_rejects_oversized_and_malformed_content_length():
    # Oversized claims must be rejected outright (no unbounded rfile read).
    assert IntentParserHandler._read_bounded_body(_bounded_body("999999999")) is None
    # Non-numeric Content-Length must be rejected, not raise ValueError.
    assert IntentParserHandler._read_bounded_body(_bounded_body("abc")) is None
    # Negative lengths are malformed.
    assert IntentParserHandler._read_bounded_body(_bounded_body("-1")) is None
    print("✓ test_bounded_body_rejects_oversized_and_malformed_content_length passed")


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
    """Verify all manifest program IDs are valid base58, the manifest set is
    exactly what the registry ships, and the AI layer's canonical intent→program
    suggestions are backed by a real manifest (no fabricated IDs).

    The set is explicit so additions AND removals both fail loudly; the
    cross-check compares against the GROUP of manifests for each intent rather
    than a single canonical file (Jupiter is the AI layer's canonical swap, so
    the suggested ID legitimately differs from Raydium/Orca/Meteora).
    """
    manifest_dir = os.path.join(os.path.dirname(__file__), "..", "graphite-core", "protocols")

    # Map of manifest filename -> AI-layer intent type (if applicable). New
    # protocols without an AI-layer intent (Pump.fun, Jupiter DCA, Wormhole,
    # Metaplex) map to None — the AI layer has no intent type for them yet.
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
        "memo-program.json": None,         # memo v4.0.0 (upgradeable), no direct intent
        "legacy-memo-program.json": None,  # legacy memo (Memo1Uhk), no direct intent
        "spl-memo-program.json": None,     # classic SPL memo (MemoSq4gq, restored C16), no direct intent
"ata-program.json": None,           # ATA creation, no AI intent
"compute-budget.json": None,        # tx-level settings, no AI intent
"bpf-loader.json": None,            # program deployment, no AI intent
"bpf-loader-upgradeable.json": None,# program deployment/upgrade, no AI intent
        "pump-fun.json": None,      # bonding-curve mint/buy/sell, no AI intent
        "jupiter-dca.json": None,   # escrow scheduling, no AI intent
        "wormhole-core.json": None, # bridging, no AI intent
        "metaplex-token-metadata.json": None,  # NFT metadata, no AI intent
    }
    expected_manifests = set(manifest_to_intent.keys())
    assert len(expected_manifests) == 20, f"expected 20 manifests, map has {len(expected_manifests)}"

    all_manifests = sorted(glob.glob(os.path.join(manifest_dir, "*.json")))
    # verified_program_ids.json is the ID registry, not a protocol manifest.
    all_manifests = [p for p in all_manifests if os.path.basename(p) != "verified_program_ids.json"]
    found = {os.path.basename(p) for p in all_manifests}
    assert found == expected_manifests, (
        f"manifest set drift: missing={sorted(expected_manifests - found)} "
        f"unexpected={sorted(found - expected_manifests)}"
    )

    # Single source of truth: the verified program-ID registry. Every manifest
    # ID must be in the registry AND every registry ID must have a manifest
    # (bidirectional) — the systematic guard against the memo class of
    # fabricated/removed/duplicated identifiers (C1/C10/C15). The registry
    # itself is on-chain verified (scripts/live_revalidate.py reproduces the
    # check), and the Rust blessed-set test anchors the canonical core IDs.
    registry_path = os.path.join(manifest_dir, "verified_program_ids.json")
    with open(registry_path) as f:
        registry = json.load(f)
    verified_ids = {p["program_id"]: p["name"] for p in registry["programs"]}
    manifest_ids = set()
    for manifest_path in all_manifests:
        with open(manifest_path) as f:
            manifest = json.load(f)
        manifest_ids.add(manifest["protocol"]["program_id"])
    assert manifest_ids == set(verified_ids), (
        f"manifest↔registry drift: in-manifests-not-registry="
        f"{sorted(manifest_ids - set(verified_ids))} "
        f"in-registry-not-manifests={sorted(set(verified_ids) - manifest_ids)}"
    )

    # intent -> set of manifest program IDs that support it
    intent_to_ids = {}
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

        intent_type = manifest_to_intent[filename]
        if intent_type:
            intent_to_ids.setdefault(intent_type, set()).add(program_id)

    # No duplicate program IDs across manifests (the memo pair has distinct
    # on-chain-verified IDs; any true duplicate would indicate a pin error).
    seen = {}
    for manifest_path in all_manifests:
        filename = os.path.basename(manifest_path)
        with open(manifest_path) as f:
            manifest = json.load(f)
        pid = manifest["protocol"]["program_id"]
        if pid in seen:
            raise AssertionError(f"duplicate program_id {pid} in {seen[pid]} and {filename}")
        seen[pid] = filename

    # Cross-check: the AI layer's canonical suggestion for each intent must be
    # one of the manifests that actually declares that intent (group check).
    from intent_parser import PROGRAM_IDS
    for intent_type, manifest_ids in intent_to_ids.items():
        suggested = PROGRAM_IDS.get(intent_type)
        assert suggested in manifest_ids, (
            f"AI layer suggests {suggested} for '{intent_type}' but no manifest "
            f"among {sorted(manifest_ids)} declares it"
        )

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
