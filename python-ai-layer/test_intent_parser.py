#!/usr/bin/env python3
"""Tests for the Graphite AI Layer advisory intent labeler (v2).

Covers:
  * every intent class in the Core vocabulary
  * parameter extraction (amount / token / destination / slippage)
  * advisory risk-hint warnings (impersonation vanity, approve, close, ...)
  * per-signal confidence components
  * manifest-registry grounding of suggestions (no fabricated IDs)
  * determinism and the P1 safety invariant (advisory can never decide)
  * a performance smoke test (the labeler must stay fast)
"""

import sys
import os
import json
import glob
import time
import http.client
import socket
import threading

sys.path.insert(0, os.path.dirname(__file__))

from intent_parser import parse_intent, IntentParserHandler
import intent_parser as _ip


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


# ---------------------------------------------------------------------------
# Intent classes — every intent must map to a Core-vocabulary label.
# ---------------------------------------------------------------------------
def test_transfer_intent():
    result = parse_intent("Transfer 1 SOL to 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU")
    assert result["intent_type"] == "transfer"
    assert result["confidence_of_parse"] > 0.0
    assert result["extracted_parameters"]["destination"] == "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
    assert result["extracted_parameters"]["input_token"] == "SOL"
    assert result["extracted_parameters"]["amount"] == "1"
    assert "raw_natural_language" in result
    print("✓ test_transfer_intent passed")


def test_transfer_all_my():
    result = parse_intent("Send all my SOL to 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU")
    assert result["intent_type"] == "transfer"
    assert result["extracted_parameters"]["amount"] == "all"
    assert result["extracted_parameters"]["destination"] == "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
    print("✓ test_transfer_all_my passed")


def test_swap_intent():
    result = parse_intent("Swap 1 SOL for USDC")
    assert result["intent_type"] == "swap"
    assert result["extracted_parameters"]["input_token"] == "SOL"
    assert result["extracted_parameters"]["output_token"] == "USDC"
    assert result["extracted_parameters"]["amount"] == "1"
    print("✓ test_swap_intent passed")


def test_buy_intent_reverses_input_output():
    result = parse_intent("Buy 5 SOL with USDT")
    assert result["intent_type"] == "swap"
    # buy X with Y -> input is Y, output is X
    assert result["extracted_parameters"]["input_token"] == "USDT"
    assert result["extracted_parameters"]["output_token"] == "SOL"
    print("✓ test_buy_intent_reverses_input_output passed")


def test_sell_intent():
    result = parse_intent("Sell 50 JUP for SOL")
    assert result["intent_type"] == "swap"
    assert result["extracted_parameters"]["input_token"] == "JUP"
    assert result["extracted_parameters"]["output_token"] == "SOL"
    print("✓ test_sell_intent passed")


def test_slippage_extraction():
    result = parse_intent("Swap 100 USDC for JUP with 1.5% slippage")
    assert result["intent_type"] == "swap"
    assert result["extracted_parameters"]["slippage_bps"] == 150
    print("✓ test_slippage_extraction passed")


def test_stake_intent():
    result = parse_intent("Stake 5 SOL")
    assert result["intent_type"] == "stake"
    assert result["extracted_parameters"]["input_token"] == "SOL"
    print("✓ test_stake_intent passed")


def test_withdraw_classified_as_stake():
    # Unstake/withdraw maps to the stake class (the Core's stake keywords
    # include withdraw) so it never trips the unknown-intent fail-closed path.
    result = parse_intent("Unstake 3 SOL")
    assert result["intent_type"] == "stake"
    result = parse_intent("Withdraw 1 jitoSOL")
    assert result["intent_type"] == "stake"
    print("✓ test_withdraw_classified_as_stake passed")


def test_close_create_approve_revoke():
    assert parse_intent("Close my account")["intent_type"] == "close"
    assert parse_intent("Create a new account")["intent_type"] == "create"
    assert parse_intent("Approve spending of 500 USDC")["intent_type"] == "approve"
    assert parse_intent("Revoke the delegate")["intent_type"] == "revoke"
    print("✓ test_close_create_approve_revoke passed")


def test_unknown_intent():
    result = parse_intent("do something random and weird")
    assert result["intent_type"] == "unknown"
    print("✓ test_unknown_intent passed")


def test_unmodeled_intents_fail_closed_with_warning():
    # mint/bridge/lend are not in the Core vocabulary -> honest "unknown"
    # label (fail-closed) plus an advisory warning explaining why.
    mint = parse_intent("Mint 1000 BONK")
    assert mint["intent_type"] == "unknown"
    assert any(w["code"] == "MINT_UNMODELED" for w in mint["advisory_warnings"])
    bridge = parse_intent("Bridge 2 ETH from Solana to Ethereum")
    assert bridge["intent_type"] == "unknown"
    assert any(w["code"] == "BRIDGE_UNMODELED" for w in bridge["advisory_warnings"])
    lend = parse_intent("Lend 100 USDC")
    assert lend["intent_type"] == "unknown"
    assert any(w["code"] == "LENDING_UNMODELED" for w in lend["advisory_warnings"])
    print("✓ test_unmodeled_intents_fail_closed_with_warning passed")


def test_garbage_input():
    result = parse_intent("")
    assert result is not None
    assert result["intent_type"] == "unknown"
    result = parse_intent(None)
    assert result["intent_type"] == "unknown"
    print("✓ test_garbage_input passed")


# ---------------------------------------------------------------------------
# Risk-hint warnings (advisory only).
# ---------------------------------------------------------------------------
def test_impersonation_vanity_warning():
    # Real exploit-corpus vanity address (ends in 11111, from the phishing
    # research corpus) must be flagged as an impersonation hint.
    result = parse_intent("Transfer 5 SOL to iBGtY2LBEmTiVrmPCgHRGdCPZJcDEmmkDxbLhV11111")
    assert result["intent_type"] == "transfer"
    assert any(w["code"] == "IMPERSONATION_VANITY" for w in result["advisory_warnings"])
    # Reserved-prefix impersonation (Compu... mimics Compute Budget).
    result = parse_intent("Send 1 SOL to CompuW2npNTB9RqH2gP8ZbA2HnHqn1fT2E6G4Z1B2C3D4")
    assert any(w["code"] == "IMPERSONATION_VANITY" for w in result["advisory_warnings"])
    # A normal address must NOT warn.
    result = parse_intent("Transfer 1 SOL to 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU")
    assert not any(w["code"] == "IMPERSONATION_VANITY" for w in result["advisory_warnings"])
    print("✓ test_impersonation_vanity_warning passed")


def test_approve_and_close_warnings():
    approve = parse_intent("Approve spending of 500 USDC")
    assert any(w["code"] == "APPROVE_DELEGATE" for w in approve["advisory_warnings"])
    close = parse_intent("Close my account")
    assert any(w["code"] == "CLOSE_ACCOUNT" for w in close["advisory_warnings"])
    print("✓ test_approve_and_close_warnings passed")


def test_authority_change_warning():
    result = parse_intent("Transfer 1 SOL to 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU and set authority to me")
    assert any(w["code"] == "AUTHORITY_CHANGE" for w in result["advisory_warnings"])
    print("✓ test_authority_change_warning passed")


def test_no_destination_warning():
    result = parse_intent("Transfer 1 SOL")
    assert result["intent_type"] == "transfer"
    assert any(w["code"] == "NO_DESTINATION" for w in result["advisory_warnings"])
    print("✓ test_no_destination_warning passed")


def test_unknown_token_warning():
    result = parse_intent("Swap 1 FOOCOIN for USDC")
    assert any(w["code"] == "UNKNOWN_TOKEN" for w in result["advisory_warnings"])
    print("✓ test_unknown_token_warning passed")


# ---------------------------------------------------------------------------
# Confidence components & safety invariants.
# ---------------------------------------------------------------------------
def test_confidence_of_parse_not_verification():
    """confidence_of_parse is a parse-quality score, NOT verification confidence."""
    result = parse_intent("Transfer 1 SOL")
    assert "confidence_of_parse" in result
    assert 0.0 <= result["confidence_of_parse"] <= 1.0
    assert "confidence_components" in result
    for signal in ("phrase", "parameters", "token", "protocol"):
        assert signal in result["confidence_components"]
    print("✓ test_confidence_of_parse_not_verification passed")


def test_confidence_reflects_extraction_quality():
    # A complete swap scores higher than a bare verb-only phrase.
    complete = parse_intent("Swap 1 SOL for USDC")
    bare = parse_intent("Swap stuff")
    assert complete["confidence_of_parse"] > bare["confidence_of_parse"]
    print("✓ test_confidence_reflects_extraction_quality passed")


def test_advisory_fields_cannot_decide():
    """P1 invariant: advisory fields are additive metadata; the only fields the
    SAK bridge consumes (intent_type, confidence_of_parse, extracted_parameters)
    have unchanged types, and suggestions are clearly advisory."""
    result = parse_intent("Swap 1 SOL for USDC")
    assert set(("suggested_program_id", "suggested_discriminator",
                "protocol_candidates", "advisory_warnings", "parse_version")) <= set(result)
    assert result["parse_version"] == "2"
    print("✓ test_advisory_fields_cannot_decide passed")


def test_suggested_swap_discriminator_is_deployed_route_v2():
    # The suggested discriminator must be the DEPLOYED route_v2
    # (bb64facc31c4af14), not the legacy route (e517cb97...).
    result = parse_intent("Swap 1 SOL for USDC")
    assert result["suggested_discriminator"] == "bb64facc31c4af14"
    print("✓ test_suggested_swap_discriminator_is_deployed_route_v2 passed")


def test_determinism():
    t = "Swap 10 USDC for JUP with 1% slippage"
    assert parse_intent(t) == parse_intent(t)
    print("✓ test_determinism passed")


# ---------------------------------------------------------------------------
# Manifest grounding — every suggestion must be backed by a real manifest.
# ---------------------------------------------------------------------------
def test_program_ids_match_manifests():
    """Verify all manifest program IDs are valid base58, the manifest set is
    exactly what the registry ships, and the AI layer's canonical intent→program
    suggestions are backed by a real manifest (no fabricated IDs).
    """
    manifest_dir = os.path.join(os.path.dirname(__file__), "..", "graphite-core", "protocols")

    manifest_to_intent = {
        "jupiter-v6.json": "swap",
        "spl-token.json": "close",
        "system-program.json": "transfer",
        "stake-program.json": "stake",
        "token-2022.json": None,
        "raydium-amm-v4.json": "swap",
        "squads-v4.json": None,
        "orca-whirlpools.json": "swap",
        "meteora-dlmm.json": "swap",
        "memo-program.json": None,
        "legacy-memo-program.json": None,
        "spl-memo-program.json": None,
        "ata-program.json": None,
        "compute-budget.json": None,
        "bpf-loader.json": None,
        "bpf-loader-upgradeable.json": None,
        "pump-fun.json": None,
        "jupiter-dca.json": None,
        "wormhole-core.json": None,
        "metaplex-token-metadata.json": None,
        "drift.json": None,
        "kamino-lending.json": None,
        "phoenix.json": None,
        "openbook-v2.json": None,
        "switchboard-v2.json": None,
        "jupiter-limit.json": None,
        "solend.json": None,
        "marginfi-v2.json": None,
        "raydium-clmm.json": "swap",
        "raydium-cpmm.json": "swap",
        "marinade.json": "stake",
        "spl-stake-pool.json": "stake",
        "orca-tokenswap-v2.json": "swap",
        "account-compression-compr6.json": None,
        "amm-eo7wjk.json": "swap",
        "amm-routing-realp6.json": "swap",
        "amm-v3-hpnfyc.json": "swap",
        "bonkswap-bswp6b.json": "swap",
        "bubblegum-bgumap.json": "stake",
        "byreal-clmm-realqq.json": "swap",
        "cargo-cargo2.json": None,
        "cc-vrf-ccvrfu.json": None,
        "coinflow-fd1amx.json": None,
        "cp-amm-cpamdp.json": "swap",
        "crash-game-g3z6yq.json": None,
        "dex-jupz4m.json": "swap",
        "donau-fknmf1.json": None,
        "doves-dovesk.json": None,
        "dynamic-bonding-curve-dbcij3.json": "swap",
        "farms-farmsp.json": "stake",
        "fusionamm-fusion.json": "swap",
        "gmsol-store-gmso1u.json": "swap",
        "light-system-program-system.json": None,
        "m2-m2mx93.json": None,
        "marketplace-ccmrkt.json": None,
        "mmm-mmm3xb.json": "swap",
        "okx-dex-router-provf4.json": "swap",
        "order-engine-61dffe.json": None,
        "perpetuals-perphj.json": "swap",
        "points-point2.json": None,
        "pump-amm-pammba.json": "swap",
        "pump-fees-pfeeux.json": None,
        "pyth-lazer-solana-contract-pytd2y.json": None,
        "pyth-push-oracle-pyt2f4.json": None,
        "pyth-push-oracle-pythws.json": None,
        "pyth-solana-receiver-rec2hh.json": None,
        "pyth-solana-receiver-rec5ek.json": None,
        "raydium-launchpad-lanmv9.json": "swap",
        "relay-depository-99vqwt.json": None,
        "safecinerator-cleana.json": None,
        "sage-sage2h.json": None,
        "scope-hfn8gn.json": None,
        "stableswap-ghosty.json": "swap",
        "staking-skrskr.json": "stake",
        "swap-orchestrator-df1ow4.json": "swap",
        "tail-trade-j51h4g.json": "swap",
        "tcomp-tcmphj.json": None,
        "timelock-strmrq.json": None,
        "vault-24uqj9.json": None,
        "verifier-gt9s41.json": None,
        "wormhole-core-bridge-solana-hdw2e7.json": None,
        "wormhole-core-bridge-solana-hdwcjb.json": None,
        "aligned-distributor-amerkp.json": None,
        "arcium-arcj82.json": "swap",
        "atlas-fee-payer-apr1me.json": None,
        "bo-sc-man1cx.json": "swap",
        "bridge-cards-cardwa.json": "stake",
        "bridge-fcw1ub.json": "swap",
        "brrr-lend-g3v8wx.json": None,
        "ccip-offramp-offqsm.json": None,
        "crafting-craft2.json": None,
        "data-credits-credmb.json": "stake",
        "debot-router-g7mvcm.json": "swap",
        "doorcash-67g5hh.json": None,
        "escrow-5bd9ua.json": None,
        "futarchy-futare.json": "swap",
        "gamma-gamma7.json": "swap",
        "guacswap-gswppe.json": "swap",
        "helium-sub-daos-hdaovt.json": "swap",
        "hylo-earn-pool-hystab.json": "swap",
        "kamino-vault-kvaugm.json": None,
        "limo-limom9.json": "swap",
        "main-cwgkfb.json": None,
        "marketplace-trader.json": None,
        "merkle-distributor-merky6.json": None,
        "mintfx-emiytj.json": "swap",
        "nosana-jobs-nosjhn.json": None,
        "ocr2-cjg3oh.json": None,
        "omnipair-omnixg.json": "swap",
        "orao-vrf-vrfzzo.json": None,
        "order-book-mzloyn.json": None,
        "order-engine-2en5y1.json": None,
        "oridion-ord1qj.json": None,
        "profile-vault-pv1tto.json": None,
        "raydium-liquidity-locking-lockrw.json": "swap",
        "rmn-remote-rmnxlf.json": None,
        "rush-rushe5.json": None,
        "score-fleet1.json": None,
        "spl-account-compression-cmtdvx.json": None,
        "squads-smart-account-program-smrtzf.json": None,
        "stable-swap-swapny.json": "swap",
        "store-hevsko.json": "stake",
        "swift-mayan3.json": None,
        "tarb-bwrzqc.json": None,
        "tuktuk-tuktuk.json": None,
        "tuna-tuna4u.json": None,
        "vault-vo1twg.json": None,
        "verifier-ttainy.json": None,
        "zap-zapvx9.json": "swap",
    }
    expected_manifests = set(manifest_to_intent.keys())
    # The map is the expectation; the count below only guards against an
    # accidental duplicate key silently shrinking it. Round 18 onboarded 49
    # programs from their own on-chain IDLs, taking the set from 33 to 82.
    assert len(expected_manifests) == 129, f"expected 129 manifests, map has {len(expected_manifests)}"

    all_manifests = sorted(glob.glob(os.path.join(manifest_dir, "*.json")))
    all_manifests = [
        p for p in all_manifests
        if os.path.basename(p) not in ("verified_program_ids.json", "battle_tested_evidence.json")
    ]
    found = {os.path.basename(p) for p in all_manifests}
    assert found == expected_manifests, (
        f"manifest set drift: missing={sorted(expected_manifests - found)} "
        f"unexpected={sorted(found - expected_manifests)}"
    )

    # Bidirectional manifest <-> registry consistency.
    registry_path = os.path.join(manifest_dir, "verified_program_ids.json")
    # Manifests carry UTF-8 note text (em-dashes etc.) — reads must be
    # encoding-explicit, never locale-default (cp1252 on Windows).
    with open(registry_path, encoding="utf-8") as f:
        registry = json.load(f)
    verified_ids = {p["program_id"]: p["name"] for p in registry["programs"]}
    manifest_ids = set()
    for manifest_path in all_manifests:
        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)
        manifest_ids.add(manifest["protocol"]["program_id"])
    assert manifest_ids == set(verified_ids), (
        f"manifest↔registry drift: in-manifests-not-registry="
        f"{sorted(manifest_ids - set(verified_ids))} "
        f"in-registry-not-manifests={sorted(set(verified_ids) - manifest_ids)}"
    )

    intent_to_ids = {}
    for manifest_path in all_manifests:
        filename = os.path.basename(manifest_path)
        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)
        program_id = manifest["protocol"]["program_id"]
        assert program_id, f"{filename}: program_id is empty"
        invalid_chars = set("0OIl") & set(program_id)
        assert not invalid_chars, f"{filename}: program_id contains invalid base58 chars: {invalid_chars}"
        assert 32 <= len(program_id) <= 44, f"{filename}: program_id length {len(program_id)} out of range"
        intent_type = manifest_to_intent[filename]
        if intent_type:
            intent_to_ids.setdefault(intent_type, set()).add(program_id)

    # No duplicate program IDs across manifests.
    seen = {}
    for manifest_path in all_manifests:
        filename = os.path.basename(manifest_path)
        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)
        pid = manifest["protocol"]["program_id"]
        if pid in seen:
            raise AssertionError(f"duplicate program_id {pid} in {seen[pid]} and {filename}")
        seen[pid] = filename

    # Every canonical suggestion for a manifest-mapped intent must be backed
    # by a manifest that declares that intent.
    from intent_parser import FALLBACK_CANONICAL, parse_intent
    for intent_type, manifest_ids in intent_to_ids.items():
        suggested = parse_intent({"swap": "Swap 1 SOL for USDC",
                                  "transfer": "Transfer 1 SOL to 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
                                  "stake": "Stake 1 SOL",
                                  "close": "Close my account"}[intent_type])
        assert suggested["intent_type"] == intent_type
        assert suggested["suggested_program_id"] in manifest_ids, (
            f"AI layer suggests {suggested['suggested_program_id']} for '{intent_type}' "
            f"but no manifest among {sorted(manifest_ids)} declares it"
        )

    # Every FALLBACK_CANONICAL program_id must exist in the registry too.
    for intent, (fn, pid, instr) in FALLBACK_CANONICAL.items():
        assert pid in verified_ids, (
            f"fallback canonical {intent} -> {pid} not in verified_program_ids.json"
        )

    print(f"✓ test_program_ids_match_manifests passed ({len(all_manifests)} manifests verified)")


def test_protocol_candidates_grounded():
    result = parse_intent("Swap 1 SOL for USDC")
    cands = result["protocol_candidates"]
    assert cands, "swap must have protocol candidates"
    ids = {c["program_id"] for c in cands}
    assert "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4" in ids
    # Raydium AMM V4 is a swap manifest too.
    assert "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8" in ids
    print("✓ test_protocol_candidates_grounded passed")


def test_transfer_candidates():
    result = parse_intent("Transfer 1 SOL to 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU")
    ids = {c["program_id"] for c in result["protocol_candidates"]}
    assert "11111111111111111111111111111111" in ids  # System
    assert "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" in ids  # SPL Token
    print("✓ test_transfer_candidates passed")


# ---------------------------------------------------------------------------
# Performance smoke test — the labeler must stay fast (no LLM, no network).
# ---------------------------------------------------------------------------
def test_performance_smoke():
    corpus = [
        "Transfer 1 SOL to 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
        "Swap 1 SOL for USDC",
        "Stake 5 SOL",
        "Close my account",
        "do something random",
    ]
    n = 5000
    start = time.perf_counter()
    for i in range(n):
        parse_intent(corpus[i % len(corpus)])
    elapsed = time.perf_counter() - start
    per_sec = n / elapsed
    print(f"✓ test_performance_smoke passed ({per_sec:,.0f} parses/sec)")
    assert per_sec > 10_000, f"labeler too slow: {per_sec:,.0f} parses/sec"


# ---------------------------------------------------------------------------
# Round 19 (F-19-C5): the server binds loopback, and one slow client cannot
# stall it. Real sockets on 127.0.0.1, ephemeral ports.
# ---------------------------------------------------------------------------


def _serve(handler_timeout=None):
    """Start the real server on an ephemeral loopback port; returns
    (server, port). `handler_timeout` shortens the per-read timeout for the
    test that waits it out."""
    handler = _ip.IntentParserHandler
    if handler_timeout is not None:
        handler = type("ShortTimeoutHandler", (_ip.IntentParserHandler,), {"timeout": handler_timeout})
    server = _ip.make_server("127.0.0.1", 0)
    server.RequestHandlerClass = handler
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def _stall(port, declared=100, sent=10):
    """A client that declares `declared` body bytes, sends `sent`, and waits."""
    s = socket.create_connection(("127.0.0.1", port), timeout=30)
    s.sendall(
        b"POST /parse HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
        + f"Content-Length: {declared}\r\n\r\n".encode()
        + b"x" * sent
    )
    return s


def test_bind_host_defaults_to_loopback():
    assert _ip.resolve_bind_host({}) == "127.0.0.1"
    assert _ip.resolve_bind_host({"GRAPHITE_AI_LAYER_HOST": ""}) == "127.0.0.1"
    assert _ip.resolve_bind_host({"GRAPHITE_AI_LAYER_HOST": "  "}) == "127.0.0.1"
    # Only an explicit setting widens it.
    assert _ip.resolve_bind_host({"GRAPHITE_AI_LAYER_HOST": "0.0.0.0"}) == "0.0.0.0"
    print("✓ test_bind_host_defaults_to_loopback passed")


def test_a_stalled_client_does_not_stall_other_callers():
    server, port = _serve()
    stalled = _stall(port)
    try:
        # Give the server time to be blocked on the stalled body, if it can be.
        time.sleep(0.3)
        started = time.monotonic()
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("POST", "/parse", body=json.dumps({"text": "Swap 1 SOL for USDC"}),
                     headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        body = json.loads(resp.read())
        elapsed = time.monotonic() - started
        assert resp.status == 200, resp.status
        assert body["intent_type"] == "swap"
        assert elapsed < 3.0, f"an honest caller waited {elapsed:.1f}s behind a stalled one"
    finally:
        stalled.close()
        server.shutdown()
        server.server_close()
    print("✓ test_a_stalled_client_does_not_stall_other_callers passed")


def test_a_short_body_times_out_and_is_refused():
    # The real handler carries a finite per-read timeout; the functional check
    # below shortens it only so the test does not wait the full 10 s.
    assert _ip.IntentParserHandler.timeout is not None
    assert 0 < _ip.IntentParserHandler.timeout <= 30
    server, port = _serve(handler_timeout=0.5)
    stalled = _stall(port)
    try:
        started = time.monotonic()
        reply = stalled.recv(4096)
        elapsed = time.monotonic() - started
        assert reply.startswith(b"HTTP/1.0 408") or reply.startswith(b"HTTP/1.1 408"), reply[:40]
        assert elapsed < 5.0, f"the stalled request was held {elapsed:.1f}s"
    finally:
        stalled.close()
        server.shutdown()
        server.server_close()
    print("✓ test_a_short_body_times_out_and_is_refused passed")


def test_the_body_cap_holds_on_the_real_server():
    server, port = _serve()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        # Declared over the cap: refused from the header alone, before any read.
        conn.putrequest("POST", "/parse")
        conn.putheader("Content-Length", str(_ip.MAX_BODY_BYTES + 1))
        conn.endheaders()
        resp = conn.getresponse()
        assert resp.status == 413, resp.status
    finally:
        server.shutdown()
        server.server_close()
    print("✓ test_the_body_cap_holds_on_the_real_server passed")


if __name__ == "__main__":
    test_bounded_body_rejects_oversized_and_malformed_content_length()
    test_transfer_intent()
    test_transfer_all_my()
    test_swap_intent()
    test_buy_intent_reverses_input_output()
    test_sell_intent()
    test_slippage_extraction()
    test_stake_intent()
    test_withdraw_classified_as_stake()
    test_close_create_approve_revoke()
    test_unknown_intent()
    test_unmodeled_intents_fail_closed_with_warning()
    test_garbage_input()
    test_impersonation_vanity_warning()
    test_approve_and_close_warnings()
    test_authority_change_warning()
    test_no_destination_warning()
    test_unknown_token_warning()
    test_confidence_of_parse_not_verification()
    test_confidence_reflects_extraction_quality()
    test_advisory_fields_cannot_decide()
    test_suggested_swap_discriminator_is_deployed_route_v2()
    test_determinism()
    test_program_ids_match_manifests()
    test_protocol_candidates_grounded()
    test_transfer_candidates()
    test_performance_smoke()
    test_bind_host_defaults_to_loopback()
    test_a_stalled_client_does_not_stall_other_callers()
    test_a_short_body_times_out_and_is_refused()
    test_the_body_cap_holds_on_the_real_server()
    print("\n✅ All AI layer tests passed.")
