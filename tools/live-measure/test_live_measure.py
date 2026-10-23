"""The live-measurement scripts' logic, without a network (Round 32, P3).

    python3 -m pytest -q -p no:cacheprovider tools/live-measure/test_live_measure.py
"""
import base64
import copy
import json
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import live_devnet  # noqa: E402
import live_mainnet as lm  # noqa: E402
import solrpc  # noqa: E402
import wire  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "examples", "decisions")


def fixture(name):
    with open(os.path.join(FIXTURES, f"{name}.json"), encoding="utf-8") as f:
        return json.load(f)


ENTRY = {"row": 7, "slot": 1, "program_id": "11111111111111111111111111111111", "manifest_found": True, "failed_on_chain": False}


# ── solrpc ───────────────────────────────────────────────────────────────────


def test_base58_round_trips_and_keeps_leading_zeros():
    for raw in [b"", b"\0\0\x01", bytes(range(32)), b"\xff" * 64]:
        assert solrpc.b58decode(solrpc.b58encode(raw)) == raw
    assert solrpc.b58encode(b"\0" * 32) == "1" * 32


def test_first_signature_reads_the_first_slot():
    sig = bytes(range(64))
    tx = bytes([1]) + sig + b"message"
    assert solrpc.first_signature(tx) == solrpc.b58encode(sig)
    with pytest.raises(ValueError):
        solrpc.first_signature(bytes([0]) + b"message")
    with pytest.raises(ValueError):
        solrpc.first_signature(bytes([1]) + b"short")


def test_shortvec_multi_byte():
    assert solrpc.shortvec(bytes([0x80, 0x01])) == (128, 2)
    with pytest.raises(ValueError):
        solrpc.shortvec(bytes([0x80, 0x80, 0x80, 0x01]))


def test_a_rate_limit_backs_off_then_reports_rather_than_retrying_forever(monkeypatch):
    calls, sleeps = [], []

    class Resp:
        def __init__(self, doc):
            self.doc = doc

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return json.dumps(self.doc).encode()

    def fake_urlopen(req, timeout):
        calls.append(req)
        return Resp({"jsonrpc": "2.0", "id": 1, "error": {"code": 429, "message": "Too many requests"}})

    monkeypatch.setattr(solrpc.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(solrpc.RateLimited):
        solrpc.call("http://x", "getBlock", [], attempts=4, base_pause=1.0, sleep=sleeps.append)
    assert len(calls) == 4
    assert sleeps == [1.0, 2.0, 4.0]


def test_host_of_never_returns_the_key():
    assert solrpc.host_of("https://rpc.example.com/v2/SECRETKEY?api-key=K") == "rpc.example.com"


# ── select ───────────────────────────────────────────────────────────────────


def test_select_spreads_across_programs():
    lines = [{"row": i, "program_id": "A"} for i in range(10)] + [{"row": 100 + i, "program_id": "B"} for i in range(2)] + [{"row": 200, "program_id": "C"}]
    picked = lm.select(lines, 5)
    assert [e["program_id"] for e in picked] == ["A", "B", "C", "A", "B"]
    assert len(lm.select(lines, 100)) == 13


# ── judging verdicts ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("name", ["executable_approved", "analysis_only", "inconclusive", "blocked"])
def test_the_core_fixtures_are_not_defects(name):
    v = fixture(name)
    assert lm.recomputed_decision(v) == name
    assert lm.defects_for(ENTRY, v) == []


def test_an_executable_verdict_its_own_fields_contradict_is_a_defect():
    v = fixture("analysis_only")
    v["decision"], v["executable"] = "executable_approved", True
    assert any("own fields make it analysis_only" in d for d in lm.defects_for(ENTRY, v))


def test_executable_and_decision_must_agree():
    v = fixture("executable_approved")
    v["executable"] = False
    assert any("contradicts decision" in d for d in lm.defects_for(ENTRY, v))


def test_an_unknown_decision_is_a_defect():
    v = fixture("blocked")
    v["decision"] = "approved"
    assert lm.defects_for(ENTRY, v)


def test_executable_for_an_unmanifested_program_is_a_defect():
    v = fixture("executable_approved")
    v["manifest_found"] = False
    assert any("no manifest" in d for d in lm.defects_for(ENTRY, v))


def test_executable_with_a_failed_or_flagged_l3_is_a_defect():
    v = fixture("executable_approved")
    v2 = copy.deepcopy(v)
    v2["simulation_flagged"] = True
    assert any("L3" in d for d in lm.defects_for(ENTRY, v2))


def test_executable_for_a_transaction_that_failed_on_chain_is_flagged_for_review():
    v = fixture("executable_approved")
    assert any("FAILED on chain" in d for d in lm.defects_for(dict(ENTRY, failed_on_chain=True), v))
    # a refusal of a failed transaction is just a refusal
    assert lm.defects_for(dict(ENTRY, failed_on_chain=True), fixture("blocked")) == []


def test_l3_classes():
    assert lm.l3_class(fixture("blocked")) == "failed: simulation error"
    assert lm.l3_class(fixture("analysis_only")).startswith("inconclusive")
    v = fixture("executable_approved")
    for l in v["layers"]:
        if l["layer"].startswith("L3"):
            l["status"], l["reason"] = "failed", "Compute divergence: 4.2σ from the baseline's anchored band (threshold: 2.00σ)"
    assert lm.l3_class(v) == "failed: outside the anchored band"


def test_rate_limited_verdicts_are_recognised():
    v = fixture("inconclusive")
    v["risk_verdict"]["findings"][0]["reason"] = "simulation failed: HTTP 429 Too Many Requests"
    assert lm.rate_limited(v)
    assert not lm.rate_limited(fixture("executable_approved"))


def test_a_429_inside_an_address_or_hash_is_not_a_rate_limit():
    # Found in the mock dry run: 2 of 40 verdicts were counted as rate-limited
    # because an account address in them contained the digits "429".
    v = fixture("inconclusive")
    v["risk_verdict"]["findings"][0]["reason"] = "account MEViZt7uNtZs4294jujUuMSAxxxVtQQ25SwToLcEckt is not the expected PDA"
    v["transaction_sha256"] = "ab4290" * 10
    assert not lm.rate_limited(v)
    v["layers"][0]["reason"] = "RPC: HTTP 429 from the provider"
    assert lm.rate_limited(v)


# ── replay, end to end against fakes ─────────────────────────────────────────


def fake_core(verdicts, health=None, execution=None):
    calls = []
    it = iter(verdicts)

    def post_fn(url, key, body):
        calls.append((url, body))
        if url.endswith("/verify"):
            v = next(it)
            return (v if isinstance(v, int) else 200), ({} if isinstance(v, int) else v)
        return 200, execution or {"reconciliation": "BlockedButExecuted", "attribution": "chain", "inclusion_assurance": "single_provider", "chain_status": {"Confirmed": {}}}

    def get_fn(url, key=None):
        return health or {"status": "ok", "verification_mode": "executable", "rpc_attached": True}

    return post_fn, get_fn, calls


def selected(n):
    return [{"row": i, "slot": 1, "program_id": f"P{i % 2}", "instruction_name": "x", "manifest_found": True, "failed_on_chain": False, "input": {}} for i in range(n)]


def sample_rows(n):
    tx = bytes([1]) + bytes(range(64)) + b"msg"
    return [{"row": i, "b64": base64.b64encode(tx).decode()} for i in range(n)]


def test_a_clean_run_is_ok_and_reconciles_executed_transactions():
    post_fn, get_fn, calls = fake_core([fixture("blocked"), fixture("analysis_only")] * 2)
    rep = lm.replay(selected(4), sample_rows(4), "http://core", "k", pace=0, l8=2, sleep=lambda s: None, post_fn=post_fn, get_fn=get_fn)
    assert rep["status"] == "OK", rep["defects"]
    assert rep["decisions"] == {"blocked": 2, "analysis_only": 2}
    assert len(rep["l8"]) == 2 and rep["l8"][0]["inclusion_assurance"] == "single_provider"
    assert sum(1 for u, _ in calls if u.endswith("/verify/execution")) == 2


def test_a_5xx_is_a_defect():
    post_fn, get_fn, _ = fake_core([fixture("blocked"), 500])
    rep = lm.replay(selected(2), sample_rows(2), "http://core", "k", pace=0, l8=0, sleep=lambda s: None, post_fn=post_fn, get_fn=get_fn)
    assert rep["status"] == "DEFECTS" and any("500" in d for d in rep["defects"])


def test_a_core_without_an_rpc_is_refused_before_anything_is_measured():
    post_fn, get_fn, calls = fake_core([], health={"verification_mode": "analysis_only", "rpc_attached": False})
    rep = lm.replay(selected(2), sample_rows(2), "http://core", "k", pace=0, l8=0, sleep=lambda s: None, post_fn=post_fn, get_fn=get_fn)
    assert rep["status"] == "DEFECTS" and not calls


def test_mostly_rate_limited_is_inconclusive_not_a_failure():
    limited = fixture("inconclusive")
    limited["risk_verdict"]["findings"][0]["reason"] = "RPC request failed: HTTP 429 Too Many Requests"
    post_fn, get_fn, _ = fake_core([limited] * 4)
    rep = lm.replay(selected(4), sample_rows(4), "http://core", "k", pace=0, l8=0, sleep=lambda s: None, post_fn=post_fn, get_fn=get_fn)
    assert rep["status"] == "INCONCLUSIVE", rep
    assert "INCONCLUSIVE" in lm.markdown(rep)


def test_requests_the_core_refused_are_counted_not_judged():
    post_fn, get_fn, _ = fake_core([422, fixture("blocked")])
    rep = lm.replay(selected(2), sample_rows(2), "http://core", "k", pace=0, l8=0, sleep=lambda s: None, post_fn=post_fn, get_fn=get_fn)
    assert rep["refused_requests"] == {"422": 1} and rep["measured"] == 1


def test_watched_l4_findings_are_printed_row_by_row_with_what_the_chain_did():
    w19 = fixture("blocked")
    for l in w19["layers"]:
        if str(l.get("layer", "")).startswith("L4"):
            l["status"] = "Failed"
            l["reason"] = "State diff FAILED: SignerLamportsOutsideDeclaredDebit: the signer lost 1000000 lamports\noutside the declared debit"
    post_fn, get_fn, _ = fake_core([w19, fixture("blocked")])
    sel = selected(2)
    sel[0]["input"] = {"transaction_instructions": [{"program_id": "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"}, {"program_id": "11111111111111111111111111111111"}]}
    rows = sample_rows(2)
    rows[0]["cu"] = 123456
    rep = lm.replay(sel, rows, "http://core", "k", pace=0, l8=0, sleep=lambda s: None, post_fn=post_fn, get_fn=get_fn)
    watched = [r for r in rep["rows"] if r.get("watched")]
    assert [r["row"] for r in watched] == [0]
    r = watched[0]
    assert r["watched"] == ["SignerLamportsOutsideDeclaredDebit"]
    assert r["cu_on_chain"] == 123456 and r["signature"] == solrpc.b58encode(bytes(range(64)))
    assert r["programs"] == ["JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4", "11111111111111111111111111111111"]
    md = lm.markdown(rep)
    line = next(l for l in md.splitlines() if l.startswith("| 0 |"))
    # One table row: the reason's newline does not break the table.
    assert "SignerLamportsOutsideDeclaredDebit" in line and "JUP6LkbZ 11111111" in line and "123456" in line
    assert line.endswith("lamports outside the declared debit |")


def test_a_seeded_programs_verdicts_are_watched_and_no_watched_row_says_so():
    post_fn, get_fn, _ = fake_core([fixture("blocked"), fixture("blocked")])
    seeded = {"ok": True, "programs": {"P1": {}}}
    rep = lm.replay(selected(2), sample_rows(2), "http://core", "k", pace=0, l8=0, sleep=lambda s: None,
                    post_fn=post_fn, get_fn=get_fn, seeded=seeded)
    assert [(r["row"], r["watched"]) for r in rep["rows"] if r.get("watched")] == [(1, ["seeded"])]
    post_fn, get_fn, _ = fake_core([fixture("blocked")])
    rep = lm.replay(selected(1), sample_rows(1), "http://core", "k", pace=0, l8=0, sleep=lambda s: None, post_fn=post_fn, get_fn=get_fn)
    assert "No verdict named a watched L4 finding" in lm.markdown(rep)


# ── devnet log parsing ───────────────────────────────────────────────────────


GUARD_LOG = """
✅ TRANSACTION CONFIRMED ON DEVNET!
Signature: 5abc
Solscan:   https://solscan.io/tx/5abc?cluster=devnet
Decision:            executable_approved (reported by the Core: executable_approved)
Signing on trail:    true (verdict on record: true)
Submission on trail: true
L8 reconciliation:   "ApprovedAndExecuted" (attribution: chain)
Fee Paid:       0.000005
"""


def test_the_guard_log_is_parsed():
    p = live_devnet.parse_guard_log(GUARD_LOG)
    assert p["signature"] == "5abc"
    assert p["decision"] == "executable_approved"
    assert p["reported_decision"] == "executable_approved"
    assert p["confirmed"] is True
    assert p["discrepancy"] is False
    assert p["l8"].startswith('"ApprovedAndExecuted"')
    assert live_devnet.parse_guard_log(GUARD_LOG + "\n❌ L8 DISCREPANCY")["discrepancy"] is True


def test_l8_outcomes():
    assert live_devnet.l8_outcome('"ApprovedAndExecuted" (attribution: chain)') == "reconciled"
    assert live_devnet.l8_outcome('{"Unavailable":{"reason":"HTTP 429 Too Many Requests"}}') == "unavailable"
    # Found in the mock dry run: Graphite failing to READ a status is not the
    # endpoint's fault, and must not pass as "unavailable".
    assert live_devnet.l8_outcome(
        '{"Unavailable":{"reason":"RPC error confirming signature: Invalid response: getSignatureStatuses status is neither Ok nor Err"}}'
    ) == "defect"
    assert live_devnet.l8_outcome('"BlockedButExecuted"') == "defect"
    assert live_devnet.l8_outcome(None) == "defect"


# ── the blockhash rewrite, on real committed mainnet bytes (Round 32, P3b) ───

SAMPLE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "graphite-core", "fixtures", "mainnet",
                      "sample-2026-09-23-last-2-blocks.json")


@pytest.fixture(scope="module")
def sample():
    with open(SAMPLE, encoding="utf-8") as f:
        rows = json.load(f)["rows"]
    return [base64.b64decode(r["b64"]) for r in rows], rows


def unsigned(frame):
    """What the conformance harness sends: every signature slot zeroed."""
    lay = wire.layout(frame)
    out = bytearray(frame)
    out[lay.signatures_at : lay.signatures_at + 64 * lay.signature_count] = bytes(64 * lay.signature_count)
    return bytes(out)


# Row → recentBlockhash as Agave 4.2.2 reads it (`solana decode-transaction
# <b64> base64 --output json`, the pinned release the devnet workflow uses):
# an oracle independent of wire.py. Rows 13 and 26 are durable-nonce
# transactions (Agave: instruction 0 is System AdvanceNonceAccount).
AGAVE_BLOCKHASHES = {
    0: ("legacy", "FRGFASXt3moXYQKSsETL4ztaeebXYjsAHWUUers76eP9"),
    5: ("legacy", "CSr7kwvD6G2Za1xV3WaFFHLfPHeozmh72QX7c8xF9FoH"),
    13: ("legacy", "2cXd494m2wPpRdbRxGq3JyRyTJaR2AtchXb4ZcGvV22w"),
    15: ("legacy", "HLeLSWw42zBP5goNkuHqDve2eKLAkVNhuk41aXz9MhdU"),
    4: ("0", "FRGFASXt3moXYQKSsETL4ztaeebXYjsAHWUUers76eP9"),
    6: ("0", "CSr7kwvD6G2Za1xV3WaFFHLfPHeozmh72QX7c8xF9FoH"),
    26: ("0", "FAwbae348zkdxfn5y2SKQQJJhm4A3cbQT5b6ZuqLB3uC"),
    41: ("0", "2eZ3YfBY3GamMVztuXNxAUEG3guFDTNQZsnb4G8iN7bw"),
    8: ("1", "Bh2G4bTbnDQA29mDAfFw8Ct3o7cLkQQBSzEskAbQYEx2"),
    21: ("1", "J5Zf6P24NJBdjohuA2G4Px9LVxaZxSSn4RuSJvkDAo7g"),
    38: ("1", "5nFGBEpmKaqBDay7Ufc3zC3gUgUn4rAcYuZcJQxkMUP6"),
}


def test_blockhash_offsets_match_agave_on_committed_legacy_v0_and_v1(sample):
    frames, _ = sample
    for row, (version, expected) in AGAVE_BLOCKHASHES.items():
        lay = wire.layout(frames[row])
        assert lay.version == version, row
        assert solrpc.b58encode(wire.blockhash(frames[row])) == expected, (row, lay)
        # the unsigned frame the harness sends keeps the blockhash where it was
        assert wire.blockhash(unsigned(frames[row])) == wire.blockhash(frames[row])
    assert wire.layout(frames[8]).blockhash_at == 8  # v1: prefix, header, config mask


def test_every_committed_frame_parses_to_its_last_byte(sample):
    frames, rows = sample
    versions, nonces = {}, 0
    for frame, r in zip(frames, rows):
        lay = wire.layout(frame)
        assert lay.version == str(r["version"])
        versions[lay.version] = versions.get(lay.version, 0) + 1
        nonces += lay.durable_nonce
    assert versions == {"legacy": 1499, "0": 472, "1": 313}
    assert nonces == 97
    assert wire.layout(frames[13]).durable_nonce and wire.layout(frames[26]).durable_nonce
    assert not wire.layout(frames[0]).durable_nonce


def test_the_patch_rewrites_exactly_the_32_blockhash_bytes(sample):
    frames, _ = sample
    new = bytes(range(1, 33))
    for row in (0, 5, 4, 41, 8, 38):
        before = unsigned(frames[row])
        after = wire.patch_blockhash(before, new)
        at = wire.layout(before).blockhash_at
        assert len(after) == len(before)
        assert [i for i in range(len(before)) if before[i] != after[i]] == [i for i in range(at, at + 32) if before[i] != new[i - at]]
        assert wire.blockhash(after) == new
        assert wire.layout(after) == wire.layout(before)


def test_the_patch_refuses_signed_bytes_and_durable_nonces(sample):
    frames, _ = sample
    with pytest.raises(ValueError, match="signature"):
        wire.patch_blockhash(frames[0], bytes(32))  # the chain's bytes are signed
    with pytest.raises(ValueError, match="durable nonce"):
        wire.patch_blockhash(unsigned(frames[13]), bytes(32))
    with pytest.raises(ValueError, match="32 bytes"):
        wire.patch_blockhash(unsigned(frames[0]), bytes(31))


def test_truncated_or_padded_frames_are_refused(sample):
    frames, _ = sample
    for row in (0, 4, 8):
        with pytest.raises(ValueError):
            wire.layout(frames[row][:-1])
        with pytest.raises(ValueError):
            wire.layout(frames[row] + b"\0")
    with pytest.raises(ValueError):
        wire.layout(b"")


# ── why: reasons behind L3/L4 failures and inconclusives ────────────────────


@pytest.mark.parametrize(
    "err,cls",
    [
        ("BlockhashNotFound", "BlockhashNotFound"),
        ("AccountNotFound — the transaction would not land", "AccountNotFound"),
        ("AlreadyProcessed", "AlreadyProcessed"),
        ("InsufficientFundsForFee", "InsufficientFundsForFee"),
        ('{"InstructionError":[2,{"Custom":6001}]} — the transaction', "InstructionError{2, Custom(6001)}"),
        ('{"InstructionError":[0,"InvalidAccountData"]}: the', "InstructionError{0, InvalidAccountData}"),
        ('{"InstructionError":[0,"Custom(1)"]}', "InstructionError{0, Custom(1)}"),
        ('{"InstructionError":[3,{"BorshIoError":"Unknown"}]}', "InstructionError{3, BorshIoError}"),
        ('{"InsufficientFundsForRent":{"account_index":0}}', "InsufficientFundsForRent"),
        ('{"DuplicateInstruction":3}', "DuplicateInstruction"),
    ],
)
def test_simulator_errors_are_named(err, cls):
    assert lm.sim_error_class(err) == cls


def l3l4(l3_status, l3_reason, l4_status="passed", l4_reason="ok"):
    v = fixture("executable_approved")
    for l in v["layers"]:
        if l["layer"].startswith("L3"):
            l["status"], l["reason"] = l3_status, l3_reason
        if l["layer"].startswith("L4"):
            l["status"], l["reason"] = l4_status, l4_reason
    return v


def test_l3_and_l4_reasons_read_the_cores_own_wording():
    # the committed fixture: an InstructionError from the simulator
    assert lm.failure_reasons(fixture("blocked")) == ["L3 failed: InstructionError{0, Custom(1)}", "L4 inconclusive: State not observed: no pre/post diff"]
    v = l3l4("inconclusive", "Simulation ran, but no trusted baseline exists for this program yet (2 of 10 samples needed). The baseline grows")
    assert lm.failure_reasons(v) == ["L3 inconclusive: no mature baseline"]
    v = l3l4("inconclusive", "Simulation INCOMPLETE — no complete simulation was obtained (simulation failed: RPC error: HTTP 429 Too Many Requests)",
             "inconclusive", "State not observed | NOTE: the pre/post state diff was attempted and could not be built (simulation failed: RPC error: HTTP 429 Too Many Requests) — this")
    assert lm.failure_reasons(v) == ["L3 inconclusive: incomplete: RPC rate-limited", "L4 inconclusive: simulation call failed: RPC rate-limited"]
    v = l3l4("inconclusive", "Simulation INCOMPLETE — no complete simulation was obtained (simulation failed: Invalid response: no unitsConsumed)")
    assert lm.failure_reasons(v) == ["L3 inconclusive: incomplete: simulation call failed: Invalid response: no unitsConsumed"]
    v = l3l4("failed", "Simulation integrity FLAGGED: 90000 CU / 3 writes / 1 hops [RPC-measured] (divergence 6.10σ vs this transaction shape's baseline)")
    assert lm.failure_reasons(v) == ["L3 failed: flagged: divergence from the shape baseline"]
    # addresses and numbers do not split one cause into many
    a = l3l4("passed", "x", "failed", "account 9RGFwSryu7FvDaqHWFLrnvQHge7hc5chawhcSH7m8FVU changed by 5000 lamports, undeclared")
    b = l3l4("passed", "x", "failed", "account DuFgLf6zzf2N9v3iT4NrkdTPDSD2xK52CCnx6Ag2ckTP changed by 17 lamports, undeclared")
    assert lm.failure_reasons(a) == lm.failure_reasons(b) == ["L4 failed: account <addr> changed by N lamports, undeclared"]
    # an executable verdict whose L3 had no baseline to judge against (the fixture)
    assert lm.failure_reasons(fixture("executable_approved")) == ["L3 inconclusive: no mature baseline"]
    assert lm.failure_reasons(l3l4("passed", "Simulation integrity clean (RPC-verified): 150 CU")) == []


def test_the_report_breaks_reasons_down_per_program_and_prints_them():
    post_fn, get_fn, _ = fake_core([fixture("blocked"), fixture("analysis_only"), fixture("blocked"), fixture("executable_approved")])
    rep = lm.replay(selected(4), sample_rows(4), "http://core", "k", pace=0, l8=0, sleep=lambda s: None, post_fn=post_fn, get_fn=get_fn)
    assert rep["reasons"]["L3 failed: InstructionError{0, Custom(1)}"] == 2
    assert rep["reasons_by_program"]["P0"]["L3 failed: InstructionError{0, Custom(1)}"] == 2
    assert "P1" in rep["reasons_by_program"]  # analysis_only: L3 inconclusive, no RPC
    assert rep["finding_patterns"]["SimulationFailed"] == 2
    md = lm.markdown(rep)
    assert "| `P0` | L3 failed: InstructionError{0, Custom(1)} | 2 |" in md
    assert "A fresh Core has earned no evidence for any program" in md


# ── the fresh-blockhash pass ─────────────────────────────────────────────────


def frame_entries(sample, rows):
    frames, _ = sample
    return [
        {"row": r, "slot": 1, "program_id": f"P{r}", "instruction_name": "x", "manifest_found": True, "failed_on_chain": False,
         "input": {"signed_transaction": list(unsigned(frames[r])), "intent": {"intent_type": "Transfer"}}}
        for r in rows
    ]


def test_the_fresh_pass_rewrites_only_the_blockhash_and_compares_side_by_side(sample):
    entries = frame_entries(sample, [0, 4, 8, 13, 5])  # legacy, v0, v1, durable nonce, (outside the fresh subset)
    new = bytes(range(100, 132))
    stale_only = l3l4("inconclusive", "Simulation INCOMPLETE — no complete simulation was obtained (simulation failed: BlockhashNotFound)")
    # stale, fresh per request in call order; row 8's outcome differs between its two passes
    post_fn, get_fn, calls = fake_core([fixture("blocked"), fixture("blocked"), fixture("analysis_only"), fixture("analysis_only"),
                                        stale_only, fixture("blocked"), fixture("blocked"), fixture("blocked")])
    rep = lm.replay(entries, [], "http://core", "k", pace=0, l8=0, fresh=4, blockhash_fn=lambda: new,
                    sleep=lambda s: None, post_fn=post_fn, get_fn=get_fn)
    f = rep["fresh"]
    assert f["requested"] == 4 and f["compared"] == 3 and f["changed"] == 1
    assert f["patched_by_version"] == {"legacy": 1, "0": 1, "1": 1}
    assert f["skipped"] == {"durable nonce (legacy)": 1}
    verify_bodies = [b for u, b in calls if u.endswith("/verify")]
    assert len(verify_bodies) == 8 and all(u.startswith("http://core/") for u, _ in calls)  # nothing goes to a cluster
    for stale, fresh in ((verify_bodies[0], verify_bodies[1]), (verify_bodies[2], verify_bodies[3]), (verify_bodies[4], verify_bodies[5])):
        s, n = bytes(stale["signed_transaction"]), bytes(fresh["signed_transaction"])
        lay = wire.layout(s)
        at = lay.blockhash_at
        assert n[:at] == s[:at] and n[at + 32 :] == s[at + 32 :] and n[at : at + 32] == new
        assert {k: v for k, v in fresh.items() if k != "signed_transaction"} == {k: v for k, v in stale.items() if k != "signed_transaction"}
        assert not any(n[lay.signatures_at : lay.signatures_at + 64 * lay.signature_count])  # still unsigned
    changed = [p for p in f["pairs"] if p["changed"]]
    assert changed[0]["row"] == 8
    assert changed[0]["stale"]["reasons"] == ["L3 inconclusive: incomplete: simulation call failed: BlockhashNotFound"]
    assert f["stale_decisions"] == {"blocked": 1, "analysis_only": 1, "executable_approved": 1}
    md = lm.markdown(rep)
    assert "## Fresh-blockhash pass" in md and "outcome changed: **1**" in md and "| 8 | `P8` | 1 |" in md


def test_the_fresh_pass_counts_what_it_could_not_patch(sample):
    entries = frame_entries(sample, [0, 4])

    def no_hash():
        raise solrpc.RateLimited("getLatestBlockhash: 429")

    post_fn, get_fn, calls = fake_core([fixture("blocked")] * 2)
    rep = lm.replay(entries, [], "http://core", "k", pace=0, l8=0, fresh=2, blockhash_fn=no_hash, sleep=lambda s: None, post_fn=post_fn, get_fn=get_fn)
    assert rep["fresh"]["skipped"] == {"no fresh blockhash (RateLimited)": 2} and len(calls) == 2
    post_fn, get_fn, _ = fake_core([fixture("blocked")] * 2)
    rep = lm.replay(entries, [], "http://core", "k", pace=0, l8=0, fresh=2, blockhash_fn=None, sleep=lambda s: None, post_fn=post_fn, get_fn=get_fn)
    assert rep["fresh"]["skipped"] == {"no RPC for a fresh blockhash": 2}


def test_a_fresh_blockhash_is_reused_for_its_ttl():
    calls, now = [], [0.0]
    hashes = iter(["4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZAMdL4VZHirAn", "FRGFASXt3moXYQKSsETL4ztaeebXYjsAHWUUers76eP9"])

    def call(url, method, params, **kw):
        calls.append(method)
        return {"result": {"value": {"blockhash": next(hashes)}}}

    fb = lm.FreshBlockhash("http://rpc", ttl=20, call=call, clock=lambda: now[0])
    a = fb()
    now[0] = 19
    assert fb() == a and calls == ["getLatestBlockhash"]
    now[0] = 41
    assert fb() != a and len(calls) == 2 and len(a) == 32
    bad = lm.FreshBlockhash("http://rpc", call=lambda *a, **k: {"error": {"code": -32000, "message": "x"}})
    with pytest.raises(solrpc.RpcError):
        bad()


# ── operator evidence for System and SPL Token ───────────────────────────────


class Done:
    def __init__(self, code=0, out="tier: SimulationValidated"):
        self.returncode, self.stdout, self.stderr = code, out, "boom" if code else ""


def test_seeding_covers_system_and_spl_token():
    ran = []
    doc = lm.seed("graphite", "/d", run=lambda c, **k: ran.append(c) or Done())
    assert doc["ok"] and set(doc["programs"]) == {lm.SYSTEM_PROGRAM, lm.SPL_TOKEN_PROGRAM}
    seeded = [(c[2], c[c.index("--program") + 1]) for c in ran]
    for p in (lm.SYSTEM_PROGRAM, lm.SPL_TOKEN_PROGRAM):
        assert ("seed", p) in seeded and ("baseline", p) in seeded and ("show", p) in seeded
    token_baseline = next(c for c in ran if c[2] == "baseline" and lm.SPL_TOKEN_PROGRAM in c)
    assert token_baseline[token_baseline.index("--mean-compute-units") + 1] == "5000"
    assert all(c[c.index("--data-dir") + 1] == "/d" for c in ran)
    failed = lm.seed("graphite", "/d", run=lambda c, **k: Done(1 if c[2] == "baseline" else 0))
    assert not failed["ok"] and "baseline" in failed["error"]


def test_a_seeded_run_reports_the_seeded_programs_and_the_caveat():
    post_fn, get_fn, _ = fake_core([fixture("executable_approved"), fixture("blocked")])
    entries = selected(2)
    entries[0]["program_id"] = lm.SYSTEM_PROGRAM
    seeded = {"ok": True, "programs": {lm.SYSTEM_PROGRAM: {}, lm.SPL_TOKEN_PROGRAM: {}}}
    rep = lm.replay(entries, sample_rows(2), "http://core", "k", pace=0, l8=0, seeded=seeded, sleep=lambda s: None, post_fn=post_fn, get_fn=get_fn)
    assert rep["seeded_outcomes"][lm.SYSTEM_PROGRAM]["decisions"] == {"executable_approved": 1}
    assert rep["seeded_outcomes"][lm.SPL_TOKEN_PROGRAM]["verdicts"] == 0
    md = lm.markdown(rep)
    assert "operator evidence was seeded for" in md and "## Seeded programs" in md
    assert "A fresh Core has earned no evidence for any other program" in md


# ── devnet: faucet retries, then a local real runtime ───────────────────────


def test_the_faucet_is_retried_with_backoff_then_the_refusal_carries_every_attempt():
    sleeps, tries = [], []

    def refuse(rpc, pubkey, lamports):
        tries.append(rpc)
        raise solrpc.RateLimited("requestAirdrop: HTTP 429")

    with pytest.raises(solrpc.RateLimited) as e:
        live_devnet.airdrop_with_retry("https://faucet", "pk", 1, rounds=3, pause=30, airdrop_fn=refuse, sleep=sleeps.append)
    assert len(tries) == 3 and sleeps == [30, 60] and len(e.value.attempts) == 3
    outcomes = iter([solrpc.RpcError("airdrop not visible"), 500])

    def second_round(rpc, pubkey, lamports):
        o = next(outcomes)
        if isinstance(o, Exception):
            raise o
        return o

    assert live_devnet.airdrop_with_retry("x", "pk", 1, airdrop_fn=second_round, sleep=lambda s: None)[0] == 500


class FakeProc:
    def __init__(self, code=None):
        self.returncode, self.terminated = code, False

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True


def test_the_local_validator_is_started_on_loopback_and_waited_for():
    launched, answers = [], iter([solrpc.RpcError("refused"), {"result": "behind"}, {"result": "ok"}])

    def call(rpc, method, params, **kw):
        assert rpc == "http://127.0.0.1:8899" and method == "getHealth"
        a = next(answers)
        if isinstance(a, Exception):
            raise a
        return a

    proc, rpc = live_devnet.start_validator("/bin/stv", "/w", popen=lambda cmd, **k: launched.append(cmd) or FakeProc(), call=call, sleep=lambda s: None)
    assert rpc == "http://127.0.0.1:8899"
    cmd = launched[0]
    assert cmd[0] == "/bin/stv" and cmd[cmd.index("--bind-address") + 1] == "127.0.0.1" and "--reset" in cmd
    assert cmd[cmd.index("--ledger") + 1] == "/w/ledger"
    with pytest.raises(RuntimeError, match="exited 1"):
        live_devnet.start_validator("/bin/stv", "/w", popen=lambda cmd, **k: FakeProc(1), call=call, sleep=lambda s: None)


def devnet_args(tmp_path, **kw):
    a = dict(graphite="/bin/false", rpc="https://api.devnet.solana.com", airdrop_lamports=1, core_port=7331, seed_evidence=True,
             guard_cmd=None, out_dir=str(tmp_path), cluster="devnet", validator="/bin/stv", faucet_rounds=2)
    a.update(kw)
    return type("Args", (), a)()


@pytest.fixture
def devnet_fakes(monkeypatch):
    seen = {"airdrops": [], "validators": 0}
    monkeypatch.setattr(live_devnet, "gen_keys", lambda work: {"payer_secret": "S", "payer": "PAYER", "destination": "D"})
    monkeypatch.setattr(live_devnet, "validator_version", lambda b: "solana-test-validator 4.2.2")

    def fake_airdrop(rpc, pubkey, lamports, rounds=3, **kw):
        seen["airdrops"].append(rpc)
        if rpc.startswith("https://api.devnet"):
            e = solrpc.RateLimited("requestAirdrop: HTTP 429")
            e.attempts = [{"round": n + 1, "result": "RateLimited"} for n in range(rounds)]
            raise e
        return lamports, [{"round": 1, "result": "paid"}]

    def fake_validator(binary, work, **kw):
        seen["validators"] += 1
        return FakeProc(0), "http://127.0.0.1:8899"

    monkeypatch.setattr(live_devnet, "airdrop_with_retry", fake_airdrop)
    monkeypatch.setattr(live_devnet, "start_validator", fake_validator)
    return seen


def test_a_refusing_faucet_falls_back_to_the_local_validator(tmp_path, devnet_fakes):
    # /bin/false as the Core binary stops the run at the evidence step: what
    # is tested is that it got there on the local cluster, and says so.
    rep = live_devnet.run(devnet_args(tmp_path))
    assert rep["cluster"] == "local-validator" and "faucet refused" in rep["cluster_reason"]
    assert rep["rpc_host"] == "127.0.0.1"
    assert [(s["step"], s["status"]) for s in rep["steps"]][:5] == [
        ("keys", "ok"), ("airdrop", "REFUSED"), ("validator", "ok"), ("airdrop", "ok"), ("evidence", "FAILED")]
    assert devnet_fakes["airdrops"] == ["https://api.devnet.solana.com", "http://127.0.0.1:8899"]
    md = live_devnet.markdown(rep)
    assert "Cluster: **local-validator**" in md and "local real Solana runtime" in md


def test_without_a_validator_a_refusing_faucet_is_still_skipped(tmp_path, devnet_fakes):
    rep = live_devnet.run(devnet_args(tmp_path, validator=None))
    assert rep["status"] == "SKIPPED" and devnet_fakes["validators"] == 0 and rep["cluster"] == "devnet"


def test_local_validator_mode_never_asks_the_public_faucet(tmp_path, devnet_fakes):
    rep = live_devnet.run(devnet_args(tmp_path, cluster="local-validator"))
    assert devnet_fakes["airdrops"] == ["http://127.0.0.1:8899"] and rep["cluster"] == "local-validator"
    assert "forced" in rep["cluster_reason"]
    assert live_devnet.run(devnet_args(tmp_path, cluster="local-validator", validator=None))["status"] == "DEFECTS"


def test_evidence_is_seeded_under_the_key_the_core_runs_with(tmp_path, devnet_fakes, monkeypatch):
    # Round 35: seeding without the key left an unkeyed record on the trail,
    # and the keyed Core then refused to start (R33-4's no-downgrade rule).
    # A stand-in binary logs the key file each invocation sees, the Core's
    # launch included; /health never answers, so the run stops there.
    seen = tmp_path / "seen.txt"
    fake = tmp_path / "graphite"
    fake.write_text('#!/bin/sh\necho "$1 ${GRAPHITE_AUDIT_KEY_FILE:-<none>}" >> "%s"\n' % seen)
    fake.chmod(0o755)

    def no_core(url, **kw):
        for _ in range(500):
            if seen.exists() and "server" in seen.read_text():
                break
            time.sleep(0.01)
        raise TimeoutError(f"{url} did not answer")

    monkeypatch.setattr(live_devnet, "wait_http", no_core)
    rep = live_devnet.run(devnet_args(tmp_path, graphite=str(fake)))
    assert [(s["step"], s["status"]) for s in rep["steps"]][-2:] == [("evidence", "ok"), ("core", "FAILED")]
    lines = [l.split(" ", 1) for l in seen.read_text().splitlines()]
    assert [c for c, _ in lines] == ["evidence", "evidence", "evidence", "server"]
    keys = {k for _, k in lines}
    assert len(keys) == 1 and next(iter(keys)).endswith("audit.key")


def test_fetch_keeps_going_until_the_sample_is_large_enough(tmp_path, monkeypatch):
    # Round 35: two blocks held 493 transactions and the harness (which needs
    # more than 500 verdicts) failed the run. Fetching continues past
    # `blocks` until `min_transactions`, never past `max_blocks`.
    import fetch_mainnet

    monkeypatch.setattr(fetch_mainnet, "rows_from_block", lambda slot, block: [{"slot": slot}] * block["n"])

    def fake_call(size, skip=()):
        def call(rpc, method, params, **kw):
            if method == "getSlot":
                return {"result": 1000}
            if params[0] in skip:
                return {"error": {"code": -32007, "message": "skipped"}}
            return {"result": {"n": size}}
        return call

    out = str(tmp_path / "s.json")
    doc = lm.fetch("https://rpc.example", 2, out, sleep=lambda s: None, call=fake_call(250))
    assert len(doc["slots"]) == 4 and doc["count"] == 1000
    doc = lm.fetch("https://rpc.example", 2, out, max_blocks=3, sleep=lambda s: None, call=fake_call(250))
    assert len(doc["slots"]) == 3 and doc["count"] == 750
    doc = lm.fetch("https://rpc.example", 2, out, sleep=lambda s: None, call=fake_call(1500))
    assert len(doc["slots"]) == 2 and doc["count"] == 3000
    doc = lm.fetch("https://rpc.example", 2, out, sleep=lambda s: None, call=fake_call(400, skip={940}))
    assert doc["skipped_slots"] == [940] and doc["slots"] == [960, 920, 900] and doc["count"] == 1200
    assert json.load(open(out))["count"] == 1200
