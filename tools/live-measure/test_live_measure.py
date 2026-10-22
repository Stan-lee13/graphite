"""The live-measurement scripts' logic, without a network (Round 32, P3).

    python3 -m pytest -q -p no:cacheprovider tools/live-measure/test_live_measure.py
"""
import base64
import copy
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import live_devnet  # noqa: E402
import live_mainnet as lm  # noqa: E402
import solrpc  # noqa: E402

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
