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


@pytest.mark.parametrize(
    "edit",
    [
        lambda s: s.pop("unobserved_codes"),
        lambda s: s["unobserved"].append("a residual nobody named"),
        lambda s: s.update(transaction_sha256="E" * 64),
    ],
    ids=["codes missing", "prose without a code", "digest not lower-hex"],
)
def test_an_executable_verdict_over_an_unnamed_residual_is_a_defect(edit):
    # Round 39 (R39-CLIENTS-8): the recomputation read missing codes as none
    # and prose without a code as nothing, so these were not defects.
    v = fixture("executable_approved")
    edit(v["scope"])
    assert lm.recomputed_decision(v) == "analysis_only"
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


JUPITER = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"


def census_output(ids, sha="ab" * 32):
    """What `graphite evidence import-census` prints (cli.rs, run_import_census)."""
    lines = [f"CENSUS  battle_tested_evidence.json sha256={sha}  (compiled in)", ""]
    for p in ids:
        lines += [f"IMPORT  {p}  (Name)", "  census       1456 successful transactions over 1s, slots 1..2, measured_at x"]
    lines += ["SKIP    Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo  (Memo): no decode rate", "",
              f"IMPORTED {len(ids)} program(s) into /d; each is one operator_action row on its audit trail."]
    return "\n".join(lines)


def fake_graphite(ran, imported=(lm.SYSTEM_PROGRAM, lm.SPL_TOKEN_PROGRAM), fail=None):
    def run(c, **k):
        ran.append(c)
        if c[2] == fail:
            return Done(1)
        return Done(out=census_output(imported)) if c[2] == "import-census" else Done()
    return run


def test_seeding_imports_the_census_and_types_no_baseline():
    ran = []
    doc = lm.seed("graphite", "/d", run=fake_graphite(ran))
    assert doc["ok"] and set(doc["programs"]) == {lm.SYSTEM_PROGRAM, lm.SPL_TOKEN_PROGRAM}
    # Round 40: the evidence is the measured census, imported in one command;
    # no `evidence seed` with typed numbers, and (Round 40, measure) no typed
    # L3 baseline — it flagged honest System and SPL Token instructions in run
    # 40280048548.
    imported = [c for c in ran if c[2] == "import-census"]
    assert len(imported) == 1 and not any(c[2] in ("seed", "baseline") for c in ran)
    assert imported[0][imported[0].index("--cluster") + 1] == "mainnet-beta"
    assert [imported[0][i + 1] for i, a in enumerate(imported[0]) if a == "--program"] == [
        lm.SYSTEM_PROGRAM, lm.SPL_TOKEN_PROGRAM]
    assert sorted(c[c.index("--program") + 1] for c in ran if c[2] == "show") == sorted(
        [lm.SYSTEM_PROGRAM, lm.SPL_TOKEN_PROGRAM])
    assert all(c[c.index("--data-dir") + 1] == "/d" for c in ran)
    assert doc["imported"] == [lm.SYSTEM_PROGRAM, lm.SPL_TOKEN_PROGRAM] and doc["imported_count"] == 2
    assert doc["census_sha256"] == "ab" * 32 and "none typed" in doc["l3_baselines"]
    assert all(d["imported"] for d in doc["programs"].values())
    failed = lm.seed("graphite", "/d", run=fake_graphite([], fail="import-census"))
    assert not failed["ok"] and "import-census" in failed["error"]


def test_a_census_import_that_skipped_a_named_program_fails_the_seeding():
    # Asked for and not in force: the report would call it census-imported.
    doc = lm.seed("graphite", "/d", run=fake_graphite([], imported=[lm.SYSTEM_PROGRAM]))
    assert not doc["ok"] and lm.SPL_TOKEN_PROGRAM in doc["error"]
    assert lm.main(["seed", "--graphite", "/bin/false", "--data-dir", "/nonexistent", "--out", os.devnull]) == 1


def test_whole_census_seeding_imports_every_admitted_record():
    # Round 40: a labelled run imports the whole census (an operator's first
    # start), so `import-census` names no program.
    ran = []
    doc = lm.seed("graphite", "/d", whole_census=True,
                  run=fake_graphite(ran, imported=[lm.SYSTEM_PROGRAM, JUPITER, lm.SPL_TOKEN_PROGRAM]))
    assert doc["ok"] and doc["evidence"] == "census-imported (whole census)" and doc["whole_census"]
    imported = [c for c in ran if c[2] == "import-census"]
    assert len(imported) == 1 and "--program" not in imported[0]
    assert imported[0][imported[0].index("--cluster") + 1] == "mainnet-beta"
    assert doc["imported_count"] == 3 and JUPITER in doc["imported"]
    assert not any(c[2] == "baseline" for c in ran)


def test_a_seeded_run_reports_the_census_programs_and_the_caveat():
    post_fn, get_fn, _ = fake_core([fixture("executable_approved"), fixture("blocked")])
    entries = selected(2)
    entries[0]["program_id"] = lm.SYSTEM_PROGRAM
    seeded = {"ok": True, "imported": [lm.SYSTEM_PROGRAM, lm.SPL_TOKEN_PROGRAM], "imported_count": 2,
              "programs": {lm.SYSTEM_PROGRAM: {"imported": True}, lm.SPL_TOKEN_PROGRAM: {"imported": True}}}
    rep = lm.replay(entries, sample_rows(2), "http://core", "k", pace=0, l8=0, seeded=seeded, sleep=lambda s: None, post_fn=post_fn, get_fn=get_fn)
    assert rep["seeded_outcomes"][lm.SYSTEM_PROGRAM]["decisions"] == {"executable_approved": 1}
    assert rep["seeded_outcomes"][lm.SPL_TOKEN_PROGRAM]["verdicts"] == 0
    assert rep["decisions_by_evidence"] == {"census-imported program": {"executable_approved": 1},
                                            "program not imported": {"blocked": 1}}
    md = lm.markdown(rep)
    assert f"the measured census was imported for `{lm.SYSTEM_PROGRAM}`, `{lm.SPL_TOKEN_PROGRAM}` only" in md
    assert "## System and SPL Token (census-imported)" in md
    assert "Programs the import did not cover have no evidence" in md
    assert "No L3 baseline was typed" in md and "| census-imported program | 1 |" in md


def test_after_a_whole_census_import_the_report_does_not_say_two_programs():
    # Round 40 (measure): run 40280048548 imported the whole census and its
    # report said evidence was seeded for System and SPL Token only.
    post_fn, get_fn, _ = fake_core([fixture("blocked")])
    seeded = {"ok": True, "whole_census": True, "imported": [lm.SYSTEM_PROGRAM, lm.SPL_TOKEN_PROGRAM, JUPITER],
              "imported_count": 114, "census_sha256": "cd" * 32,
              "programs": {lm.SYSTEM_PROGRAM: {"imported": True}, lm.SPL_TOKEN_PROGRAM: {"imported": True}}}
    rep = lm.replay(selected(1), sample_rows(1), "http://core", "k", pace=0, l8=0, seeded=seeded, sleep=lambda s: None,
                    post_fn=post_fn, get_fn=get_fn)
    md = lm.markdown(rep)
    assert "for every program the committed census admits — 114 program(s) imported" in md
    assert " only (" not in md and "seeded for" not in md and "cd" * 32 in md
    # An old record with a typed baseline is still named as such.
    old = dict(seeded, programs={lm.SYSTEM_PROGRAM: {"baseline": {"mean": 150}}})
    assert "An L3 compute baseline was also typed" in "\n".join(lm.evidence_markdown(old, [lm.SYSTEM_PROGRAM]))
    assert "A fresh Core has earned no evidence for any program" in "\n".join(lm.evidence_markdown({}, []))


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


# ── Round 40 (measure): the message parser and the legacy builder ───────────

# Committed legacy rows that are one System Transfer (and Compute Budget
# instructions) whose wallet ordered its accounts as `build_legacy` does:
# rebuilt from their parts they are the same bytes, signature slot aside.
LEGACY_TRANSFER_ROWS_BYTE_IDENTICAL = (443, 1070, 1115, 1387)


def privileges(msg, i):
    nreq, ro_s, ro_u = msg.num_required_signatures, msg.num_readonly_signed, msg.num_readonly_unsigned
    signer = i < nreq
    writable = i < nreq - ro_s if signer else i < len(msg.static_keys) - ro_u
    return signer, writable


def parts(msg, keys):
    """A message as (fee payer, [(program, [(account, signer, writable)], data)])."""
    return keys[0], [
        (keys[ix.program_index], [(keys[a], *privileges(msg, a)) for a in ix.accounts], ix.data)
        for ix in msg.instructions
    ]


def test_the_message_parser_agrees_with_layout_on_every_committed_frame(sample):
    frames, rows = sample
    for frame in frames:
        msg, lay = wire.message(frame), wire.layout(frame)
        assert (msg.version, msg.num_required_signatures, msg.durable_nonce) == (lay.version, lay.signature_count, lay.durable_nonce)
        assert msg.blockhash == wire.blockhash(frame)
    with pytest.raises(ValueError):
        wire.message(frames[0] + b"\0")
    with pytest.raises(ValueError):
        wire.message(frames[8][:-1])


def test_the_builder_reproduces_real_wallet_transfers_byte_for_byte(sample):
    # The known fixture: real mainnet bytes (the committed sample), built by
    # wallets, compared byte for byte with what `build_legacy` makes of their
    # parts. The signature slot is the only difference, and it is zeroed.
    frames, rows = sample
    for row in LEGACY_TRANSFER_ROWS_BYTE_IDENTICAL:
        msg = wire.message(frames[row])
        payer, ixs = parts(msg, wire.account_keys(msg))
        assert any(p == lm.SYSTEM_PROGRAM for p, _, _ in ixs)
        assert wire.build_legacy(payer, ixs, msg.blockhash) == unsigned(frames[row]), row


def test_every_committed_simple_transfer_rebuilds_to_the_same_instructions(sample):
    # Every executed simple transfer in the committed sample (legacy and v0,
    # its lookups resolved from the block's own record), rebuilt as legacy:
    # same instructions, accounts, privileges, data and blockhash. Wallets
    # order read-only keys differently (some sort them), so bytes may differ.
    frames, rows = sample
    found = 0
    for i, r in enumerate(rows):
        t, _ = lm.simple_transfer(dict(r, row=i))
        if t is None:
            continue
        msg = wire.message(frames[i])
        payer, ixs = parts(msg, wire.account_keys(msg, r["loaded_writable"], r["loaded_readonly"]))
        rebuilt = wire.message(wire.build_legacy(payer, ixs, msg.blockhash))
        assert rebuilt.version == "legacy" and rebuilt.blockhash == msg.blockhash
        assert parts(rebuilt, wire.account_keys(rebuilt)) == (payer, ixs), i
        found += 1
    assert found >= 15


def test_a_built_transfer_checked_has_the_runtime_layout():
    owner, src, dst, mint = (solrpc.b58encode(bytes([n]) * 32) for n in (1, 2, 3, 4))
    frame = wire.build_legacy(owner, [wire.token_transfer_checked(src, mint, dst, owner, 7, 6)], bytes(range(32)))
    msg = wire.message(frame)
    assert frame[0] == 1 and frame[1:65] == bytes(64)  # one zeroed signature slot
    assert (msg.num_required_signatures, msg.num_readonly_signed, msg.num_readonly_unsigned) == (1, 0, 2)
    keys = wire.account_keys(msg)
    assert keys == [owner, src, dst, mint, lm.SPL_TOKEN_PROGRAM]
    (ix,) = msg.instructions
    assert [keys[a] for a in ix.accounts] == [src, mint, dst, owner]
    assert ix.data == bytes([12]) + (7).to_bytes(8, "little") + bytes([6])
    # A built frame is unsigned, so the measurement-side rewrite accepts it;
    # the same frame with its slot filled is refused.
    assert wire.blockhash(wire.patch_blockhash(frame, bytes(32))) == bytes(32)
    with pytest.raises(ValueError, match="signature"):
        wire.patch_blockhash(frame[:1] + b"\1" * 64 + frame[65:], bytes(32))
    with pytest.raises(ValueError):
        wire.build_legacy(owner, [], bytes(31))


@pytest.mark.parametrize("units,decimals,text", [(1, 9, "0.000000001"), (1, 6, "0.000001"), (1, 0, "1"),
                                                 (1_500_000, 6, "1.5"), (10**9, 9, "1"), (12, 1, "1.2")])
def test_amounts_are_stated_in_display_units_exactly(units, decimals, text):
    assert lm.ui_amount(units, decimals) == text


# ── Round 40 (measure): the honest-transfer pass ────────────────────────────

ALICE, BOB, CAROL, DAVE = (solrpc.b58encode(bytes([n]) * 32) for n in (11, 12, 13, 14))
ALICE_ATA, BOB_ATA, MINT = (solrpc.b58encode(bytes([n]) * 32) for n in (21, 22, 23))
CU_PRICE = (lm.COMPUTE_BUDGET_PROGRAM, [], bytes([3]) + (50_000).to_bytes(8, "little"))
CU_LIMIT = (lm.COMPUTE_BUDGET_PROGRAM, [], bytes([2]) + (1_000).to_bytes(4, "little"))


def chain_row(payer, ixs, err=False, **extra):
    """A sample row as `fetch` records it: the chain's (signed) bytes."""
    frame = bytearray(wire.build_legacy(payer, ixs, bytes(range(1, 33))))
    nsig = frame[0]
    frame[1 : 1 + 64 * nsig] = b"\x07" * (64 * nsig)
    return dict({"slot": 9, "version": "legacy", "b64": base64.b64encode(bytes(frame)).decode(), "err": err, "cu": 450,
                 "loaded_writable": [], "loaded_readonly": []}, **extra)


def honest_sample():
    nonce_advance = (lm.SYSTEM_PROGRAM, [(CAROL, False, True), (lm.SYSTEM_PROGRAM, False, False), (DAVE, True, False)],
                     (4).to_bytes(4, "little"))
    rows = [
        chain_row(ALICE, [CU_LIMIT, CU_PRICE, wire.system_transfer(ALICE, BOB, 5_000_000)]),         # 0 System
        chain_row(ALICE, [wire.token_transfer_checked(ALICE_ATA, MINT, BOB_ATA, ALICE, 250, 6)]),    # 1 token
        chain_row(CAROL, [wire.system_transfer(ALICE, BOB, 1)]),                                     # 2 someone else pays
        chain_row(ALICE, [wire.system_transfer(ALICE, BOB, 9)]),                                     # 3 duplicate of 0
        chain_row(ALICE, [wire.system_transfer(ALICE, DAVE, 9)], err=True),                          # 4 failed on chain
        chain_row(ALICE, [wire.system_transfer(ALICE, DAVE, 9), wire.system_transfer(ALICE, BOB, 1)]),  # 5 two transfers
        chain_row(DAVE, [nonce_advance, wire.system_transfer(DAVE, BOB, 3)]),                        # 6 durable nonce
        chain_row(DAVE, [wire.system_transfer(DAVE, DAVE, 3)]),                                      # 7 self-transfer
        chain_row(CAROL, [create_idempotent(CAROL, BOB_ATA, BOB), memo(),                            # 8 token, ATA + memo
                          wire.token_transfer_checked(ALICE_ATA, MINT, BOB_ATA, CAROL, 40, 6)]),
        chain_row(DAVE, [memo(), wire.system_transfer(DAVE, CAROL, 70)]),                            # 9 System + memo
        chain_row(DAVE, [(lm.SPL_TOKEN_PROGRAM, [(ALICE_ATA, False, True), (BOB_ATA, False, True), (DAVE, True, False)],
                          bytes([3]) + (5).to_bytes(8, "little"))]),                                 # 10 Token Transfer
        chain_row(DAVE, [create_idempotent(BOB, BOB_ATA, BOB),                                       # 11 ATA paid by another
                         wire.token_transfer_checked(ALICE_ATA, MINT, BOB_ATA, DAVE, 40, 6)]),
        chain_row(DAVE, [wire.system_transfer(DAVE, CAROL, 70), (JUPITER, [(DAVE, True, True)], b"\x01")]),  # 12 not simple
    ]
    return [dict(r, row=i) for i, r in enumerate(rows)]


def create_idempotent(payer, ata, owner):
    return (lm.ATA_PROGRAM, [(payer, True, True), (ata, False, True), (owner, False, False), (MINT, False, False),
                             (lm.SYSTEM_PROGRAM, False, False), (lm.SPL_TOKEN_PROGRAM, False, False)], b"\x01")


def memo():
    return (lm.MEMO_PROGRAMS[0], [], b"the original sender's words")


def test_only_executed_simple_transfers_by_their_own_fee_payer_are_taken():
    picked, stats = lm.honest_candidates(honest_sample(), 10)
    assert [(t["row"], t["kind"]) for t in picked] == [
        (0, "System Transfer"), (1, "SPL Token TransferChecked"), (9, "System Transfer"), (8, "SPL Token TransferChecked")]
    assert stats["set aside"] == {"sender is not the fee payer": 1, "duplicate sender, recipient and asset": 1,
                                  "durable nonce": 1, "self-transfer": 1,
                                  "SPL Token Transfer (no mint recorded for its source)": 1, "ATA created by another payer": 1}
    assert stats["by kind"] == {"System Transfer": 2, "SPL Token TransferChecked": 2}
    assert picked[0]["budget_source"] == "2 Compute Budget" and len(picked[0]["layout"]) == 3
    assert picked[3]["budget_source"] == "1 ATA CreateIdempotent"
    assert picked[2]["budget_source"] == "none"  # the memo is dropped
    assert [t["row"] for t in lm.honest_candidates(honest_sample(), 1)[0]] == [0]


def test_an_idempotent_ata_create_is_copied_and_declared_and_a_memo_is_dropped():
    picked, _ = lm.honest_candidates(honest_sample(), 10)
    token = next(t for t in picked if t["row"] == 8)
    frame, body = lm.honest_request(token, bytes(32))
    msg = wire.message(frame)
    keys = wire.account_keys(msg)
    assert [keys[ix.program_index] for ix in msg.instructions] == [lm.ATA_PROGRAM, lm.SPL_TOKEN_PROGRAM]
    assert body["transaction_instructions"] == [{
        "program_id": lm.ATA_PROGRAM, "instruction_discriminator": "01",
        "account_addresses": [CAROL, BOB_ATA, BOB, MINT, lm.SYSTEM_PROGRAM, lm.SPL_TOKEN_PROGRAM], "cpi_targets": []}]
    assert wire.privileges(msg, keys.index(BOB_ATA)) == (False, True) and wire.privileges(msg, 0) == (True, True)
    system = next(t for t in picked if t["row"] == 9)
    frame, body = lm.honest_request(system, bytes(32))
    assert [wire.account_keys(wire.message(frame))[ix.program_index] for ix in wire.message(frame).instructions] == [lm.SYSTEM_PROGRAM]
    assert body["transaction_instructions"] == []


def test_the_honest_request_is_a_new_unsigned_one_lamport_transfer_with_everything_stated():
    (sys_t, tok_t), _ = lm.honest_candidates(honest_sample(), 2)
    fresh = bytes(range(100, 132))
    frame, body = lm.honest_request(sys_t, fresh)
    msg = wire.message(frame)
    assert frame[1:65] == bytes(64) and msg.blockhash == fresh and msg.version == "legacy"
    keys = wire.account_keys(msg)
    assert keys[0] == ALICE  # the sender pays its own fee
    assert [(keys[ix.program_index], ix.data) for ix in msg.instructions] == [
        (lm.COMPUTE_BUDGET_PROGRAM, CU_LIMIT[2]), (lm.COMPUTE_BUDGET_PROGRAM, CU_PRICE[2]),
        (lm.SYSTEM_PROGRAM, (2).to_bytes(4, "little") + (1).to_bytes(8, "little"))]
    assert bytes(body["signed_transaction"]) == frame
    assert body["proposed_intent"]["intent_type"] == "transfer"
    assert body["proposed_intent"]["extracted_parameters"] == {"amount": "0.000000001", "destination": BOB, "input_token": "SOL"}
    assert body["program_id"] == lm.SYSTEM_PROGRAM and body["account_addresses"] == [ALICE, BOB]
    assert body["instruction_discriminator"] == "0200000001000000" and body["wallet_profile"] == "Gaming"
    assert [s["program_id"] for s in body["transaction_instructions"]] == [lm.COMPUTE_BUDGET_PROGRAM] * 2
    # Exactly the fields VerificationInput accepts (it refuses unknown ones).
    assert set(body) <= {"proposed_intent", "program_id", "protocol_version", "instruction_discriminator",
                         "account_addresses", "instruction_data", "cpi_targets", "wallet_profile", "behavior_evidence",
                         "compute_units", "account_writes", "cpi_hops", "signed_transaction", "transaction_instructions",
                         "cpi_trace", "uses_versioned_transaction", "lookup_table_count", "real_account_metas", "state_diff"}
    frame, body = lm.honest_request(tok_t, fresh)
    msg = wire.message(frame)
    keys = wire.account_keys(msg)
    (ix,) = msg.instructions
    assert keys[0] == ALICE and [keys[a] for a in ix.accounts] == [ALICE_ATA, MINT, BOB_ATA, ALICE]
    assert ix.data == bytes([12]) + (1).to_bytes(8, "little") + bytes([6])
    assert body["proposed_intent"]["extracted_parameters"] == {"amount": "0.000001", "destination": BOB_ATA, "input_token": MINT}
    # Never more than the original.
    capped = wire.message(lm.honest_request(dict(tok_t, original_amount=1), fresh, amount=5)[0])
    assert capped.instructions[0].data[1:9] == (1).to_bytes(8, "little")


def test_the_honest_pass_runs_first_and_reports_every_refusal():
    post_fn, get_fn, calls = fake_core([fixture("executable_approved"), fixture("blocked"), fixture("analysis_only")])
    rep = lm.replay(selected(1), honest_sample(), "http://core", "k", pace=0, l8=0, honest=2,
                    blockhash_fn=lambda: bytes(range(100, 132)), sleep=lambda s: None, post_fn=post_fn, get_fn=get_fn)
    h = rep["honest"]
    assert h["constructed"] == 2 and h["decisions"] == {"executable_approved": 1, "blocked": 1}
    assert h["decisions_by_kind"] == {"System Transfer": {"executable_approved": 1}, "SPL Token TransferChecked": {"blocked": 1}}
    bodies = [b for u, b in calls if u.endswith("/verify")]
    # honest first, then the replay; nothing goes anywhere but the local Core
    assert [(b.get("proposed_intent") or {}).get("extracted_parameters") is not None for b in bodies] == [True, True, False]
    assert all(u.startswith("http://core/") for u, _ in calls)
    assert all(not any(bytes(b["signed_transaction"])[1:65]) for b in bodies[:2])
    # the replay's numbers are the replay's alone
    assert rep["measured"] == 1 and rep["decisions"] == {"analysis_only": 1}
    md = lm.markdown(rep)
    assert "## Honest transfers: what an agent's own transaction gets" in md
    assert "constructed and verified: **2**" in md
    line = next(l for l in md.splitlines() if l.startswith("| 1 | SPL Token TransferChecked"))
    assert "`blocked`" in line and "InstructionError{0, Custom(1)}" in line
    assert md.index("## Honest transfers") < md.index("## Decisions (the replay")
    # Round 41: a refused honest transfer lists what it contains.
    detail = next(l for l in md.splitlines() if l.startswith("- row 1: "))
    assert "SetComputeUnit" in detail or "[0c]" in detail


def test_without_a_fresh_blockhash_nothing_is_built():
    post_fn, get_fn, calls = fake_core([fixture("blocked")])
    rep = lm.replay(selected(1), honest_sample(), "http://core", "k", pace=0, l8=0, honest=2, blockhash_fn=None,
                    sleep=lambda s: None, post_fn=post_fn, get_fn=get_fn)
    assert rep["honest"]["skipped"] == {"no RPC for a fresh blockhash": 2} and rep["honest"]["constructed"] == 0
    assert len(calls) == 1


# ── Round 40 (measure): signer debits, set beside the fee and the chain ────


def test_a_signer_debit_row_carries_the_fee_and_what_the_chain_did():
    tip = wire.system_transfer(ALICE, DAVE, 10_000)
    row = chain_row(ALICE, [CU_LIMIT, CU_PRICE, (JUPITER, [(ALICE, True, True), (BOB, False, True)], b"\xe5"), tip],
                    fee=5_050, pre_balances=[1_000_000, 0, 0, 0, 0, 0], post_balances=[984_950, 0, 10_000, 0, 0, 0])
    v = fixture("blocked")
    for l in v["layers"]:
        if l["layer"].startswith("L4"):
            l["status"], l["reason"] = "failed", ("State diff contradicts the manifest across 2 account(s): UndeclaredSignerLamportDebit: "
                                                  "the transaction's signers lose 10000 lamports beyond the fee, what stayed")
    v["scope"]["compute_budget"] = {"compute_unit_limit": 1000, "effective_compute_unit_limit": 1000,
                                    "compute_unit_price_micro_lamports": 50_000, "priority_fee_lamports": 50,
                                    "source": "compute_budget_instructions"}
    post_fn, get_fn, _ = fake_core([v])
    sel = selected(1)
    sel[0]["program_id"] = JUPITER
    rep = lm.replay(sel, [dict(row, row=0)], "http://core", "k", pace=0, l8=0, sleep=lambda s: None, post_fn=post_fn, get_fn=get_fn)
    f = rep["rows"][0]["fee_breakdown"]
    assert f["graphite_beyond_fee"] == 10_000 and f["signatures"] == 1 and f["precompile_signatures"] == 0
    assert (f["cu_price_micro_lamports"], f["cu_limit"], f["priority_fee"]) == (50_000, 1000, 50)
    assert f["expected_fee"] == 5_050 == f["chain_fee"]
    assert f["signer_deltas"] == [{"signer": ALICE, "delta": -15_050, "beyond_fee": 10_000}]
    assert f"System Transfer 10000 lamports {ALICE[:8]}→{DAVE[:8]}" in f["instructions"]
    md = lm.markdown(rep)
    assert "### Signer debits beyond the fee" in md
    line = next(l for l in md.splitlines() if l.startswith("| 0 |") and "µl" in l)
    assert "| 10000 | 1 (+0) | 50000 µl × 1000 → 50 | 5050 | 5050 |" in line and "(10000)" in line


def test_a_row_the_sample_recorded_without_meta_says_so():
    row = chain_row(ALICE, [wire.system_transfer(ALICE, BOB, 3)])
    f = lm.fee_breakdown(row, {"l4_reason_full": "1 lamports left this signer's wallet", "compute_budget": {"priority_fee_lamports": 0}})
    assert f["graphite_beyond_fee"] == 1 and f["chain_fee"] is None and "signer_deltas" not in f
    assert f["expected_fee"] == 5000


def test_the_mock_charges_agaves_fee_every_signature_and_the_priority_fee():
    # Round 40 (measure): the loopback mock the Core is dry-run against now
    # reports `fee` as Agave's simulate does (`fee_details.total_fee()`), with
    # the payer's post-state after it: 5,000 per signature plus price × limit.
    import mock_rpc

    two_signers = (lm.SYSTEM_PROGRAM, [(ALICE, True, True), (CAROL, True, True)], (2).to_bytes(4, "little") + (7).to_bytes(8, "little"))
    frame = wire.build_legacy(ALICE, [CU_LIMIT, CU_PRICE, two_signers], bytes(32))
    keys, delta, fee, _ = mock_rpc.effects(frame)
    assert fee == 2 * 5000 + 50 and delta[keys.index(ALICE)] == -(fee + 7) and delta[keys.index(CAROL)] == 7
    # no limit set: 200,000 per non-Compute-Budget instruction, rounded up
    frame = wire.build_legacy(ALICE, [CU_PRICE, wire.system_transfer(ALICE, BOB, 1)], bytes(32))
    assert mock_rpc.effects(frame)[2] == 5000 + 10_000
    assert mock_rpc.effects(wire.build_legacy(ALICE, [wire.system_transfer(ALICE, BOB, 1)], bytes(32)))[2] == 5000


def test_a_token_transfer_is_taken_when_the_block_names_its_mint():
    # SPL Token `Transfer` names no mint; with the block's token balances the
    # new transaction states it (and is a TransferChecked, decimals included).
    row = honest_sample()[10]
    msg = wire.message(base64.b64decode(row["b64"]))
    source_index = wire.account_keys(msg).index(ALICE_ATA)
    t, why = lm.simple_transfer(dict(row, pre_token_balances=[{"account_index": source_index, "mint": MINT, "decimals": 6}]))
    assert why is None and t["original_kind"] == "SPL Token Transfer" and (t["sender"], t["recipient"], t["mint"]) == (DAVE, BOB_ATA, MINT)
    frame, body = lm.honest_request(t, bytes(32))
    (ix,) = wire.message(frame).instructions
    assert ix.data == bytes([12]) + (1).to_bytes(8, "little") + bytes([6])
    assert body["proposed_intent"]["extracted_parameters"] == {"amount": "0.000001", "destination": BOB_ATA, "input_token": MINT}
    # A balance for another account does not name this one's mint.
    assert lm.simple_transfer(dict(row, pre_token_balances=[{"account_index": source_index + 1, "mint": MINT, "decimals": 6}]))[1] == \
        "SPL Token Transfer (no mint recorded for its source)"


def test_fetch_records_the_chains_fee_and_balances_beside_each_row():
    block = {"transactions": [
        {"transaction": ["AAA=", "base64"], "meta": {"fee": 5000, "preBalances": [10, 0], "postBalances": [4, 1]}},
        {"transaction": {"json": 1}},
        {"transaction": ["BBB=", "base64"], "meta": {"fee": 10000, "preBalances": [1], "postBalances": [1],
                                                     "preTokenBalances": [{"accountIndex": 2, "mint": MINT, "owner": BOB,
                                                                           "uiTokenAmount": {"decimals": 6, "amount": "9"}}]}},
    ]}
    rows = [{"b64": "AAA="}, {"b64": "BBB="}]
    out = lm.with_chain_meta(rows, block)
    assert [(r["fee"], r["pre_balances"], r["post_balances"]) for r in out] == [(5000, [10, 0], [4, 1]), (10000, [1], [1])]
    # Round 41: the owner and amount too, before and after (the swap pass reads what the wallet gave and got).
    assert out[1]["pre_token_balances"] == [{"account_index": 2, "mint": MINT, "owner": BOB, "amount": "9", "decimals": 6}]
    assert out[0]["pre_token_balances"] == [] and out[1]["post_token_balances"] == [] == out[0]["post_token_balances"]
    # Not paired: nothing is attributed.
    assert lm.with_chain_meta([{"b64": "AAA="}], block) == [{"b64": "AAA="}]
    assert lm.with_chain_meta([{"b64": "XXX="}, {"b64": "BBB="}], block) == [{"b64": "XXX="}, {"b64": "BBB="}]


# ── the honest-swap pass (Round 41) ──────────────────────────────────────────

import honest_swaps as hs  # noqa: E402

CPMM_SELECTOR = bytes.fromhex("8fbe5adac41e33de")
WALLET, POOL, VAULT_IN, VAULT_OUT, USDC, BONK, W_USDC, W_BONK, W_WSOL, TIPPER = (
    solrpc.b58encode(bytes([n]) * 32) for n in range(31, 41))
CB = (hs.COMPUTE_BUDGET_PROGRAM, [], bytes([2]) + (200_000).to_bytes(4, "little"))


def cpmm(src, dst, amount, minimum=7):
    """A Raydium CPMM swap_base_input: the wallet signs; its input and output
    accounts, the pool and its vaults are named."""
    return (hs.RAYDIUM_CPMM,
            [(WALLET, True, True), (POOL, False, True), (src, False, True), (dst, False, True),
             (VAULT_IN, False, True), (VAULT_OUT, False, True)],
            CPMM_SELECTOR + amount.to_bytes(8, "little") + minimum.to_bytes(8, "little"))


def swap_row(instructions, pre, post, *, fee=5000, lamports=(10**9, 10**9 - 5000), err=None):
    """A sample row as fetch records it: `pre` / `post` are (account, mint,
    owner, amount) token balances, indexed against the built frame."""
    frame = wire.build_legacy(WALLET, instructions, bytes(32))
    keys = wire.account_keys(wire.message(frame))
    bal = lambda side: [{"account_index": keys.index(a), "mint": m, "owner": o, "amount": str(n), "decimals": 6}  # noqa: E731
                        for a, m, o, n in side]
    return {"row": 3, "slot": 9, "b64": base64.b64encode(frame).decode(), "err": err, "fee": fee,
            "pre_balances": [lamports[0]] + [0] * (len(keys) - 1), "post_balances": [lamports[1]] + [0] * (len(keys) - 1),
            "pre_token_balances": bal(pre), "post_token_balances": bal(post)}, frame


def usdc_to_bonk(extra=()):
    return swap_row([CB, cpmm(W_USDC, W_BONK, 2_000_000), *extra],
                    pre=[(W_USDC, USDC, WALLET, 5_000_000), (W_BONK, BONK, WALLET, 0)],
                    post=[(W_USDC, USDC, WALLET, 3_000_000), (W_BONK, BONK, WALLET, 900)])


def test_the_swap_layouts_are_the_cores():
    data = CPMM_SELECTOR + (5).to_bytes(8, "little") + (9).to_bytes(8, "little")
    assert hs.venue(hs.RAYDIUM_CPMM, data) == ("Raydium CPMM swap_base_input", "in_min8")
    assert hs.amount_in("in_min8", data) == 5 and hs.minimum_of("in_min8", data) == 9
    assert hs.minimum_of("in_min8", hs.with_minimum("in_min8", data, 1000, 50)) == 995
    assert hs.minimum_of("in_min8", hs.with_minimum("in_min8", data, 1, 0)) == 1
    v4 = bytes([9]) + (5).to_bytes(8, "little") + (9).to_bytes(8, "little")
    assert hs.venue(hs.RAYDIUM_AMM_V4, v4)[1] == "in_min1" and hs.amount_in("in_min1", v4) == 5
    assert hs.minimum_of("in_min1", hs.with_minimum("in_min1", v4, 2000, 50)) == 1990
    # Jupiter: the last 19 bytes are in_amount, quoted_out_amount, slippage_bps, platform_fee_bps.
    route = bytes.fromhex("e517cb977ae3ad2a") + b"\x01\x02plan" + (7).to_bytes(8, "little") + (100).to_bytes(8, "little") \
        + (30).to_bytes(2, "little") + b"\x00"
    assert hs.venue(hs.JUPITER_V6, route)[1] == "jupiter" and hs.amount_in("jupiter", route) == 7
    assert hs.minimum_of("jupiter", route) == 99
    patched = hs.with_minimum("jupiter", route, 4000, 50)
    assert patched[:-11] == route[:-11] and patched[-1:] == b"\x00" and hs.minimum_of("jupiter", patched) == 3980
    assert hs.venue(hs.JUPITER_V6, route[:-1] + b"\x05") == (None, "Jupiter route with a platform fee (the Core refuses one)")
    # Concentrated: an exact-output swap is not bound by the Core, so not built.
    clmm = bytes.fromhex("f8c69e91e17587c8") + (5).to_bytes(8, "little") + (9).to_bytes(8, "little") + bytes(16)
    assert hs.venue(hs.RAYDIUM_CLMM, clmm + b"\x01")[1] == "concentrated"
    assert hs.venue(hs.RAYDIUM_CLMM, clmm + b"\x00")[0] is None
    assert hs.venue(hs.RAYDIUM_CPMM, bytes(24)) == (None, "Raydium CPMM instruction 0000000000000000 (not an exact-in swap the Core decodes)")
    assert hs.venue(hs.SYSTEM_PROGRAM, data) is None


def _route_v2(shared, amount=7, quoted=100, slippage=30, platform=0, positive=0, plan=b"\x01\x00\x00\x00\x1a\x10\x27\x00\x01"):
    head = bytes.fromhex("d19853937cfed8e9" if shared else "bb64facc31c4af14") + (b"\x03" if shared else b"")
    return head + amount.to_bytes(8, "little") + quoted.to_bytes(8, "little") + slippage.to_bytes(2, "little") \
        + platform.to_bytes(2, "little") + positive.to_bytes(2, "little") + plan


def test_a_jupiter_v2_route_is_read_at_its_fixed_offsets():
    # Round 41 (D-23): route_v2 / shared_accounts_route_v2 carry their amounts
    # first (after shared's id byte), the route plan last.
    for shared, name in ((False, "Jupiter v6 route_v2"), (True, "Jupiter v6 shared_accounts_route_v2")):
        route = _route_v2(shared)
        assert hs.venue(hs.JUPITER_V6, route) == (name, "jupiter_v2")
        assert hs.amount_in("jupiter_v2", route) == 7 and hs.minimum_of("jupiter_v2", route) == 99
        patched = hs.with_minimum("jupiter_v2", route, 4000, 50)
        assert len(patched) == len(route) and hs.minimum_of("jupiter_v2", patched) == 3980
        assert hs.amount_in("jupiter_v2", patched) == 7
        # Only quoted_out_amount and slippage_bps changed: fees and plan are kept.
        at = 9 if shared else 8
        assert patched[: at + 8] == route[: at + 8] and patched[at + 18 :] == route[at + 18 :]


def test_a_jupiter_v2_route_with_a_fee_or_cut_short_is_not_built():
    for shared in (False, True):
        assert hs.venue(hs.JUPITER_V6, _route_v2(shared, platform=5)) == (
            None, "Jupiter route with a platform fee (the Core refuses one)")
        assert hs.venue(hs.JUPITER_V6, _route_v2(shared, positive=5)) == (
            None, "Jupiter v2 route with a positive-slippage fee (the Core refuses one)")
        cut = _route_v2(shared, plan=b"")[:-1]
        assert hs.venue(hs.JUPITER_V6, cut)[0] is None


def test_an_honest_direct_swap_is_a_candidate_with_what_the_wallet_gave_and_got():
    row, _ = usdc_to_bonk()
    c, why = hs.swap_candidate(row)
    assert why is None
    assert (c["venue"], c["asset_in"], c["asset_out"], c["amount_in"], c["decimals_in"]) == \
        ("Raydium CPMM swap_base_input", USDC, BONK, 2_000_000, 6)
    assert c["index"] == 1 and c["watch"] == [W_BONK] and c["sender"] == WALLET


def test_a_swap_beside_a_tip_or_another_signer_is_set_aside_by_reason():
    row, _ = usdc_to_bonk([wire.system_transfer(WALLET, TIPPER, 10_000)])
    assert hs.swap_candidate(row) == (None, "a SOL transfer beside the swap (a tip or a payment)")
    row, _ = usdc_to_bonk([wire.token_transfer_checked(W_USDC, USDC, ALICE_ATA, WALLET, 1, 6)])
    assert hs.swap_candidate(row) == (None, "another program beside the swap")
    row, _ = usdc_to_bonk([(hs.SPL_TOKEN_PROGRAM, [(W_BONK, False, True), (TIPPER, False, True), (WALLET, True, False)], b"\x09")])
    assert hs.swap_candidate(row) == (None, "an account closed to someone else")
    two = swap_row([cpmm(W_USDC, W_BONK, 1), (hs.MEMO_PROGRAMS[0], [(TIPPER, True, False)], b"hi")],
                   pre=[(W_USDC, USDC, WALLET, 5)], post=[(W_BONK, BONK, WALLET, 1)])[0]
    assert hs.swap_candidate(two) == (None, "more than one signer")
    failed, _ = swap_row([cpmm(W_USDC, W_BONK, 1)], pre=[], post=[], err={"InstructionError": [0, "X"]})
    assert hs.swap_candidate(failed) == (None, None)
    no_owner, _ = usdc_to_bonk()
    no_owner["pre_token_balances"][0]["owner"] = None
    assert hs.swap_candidate(no_owner) == (None, "the block's token balances name no owners")


def test_wrapping_and_unwrapping_its_own_sol_is_part_of_the_swap():
    sync = (hs.SPL_TOKEN_PROGRAM, [(W_WSOL, False, True)], b"\x11")
    close = (hs.SPL_TOKEN_PROGRAM, [(W_WSOL, False, True), (WALLET, False, True), (WALLET, True, False)], b"\x09")
    row, _ = swap_row([CB, wire.system_transfer(WALLET, W_WSOL, 3_000_000), sync, cpmm(W_WSOL, W_BONK, 3_000_000), close],
                      pre=[(W_WSOL, hs.NATIVE_MINT, WALLET, 0), (W_BONK, BONK, WALLET, 0)],
                      post=[(W_BONK, BONK, WALLET, 777)], lamports=(10**9, 10**9 - 3_005_000))
    c, why = hs.swap_candidate(row)
    assert why is None and (c["asset_in"], c["asset_out"], c["decimals_in"]) == ("SOL", BONK, 9)
    # BONK for SOL, unwrapped: the output is SOL, quoted on the wallet itself.
    row, _ = swap_row([cpmm(W_BONK, W_WSOL, 500), close],
                      pre=[(W_BONK, BONK, WALLET, 500), (W_WSOL, hs.NATIVE_MINT, WALLET, 0)],
                      post=[(W_BONK, BONK, WALLET, 0)], lamports=(10**9, 10**9 + 40_000))
    c, why = hs.swap_candidate(row)
    assert why is None and (c["asset_in"], c["asset_out"]) == (BONK, "SOL") and c["watch"] == [WALLET, W_WSOL]


def test_only_the_swap_data_and_blockhash_change_in_the_rebuilt_frame():
    row, frame = usdc_to_bonk()
    c, _ = hs.swap_candidate(row)
    built, data = hs.build(frame, c, 1000, 50, bytes([7]) * 32)
    old, new = wire.message(frame), wire.message(built)
    assert new.blockhash == bytes([7]) * 32 and new.static_keys == old.static_keys
    assert [ix.data for ix in new.instructions] == [old.instructions[0].data, data]
    assert hs.minimum_of("in_min8", data) == 995 and hs.amount_in("in_min8", data) == 2_000_000
    with pytest.raises(ValueError, match="replacement is"):
        wire.patch_instruction_data(frame, 1, b"short")
    signed = bytes([1]) + bytes([9]) * 64 + bytes(frame[65:])
    with pytest.raises(ValueError, match="carries a signature"):
        wire.patch_instruction_data(signed, 1, data)


def fake_rpc(before, after, err=None):
    calls = []

    def call(url, method, params, **kw):
        calls.append(method)
        acct = lambda n: None if n is None else {"lamports": n if isinstance(n, int) and n > 10**6 else 2039280,  # noqa: E731
                                                  "data": [base64.b64encode(bytes(64) + int(n).to_bytes(8, "little")).decode(), "base64"]}
        if method == "getMultipleAccounts":
            return {"result": {"value": [acct(n) for n in before]}}
        if method == "simulateTransaction":
            return {"result": {"value": {"err": err, "accounts": [acct(n) for n in after]}}}
        raise AssertionError(method)
    return call, calls


def test_the_quote_is_what_the_simulation_delivers_to_the_wallet():
    row, frame = usdc_to_bonk()
    c, _ = hs.swap_candidate(row)
    call, calls = fake_rpc([100], [1100])
    assert hs.quote("rpc", frame, c, call=call) == 1000 and calls == ["getMultipleAccounts", "simulateTransaction"]
    call, _ = fake_rpc([None], [640])  # the output account is created by the swap
    assert hs.quote("rpc", frame, c, call=call) == 640
    with pytest.raises(hs.QuoteFailed) as e:
        hs.quote("rpc", frame, c, call=fake_rpc([100], [100], err={"InstructionError": [1, {"Custom": 6005}]})[0])
    assert e.value.sim_err == {"InstructionError": [1, {"Custom": 6005}]}
    with pytest.raises(hs.QuoteFailed, match="delivered nothing"):
        hs.quote("rpc", frame, c, call=fake_rpc([100], [100])[0])
    # SOL out: the wallet's lamports, plus the fee it paid (what reached it before the fee).
    sol = dict(c, asset_out="SOL", watch=[WALLET], fee=5000)
    call, _ = fake_rpc([2 * 10**9], [2 * 10**9 + 35_000])
    assert hs.quote("rpc", frame, sol, call=call) == 40_000


def test_the_swap_pass_verifies_the_requoted_swap_with_a_swap_intent():
    row, frame = usdc_to_bonk()
    harness = {"program_id": hs.RAYDIUM_CPMM, "instruction_data": [0], "signed_transaction": list(frame),
               "proposed_intent": {"intent_type": "unknown"}, "wallet_profile": "Gaming"}
    sent = []

    def post_fn(url, key, body):
        sent.append(body)
        return 200, {"decision": "executable_approved", "executable": True, "approved": True, "layers": []}

    call, _ = fake_rpc([0], [20_000])
    report = lm.replay([], [row], "http://core", "", swaps=5, requests_by_row={3: {"row": 3, "input": harness}},
                       rpc="rpc", rpc_call=call, blockhash_fn=lambda: bytes([5]) * 32, sleep=lambda s: None,
                       post_fn=post_fn, get_fn=lambda url: {"verification_mode": "executable", "rpc_attached": True})
    s = report["swaps"]
    assert s["constructed"] == 1 and s["decisions"] == {"executable_approved": 1}
    (body,) = sent
    assert body["proposed_intent"]["intent_type"] == "swap"
    assert body["proposed_intent"]["extracted_parameters"] == {"amount": "2", "input_token": USDC, "output_token": BONK,
                                                               "slippage_bps": 100}
    msg = wire.message(bytes(body["signed_transaction"]))
    assert msg.blockhash == bytes([5]) * 32 and hs.minimum_of("in_min8", msg.instructions[1].data) == 19_900
    assert body["instruction_data"] == list(msg.instructions[1].data)
    assert s["rows"][0]["quoted"] == 20_000 and s["rows"][0]["minimum"] == 19_900
    md = "\n".join(lm.swaps_markdown(s))
    assert "Honest swaps" in md and "Raydium CPMM swap_base_input" in md


def test_a_swap_that_does_not_simulate_now_is_counted_not_verified():
    row, frame = usdc_to_bonk()
    harness = {"program_id": hs.RAYDIUM_CPMM, "signed_transaction": list(frame)}
    call, _ = fake_rpc([0], [0], err={"InstructionError": [1, {"Custom": 1}]})
    report = lm.replay([], [row], "http://core", "", swaps=5, requests_by_row={3: {"row": 3, "input": harness}},
                       rpc="rpc", rpc_call=call, blockhash_fn=lambda: bytes(32), sleep=lambda s: None,
                       post_fn=lambda *a: pytest.fail("nothing is verified without a quote"),
                       get_fn=lambda url: {"verification_mode": "executable", "rpc_attached": True})
    assert report["swaps"]["constructed"] == 0
    assert report["swaps"]["skipped"] == {"no quote: the swap does not simulate now (InstructionError{1, Custom(1)})": 1}
    # No harness request, or no RPC: counted as not built.
    report = lm.replay([], [row], "http://core", "", swaps=5, requests_by_row={}, rpc=None, sleep=lambda s: None,
                       post_fn=lambda *a: pytest.fail("unreachable"),
                       get_fn=lambda url: {"verification_mode": "executable", "rpc_attached": True})
    assert report["swaps"]["skipped"] == {"the harness built no request for the row": 1}


def test_a_transfer_the_chain_would_reject_now_is_counted_not_verified():
    """Round 41: run 41129142710 refused 12 honest transfers, 11 of them ones
    the chain itself would reject (the sender's account gone; 1 lamport into
    an account that does not exist). Pre-simulated, they are counted; one
    under the rent minimum is rebuilt once with the original's amount."""
    sims = []

    def rpc_call(url, method, params, **kw):
        assert method == "simulateTransaction" and params[1]["sigVerify"] is False
        msg = wire.message(base64.b64decode(params[0]))
        data = msg.instructions[-1].data
        sims.append(data)
        if data[:4] == (2).to_bytes(4, "little") and int.from_bytes(data[4:12], "little") == 1:
            return {"result": {"value": {"err": {"InsufficientFundsForRent": {"account_index": 1}}}}}
        if data[:1] == b"\x0c":
            return {"result": {"value": {"err": "AccountNotFound"}}}
        return {"result": {"value": {"err": None}}}

    post_fn, get_fn, calls = fake_core([fixture("executable_approved"), fixture("analysis_only")])
    rep = lm.replay(selected(1), honest_sample(), "http://core", "k", pace=0, l8=0, honest=2,
                    blockhash_fn=lambda: bytes(range(100, 132)), sleep=lambda s: None, post_fn=post_fn,
                    get_fn=get_fn, rpc="rpc", rpc_call=rpc_call)
    h = rep["honest"]
    assert h["skipped"] == {"the chain would reject it now (AccountNotFound)": 1}
    assert h["constructed"] == 1 and h["rebuilt_with_original_amount"] == 1
    (row,) = h["rows"]
    # The System transfer, rebuilt with its original amount, is what was verified.
    body = next(b for u, b in calls if u.endswith("/verify") and (b.get("proposed_intent") or {}).get("extracted_parameters"))
    sent = wire.message(bytes(body["signed_transaction"])).instructions[-1].data
    assert int.from_bytes(sent[4:12], "little") > 1 and row["kind"] == "System Transfer"
    md = lm.markdown(rep)
    assert "the chain would reject it now (AccountNotFound)" in md and "rebuilt with the original's amount (rent minimum): 1" in md
    # An RPC failure during pre-simulation is counted, never verified blind.
    def broken(url, method, params, **kw):
        return {"error": {"code": -32005, "message": "busy"}}
    post_fn, get_fn, calls = fake_core([fixture("analysis_only")])
    rep = lm.replay(selected(1), honest_sample(), "http://core", "k", pace=0, l8=0, honest=2,
                    blockhash_fn=lambda: bytes(32), sleep=lambda s: None, post_fn=post_fn, get_fn=get_fn,
                    rpc="rpc", rpc_call=broken)
    assert rep["honest"]["skipped"] == {"not pre-simulated (RpcError)": 2} and rep["honest"]["constructed"] == 0


def test_a_refused_swap_names_its_original_transaction_and_accounts():
    row, frame = usdc_to_bonk()
    harness = {"program_id": hs.RAYDIUM_CPMM, "signed_transaction": list(frame)}
    call, _ = fake_rpc([0], [20_000])
    post_fn, get_fn, _ = fake_core([fixture("blocked")])
    report = lm.replay([], [row], "http://core", "", swaps=5, requests_by_row={3: {"row": 3, "input": harness}},
                       rpc="rpc", rpc_call=call, blockhash_fn=lambda: bytes(32), sleep=lambda s: None,
                       post_fn=post_fn, get_fn=get_fn)
    (r,) = report["swaps"]["rows"]
    assert r["decision"] == "blocked" and r["original_signature"] == solrpc.b58encode(bytes(64))
    assert r["swap_accounts"][0] == (WALLET, True, True) and r["swap_accounts"][2] == (W_USDC, False, True)
    md = "\n".join(lm.swaps_markdown(report["swaps"]))
    assert f"- row 3 (`{solrpc.b58encode(bytes(64))}`): 0:`{WALLET[:8]}`sw" in md


def v1_frame(keys, instructions, *, priority_fee=None, cu_limit=None):
    """A v1 frame (SIMD-0385 layout, as wire._message_v1 reads it): one
    signer, the rest read-only unsigned past the writable ones; `instructions`
    are (program index, account indexes, data)."""
    mask = (wire.V1_MASK_PRIORITY_FEE if priority_fee is not None else 0) | (wire.V1_MASK_COMPUTE_UNIT_LIMIT if cu_limit is not None else 0)
    out = bytearray([wire.V1_PREFIX, 1, 0, 1]) + mask.to_bytes(4, "little") + bytes([7]) * 32
    out += bytes([len(instructions), len(keys)]) + b"".join(solrpc.b58decode(k) for k in keys)
    if priority_fee is not None:
        out += priority_fee.to_bytes(8, "little")
    if cu_limit is not None:
        out += cu_limit.to_bytes(4, "little")
    for p, accts, data in instructions:
        out += bytes([p, len(accts)]) + len(data).to_bytes(2, "little")
    for p, accts, data in instructions:
        out += bytes(accts) + data
    return bytes(out) + bytes(64)


def test_a_v1_frame_has_its_swap_data_patched_in_place():
    """Round 41: run 41137247587 set aside 10 of 40 swaps as v1 frames; the
    patch reads v1's header table to find each instruction's data."""
    data = CPMM_SELECTOR + (2_000_000).to_bytes(8, "little") + (7).to_bytes(8, "little")
    keys = [WALLET, POOL, W_USDC, W_BONK, VAULT_IN, VAULT_OUT, hs.RAYDIUM_CPMM]
    frame = v1_frame(keys, [(6, [0, 1, 2, 3, 4, 5], data), (6, [0], b"\x01\x02")], priority_fee=5000, cu_limit=200_000)
    before = wire.message(frame)
    assert before.version == "1" and [ix.data for ix in before.instructions] == [data, b"\x01\x02"]
    spans = wire.instruction_data_spans(frame)
    assert [frame[a:b] for a, b in spans] == [data, b"\x01\x02"]
    new = hs.with_minimum("in_min8", data, 1000, 50)
    after = wire.message(wire.patch_instruction_data(frame, 0, new))
    assert [ix.data for ix in after.instructions] == [new, b"\x01\x02"]
    assert after.static_keys == before.static_keys and after.v1_config == before.v1_config
    assert after.blockhash == before.blockhash
    with pytest.raises(ValueError, match="carries a signature"):
        wire.patch_instruction_data(frame[:-64] + bytes([1]) * 64, 0, new)
    # A v1 swap is a candidate now (it was set aside as "v1 frame").
    pre = [{"account_index": 2, "mint": USDC, "owner": WALLET, "amount": "5000000", "decimals": 6},
           {"account_index": 3, "mint": BONK, "owner": WALLET, "amount": "0", "decimals": 6}]
    post = [{"account_index": 2, "mint": USDC, "owner": WALLET, "amount": "3000000", "decimals": 6},
            {"account_index": 3, "mint": BONK, "owner": WALLET, "amount": "900", "decimals": 6}]
    row = {"row": 1, "slot": 1, "b64": base64.b64encode(v1_frame(keys, [(6, [0, 1, 2, 3, 4, 5], data)])).decode(),
           "err": None, "fee": 5000, "pre_balances": [10**9] + [0] * 6, "post_balances": [10**9 - 5000] + [0] * 6,
           "pre_token_balances": pre, "post_token_balances": post}
    c, why = hs.swap_candidate(row)
    assert why is None and c["version"] == "1" and c["asset_in"] == USDC and c["asset_out"] == BONK
