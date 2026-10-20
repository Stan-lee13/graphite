#!/usr/bin/env python3
"""Tests for the mainnet-sample tools. No network: the RPC is replaced.

Round 29 (audit 2026-10-20, M1-M3). Run with `python3 -m pytest` or directly
(`python3 test_mainnet_sample.py`, standard library only).
"""
import io
import json
import os
import sys
import tempfile
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import fetch_mainnet  # noqa: E402
import verify_sample  # noqa: E402

SLICE = os.path.join(HERE, "..", "..", "graphite-core", "fixtures", "mainnet", "sample-2026-09-23-last-2-blocks.json")


class _Patch:
    def __init__(self):
        self._undo = []

    def set(self, target, name, value):
        old = getattr(target, name)
        self._undo.append(lambda: setattr(target, name, old))
        setattr(target, name, value)

    def undo(self):
        while self._undo:
            self._undo.pop()()


def _block_from_rows(rows):
    """A getBlock result that holds exactly these recorded rows."""
    return {
        "transactions": [
            {
                "transaction": [r["b64"], "base64"],
                "version": r["version"],
                "meta": {
                    "err": {"InstructionError": [0, "Custom"]} if r["err"] else None,
                    "computeUnitsConsumed": r["cu"],
                    "loadedAddresses": {"writable": r["loaded_writable"], "readonly": r["loaded_readonly"]},
                },
            }
            for r in rows
        ]
    }


def _fake_rpc(blocks):
    """An RPC that serves `blocks` ({slot: result}) and errors for any other
    slot, the way an endpoint answers a slot it cannot return."""

    def rpc(method, params, **_kw):
        assert method == "getBlock", method
        slot = params[0]
        if slot in blocks:
            return {"jsonrpc": "2.0", "id": 1, "result": blocks[slot]}
        return {"jsonrpc": "2.0", "id": 1, "error": {"code": -32009, "message": f"Slot {slot} was skipped, or missing"}}

    return rpc


def _quiet(fn, *args, **kwargs):
    old = sys.stdout
    sys.stdout = io.StringIO()
    try:
        return fn(*args, **kwargs)
    finally:
        sys.stdout = old


def test_a_requested_slot_that_cannot_be_fetched_fails_with_no_file():
    # M1: it printed "skipped", wrote the file without that block, exit 0.
    p = _Patch()
    p.set(fetch_mainnet, "PAUSE_S", 0)
    p.set(fetch_mainnet, "rpc", _fake_rpc({10: {"transactions": []}}))
    try:
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "s.json")
            try:
                _quiet(fetch_mainnet.main, ["--slots", "10,11", "--out", out])
            except SystemExit as e:
                assert e.code not in (0, None), e.code
                assert "slot 11" in str(e.code)
            else:
                raise AssertionError("a missing requested slot must fail the run")
            assert not os.path.exists(out), "no file may be written for an incomplete sample"
    finally:
        p.undo()


def test_counting_back_from_the_head_still_skips_a_skipped_slot():
    # Without --slots the blocks are counted back from the head, where a
    # leader's skipped slot is ordinary: reported and left out.
    p = _Patch()
    p.set(fetch_mainnet, "rpc", _fake_rpc({10: {"transactions": []}}))
    try:
        rows, fetched = _quiet(fetch_mainnet.fetch, [10, 11], False, 0)
    finally:
        p.undo()
    assert fetched == [10] and rows == []


def test_the_endpoint_kind_says_whose_endpoint_it_was():
    # M3: always "public mainnet", even with GRAPHITE_RPC_URL set.
    assert fetch_mainnet.endpoint_kind({}) == "public mainnet"
    assert fetch_mainnet.endpoint_kind({"GRAPHITE_RPC_URL": ""}) == "public mainnet"
    kind = fetch_mainnet.endpoint_kind({"GRAPHITE_RPC_URL": "https://rpc.example/?api-key=SECRET"})
    assert kind.startswith("operator-supplied"), kind
    assert "SECRET" not in kind and "rpc.example" not in kind, "the URL (and any key in it) is never recorded"


def test_network_failures_and_429_stop_cleanly():
    p = _Patch()
    p.set(fetch_mainnet, "PAUSE_S", 0)
    calls = []

    def unreachable(*_a, **_kw):
        calls.append(1)
        raise urllib.error.URLError("Name or service not known")

    p.set(fetch_mainnet.urllib.request, "urlopen", unreachable)
    try:
        try:
            _quiet(fetch_mainnet.rpc, "getSlot", [], attempts=3)
        except SystemExit as e:
            assert e.code not in (0, None)
            assert "URLError" in str(e.code)
        else:
            raise AssertionError("URLError must stop the run")
        assert len(calls) == 3, "retried, then reported"

        def throttled(*_a, **_kw):
            raise urllib.error.HTTPError("u", 429, "Too Many Requests", {}, None)

        p.set(fetch_mainnet.urllib.request, "urlopen", throttled)
        try:
            fetch_mainnet.rpc("getSlot", [])
        except SystemExit as e:
            assert "429" in str(e.code)
        else:
            raise AssertionError("429 must stop the run")
    finally:
        p.undo()


def test_compare_rows_finds_every_kind_of_difference():
    a = [{"slot": 1, "version": "0", "b64": "AA", "err": False, "cu": 5, "loaded_writable": [], "loaded_readonly": []}]
    assert verify_sample.compare_rows(a, [dict(a[0])]) == ([], 0)
    for field, value in (("b64", "AB"), ("err", True), ("cu", 6), ("loaded_readonly", ["x"]), ("version", "1")):
        diffs, total = verify_sample.compare_rows(a, [{**a[0], field: value}])
        assert total == 1 and field in diffs[0], (field, diffs)
    diffs, total = verify_sample.compare_rows(a, [])
    assert total == 1 and "row count" in diffs[0]


def test_the_committed_slice_round_trips_through_a_refetch():
    # M2: the slice's blocks, served by an endpoint, refetched and compared
    # field for field — the check SAMPLES.md now points to.
    with open(SLICE, encoding="utf-8") as f:
        sample = json.load(f)
    slots = verify_sample.recorded_slots(sample)
    # The rows run newest block first (the source sample was fetched head
    # first); the slice's `slots` field is ascending. Fetch in row order.
    assert slots == [449808725, 449808325]
    assert sorted(slots) == sample["slots"]
    blocks = {s: _block_from_rows([r for r in sample["rows"] if r["slot"] == s]) for s in slots}
    p = _Patch()
    p.set(fetch_mainnet, "PAUSE_S", 0)
    p.set(fetch_mainnet, "rpc", _fake_rpc(blocks))
    try:
        assert _quiet(verify_sample.main, [SLICE]) == 0
        # One changed byte in one row of one block is found.
        rows = list(sample["rows"])
        i = len(rows) // 2
        tampered = dict(blocks)
        bad = [dict(r) for r in rows if r["slot"] == rows[i]["slot"]]
        j = next(k for k, r in enumerate(bad) if r["b64"] == rows[i]["b64"])
        bad[j]["b64"] = ("B" if bad[j]["b64"][0] != "B" else "C") + bad[j]["b64"][1:]
        tampered[rows[i]["slot"]] = _block_from_rows(bad)
        p.set(fetch_mainnet, "rpc", _fake_rpc(tampered))
        assert _quiet(verify_sample.main, [SLICE]) == 1
        # A slot the endpoint cannot return fails the verification outright.
        p.set(fetch_mainnet, "rpc", _fake_rpc({slots[0]: blocks[slots[0]]}))
        try:
            _quiet(verify_sample.main, [SLICE])
        except SystemExit as e:
            assert e.code not in (0, None)
        else:
            raise AssertionError("a missing slot must fail verification")
    finally:
        p.undo()


def test_samples_that_predate_the_slots_field_are_read_by_their_rows():
    rows = [{"slot": 7}, {"slot": 7}, {"slot": 3}]
    assert verify_sample.recorded_slots({"rows": rows}) == [7, 3]


if __name__ == "__main__":
    tests = [(n, f) for n, f in list(globals().items()) if n.startswith("test_") and callable(f)]
    for name, fn in tests:
        fn()
        print(f"✓ {name}")
    print(f"\n{len(tests)} mainnet-sample tests passed.")
