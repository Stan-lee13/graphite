#!/usr/bin/env python3
"""Check that a recorded mainnet sample is what its slots say it is.

Round 29 (audit 2026-10-20, M2): SAMPLES.md said refetching a sample's slots
"gives the same rows", and the committed slice's notes said "regenerating it
gives the same bytes" — but no tool compared anything. A refetch cannot hash
to a recorded file's SHA-256 (the fetcher now also writes a `slots` field the
recorded files predate), so the hash cannot be the check. This is the check:
the recorded file's slots are fetched again and every row compared, field by
field, in order.

  verify_sample.py <recorded.json>                    refetch its slots, compare
  verify_sample.py <recorded.json> --against <f.json> compare with a file you
                                                      fetched yourself (offline)

Every field a row carries is compared — slot, version, the transaction's
base64 bytes, whether it failed, compute units, and the lookup-table
addresses it loaded. None is volatile for a finalized block, so nothing is
ignored. Exit 0 and "IDENTICAL" when every row matches; exit 1 with the first
differences otherwise. A refetch goes through fetch_mainnet.py's reader: the
same endpoint rules, the same pause between blocks, a stop on a 429, and a
failure if any slot cannot be fetched.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fetch_mainnet  # noqa: E402

ROW_FIELDS = ("slot", "version", "b64", "err", "cu", "loaded_writable", "loaded_readonly")


def recorded_slots(sample):
    """The slots a sample holds, in the order its rows hold them — the order
    to fetch them in, since rows are compared in order. (The recorded samples
    were fetched head first, so their rows run newest block first, while the
    committed slice lists its `slots` ascending.) A slot listed in `slots`
    with no rows (a block with no transactions) is appended."""
    seen = []
    for r in sample["rows"]:
        if r["slot"] not in seen:
            seen.append(r["slot"])
    for s in sample.get("slots") or []:
        if s not in seen:
            seen.append(s)
    return seen


def compare_rows(recorded, fetched, limit=10):
    """Row-by-row differences between two row lists, at most `limit` of them
    described. Returns (differences_described, total_differences)."""
    out = []
    total = 0
    if len(recorded) != len(fetched):
        total += 1
        out.append(f"row count: recorded {len(recorded)}, fetched {len(fetched)}")
    for i, (a, b) in enumerate(zip(recorded, fetched)):
        for field in ROW_FIELDS:
            if a.get(field) != b.get(field):
                total += 1
                if len(out) < limit:
                    out.append(
                        f"row {i} (slot {a.get('slot')}): {field} differs "
                        f"(recorded {str(a.get(field))[:40]!r}, fetched {str(b.get(field))[:40]!r})"
                    )
    return out, total


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("recorded", help="a recorded sample or committed slice (JSON with `rows`)")
    parser.add_argument("--against", help="compare with this already-fetched file instead of refetching")
    args = parser.parse_args(argv)

    with open(args.recorded, encoding="utf-8") as f:
        recorded = json.load(f)
    slots = recorded_slots(recorded)
    if args.against:
        with open(args.against, encoding="utf-8") as f:
            fetched_rows = json.load(f)["rows"]
        source = args.against
    else:
        print(f"refetching {len(slots)} slots from {fetch_mainnet.endpoint_kind()}: {slots}", flush=True)
        fetched_rows, _ = fetch_mainnet.fetch(slots, require_all=True)
        source = "the endpoint"

    diffs, total = compare_rows(recorded["rows"], fetched_rows)
    if total == 0:
        print(f"IDENTICAL: {len(fetched_rows)} rows from {len(slots)} blocks match {args.recorded} "
              f"field for field ({', '.join(ROW_FIELDS)}), in order, against {source}")
        return 0
    print(f"DIFFERENT: {total} difference(s) between {args.recorded} and {source}")
    for d in diffs:
        print(f"  {d}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
