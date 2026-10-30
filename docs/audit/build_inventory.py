#!/usr/bin/env python3
"""Round 39: the exhaustive file inventory, one row per tracked file.

`EXHAUSTIVE_FILE_INVENTORY.csv` is built from two inputs and nothing else:

1. The Round 36 ledger generator (`docs/audit-r36/build_ledger.py`) run on the
   git objects of one commit. It gives each file its SHA-256, size, lines,
   classification, subsystem, the automated checks it ran on the bytes and
   what they found. It claims no review.
2. `docs/audit/review-map.tsv`: which Round 39 workstream covered each path,
   how (read fully, read in part, machine-validated only), the findings it
   raised and its disposition. Written from the workstreams' scope lists
   (`docs/audit/parts/*.md`). The most specific matching pattern wins; a file
   no pattern matches is reported as `not-covered`, never as reviewed.

Deterministic: the same commit and review map give the same bytes. Stdlib
only, no network.

Usage:
    python3 -I docs/audit/build_inventory.py [--commit <sha>] [--out <csv>]
"""
import argparse
import csv
import fnmatch
import io
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
LEDGER = os.path.join(ROOT, "docs", "audit-r36", "build_ledger.py")
REVIEW_MAP = os.path.join(HERE, "review-map.tsv")

COLUMNS = [
    "path", "sha256", "bytes", "lines", "binary", "classification", "kind",
    "subsystem", "role", "automated_checks", "automated_problems",
    "workstream", "review", "findings", "disposition",
]

# The role a classification plays, in the brief's terms
# (production/runtime/test/build/generated/evidence/binary).
ROLE = {
    "runtime-source": "production",
    "manifest": "production-data",
    "schema": "contract",
    "config": "build",
    "lockfile": "build",
    "ci": "build",
    "deployment": "deployment",
    "script": "tooling",
    "test": "test",
    "corpus/fixture data": "test-data",
    "generated": "generated",
    "documentation": "documentation",
    "historical-report": "evidence",
    "asset/binary": "binary",
}


def load_review_map(path):
    """`pattern<TAB>workstream<TAB>review<TAB>findings<TAB>disposition` rows;
    `#` starts a comment."""
    rows = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) != 5:
                sys.exit(f"{path}:{n}: expected 5 tab-separated fields, got {len(parts)}")
            rows.append(parts)
    return rows


def specificity(pattern):
    """A literal path beats a glob; a longer literal prefix beats a shorter."""
    literal = pattern.split("*", 1)[0].split("?", 1)[0].split("[", 1)[0]
    return (0 if any(c in pattern for c in "*?[") else 1, len(literal))


def review_for(path, review_map):
    best = None
    for row in review_map:
        if fnmatch.fnmatchcase(path, row[0]):
            if best is None or specificity(row[0]) > specificity(best[0]):
                best = row
    if best is None:
        return ("", "not-covered", "", "no workstream's scope names this path")
    return tuple(best[1:])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--commit", default="HEAD")
    ap.add_argument("--out", default=os.path.join(HERE, "EXHAUSTIVE_FILE_INVENTORY.csv"))
    args = ap.parse_args()
    commit = subprocess.run(
        ["git", "-C", ROOT, "rev-parse", args.commit], check=True, capture_output=True, text=True
    ).stdout.strip()
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(
            [sys.executable, "-I", LEDGER, "--repo", ROOT, "--commit", commit, "--out", tmp],
            check=True, stdout=subprocess.DEVNULL,
        )
        with open(os.path.join(tmp, "file-ledger.json"), encoding="utf-8") as f:
            ledger = json.load(f)
    review_map = load_review_map(REVIEW_MAP)
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(COLUMNS)
    uncovered = 0
    for rec in sorted(ledger["files"], key=lambda r: r["path"]):
        workstream, review, findings, disposition = review_for(rec["path"], review_map)
        uncovered += review == "not-covered"
        v = rec.get("validation", {})
        w.writerow([
            rec["path"], rec.get("sha256", ""), rec.get("size", ""), rec.get("lines", ""),
            "yes" if rec.get("lines") is None else "no", rec.get("classification", ""),
            rec.get("kind", ""), rec.get("subsystem", ""),
            ROLE.get(rec.get("classification", ""), "other"),
            "; ".join(v.get("checks", [])), "; ".join(map(str, v.get("problems", []))),
            workstream, review, findings, disposition,
        ])
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(buf.getvalue())
    print(f"{len(ledger['files'])} files at {commit[:12]}; {uncovered} not covered by any workstream")
    return 1 if uncovered else 0


if __name__ == "__main__":
    sys.exit(main())
