#!/usr/bin/env python3
"""Round 30 historical-findings regression matrix.

Reads every historical finding ID out of the repository's audit records
(AUDIT/*.md, docs/round*.md and the other dated reports, SECURITY.md,
docs/CURRENT.md), collects the tests each record names for it, and resolves
those names against the test runs of THIS commit:

  - Rust: the output of `cargo test --release --all-features --no-fail-fast`
  - Go:   `go test -v ./...`
  - Python: `pytest -rA`
  - TypeScript: one TAP log per package (`tsx --test --test-reporter=tap`)

A finding is labelled from two things only: what its records say about it
(fixed / open / limitation / owner / not a finding / superseded) and whether
the tests they name ran and passed here. Nothing is labelled "confirmed fixed
on HEAD" unless at least one named test was found in a run of this commit and
none of its named tests failed. The labels are deliberately mechanical; the
handful of findings that need a human reading are listed for review.

Usage:
  regression_matrix.py <repo-root> <logs-dir> <out-dir>
logs-dir holds rust-all.log, go.log, py-ai.log, py-ms.log, ts-<pkg>.tap.
"""
import json
import os
import re
import sys
from collections import defaultdict

ID_RE = re.compile(
    r"(?<![\w-])("
    r"A[1-6]-\d{2}"
    r"|F-\d{2}-(?:\d{2}|C\d)"
    r"|F\d{1,2}"
    r"|R\d{1,2}-\d{2}"
    r"|R\d{1,2}(?:-[a-z])?"
    r"|W\d{1,2}(?:-[a-z])?"
    r"|W18/19-[a-f]"
    r"|E\d{1,2}b?"
    r"|H[1-4]"
    r"|M\d{1,2}"
    r"|GFX-\d{3}"
    r"|R-[MP]\d{1,2}"
    r"|R2-c|R3-b"
    r"|R28-\d"
    r")(?![\w-])"
)
# Break IDs (B01..B127, TSB1..) are records of a revert, not findings; they
# are counted separately.
BREAK_RE = re.compile(r"(?<![\w-])(B\d{2,3}|TSB\d{1,2})(?![\w-])")

RUST_FILE_RE = re.compile(r"tests/([a-z0-9_]+)\.rs")
RUST_PATH_RE = re.compile(r"`?((?:lib::)?[a-z][a-z0-9_]*(?:::[a-z0-9_]+)+(?:::\{[a-z0-9_, ]+\})?)`?")
TS_FILE_RE = re.compile(r"([a-z0-9-]+\.test\.ts)")
GO_TEST_RE = re.compile(r"\b(Test[A-Z][A-Za-z0-9_]+)\b")
PY_TEST_RE = re.compile(r"\b(test_[a-z0-9_]+)\b")

STATUS_WORDS = [
    ("not-a-finding", re.compile(r"NOT A FINDING|not a finding|\(rejected\)|VERIFIED SOUND", re.I)),
    ("superseded", re.compile(r"\bsuperseded\b|covered by R1|= R10", re.I)),
    ("owner", re.compile(r"OWNER DECISION|owner decision|\*\*OWNER\*\*|Owner \|", re.I)),
    ("limitation", re.compile(r"DOCUMENTED LIMITATION|documented limitation|disclosed, not refused", re.I)),
    ("open", re.compile(r"\*\*OPEN\*\*|\bOpen \(|\| Open\b|still open|remains open|\bOPEN\b")),
    ("partial", re.compile(r"\bpartial\b|\bAdvanced\b|Still partial", re.I)),
    ("fixed", re.compile(r"\bFIXED\b|\bFixed\b|\bfixed\b|\bDone\b|\*\*Done|\bClosed\b|CONFIRMED.*FIXED|caught")),
]


def read_docs(root):
    docs = []
    for d in ("AUDIT", "docs"):
        for name in sorted(os.listdir(os.path.join(root, d))):
            if name.endswith(".md"):
                docs.append(os.path.join(d, name))
    docs.append("SECURITY.md")
    return docs


def blocks_of(text):
    """Table rows, list items and paragraphs, each with its nearest heading."""
    heading = ""
    out = []
    cur = []

    def flush():
        if cur:
            out.append((heading, " ".join(cur)))
            cur.clear()

    for line in text.splitlines():
        s = line.strip()
        if s.startswith("#"):
            flush()
            heading = s.lstrip("# ").strip()
            continue
        if s.startswith("|"):
            flush()
            out.append((heading, s))
            continue
        if not s:
            flush()
            continue
        if re.match(r"^([-*]|\d+\.)\s", s) and cur:
            flush()
        cur.append(s)
    flush()
    return out


def expand_rust_path(p):
    p = p.strip("`")
    m = re.match(r"^(.*)::\{([^}]*)\}$", p)
    if m:
        base = m.group(1)
        return [f"{base}::{x.strip()}" for x in m.group(2).split(",") if x.strip()]
    return [p]


def parse_rust_log(path):
    """{(binary, test_name): status} from cargo test output."""
    results = {}
    binary = None
    if not os.path.exists(path):
        return results
    for line in open(path, encoding="utf-8", errors="replace"):
        m = re.match(r"\s*Running (unittests src/lib\.rs|unittests src/bin/\S+|tests/([a-z0-9_]+)\.rs|benches/\S+)", line)
        if m:
            if m.group(2):
                binary = m.group(2)
            elif "src/lib.rs" in m.group(1):
                binary = "lib"
            else:
                binary = m.group(1)
            continue
        m = re.match(r"^test (\S+) \.\.\. (ok|FAILED|ignored)", line)
        if m and binary:
            results[(binary, m.group(1))] = m.group(2)
    return results


def parse_go_log(path):
    res = {}
    if os.path.exists(path):
        for line in open(path, encoding="utf-8", errors="replace"):
            m = re.match(r"^\s*--- (PASS|FAIL|SKIP): (\S+)", line)
            if m:
                res[m.group(2)] = m.group(1)
    return res


def parse_py_logs(paths):
    res = {}
    for p in paths:
        if os.path.exists(p):
            for line in open(p, encoding="utf-8", errors="replace"):
                m = re.match(r"^(PASSED|FAILED|SKIPPED|ERROR) \S*::(test_[a-z0-9_]+)", line)
                if m:
                    res[m.group(2)] = m.group(1)
    return res


def parse_tap(path):
    summary = {}
    if os.path.exists(path):
        for line in open(path, encoding="utf-8", errors="replace"):
            m = re.match(r"^# (tests|pass|fail|cancelled|skipped|todo) (\d+)", line)
            if m:
                summary[m.group(1)] = int(m.group(2))
    return summary


def main():
    root, logs, out = sys.argv[1], sys.argv[2], sys.argv[3]
    rust = parse_rust_log(os.path.join(logs, "rust-all.log"))
    rust_binaries = defaultdict(list)
    for (b, t), st in rust.items():
        rust_binaries[b].append(st)
    lib_tests = {t: st for (b, t), st in rust.items() if b == "lib"}
    go = parse_go_log(os.path.join(logs, "go.log"))
    py = parse_py_logs([os.path.join(logs, "py-ai.log"), os.path.join(logs, "py-ms.log")])
    tap = {}
    for f in os.listdir(logs):
        if f.startswith("ts-") and f.endswith(".tap"):
            tap[f[3:-4]] = parse_tap(os.path.join(logs, f))
    ts_files = {}
    for pkgdir in ("integrations/agent-guard", "integrations/mcp-server", "integrations/solana-agent-kit",
                   "integrations/vercel-ai", "sdk/typescript/src", "dashboard/src"):
        full = os.path.join(root, pkgdir)
        pkg = {"sdk/typescript/src": "typescript", "dashboard/src": "dashboard"}.get(pkgdir, os.path.basename(pkgdir))
        for f in os.listdir(full):
            if f.endswith(".test.ts"):
                ts_files.setdefault(f, []).append(pkg)

    def resolve_rust(ref):
        """Return list of (ref, status) for one Rust test reference."""
        out = []
        for p in expand_rust_path(ref):
            parts = p.split("::")
            if parts[0] == "lib":
                parts = parts[1:]
            # tests/<binary>.rs::name or <binary>::name
            if parts[0] in rust_binaries:
                if len(parts) == 1:
                    sts = rust_binaries[parts[0]]
                    out.append((p, "ok" if sts and all(s in ("ok", "ignored") for s in sts) and "ok" in sts else ("FAILED" if "FAILED" in sts else "ignored")))
                else:
                    name = "::".join(parts[1:])
                    hits = [st for (b, t), st in rust.items() if b == parts[0] and (t == name or t.endswith("::" + name) or t.startswith(name + "::"))]
                    out.append((p, agg(hits)))
                continue
            name = "::".join(parts)
            hits = [st for t, st in lib_tests.items() if t == name or t.endswith("::" + name) or t.startswith(name + "::")]
            if hits:
                out.append((p, agg(hits)))
                continue
            out.append((p, "not-found"))
        return out

    def agg(hits):
        if not hits:
            return "not-found"
        if "FAILED" in hits:
            return "FAILED"
        if "ok" in hits:
            return "ok"
        return "ignored"

    findings = defaultdict(lambda: {"sources": set(), "status_words": set(), "refs": {}, "headings": set(),
                                    "breaks": set(), "text": []})
    for doc in read_docs(root):
        text = open(os.path.join(root, doc), encoding="utf-8").read()
        for heading, block in blocks_of(text):
            ids = set(ID_RE.findall(block))
            if not ids:
                continue
            refs = {}
            for m in RUST_FILE_RE.finditer(block):
                refs[f"rust:{m.group(1)}"] = None
            # A test binary named on its own, in backticks (`round21_open_list`).
            for m in re.finditer(r"`([a-z0-9_]+)`", block):
                if m.group(1) in rust_binaries:
                    refs[f"rust:{m.group(1)}"] = None
            for m in RUST_PATH_RE.finditer(block):
                p = m.group(1)
                # Unresolvable paths (a type, a function) are dropped at
                # resolution unless they look like a test path.
                if "::" in p and not p.startswith(("std::", "crate::", "serde", "tokio", "axum", "hyper")):
                    refs[f"rustpath:{p}"] = None
            for m in TS_FILE_RE.finditer(block):
                refs[f"ts:{m.group(1)}"] = None
            for m in GO_TEST_RE.finditer(block):
                refs[f"go:{m.group(1)}"] = None
            for m in PY_TEST_RE.finditer(block):
                refs[f"py:{m.group(1)}"] = None
            words = {name for name, rx in STATUS_WORDS if rx.search(block)}
            brk = set(BREAK_RE.findall(block))
            # A block naming many IDs (a summary list) attributes its tests to
            # none of them: only blocks naming at most three IDs carry refs.
            for fid in ids:
                f = findings[fid]
                f["sources"].add(doc)
                f["headings"].add(heading[:80])
                if len(ids) <= 3:
                    # Status words and breaks, like tests, are read only from
                    # blocks about this finding, not from summary lists.
                    f["status_words"] |= words
                    f["breaks"] |= brk
                    for r in refs:
                        f["refs"][r] = None
                if len(f["text"]) < 2 and len(block) < 600:
                    f["text"].append(block[:300])

    rows = []
    for fid in sorted(findings, key=sort_key):
        f = findings[fid]
        resolved = []
        for r in sorted(f["refs"]):
            kind, name = r.split(":", 1)
            if kind == "rust":
                sts = rust_binaries.get(name)
                st = "not-found" if not sts else ("FAILED" if "FAILED" in sts else ("ok" if "ok" in sts else "ignored"))
                resolved.append((f"tests/{name}.rs", st))
            elif kind == "rustpath":
                for p, st in resolve_rust(name):
                    if st != "not-found" or p.split("::")[0] in rust_binaries or p.split("::")[0] in ("lib",) or "tests" in p.split("::"):
                        resolved.append((p, st))
            elif kind == "ts":
                pk = ts_files.get(name)
                if not pk:
                    resolved.append((name, "not-found"))
                else:
                    s = tap.get(pk[0], {})
                    resolved.append((f"{pk[0]}/{name}", "ok" if s.get("fail", 1) == 0 and s.get("pass", 0) > 0 else "FAILED"))
            elif kind == "go":
                resolved.append((name, {"PASS": "ok", "FAIL": "FAILED", "SKIP": "skipped"}.get(go.get(name, ""), "not-found")))
            elif kind == "py":
                if name in py:
                    resolved.append((name, {"PASSED": "ok", "FAILED": "FAILED", "SKIPPED": "skipped", "ERROR": "FAILED"}[py[name]]))
        ran = [st for _, st in resolved if st in ("ok", "FAILED")]
        words = f["status_words"]
        if "FAILED" in ran:
            label = "REGRESSED (a named test fails on HEAD)"
        elif "open" in words and "fixed" not in words:
            label = "still open (per its records)"
        elif "owner" in words and "fixed" not in words:
            label = "owner / external decision"
        elif "limitation" in words and "fixed" not in words:
            label = "documented limitation"
        elif "not-a-finding" in words and "fixed" not in words:
            label = "not a finding (its pin passes here)" if ran else "not a finding"
        elif ran and all(st == "ok" for st in ran):
            label = "confirmed fixed on HEAD (named test passed here)"
        elif "partial" in words and "fixed" not in words:
            label = "partial (per its records)"
        elif "fixed" in words:
            label = "fixed per records; no named test resolved here"
        else:
            label = "needs review (no status word, no test resolved)"
        if ("open" in words or "limitation" in words or "owner" in words) and "fixed" in words:
            mixed = True
        else:
            mixed = False
        rows.append({
            "id": fid,
            "label": label,
            "mixed_status_words": mixed,
            "status_words": sorted(words),
            "tests": [{"ref": r, "result": st} for r, st in resolved],
            "breaks": sorted(f["breaks"], key=sort_key),
            "sources": sorted(f["sources"]),
            "context": f["text"][:1],
        })
    os.makedirs(out, exist_ok=True)
    counts = defaultdict(int)
    for r in rows:
        counts[r["label"]] += 1
    summary = {
        "findings": len(rows),
        "labels": dict(sorted(counts.items())),
        "rust_tests_seen": len(rust),
        "rust_failed": sum(1 for s in rust.values() if s == "FAILED"),
        "rust_ignored": sum(1 for s in rust.values() if s == "ignored"),
        "go_tests_seen": len(go),
        "py_tests_seen": len(py),
        "ts_packages": {k: v for k, v in sorted(tap.items())},
    }
    json.dump({"summary": summary, "findings": rows}, open(os.path.join(out, "historical-regression-matrix.json"), "w"),
              indent=1, sort_keys=True)
    write_markdown(os.path.join(out, "historical-regression-matrix.md"), summary, rows)
    print(json.dumps(summary, indent=1))


def write_markdown(path, summary, rows):
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Historical findings: regression matrix (generated)\n\n")
        f.write("Generated by `docs/audit-r30/tools/regression_matrix.py` from the repository's audit records "
                "and the test runs of this commit. Do not edit by hand; the reviewed dispositions of the "
                "open items are in `historical-findings.md`.\n\n")
        f.write(f"Findings: {summary['findings']}. Rust tests seen: {summary['rust_tests_seen']} "
                f"({summary['rust_failed']} failed, {summary['rust_ignored']} ignored). Go: {summary['go_tests_seen']}. "
                f"Python: {summary['py_tests_seen']}. TypeScript packages: "
                + ", ".join(f"{k} {v.get('pass', 0)}/{v.get('tests', 0)}" for k, v in summary["ts_packages"].items())
                + ".\n\n")
        f.write("| Label | Findings |\n|---|---|\n")
        for k, v in summary["labels"].items():
            f.write(f"| {k} | {v} |\n")
        f.write("\n| ID | Label | Tests named by its records, and their result here | Breaks | Records |\n|---|---|---|---|---|\n")
        for r in rows:
            tests = "; ".join(f"`{t['ref']}` {t['result']}" for t in r["tests"][:6])
            if len(r["tests"]) > 6:
                tests += f"; … {len(r['tests']) - 6} more"
            srcs = ", ".join(s.replace("docs/", "").replace(".md", "") for s in r["sources"][:4])
            if len(r["sources"]) > 4:
                srcs += f", … {len(r['sources']) - 4} more"
            f.write(f"| {r['id']} | {r['label']} | {tests or '—'} | {', '.join(r['breaks'][:6]) or '—'} | {srcs} |\n")


def sort_key(s):
    m = re.match(r"([A-Za-z/-]+?)(\d+)(.*)", s)
    return (m.group(1), int(m.group(2)), m.group(3)) if m else (s, 0, "")


if __name__ == "__main__":
    main()
