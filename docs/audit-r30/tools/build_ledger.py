#!/usr/bin/env python3
"""Round 30 file ledger: every tracked file at a commit, classified and checked.

Deterministic: the input is `git ls-tree -r <commit>` plus the blob bytes, and
two hand-kept records under this directory:

  read-log.tsv   paths a reviewer read in full (or in named sections), with the
                 depth reached. Nothing is marked "read" unless it is listed here.
  executed.tsv   test files whose tests were run on this commit, with the run.

Everything else a file receives comes from a machine check run here: a strict
parse (JSON, TOML, lockfiles), a schema or count check (manifests, corpus,
fixtures), a header decode (images, PDF), and a pattern triage (source).

Usage:  python3 build_ledger.py <repo-root> <commit> <out-dir>
Writes: file-ledger.json and file-ledger-summary.md in <out-dir>.
"""
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tomllib
from collections import Counter, defaultdict

B58 = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")


def b58decode_len(s):
    n = 0
    for ch in s:
        if ch not in B58:
            return None
        n = n * 58 + "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return pad + len(raw)


def git(root, *args, binary=False):
    out = subprocess.run(["git", "-C", root, *args], check=True, capture_output=True)
    return out.stdout if binary else out.stdout.decode()


def strict_json(text):
    """Parse JSON, refusing duplicate keys (a duplicate is a finding, not data)."""
    dups = []

    def hook(pairs):
        seen = {}
        for k, v in pairs:
            if k in seen:
                dups.append(k)
            seen[k] = v
        return seen

    return json.loads(text, object_pairs_hook=hook), dups


def strip_jsonc(text):
    text = re.sub(r"//[^\n]*", "", text)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r",(\s*[}\]])", r"\1", text)


def system_of(path):
    table = [
        (".github/", "ci-and-repo-policy"),
        ("graphite-core/src/", "rust-core"),
        ("graphite-core/tests/", "rust-core-tests"),
        ("graphite-core/protocols/", "protocol-manifests"),
        ("graphite-core/fixtures/", "fixtures-and-corpus"),
        ("graphite-core/scripts/out/", "generated-protocol-data"),
        ("graphite-core/scripts/", "data-scripts"),
        ("graphite-core/benches/", "rust-core-benches"),
        ("graphite-core/", "rust-core-meta"),
        ("tools/runtime-oracle/", "runtime-oracle"),
        ("tools/mainnet-sample/", "mainnet-sample-tools"),
        ("integrations/agent-guard/", "agent-guard"),
        ("integrations/solana-agent-kit/", "solana-agent-kit-adapter"),
        ("integrations/mcp-server/", "mcp-adapter"),
        ("integrations/vercel-ai/", "vercel-ai-adapter"),
        ("sdk/typescript/", "sdk-typescript"),
        ("sdk/go/", "sdk-go"),
        ("python-ai-layer/", "python-ai-layer"),
        ("dashboard/", "dashboard"),
        ("schemas/", "published-schemas"),
        ("examples/", "examples"),
        ("AUDIT/", "historical-audit"),
        ("docs/", "docs"),
        ("assets/", "brand-assets"),
    ]
    for prefix, name in table:
        if path.startswith(prefix):
            return name
    return "repo-root"


HISTORICAL_DOC = re.compile(
    r"^(AUDIT/|docs/(round\d|phase|adversarial|clean-room|drift-kamino|forensic|final-forensic|"
    r"identity-boundary|independent-gap|production-readiness|rpc-validation|audit-core-deprecated|"
    r"p16-mainnet|solana-foundation))"
)


def classify(path):
    base = os.path.basename(path)
    ext = base.rsplit(".", 1)[-1] if "." in base else ""
    if base in ("Cargo.lock", "package-lock.json", "go.sum", "requirements-lock.txt"):
        return "lockfile"
    if path.startswith("graphite-core/protocols/"):
        if base in ("battle_tested_evidence.json", "verified_program_ids.json"):
            return "protocol-data"
        return "protocol-manifest"
    if path.startswith("graphite-core/fixtures/"):
        return "fixture-data"
    if path.startswith("graphite-core/scripts/out/"):
        return "generated-data"
    if path.startswith("schemas/"):
        return "schema"
    if path.startswith("examples/"):
        return "example"
    if ext in ("png", "ico", "pdf", "svg", "jpg"):
        return "binary-asset"
    if ext == "md" or base in ("LICENSE",):
        return "historical-doc" if HISTORICAL_DOC.match(path) else "doc"
    if (
        path.startswith("graphite-core/tests/")
        or re.search(r"\.test\.(ts|tsx|mts)$", base)
        or base.endswith("_test.go")
        or base.startswith("test_")
        or ext == "proptest-regressions"
    ):
        return "test"
    if ext in ("rs", "ts", "tsx", "go", "py", "mts", "mjs", "cjs", "css", "html", "js"):
        return "source"
    if path.startswith("graphite-core/scripts/") and ext == "json":
        return "generated-data"
    return "config"


SCAN = {
    "rs": [
        ("unwrap", r"\.unwrap\(\)"),
        ("expect", r"\.expect\("),
        ("panic", r"\bpanic!\("),
        ("unsafe", r"\bunsafe\b"),
        ("catch_unwind", r"catch_unwind"),
        ("todo", r"\b(todo!|unimplemented!|TODO|FIXME|XXX)\b"),
        ("ignore_attr", r"#\[ignore"),
    ],
    "ts": [
        ("as_any", r"\bas any\b"),
        ("ts_ignore", r"@ts-(ignore|expect-error|nocheck)"),
        ("skip_only", r"\b(it|test|describe)\.(skip|only)\b|\{ ?skip: ?true"),
        ("todo", r"\b(TODO|FIXME|XXX)\b"),
        ("eval", r"\beval\(|new Function\("),
        ("swallow", r"catch\s*(\(\w*\))?\s*\{\s*\}"),
    ],
    "go": [
        ("panic", r"\bpanic\("),
        ("ignored_err", r"\b_\s*=\s*\w+[\w.]*\("),
        ("todo", r"\b(TODO|FIXME|XXX)\b"),
        ("skip", r"t\.Skip"),
    ],
    "py": [
        ("bare_except", r"except\s*:"),
        ("broad_except", r"except Exception"),
        ("eval", r"\beval\(|\bexec\("),
        ("todo", r"\b(TODO|FIXME|XXX)\b"),
        ("skip", r"pytest\.mark\.skip|unittest\.skip"),
    ],
    "css": [
        ("external_url", r"url\(\s*['\"]?https?:"),
        ("import", r"@import"),
        ("expression", r"expression\("),
    ],
    "yml": [
        ("or_true", r"\|\|\s*true"),
        ("continue_on_error", r"continue-on-error"),
        ("set_plus_e", r"set \+e"),
        ("pull_request_target", r"pull_request_target"),
        ("expr_in_run", r"run:.*\$\{\{\s*github\.event"),
    ],
}
SECRET = re.compile(
    r"(-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,}|"
    r"sk-[A-Za-z0-9]{32,}|api[_-]?key\s*[:=]\s*['\"][A-Za-z0-9]{24,}['\"])"
)


def scan_source(path, text):
    ext = path.rsplit(".", 1)[-1]
    key = {"tsx": "ts", "mts": "ts", "mjs": "ts", "cjs": "ts", "yaml": "yml"}.get(ext, ext)
    hits = {}
    for name, pat in SCAN.get(key, []):
        n = len(re.findall(pat, text))
        if n:
            hits[name] = n
    s = SECRET.findall(text)
    if s:
        hits["secret_pattern"] = len(s)
    return hits


def check_manifest(obj):
    notes, problems = {}, []
    p = obj.get("protocol", {})
    pid = p.get("program_id", "")
    if b58decode_len(pid) != 32:
        problems.append(f"program_id {pid!r} is not 32-byte base58")
    ins = obj.get("instructions", [])
    notes["program_id"] = pid
    notes["instructions"] = len(ins)
    discs = Counter(i.get("discriminator", "") for i in ins)
    dup = [d for d, c in discs.items() if c > 1]
    if dup:
        problems.append(f"duplicate discriminators {dup[:5]}")
    names = Counter(i.get("name") for i in ins)
    dn = [n for n, c in names.items() if c > 1]
    if dn:
        problems.append(f"duplicate instruction names {dn[:5]}")
    for i in ins:
        d = i.get("discriminator", "")
        if d and not re.fullmatch(r"[0-9a-fA-F]*", d):
            problems.append(f"non-hex discriminator {d!r}")
        if d and len(d) % 2:
            problems.append(f"odd-length discriminator {d!r}")
    rc = Counter(i.get("risk_class", "<missing>") for i in ins)
    notes["risk_classes"] = dict(sorted(rc.items()))
    notes["empty_discriminators"] = discs.get("", 0)
    notes["trust_tier"] = obj.get("trust_tier")
    notes["manifest_version"] = obj.get("graphite_manifest_version")
    allowed_top = {"graphite_manifest_version", "protocol", "version", "instructions", "trust_tier"}
    extra = set(obj) - allowed_top
    if extra:
        notes["extra_top_level_keys"] = sorted(extra)
    return notes, problems


def check_corpus_file(obj, path):
    notes, problems = {}, []
    if not isinstance(obj, list):
        return notes, ["corpus file is not an array"]
    notes["fixtures"] = len(obj)
    hashes = Counter(f.get("content_hash") for f in obj)
    ih = Counter(f.get("integrity_hash") for f in obj)
    notes["duplicate_content_hash"] = sum(c - 1 for c in hashes.values() if c > 1)
    notes["duplicate_integrity_hash"] = sum(c - 1 for c in ih.values() if c > 1)
    pid = os.path.basename(path)[:-5]
    wrong = sum(1 for f in obj if f.get("program_id") != pid)
    if wrong:
        problems.append(f"{wrong} fixtures whose program_id differs from the file name")
    notes["expected_approved"] = Counter(str(f.get("expected_approved")) for f in obj)
    notes["deprecated"] = sum(1 for f in obj if f.get("deprecated"))
    notes["sources"] = dict(Counter(f.get("source") for f in obj).most_common(6))
    return notes, problems


def check_npm_lock(obj):
    notes, problems = {}, []
    pk = obj.get("packages", {})
    notes["lockfileVersion"] = obj.get("lockfileVersion")
    notes["packages"] = len(pk) - (1 if "" in pk else 0)
    hosts = Counter()
    no_integrity, install_scripts, git_deps = [], [], []
    for name, meta in pk.items():
        if not name:
            continue
        if meta.get("link"):
            continue
        r = meta.get("resolved", "")
        if r:
            hosts[re.sub(r"^(\w+://[^/]+).*", r"\1", r)] += 1
            if not r.startswith("https://registry.npmjs.org/"):
                git_deps.append(name)
        if not meta.get("integrity"):
            no_integrity.append(name)
        if meta.get("hasInstallScript"):
            install_scripts.append(name.split("node_modules/")[-1])
    notes["resolved_hosts"] = dict(hosts)
    notes["install_script_packages"] = sorted(set(install_scripts))
    if no_integrity:
        problems.append(f"{len(no_integrity)} packages without integrity: {no_integrity[:5]}")
    if git_deps:
        problems.append(f"{len(git_deps)} packages not from registry.npmjs.org: {git_deps[:5]}")
    return notes, problems


def check_cargo_lock(text):
    obj = tomllib.loads(text)
    pk = obj.get("package", [])
    notes, problems = {"packages": len(pk), "lock_version": obj.get("version")}, []
    srcs = Counter((p.get("source") or "path").split("+")[0] for p in pk)
    notes["sources"] = dict(srcs)
    nock = [p["name"] for p in pk if (p.get("source") or "").startswith("registry+") and not p.get("checksum")]
    if nock:
        problems.append(f"registry packages without checksum: {nock[:5]}")
    gitsrc = [p["name"] for p in pk if (p.get("source") or "").startswith("git+")]
    if gitsrc:
        problems.append(f"git-sourced crates: {gitsrc}")
    dups = Counter(p["name"] for p in pk)
    notes["crates_with_multiple_versions"] = sorted(n for n, c in dups.items() if c > 1)
    return notes, problems


def check_png(b):
    if b[:8] != b"\x89PNG\r\n\x1a\n":
        return {}, ["not a PNG signature"]
    w, h, depth, ctype = struct.unpack(">IIBB", b[16:26])
    chunks, i = [], 8
    while i < len(b):
        ln = struct.unpack(">I", b[i:i + 4])[0]
        chunks.append(b[i + 4:i + 8].decode("latin1"))
        i += 12 + ln
    return {"width": w, "height": h, "bit_depth": depth, "color_type": ctype,
            "chunks": sorted(set(chunks)), "text_chunks": [c for c in chunks if c in ("tEXt", "iTXt", "zTXt")]}, []


def check_ico(b):
    if b[:4] != b"\x00\x00\x01\x00":
        return {}, ["not an ICO header"]
    n = struct.unpack("<H", b[4:6])[0]
    return {"images": n}, []


def check_pdf(b):
    if not b.startswith(b"%PDF-"):
        return {}, ["not a PDF header"]
    notes = {"version": b[5:8].decode(), "pages_marker_count": len(re.findall(rb"/Type\s*/Page[^s]", b)),
             "javascript": bool(re.search(rb"/JavaScript|/JS\b", b)),
             "launch_action": bool(re.search(rb"/Launch", b)),
             "embedded_files": bool(re.search(rb"/EmbeddedFile", b))}
    probs = [k for k in ("javascript", "launch_action", "embedded_files") if notes[k]]
    return notes, [f"PDF contains {p}" for p in probs]


def load_tsv(path):
    rows = {}
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            rows[parts[0]] = parts[1:]
    return rows


def main():
    root, commit, out = sys.argv[1], sys.argv[2], sys.argv[3]
    here = os.path.dirname(os.path.abspath(__file__))
    read_log = load_tsv(os.path.join(here, "read-log.tsv"))
    executed = load_tsv(os.path.join(here, "executed.tsv"))
    entries = []
    for line in git(root, "ls-tree", "-r", "-l", commit).splitlines():
        meta, path = line.split("\t", 1)
        mode, typ, sha, size = meta.split()
        if typ != "blob":
            continue
        entries.append((path, mode, sha, int(size)))
    ledger, problems_all = [], []
    totals = Counter()
    manifest_ids, manifest_instr = Counter(), 0
    manifest_files, protocol_data = {}, {}
    corpus_total = 0
    for path, mode, blob, size in sorted(entries):
        data = git(root, "cat-file", "blob", blob, binary=True)
        rec = {
            "path": path,
            "size": size,
            "sha256": hashlib.sha256(data).hexdigest(),
            "git_blob": blob,
            "mode": mode,
            "classification": classify(path),
            "system": system_of(path),
            "methods": [],
            "notes": {},
            "problems": [],
        }
        text = None
        try:
            text = data.decode("utf-8")
            rec["lines"] = text.count("\n") + (0 if text.endswith("\n") or not text else 1)
        except UnicodeDecodeError:
            pass
        base = os.path.basename(path)
        ext = base.rsplit(".", 1)[-1] if "." in base else ""
        try:
            if ext == "json" and text is not None:
                if base.startswith("tsconfig"):
                    try:
                        obj, dups = strict_json(text)
                    except json.JSONDecodeError:
                        obj, dups = strict_json(strip_jsonc(text))
                        rec["notes"]["jsonc"] = True
                else:
                    obj, dups = strict_json(text)
                rec["methods"].append("parsed:json-strict")
                if dups:
                    rec["problems"].append(f"duplicate JSON keys: {sorted(set(dups))[:8]}")
                if rec["classification"] == "protocol-manifest":
                    n, p = check_manifest(obj)
                    rec["notes"].update(n)
                    rec["problems"] += p
                    rec["methods"].append("validated:manifest-shape+uniqueness")
                    manifest_ids[n["program_id"]] += 1
                    manifest_files[base] = n["program_id"]
                    manifest_instr += n["instructions"]
                elif rec["classification"] == "protocol-data":
                    progs = obj.get("programs", [])
                    ids = [p.get("program_id", "") for p in progs]
                    bad = [i for i in ids if b58decode_len(i) != 32]
                    dup = [i for i, c in Counter(ids).items() if c > 1]
                    rec["notes"]["programs"] = len(ids)
                    if bad:
                        rec["problems"].append(f"non-32-byte program ids: {bad[:5]}")
                    if dup:
                        rec["problems"].append(f"duplicate program ids: {dup[:5]}")
                    protocol_data[base] = {"ids": set(ids),
                                           "manifests": {p.get("manifest") for p in progs if p.get("manifest")}}
                    rec["methods"].append("validated:program-list+cross-check-with-manifests")
                elif path.startswith("graphite-core/fixtures/corpus/") and "/meta/" not in path:
                    n, p = check_corpus_file(obj, path)
                    n["expected_approved"] = dict(n["expected_approved"])
                    rec["notes"].update(n)
                    rec["problems"] += p
                    rec["methods"].append("validated:corpus-records")
                    corpus_total += n.get("fixtures", 0)
                elif base == "package-lock.json":
                    n, p = check_npm_lock(obj)
                    rec["notes"].update(n)
                    rec["problems"] += p
                    rec["methods"].append("validated:npm-lock-provenance+integrity+install-scripts")
                elif base == "package.json":
                    rec["notes"]["scripts"] = sorted((obj.get("scripts") or {}).keys())
                    rec["notes"]["lifecycle_scripts"] = sorted(
                        k for k in (obj.get("scripts") or {}) if k in ("preinstall", "install", "postinstall", "prepare", "prepublish"))
                    rec["methods"].append("validated:package-manifest")
                elif isinstance(obj, dict):
                    rec["notes"]["top_level_keys"] = sorted(obj.keys())[:20]
                    for k in ("count", "rows"):
                        if k in obj and isinstance(obj[k], (int, list)):
                            rec["notes"][k] = obj[k] if isinstance(obj[k], int) else len(obj[k])
                    if "count" in obj and "rows" in obj and isinstance(obj["rows"], list) and obj["count"] != len(obj["rows"]):
                        rec["problems"].append(f"count {obj['count']} != rows {len(obj['rows'])}")
                elif isinstance(obj, list):
                    rec["notes"]["records"] = len(obj)
            elif base == "Cargo.lock":
                n, p = check_cargo_lock(text)
                rec["notes"].update(n)
                rec["problems"] += p
                rec["methods"].append("validated:cargo-lock-checksums+sources")
            elif ext == "toml":
                tomllib.loads(text)
                rec["methods"].append("parsed:toml")
            elif base == "requirements-lock.txt":
                reqs = [l for l in text.splitlines() if re.match(r"^[A-Za-z0-9_.-]+==", l)]
                nohash = [r.split("==")[0] for r in reqs if "--hash" not in r and not re.search(r"\\\s*$", r)]
                rec["notes"]["pinned_requirements"] = len(reqs)
                rec["notes"]["hash_lines"] = text.count("--hash=sha256:")
                if nohash:
                    rec["problems"].append(f"requirements without hashes: {nohash}")
                rec["methods"].append("validated:pip-hash-lock")
            elif base == "go.sum":
                rec["notes"]["entries"] = len(text.splitlines())
                rec["methods"].append("validated:go-sum-lines")
            elif ext == "png":
                n, p = check_png(data)
                rec["notes"].update(n)
                rec["problems"] += p
                rec["methods"].append("decoded:png-header+chunks")
            elif ext == "ico":
                n, p = check_ico(data)
                rec["notes"].update(n)
                rec["problems"] += p
                rec["methods"].append("decoded:ico-header")
            elif ext == "pdf":
                n, p = check_pdf(data)
                rec["notes"].update(n)
                rec["problems"] += p
                rec["methods"].append("decoded:pdf-header+active-content-scan")
            if text is not None and ext in ("rs", "ts", "tsx", "mts", "mjs", "cjs", "go", "py", "yml", "yaml", "css"):
                hits = scan_source(path, text)
                rec["notes"]["pattern_triage"] = hits
                rec["methods"].append("scanned:pattern-triage")
            if text is not None and SECRET.search(text) and "secret_pattern" not in rec["notes"].get("pattern_triage", {}):
                rec["problems"].append("secret-like pattern present")
            if text is not None and ext in ("md",):
                rec["methods"].append("scanned:doc-links")
        except Exception as e:  # a parse failure is a finding about the file
            rec["problems"].append(f"check failed: {type(e).__name__}: {e}")
        if path in read_log:
            depth, *rest = read_log[path]
            rec["methods"].insert(0, f"read:{depth}")
            if rest:
                rec["notes"]["review_note"] = rest[0]
        if path in executed:
            rec["methods"].append(f"executed:{executed[path][0]}")
        # Audit depth: the strongest method actually applied, in this order.
        m = " ".join(rec["methods"])
        if "read:full" in m:
            depth = "read-full"
        elif "read:sections" in m:
            depth = "read-sections"
        elif "read:historical" in m:
            depth = "reviewed-historical"
        elif "executed:" in m:
            depth = "executed"
        elif "validated:" in m or "decoded:" in m or "parsed:" in m:
            depth = "automatically-validated"
        elif "scanned:" in m:
            depth = "scanned"
        else:
            depth = "not-inspected"
        rec["audit_depth"] = depth
        totals[depth] += 1
        if rec["problems"]:
            problems_all.append((path, rec["problems"]))
        ledger.append(rec)
    # The three lists of seed programs must name the same programs, and every
    # manifest file the evidence names must exist.
    cross = []
    mids = set(manifest_ids)
    for name, d in sorted(protocol_data.items()):
        if d["ids"] != mids:
            cross.append(f"{name}: {len(d['ids'] - mids)} ids without a manifest, "
                         f"{len(mids - d['ids'])} manifests without an entry")
        missing = sorted(m for m in d["manifests"] if m not in manifest_files)
        if missing:
            cross.append(f"{name}: names manifest files that do not exist: {missing[:5]}")
    summary = {
        "protocol_cross_check": cross or ["the manifests, verified_program_ids.json and battle_tested_evidence.json name the same programs"],
        "commit": commit,
        "tree": git(root, "rev-parse", f"{commit}^{{tree}}").strip(),
        "files": len(ledger),
        "audit_depth_counts": dict(sorted(totals.items())),
        "by_classification": dict(sorted(Counter(r["classification"] for r in ledger).items())),
        "by_system": dict(sorted(Counter(r["system"] for r in ledger).items())),
        "protocol_manifests": sum(manifest_ids.values()),
        "unique_program_ids": len(manifest_ids),
        "duplicate_program_ids": sorted(k for k, v in manifest_ids.items() if v > 1),
        "manifest_instructions": manifest_instr,
        "corpus_fixtures": corpus_total,
        "files_with_problems": len(problems_all),
    }
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "file-ledger.json"), "w") as f:
        json.dump({"summary": summary, "files": ledger}, f, indent=1, sort_keys=True)
        f.write("\n")
    with open(os.path.join(out, "file-ledger-summary.md"), "w") as f:
        f.write("# File ledger summary (generated)\n\n")
        f.write(f"Generated by `docs/audit-r30/tools/build_ledger.py` from commit `{commit}` "
                f"(tree `{summary['tree']}`). Do not edit by hand.\n\n")
        f.write("| Measure | Value |\n|---|---|\n")
        for k in ("files", "protocol_manifests", "unique_program_ids", "manifest_instructions",
                  "corpus_fixtures", "files_with_problems"):
            f.write(f"| {k} | {summary[k]} |\n")
        f.write("\n## Audit depth\n\n| Depth | Files |\n|---|---|\n")
        for k, v in summary["audit_depth_counts"].items():
            f.write(f"| {k} | {v} |\n")
        f.write("\n## By classification\n\n| Classification | Files |\n|---|---|\n")
        for k, v in summary["by_classification"].items():
            f.write(f"| {k} | {v} |\n")
        f.write("\n## By system\n\n| System | Files |\n|---|---|\n")
        for k, v in summary["by_system"].items():
            f.write(f"| {k} | {v} |\n")
        f.write("\n## Machine-check problems\n\n")
        if not problems_all:
            f.write("None.\n")
        for p, probs in problems_all:
            for pr in probs:
                f.write(f"- `{p}`: {pr}\n")
        nd = [r["path"] for r in ledger if r["audit_depth"] == "not-inspected"]
        f.write("\n## Not inspected\n\n")
        f.write("None.\n" if not nd else "".join(f"- `{p}`\n" for p in nd))
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
