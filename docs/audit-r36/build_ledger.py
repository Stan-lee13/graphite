#!/usr/bin/env python3
"""Round 36 file coverage ledger: every tracked file at one commit, classified
and put through the automated checks named in its record. Nothing more.

What this ledger is: for each file, the checks this script ran on the bytes git
holds for it (parse, schema/count check, header decode, lexical scan), and
what they returned. What it is not: a review. No record claims that a person
or a model read the file; every record carries `"review": "not-claimed"`.

Deterministic: the only inputs are the git objects of one commit (the blob
bytes, never the working tree), so two runs on the same commit produce the
same bytes. No timestamps, no network, stdlib only.

Usage:
    python3 -I docs/audit-r36/build_ledger.py [--repo <root>] [--commit <sha>] [--out <dir>]

Defaults: the repository that contains this file, the Round 36 base commit
(BASE_COMMIT below; the ledger describes that tree, not a later one that also
contains the ledger), and docs/audit-r36/ as the output directory.

Writes: file-ledger.json, scan-triage.json (both sorted, indent=1, sort_keys).
LEDGER.md is written by hand from these two files.
"""
import ast
import configparser
import hashlib
import io
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import tokenize
import tomllib
import zlib
from collections import Counter, defaultdict

BASE_COMMIT = "214042762aa184d4994243b00d3674285dda41c5"
R30_LEDGER = "docs/audit-r30/file-ledger.json"
GENERATOR = "docs/audit-r36/build_ledger.py"

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_INDEX = {c: i for i, c in enumerate(B58_ALPHABET)}


def b58_len(s):
    """Decoded byte length of a base58 string, or None if it is not base58."""
    if not isinstance(s, str) or not s:
        return None
    n = 0
    for ch in s:
        if ch not in B58_INDEX:
            return None
        n = n * 58 + B58_INDEX[ch]
    raw = (n.bit_length() + 7) // 8
    return (len(s) - len(s.lstrip("1"))) + raw


def is_pubkey(s):
    return b58_len(s) == 32


# --------------------------------------------------------------------------
# git access (object database only)
# --------------------------------------------------------------------------

def git(root, *args, env=None):
    out = subprocess.run(["git", "-C", root, *args], check=True, capture_output=True, env=env)
    return out.stdout


def tree_entries(root, commit):
    rows = []
    for line in git(root, "ls-tree", "-r", "-l", "-z", commit).split(b"\0"):
        if not line:
            continue
        meta, path = line.split(b"\t", 1)
        mode, typ, sha, size = meta.decode().split()
        rows.append({"path": path.decode("utf-8"), "mode": mode, "type": typ, "sha": sha,
                     "size": None if size == "-" else int(size)})
    return rows


def ls_files_at(root, commit):
    """`git ls-files -s` of the commit, through a throwaway index file, so the
    count does not depend on the state of the caller's own index."""
    with tempfile.TemporaryDirectory() as d:
        idx = os.path.join(d, "index")
        env = dict(os.environ, GIT_INDEX_FILE=idx)
        git(root, "read-tree", commit, env=env)
        out = git(root, "ls-files", "-s", "-z", env=env)
    rows = {}
    for line in out.split(b"\0"):
        if not line:
            continue
        meta, path = line.split(b"\t", 1)
        mode, sha, stage = meta.decode().split()
        rows[path.decode("utf-8")] = (mode, sha)
    return rows


def read_blobs(root, shas):
    proc = subprocess.Popen(["git", "-C", root, "cat-file", "--batch"], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE)
    out = {}
    for sha in shas:
        proc.stdin.write(sha.encode() + b"\n")
        proc.stdin.flush()
        header = proc.stdout.readline().split()
        size = int(header[2])
        out[sha] = proc.stdout.read(size)
        proc.stdout.read(1)
    proc.stdin.close()
    proc.wait()
    return out


# --------------------------------------------------------------------------
# lexers: per-character context mask (0 code, 1 comment, 2 string/char)
# --------------------------------------------------------------------------
CODE, COMMENT, STRING = 0, 1, 2


def rust_mask(t):
    n = len(t)
    m = bytearray(n)
    i = 0
    while i < n:
        c = t[i]
        if c == "/" and i + 1 < n and t[i + 1] == "/":
            j = t.find("\n", i)
            j = n if j < 0 else j
            m[i:j] = b"\x01" * (j - i)
            i = j
            continue
        if c == "/" and i + 1 < n and t[i + 1] == "*":
            depth, j = 1, i + 2
            while j < n and depth:
                if t.startswith("/*", j):
                    depth += 1
                    j += 2
                elif t.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            m[i:j] = b"\x01" * (j - i)
            i = j
            continue
        prev_ident = i > 0 and (t[i - 1].isalnum() or t[i - 1] == "_")
        # raw strings r"..", r#".."#, br"..", cr".."
        if not prev_ident and c in "rbc":
            k = i
            if c in "bc" and k + 1 < n and t[k + 1] == "r":
                k += 1
            if t[k] == "r" and k + 1 < n and t[k + 1] in '#"':
                h = k + 1
                while h < n and t[h] == "#":
                    h += 1
                if h < n and t[h] == '"':
                    hashes = h - (k + 1)
                    end = t.find('"' + "#" * hashes, h + 1)
                    end = n if end < 0 else end + 1 + hashes
                    m[i:end] = b"\x02" * (end - i)
                    i = end
                    continue
        if c == '"' or (not prev_ident and c in "bc" and i + 1 < n and t[i + 1] == '"'):
            j = i + (1 if c == '"' else 2)
            while j < n and t[j] != '"':
                j += 2 if t[j] == "\\" else 1
            j = min(n, j + 1)
            m[i:j] = b"\x02" * (j - i)
            i = j
            continue
        if c == "'" or (not prev_ident and c == "b" and i + 1 < n and t[i + 1] == "'"):
            s = i + (1 if c == "'" else 2)
            if s < n and t[s] == "\\":
                j = t.find("'", s + 2)
                if j > 0 and j - s <= 12:
                    m[i:j + 1] = b"\x02" * (j + 1 - i)
                    i = j + 1
                    continue
            elif s + 1 < n and t[s + 1] == "'" and t[s] != "\n":
                m[i:s + 2] = b"\x02" * (s + 2 - i)
                i = s + 2
                continue
            i += 1  # a lifetime or label
            continue
        i += 1
    return m


def clike_mask(t, template=False, go_raw=False, regex=False):
    """JS/TS (template literals, regex literals) and Go (raw strings)."""
    n = len(t)
    m = bytearray(n)
    i = 0
    stack = []  # template literal nesting: brace depth inside each ${ }
    last_sig = ""
    while i < n:
        c = t[i]
        if stack and c == "}" and stack[-1] == 0:
            stack.pop()
            # back into the template literal body
            j = i + 1
            while j < n and t[j] != "`":
                if t[j] == "\\":
                    j += 2
                    continue
                if t.startswith("${", j):
                    break
                j += 1
            if j < n and t[j] == "`":
                m[i:j + 1] = b"\x02" * (j + 1 - i)
                i = j + 1
            else:
                m[i:j + 2] = b"\x02" * (min(n, j + 2) - i)
                stack.append(0)
                i = j + 2
            last_sig = "`"
            continue
        if stack:
            if c == "{":
                stack[-1] += 1
            elif c == "}":
                stack[-1] -= 1
        if c == "/" and i + 1 < n and t[i + 1] == "/":
            j = t.find("\n", i)
            j = n if j < 0 else j
            m[i:j] = b"\x01" * (j - i)
            i = j
            continue
        if c == "/" and i + 1 < n and t[i + 1] == "*":
            j = t.find("*/", i + 2)
            j = n if j < 0 else j + 2
            m[i:j] = b"\x01" * (j - i)
            i = j
            continue
        if c in "\"'":
            if go_raw and c == "'":
                j = i + 1
                while j < n and t[j] != "'" and t[j] != "\n":
                    j += 2 if t[j] == "\\" else 1
            else:
                j = i + 1
                while j < n and t[j] != c and t[j] != "\n":
                    j += 2 if t[j] == "\\" else 1
            j = min(n, j + 1)
            m[i:j] = b"\x02" * (j - i)
            i = j
            last_sig = c
            continue
        if c == "`" and go_raw:
            j = t.find("`", i + 1)
            j = n if j < 0 else j + 1
            m[i:j] = b"\x02" * (j - i)
            i = j
            last_sig = c
            continue
        if c == "`" and template:
            j = i + 1
            while j < n and t[j] != "`":
                if t[j] == "\\":
                    j += 2
                    continue
                if t.startswith("${", j):
                    break
                j += 1
            if j < n and t[j] == "`":
                m[i:j + 1] = b"\x02" * (j + 1 - i)
                i = j + 1
            else:
                m[i:min(n, j + 2)] = b"\x02" * (min(n, j + 2) - i)
                stack.append(0)
                i = j + 2
            last_sig = "`"
            continue
        if regex and c == "/" and (last_sig == "" or last_sig in "(,=:[!&|?{};+-*%<>~^" or
                                   re.search(r"\b(return|typeof|case|in|of|delete|void|throw)\s*$", t[max(0, i - 12):i])):
            j, cls = i + 1, False
            while j < n and t[j] != "\n":
                if t[j] == "\\":
                    j += 2
                    continue
                if t[j] == "[":
                    cls = True
                elif t[j] == "]":
                    cls = False
                elif t[j] == "/" and not cls:
                    break
                j += 1
            if j < n and t[j] == "/":
                j += 1
                while j < n and t[j].isalpha():
                    j += 1
                m[i:j] = b"\x02" * (j - i)
                i = j
                last_sig = "/"
                continue
        if not c.isspace():
            last_sig = c if not (c.isalnum() or c == "_" or c == "$") else "a"
        i += 1
    return m


def python_mask(t):
    m = bytearray(len(t))
    starts = [0]
    for line in t.splitlines(keepends=True):
        starts.append(starts[-1] + len(line))
    try:
        for tok in tokenize.generate_tokens(io.StringIO(t).readline):
            if tok.type in (tokenize.COMMENT, tokenize.STRING) or tok.type == getattr(tokenize, "FSTRING_MIDDLE", -1):
                a = starts[tok.start[0] - 1] + tok.start[1]
                b = starts[tok.end[0] - 1] + tok.end[1]
                m[a:b] = (b"\x01" if tok.type == tokenize.COMMENT else b"\x02") * (b - a)
    except (tokenize.TokenError, SyntaxError, IndentationError):
        return None
    return m


def hash_comment_mask(t):
    """Shell / YAML / TOML / INI: `#` at line start or after whitespace."""
    m = bytearray(len(t))
    pos = 0
    for line in t.splitlines(keepends=True):
        mm = re.search(r"(^|\s)#", line)
        if mm:
            a = pos + mm.start() + (1 if mm.group(1) else 0)
            m[a:pos + len(line)] = b"\x01" * (pos + len(line) - a)
        pos += len(line)
    return m


def css_mask(t):
    m = bytearray(len(t))
    i, n = 0, len(t)
    while i < n:
        if t.startswith("/*", i):
            j = t.find("*/", i + 2)
            j = n if j < 0 else j + 2
            m[i:j] = b"\x01" * (j - i)
            i = j
        elif t[i] in "\"'":
            j = t.find(t[i], i + 1)
            j = n if j < 0 else j + 1
            m[i:j] = b"\x02" * (j - i)
            i = j
        else:
            i += 1
    return m


def mask_for(path, text):
    ext = ext_of(path)
    if ext == "css":
        return css_mask(text), "css-lexer"
    if ext == "rs":
        return rust_mask(text), "rust-lexer"
    if ext in ("ts", "tsx", "mts", "cts", "js", "mjs", "cjs"):
        return clike_mask(text, template=True, regex=True), "js-lexer"
    if ext == "go":
        return clike_mask(text, go_raw=True), "go-lexer"
    if ext == "py":
        mk = python_mask(text)
        return (mk, "python-tokenize") if mk is not None else (None, "none")
    if ext in ("sh", "yml", "yaml", "toml", "service", "timer", "example", "allow", "txt") or \
            os.path.basename(path) in ("Dockerfile", "Caddyfile", ".gitignore", ".gitattributes", ".dockerignore",
                                       "CODEOWNERS"):
        return hash_comment_mask(text), "hash-comment-lexer"
    return None, "none"


def ext_of(path):
    base = os.path.basename(path)
    return base.rsplit(".", 1)[-1].lower() if "." in base.lstrip(".") else ""


def line_starts(text):
    starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def line_of(starts, pos):
    lo, hi = 0, len(starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if starts[mid] <= pos:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1


# --------------------------------------------------------------------------
# Rust: delimiter balance and #[cfg(test)] / #[test] regions
# --------------------------------------------------------------------------
TEST_ATTR = re.compile(r"#\[\s*cfg\s*\(\s*test\s*\)\s*\]|#\[\s*(?:tokio::)?test\b[^\]]*\]")
INNER_TEST_ATTR = re.compile(r"#!\[\s*cfg\s*\(\s*test\s*\)\s*\]")
ITEM_KEYWORDS = {"fn", "mod", "impl", "struct", "enum", "trait", "pub", "async", "const", "static",
                 "unsafe", "use", "type", "extern", "macro_rules", "thread_local", "union"}


def rust_balance(text, m):
    pairs = {")": "(", "]": "[", "}": "{"}
    stack = []
    for i, ch in enumerate(text):
        if m[i] != CODE:
            continue
        if ch in "([{":
            stack.append(ch)
        elif ch in ")]}":
            if not stack or stack[-1] != pairs[ch]:
                return False
            stack.pop()
    return not stack


def _next_code(text, m, i):
    n = len(text)
    while i < n and (m[i] != CODE or text[i].isspace()):
        i += 1
    return i


def _match_close(text, m, i):
    """i at an opening delimiter (code); return index of its partner."""
    open_c = text[i]
    close_c = {"(": ")", "[": "]", "{": "}"}[open_c]
    depth = 0
    n = len(text)
    while i < n:
        if m[i] == CODE:
            if text[i] == open_c:
                depth += 1
            elif text[i] == close_c:
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return n - 1


def rust_test_regions(text, m):
    """Character ranges of items under #[cfg(test)], #[test] or #[tokio::test],
    plus the names of `mod x;` declarations under #[cfg(test)]."""
    regions, test_mods = [], []
    n = len(text)
    if any(m[mm.start()] == CODE for mm in INNER_TEST_ATTR.finditer(text)):
        return [(0, n)], test_mods
    for mm in TEST_ATTR.finditer(text):
        if m[mm.start()] != CODE:
            continue
        start = mm.start()
        i = _next_code(text, m, mm.end())
        while i < n and text.startswith("#[", i):  # further attributes
            i = _next_code(text, m, _match_close(text, m, i + 1) + 1)
        kw = re.match(r"[A-Za-z_][A-Za-z0-9_!]*", text[i:i + 40])
        kw = kw.group(0) if kw else ""
        mod_decl = re.match(r"(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;", text[i:i + 200])
        if mod_decl:
            test_mods.append(mod_decl.group(1))
        depth = 0
        end = n
        j = i
        while j < n:
            if m[j] != CODE:
                j += 1
                continue
            ch = text[j]
            if ch in "([":
                depth += 1
            elif ch in ")]":
                if depth == 0:
                    end = j
                    break
                depth -= 1
            elif ch == "}" and depth == 0:
                end = j
                break
            elif ch in ";," and depth == 0:
                end = j + 1
                break
            elif ch == "{" and depth == 0:
                close = _match_close(text, m, j)
                k = _next_code(text, m, close + 1)
                if text.startswith("else", k) and kw not in ITEM_KEYWORDS:
                    j = k
                    continue
                end = close + 1
                break
            j += 1
        regions.append((start, end))
    return regions, test_mods


# --------------------------------------------------------------------------
# JSON helpers
# --------------------------------------------------------------------------

class DupKeys(list):
    pass


def strict_json(text):
    dups = DupKeys()

    def hook(pairs):
        seen = {}
        for k, v in pairs:
            if k in seen:
                dups.append(k)
            seen[k] = v
        return seen

    def bad_const(name):
        raise ValueError(f"non-JSON constant {name}")

    return json.loads(text, object_pairs_hook=hook, parse_constant=bad_const), dups


def strip_jsonc(text):
    """Remove // and /* */ comments and trailing commas, outside strings."""
    out, i, n, comments = [], 0, len(text), 0
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            comments += 1
            i = j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            comments += 1
            i = j
            continue
        out.append(c)
        i += 1
    s = "".join(out)
    # trailing commas (outside strings: strings were copied verbatim, so only
    # match a comma followed by whitespace and a closer)
    s2, k = re.subn(r",(\s*[}\]])", r"\1", s)
    return s2, comments, k


def json_size(o):
    return len(json.dumps(o, separators=(",", ":"), ensure_ascii=False, sort_keys=True).encode())


def canon(o):
    return json.dumps(o, separators=(",", ":"), ensure_ascii=False, sort_keys=True)


# --------------------------------------------------------------------------
# classification
# --------------------------------------------------------------------------
HISTORICAL_DOC = re.compile(
    r"^(AUDIT/|docs/audit-r30/[^/]+\.(md|json)$|docs/audit-r30/tools/[^/]+\.tsv$|docs/(round\d|phase\d|adversarial-|clean-room-|"
    r"drift-kamino-|forensic-|final-forensic|identity-boundary-|independent-gap|production-readiness-audit|"
    r"rpc-validation-|audit-core-deprecated|p16-mainnet|release-evaluation-report|solana-foundation-grant)|"
    r"graphite-core/CHANGELOG\.md$)"
)

# Files a path rule would misplace, each with the reason (all checked by
# reading the importers, see the comment on each line).
OVERRIDES = {
    # imported only by *.test.ts in the same package
    "integrations/agent-guard/loopback-mocks.ts": ("test", "test-support", "imported only by *.test.ts"),
    "integrations/agent-guard/swap-fixtures.ts": ("test", "test-support", "imported only by *.test.ts"),
    "integrations/agent-guard/wallet-lock-race-child.ts": ("test", "test-support",
                                                           "spawned only by wallet-lock-integrity.test.ts"),
    # hand-run tools and generators, not imported by the guard
    "integrations/agent-guard/devnet-test.ts": ("script", "live-devnet-harness", "run by live-devnet.yml"),
    "integrations/agent-guard/mainnet-benchmark.ts": ("script", "benchmark-harness", "hand-run (npx tsx)"),
    "integrations/agent-guard/build_exploit_corpus.mts": ("script", "corpus-generator", "hand-run generator"),
    "integrations/agent-guard/rpc-fixtures.cjs": ("script", "fixture-generator", "hand-run generator"),
    "integrations/agent-guard/emit-artifact-fixture.ts": ("script", "fixture-generator", "package.json script"),
    "integrations/agent-guard/emit-corpus.ts": ("script", "fixture-generator", "package.json script"),
    "tools/live-measure/mock_rpc.py": ("test", "test-support", "replay RPC for the live-measure tests"),
    "graphite-core/src/durable/chain_trail_tests.rs": ("test", "rust-unit-test-module",
                                                       "declared `#[cfg(test)] mod chain_trail_tests;` in durable.rs"),
    "dashboard/e2e/seed.mjs": ("test", "e2e-support", "dashboard e2e seed"),
    "dashboard/e2e/smoke.mjs": ("test", "e2e-test", "dashboard e2e smoke run"),
}


def classify(path):
    """(classification, kind, basis)."""
    if path in OVERRIDES:
        c, k, why = OVERRIDES[path]
        return c, k, "override: " + why
    base = os.path.basename(path)
    ext = ext_of(path)
    if base in ("Cargo.lock", "package-lock.json", "requirements-lock.txt", "go.sum"):
        return "lockfile", base, "path rule"
    if path.startswith("graphite-core/protocols/"):
        if base in ("battle_tested_evidence.json", "verified_program_ids.json"):
            return "manifest", "protocol-registry-data", "path rule"
        return "manifest", "protocol-manifest", "path rule"
    if base in ("Cargo.toml", "package.json", "go.mod", "requirements.txt"):
        return "manifest", "package-manifest", "path rule"
    if ext in ("png", "ico", "pdf", "jpg", "svg"):
        return "asset/binary", ext, "extension rule"
    if path.startswith("schemas/"):
        return "schema", "published-json-schema", "path rule"
    if path.startswith("graphite-core/tests/fixtures/contract/"):
        return "schema", "pinned-schema-copy", "path rule"
    if path.startswith("graphite-core/scripts/out/"):
        return "generated", "script-output", "path rule"
    if base.endswith(".proptest-regressions"):
        return "generated", "proptest-regressions", "extension rule"
    if path.startswith(("graphite-core/fixtures/", "graphite-core/tests/fixtures/", "sdk/go/testdata/")):
        return "corpus/fixture data", "fixture", "path rule"
    if path.startswith("graphite-core/fuzz/seeds/"):
        return "corpus/fixture data", "fuzz-seed", "path rule"
    if path.startswith("examples/"):
        return "corpus/fixture data", "example-data", "path rule"
    if path.startswith("graphite-core/scripts/") and ext in ("json", "txt"):
        return "corpus/fixture data", "script-input-data", "path rule"
    if ext == "md" or base == "LICENSE":
        if HISTORICAL_DOC.match(path):
            return "historical-report", "dated-report", "path rule"
        return "documentation", "doc", "extension rule"
    if path.startswith("docs/audit-r30/"):
        if ext == "py":
            return "script", "audit-tool", "path rule"
        return "historical-report", "audit-r30-record", "path rule"
    if (path.startswith("graphite-core/tests/") or path.startswith("graphite-core/fuzz/fuzz_targets/")
            or re.search(r"\.test\.(ts|tsx|mts|mjs|sh|yml)$", base) or base.endswith("_test.go")
            or (base.startswith("test_") and ext == "py") or path == "deploy/tests/run.sh"):
        kind = "fuzz-target" if "/fuzz_targets/" in path else "test"
        return "test", kind, "path rule"
    if path.startswith(".github/"):
        if path.startswith(".github/workflows/"):
            return "ci", "workflow", "path rule"
        if path.startswith(".github/scripts/"):
            return "ci", "ci-script", "path rule"
        return "ci", "repo-policy", "path rule"
    if path.startswith("deploy/") or base in ("Dockerfile", "docker-compose.yml", ".dockerignore"):
        return "deployment", "deploy", "path rule"
    if base.startswith("tsconfig") or base in ("vite.config.ts", ".gitignore", ".gitattributes") or \
            base.endswith(".env.example") or base == ".env.example":
        return "config", "config", "path rule"
    if path.startswith(("graphite-core/scripts/", "tools/")) or path in ("graphite-core/build_manifests.py",
                                                                       "graphite-core/fuzz/make_seeds.py"):
        if path.startswith("tools/") and ext in ("toml",):
            return "manifest", "package-manifest", "path rule"
        return "script", "dev-tool", "path rule"
    if ext in ("rs", "ts", "tsx", "mts", "go", "py", "mjs", "cjs", "css", "html", "js"):
        return "runtime-source", "source", "extension rule"
    return "config", "config", "fallback rule"


SUBSYSTEMS = [
    (".github/", "ci-and-repo-policy"),
    ("graphite-core/src/", "rust-core"),
    ("graphite-core/tests/fixtures/", "rust-core-test-fixtures"),
    ("graphite-core/tests/", "rust-core-tests"),
    ("graphite-core/protocols/", "protocol-registry"),
    ("graphite-core/fixtures/corpus/", "regression-corpus"),
    ("graphite-core/fixtures/", "core-fixtures"),
    ("graphite-core/fuzz/", "fuzzing"),
    ("graphite-core/scripts/out/", "protocol-data-generated"),
    ("graphite-core/scripts/", "protocol-data-scripts"),
    ("graphite-core/", "rust-core-meta"),
    ("tools/runtime-oracle/", "runtime-oracle"),
    ("tools/inner-instruction-oracle/", "inner-instruction-oracle"),
    ("tools/mainnet-sample/", "mainnet-sample-tools"),
    ("tools/live-measure/", "live-measure-tools"),
    ("integrations/agent-guard/", "agent-guard"),
    ("integrations/solana-agent-kit/", "solana-agent-kit-adapter"),
    ("integrations/mcp-server/", "mcp-adapter"),
    ("integrations/vercel-ai/", "vercel-ai-adapter"),
    ("sdk/typescript/", "sdk-typescript"),
    ("sdk/go/", "sdk-go"),
    ("python-ai-layer/", "python-ai-layer"),
    ("dashboard/", "dashboard"),
    ("deploy/", "deploy-kit"),
    ("schemas/", "published-schemas"),
    ("examples/", "examples"),
    ("AUDIT/", "historical-audit"),
    ("docs/audit-r30/", "audit-r30-record"),
    ("docs/ops/", "ops-docs"),
    ("docs/", "docs"),
    ("assets/", "brand-assets"),
]


def subsystem_of(path):
    for prefix, name in SUBSYSTEMS:
        if path.startswith(prefix):
            return name
    return "repo-root"


# --------------------------------------------------------------------------
# per-type validators: each returns (checks, results, problems)
# --------------------------------------------------------------------------
MANIFEST_TOP = {"graphite_manifest_version", "protocol", "version", "instructions", "trust_tier"}
MANIFEST_TOP_OPTIONAL = {"verification"}
INSTR_REQUIRED = {"name": str, "discriminator": str, "accounts": list, "expected_state_changes": list,
                  "allowed_cpis": list, "risk_rules": list, "risk_class": str}
INSTR_OPTIONAL = {"variable_accounts": bool, "account_layouts": list}
ACCOUNT_REQUIRED = {"name": str, "role": str, "is_writable": bool, "is_signer": bool, "pda_seeds": list}
ACCOUNT_OPTIONAL = {"optional": bool, "expected_address": list}
RISK_CLASSES = {"", "authority", "transfer", "create", "withdraw", "close", "inert", "mint", "drain", "stake"}
TRUST_TIERS = {"BattleTested", "OfficialManifest", "CommunityVerified", "Unverified"}


def check_protocol_manifest(obj, path):
    checks = ["schema_checked:protocol-manifest(top-level keys, protocol.program_id base58/32 bytes, "
              "instruction field types, account field types, discriminator hex/even-length/unique, "
              "instruction names unique, risk_class vocabulary)"]
    res, probs = {}, []
    if not isinstance(obj, dict):
        return checks, res, ["manifest is not an object"]
    missing = sorted(MANIFEST_TOP - set(obj))
    extra = sorted(set(obj) - MANIFEST_TOP - MANIFEST_TOP_OPTIONAL)
    if missing:
        probs.append(f"missing top-level keys {missing}")
    if extra:
        probs.append(f"unexpected top-level keys {extra}")
    p = obj.get("protocol") or {}
    pid = p.get("program_id")
    res["program_id"] = pid
    res["protocol_name"] = p.get("name")
    if not is_pubkey(pid):
        probs.append(f"protocol.program_id {pid!r} is not a 32-byte base58 key")
    res["trust_tier"] = obj.get("trust_tier")
    if obj.get("trust_tier") not in TRUST_TIERS:
        probs.append(f"trust_tier {obj.get('trust_tier')!r} not in {sorted(TRUST_TIERS)}")
    res["graphite_manifest_version"] = obj.get("graphite_manifest_version")
    ins = obj.get("instructions")
    if not isinstance(ins, list):
        probs.append("instructions is not a list")
        ins = []
    res["instructions"] = len(ins)
    checks.append(f"record_count:instructions={len(ins)}")
    rc = Counter()
    discs, names = Counter(), Counter()
    accounts = 0
    type_errs = Counter()
    for k, i in enumerate(ins):
        if not isinstance(i, dict):
            type_errs["instruction not an object"] += 1
            continue
        for f, t in INSTR_REQUIRED.items():
            if f not in i:
                type_errs[f"instruction missing {f}"] += 1
            elif not isinstance(i[f], t):
                type_errs[f"instruction {f} not {t.__name__}"] += 1
        for f in i:
            if f not in INSTR_REQUIRED and f not in INSTR_OPTIONAL:
                type_errs[f"instruction unexpected key {f}"] += 1
            elif f in INSTR_OPTIONAL and not isinstance(i[f], INSTR_OPTIONAL[f]):
                type_errs[f"instruction {f} not {INSTR_OPTIONAL[f].__name__}"] += 1
        d = i.get("discriminator", "")
        if not isinstance(d, str):
            d = ""
        if not re.fullmatch(r"[0-9a-f]*", d):
            type_errs["discriminator not lowercase hex"] += 1
        if len(d) % 2:
            type_errs["discriminator odd length"] += 1
        discs[d] += 1
        names[i.get("name")] += 1
        rc[i.get("risk_class") if isinstance(i.get("risk_class"), str) else "<non-string>"] += 1
        if isinstance(i.get("risk_class"), str) and i["risk_class"] not in RISK_CLASSES:
            type_errs[f"risk_class {i['risk_class']!r} outside vocabulary"] += 1
        for a in i.get("accounts") or []:
            accounts += 1
            if not isinstance(a, dict):
                type_errs["account not an object"] += 1
                continue
            for f, t in ACCOUNT_REQUIRED.items():
                if f not in a:
                    type_errs[f"account missing {f}"] += 1
                elif not isinstance(a[f], t):
                    type_errs[f"account {f} not {t.__name__}"] += 1
            for f in a:
                if f not in ACCOUNT_REQUIRED and f not in ACCOUNT_OPTIONAL:
                    type_errs[f"account unexpected key {f}"] += 1
            for addr in a.get("expected_address") or []:
                if not is_pubkey(addr):
                    type_errs["expected_address not a 32-byte base58 key"] += 1
    # an empty discriminator matches any data (the Memo programs have no
    # instruction tag): recorded, not flagged
    res["empty_discriminators"] = discs.get("", 0)
    res["accounts"] = accounts
    res["risk_classes"] = dict(sorted(rc.items()))
    res["unclassed_instructions"] = rc.get("", 0)
    dupd = sorted(d for d, c in discs.items() if c > 1)
    dupn = sorted(str(x) for x, c in names.items() if c > 1)
    if dupd:
        probs.append(f"duplicate discriminators {dupd[:8]}")
    if dupn:
        probs.append(f"duplicate instruction names {dupn[:8]}")
    # one discriminator a strict prefix of another: informational (the
    # matcher's longest-prefix rule is the code's business, not this tool's)
    dl = sorted(d for d in discs if d)
    prefix_pairs = sum(1 for a in dl for b in dl if a != b and b.startswith(a))
    res["discriminator_prefix_pairs"] = prefix_pairs
    for k, v in sorted(type_errs.items()):
        probs.append(f"{k} (x{v})")
    return checks, res, probs


def check_protocol_registry_data(obj, base):
    checks = ["schema_checked:program-list(program_id base58/32 bytes, unique ids)"]
    res, probs = {}, []
    progs = obj.get("programs") if isinstance(obj, dict) else None
    if not isinstance(progs, list):
        return checks, res, ["no programs list"]
    ids = [p.get("program_id") for p in progs]
    res["programs"] = len(progs)
    checks.append(f"record_count:programs={len(progs)}")
    bad = sorted(str(i) for i in ids if not is_pubkey(i))
    dup = sorted(i for i, c in Counter(ids).items() if c > 1)
    if bad:
        probs.append(f"program ids not 32-byte base58: {bad[:5]}")
    if dup:
        probs.append(f"duplicate program ids: {dup[:5]}")
    if base == "battle_tested_evidence.json":
        rates = [((p.get("decode") or {}).get("decode_rate"), p.get("program_id"), p.get("name")) for p in progs]
        below = sorted((n or pid) for r, pid, n in rates if isinstance(r, (int, float)) and r < 0.9)
        res["decode_rate_below_0.9"] = len(below)
        res["decode_rate_below_0.9_names"] = below
        res["decode_rate_missing"] = sum(1 for r, _, _ in rates if not isinstance(r, (int, float)))
        res["meets_battle_tested_true"] = sum(1 for p in progs if p.get("meets_battle_tested") is True)
        res["declared_trust_tier"] = dict(sorted(Counter(str(p.get("declared_trust_tier")) for p in progs).items()))
    if base == "verified_program_ids.json":
        res["verified_true"] = sum(1 for p in progs if p.get("verified") is True)
    return checks, res, probs


CORPUS_KEYS = {"program_id", "version", "content_hash", "expected_approved", "source", "deprecated", "input",
               "integrity_hash"}
CORPUS_OPTIONAL = {"label_source"}
OVERSIZE_RECORD_BYTES = 256 * 1024


def corpus_hashes(r):
    c = hashlib.sha256((r["source"] + "\n" + json.dumps(r["input"], separators=(",", ":"),
                                                        ensure_ascii=False)).encode()).hexdigest()
    h = hashlib.sha256()
    h.update(b"graphite-regression-fixture-integrity-v1\0")
    for part in [r["program_id"], r["version"], r["content_hash"],
                 "approved" if r["expected_approved"] else "refused",
                 "deprecated" if r["deprecated"] else "active", r.get("label_source") or ""]:
        h.update(part.encode())
        h.update(b"\0")
    return c, h.hexdigest()


def check_corpus_file(obj, path):
    checks = ["schema_checked:regression-fixture(keys, types, program_id == file name == input.program_id)",
              "content_hash_recomputed(sha256(source + '\\n' + compact JSON of input), as regression_engine.rs)",
              "integrity_hash_recomputed(as RegressionFixture::integrity_hash_of)",
              "duplicate_record_scan(content_hash, integrity_hash, whole record)",
              f"oversize_scan(record > {OVERSIZE_RECORD_BYTES} bytes compact JSON)"]
    res, probs = {}, []
    if not isinstance(obj, list):
        return checks, res, ["corpus file is not an array"]
    res["records"] = len(obj)
    checks.append(f"record_count:{len(obj)}")
    pid = os.path.basename(path)[:-5]
    malformed = Counter()
    ch_bad = ih_bad = 0
    sizes = []
    for r in obj:
        if not isinstance(r, dict):
            malformed["record not an object"] += 1
            continue
        miss = CORPUS_KEYS - set(r)
        extra = set(r) - CORPUS_KEYS - CORPUS_OPTIONAL
        for k in sorted(miss):
            malformed[f"missing {k}"] += 1
        for k in sorted(extra):
            malformed[f"unexpected key {k}"] += 1
        if miss:
            continue
        if r["program_id"] != pid:
            malformed["program_id differs from file name"] += 1
        if not isinstance(r["input"], dict) or r["input"].get("program_id") != r["program_id"]:
            malformed["input.program_id differs from program_id"] += 1
        if not isinstance(r["expected_approved"], bool) or not isinstance(r["deprecated"], bool):
            malformed["expected_approved/deprecated not boolean"] += 1
        if not re.fullmatch(r"[0-9a-f]{64}", str(r["content_hash"])) or \
                not re.fullmatch(r"[0-9a-f]{64}", str(r["integrity_hash"])):
            malformed["hash not 64 lowercase hex"] += 1
        try:
            c, h = corpus_hashes(r)
            ch_bad += c != r["content_hash"]
            ih_bad += h != r["integrity_hash"]
        except (TypeError, AttributeError, KeyError):
            malformed["hash inputs not strings"] += 1
        sizes.append(json_size(r))
    dch = sum(c - 1 for c in Counter(r.get("content_hash") for r in obj if isinstance(r, dict)).values() if c > 1)
    dih = sum(c - 1 for c in Counter(r.get("integrity_hash") for r in obj if isinstance(r, dict)).values() if c > 1)
    drec = sum(c - 1 for c in Counter(canon(r) for r in obj).values() if c > 1)
    res.update({
        "content_hash_mismatches": ch_bad, "integrity_hash_mismatches": ih_bad,
        "duplicate_content_hash": dch, "duplicate_integrity_hash": dih, "duplicate_records": drec,
        "expected_approved": {"true": sum(1 for r in obj if isinstance(r, dict) and r.get("expected_approved") is True),
                              "false": sum(1 for r in obj if isinstance(r, dict) and r.get("expected_approved") is False)},
        "deprecated": sum(1 for r in obj if isinstance(r, dict) and r.get("deprecated") is True),
        "sources": dict(sorted(Counter(str(r.get("source")) for r in obj if isinstance(r, dict)).items())),
        "max_record_bytes": max(sizes) if sizes else 0,
        "oversized_records": sum(1 for s in sizes if s > OVERSIZE_RECORD_BYTES),
    })
    for k, v in sorted(malformed.items()):
        probs.append(f"malformed: {k} (x{v})")
    if ch_bad:
        probs.append(f"{ch_bad} content_hash values do not recompute")
    if ih_bad:
        probs.append(f"{ih_bad} integrity_hash values do not recompute")
    for k in ("duplicate_content_hash", "duplicate_integrity_hash", "duplicate_records"):
        if res[k]:
            probs.append(f"{k}: {res[k]}")
    if res["oversized_records"]:
        probs.append(f"{res['oversized_records']} records over {OVERSIZE_RECORD_BYTES} bytes")
    return checks, res, probs


def check_corpus_meta(obj):
    checks = ["schema_checked:corpus-meta(hash 64 hex, split/class/provenance strings)",
              "duplicate_record_scan(hash)"]
    res, probs = {}, []
    if not isinstance(obj, list):
        return checks, res, ["not an array"]
    res["records"] = len(obj)
    checks.append(f"record_count:{len(obj)}")
    bad = sum(1 for r in obj if not (isinstance(r, dict) and re.fullmatch(r"[0-9a-f]{64}", str(r.get("hash")))
                                     and all(isinstance(r.get(k), str) for k in ("split", "class", "provenance"))))
    if bad:
        probs.append(f"malformed records: {bad}")
    d = sum(c - 1 for c in Counter(r.get("hash") for r in obj if isinstance(r, dict)).values() if c > 1)
    res["duplicate_hash"] = d
    if d:
        probs.append(f"duplicate hash: {d}")
    res["split"] = dict(sorted(Counter(str(r.get("split")) for r in obj if isinstance(r, dict)).items()))
    res["class"] = dict(sorted(Counter(str(r.get("class")) for r in obj if isinstance(r, dict)).items()))
    return checks, res, probs


def check_idl(obj, path):
    checks = ["schema_checked:idl(instructions list, names unique, address/file-name agreement where present)"]
    res, probs = {}, []
    if not isinstance(obj, dict) or not isinstance(obj.get("instructions"), list):
        return checks, res, ["no instructions list"]
    ins = obj["instructions"]
    res["instructions"] = len(ins)
    checks.append(f"record_count:instructions={len(ins)}")
    names = Counter(i.get("name") for i in ins if isinstance(i, dict))
    dn = sorted(str(n) for n, c in names.items() if c > 1)
    if dn:
        probs.append(f"duplicate instruction names {dn[:5]}")
    if any(not isinstance(i, dict) or not isinstance(i.get("name"), str) for i in ins):
        probs.append("instruction without a string name")
    for k in ("accounts", "types", "events", "errors"):
        if isinstance(obj.get(k), list):
            res[k] = len(obj[k])
    stem = os.path.basename(path)[:-5]
    if path.startswith("graphite-core/scripts/out/onchain_idls/"):
        if not is_pubkey(stem):
            probs.append("file name is not a 32-byte base58 program id")
        addr = obj.get("address") or (obj.get("metadata") or {}).get("address")
        res["address_field"] = addr
        if addr is not None and addr != stem:
            probs.append(f"address {addr!r} differs from file name")
    return checks, res, probs


def check_json_schema(obj):
    checks = ["schema_checked:json-schema-shape($schema present, required names listed in properties, recursively)"]
    probs = []
    if not isinstance(obj, dict) or "$schema" not in obj:
        probs.append("no $schema")

    def walk(o, where):
        if isinstance(o, dict):
            req, props = o.get("required"), o.get("properties")
            if isinstance(req, list) and isinstance(props, dict):
                miss = [r for r in req if r not in props]
                if miss:
                    probs.append(f"{where}: required not in properties: {miss}")
            for k, v in o.items():
                walk(v, f"{where}/{k}")
        elif isinstance(o, list):
            for k, v in enumerate(o):
                walk(v, f"{where}/{k}")

    walk(obj, "#")
    res = {"top_level_required": len(obj.get("required") or []) if isinstance(obj, dict) else 0,
           "top_level_properties": len(obj.get("properties") or {}) if isinstance(obj, dict) else 0}
    return checks, res, probs


def check_npm_lock(obj):
    checks = ["npm_lock_checked(packages counted; integrity present; resolved host; install scripts listed)"]
    res, probs = {}, []
    pk = obj.get("packages") or {}
    res["lockfileVersion"] = obj.get("lockfileVersion")
    res["packages"] = sum(1 for k in pk if k)
    checks.append(f"record_count:packages={res['packages']}")
    hosts, noint, scripts, links = Counter(), [], [], 0
    for name, meta in sorted(pk.items()):
        if not name:
            continue
        if meta.get("link"):
            links += 1
            continue
        r = meta.get("resolved", "")
        if r:
            hosts[re.sub(r"^(\w+://[^/]+).*", r"\1", r)] += 1
        if not meta.get("integrity"):
            noint.append(name)
        if meta.get("hasInstallScript"):
            scripts.append(name.split("node_modules/")[-1])
    res["resolved_hosts"] = dict(sorted(hosts.items()))
    res["links"] = links
    res["install_script_packages"] = sorted(set(scripts))
    if noint:
        probs.append(f"{len(noint)} packages without integrity: {noint[:5]}")
    other = sorted(h for h in hosts if h != "https://registry.npmjs.org")
    if other:
        probs.append(f"packages resolved from hosts other than registry.npmjs.org: {other}")
    return checks, res, probs


def check_cargo_lock(text):
    obj = tomllib.loads(text)
    checks = ["toml_parsed", "cargo_lock_checked(packages counted; registry packages carry checksums; git sources)"]
    pk = obj.get("package", [])
    res = {"lock_version": obj.get("version"), "packages": len(pk),
           "sources": dict(sorted(Counter((p.get("source") or "path").split("+")[0] for p in pk).items())),
           "crates_with_multiple_versions": len([n for n, c in Counter(p["name"] for p in pk).items() if c > 1])}
    checks.append(f"record_count:packages={len(pk)}")
    probs = []
    nock = sorted(p["name"] for p in pk if (p.get("source") or "").startswith("registry+") and not p.get("checksum"))
    if nock:
        probs.append(f"registry packages without checksum: {nock[:5]}")
    gits = sorted(p["name"] for p in pk if (p.get("source") or "").startswith("git+"))
    if gits:
        probs.append(f"git-sourced crates: {gits}")
    dupkey = sorted(f"{n}@{v}" for (n, v), c in Counter((p["name"], p["version"]) for p in pk).items() if c > 1)
    if dupkey:
        probs.append(f"duplicate name@version entries: {dupkey[:5]}")
    return checks, res, probs


def check_pip_lock(text):
    checks = ["pip_lock_checked(every pinned requirement followed by --hash=sha256 lines)"]
    reqs, cur, nohash = [], None, []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        mm = re.match(r"^([A-Za-z0-9_.\-\[\]]+)==([^\s\\;]+)", s)
        if mm:
            if cur and not cur[1]:
                nohash.append(cur[0])
            cur = [mm.group(1), "--hash=sha256:" in s]
            reqs.append(mm.group(1))
        elif s.startswith("--hash=sha256:") and cur:
            cur[1] = True
    if cur and not cur[1]:
        nohash.append(cur[0])
    res = {"pinned_requirements": len(reqs), "hash_lines": text.count("--hash=sha256:")}
    checks.append(f"record_count:requirements={len(reqs)}")
    return checks, res, ([f"requirements without a hash: {nohash}"] if nohash else [])


def check_requirements(text):
    checks = ["requirements_lines_parsed"]
    reqs, odd = [], []
    for line in text.splitlines():
        s = line.split("#", 1)[0].strip()
        if not s:
            continue
        if re.match(r"^[A-Za-z0-9_.\-\[\]]+\s*([<>=!~]=?[^,\s]+(\s*,\s*[<>=!~]=?[^,\s]+)*)?(\s*;.*)?$", s) or s.startswith("-"):
            reqs.append(s)
        else:
            odd.append(s)
    checks.append(f"record_count:requirements={len(reqs)}")
    return checks, {"requirements": len(reqs)}, ([f"unparsed lines: {odd[:5]}"] if odd else [])


def check_go_mod(text):
    checks = ["go_mod_parsed(module, go directive, require entries)"]
    mod = re.search(r"^module\s+(\S+)", text, re.M)
    gov = re.search(r"^go\s+(\S+)", text, re.M)
    req = re.findall(r"^\s*(?:require\s+)?([a-z0-9.\-]+\.[a-z]+/\S+)\s+v\S+", text, re.M)
    res = {"module": mod.group(1) if mod else None, "go": gov.group(1) if gov else None, "requires": len(req)}
    probs = [] if mod and gov else ["module or go directive missing"]
    if req:
        probs.append("go.mod has requirements but the tree has no go.sum")
    return checks, res, probs


def check_png(b):
    if b[:8] != b"\x89PNG\r\n\x1a\n":
        return ["png_header_checked:failed"], {}, ["not a PNG signature"]
    w, h, depth, ctype = struct.unpack(">IIBB", b[16:26])
    chunks, i, crc_bad, trailing = [], 8, 0, 0
    while i + 8 <= len(b):
        ln = struct.unpack(">I", b[i:i + 4])[0]
        typ = b[i + 4:i + 8]
        body = b[i + 8:i + 8 + ln]
        crc = struct.unpack(">I", b[i + 8 + ln:i + 12 + ln])[0] if i + 12 + ln <= len(b) else None
        if crc is None or zlib.crc32(typ + body) & 0xFFFFFFFF != crc:
            crc_bad += 1
        chunks.append(typ.decode("latin1"))
        i += 12 + ln
        if typ == b"IEND":
            trailing = len(b) - i
            break
    probs = []
    if crc_bad:
        probs.append(f"{crc_bad} chunks with a bad CRC")
    if not chunks or chunks[-1] != "IEND":
        probs.append("no IEND chunk")
    if trailing:
        probs.append(f"{trailing} bytes after IEND")
    return ([f"png_header_checked:{w}x{h}", "png_chunks_crc_checked"],
            {"width": w, "height": h, "bit_depth": depth, "color_type": ctype,
             "chunk_types": sorted(set(chunks)), "text_chunks": sum(1 for c in chunks if c in ("tEXt", "iTXt", "zTXt"))},
            probs)


def check_ico(b):
    if b[:4] != b"\x00\x00\x01\x00":
        return ["ico_header_checked:failed"], {}, ["not an ICO header"]
    n = struct.unpack("<H", b[4:6])[0]
    sizes, probs = [], []
    for k in range(n):
        e = b[6 + 16 * k:22 + 16 * k]
        if len(e) < 16:
            probs.append("directory truncated")
            break
        w, h = e[0] or 256, e[1] or 256
        size, off = struct.unpack("<II", e[8:16])
        if off + size > len(b):
            probs.append(f"image {k} extends past end of file")
        sizes.append(f"{w}x{h}")
    return [f"ico_header_checked:{n}-images"], {"images": n, "sizes": sizes}, probs


def check_pdf(b):
    checks = ["pdf_header_checked", "pdf_eof_marker_checked", "pdf_active_content_scan(/JavaScript /JS /Launch /EmbeddedFile /OpenAction /AA)"]
    probs = []
    if not b.startswith(b"%PDF-"):
        return checks, {}, ["not a PDF header"]
    res = {"version": b[5:8].decode("latin1"),
           "page_objects": len(re.findall(rb"/Type\s*/Page(?!s)", b)),
           "eof_marker": b"%%EOF" in b[-1024:]}
    for k, pat in (("javascript", rb"/JavaScript|/JS\b"), ("launch", rb"/Launch"), ("embedded_files", rb"/EmbeddedFile"),
                   ("open_action", rb"/OpenAction"), ("additional_actions", rb"/AA\b")):
        res[k] = bool(re.search(pat, b))
    if not res["eof_marker"]:
        probs.append("no %%EOF in the last 1 KiB")
    for k in ("javascript", "launch", "embedded_files"):
        if res[k]:
            probs.append(f"PDF contains {k}")
    return checks, res, probs


def check_ini(text):
    checks = ["ini_parsed(configparser, duplicate keys allowed as systemd allows)", "duplicate_key_scan"]
    cp = configparser.ConfigParser(strict=False, interpolation=None)
    cp.optionxform = str
    probs = []
    try:
        cp.read_string(text)
    except configparser.Error as e:
        return checks, {}, [f"ini parse failed: {type(e).__name__}"]
    sect, dups = None, Counter()
    seen = defaultdict(Counter)
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("["):
            sect = s
        elif "=" in s and not s.startswith(("#", ";")):
            seen[sect][s.split("=", 1)[0].strip()] += 1
    res = {"sections": sorted(cp.sections()),
           "repeated_keys": {f"{s}{k}": c for s, ks in sorted(seen.items(), key=lambda x: str(x[0]))
                             for k, c in sorted(ks.items()) if c > 1}}
    return checks, res, probs


def check_dotenv(text):
    checks = ["dotenv_line_format(KEY=VALUE or comment)", "duplicate_key_scan"]
    keys, bad = Counter(), []
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        mm = re.match(r"^(export\s+)?([A-Za-z_][A-Za-z0-9_]*)=", s)
        if mm:
            keys[mm.group(2)] += 1
        else:
            bad.append(n)
    dups = sorted(k for k, c in keys.items() if c > 1)
    probs = []
    if bad:
        probs.append(f"lines not KEY=VALUE: {bad[:10]}")
    if dups:
        probs.append(f"duplicate keys: {dups}")
    return checks, {"keys": len(keys)}, probs


YAML_KEY = re.compile(r"^(\s*)(-\s+)?((?:\"[^\"]*\"|'[^']*'|[^\s#:][^:#]*?))\s*:(\s|$)")


def check_yaml_lexical(text):
    """Not a YAML parse (the standard library has none): tab indentation and
    repeated keys in one block mapping, by indentation, skipping block
    scalars and flow collections."""
    checks = ["yaml_not_parsed(no stdlib YAML parser)",
              "yaml_line_scan(tab indentation; repeated keys within one block mapping, by indentation)"]
    probs, tabs = [], 0
    stack = []  # (indent, Counter)
    block_indent = None
    dups = []
    for n, line in enumerate(text.splitlines(), 1):
        if line.strip() == "" or line.lstrip().startswith("#"):
            continue
        ind = len(line) - len(line.lstrip(" "))
        if line[ind:ind + 1] == "\t":
            tabs += 1
        if block_indent is not None:
            if ind > block_indent:
                continue
            block_indent = None
        if line.strip() == "---":
            stack = []
            continue
        mm = YAML_KEY.match(line)
        if not mm:
            continue
        key_ind = ind + (len(mm.group(2)) if mm.group(2) else 0)
        while stack and stack[-1][0] > key_ind:
            stack.pop()
        if mm.group(2):
            while stack and stack[-1][0] >= key_ind:
                stack.pop()
            stack.append((key_ind, Counter()))
        elif not stack or stack[-1][0] < key_ind:
            stack.append((key_ind, Counter()))
        key = mm.group(3).strip().strip("\"'")
        stack[-1][1][key] += 1
        if stack[-1][1][key] == 2:
            dups.append(f"{key}@{n}")
        rest = line[mm.end():].split(" #", 1)[0].strip()
        if rest[:1] in ("|", ">"):
            block_indent = ind if not mm.group(2) else key_ind
    if tabs:
        probs.append(f"{tabs} lines indented with a tab")
    if dups:
        probs.append(f"repeated key in one block mapping (lexical scan, verify by hand): {dups[:5]}")
    return checks, {}, probs


def check_markdown_links(path, text, tree_paths, tree_dirs):
    checks = ["markdown_relative_links_checked(relative link targets exist in the tree)"]
    base = os.path.dirname(path)
    total, broken = 0, []
    nocode = re.sub(r"```.*?```", "", text, flags=re.S)
    nocode = re.sub(r"`[^`\n]*`", "", nocode)
    for mm in re.finditer(r"\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)", nocode):
        tgt = mm.group(1)
        if re.match(r"^[a-z][a-z0-9+.\-]*:", tgt, re.I) or tgt.startswith("#") or tgt.startswith("<"):
            continue
        tgt = tgt.split("#", 1)[0].split("?", 1)[0]
        if not tgt:
            continue
        total += 1
        p = os.path.normpath(os.path.join(base, tgt)) if not tgt.startswith("/") else tgt.lstrip("/")
        if p not in tree_paths and p not in tree_dirs:
            broken.append(tgt)
    res = {"relative_links": total, "broken_relative_links": len(broken)}
    if broken:
        res["broken_link_targets"] = sorted(set(broken))[:20]
    return checks, res, ([f"{len(broken)} relative links whose target is not in the tree"] if broken else [])


def check_tsv(text):
    rows = [l for l in text.splitlines() if l and not l.startswith("#")]
    widths = Counter(len(r.split("\t")) for r in rows)
    return (["tsv_column_check"], {"rows": len(rows), "column_counts": dict(sorted(widths.items()))},
            [] if len(widths) <= 1 else [f"rows with differing column counts: {dict(sorted(widths.items()))}"])


def check_proptest_regressions(text):
    rows = [l for l in text.splitlines() if l.strip() and not l.startswith("#")]
    bad = [l for l in rows if not re.match(r"^cc [0-9a-f]{64}\b", l)]
    return (["proptest_regressions_format(cc <64 hex> lines)"], {"cases": len(rows)},
            [f"{len(bad)} lines not in `cc <hash>` form"] if bad else [])


SECRET = re.compile(
    r"(-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|"
    r"github_pat_[A-Za-z0-9_]{40,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{32,}|sk-ant-[A-Za-z0-9\-_]{20,}|"
    r"AIza[0-9A-Za-z\-_]{35})"
)
SECRET_LABEL = "secret_pattern_scan(PEM private key, AWS AKIA, GitHub ghp_/gho_/github_pat_, Slack xox*, sk-/sk-ant-, Google AIza)"


# --------------------------------------------------------------------------
# scan triage patterns
# --------------------------------------------------------------------------
TS_EXT = ("ts", "tsx", "mts", "cts")
JS_EXT = TS_EXT + ("js", "mjs", "cjs")


def in_core_src(p):
    return p.startswith("graphite-core/src/") and p.endswith(".rs")


PATTERNS = [
    # name, regex, flags, scope predicate(path, rec), scope description
    ("todo_marker", r"\b(?:TODO|FIXME|XXX)\b", 0, lambda p, r: r["_text"] is not None,
     "every UTF-8 file in the tree"),
    ("todo_macro", r"\btodo!\s*\(", 0, lambda p, r: p.endswith(".rs"), "every .rs file"),
    ("unimplemented_macro", r"\bunimplemented!\s*\(", 0, lambda p, r: p.endswith(".rs"), "every .rs file"),
    ("unsafe", r"\bunsafe\b", 0, lambda p, r: p.endswith(".rs"), "every .rs file (the Rust keyword)"),
    ("as_any", r"\bas\s+any\b", 0, lambda p, r: ext_of(p) in TS_EXT, "every .ts/.tsx/.mts/.cts file"),
    ("unwrap_expect", r"\.unwrap\(\)|\.expect\(", 0, lambda p, r: in_core_src(p),
     "graphite-core/src/**/*.rs (counted per file; non-test hits listed)"),
    ("catch_unwind", r"\bcatch_unwind\b", 0, lambda p, r: p.endswith(".rs"), "every .rs file"),
    ("panic_macro", r"\bpanic!\s*\(", 0, lambda p, r: in_core_src(p), "graphite-core/src/**/*.rs"),
    ("test_skip_rust_ignore", r"#\[\s*ignore\b", 0, lambda p, r: p.endswith(".rs"), "every .rs file"),
    ("test_skip_js", r"\b(?:test|it|describe)\.(?:skip|only|todo)\b|\{\s*skip\s*:|\bskip\s*:\s*(?:true|!|process)", 0,
     lambda p, r: ext_of(p) in JS_EXT, "every JS/TS file (also .only/.todo and node:test {skip:})"),
    ("test_skip_go", r"\bt\.Skip(?:f|Now)?\s*\(", 0, lambda p, r: p.endswith(".go"), "every .go file"),
    ("test_skip_py", r"pytest\.mark\.skip|unittest\.skip|\.skipTest\s*\(", 0, lambda p, r: p.endswith(".py"),
     "every .py file"),
    ("workflow_continue_on_error", r"continue-on-error", 0,
     lambda p, r: p.startswith(".github/workflows/"), ".github/workflows/*"),
    ("workflow_error_masking", r"\|\|\s*true\b|\bset\s+\+e\b", 0,
     lambda p, r: p.startswith(".github/workflows/") or (p.startswith(".github/scripts/") and p.endswith(".sh")),
     ".github/workflows/* and .github/scripts/*.sh (`|| true`, `set +e`)"),
    ("mock_words", r"mock|fake|stub|demo|sample", re.I,
     lambda p, r: r["classification"] == "runtime-source", "files classified runtime-source (case-insensitive substring)"),
    ("secret_like", SECRET.pattern, 0, lambda p, r: r["_text"] is not None, "every UTF-8 file"),
]
COMPILED = [(n, re.compile(rx, fl), scope, desc) for n, rx, fl, scope, desc in PATTERNS]


def main():
    args = sys.argv[1:]
    opt = {"--repo": os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")),
           "--commit": BASE_COMMIT, "--out": None}
    while args:
        k = args.pop(0)
        if k not in opt or not args:
            sys.exit(__doc__)
        opt[k] = args.pop(0)
    root = opt["--repo"]
    commit = git(root, "rev-parse", "--verify", opt["--commit"] + "^{commit}").decode().strip()
    out_dir = opt["--out"] or os.path.join(root, "docs", "audit-r36")
    tree = git(root, "rev-parse", commit + "^{tree}").decode().strip()

    entries = tree_entries(root, commit)
    non_blob = [e for e in entries if e["type"] != "blob"]
    entries = sorted((e for e in entries if e["type"] == "blob"), key=lambda e: e["path"])
    lsf = ls_files_at(root, commit)
    count_check = {
        "ls_tree_blobs": len(entries),
        "ls_tree_non_blob_entries": len(non_blob),
        "ls_files": len(lsf),
        "same_paths": sorted(lsf) == [e["path"] for e in entries],
        "same_blobs_and_modes": all(lsf.get(e["path"]) == (e["mode"], e["sha"]) for e in entries),
    }
    blobs = read_blobs(root, sorted({e["sha"] for e in entries}))
    tree_paths = {e["path"] for e in entries}
    tree_dirs = set()
    for p in tree_paths:
        d = os.path.dirname(p)
        while d:
            tree_dirs.add(d)
            d = os.path.dirname(d)

    # the Round 30 ledger, from this commit's own blob
    r30 = {}
    r30_entry = next((e for e in entries if e["path"] == R30_LEDGER), None)
    if r30_entry:
        for f in json.loads(blobs[r30_entry["sha"]])["files"]:
            r30[f["path"]] = f["git_blob"]

    records = []
    rust_test_mod_files = set()
    for e in entries:
        path, data = e["path"], blobs[e["sha"]]
        cls, kind, basis = classify(path)
        rec = {
            "path": path, "git_blob": e["sha"], "mode": e["mode"], "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(), "classification": cls, "kind": kind,
            "classification_basis": basis, "subsystem": subsystem_of(path),
            "changed_since_r30_ledger": ("new" if path not in r30 else
                                         "unchanged" if r30[path] == e["sha"] else "content-changed"),
            "review": "not-claimed",
        }
        checks, results, problems = [], {}, []
        text = None
        try:
            text = data.decode("utf-8")
            checks.append("utf8_ok")
            rec["lines"] = text.count("\n") + (0 if text.endswith("\n") or not text else 1)
            crlf = text.count("\r\n")
            lf = text.count("\n") - crlf
            results["line_endings"] = "none" if not (crlf or lf) else "crlf" if crlf and not lf else \
                "mixed" if crlf else "lf"
            results["final_newline"] = text.endswith("\n") if text else None
            checks.append("line_ending_scan")
            if text.startswith("﻿"):
                problems.append("UTF-8 byte-order mark")
        except UnicodeDecodeError:
            checks.append("utf8_decode_failed(binary)")
            rec["lines"] = None
        rec["_text"] = text
        base = os.path.basename(path)
        ext = ext_of(path)
        try:
            if e["mode"] == "100755":
                checks.append("exec_bit_shebang_check")
                if text is None or not text.startswith("#!"):
                    problems.append("executable without a #! line")
                else:
                    results["shebang"] = text.splitlines()[0]
            if ext == "json" and text is not None:
                obj = None
                try:
                    obj, dups = strict_json(text)
                    checks += ["parsed_strict_json", "duplicate_key_scan"]
                except json.JSONDecodeError as err:
                    if base.startswith("tsconfig"):
                        stripped, ncom, ntrail = strip_jsonc(text)
                        obj, dups = strict_json(stripped)
                        checks += [f"parsed_strict_json:failed({err.msg})", "parsed_jsonc", "duplicate_key_scan"]
                        results["jsonc_comments_removed"] = ncom
                        results["jsonc_trailing_commas_removed"] = ntrail
                    elif kind == "fuzz-seed":
                        checks.append(f"parsed_strict_json:failed({err.msg}) — fuzz seeds may be malformed by design")
                        dups = []
                    else:
                        raise
                if dups:
                    problems.append(f"duplicate JSON keys: {sorted(set(dups))[:8]}")
                if obj is not None:
                    results["json_top_level"] = type(obj).__name__
                    if kind == "protocol-manifest":
                        c, r, p = check_protocol_manifest(obj, path)
                    elif kind == "protocol-registry-data":
                        c, r, p = check_protocol_registry_data(obj, base)
                    elif path.startswith("graphite-core/fixtures/corpus/") and "/meta/" not in path:
                        c, r, p = check_corpus_file(obj, path)
                    elif path == "graphite-core/fixtures/corpus/meta/corpus_manifest.json":
                        c, r, p = check_corpus_meta(obj)
                    elif path.startswith("graphite-core/scripts/out/onchain_idls/") or \
                            (path.startswith("graphite-core/scripts/") and isinstance(obj, dict)
                             and isinstance(obj.get("instructions"), list) and "programs" not in obj):
                        c, r, p = check_idl(obj, path)
                    elif cls == "schema":
                        c, r, p = check_json_schema(obj)
                    elif base == "package-lock.json":
                        c, r, p = check_npm_lock(obj)
                    elif kind == "fuzz-seed" and isinstance(obj, dict) and "instructions" in obj:
                        c, r, p = check_protocol_manifest(obj, path)
                        c = [x.replace("protocol-manifest", "protocol-manifest(fuzz seed copy)") for x in c]
                    elif base == "package.json":
                        sc = obj.get("scripts") or {}
                        c = ["package_json_checked(name, scripts, lifecycle hooks)"]
                        r = {"name": obj.get("name"), "scripts": sorted(sc),
                             "lifecycle_scripts": sorted(k for k in sc if k in (
                                 "preinstall", "install", "postinstall", "prepare", "prepublish", "prepack"))}
                        p = [] if obj.get("name") else ["no name"]
                    else:
                        c, r, p = generic_json(obj, path)
                    checks += c
                    results.update(r)
                    problems += p
            elif base == "Cargo.lock":
                c, r, p = check_cargo_lock(text)
                checks += c
                results.update(r)
                problems += p
            elif ext == "toml":
                obj = tomllib.loads(text)
                checks += ["toml_parsed(tomllib; a repeated key is a parse error)"]
                if base == "Cargo.toml":
                    pkg = obj.get("package") or {}
                    results.update({"package": pkg.get("name"), "dependencies": len(obj.get("dependencies") or {}),
                                    "dev_dependencies": len(obj.get("dev-dependencies") or {}),
                                    "features": sorted((obj.get("features") or {}).keys())})
                    checks.append("cargo_toml_summarised")
            elif base == "requirements-lock.txt":
                c, r, p = check_pip_lock(text)
                checks += c
                results.update(r)
                problems += p
            elif base == "requirements.txt":
                c, r, p = check_requirements(text)
                checks += c
                results.update(r)
                problems += p
            elif base == "go.mod":
                c, r, p = check_go_mod(text)
                checks += c
                results.update(r)
                problems += p
            elif ext == "png":
                c, r, p = check_png(data)
                checks += c
                results.update(r)
                problems += p
            elif ext == "ico":
                c, r, p = check_ico(data)
                checks += c
                results.update(r)
                problems += p
            elif ext == "pdf":
                c, r, p = check_pdf(data)
                checks += c
                results.update(r)
                problems += p
            elif ext in ("yml", "yaml"):
                c, r, p = check_yaml_lexical(text)
                checks += c
                results.update(r)
                problems += p
            elif ext in ("service", "timer"):
                c, r, p = check_ini(text)
                checks += c
                results.update(r)
                problems += p
            elif base.endswith(".env.example") or base == ".env.example":
                c, r, p = check_dotenv(text)
                checks += c
                results.update(r)
                problems += p
            elif ext == "tsv":
                c, r, p = check_tsv(text)
                checks += c
                results.update(r)
                problems += p
            elif ext == "proptest-regressions":
                c, r, p = check_proptest_regressions(text)
                checks += c
                results.update(r)
                problems += p
            elif ext == "py":
                ast.parse(text, filename=path)
                checks.append("python_ast_parsed")
            elif ext == "md" and text is not None:
                c, r, p = check_markdown_links(path, text, tree_paths, tree_dirs)
                checks += c
                results.update(r)
                problems += p
            elif kind == "fuzz-seed":
                checks.append("bytes_recorded_only(fuzz seed: no format is asserted)")
            if ext == "rs" and text is not None:
                m = rust_mask(text)
                ok = rust_balance(text, m)
                checks.append("rust_lexed(comments, strings, raw strings, char literals; delimiters balanced)")
                if not ok:
                    problems.append("delimiters do not balance under this lexer (lexer limit or file defect; verify)")
                regions, mods = rust_test_regions(text, m)
                st = line_starts(text)
                rec["_test_lines"] = set()
                for a, b in regions:
                    la, lb = line_of(st, a), line_of(st, max(a, b - 1))
                    rec["_test_lines"].update(range(la, lb + 1))
                rec["_test_spans"] = [(line_of(st, a), line_of(st, max(a, b - 1))) for a, b in regions]
                rec["_mask"], rec["_starts"] = m, st
                if path.startswith("graphite-core/src/"):
                    checks.append("rust_test_region_scan(#[cfg(test)], #[test], #[tokio::test] items)")
                    results["test_attribute_items"] = len(regions)
                    results["test_region_lines"] = len(rec["_test_lines"])
                    stem = path[:-3]
                    parent = os.path.dirname(path) if base in ("lib.rs", "mod.rs", "main.rs") else stem
                    for mname in mods:
                        rust_test_mod_files.add(os.path.join(parent, mname + ".rs"))
                        rust_test_mod_files.add(os.path.join(parent, mname, "mod.rs"))
            if text is not None:
                checks.append(SECRET_LABEL)
                s = SECRET.findall(text)
                if s:
                    problems.append(f"{len(s)} secret-like strings (see scan-triage.json)")
        except Exception as err:  # a failed check is a finding about the file
            problems.append(f"check failed: {type(err).__name__}: {err}")
        rec["validation"] = {"checks": checks, "results": results, "problems": problems}
        records.append(rec)

    # a file declared `#[cfg(test)] mod x;` is test code from top to bottom
    for rec in records:
        if rec["path"] in rust_test_mod_files and "_mask" in rec:
            rec["_test_lines"] = set(range(1, (rec["lines"] or 0) + 1))
            rec["_test_spans"] = [(1, rec["lines"] or 0)]
            rec["validation"]["results"]["whole_file_cfg_test_module"] = True

    # examples that claim to be verification results / intents: their top-level
    # keys against the published schema's `required` list
    schemas = {}
    for rec in records:
        if rec["path"] in ("schemas/verification-result-v1.json", "schemas/proposed-intent-v1.json"):
            schemas[rec["path"]] = json.loads(rec["_text"])
    for rec in records:
        res = rec["validation"]["results"]
        if res.pop("_needs_schema_required", False) or rec["path"] == "examples/sample-proposed-intent.json":
            sp = ("schemas/proposed-intent-v1.json" if rec["path"] == "examples/sample-proposed-intent.json"
                  else "schemas/verification-result-v1.json")
            if sp in schemas:
                obj = json.loads(rec["_text"])
                miss = sorted(k for k in schemas[sp].get("required", []) if k not in obj)
                extra = sorted(k for k in obj if k not in (schemas[sp].get("properties") or {}))
                rec["validation"]["checks"] = [c for c in rec["validation"]["checks"]
                                               if not c.startswith("schema_checked:verification-result")]
                rec["validation"]["checks"].append(f"schema_checked:top-level-keys-vs-{sp}(required present; "
                                                   f"keys outside properties listed) — not a full JSON Schema validation")
                res["schema_required_missing"] = miss
                res["keys_outside_schema_properties"] = extra
                if miss:
                    rec["validation"]["problems"].append(f"missing keys the schema requires: {miss}")
    # raw text of the data files the aggregate re-reads
    for rec in records:
        rec["_raw"] = rec["_text"]

    allow = next((r for r in records if r["path"] == ".github/test-allowlists/rust-ignored.txt"), None)
    if allow is not None:
        for line in allow["_text"].splitlines():
            s = line.strip()
            if s and not s.startswith("#"):
                IGNORE_ALLOWLIST.add(s.split("::")[-1])
    doc = next((r for r in records if r["path"] == "docs/CURRENT.md"), None)
    triage = run_scan(records)
    aggregate = build_aggregate(records, r30, count_check, triage, doc["_text"] if doc else None)

    for rec in records:
        if rec["path"].endswith(".rs") and rec["path"].startswith("graphite-core/src/"):
            rec["validation"]["results"]["scan_counts"] = triage["per_file"].get(rec["path"], {})
        elif rec["path"] in triage["per_file"]:
            rec["validation"]["results"]["scan_counts"] = triage["per_file"][rec["path"]]
        sc = [d for n, _, scope, d in COMPILED if scope(rec["path"], rec)]
        if sc:
            names = [n for n, _, scope, _ in COMPILED if scope(rec["path"], rec)]
            rec["validation"]["checks"].append("scanned_for:" + ",".join(names))
        for k in [k for k in rec if k.startswith("_")]:
            del rec[k]

    meta = {
        "generator": GENERATOR,
        "commit": commit,
        "tree": tree,
        "files": len(records),
        "count_check": count_check,
        "what_this_is": ("One record per blob in `git ls-tree -r <commit>`, with the automated checks this "
                         "generator ran on that blob (`validation.checks`), what they returned "
                         "(`validation.results`) and anything they flagged (`validation.problems`)."),
        "what_this_is_not": ("A review. No record claims that anyone read the file. `review` is "
                             "\"not-claimed\" on every record. A check named here was run by this script and "
                             "nothing else was."),
        "changed_since_r30_ledger": ("new: path absent from docs/audit-r30/file-ledger.json; unchanged: same git "
                                     "blob as that ledger; content-changed: same path, different blob."),
    }
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "file-ledger.json"), "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "aggregate": aggregate, "files": records}, f, indent=1, sort_keys=True,
                  ensure_ascii=False)
        f.write("\n")
    with open(os.path.join(out_dir, "scan-triage.json"), "w", encoding="utf-8") as f:
        json.dump({"meta": {"generator": GENERATOR, "commit": commit, "tree": tree,
                            "patterns": {n: {"regex": rx, "case_insensitive": bool(fl & re.I), "scope": d}
                                         for n, rx, fl, _, d in PATTERNS},
                            "dispositions": DISPOSITION_DOC},
                   "summary": triage["summary"], "needs_review": triage["needs_review"],
                   "unwrap_expect_per_file": triage["unwrap_expect_per_file"],
                   "per_file": triage["per_file"], "hits": triage["hits"]},
                  f, indent=1, sort_keys=True, ensure_ascii=False)
        f.write("\n")
    print(json.dumps({"files": len(records), "count_check": count_check,
                      "triage": triage["summary"]["by_pattern"]}, indent=1, sort_keys=True))


# Numbers docs/CURRENT.md states about the data, each found by a pattern in the
# document at the same commit and compared with what this script counted.
DOC_CLAIMS = [
    ("CURRENT.md: 'N manifests / M instructions'", r"(\d[\d,]*) manifests / (\d[\d,]*) instructions",
     ["protocol_manifests", "manifest_instructions"]),
    ("CURRENT.md: Round 30 re-count '(N, N unique program ids, M instructions, K unclassed)'",
     r"\((\d[\d,]*), (\d[\d,]*) unique program ids, (\d[\d,]*) instructions, (\d[\d,]*) unclassed\)",
     ["protocol_manifests", "unique_program_ids", "manifest_instructions", "unclassed_instructions"]),
    ("CURRENT.md: 'N records measure a decode rate under 90%'", r"(\d+) records measure a decode rate under 90%",
     ["decode_rate_below_0.9"]),
    ("CURRENT.md: 'corpus: N fixtures (A dev, B regression, C holdout)'",
     r"corpus: (\d[\d,]*) fixtures \((\d[\d,]*) dev, (\d[\d,]*) regression, (\d[\d,]*) holdout\)",
     ["corpus_records", "corpus_meta_split_dev", "corpus_meta_split_regression", "corpus_meta_split_holdout"]),
    ("CURRENT.md: '113 battle-tested' (Round 24 row)", r"(\d+) battle-tested\)",
     ["manifests_declaring_BattleTested"]),
]


def build_aggregate(records, r30, count_check, triage, doc_text):
    by = {r["path"]: r for r in records}
    agg = {"files": len(records), "count_check": count_check}
    agg["by_classification"] = dict(sorted(Counter(r["classification"] for r in records).items()))
    agg["by_kind"] = dict(sorted(Counter(f"{r['classification']} / {r['kind']}" for r in records).items()))
    agg["by_subsystem"] = dict(sorted(Counter(r["subsystem"] for r in records).items()))
    agg["changed_since_r30_ledger"] = dict(sorted(Counter(r["changed_since_r30_ledger"] for r in records).items()))
    agg["r30_ledger_paths_absent_at_this_commit"] = sorted(set(r30) - set(by))
    agg["r30_ledger_files"] = len(r30)
    agg["review"] = dict(Counter(r["review"] for r in records))
    chk = Counter()
    for r in records:
        for c in r["validation"]["checks"]:
            chk[re.split(r"[:(]", c, maxsplit=1)[0]] += 1
    agg["check_counts"] = dict(sorted(chk.items()))
    agg["files_with_problems"] = sum(1 for r in records if r["validation"]["problems"])
    agg["problems"] = {r["path"]: r["validation"]["problems"] for r in records if r["validation"]["problems"]}
    generic = {"utf8_ok", "line_ending_scan", "secret_pattern_scan", "scanned_for", "exec_bit_shebang_check"}
    lex = [r for r in records if all(re.split(r"[:(]", c, maxsplit=1)[0] in generic for c in r["validation"]["checks"])]
    agg["files_with_lexical_checks_only"] = {
        "count": len(lex),
        "by_extension": dict(sorted(Counter(ext_of(r["path"]) or os.path.basename(r["path"]) for r in lex).items())),
        "note": "UTF-8 decode, line-ending scan, secret-pattern scan and the triage patterns only: no parser for "
                "the language ran (TypeScript/JavaScript, Go, shell, CSS, HTML, Caddyfile, Dockerfile, plain text)",
    }
    agg["text_files"] = sum(1 for r in records if r["lines"] is not None)
    agg["binary_files"] = sum(1 for r in records if r["lines"] is None)
    agg["total_lines"] = sum(r["lines"] or 0 for r in records)
    agg["line_endings"] = dict(sorted(Counter(r["validation"]["results"].get("line_endings", "binary")
                                              for r in records).items()))
    agg["json_files"] = {
        "total": sum(1 for r in records if r["path"].endswith(".json")),
        "parsed_strict_json": sum(1 for r in records if "parsed_strict_json" in r["validation"]["checks"]),
        "parsed_jsonc": sorted(r["path"] for r in records if "parsed_jsonc" in r["validation"]["checks"]),
        "strict_parse_failed_fuzz_seeds": sorted(r["path"] for r in records if any(
            c.startswith("parsed_strict_json:failed") for c in r["validation"]["checks"]) and r["kind"] == "fuzz-seed"),
    }

    # protocol manifests
    mans = [r for r in records if r["kind"] == "protocol-manifest"]
    ids = Counter(r["validation"]["results"].get("program_id") for r in mans)
    tiers = Counter(r["validation"]["results"].get("trust_tier") for r in mans)
    rc = Counter()
    for r in mans:
        rc.update(r["validation"]["results"].get("risk_classes", {}))
    census = {
        "protocol_manifests": len(mans),
        "unique_program_ids": len(ids),
        "duplicate_program_ids": sorted(str(k) for k, v in ids.items() if v > 1),
        "manifest_instructions": sum(r["validation"]["results"].get("instructions", 0) for r in mans),
        "manifest_accounts": sum(r["validation"]["results"].get("accounts", 0) for r in mans),
        "unclassed_instructions": rc.get("", 0),
        "risk_classes": dict(sorted(rc.items())),
        "manifests_declaring_BattleTested": tiers.get("BattleTested", 0),
        "trust_tiers": dict(sorted((str(k), v) for k, v in tiers.items())),
        "manifests_with_problems": sorted(r["path"] for r in mans if r["validation"]["problems"]),
        "instructions_with_empty_discriminator": {r["path"]: r["validation"]["results"]["empty_discriminators"]
                                                  for r in mans if r["validation"]["results"].get("empty_discriminators")},
        "discriminator_prefix_pairs_total": sum(r["validation"]["results"].get("discriminator_prefix_pairs", 0)
                                                for r in mans),
    }
    manifest_ids = {r["validation"]["results"].get("program_id") for r in mans}
    manifest_files = {os.path.basename(r["path"]) for r in mans}
    tier_of = {r["validation"]["results"].get("program_id"): r["validation"]["results"].get("trust_tier") for r in mans}
    cross = []
    bte = by.get("graphite-core/protocols/battle_tested_evidence.json")
    vpi = by.get("graphite-core/protocols/verified_program_ids.json")
    for rec, label in ((bte, "battle_tested_evidence.json"), (vpi, "verified_program_ids.json")):
        if rec is None:
            cross.append(f"{label}: absent")
            continue
        obj = json.loads(rec["_raw"])
        pids = {p.get("program_id") for p in obj["programs"]}
        cross.append(f"{label}: {len(pids & manifest_ids)} program ids shared with the manifests, "
                     f"{len(pids - manifest_ids)} without a manifest, {len(manifest_ids - pids)} manifests without an entry")
        if label == "battle_tested_evidence.json":
            missing = sorted(p.get("manifest") for p in obj["programs"] if p.get("manifest") not in manifest_files)
            cross.append(f"{label}: {len(missing)} named manifest files that do not exist {missing[:5]}")
            mism = sorted(p.get("program_id") for p in obj["programs"]
                          if p.get("program_id") in tier_of and p.get("declared_trust_tier") != tier_of[p["program_id"]])
            cross.append(f"{label}: {len(mism)} entries whose declared_trust_tier differs from the manifest's trust_tier"
                         + (f" {mism[:5]}" if mism else ""))
            census["decode_rate_below_0.9"] = bte["validation"]["results"].get("decode_rate_below_0.9")
            census["decode_rate_below_0.9_names"] = bte["validation"]["results"].get("decode_rate_below_0.9_names")
    census["cross_checks"] = cross
    fuzz_manifests = [r for r in records if r["kind"] == "fuzz-seed" and r["path"].startswith(
        "graphite-core/fuzz/seeds/manifest_json/")]
    census["fuzz_seed_manifest_copies"] = len(fuzz_manifests)
    agg["protocol_manifest_census"] = census

    # corpus
    corp = [r for r in records if r["path"].startswith("graphite-core/fixtures/corpus/") and "/meta/" not in r["path"]]
    meta = by.get("graphite-core/fixtures/corpus/meta/corpus_manifest.json")
    keys = ("records", "content_hash_mismatches", "integrity_hash_mismatches", "duplicate_content_hash",
            "duplicate_integrity_hash", "duplicate_records", "deprecated", "oversized_records")
    cagg = {"files": len(corp)}
    for k in keys:
        cagg[k] = sum(r["validation"]["results"].get(k, 0) for r in corp)
    cagg["expected_approved_true"] = sum(r["validation"]["results"].get("expected_approved", {}).get("true", 0) for r in corp)
    cagg["expected_approved_false"] = sum(r["validation"]["results"].get("expected_approved", {}).get("false", 0) for r in corp)
    cagg["max_record_bytes"] = max((r["validation"]["results"].get("max_record_bytes", 0) for r in corp), default=0)
    cagg["oversize_threshold_bytes"] = OVERSIZE_RECORD_BYTES
    all_hashes = Counter()
    for r in corp:
        for f in json.loads(r["_raw"]):
            all_hashes[f.get("content_hash")] += 1
    cagg["duplicate_content_hash_across_files"] = sum(v - 1 for v in all_hashes.values() if v > 1)
    corpus_ids = {os.path.basename(r["path"])[:-5] for r in corp}
    cagg["corpus_files_without_a_manifest"] = sorted(corpus_ids - manifest_ids)
    cagg["manifests_without_a_corpus_file"] = sorted(manifest_ids - corpus_ids)
    if meta is not None:
        mobj = json.loads(meta["_raw"])
        mh = Counter(m.get("hash") for m in mobj)
        cagg["meta_records"] = len(mobj)
        cagg["meta_hashes_not_in_corpus"] = len(set(mh) - set(all_hashes))
        cagg["corpus_hashes_not_in_meta"] = len(set(all_hashes) - set(mh))
        for k, v in meta["validation"]["results"].get("split", {}).items():
            cagg[f"meta_split_{k}"] = v
    agg["corpus"] = cagg
    census["corpus_records"] = cagg["records"]
    for k in ("dev", "regression", "holdout"):
        census[f"corpus_meta_split_{k}"] = cagg.get(f"meta_split_{k}")

    # other JSON data sets: record counts and duplicate scans
    corp_paths = {r["path"] for r in corp}
    data = {}
    for r in records:
        res = r["validation"]["results"]
        if r["classification"] in ("corpus/fixture data", "generated", "schema") and r["path"].endswith(".json") \
                and r["path"] not in corp_paths and r is not meta:
            row = {k: v for k, v in res.items() if k.endswith("_records") or k in (
                "records", "instructions", "duplicate_records") or k.endswith("_duplicate_records")}
            row["problems"] = len(r["validation"]["problems"])
            data[r["path"]] = row
    agg["other_json_data"] = data

    # lockfiles
    agg["lockfiles"] = {r["path"]: {k: r["validation"]["results"].get(k) for k in (
        "packages", "lockfileVersion", "lock_version", "pinned_requirements", "resolved_hosts", "sources",
        "install_script_packages") if r["validation"]["results"].get(k) is not None}
        | {"problems": r["validation"]["problems"]}
        for r in records if r["classification"] == "lockfile"}

    # docs claims
    claims = []
    for label, rx, fields in DOC_CLAIMS:
        mm = re.search(rx, doc_text or "")
        if not mm:
            claims.append({"claim": label, "found_in_doc": False})
            continue
        stated = [int(g.replace(",", "")) for g in mm.groups()]
        measured = [census.get(f) for f in fields]
        claims.append({"claim": label, "found_in_doc": True, "doc_text": mm.group(0),
                       "fields": fields, "stated": stated, "measured": measured,
                       "match": stated == measured})
    agg["doc_claims_vs_measured"] = claims
    agg["scan_triage"] = triage["summary"]
    return agg


def generic_json(obj, path):
    checks, res, probs = [], {}, []
    if isinstance(obj, list):
        res["records"] = len(obj)
        checks.append(f"record_count:{len(obj)}")
        d = sum(c - 1 for c in Counter(canon(x) for x in obj).values() if c > 1)
        checks.append("duplicate_record_scan(whole record)")
        res["duplicate_records"] = d
        if d:
            probs.append(f"{d} duplicate records")
        return checks, res, probs
    if isinstance(obj, dict):
        res["top_level_keys"] = sorted(obj)[:30]
        for lk in ("rows", "entries", "transactions", "programs", "findings", "files", "tools", "mutations"):
            if isinstance(obj.get(lk), list):
                lst = obj[lk]
                res[f"{lk}_records"] = len(lst)
                checks.append(f"record_count:{lk}={len(lst)}")
                d = sum(c - 1 for c in Counter(canon(x) for x in lst).values() if c > 1)
                res[f"{lk}_duplicate_records"] = d
                checks.append(f"duplicate_record_scan({lk}, whole record)")
                if d:
                    probs.append(f"{d} duplicate records in {lk}")
                ids = [x.get("id") for x in lst if isinstance(x, dict) and "id" in x]
                if ids:
                    di = sorted(str(i) for i, c in Counter(ids).items() if c > 1)
                    checks.append(f"duplicate_id_scan({lk}.id)")
                    if di:
                        probs.append(f"duplicate ids in {lk}: {di[:5]}")
                if "count" in obj and isinstance(obj["count"], int):
                    checks.append(f"count_field_check(count vs {lk})")
                    if obj["count"] != len(lst):
                        probs.append(f"count {obj['count']} != {len(lst)} {lk}")
        if "transaction" in obj and "meta" in obj:
            checks.append("schema_checked:rpc-transaction-shape(transaction, meta, slot present)")
            if "slot" not in obj:
                probs.append("rpc transaction without slot")
            res["meta_err"] = (obj.get("meta") or {}).get("err") if isinstance(obj.get("meta"), dict) else None
        if path.startswith("examples/decisions/") or path.startswith("examples/sample-verification"):
            checks.append("schema_checked:verification-result-required-keys(against schemas/verification-result-v1.json required)")
            res["_needs_schema_required"] = True
    return checks, res, probs


# --------------------------------------------------------------------------
# scan + dispositions
# --------------------------------------------------------------------------
DISPOSITION_DOC = {
    "test-only": "the hit is in a file classified test, or inside a #[cfg(test)]/#[test] item of a src file",
    "comment/historical": "the hit is in a historical report or the Round 30 record (text about the past)",
    "documentation-prose": "the hit is a word in documentation prose, not a marker of unfinished work",
    "comment": "the hit is inside a comment (lexer-determined) and the rule named in `basis` explains it",
    "string-literal": "the hit is inside a string literal (lexer-determined), e.g. an error message or IDL text",
    "identifier/code": "the hit is in code and the rule named in `basis` explains it from the matched line",
    "data": "the hit is in a data file (fixture, IDL, generated output)",
    "needs-review": "no rule in this script justifies the hit from its line; a person must look",
}


def run_scan(records):
    hits, per_file = [], defaultdict(Counter)
    unwrap_pf = {}
    for rec in records:
        text = rec.get("_text")
        if text is None:
            continue
        path = rec["path"]
        applicable = [(n, rx) for n, rx, scope, _ in COMPILED if scope(path, rec)]
        if not applicable:
            continue
        mask = rec.get("_mask")
        lexer = "rust-lexer" if mask is not None else None
        if mask is None:
            mask, lexer = mask_for(path, text)
        starts = rec.get("_starts") or line_starts(text)
        lines = text.split("\n")
        test_lines = rec.get("_test_lines", set())
        for name, rx in applicable:
            for mm in rx.finditer(text):
                ln = line_of(starts, mm.start())
                ctx = "unknown" if mask is None else ("code", "comment", "string")[mask[mm.start()]]
                in_test = ln in test_lines
                h = {"pattern": name, "path": path, "line": ln, "match": mm.group(0),
                     "text": lines[ln - 1].strip()[:240], "context": ctx, "lexer": lexer,
                     "in_test_region": in_test}
                h["disposition"], h["basis"] = dispose(h, rec, lines)
                hits.append(h)
                per_file[path][name] += 1
                if name == "unwrap_expect":
                    u = unwrap_pf.setdefault(path, Counter())
                    u["total"] += 1
                    u["test_region" if in_test else ("non_test_" + ctx)] += 1
    hits.sort(key=lambda h: (h["path"], h["line"], h["pattern"], h["match"]))
    by_pattern = defaultdict(Counter)
    for h in hits:
        by_pattern[h["pattern"]][h["disposition"].split(":", 1)[0]] += 1
    needs = [{"path": h["path"], "line": h["line"], "pattern": h["pattern"], "text": h["text"], "why": h["basis"]}
             for h in hits if h["disposition"].startswith("needs-review")]
    summary = {"hits": len(hits),
               "by_pattern": {n: dict(sorted(by_pattern.get(n, Counter()).items())) for n, *_ in sorted(PATTERNS)},
               "patterns_with_no_hit": sorted(n for n, *_ in PATTERNS if n not in by_pattern),
               "needs_review": len(needs)}
    return {"hits": hits, "per_file": {p: dict(sorted(c.items())) for p, c in sorted(per_file.items())},
            "summary": summary, "needs_review": needs,
            "unwrap_expect_per_file": {p: dict(sorted(c.items())) for p, c in sorted(unwrap_pf.items())}}


# Hits whose disposition rests on the lines around them. Each entry was set by
# reading the cited lines of the base commit (Round 36); the key carries the
# line number AND a substring of the line, so an entry stops applying (and the
# hit falls back to needs-review) the moment the line changes. This is the only
# hand-kept input of this generator.
CONTEXT = {
    # ---- unwrap/expect outside test code in graphite-core/src -----------
    ("graphite-core/src/benchmark.rs", "unwrap_expect", 104, "benchmark baseline must be valid"):
        ("needs-review", "expect on GraphiteCore::seed_simulation_baseline with a literal baseline (benchmark.rs:85-104); "
                         "that call can return Err from validate_baseline (semantic_graph_store.rs:1039), which this "
                         "triage did not trace for these literals. Benchmark harness path, not the server."),
    ("graphite-core/src/benchmark.rs", "unwrap_expect", 289, "benchmark suite must include a safe case"):
        ("identifier/code", "the suite built in this file has category \"safe\" cases (benchmark.rs:451, 471, ...) and "
                            "its unit test asserts seven of them (benchmark.rs:1360)"),
    ("graphite-core/src/manifest_registry.rs", "unwrap_expect", 213, "a manifest is plain data"):
        ("needs-review", "serde_json::to_value(ProtocolManifest) is infallible only if no nested type has a non-string "
                         "map key or a failing Serialize impl; this triage did not trace the type graph"),
    ("graphite-core/src/manifest_registry.rs", "unwrap_expect", 741, "append cannot fail after program_id validation"):
        ("identifier/code", "append_registry_evidence returns append's result (semantic_graph_store.rs:683); append's "
                            "only Err is an empty program_id (semantic_graph_store.rs:481-485), and submit refuses a "
                            "blank program_id first (manifest_registry.rs:586-588)"),
    ("graphite-core/src/plugins/mod.rs", "unwrap_expect", 38, "builtin exists"):
        ("identifier/code", "builtin_plugin matches this constant and returns Some (plugins/mod.rs:24-31)"),
    ("graphite-core/src/plugins/mod.rs", "unwrap_expect", 39, "builtin exists"):
        ("identifier/code", "builtin_plugin matches this constant and returns Some (plugins/mod.rs:24-31)"),
    ("graphite-core/src/regression_engine.rs", "unwrap_expect", 199, "VerificationInput is always serializable"):
        ("needs-review", "serde_json::to_string(VerificationInput) is infallible only if no nested type has a non-string "
                         "map key or a failing Serialize impl; the comment asserts it, this triage did not trace it"),
    ("graphite-core/src/server.rs", "unwrap_expect", 1939, ".unwrap()"):
        ("identifier/code", "Response::builder() with a constant status, the constant header pair content-type: "
                            "application/json and a static body (server.rs:1932-1938); the builder errs only on an "
                            "invalid status or header"),
    ("graphite-core/src/state_diff.rs", "unwrap_expect", 665, "expect(\"8 bytes\")"):
        ("identifier/code", "b comes from data.get(76..84) on the line above: Some only with exactly 8 bytes"),
    ("graphite-core/src/state_diff.rs", "unwrap_expect", 667, "expect(\"8 bytes\")"):
        ("identifier/code", "b comes from data.get(84..92) on the line above: Some only with exactly 8 bytes"),
    ("graphite-core/src/tx_artifact.rs", "unwrap_expect", 1115, "take(4) returns exactly 4 bytes"):
        ("identifier/code", "Reader::take(n) returns exactly n bytes or Err (tx_artifact.rs:426-437); the Err is "
                            "propagated by `?` on the line above"),
    ("graphite-core/src/tx_artifact.rs", "unwrap_expect", 1201, "take(8) returns exactly 8 bytes"):
        ("identifier/code", "Reader::take(n) returns exactly n bytes or Err (tx_artifact.rs:426-437); the Err is "
                            "propagated by `?` on the line above"),
    ("graphite-core/src/tx_artifact.rs", "unwrap_expect", 1570, "slice of exactly 4 bytes is an array"):
        ("identifier/code", "data[0..4] on the line above has width 4 = [u8; 4]; the length check before it returns "
                            "Err for a short account (tx_artifact.rs:1558-1562)"),
    ("graphite-core/src/tx_artifact.rs", "unwrap_expect", 1581, "slice of exactly 8 bytes is an array"):
        ("identifier/code", "data[4..12] on the line above has width 8 = [u8; 8]; same length check "
                            "(tx_artifact.rs:1558-1562)"),
    ("graphite-core/src/verification.rs", "unwrap_expect", 1187, "expect(\"peeked\")"):
        ("identifier/code", "inside `while let Some(next) = items.peek()` (verification.rs:1183): next() after a "
                            "Some peek is Some"),
    ("graphite-core/src/verification.rs", "unwrap_expect", 2719, "the scan semaphore is never closed"):
        ("identifier/code", "acquire_owned errs only on a closed semaphore; SCANS is a function-local static "
                            "(verification.rs:2711-2714) and nothing in the file calls close() on it"),
    # ---- panic! in graphite-core/src --------------------------------------
    ("graphite-core/src/manifest.rs", "panic_macro", 1469, "seed manifests compiled into this build are unusable"):
        ("identifier/code", "deliberate fatal stop documented at manifest.rs:1455-1466: the seeds are include_str!'d, "
                            "so it fires only on a broken build; try_load_seed_manifests is the non-panicking API"),
    ("graphite-core/src/server.rs", "panic_macro", 4568, "an audit-trail scan did not complete"):
        ("identifier/code", "the arm above re-raises a scan panic; this arm is a JoinError that is not a panic (a "
                            "cancelled blocking task); off_runtime's doc (server.rs:4572-4577) states a failed scan "
                            "answers 500, via the CatchPanicLayer at server.rs:1930"),
    ("graphite-core/src/server.rs", "panic_macro", 4586, "an audit-trail scan did not complete"):
        ("identifier/code", "same as server.rs:4568 (the arm above re-raises a panic; doc at server.rs:4572-4577)"),
    ("graphite-core/src/verification.rs", "panic_macro", 3262, "unwrap_or_else(|e| panic!"):
        ("identifier/code", "#[deprecated] with_data_dir (verification.rs:3256-3260) whose doc says no server or CLI "
                            "path calls it; the only caller in the tree is tests/audit_2026_10_20_core_gates.rs:211"),
    # ---- catch_unwind ------------------------------------------------------
    ("graphite-core/src/plugin_orchestrator.rs", "catch_unwind", 23, "catch_unwind"):
        ("comment", "module doc of the plugin panic isolation (plugin_orchestrator.rs:22-27)"),
    ("graphite-core/src/plugin_orchestrator.rs", "catch_unwind", 43, "use std::panic"):
        ("identifier/code", "import for the plugin panic isolation documented at plugin_orchestrator.rs:22-27"),
    ("graphite-core/src/plugin_orchestrator.rs", "catch_unwind", 587, "kind.run(ctx)"):
        ("identifier/code", "plugin panic isolation documented at plugin_orchestrator.rs:22-27 (a blocking plugin's "
                            "panic becomes a block)"),
    ("graphite-core/src/plugin_orchestrator.rs", "catch_unwind", 724, "catch_unwind(AssertUnwindSafe"):
        ("identifier/code", "plugin panic isolation documented at plugin_orchestrator.rs:22-27"),
    ("graphite-core/src/plugin_orchestrator.rs", "catch_unwind", 760, "on_verification(result)"):
        ("identifier/code", "plugin panic isolation documented at plugin_orchestrator.rs:22-27"),
    ("tools/runtime-oracle/src/main.rs", "catch_unwind", 29, "catch_unwind"):
        ("comment", "dev-tool doc: each oracle input runs under catch_unwind and a panic is tallied"),
    ("tools/runtime-oracle/src/main.rs", "catch_unwind", 172, "catch_unwind"):
        ("comment", "dev-tool doc of the helper at main.rs:181"),
    ("tools/runtime-oracle/src/main.rs", "catch_unwind", 181, "catch_unwind"):
        ("identifier/code", "dev tool (classified script): a panic is tallied as a finding (doc at main.rs:172-176)"),
    # ---- as any --------------------------------------------------------------
    ("integrations/agent-guard/guard.ts", "as_any", 861, "as any"):
        ("needs-review", "runtime source: any string from the AI layer's result is asserted to the intent_type type "
                         "without a check against the allowed set at this line"),
    ("integrations/agent-guard/guard.ts", "as_any", 996, "} as any;"):
        ("needs-review", "runtime source: the whole VerificationInput literal (guard.ts:984-996) is asserted to any, "
                         "so the compiler does not check its fields against the type"),
    ("integrations/agent-guard/guard.ts", "as_any", 1282, "intent_type: intentType as any"):
        ("needs-review", "runtime source: the grounded intent class is asserted to ProposedIntent.intent_type's type; "
                         "whether groundTransferClass's return type always fits was not established here"),
    ("integrations/agent-guard/guard.ts", "as_any", 1506, "intent_type: intentType as any"):
        ("needs-review", "runtime source: the grounded swap intent is asserted to ProposedIntent.intent_type's type; "
                         "whether groundSwapIntent's return type always fits was not established here"),
    ("sdk/typescript/src/client.ts", "as_any", 674, "read as any of them"):
        ("comment", "English prose (\"not read as any of them\"), not a type assertion"),
    # ---- markers ------------------------------------------------------------
    (".github/workflows/ci.yml", "todo_marker", 502, "# (SKIP|TODO)"):
        ("identifier/code", "the step greps the TAP log for SKIP/TODO directives and fails the job on one "
                            "(ci.yml:502-504)"),
    # ---- error masking in CI shell ---------------------------------------------
    (".github/scripts/dashboard-e2e.sh", "workflow_error_masking", 55, "kill \"$pid\""):
        ("identifier/code", "best-effort cleanup in the EXIT trap; the trap exits with the saved status "
                            "(dashboard-e2e.sh:52-61)"),
    (".github/scripts/dashboard-e2e.sh", "workflow_error_masking", 58, "cat \"$work/core.log\""):
        ("identifier/code", "diagnostic log dump on failure inside the EXIT trap; the trap exits with the saved status"),
    (".github/scripts/dashboard-e2e.sh", "workflow_error_masking", 59, "cat \"$work/preview.log\""):
        ("identifier/code", "diagnostic log dump on failure inside the EXIT trap; the trap exits with the saved status"),
    (".github/scripts/release-gate.sh", "workflow_error_masking", 157, "find-principals"):
        ("identifier/code", "an empty result is refused on the next line (release-gate.sh:158 `die`)"),
    (".github/scripts/test-count.sh", "workflow_error_masking", 33, "grep -c '^test result:'"):
        ("identifier/code", "grep -c prints 0 and exits 1 on no match; the next line fails when the count is < 1"),
    (".github/scripts/test-count.sh", "workflow_error_masking", 59, "grep -c -E '^--- PASS: '"):
        ("identifier/code", "grep -c prints 0 and exits 1 on no match; the count is the value used, FAIL/SKIP lines "
                            "fail the run on the next lines"),
    (".github/workflows/assurance.yml", "workflow_error_masking", 161, "set +e"):
        ("identifier/code", "cargo-mutants' exit is printed; the next step enforces the mutation-score floor from "
                            "mutants.out/outcomes.json (assurance.yml:166-167)"),
    (".github/workflows/ci.yml", "workflow_error_masking", 568, "docker rm -f graphite-keyless"):
        ("identifier/code", "best-effort removal of a container that may not exist, before a run"),
    (".github/workflows/ci.yml", "workflow_error_masking", 569, "set +e"):
        ("identifier/code", "exit captured as code=$? and set -e restored (ci.yml:573-574); 124/137/0 fail the step"),
    (".github/workflows/ci.yml", "workflow_error_masking", 575, "logs=$(docker logs"):
        ("identifier/code", "logs captured, then required to contain \"refusing to\" (ci.yml:583-585)"),
    (".github/workflows/ci.yml", "workflow_error_masking", 588, "docker rm -f graphite-keyless"):
        ("identifier/code", "best-effort cleanup after the loop"),
    (".github/workflows/ci.yml", "workflow_error_masking", 602, "docker rm -f graphite-ci"):
        ("identifier/code", "best-effort removal to free port 7331 (comment on the line)"),
    (".github/workflows/ci.yml", "workflow_error_masking", 691, "docker logs graphite-ci"):
        ("identifier/code", "diagnostic output in an `if: always()` log step"),
    (".github/workflows/ci.yml", "workflow_error_masking", 692, "docker compose logs"):
        ("identifier/code", "diagnostic output in an `if: always()` log step"),
    (".github/workflows/ci.yml", "workflow_error_masking", 696, "docker rm -f graphite-ci graphite-keyless"):
        ("identifier/code", "best-effort cleanup in an `if: always()` step"),
    (".github/workflows/ci.yml", "workflow_error_masking", 697, "docker compose down -v"):
        ("identifier/code", "best-effort cleanup in an `if: always()` step"),
    (".github/workflows/live-devnet.yml", "workflow_error_masking", 132, "set +e"):
        ("identifier/code", "exit captured (code=$?), written to outputs.exit; a later step fails on CODE != 0 "
                            "(live-devnet.yml:164-166)"),
    (".github/workflows/live-mainnet.yml", "workflow_error_masking", 121, "set +e"):
        ("identifier/code", "exit captured; 3 is recorded as INCONCLUSIVE (skip), any other non-zero exits the step "
                            "(live-mainnet.yml:125-131)"),
    (".github/workflows/live-mainnet.yml", "workflow_error_masking", 149, "set +e"):
        ("identifier/code", "exit captured from PIPESTATUS, written to outputs.exit and passed to the replay as "
                            "--harness-exit (live-mainnet.yml:151-153, 198)"),
    (".github/workflows/live-mainnet.yml", "workflow_error_masking", 170, "set +e"):
        ("needs-review", "the seed step's exit goes to outputs.exit, which nothing reads; the replay step decides "
                         "SEEDED from steps.seed.outcome (live-mainnet.yml:200), and the step's last command is the "
                         "echo, so the outcome reads success even when seeding failed"),
    (".github/workflows/live-mainnet.yml", "workflow_error_masking", 204, "set +e"):
        ("identifier/code", "exit captured to outputs.exit; the Verdict step fails on REPLAY != 0 "
                            "(live-mainnet.yml:250-255)"),
    (".github/workflows/live-mainnet.yml", "workflow_error_masking", 218, "core.pid"):
        ("identifier/code", "an empty pid is handled on the next line (records clean=false and an error)"),
    # ---- mock/fake/stub/demo/sample words that no word-sense rule covers ----------
    ("dashboard/src/views/GraphView.tsx", "mock_words", 50, "const stubs"):
        ("identifier/code", "placeholder graph nodes for CPI targets with no manifest, drawn so an undeclared callee is "
                            "visible (comment at GraphView.tsx:48-49); not stub data"),
    ("dashboard/src/views/GraphView.tsx", "mock_words", 66, "...stubs"):
        ("identifier/code", "the placeholder nodes of GraphView.tsx:50"),
    ("graphite-core/src/account_resolution.rs", "mock_words", 75, "substituted fake"):
        ("comment", "describes an attack (a substituted fake token program)"),
    ("graphite-core/src/rpc_client.rs", "mock_words", 695, "a mock or a"):
        ("comment", "describes RPC providers that omit context.slot"),
    ("graphite-core/src/rpc_client.rs", "mock_words", 1095, "removed from the RPC client as fake logic"):
        ("comment", "historical note that a placeholder was removed (2026-08-06)"),
    ("graphite-core/src/simulation_integrity.rs", "mock_words", 29, "never faked"):
        ("comment", "states the check never fakes a result"),
    ("graphite-core/src/verification.rs", "mock_words", 4487, "fail-closed stub below"):
        ("comment", "names the no-feature verify(), which returns Err (verification.rs:4513-4521)"),
    ("graphite-core/src/verification.rs", "mock_words", 5518, "fake community"):
        ("comment", "describes an attacker's fake evidence counts"),
    ("graphite-core/src/live_corpus.rs", "mock_words", 130, "refused as a fake one"):
        ("comment", "refers to the FakeSwap check (a swap refused as a fake swap)"),
    ("integrations/agent-guard/execution-lifecycle.ts", "mock_words", 39, "a test can stand in a fake"):
        ("comment", "documents a dependency-injection seam (the two Connection calls as an interface)"),
    ("integrations/agent-guard/guard.ts", "mock_words", 576, "guard.graphite = stub"):
        ("comment", "historical description of a fixed attack (Round 29, M8)"),
    ("sdk/typescript/src/types.ts", "mock_words", 337, "test fakes"):
        ("comment", "type-compatibility note for callers' test fakes"),
    ("dashboard/src/styles.css", "mock_words", 19, "sampled from the logo"):
        ("comment", "colour-palette note (colours sampled from the logo)"),
}

STAT_SAMPLE = re.compile(r"(?i)^(min_samples|samples?|sampled|sample_count|baseline_samples|window_samples|windowsample|"
                         r"recent-sample|256-sample|sample\(s\))$")
MAINNET_SAMPLE_LINE = re.compile(r"(?i)mainnet[ _]sample|mainnetsample|sample-2026|sample_bias|mainnet samples|"
                                 r"transaction mainnet sample|mainnet_sample|fixtures/mainnet")
DETECTOR = re.compile(r"(?i)fakeswap|fake_swap|fakerewards|fake_rewards|fake-rewards|fake swaps?|fake rewards?|"
                      r"fake_rewards_drainer|FAKE_REWARDS")
WIDTH = {"u16": 2, "i16": 2, "u32": 4, "i32": 4, "u64": 8, "i64": 8, "u128": 16, "i128": 16, "Pubkey": 32}

IGNORE_ALLOWLIST = set()


def _word_at(text_line, match, case_line):
    """The identifier-ish word (letters, digits, _, -) around the match in the line."""
    k = case_line.find(match)
    if k < 0:
        return match
    a, b = k, k + len(match)
    while a > 0 and (text_line[a - 1].isalnum() or text_line[a - 1] in "_-"):
        a -= 1
    while b < len(text_line) and (text_line[b].isalnum() or text_line[b] in "_-"):
        b += 1
    return text_line[a:b].strip("-")


def dispose(h, rec, lines):
    """(disposition, basis). Only the rules written here; otherwise needs-review."""
    cls, kind = rec["classification"], rec["kind"]
    name, ctx, text, path = h["pattern"], h["context"], h["text"], h["path"]
    if name == "test_skip_rust_ignore" and ctx == "code":
        fn = None
        for nxt in lines[h["line"]:h["line"] + 6]:
            mm = re.search(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)", nxt)
            if mm:
                fn = mm.group(1)
                break
        listed = fn is not None and fn in IGNORE_ALLOWLIST
        h["ignored_test"] = fn
        if not listed:
            return "needs-review", f"#[ignore] on {fn!r}, which is not listed in .github/test-allowlists/rust-ignored.txt"
        return "test-only", f"#[ignore] on {fn}, listed in .github/test-allowlists/rust-ignored.txt (reason in the attribute)"
    if cls == "test":
        return "test-only", f"file classified test ({kind}; {rec['classification_basis']})"
    if h["in_test_region"]:
        return "test-only", "inside a #[cfg(test)]/#[test] item (rust_test_region_scan)"
    if cls == "historical-report":
        return "comment/historical", "file classified historical-report"
    if cls in ("corpus/fixture data", "generated") or (cls == "manifest" and kind != "package-manifest"):
        if "idl" in path.lower():
            return "data", "IDL text (a program's own IDL doc string)"
        return "data", f"file classified {cls} ({kind})"
    key = next((k for k in CONTEXT if k[0] == path and k[1] == name and k[2] == h["line"] and k[3] in text), None)
    if key:
        d, why = CONTEXT[key]
        return d, ("context-read: " if d != "needs-review" else "") + why
    if name == "unwrap_expect":
        mm = re.search(r"\b(u16|i16|u32|i32|u64|i64|u128|i128|Pubkey)::from_(?:le_|be_)?bytes\(\s*\w+\[(\d+)\.\.(\d+)\]"
                       r"\.try_into\(\)\.(?:unwrap\(\)|expect\()", text)
        if mm and int(mm.group(3)) - int(mm.group(2)) == WIDTH[mm.group(1)]:
            return "identifier/code", (f"slice [{mm.group(2)}..{mm.group(3)}] has width {WIDTH[mm.group(1)]} = "
                                       f"{mm.group(1)}'s byte width, so try_into() cannot fail (the index itself is "
                                       f"bounds-checked separately)")
        mm = re.search(r"\b(u16|i16|u32|i32|u64|i64|u128|i128|Pubkey)::from_(?:le_|be_)?bytes\(\s*\w+\[(\w+)\.\.\2\s*\+\s*(\d+)\]"
                       r"\.try_into\(\)\.(?:unwrap\(\)|expect\()", text)
        if mm and int(mm.group(3)) == WIDTH[mm.group(1)]:
            return "identifier/code", (f"slice [{mm.group(2)}..{mm.group(2)} + {mm.group(3)}] has width "
                                       f"{mm.group(3)} = {mm.group(1)}'s byte width, so try_into() cannot fail")
        return "needs-review", "no rule in this generator shows this unwrap/expect cannot fail"
    if name == "as_any" and cls == "script":
        return "identifier/code", f"dev tool ({rec['classification_basis']}), not part of the runtime guard"
    if name == "todo_marker" and cls == "script" and ctx == "string" and re.search(r"\\b\(", text):
        return "string-literal", "the marker words inside a scan-pattern regex of an audit tool"
    if name == "unsafe" and ctx == "comment":
        return "comment", "the English word in a comment; not the Rust keyword in code"
    if name == "mock_words":
        word = _word_at(text, h["match"], text)
        lw = word.lower()
        where = {"comment": "comment", "string": "string-literal"}.get(ctx, "identifier/code")
        if "demot" in lw or "demonstrat" in lw:
            return where, f"part of the word {word!r} (demote/demonstrate), not 'demo'"
        if DETECTOR.search(word) or DETECTOR.search(text[max(0, text.lower().find(h['match'].lower()) - 1):][:20]):
            return where, f"name of the FakeSwap / FakeRewardsDrainer detector or the attack class it detects ({word!r})"
        if MAINNET_SAMPLE_LINE.search(text) and "sample" in lw:
            return where, f"names the committed or measured mainnet sample (measurement data), word {word!r}"
        if STAT_SAMPLE.match(word.split("::")[-1]) or "sample_count" in lw or "min_samples" in lw or \
                "baseline_samples" in lw or "windowsample" in lw or "window_samples" in lw or lw.endswith("-sample"):
            return where, (f"ordinary sense of 'sample': observations or measurements (baseline counts and windows, "
                           f"measured traffic), not placeholder data ({word!r})")
        return "needs-review", f"word {word!r} in runtime source matches no rule"
    return "needs-review", "no rule in this generator covers this hit"


if __name__ == "__main__":
    main()
