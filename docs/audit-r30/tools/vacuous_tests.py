#!/usr/bin/env python3
"""List Rust test functions whose body asserts nothing.

A test body is "asserting" when it contains any of: assert!, assert_eq!,
assert_ne!, debug_assert*, panic!, unreachable!, .expect(, .unwrap(, `?` on a
Result return, matches! inside an assert, or a call to a local helper whose
name starts with assert_/check_/expect_/must_/refuse/require. Everything else
is reported for a person to read: a test that only runs code proves it did not
panic, which may or may not be the property it is named for.

Usage: vacuous_tests.py <graphite-core-dir>
"""
import os
import re
import sys

ASSERTS = re.compile(
    r"assert!|assert_eq!|assert_ne!|debug_assert|panic!|unreachable!|\.expect\(|\.unwrap\(|\.unwrap_err\(|"
    r"\b(assert|check|expect|must|refuse|require|verify_that)_\w*\(|\?\s*;|\.is_err\(\)\)|bail!"
)


def test_bodies(text):
    for m in re.finditer(r"#\[(?:tokio::)?test[^\]]*\]\s*(?:#\[[^\]]*\]\s*)*(?:async\s+)?fn\s+(\w+)[^{]*\{", text):
        start = m.end()
        depth, i = 1, start
        while i < len(text) and depth:
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            i += 1
        yield m.group(1), text[start:i - 1], text.count("\n", 0, m.start()) + 1


def main():
    root = sys.argv[1]
    found = []
    total = 0
    for d in ("tests", "src"):
        for dirpath, _, files in os.walk(os.path.join(root, d)):
            for f in sorted(files):
                if not f.endswith(".rs"):
                    continue
                path = os.path.join(dirpath, f)
                text = open(path, encoding="utf-8").read()
                for name, body, line in test_bodies(text):
                    total += 1
                    if not ASSERTS.search(body):
                        found.append((os.path.relpath(path, root), line, name))
    print(f"{total} test functions; {len(found)} with no assertion form found")
    for p, line, name in found:
        print(f"{p}:{line}\t{name}")


if __name__ == "__main__":
    main()
