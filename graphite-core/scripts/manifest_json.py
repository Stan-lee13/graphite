#!/usr/bin/env python3
"""Read and write a shipped manifest without reformatting it.

The seed manifests are hand-reviewed and diffed line by line, so a tool that
edits one field must not re-indent the other thousand lines. Every manifest in
`protocols/` is `json.dumps(..., ensure_ascii=False)` output at indent 1 or 2,
with or without a final newline; `load` records which, and `dump` writes the
same layout back. A file that does not round-trip through its own layout is
refused rather than rewritten.
"""
import json
from pathlib import Path


class Layout:
    def __init__(self, indent, ensure_ascii, newline):
        self.indent = indent
        self.ensure_ascii = ensure_ascii
        self.newline = newline

    def render(self, data):
        out = json.dumps(data, indent=self.indent, ensure_ascii=self.ensure_ascii)
        return out + ("\n" if self.newline else "")


def load(path):
    """(data, layout) for a manifest file; raises if no layout reproduces it."""
    text = Path(path).read_text(encoding="utf-8")
    data = json.loads(text)
    for indent in (1, 2, 4):
        for ensure_ascii in (False, True):
            for newline in (True, False):
                layout = Layout(indent, ensure_ascii, newline)
                if layout.render(data) == text:
                    return data, layout
    raise ValueError(f"{path}: not in a json.dumps layout this tool can reproduce; edit it by hand")


def dump(path, data, layout):
    Path(path).write_text(layout.render(data), encoding="utf-8")
