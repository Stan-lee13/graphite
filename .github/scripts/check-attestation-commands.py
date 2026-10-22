#!/usr/bin/env python3
"""Every published `gh attestation verify` command pins the signer (Round 34, R33-18).

`gh attestation verify ... --repo OWNER/graphite` alone accepts an attestation
made by ANY workflow of the repository, from any ref, on any runner. Every
command line this repository tells someone to run must also carry
`--signer-workflow OWNER/graphite/.github/workflows/release.yml`,
`--source-ref refs/tags/v...` and `--deny-self-hosted-runners`.

  check-attestation-commands.py [PATH...]

With no PATH, every file `git ls-files` lists. A command spans the lines it
continues with a trailing backslash. Mentions of the bare command name in
prose (`gh attestation verify` followed by a backtick) are not commands.
Exit 1 naming each command that lacks a flag; exit 1 too when no command is
found at all (the scan itself broke).
"""
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
NEEDED = {
    "--signer-workflow": re.compile(r"--signer-workflow[ =]\S+/\.github/workflows/release\.yml\b"),
    "--source-ref": re.compile(r"--source-ref[ =]refs/tags/\S+"),
    "--deny-self-hosted-runners": re.compile(r"--deny-self-hosted-runners\b"),
}
COMMAND = re.compile(r"gh attestation verify (?!`)")


def commands(path):
    try:
        lines = open(path, encoding="utf-8").read().splitlines()
    except (OSError, UnicodeDecodeError):
        return
    i = 0
    while i < len(lines):
        if COMMAND.search(lines[i]):
            start, cmd = i, lines[i]
            while cmd.rstrip().endswith("\\") and i + 1 < len(lines):
                i += 1
                cmd = cmd.rstrip()[:-1] + " " + lines[i].lstrip(" #")
            yield start + 1, cmd
        i += 1


def main(argv):
    if argv:
        paths = argv
    else:
        out = subprocess.run(["git", "-C", ROOT, "ls-files", "-z"], capture_output=True, check=True).stdout
        paths = [os.path.join(ROOT, p) for p in out.decode().split("\0") if p]
    here = os.path.abspath(__file__)
    found, bad = 0, []
    for p in paths:
        if os.path.abspath(p) == here:
            continue
        for line, cmd in commands(p):
            found += 1
            missing = [flag for flag, rx in NEEDED.items() if not rx.search(cmd)]
            if missing:
                bad.append(f"{os.path.relpath(p, ROOT)}:{line}: lacks {', '.join(missing)}")
    for b in bad:
        print(f"::error::gh attestation verify without the signer pinned: {b}")
    if not found:
        print("::error::no `gh attestation verify` command found; the scan is broken")
        return 1
    if bad:
        return 1
    print(f"attestation commands: all {found} pin the signer workflow, the tag and GitHub-hosted runners")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
