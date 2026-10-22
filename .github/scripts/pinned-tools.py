#!/usr/bin/env python3
"""Hand-pinned CI tools: are the pins where the list says, and are they current?
(Round 34, R33-20.) The list is .github/pinned-tools.json.

  pinned-tools.py check-pins [--list F] [--root DIR]
      Offline. Every tool's `pinned_in` text occurs verbatim in its file, and
      every entry is well formed. Exit 1 otherwise. Runs in CI on every change,
      so a bump in a workflow without the list (or the reverse) fails.

  pinned-tools.py report [--list F] [--today YYYY-MM-DD] [--latest F]
      Asks upstream (GitHub releases/latest, crates.io max_stable_version) for
      each tool's newest release; reports a tool whose newer release exists or
      whose `reviewed` date is more than max_age_days old. Exit 1 when any is
      reported, 2 when upstream could not be asked (never a silent pass).
      `--latest F` reads {"tool name": "version"} instead of the network (tests).
      Uses GH_TOKEN for GitHub API reads when set; no secret is needed.
"""
import argparse
import datetime as dt
import json
import os
import re
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def load(path):
    with open(path) as f:
        data = json.load(f)
    tools = data.get("tools")
    if not isinstance(tools, list) or not tools:
        sys.exit(f"{path}: no tools")
    if not isinstance(data.get("max_age_days"), int) or data["max_age_days"] <= 0:
        sys.exit(f"{path}: max_age_days must be a positive integer")
    return data


def vkey(v):
    return tuple(int(x) for x in re.findall(r"\d+", v))


def check_pins(args):
    data = load(args.list)
    problems = []
    for t in data["tools"]:
        name = t.get("name", "?")
        for k in ("name", "version", "reviewed", "source", "pinned_in"):
            if k not in t:
                problems.append(f"{name}: missing '{k}'")
        try:
            dt.date.fromisoformat(t.get("reviewed", ""))
        except ValueError:
            problems.append(f"{name}: reviewed {t.get('reviewed')!r} is not YYYY-MM-DD")
        src = t.get("source") or {}
        if len(src) != 1 or next(iter(src)) not in ("github", "crate", "none"):
            problems.append(f"{name}: source must be one of github / crate / none")
        pins = t.get("pinned_in") or []
        if not pins:
            problems.append(f"{name}: pinned_in is empty")
        if not any(t.get("version", "\0") in p.get("text", "") for p in pins):
            problems.append(f"{name}: no pinned_in text names version {t.get('version')!r}")
        for p in pins:
            path = os.path.join(args.root, p.get("file", ""))
            try:
                text = open(path).read()
            except OSError as e:
                problems.append(f"{name}: {p.get('file')}: {e.strerror}")
                continue
            if p.get("text", "") not in text:
                problems.append(f"{name}: {p.get('file')} no longer contains {p.get('text')!r} (update the pin and this list together)")
    for p in problems:
        print(f"::error::pinned-tools: {p}")
    if problems:
        return 1
    print(f"pinned-tools: all {len(data['tools'])} pins are where the list says")
    return 0


def fetch_json(url, headers):
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def latest_online(tool):
    src = tool["source"]
    if "github" in src:
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "graphite-pinned-tools"}
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return fetch_json(f"https://api.github.com/repos/{src['github']}/releases/latest", headers)["tag_name"]
    if "crate" in src:
        headers = {"User-Agent": "graphite-pinned-tools (github.com/Stan-lee13/graphite)"}
        return fetch_json(f"https://crates.io/api/v1/crates/{src['crate']}", headers)["crate"]["max_stable_version"]
    return None


def report(args):
    data = load(args.list)
    today = dt.date.fromisoformat(args.today) if args.today else dt.date.today()
    given = json.load(open(args.latest)) if args.latest else None
    max_age = data["max_age_days"]
    findings, errors, rows = [], [], []
    for t in data["tools"]:
        name, version = t["name"], t["version"]
        age = (today - dt.date.fromisoformat(t["reviewed"])).days
        try:
            latest = given.get(name) if given is not None else latest_online(t)
        except Exception as e:  # noqa: BLE001 - any failure to ask is reported, never passed
            errors.append(f"{name}: could not read the latest release: {e}")
            latest = "?"
        if given is not None and name not in given and "none" not in t["source"]:
            errors.append(f"{name}: no latest version given")
            latest = "?"
        status = []
        if latest not in (None, "?") and vkey(latest) > vkey(version):
            status.append(f"newer release {latest}")
        if age > max_age:
            status.append(f"reviewed {age} days ago (> {max_age})")
        rows.append((name, version, latest or "-", t["reviewed"], ", ".join(status) or "current"))
        if status:
            findings.append(f"{name} {version}: " + "; ".join(status))
    lines = ["| tool | pinned | latest | reviewed | status |", "|---|---|---|---|---|"]
    lines += [f"| {' | '.join(r)} |" for r in rows]
    print("\n".join(lines))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            f.write("## Hand-pinned tools\n\n" + "\n".join(lines) + "\n")
    for e in errors:
        print(f"::error::pinned-tools: {e}")
    for f in findings:
        print(f"::warning::pinned-tools: {f} — bump it (or re-check and move `reviewed`) in .github/pinned-tools.json and the workflow")
    if errors:
        return 2
    return 1 if findings else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check-pins")
    c.add_argument("--list", default=os.path.join(ROOT, ".github", "pinned-tools.json"))
    c.add_argument("--root", default=ROOT)
    r = sub.add_parser("report")
    r.add_argument("--list", default=os.path.join(ROOT, ".github", "pinned-tools.json"))
    r.add_argument("--today")
    r.add_argument("--latest")
    args = ap.parse_args()
    sys.exit(check_pins(args) if args.cmd == "check-pins" else report(args))


if __name__ == "__main__":
    main()
