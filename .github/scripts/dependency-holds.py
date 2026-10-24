#!/usr/bin/env python3
"""Dependency holds carry review-by dates (Round 38, D2-7).

A hold is a decision NOT to take an update: a semver-major `ignore` in
.github/dependabot.yml, or an `overrides` entry in a package.json that forces
a transitive package to one version (Zod at 4.6.7 in the SAK adapter, past
GHSA-mrhx-c7xc-m3w5). Each one is right when it is made and goes stale
silently: an ignore hides every later major, an exact override hides every
later patch, security fixes included. The list is .github/dependency-holds.json.

  dependency-holds.py check [--list F] [--root DIR] [--today YYYY-MM-DD]
      Offline. Exit 0 only when
        - every Dependabot ignore entry and every npm override in a tracked
          package.json is listed, with the same value (an override moved
          without its hold, or a new ignore, fails);
        - every listed hold still exists (a stale one fails: prune it);
        - every hold has a reason, a `since` date and a `review_by` date that
          is not past and at most `max_days` after `since` (a far-future date
          is not a review date).
      Exit 1 otherwise, 2 when an input cannot be read.
"""
import argparse
import datetime as dt
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def die(msg):
    print(f"::error::dependency-holds: {msg}")
    sys.exit(2)


def dependabot_ignores(root):
    try:
        import yaml
    except ImportError:
        die("python3-yaml is required")
    path = os.path.join(root, ".github", "dependabot.yml")
    try:
        data = yaml.safe_load(open(path))
    except (OSError, yaml.YAMLError) as e:
        die(f"cannot read {path}: {e}")
    found = {}
    for u in data.get("updates") or []:
        for ig in u.get("ignore") or []:
            key = ("dependabot-ignore", u.get("package-ecosystem"), u.get("directory"), ig.get("dependency-name"))
            value = json.dumps({k: ig[k] for k in sorted(ig) if k != "dependency-name"}, sort_keys=True)
            found[key] = value
    return found


def package_files(root):
    try:
        out = subprocess.run(["git", "-C", root, "ls-files", "-z", "--", "*package.json"],
                             capture_output=True, check=True).stdout.decode()
        files = [f for f in out.split("\0") if f and "node_modules/" not in f]
    except (OSError, subprocess.CalledProcessError):
        files = []
    if not files:  # not a git checkout (a test copy): walk it
        for d, dirs, fs in os.walk(root):
            dirs[:] = [x for x in dirs if x not in ("node_modules", ".git", "target")]
            files += [os.path.relpath(os.path.join(d, f), root) for f in fs if f == "package.json"]
    return sorted(files)


def npm_overrides(root):
    found = {}
    for f in package_files(root):
        try:
            data = json.load(open(os.path.join(root, f)))
        except (OSError, ValueError) as e:
            die(f"cannot read {f}: {e}")

        def walk(obj, path):
            for k, v in obj.items():
                p = path + [k]
                if isinstance(v, dict):
                    walk(v, p)
                else:
                    found[("npm-override", None, f, "/".join(p))] = json.dumps(v)

        walk(data.get("overrides") or {}, [])
    return found


def key_of(h):
    if h.get("kind") == "dependabot-ignore":
        return ("dependabot-ignore", h.get("ecosystem"), h.get("directory"), h.get("package"))
    if h.get("kind") == "npm-override":
        return ("npm-override", None, h.get("file"), h.get("package"))
    return None


def value_of(h):
    if h.get("kind") == "dependabot-ignore":
        return json.dumps(h.get("value") or {}, sort_keys=True)
    return json.dumps(h.get("value"))


def check(args):
    try:
        data = json.load(open(args.list))
    except (OSError, ValueError) as e:
        die(f"cannot read {args.list}: {e}")
    holds, max_days = data.get("holds"), data.get("max_days")
    if not isinstance(holds, list) or not holds or not isinstance(max_days, int) or max_days <= 0:
        die(f"{args.list}: needs a non-empty `holds` list and a positive `max_days`")
    today = dt.date.fromisoformat(args.today) if args.today else dt.date.today()
    live = {**dependabot_ignores(args.root), **npm_overrides(args.root)}
    problems, listed = [], {}
    for h in holds:
        k = key_of(h)
        name = f"{h.get('kind')} {h.get('package')!r} ({h.get('directory') or h.get('file')})"
        if k is None:
            problems.append(f"{name}: kind must be dependabot-ignore or npm-override")
            continue
        if k in listed:
            problems.append(f"{name}: listed twice")
        listed[k] = h
        if not str(h.get("why") or "").strip():
            problems.append(f"{name}: no `why`")
        try:
            since, review = dt.date.fromisoformat(h.get("since", "")), dt.date.fromisoformat(h.get("review_by", ""))
        except (TypeError, ValueError):
            problems.append(f"{name}: since {h.get('since')!r} / review_by {h.get('review_by')!r} are not YYYY-MM-DD")
            continue
        if review < today:
            problems.append(f"{name}: review_by {review} has passed: re-decide the hold (take the update, or re-check and move the date)")
        if (review - since).days > max_days:
            problems.append(f"{name}: review_by {review} is {(review - since).days} days after {since} (at most {max_days})")
        if k not in live:
            problems.append(f"{name}: no longer in the tree: remove the hold")
        elif live[k] != value_of(h):
            problems.append(f"{name}: the tree says {live[k]}, the hold {value_of(h)}: change them together")
    for k, v in sorted(live.items(), key=str):
        if k not in listed:
            where = k[2]
            problems.append(f"{k[0]} {k[3]!r} ({where}) = {v} has no hold in {os.path.relpath(args.list, args.root)}: add it with a reason and a review_by date")
    for p in problems:
        print(f"::error::dependency-holds: {p}")
    if problems:
        return 1
    first = min(dt.date.fromisoformat(h["review_by"]) for h in holds)
    print(f"dependency-holds: all {len(holds)} holds listed and current; the first is due {first}")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("--list", default=os.path.join(ROOT, ".github", "dependency-holds.json"))
    c.add_argument("--root", default=ROOT)
    c.add_argument("--today")
    args = ap.parse_args()
    sys.exit(check(args))


if __name__ == "__main__":
    main()
