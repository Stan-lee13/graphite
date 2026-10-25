#!/usr/bin/env python3
"""Do the live rulesets and the `release` environment match the committed files?
(Round 38, R37-8.) Read-only; run weekly by .github/workflows/ruleset-drift.yml.

  ruleset-drift.py --live DIR [--committed DIR] [--environment FILE]

DIR holds the API's answers, as GITHUB_TOKEN reads them:
  rulesets.json                       GET repos/{repo}/rulesets
  ruleset-<id>.json                   GET repos/{repo}/rulesets/{id}, each one listed
  environment-release.json            GET repos/{repo}/environments/release
  environment-release-policies.json   GET .../environments/release/deployment-branch-policies
(a missing environment file is a missing environment: the workflow removes the
file when the API answers 404).

Exit 0 only when every REQUIRED committed ruleset (main.json, release-tags.json,
release-tags-create.json) is live, once, by name, with the same target,
enforcement, conditions and rules, and the environment has its reviewers and
exactly its tag policy. Exit 1 on any difference or absence; 2 when an answer
cannot be read (an API error is never a pass).

What GITHUB_TOKEN cannot see is said, not assumed: GitHub returns a ruleset's
`bypass_actors` only to a caller that may edit it. When the field is visible
it must equal the committed one; when it is not, the check requires
`current_user_can_bypass` to be "never" (the workflow token, which can write,
cannot bypass) and reports the bypass list as not verified.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
REQUIRED = ("main.json", "release-tags.json", "release-tags-create.json")


def load(path, kind):
    try:
        data = json.load(open(path))
    except (OSError, ValueError) as e:
        print(f"::error::cannot read {path}: {e}")
        sys.exit(2)
    if not isinstance(data, kind):
        print(f"::error::{path} is not the expected API answer: {str(data)[:200]}")
        sys.exit(2)
    return data


def canon(v):
    """Order-free form of a JSON value: lists compare as sets of canonical items."""
    if isinstance(v, dict):
        return {k: canon(x) for k, x in v.items()}
    if isinstance(v, list):
        return sorted((canon(x) for x in v), key=lambda x: json.dumps(x, sort_keys=True))
    return v


def falsy(v):
    return v in (False, None, 0, "", [], {})


def compare_ruleset(fname, want, live, problems, notes):
    name = want["name"]
    for k in ("target", "enforcement"):
        if live.get(k) != want.get(k):
            problems.append(f"{fname} ({name}): {k} is {live.get(k)!r}, committed {want.get(k)!r}")
    if canon(live.get("conditions")) != canon(want.get("conditions")):
        problems.append(f"{fname} ({name}): conditions {json.dumps(live.get('conditions'))}, committed {json.dumps(want.get('conditions'))}")
    lrules = {}
    for r in live.get("rules") or []:
        lrules.setdefault(r.get("type"), []).append(r)
    wrules = {r["type"]: r for r in want.get("rules") or []}
    for t in sorted(set(lrules) - set(wrules)):
        problems.append(f"{fname} ({name}): live rule {t!r} is not in the committed file")
    for t, w in wrules.items():
        got = lrules.get(t)
        if not got:
            problems.append(f"{fname} ({name}): rule {t!r} is missing")
            continue
        if len(got) > 1:
            problems.append(f"{fname} ({name}): rule {t!r} appears {len(got)} times")
        lp, wp = got[0].get("parameters") or {}, w.get("parameters") or {}
        for k, v in wp.items():
            if canon(lp.get(k)) != canon(v):
                problems.append(f"{fname} ({name}): {t}.{k} is {json.dumps(lp.get(k))}, committed {json.dumps(v)}")
        for k in sorted(set(lp) - set(wp)):
            # A parameter the committed file does not name is GitHub's default
            # for a feature left off; one switched ON is a difference.
            if not falsy(lp[k]):
                problems.append(f"{fname} ({name}): {t}.{k} is {json.dumps(lp[k])} live, and not in the committed file")
    if "bypass_actors" in live:
        if canon(live["bypass_actors"]) != canon(want.get("bypass_actors") or []):
            problems.append(f"{fname} ({name}): bypass_actors {json.dumps(live['bypass_actors'])}, committed {json.dumps(want.get('bypass_actors'))}")
    else:
        notes.append(f"{fname} ({name}): bypass_actors not visible to this token (GitHub shows it only to an editor of the ruleset); not verified")
    cub = live.get("current_user_can_bypass")
    if cub is None:
        notes.append(f"{fname} ({name}): current_user_can_bypass not reported")
    elif cub != "never":
        problems.append(f"{fname} ({name}): the workflow token can bypass it ({cub!r})")


def compare_environment(want, live_dir, problems, notes):
    env_file = os.path.join(live_dir, "environment-release.json")
    pol_file = os.path.join(live_dir, "environment-release-policies.json")
    if not os.path.exists(env_file):
        problems.append(f"environment {want['name']!r} does not exist")
        return
    env = load(env_file, dict)
    if env.get("name") != want["name"] or "protection_rules" not in env:
        print(f"::error::{env_file} is not the environment {want['name']!r}: {str(env)[:200]}")
        sys.exit(2)
    rules = env.get("protection_rules") or []
    reviewers = [r for r in rules if r.get("type") == "required_reviewers"]
    n = sum(len(r.get("reviewers") or []) for r in reviewers)
    if n < want["required_reviewers"]["min"]:
        problems.append(f"environment {want['name']!r}: {n} required reviewers, at least {want['required_reviewers']['min']} wanted")
    if env.get("deployment_branch_policy") != want["deployment_branch_policy"]:
        problems.append(f"environment {want['name']!r}: deployment_branch_policy {json.dumps(env.get('deployment_branch_policy'))}, committed {json.dumps(want['deployment_branch_policy'])}")
    if not os.path.exists(pol_file):
        problems.append(f"environment {want['name']!r}: its deployment branch policies could not be read")
        return
    pol = load(pol_file, dict)
    if not isinstance(pol.get("branch_policies"), list):
        print(f"::error::{pol_file} is not a branch-policy list: {str(pol)[:200]}")
        sys.exit(2)
    got = sorted((p.get("name"), p.get("type", "branch")) for p in pol["branch_policies"])
    exp = sorted((p["name"], p["type"]) for p in want["branch_policies"])
    if got != exp:
        problems.append(f"environment {want['name']!r}: branch and tag policies {got}, committed {exp}")
    notes.append(f"environment {want['name']!r}: can_admins_bypass {env.get('can_admins_bypass')!r}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--live", required=True)
    ap.add_argument("--committed", default=os.path.join(ROOT, ".github", "rulesets"))
    ap.add_argument("--environment", default=os.path.join(ROOT, ".github", "environments", "release.json"))
    args = ap.parse_args()

    committed = {}
    for f in sorted(os.listdir(args.committed)):
        if f.endswith(".json"):
            committed[f] = load(os.path.join(args.committed, f), dict)
    for f in REQUIRED:
        if f not in committed:
            print(f"::error::the committed ruleset {f} is missing from {args.committed}")
            sys.exit(2)
    listing = load(os.path.join(args.live, "rulesets.json"), list)
    live = {}
    for s in listing:
        rid = s.get("id")
        if not isinstance(rid, int):
            print(f"::error::a listed ruleset has no id: {s}")
            sys.exit(2)
        live.setdefault(s.get("name"), []).append(load(os.path.join(args.live, f"ruleset-{rid}.json"), dict))

    problems, notes, rows = [], [], []
    for f, want in committed.items():
        got = live.get(want["name"], [])
        if not got:
            if f in REQUIRED:
                problems.append(f"{f} ({want['name']}): not applied")
                rows.append((f, "ABSENT"))
            else:
                notes.append(f"{f} ({want['name']}): not applied (optional)")
                rows.append((f, "not applied (optional)"))
            continue
        if len(got) > 1:
            problems.append(f"{f} ({want['name']}): {len(got)} live rulesets have this name")
        before = len(problems)
        compare_ruleset(f, want, got[0], problems, notes)
        rows.append((f, "matches" if len(problems) == before else "DIFFERS"))
    names = {w["name"] for w in committed.values()}
    for n in sorted(set(live) - names, key=str):
        notes.append(f"live ruleset {n!r} has no committed file (rulesets only add restrictions; review it)")
    before = len(problems)
    compare_environment(load(args.environment, dict), args.live, problems, notes)
    rows.append(("environment release", "matches" if len(problems) == before else "DIFFERS"))

    table = ["| committed | live |", "|---|---|"] + [f"| {a} | {b} |" for a, b in rows]
    print("\n".join(table))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as fh:
            fh.write("## Rulesets and the release environment\n\n" + "\n".join(table) + "\n\n"
                     + "\n".join(f"- {n}" for n in notes) + "\n")
    for n in notes:
        print(f"::notice::ruleset-drift: {n}")
    for p in problems:
        print(f"::error::ruleset-drift: {p}")
    if problems:
        print(f"ruleset-drift: {len(problems)} difference(s): the repository is not configured as committed")
        return 1
    print("ruleset-drift: the live rulesets and the release environment match the committed files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
