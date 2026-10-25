#!/usr/bin/env python3
"""Do the live rulesets and the `release` environment match the committed files?
(Round 38, R37-8; Round 39.) Read-only; run weekly by .github/workflows/ruleset-drift.yml.

  ruleset-drift.py --live DIR [--committed DIR] [--environment FILE] [--require-bypass]

DIR holds the API's answers:
  rulesets.json                       GET repos/{repo}/rulesets
  ruleset-<id>.json                   GET repos/{repo}/rulesets/{id}, each one listed
  environment-release.json            GET repos/{repo}/environments/release
  environment-release-policies.json   GET .../environments/release/deployment-branch-policies
(a missing environment file is a missing environment: the workflow removes the
file when the API answers 404).

The live state must be EXACTLY the committed files (Round 39):
  - every committed ruleset in REQUIRED (main.json, main-review.json,
    release-tags.json, release-tags-create.json) is live, once, under its
    committed name, with the same target, enforcement, conditions, rules and
    bypass list;
  - no live ruleset exists that has no committed file. Round 38 only noted
    one, so the repository's real ruleset ("Main-review", 2026-10-25: 26
    always-bypass actors, an extra rule, 0 approvals) was compared with
    nothing. Such a ruleset is now a difference, and it is compared, field by
    field, with the committed ruleset for the same target and refs, so every
    way it differs is named;
  - the `release` environment has its reviewers and exactly its tag policy.
Exit 0 only then; 1 on any difference or absence; 2 when an answer cannot be
read (an API error is never a pass).

What a token cannot see is said, not assumed: GitHub returns a ruleset's
`bypass_actors` only to a caller that may edit it, and GITHUB_TOKEN cannot.
When the field is visible it must equal the committed one. When it is not,
the check requires `current_user_can_bypass` to be "never" (the workflow
token cannot bypass) and reports the bypass list as NOT VERIFIED; with
--require-bypass (the owner's run, with an admin token:
docs/ops/production-checklist.md, R5) an invisible bypass list is a
difference, so exit 0 then covers the bypass lists too.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
# Round 39: main-review.json is required. Since Round 38 (D2-4) it lets the
# admin role bypass it through a pull request only, so one maintainer can
# merge (each merge is logged as a bypass); without it live, "0 required
# approvals" was the committed state and no check could call it a gap.
REQUIRED = ("main.json", "main-review.json", "release-tags.json", "release-tags-create.json")


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


def actor(a):
    return f"{a.get('actor_type')} {a.get('actor_id')} ({a.get('bypass_mode')})"


def akey(a):
    return (a.get("actor_type"), a.get("actor_id"), a.get("bypass_mode"))


def aorder(k):
    return (str(k[0]), k[1] if isinstance(k[1], int) else -1, str(k[2]))


def compare_ruleset(label, want, live, problems, notes, require_bypass):
    """Every difference between a live ruleset and the committed one, named.
    Returns the number of bypass lists left unverified (0 or 1)."""
    if live.get("name") != want.get("name"):
        problems.append(f"{label}: named {live.get('name')!r}, committed {want.get('name')!r}")
    for k in ("target", "enforcement"):
        if live.get(k) != want.get(k):
            problems.append(f"{label}: {k} is {live.get(k)!r}, committed {want.get(k)!r}")
    if canon(live.get("conditions")) != canon(want.get("conditions")):
        problems.append(f"{label}: conditions {json.dumps(live.get('conditions'))}, committed {json.dumps(want.get('conditions'))}")
    lrules = {}
    for r in live.get("rules") or []:
        lrules.setdefault(r.get("type"), []).append(r)
    wrules = {r["type"]: r for r in want.get("rules") or []}
    for t in sorted(set(lrules) - set(wrules), key=str):
        problems.append(f"{label}: live rule {t!r} is not in the committed file ({json.dumps(lrules[t][0].get('parameters') or {})})")
    for t, w in wrules.items():
        got = lrules.get(t)
        if not got:
            problems.append(f"{label}: rule {t!r} is missing")
            continue
        if len(got) > 1:
            problems.append(f"{label}: rule {t!r} appears {len(got)} times")
        lp, wp = got[0].get("parameters") or {}, w.get("parameters") or {}
        for k, v in wp.items():
            if canon(lp.get(k)) != canon(v):
                problems.append(f"{label}: {t}.{k} is {json.dumps(lp.get(k))}, committed {json.dumps(v)}")
        for k in sorted(set(lp) - set(wp)):
            # A parameter the committed file does not name is GitHub's default
            # for a feature left off; one switched ON is a difference.
            if not falsy(lp[k]):
                problems.append(f"{label}: {t}.{k} is {json.dumps(lp[k])} live, and not in the committed file")
    unverified = 0
    if "bypass_actors" in live:
        lb = {akey(a): a for a in live["bypass_actors"] or []}
        wb = {akey(a): a for a in want.get("bypass_actors") or []}
        for k in sorted(set(lb) - set(wb), key=aorder):
            problems.append(f"{label}: bypass actor {actor(lb[k])} is live and not committed")
        for k in sorted(set(wb) - set(lb), key=aorder):
            problems.append(f"{label}: committed bypass actor {actor(wb[k])} is missing")
        # The list read is the authority; this caller's own answer (an admin
        # token reads "always" on release-tags-create) is only reported.
        if live.get("current_user_can_bypass") is not None:
            notes.append(f"{label}: current_user_can_bypass {live.get('current_user_can_bypass')!r} for this token")
    else:
        unverified = 1
        msg = f"{label}: bypass_actors not visible to this token (GitHub shows it only to an editor of the ruleset); NOT VERIFIED"
        (problems if require_bypass else notes).append(msg + (" (--require-bypass)" if require_bypass else ""))
        cub = live.get("current_user_can_bypass")
        if cub is None:
            notes.append(f"{label}: current_user_can_bypass not reported")
        elif cub != "never":
            problems.append(f"{label}: this token can bypass it ({cub!r})")
    return unverified


def nearest(live, committed):
    """The committed ruleset a live one stands in for: same target and refs."""
    same = [f for f, w in committed.items()
            if w.get("target") == live.get("target") and canon(w.get("conditions")) == canon(live.get("conditions"))]
    return sorted(same)


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
    ap.add_argument("--require-bypass", action="store_true",
                    help="an invisible bypass list is a difference (run with an admin token)")
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
    unverified = 0
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
        u = compare_ruleset(f"{f} ({want['name']})", want, got[0], problems, notes, args.require_bypass)
        unverified += u
        state = "matches" if len(problems) == before else "DIFFERS"
        rows.append((f, state + (" (bypass list NOT VERIFIED)" if u and state == "matches" else "")))
    names = {w["name"] for w in committed.values()}
    for n in sorted(set(live) - names, key=str):
        for lr in live[n]:
            # Round 39: an uncommitted live ruleset is a difference, compared
            # with the committed one(s) it stands in for, field by field.
            label = f"live ruleset {n!r} (id {lr.get('id')})"
            near = nearest(lr, committed)
            if near:
                problems.append(f"{label} has no committed file; it covers the refs of {', '.join(near)}: "
                                f"delete it once the committed file is applied, or commit it")
                for f in near:
                    compare_ruleset(f"{label} vs committed {f}", committed[f], lr, problems, notes, args.require_bypass)
            else:
                problems.append(f"{label} has no committed file and covers refs no committed ruleset covers "
                                f"({lr.get('target')}, {json.dumps(lr.get('conditions'))}); delete it or commit it")
                compare_ruleset(label, {"name": None, "rules": [], "bypass_actors": []}, lr, problems, notes, args.require_bypass)
            rows.append((f"(none: {n!r})", "UNCOMMITTED"))
    before = len(problems)
    compare_environment(load(args.environment, dict), args.live, problems, notes)
    rows.append(("environment release", "matches" if len(problems) == before else "DIFFERS"))

    table = ["| committed | live |", "|---|---|"] + [f"| {a} | {b} |" for a, b in rows]
    print("\n".join(table))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as fh:
            fh.write("## Rulesets and the release environment\n\n" + "\n".join(table) + "\n\n"
                     + "\n".join(f"- {p}" for p in problems) + ("\n\n" if problems else "")
                     + "\n".join(f"- {n}" for n in notes) + "\n")
    for n in notes:
        print(f"::notice::ruleset-drift: {n}")
    for p in problems:
        print(f"::error::ruleset-drift: {p}")
    if problems:
        print(f"ruleset-drift: {len(problems)} difference(s): the repository is not configured as committed")
        return 1
    if unverified:
        print(f"ruleset-drift: everything this token can read matches the committed files; {unverified} bypass "
              f"list(s) NOT VERIFIED (re-run with --require-bypass and an admin token)")
        return 0
    print("ruleset-drift: the live rulesets, their bypass lists and the release environment match the committed files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
