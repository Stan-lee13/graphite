#!/usr/bin/env bash
# The release gate's decisions (Round 34, R33-9), one per subcommand, each a
# pure function of its inputs so .github/scripts/release-gate.test.sh can run
# it against recorded API answers and throwaway repositories.
#
#   release-gate.sh ci-gate CHECK_RUNS_JSON WORKFLOW_RUNS_JSON SHA REPO
#       exit 0: a `CI gate` check run of the GitHub Actions app (app id 15368)
#               that belongs to a PUSH run of .github/workflows/ci.yml on
#               refs/heads/main for SHA, in REPO, completed with success, and
#               is the latest such run to complete
#       exit 1: the latest qualifying run did not succeed and none is pending
#       exit 3: no qualifying run has completed yet (the caller waits)
#     CHECK_RUNS_JSON is GET repos/{repo}/commits/{sha}/check-runs; the
#     WORKFLOW_RUNS_JSON is GET repos/{repo}/actions/runs?head_sha={sha}. A
#     check run only names its check suite; the workflow run that owns that
#     suite says which event started it and on which branch. A pull_request
#     run of a branch's own ci.yml, a run on a tag, a check run some other app
#     created under the same name, and a run of any other workflow file are
#     all ignored, and each one ignored is named in the output.
#
#   release-gate.sh ancestor SHA MAIN_REF [SINCE]
#       exit 0 when SHA is MAIN_REF or an ancestor of it, AND SHA is SINCE or
#       a descendant of it (git, in the cwd). SINCE defaults to
#       GATE_INTRODUCED below, the commit that added this script (Round 38,
#       R37-8): a commit older than the gate carries a release.yml without
#       it, so a tag on it is never a release, however signed. Limit: a tag
#       on such a commit runs THAT commit's release.yml, which never calls
#       this; release-guard.yml (main's copy, on every Release run) and the
#       owner's tag ruleset and `release` environment are what stop it.
#
#   release-gate.sh tag-signature RAW_TAG TAG SHA ALLOWED_SIGNERS REVOKED
#       exit 0 when RAW_TAG (the output of `git cat-file tag TAG`) is an
#       annotated tag named TAG, of the commit SHA, carrying an SSH signature
#       (namespace `git`) by a key in ALLOWED_SIGNERS that is not in REVOKED
#       and is inside its valid-after / valid-before window at the time of
#       the check (the release, never the tag's own tagger date, which the
#       signer chooses). FAILS CLOSED when ALLOWED_SIGNERS names no key: an
#       empty list is "nobody may release", never "anybody may"; and when
#       REVOKED is missing (an empty list, comments only, revokes nothing).
#
#   release-gate.sh same-tag REF_JSON TAG_JSON TAG TAG_OBJECT SHA
#       exit 0 when REF_JSON (GET repos/{repo}/git/ref/tags/TAG) still names
#       the annotated tag object TAG_OBJECT the gate verified, and TAG_JSON
#       (GET repos/{repo}/git/tags/TAG_OBJECT) is that object, named TAG, of
#       the commit SHA (Round 38, D2-3: publish re-reads this right before
#       it pushes, attests and creates the release, and once after).
#
# Every other exit is a usage or input error and stops the release.
set -euo pipefail

die() { echo "::error::$*" >&2; exit 1; }
usage() { sed -n '2,48p' "$0" >&2; exit 64; }

# The commit that introduced this gate on main (Round 34, R33-9), found with
# `git log --diff-filter=A --format=%H -- .github/scripts/release-gate.sh`;
# release-gate.test.sh checks the two still agree. Every main commit before
# it carries a release.yml with no signature, ancestry or push-run check.
GATE_INTRODUCED=ad3f7ad9e41e932869a1f68322396b1ef86254f4

cmd="${1:-}"
[ $# -gt 0 ] && shift
case "$cmd" in
  ci-gate)
    [ $# -eq 4 ] || usage
    rc=0
    python3 -I - "$@" <<'PY' || rc=$?
import json, sys

runs_file, wf_file, sha, repo = sys.argv[1:5]
# The GitHub Actions app. Any GitHub App can create a check run named
# "CI gate" through the checks API; only this app's runs are workflow runs.
ACTIONS_APP_ID = 15368
CI_WORKFLOW = ".github/workflows/ci.yml"

def load(path, key):
    try:
        data = json.load(open(path))
    except (OSError, ValueError) as e:
        print(f"::error::cannot read {path}: {e}")
        sys.exit(2)
    if not isinstance(data, dict) or not isinstance(data.get(key), list):
        print(f"::error::{path} is not an API answer with a '{key}' list")
        sys.exit(2)
    return data[key]

check_runs = load(runs_file, "check_runs")
workflow_runs = load(wf_file, "workflow_runs")

# The check suites that belong to a push of main's own ci.yml at this commit.
push_suites = {}
for w in workflow_runs:
    why = None
    if w.get("event") != "push":
        why = f"event {w.get('event')!r}"
    elif w.get("head_branch") != "main":
        why = f"branch {w.get('head_branch')!r}"
    elif w.get("head_sha") != sha:
        why = f"head_sha {w.get('head_sha')!r}"
    elif w.get("path") != CI_WORKFLOW:
        why = f"workflow {w.get('path')!r}"
    elif (w.get("repository") or {}).get("full_name") != repo or (
        w.get("head_repository") or {}
    ).get("full_name") != repo:
        why = "another repository"
    if why:
        print(f"ignored workflow run {w.get('id')} ({w.get('name')}): {why}, not a push of {CI_WORKFLOW} on main")
    else:
        push_suites[w.get("check_suite_id")] = w

qualifying = []
for r in check_runs:
    if r.get("name") != "CI gate":
        continue
    app = (r.get("app") or {}).get("id")
    suite = (r.get("check_suite") or {}).get("id")
    if app != ACTIONS_APP_ID:
        print(f"ignored check run {r.get('id')}: created by app {app}, not GitHub Actions ({ACTIONS_APP_ID})")
    elif r.get("head_sha") != sha:
        print(f"ignored check run {r.get('id')}: head_sha {r.get('head_sha')!r}")
    elif suite is None or suite not in push_suites:
        print(f"ignored check run {r.get('id')} ({r.get('conclusion') or r.get('status')}): suite {suite} is not a push run of {CI_WORKFLOW} on main")
    else:
        qualifying.append(r)

done = sorted((r for r in qualifying if r.get("status") == "completed"), key=lambda r: r.get("completed_at") or "")
pending = [r for r in qualifying if r.get("status") != "completed"]
if not done:
    print(f"no completed CI gate from a push to main on {sha} yet ({len(pending)} pending)")
    sys.exit(3)
latest = done[-1]
print(f"latest CI gate from a push to main on {sha}: {latest.get('conclusion')} ({latest.get('html_url')})")
if latest.get("conclusion") == "success":
    sys.exit(0)
if pending:
    print("a newer CI gate run is still in progress")
    sys.exit(3)
print("::error::the CI gate of the push to main did not pass on this commit; not releasing")
sys.exit(1)
PY
    case "$rc" in 0 | 1 | 3) exit "$rc" ;; *) exit 2 ;; esac
    ;;

  ancestor)
    [ $# -eq 2 ] || [ $# -eq 3 ] || usage
    sha="$1" main="$2" since="${3:-$GATE_INTRODUCED}"
    [ -n "$since" ] || usage
    git rev-parse --verify --quiet "$main^{commit}" >/dev/null || die "$main is not a commit here (fetch-depth: 0 is required)"
    git rev-parse --verify --quiet "$sha^{commit}" >/dev/null || die "$sha is not a commit here"
    git rev-parse --verify --quiet "$since^{commit}" >/dev/null || die "the gate's introduction $since is not a commit here (fetch-depth: 0 is required)"
    git merge-base --is-ancestor "$sha" "$main" || die "$sha is not on $main: only a commit merged to main is released"
    if git merge-base --is-ancestor "$since" "$sha"; then
      echo "$sha is on $main and descends from the gate's introduction ($since)"
    else
      die "$sha predates the release gate (it does not descend from $since, the commit that introduced it): its release.yml has no gate, so it is never released"
    fi
    ;;

  tag-signature)
    [ $# -eq 5 ] || usage
    raw="$1" tag="$2" sha="$3" signers="$4" revoked="$5"
    [ -f "$signers" ] || die "$signers is missing"
    [ -f "$revoked" ] || die "the revocation list $revoked is missing (an empty one, comments only, revokes nothing; a missing one stops the release)"
    if ! grep -qvE '^[[:space:]]*(#|$)' "$signers"; then
      die "$signers names no signer, so no tag can be verified and nothing is released. The owner adds the release signing key (docs/ops/production-checklist.md, \"Release integrity\")."
    fi
    [ -s "$raw" ] || die "no tag object for $tag (a lightweight tag cannot be signed; use git tag -s)"
    work="$(mktemp -d)"
    trap 'rm -rf "$work"' EXIT
    # The header of a tag object: object, type, tag, tagger, blank line.
    obj="$(sed -n '1,/^$/{s/^object //p;}' "$raw")"
    typ="$(sed -n '1,/^$/{s/^type //p;}' "$raw")"
    name="$(sed -n '1,/^$/{s/^tag //p;}' "$raw")"
    [ "$typ" = commit ] || die "tag $tag points at a $typ, not a commit"
    [ "$name" = "$tag" ] || die "the tag object is named '$name', not $tag"
    [ "$obj" = "$sha" ] || die "tag $tag names $obj, not the commit being released ($sha)"
    # git appends the signature to the message; the signed payload is every
    # byte before it.
    begin='-----BEGIN SSH SIGNATURE-----'
    end='-----END SSH SIGNATURE-----'
    grep -qxF -- "$begin" "$raw" || die "tag $tag carries no SSH signature (sign it with gpg.format=ssh: git tag -s)"
    awk -v b="$begin" '$0 == b {exit} {print}' "$raw" >"$work/payload"
    awk -v b="$begin" -v e="$end" '$0 == b {on=1} on {print} $0 == e {exit}' "$raw" >"$work/sig"
    grep -qxF -- "$end" "$work/sig" || die "tag $tag has a truncated SSH signature"
    # find-principals and verify both judge valid-after / valid-before at
    # the time they run (now), so an expired key matches no principal.
    principals="$(ssh-keygen -Y find-principals -s "$work/sig" -f "$signers" 2>"$work/fp.err" || true)"
    if [ -z "$principals" ]; then
      if grep -q 'key has expired\|not yet valid' "$work/fp.err"; then
        die "tag $tag is signed by a key of $signers outside its validity window ($(grep -m1 'expired\|not yet valid' "$work/fp.err" | sed 's/^[^:]*:[0-9]*: //'))"
      fi
      die "tag $tag is signed by a key that is not in $signers"
    fi
    while IFS= read -r p; do
      if ssh-keygen -Y verify -f "$signers" -I "$p" -n git -s "$work/sig" -r "$revoked" <"$work/payload" >"$work/verify.out" 2>&1; then
        echo "tag $tag ($sha) has a good signature by $p (not revoked, inside its validity window)"
        exit 0
      fi
      # ssh-keygen says only "Could not verify signature" for a revoked key:
      # a signature that verifies without the list and not with it is one.
      if ssh-keygen -Y verify -f "$signers" -I "$p" -n git -s "$work/sig" <"$work/payload" >/dev/null 2>&1; then
        die "tag $tag is signed by $p with a key listed in the revocation list $revoked"
      fi
    done <<<"$principals"
    die "the signature on tag $tag does not verify"
    ;;

  same-tag)
    [ $# -eq 5 ] || usage
    [ -n "$4" ] && [ -n "$5" ] || usage
    rc=0
    python3 -I - "$@" <<'PY' || rc=$?
import json, sys

ref_file, tag_file, tag, want_obj, want_sha = sys.argv[1:6]

def load(path, keys):
    try:
        data = json.load(open(path))
    except (OSError, ValueError) as e:
        print(f"::error::cannot read {path}: {e}")
        sys.exit(2)
    if not isinstance(data, dict) or any(k not in data for k in keys):
        print(f"::error::{path} is not an API answer with {keys}")
        sys.exit(2)
    return data

ref = load(ref_file, ("ref", "object"))
obj = load(tag_file, ("sha", "tag", "object"))
problems = []
if ref.get("ref") != f"refs/tags/{tag}":
    problems.append(f"the ref is {ref.get('ref')!r}, not refs/tags/{tag}")
if (ref.get("object") or {}).get("type") != "tag":
    problems.append(f"refs/tags/{tag} now names a {(ref.get('object') or {}).get('type')!r}, not an annotated tag")
if (ref.get("object") or {}).get("sha") != want_obj:
    problems.append(f"refs/tags/{tag} now names {(ref.get('object') or {}).get('sha')}, not the tag object the gate verified ({want_obj})")
if obj.get("sha") != want_obj:
    problems.append(f"the tag object read is {obj.get('sha')}, not {want_obj}")
if obj.get("tag") != tag:
    problems.append(f"the tag object is named {obj.get('tag')!r}, not {tag}")
if (obj.get("object") or {}).get("type") != "commit" or (obj.get("object") or {}).get("sha") != want_sha:
    problems.append(f"the tag object names {(obj.get('object') or {}).get('sha')}, not the gated commit {want_sha}")
if problems:
    for p in problems:
        print(f"::error::{p}")
    print("::error::the tag is not the one the gate verified; not publishing")
    sys.exit(1)
print(f"tag {tag} is still {want_obj}, of {want_sha}: the one the gate verified")
PY
    case "$rc" in 0 | 1) exit "$rc" ;; *) exit 2 ;; esac
    ;;

  *) usage ;;
esac
