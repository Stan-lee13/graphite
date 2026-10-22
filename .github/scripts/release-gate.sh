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
#   release-gate.sh ancestor SHA MAIN_REF
#       exit 0 when SHA is MAIN_REF or an ancestor of it (git, in the cwd)
#
#   release-gate.sh tag-signature RAW_TAG TAG SHA ALLOWED_SIGNERS
#       exit 0 when RAW_TAG (the output of `git cat-file tag TAG`) is an
#       annotated tag named TAG, of the commit SHA, carrying an SSH signature
#       (namespace `git`) by a key in ALLOWED_SIGNERS. FAILS CLOSED when
#       ALLOWED_SIGNERS names no key: an empty list is "nobody may release",
#       never "anybody may".
#
# Every other exit is a usage or input error and stops the release.
set -euo pipefail

die() { echo "::error::$*" >&2; exit 1; }
usage() { sed -n '2,32p' "$0" >&2; exit 64; }

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
    [ $# -eq 2 ] || usage
    sha="$1" main="$2"
    git rev-parse --verify --quiet "$main^{commit}" >/dev/null || die "$main is not a commit here (fetch-depth: 0 is required)"
    git rev-parse --verify --quiet "$sha^{commit}" >/dev/null || die "$sha is not a commit here"
    if git merge-base --is-ancestor "$sha" "$main"; then
      echo "$sha is on $main"
    else
      die "$sha is not on $main: only a commit merged to main is released"
    fi
    ;;

  tag-signature)
    [ $# -eq 4 ] || usage
    raw="$1" tag="$2" sha="$3" signers="$4"
    [ -f "$signers" ] || die "$signers is missing"
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
    principals="$(ssh-keygen -Y find-principals -s "$work/sig" -f "$signers" 2>/dev/null || true)"
    [ -n "$principals" ] || die "tag $tag is signed by a key that is not in $signers"
    while IFS= read -r p; do
      if ssh-keygen -Y verify -f "$signers" -I "$p" -n git -s "$work/sig" <"$work/payload" >/dev/null 2>&1; then
        echo "tag $tag ($sha) has a good signature by $p"
        exit 0
      fi
    done <<<"$principals"
    die "the signature on tag $tag does not verify"
    ;;

  *) usage ;;
esac
