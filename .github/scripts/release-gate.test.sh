#!/usr/bin/env bash
# `A && ok … || bad …` is deliberate: ok always succeeds (SC2015).
# shellcheck disable=SC2015
# Tests for release-gate.sh (Round 34, R33-9): the CI-gate decision against
# recorded API answers, the main-ancestry check and the tag-signature check
# against throwaway repositories and keys. Needs bash, python3, git and
# ssh-keygen (OpenSSH 8.2+). Exit 0 only when every case behaved.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
gate="$here/release-gate.sh"
pass=0
fail=0
ok() { pass=$((pass + 1)); echo "  ok   $*"; }
bad() { fail=$((fail + 1)); echo "  FAIL $*"; }
expect() { # expect RC DESCRIPTION COMMAND...
  local want="$1" d="$2" rc=0 out
  shift 2
  out="$("$@" 2>&1)" || rc=$?
  if [ "$rc" = "$want" ]; then ok "$d (exit $rc)"; else bad "$d (exit $rc, wanted $want)"; printf '%s\n' "$out" | sed 's/^/       /'; fi
}

T="$(mktemp -d)" && [ -n "$T" ] && [ -d "$T" ] || { echo "cannot create a scratch directory" >&2; exit 1; }
trap 'rm -rf "$T"' EXIT
# Hermetic git: no user or system configuration (a signing program or key
# configured there would sign the test tags with something else).
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1

SHA=1111111111111111111111111111111111111111
REPO=Stan-lee13/graphite

# A workflow run (the owner of a check suite): ID EVENT BRANCH [PATH] [SHA] [REPO]
wr() {
  printf '{"id":%s,"name":"CI","event":"%s","head_branch":"%s","path":"%s","head_sha":"%s","check_suite_id":%s,"repository":{"full_name":"%s"},"head_repository":{"full_name":"%s"}}' \
    "$1" "$2" "$3" "${4:-.github/workflows/ci.yml}" "${5:-$SHA}" "$((1000 + $1))" "${6:-$REPO}" "${6:-$REPO}"
}
# A `CI gate` check run: ID SUITE_ID STATUS CONCLUSION COMPLETED_AT [APP_ID]
cr() {
  printf '{"id":%s,"name":"CI gate","head_sha":"%s","status":"%s","conclusion":%s,"completed_at":"%s","html_url":"https://example.invalid/%s","app":{"id":%s},"check_suite":{"id":%s}}' \
    "$1" "$SHA" "$3" "$4" "$5" "$1" "${6:-15368}" "$2"
}
case_files() { # case_files NAME CHECK_RUNS... -- WORKFLOW_RUNS...
  local name="$1" runs=() wfs=() side=runs
  shift
  for a in "$@"; do
    if [ "$a" = -- ]; then side=wfs; continue; fi
    if [ "$side" = runs ]; then runs+=("$a"); else wfs+=("$a"); fi
  done
  (IFS=,; printf '{"total_count":%s,"check_runs":[%s]}' "${#runs[@]}" "${runs[*]}") >"$T/$name.runs.json"
  (IFS=,; printf '{"total_count":%s,"workflow_runs":[%s]}' "${#wfs[@]}" "${wfs[*]}") >"$T/$name.wf.json"
}
ci() { "$gate" ci-gate "$T/$1.runs.json" "$T/$1.wf.json" "$SHA" "$REPO"; }

echo "== ci-gate"
# The R33-9 hole: a branch's own ci.yml, run for its pull request, reports a
# green `CI gate` on the very commit the tag names.
case_files pr "$(cr 1 1001 completed '"success"' 2026-10-22T10:00:00Z)" -- "$(wr 1 pull_request feature)"
expect 3 "a green CI gate from a pull_request run does not release" ci pr
out="$(ci pr 2>&1)"
grep -q 'ignored check run 1' <<<"$out" && ok "the pull_request run is named as ignored" || bad "the pull_request run was not reported"
case_files push_ok "$(cr 2 1002 completed '"success"' 2026-10-22T10:00:00Z)" -- "$(wr 2 push main)"
expect 0 "a green CI gate from a push to main releases" ci push_ok
case_files both "$(cr 1 1001 completed '"success"' 2026-10-22T11:00:00Z)" "$(cr 2 1002 completed '"failure"' 2026-10-22T10:00:00Z)" -- \
  "$(wr 1 pull_request feature)" "$(wr 2 push main)"
expect 1 "a red push-to-main gate is not rescued by a newer green PR gate" ci both
case_files push_red "$(cr 2 1002 completed '"failure"' 2026-10-22T10:00:00Z)" -- "$(wr 2 push main)"
expect 1 "a red CI gate from a push to main refuses" ci push_red
case_files rerun "$(cr 2 1002 completed '"success"' 2026-10-22T10:00:00Z)" "$(cr 3 1002 completed '"failure"' 2026-10-22T12:00:00Z)" -- "$(wr 2 push main)"
expect 1 "the latest completed attempt decides (green, then red)" ci rerun
case_files pending "$(cr 2 1002 in_progress null '')" -- "$(wr 2 push main)"
expect 3 "a push-to-main gate still running waits" ci pending
case_files pending_after_red "$(cr 2 1002 completed '"failure"' 2026-10-22T10:00:00Z)" "$(cr 3 1002 queued null '')" -- "$(wr 2 push main)"
expect 3 "a red gate with a re-run queued waits" ci pending_after_red
# Runs on main's code but not started by a push: a manual dispatch, and a
# pull request whose HEAD branch is main (main proposed into another branch).
case_files dispatch "$(cr 8 1008 completed '"success"' 2026-10-22T10:00:00Z)" -- "$(wr 8 workflow_dispatch main)"
expect 3 "a green gate from a workflow_dispatch run on main does not release" ci dispatch
case_files pr_from_main "$(cr 9 1009 completed '"success"' 2026-10-22T10:00:00Z)" -- "$(wr 9 pull_request main)"
expect 3 "a green gate from a pull_request whose head branch is main does not release" ci pr_from_main
case_files tag_push "$(cr 4 1004 completed '"success"' 2026-10-22T10:00:00Z)" -- "$(wr 4 push v0.3.0-beta)"
expect 3 "a green gate from the tag's own push run does not release" ci tag_push
case_files other_app "$(cr 2 1002 completed '"success"' 2026-10-22T10:00:00Z 999)" -- "$(wr 2 push main)"
expect 3 "a 'CI gate' check run created by another app does not release" ci other_app
case_files other_wf "$(cr 5 1005 completed '"success"' 2026-10-22T10:00:00Z)" -- "$(wr 5 push main .github/workflows/other.yml)"
expect 3 "a 'CI gate' job of another workflow file does not release" ci other_wf
case_files other_sha "$(cr 6 1006 completed '"success"' 2026-10-22T10:00:00Z)" -- "$(wr 6 push main .github/workflows/ci.yml 2222222222222222222222222222222222222222)"
expect 3 "a push run of another commit does not release" ci other_sha
case_files fork "$(cr 7 1007 completed '"success"' 2026-10-22T10:00:00Z)" -- "$(wr 7 push main .github/workflows/ci.yml "$SHA" someone/graphite)"
expect 3 "a run in another repository does not release" ci fork
case_files nothing --
expect 3 "no check run at all waits" ci nothing
printf '{"message":"Not Found"}' >"$T/err.runs.json"
cp "$T/push_ok.wf.json" "$T/err.wf.json"
expect 2 "an API error instead of an answer stops the gate" ci err

echo "== ancestor"
g() { git -C "$T/repo" -c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false "$@"; }
git init -q -b main "$T/repo"
g commit -q --allow-empty -m one
first="$(g rev-parse HEAD)"
# The fixture's own introduction of the gate: the commit that adds
# .github/scripts/release-gate.sh, found the way the real constant was found.
mkdir -p "$T/repo/.github/scripts"
echo gate >"$T/repo/.github/scripts/release-gate.sh"
g add .github/scripts/release-gate.sh
g commit -q -m "the release gate"
since="$(g log --diff-filter=A --format=%H -- .github/scripts/release-gate.sh | tail -n 1)"
g commit -q --allow-empty -m two
on_main="$(g rev-parse HEAD)"
g checkout -q -b feature
g commit -q --allow-empty -m side
side="$(g rev-parse HEAD)"
g checkout -q main
anc() { (cd "$T/repo" && "$gate" ancestor "$1" main "${2:-$since}"); }
expect 0 "the head of main is releasable" anc "$on_main"
expect 0 "the commit that introduced the gate is releasable" anc "$since"
# Re-pinned in Round 38 (R37-8). This case expected 0 ("an older commit of
# main is releasable"): any commit on main counted, so a signed tag on
# 99948c6 (on main at 0.3.0-beta, before the gate existed) was a release
# candidate. The gate now also requires the tagged commit to descend from
# the commit that introduced it. Limit: a tag on such a commit runs THAT
# commit's release.yml, which has no gate at all; this pins the check for
# every tag on a later commit, and release-guard.yml (main's copy) plus the
# owner's tag ruleset and `release` environment are what stop the old one.
expect 1 "an older main commit from before the gate was introduced is refused (R37-8)" anc "$first"
out="$(anc "$first" 2>&1)"
grep -q 'predates the release gate' <<<"$out" && ok "the refusal names the gate's introduction" || bad "the pre-gate refusal did not say why: $out"
expect 1 "a branch commit not merged to main is refused" anc "$side"
expect 1 "a gate-introduction commit this repository does not have fails closed" anc "$on_main" 2222222222222222222222222222222222222222
# The committed constant, against this repository's own history (ci-scripts
# checks out with fetch-depth: 0; a shallow clone fails here, it never skips).
real_root="$(cd "$here/../.." && pwd)"
const="$(sed -n 's/^GATE_INTRODUCED=\([0-9a-f]\{40\}\)$/\1/p' "$gate")"
found="$(git -C "$real_root" log --diff-filter=A --format=%H -- .github/scripts/release-gate.sh 2>/dev/null | tail -n 1)"
[ -n "$const" ] && [ "$const" = "$found" ] && ok "GATE_INTRODUCED ($const) is the commit that added release-gate.sh" \
  || bad "GATE_INTRODUCED '${const:-unset}' is not the commit that added release-gate.sh ('${found:-not found: shallow clone?}')"
real() { (cd "$real_root" && "$gate" ancestor "$1" HEAD); }
expect 1 "99948c6 (Round 32's ungated release.yml, on main) is refused by the committed constant" real 99948c6
expect 0 "this checkout's HEAD is releasable under the committed constant" real HEAD

echo "== tag-signature"
ssh-keygen -q -t ed25519 -N '' -C release -f "$T/release" >/dev/null
ssh-keygen -q -t ed25519 -N '' -C other -f "$T/other" >/dev/null
printf 'release@example.invalid namespaces="git" %s\n' "$(cut -d' ' -f1,2 "$T/release.pub")" >"$T/allowed"
printf '# the release signing key goes here\n\n' >"$T/allowed-empty"
printf '# no key revoked\n\n' >"$T/revoked"
printf '# revoked 2026-10-24\n%s\n' "$(cat "$T/release.pub")" >"$T/revoked-release"
rk="$(cut -d' ' -f1,2 "$T/release.pub")"
printf 'release@example.invalid namespaces="git",valid-before="20200101" %s\n' "$rk" >"$T/allowed-expired"
printf 'release@example.invalid namespaces="git",valid-after="20990101" %s\n' "$rk" >"$T/allowed-future"
printf 'release@example.invalid namespaces="git",valid-after="20200101",valid-before="20990101" %s\n' "$rk" >"$T/allowed-window"
stag() { # stag NAME KEY COMMIT
  g -c gpg.format=ssh -c user.signingkey="$2" tag -s "$1" -m "graphite $1" "$3"
  g cat-file tag "$1" >"$T/$1.raw"
}
stag v1.0.0 "$T/release" "$on_main"
stag v1.0.1 "$T/other" "$on_main"
g tag -a v1.0.2 -m "unsigned" "$on_main"
g cat-file tag v1.0.2 >"$T/v1.0.2.raw"
: >"$T/lightweight.raw"
sig() { "$gate" tag-signature "$T/$1.raw" "$1" "${3:-$on_main}" "${2:-$T/allowed}" "${4:-$T/revoked}"; }
expect 0 "a tag signed by the allowed release key passes" sig v1.0.0
expect 1 "a tag signed by any other key is refused" sig v1.0.1
expect 1 "an annotated tag without a signature is refused" sig v1.0.2
expect 1 "a lightweight tag (no tag object) is refused" "$gate" tag-signature "$T/lightweight.raw" v1.0.3 "$on_main" "$T/allowed" "$T/revoked"
expect 1 "a signed tag of another commit is refused" sig v1.0.0 "$T/allowed" "$first"
expect 1 "a signed tag object presented under another tag name is refused" "$gate" tag-signature "$T/v1.0.0.raw" v9.9.9 "$on_main" "$T/allowed" "$T/revoked"
expect 1 "an empty allowed-signers list fails closed" sig v1.0.0 "$T/allowed-empty"
out="$("$gate" tag-signature "$T/v1.0.0.raw" v1.0.0 "$on_main" "$T/allowed-empty" "$T/revoked" 2>&1)"
grep -q 'names no signer' <<<"$out" && ok "the empty list is named as the reason" || bad "the empty-list refusal did not say why"
# One byte of the signed payload changed (the message), signature kept.
sed 's/^graphite v1.0.0$/graphite v1.0.0!/' "$T/v1.0.0.raw" >"$T/v1.0.0x.raw"
cmp -s "$T/v1.0.0.raw" "$T/v1.0.0x.raw" && bad "the tamper fixture did not change the payload"
expect 1 "a signed tag whose message was altered is refused" "$gate" tag-signature "$T/v1.0.0x.raw" v1.0.0 "$on_main" "$T/allowed" "$T/revoked"
# D2-5 (Round 38): a signer can be revoked, and a key can carry a validity
# window (ssh-keygen's valid-after / valid-before, judged at release time,
# never at the tag's own, signer-chosen tagger date).
expect 1 "a listed key that is also in the revocation list is refused" sig v1.0.0 "$T/allowed" "$on_main" "$T/revoked-release"
out="$(sig v1.0.0 "$T/allowed" "$on_main" "$T/revoked-release" 2>&1)"
grep -q 'revoked' <<<"$out" && ok "the revocation is named as the reason" || bad "the revoked-key refusal did not say why: $out"
expect 1 "a key whose valid-before date has passed is refused" sig v1.0.0 "$T/allowed-expired"
out="$(sig v1.0.0 "$T/allowed-expired" 2>&1)"
grep -q 'expired' <<<"$out" && ok "the expiry is named as the reason" || bad "the expired-key refusal did not say why: $out"
expect 1 "a key whose valid-after date is still ahead is refused" sig v1.0.0 "$T/allowed-future"
expect 0 "a key inside its validity window passes" sig v1.0.0 "$T/allowed-window"
expect 1 "a missing revocation list fails closed" sig v1.0.0 "$T/allowed" "$on_main" "$T/no-such-revoked"
expect 64 "the revocation list cannot be left out (four arguments are a usage error)" "$gate" tag-signature "$T/v1.0.0.raw" v1.0.0 "$on_main" "$T/allowed"
# The committed list: until the owner fills it, every release fails closed.
committed="$here/../allowed_signers"
committed_revoked="$here/../revoked_signers"
[ -f "$committed_revoked" ] && ok "the committed revocation list exists" || bad "$committed_revoked is missing"
if grep -qvE '^[[:space:]]*(#|$)' "$committed"; then
  expect 1 "the committed allowed_signers does not accept a throwaway key" sig v1.0.0 "$committed" "$on_main" "$committed_revoked"
else
  expect 1 "the committed (still empty) allowed_signers refuses every tag" sig v1.0.0 "$committed" "$on_main" "$committed_revoked"
fi

echo "== same-tag (D2-3)"
# What publish re-reads right before it pushes, attests and creates the
# release: the tag ref still names the tag object the gate verified, and
# that object still names the gated commit. GET git/ref/tags/TAG and
# GET git/tags/OBJECT, as recorded answers.
TO=3333333333333333333333333333333333333333
ref() { printf '{"ref":"refs/tags/%s","object":{"type":"%s","sha":"%s"}}' "$1" "$2" "$3" >"$T/ref.json"; }
tobj() { printf '{"sha":"%s","tag":"%s","object":{"type":"%s","sha":"%s"}}' "$1" "$2" "$3" "$4" >"$T/tagobj.json"; }
same() { "$gate" same-tag "$T/ref.json" "$T/tagobj.json" v1.0.0 "$TO" "$SHA"; }
ref v1.0.0 tag "$TO"; tobj "$TO" v1.0.0 commit "$SHA"
expect 0 "the tag the gate verified, unchanged, publishes" same
# publish reads the tag object by the hash the gate output, so that object
# is always the verified one; only the ref shows a re-created tag.
ref v1.0.0 tag 4444444444444444444444444444444444444444; tobj "$TO" v1.0.0 commit "$SHA"
expect 1 "a tag re-created after the gate (the ref names another tag object) is refused" same
ref v1.0.0 commit "$SHA"; tobj "$TO" v1.0.0 commit "$SHA"
expect 1 "a tag replaced by a lightweight tag is refused" same
ref v1.0.0 tag "$TO"; tobj "$TO" v1.0.0 commit 2222222222222222222222222222222222222222
expect 1 "a tag object that names another commit is refused" same
ref v1.0.0 tag "$TO"; tobj "$TO" v9.9.9 commit "$SHA"
expect 1 "a tag object under another name is refused" same
ref v1.0.0 tag "$TO"; printf '{"message":"Not Found"}' >"$T/tagobj.json"
expect 2 "an API error instead of the tag object stops the publish" same
expect 64 "an empty expected tag object is a usage error, never a match" "$gate" same-tag "$T/ref.json" "$T/tagobj.json" v1.0.0 "" "$SHA"

echo
echo "release-gate tests: $pass passed, $fail failed"
[ "$fail" = 0 ]
