#!/usr/bin/env bash
# `A && ok … || bad …` is deliberate: ok always succeeds (SC2015); the
# backticks in single quotes are fixture text, not expansions (SC2016).
# shellcheck disable=SC2015,SC2016
# Tests for the small CI scripts of Round 34: set-rpc-env.sh (D-9),
# pinned-tools.py (R33-20) and check-attestation-commands.py (R33-18); and
# Round 36's mutation_floor.py (F-015). Round 38: pinned-tools consistency
# (D2-6), dependency-holds.py (D2-7), the rulesets and ruleset-drift.py
# (D2-4, R37-8), the release workflows (R37-8, D2-3), test-count.sh per test
# binary (D2-8) and the Dockerfile's apt snapshot (D-8). Needs git and the
# repository's full history (ci-scripts checks out with fetch-depth: 0).
# Needs bash and python3; no network. Exit 0 only when every case behaved.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
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

echo "== set-rpc-env.sh"
rpc() { : >"$T/env"; "$here/set-rpc-env.sh" "$1" "$T/env"; }
# GitHub's own reading of a GITHUB_ENV file: NAME=value lines and
# NAME<<DELIM … DELIM blocks. Prints NAME=value per variable.
readenv() {
  python3 -I - "$T/env" <<'PY'
import sys
lines = open(sys.argv[1]).read().split("\n")
i = 0
while i < len(lines):
    l = lines[i]
    if "<<" in l and ("=" not in l or l.index("<<") < l.index("=")):
        name, delim = l.split("<<", 1)
        j = lines.index(delim, i + 1)
        print(f"{name}=" + "\n".join(lines[i + 1:j]))
        i = j + 1
    elif "=" in l:
        print(l)
        i += 1
    else:
        i += 1
PY
}
expect 0 "an https URL is accepted" rpc "https://rpc.example.invalid/?api-key=abc"
[ "$(readenv)" = "LIVE_RPC_URL=https://rpc.example.invalid/?api-key=abc" ] && ok "it reaches GITHUB_ENV as LIVE_RPC_URL alone" || bad "GITHUB_ENV holds: $(readenv)"
expect 0 "an http URL (a local validator) is accepted" rpc "http://127.0.0.1:8899"
# The D-9 injection: a dispatch input with a newline set a second variable.
expect 1 "a URL with a newline and a second assignment is refused" rpc "$(printf 'https://a.example\nLD_PRELOAD=/tmp/x.so')"
[ ! -s "$T/env" ] && ok "nothing was written for the refused value" || bad "the refused value was written: $(cat "$T/env")"
out="$("$here/set-rpc-env.sh" "$(printf 'https://a.example\n::stop-commands::x')" "$T/env" 2>&1)"
grep -q 'stop-commands' <<<"$out" && bad "the refused value was printed" || ok "the refused value is never printed"
expect 1 "a URL with a space is refused" rpc "https://a.example/ x"
expect 1 "a non-http scheme is refused" rpc "file:///etc/passwd"
expect 1 "an empty value is refused" rpc ""

echo "== pinned-tools.py"
P=(python3 -I "$here/pinned-tools.py")
expect 0 "the committed list matches the workflows" "${P[@]}" check-pins
mkdir -p "$T/root/.github/workflows"
cp "$root/.github/pinned-tools.json" "$T/root/.github/"
for f in $(python3 -I -c 'import json,sys; print("\n".join(sorted({p["file"] for t in json.load(open(sys.argv[1]))["tools"] for p in t["pinned_in"]})))' "$root/.github/pinned-tools.json"); do
  mkdir -p "$T/root/$(dirname "$f")"
  cp "$root/$f" "$T/root/$f"
done
expect 0 "a copy of the tree passes" "${P[@]}" check-pins --list "$T/root/.github/pinned-tools.json" --root "$T/root"
sed -i 's/CADDY_VERSION: v2\.11\.7/CADDY_VERSION: v2.11.8/' "$T/root/.github/workflows/ci.yml"
expect 1 "a pin bumped in a workflow but not in the list fails" "${P[@]}" check-pins --list "$T/root/.github/pinned-tools.json" --root "$T/root"
latest() { python3 -I - "$root/.github/pinned-tools.json" "$@" <<'PY'
import json, sys
tools = json.load(open(sys.argv[1]))["tools"]
over = dict(a.split("=", 1) for a in sys.argv[2:])
print(json.dumps({t["name"]: over.get(t["name"], t["version"]) for t in tools if "none" not in t["source"]}))
PY
}
latest >"$T/current.json"
latest "caddy=v2.12.0" >"$T/newer.json"
latest "cargo-audit=0.22.10" >"$T/newer-patch.json"
latest >"$T/missing.json"
python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); d.pop("caddy"); json.dump(d, open(sys.argv[1],"w"))' "$T/missing.json"
expect 0 "every pin current and recently reviewed: nothing reported" "${P[@]}" report --latest "$T/current.json" --today 2026-10-23
expect 1 "a newer upstream release is reported" "${P[@]}" report --latest "$T/newer.json" --today 2026-10-23
expect 1 "a newer patch release compares numerically (0.22.10 > 0.22.2)" "${P[@]}" report --latest "$T/newer-patch.json" --today 2026-10-23
expect 1 "a pin reviewed more than max_age_days ago is reported" "${P[@]}" report --latest "$T/current.json" --today 2027-06-01
expect 2 "an upstream that could not be asked is an error, not a pass" "${P[@]}" report --latest "$T/missing.json" --today 2026-10-23

echo "== check-attestation-commands.py"
A=(python3 -I "$here/check-attestation-commands.py")
expect 0 "every command in the repository pins the signer" "${A[@]}"
# The command name is assembled, so this file's own lines are not commands
# the repository-wide scan above would read.
V="gh attestation"
V="$V verify"
printf 'run:\n  %s x.tar.gz --repo o/graphite\n' "$V" >"$T/bare.md"
expect 1 "a command with --repo alone fails" "${A[@]}" "$T/bare.md"
printf '%s x.tar.gz --repo o/graphite \\\n  --signer-workflow o/graphite/.github/workflows/release.yml \\\n  --source-ref refs/tags/v1.0.0\n' "$V" >"$T/partial.md"
expect 1 "a command without --deny-self-hosted-runners fails" "${A[@]}" "$T/partial.md"
printf '%s x.tar.gz --repo o/graphite \\\n  --signer-workflow o/graphite/.github/workflows/release.yml \\\n  --source-ref refs/tags/v1.0.0 --deny-self-hosted-runners\n' "$V" >"$T/full.md"
expect 0 "a command with all three flags across continuation lines passes" "${A[@]}" "$T/full.md"
printf 'Run `gh attestation verify` before deploying.\n' >"$T/prose.md"
expect 1 "a file with no command at all is reported (the scan found nothing)" "${A[@]}" "$T/prose.md"

echo "== ci.yml and the ci-test profile (R33-8)"
# The gate is only as complete as its `needs`: every other job of ci.yml must
# be in it (a job left out can fail without failing the gate).
expect 0 "ci-gate needs every other job of ci.yml" python3 -I - "$root/.github/workflows/ci.yml" <<'PY'
import sys, yaml
jobs = yaml.safe_load(open(sys.argv[1]))["jobs"]
needs = set(jobs["ci-gate"]["needs"])
others = set(jobs) - {"ci-gate"}
missing, extra = others - needs, needs - others
if missing or extra:
    sys.exit(f"ci-gate.needs: missing {sorted(missing)}, unknown {sorted(extra)}")
PY
# The three test legs keep their commands, floors and allowlist; and they
# run under the ci-test profile, which must stay the release profile's
# semantics (only LTO and codegen partitioning may differ).
expect 0 "the rust-test legs keep their flags, floors and the ignored-test allowlist" python3 -I - "$root/.github/workflows/ci.yml" <<'PY'
import sys, yaml
job = yaml.safe_load(open(sys.argv[1]))["jobs"]["rust-test"]
legs = {l["leg"]: l for l in job["strategy"]["matrix"]["include"]}
want = {"default": ("", 2331), "lib": ("--no-default-features --lib", 509), "cli": ("--no-default-features --features cli", 1933)}
for leg, (flags, floor) in want.items():
    l = legs.get(leg) or sys.exit(f"leg {leg} is missing")
    if l["flags"] != flags or int(l["floor"]) < floor:
        sys.exit(f"leg {leg}: flags {l['flags']!r} floor {l['floor']} (wanted {flags!r}, floor >= {floor})")
run = next(s["run"] for s in job["steps"] if s.get("name", "").startswith("Tests"))
for needle in ("cargo test --locked --profile ci-test $FLAGS", "test-count.sh cargo", '"$FLOOR"', "rust-ignored.txt"):
    if needle not in run:
        sys.exit(f"the test step lost {needle!r}")
if not any("git status --porcelain" in (s.get("run") or "") for s in job["steps"]):
    sys.exit("the clean-tree check is gone")
PY
expect 0 "[profile.ci-test] is the release profile's semantics" python3 -I - "$root/graphite-core/Cargo.toml" <<'PY'
import sys, tomllib
p = tomllib.load(open(sys.argv[1], "rb"))["profile"]["ci-test"]
want = {"inherits": "release", "opt-level": 3, "debug-assertions": False, "overflow-checks": False}
bad = {k: p.get(k) for k, v in want.items() if p.get(k) != v}
if bad:
    sys.exit(f"profile.ci-test differs from release semantics: {bad}")
PY

echo "== mutation_floor.py (F-015)"
# The shapes cargo-mutants 27.1.0 writes. A shard killed by the step timeout
# leaves outcomes.json with total_mutants EQUAL to the outcomes recorded and
# end_time null; only mutants.json, written before the first mutant runs,
# holds the shard's own count. Run 40083338181 scored 16 such shards as
# complete.
floor="$root/graphite-core/scripts/mutation_floor.py"
shard() { # shard DIR LISTED CAUGHT MISSED UNVIABLE END_TIME
  mkdir -p "$1"
  python3 -I - "$@" <<'PY'
import json, sys
d, listed, caught, missed, unviable, end = sys.argv[1], *map(int, sys.argv[2:6]), sys.argv[6]
json.dump([{"name": f"m{i}"} for i in range(listed)], open(f"{d}/mutants.json", "w"))
oc = [{"scenario": "Baseline", "summary": "Success"}]
for n, s in ((caught, "CaughtMutant"), (missed, "MissedMutant"), (unviable, "Unviable")):
    oc += [{"scenario": {"Mutant": {}}, "summary": s}] * n
json.dump({"outcomes": oc, "total_mutants": caught + missed + unviable,
           "end_time": None if end == "null" else end}, open(f"{d}/outcomes.json", "w"))
PY
}
shard "$T/m-done" 10 8 1 1 2026-10-24T12:55:19Z
expect 0 "a finished shard at its floor passes" python3 -I "$floor" "$T/m-done/outcomes.json" 0.80
expect 1 "a finished shard below its floor fails" python3 -I "$floor" "$T/m-done/outcomes.json" 0.90
shard "$T/m-killed" 40 37 1 0 null
expect 1 "a shard killed after 38 of 40 is INCOMPLETE, not scored" python3 -I "$floor" "$T/m-killed/outcomes.json" 0.10
grep -q INCOMPLETE <<<"$(python3 -I "$floor" "$T/m-killed/outcomes.json" 0.10 2>&1)" && ok "and says INCOMPLETE" || bad "the killed shard was not reported INCOMPLETE"
shard "$T/m-short" 40 37 1 0 2026-10-24T12:55:19Z
expect 1 "a shard short of its list is INCOMPLETE even with an end time" python3 -I "$floor" "$T/m-short/outcomes.json" 0.10
shard "$T/m-open" 10 8 1 1 null
expect 1 "a shard with every outcome but no end time is INCOMPLETE" python3 -I "$floor" "$T/m-open/outcomes.json" 0.10
shard "$T/m-nolist" 10 9 1 0 2026-10-24T12:55:19Z && rm "$T/m-nolist/mutants.json"
expect 1 "a shard without its mutant list cannot be judged" python3 -I "$floor" "$T/m-nolist/outcomes.json" 0.10
shard "$T/m-empty" 0 0 0 0 2026-10-24T12:55:19Z
expect 1 "a shard that tested nothing fails" python3 -I "$floor" "$T/m-empty/outcomes.json" 0.10

echo "== pinned-tools.py: the same pin everywhere (D2-6)"
# check-pins used to ask only that each listed text occurs somewhere: a
# second, different pin of the same tool in another file (or another line of
# the same file) passed. Each tool now names the patterns its pin appears
# under, and every match in the files it names must carry the one version.
cons() { "${P[@]}" check-pins --list "$T/cons/.github/pinned-tools.json" --root "$T/cons"; }
fresh_cons() {
  rm -rf "$T/cons" && mkdir -p "$T/cons/.github"
  cp -r "$root/.github/workflows" "$T/cons/.github/"
  cp "$root/.github/pinned-tools.json" "$T/cons/.github/"
  cp "$root/Dockerfile" "$T/cons/"
}
fresh_cons
expect 0 "a copy of the tree with every workflow and the Dockerfile passes" cons
fresh_cons
sed -i '0,/toolchain: 1\.99\.1/s//toolchain: 1.98.0/' "$T/cons/.github/workflows/live-mainnet.yml"
expect 1 "a second, older toolchain pin in another workflow fails" cons
fresh_cons
printf '# rust:1.98.0-bookworm\n' >>"$T/cons/Dockerfile"
expect 1 "a stale rust image tag left in the Dockerfile fails" cons
fresh_cons
printf '      - run: cargo install cargo-audit --locked --version 0.21.0\n' >>"$T/cons/.github/workflows/assurance.yml"
expect 1 "a second cargo-audit install at another version fails" cons
fresh_cons
python3 -I - "$T/cons/.github/pinned-tools.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
for t in d["tools"]:
    if t["name"] == "caddy":
        t.pop("consistent", None)
json.dump(d, open(sys.argv[1], "w"))
PY
expect 1 "a tool without a consistency rule fails (no rule is not 'consistent')" cons
fresh_cons
python3 -I - "$T/cons/.github/pinned-tools.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
for t in d["tools"]:
    if t["name"] == "caddy":
        t["consistent"][0]["pattern"] = r"CADDY_NEVER_MATCHES: (\S+)"
json.dump(d, open(sys.argv[1], "w"))
PY
expect 1 "a consistency pattern that matches nothing fails" cons
fresh_cons
sed -i 's/toolchain: 1\.89\.0/toolchain: 1.90.0/' "$T/cons/.github/workflows/ci.yml"
expect 1 "the MSRV exception names its exact text: a changed MSRV pin fails until the list says so" cons

echo "== dependency-holds.py (D2-7)"
H=(python3 -I "$here/dependency-holds.py")
expect 0 "every Dependabot ignore and npm override is listed, none past review" "${H[@]}" check --today 2026-10-24
expect 1 "a hold past its review-by date fails" "${H[@]}" check --today 2027-06-01
fresh_holds() {
  rm -rf "$T/holds" && mkdir -p "$T/holds/.github"
  cp "$root/.github/dependabot.yml" "$root/.github/dependency-holds.json" "$T/holds/.github/"
  (cd "$root" && git ls-files '*package.json' | grep -v node_modules) | while read -r f; do
    mkdir -p "$T/holds/$(dirname "$f")" && cp "$root/$f" "$T/holds/$f"
  done
}
hold() { "${H[@]}" check --list "$T/holds/.github/dependency-holds.json" --root "$T/holds" --today 2026-10-24; }
fresh_holds
expect 0 "a copy of the tree passes" hold
fresh_holds
python3 -I - "$T/holds/.github/dependabot.yml" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
for u in d["updates"]:
    if u["directory"] == "/sdk/go":
        u["ignore"] = [{"dependency-name": "golang.org/x/net", "update-types": ["version-update:semver-major"]}]
yaml.safe_dump(d, open(sys.argv[1], "w"))
PY
expect 1 "a new Dependabot ignore without a review date fails" hold
fresh_holds
sed -i 's/"zod": "4\.6\.7"/"zod": "4.6.8"/' "$T/holds/integrations/solana-agent-kit/package.json"
expect 1 "an override moved without its hold fails" hold
fresh_holds
python3 -I - "$T/holds/.github/dependency-holds.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["holds"].append({"kind": "npm-override", "file": "dashboard/package.json", "package": "left-pad",
                   "value": "1.3.0", "since": "2026-10-24", "review_by": "2027-01-20", "why": "stale"})
json.dump(d, open(sys.argv[1], "w"))
PY
expect 1 "a hold for an override that no longer exists fails (prune it)" hold
fresh_holds
python3 -I - "$T/holds/.github/dependency-holds.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["holds"][0]["review_by"] = "2099-01-01"
json.dump(d, open(sys.argv[1], "w"))
PY
expect 1 "a review-by date beyond max_days after the hold was recorded fails" hold
fresh_holds
python3 -I - "$T/holds/.github/dependency-holds.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["holds"][0]["why"] = ""
json.dump(d, open(sys.argv[1], "w"))
PY
expect 1 "a hold without a reason fails" hold

echo "== rulesets (D2-4) and ruleset-drift.py (R37-8)"
expect 0 "the committed rulesets bypass only where they say" python3 -I - "$root/.github/rulesets" <<'PY'
import json, os, sys
d = sys.argv[1]
r = {f: json.load(open(os.path.join(d, f))) for f in os.listdir(d) if f.endswith(".json")}
want = {
    "main.json": [],
    "release-tags.json": [],
    "release-tags-create.json": [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}],
    # D2-4: a single maintainer cannot approve their own pull request, so
    # without a bypass this ruleset blocks every merge. The admin role may
    # bypass it through a pull request only (never by a direct push), and
    # every such merge is logged as a bypass.
    "main-review.json": [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "pull_request"}],
}
for f, b in want.items():
    if f not in r:
        sys.exit(f"{f} is missing")
    if r[f].get("bypass_actors") != b:
        sys.exit(f"{f}: bypass_actors {r[f].get('bypass_actors')} (wanted {b})")
    if r[f].get("enforcement") != "active":
        sys.exit(f"{f}: enforcement {r[f].get('enforcement')}")
PY
D=(python3 -I "$here/ruleset-drift.py")
# A live API answer made from the committed files: what GET rulesets and
# GET rulesets/{id} return once the owner applied them, as GITHUB_TOKEN sees
# it (bypass_actors withheld, current_user_can_bypass "never").
mklive() { # mklive DIR [show-bypass]
  rm -rf "$1" && mkdir -p "$1"
  python3 -I - "$root/.github/rulesets" "$root/.github/environments/release.json" "$1" "${2:-}" <<'PY'
import json, os, sys
src, env_file, out, show = sys.argv[1:5]
listing = []
for i, f in enumerate(sorted(x for x in os.listdir(src) if x.endswith(".json")), 1):
    r = json.load(open(os.path.join(src, f)))
    rid = 100 + i
    listing.append({"id": rid, "name": r["name"], "target": r["target"], "enforcement": r["enforcement"],
                    "source_type": "Repository", "source": "Stan-lee13/graphite"})
    live = dict(r, id=rid, source_type="Repository", source="Stan-lee13/graphite", current_user_can_bypass="never")
    if not show:
        live.pop("bypass_actors")
    # GitHub adds default parameters the committed file does not name.
    for rule in live["rules"]:
        if rule["type"] == "pull_request":
            rule["parameters"]["automatic_copilot_code_review_enabled"] = False
            rule["parameters"]["required_reviewers"] = []
    json.dump(live, open(os.path.join(out, f"ruleset-{rid}.json"), "w"))
json.dump(listing, open(os.path.join(out, "rulesets.json"), "w"))
env = json.load(open(env_file))
json.dump({"name": "release", "can_admins_bypass": True,
           "protection_rules": [{"type": "required_reviewers", "prevent_self_review": False,
                                 "reviewers": [{"type": "User", "reviewer": {"login": "owner", "id": 1}}]},
                                {"type": "branch_policy"}],
           "deployment_branch_policy": env["deployment_branch_policy"]},
          open(os.path.join(out, "environment-release.json"), "w"))
json.dump({"total_count": len(env["branch_policies"]),
           "branch_policies": [dict(p, id=7 + n) for n, p in enumerate(env["branch_policies"])]},
          open(os.path.join(out, "environment-release-policies.json"), "w"))
PY
}
drift() { "${D[@]}" --live "$1"; }
edit_live() { # edit_live DIR PYTHON (d = the directory, j/w = load/save)
  # A fixture edit that fails is a failed test, never an unedited fixture.
  python3 -I - "$1" "$2" <<'PY' || bad "the fixture edit failed: $2"
import json, os, sys
d = sys.argv[1]
def j(f): return json.load(open(os.path.join(d, f)))
def w(f, v): json.dump(v, open(os.path.join(d, f), "w"))
exec(sys.argv[2])
PY
}
L="$T/live"
mklive "$L"
expect 0 "the committed rulesets and environment, applied as committed: no drift" drift "$L"
mklive "$L" show
expect 0 "the same with bypass_actors visible (an admin token) and equal: no drift" drift "$L"
printf '[]' >"$T/empty-rulesets.json"
rm -rf "$T/live0" && mkdir -p "$T/live0" && cp "$T/empty-rulesets.json" "$T/live0/rulesets.json"
expect 1 "today's state (no ruleset, no release environment) fails" drift "$T/live0"
mklive "$L"
edit_live "$L" 'l = j("rulesets.json"); r = [x for x in l if x["name"].startswith("release tags — only")][0]; os.remove(os.path.join(d, "ruleset-%d.json" % r["id"])); w("rulesets.json", [x for x in l if x is not r])'
expect 1 "the tag-creation ruleset absent fails" drift "$L"
mklive "$L"
edit_live "$L" 'f = [x for x in os.listdir(d) if x.startswith("ruleset-")][0]; r = j(f); r["enforcement"] = "evaluate"; w(f, r)'
expect 1 "a ruleset switched to evaluate (not enforced) fails" drift "$L"
mklive "$L"
edit_live "$L" 'f = [x for x in os.listdir(d) if x.startswith("ruleset-") and "integrity" in j(x)["name"]][0]; r = j(f); r["rules"] = [x for x in r["rules"] if x["type"] != "required_status_checks"]; w(f, r)'
expect 1 "main without its required CI gate check fails" drift "$L"
mklive "$L"
edit_live "$L" 'f = [x for x in os.listdir(d) if x.startswith("ruleset-") and "integrity" in j(x)["name"]][0]; r = j(f); [x["parameters"].update(required_status_checks=[{"context": "CI gate"}]) for x in r["rules"] if x["type"] == "required_status_checks"]; w(f, r)'
expect 1 "a CI gate check required from any app (integration_id dropped) fails" drift "$L"
mklive "$L"
edit_live "$L" 'f = [x for x in os.listdir(d) if x.startswith("ruleset-") and "integrity" in j(x)["name"]][0]; r = j(f); [x["parameters"].update(require_last_push_approval=True, bypass_pull_request_allowances=True) for x in r["rules"] if x["type"] == "pull_request"]; w(f, r)'
expect 1 "an extra parameter switched on live fails" drift "$L"
mklive "$L" show
edit_live "$L" 'f = [x for x in os.listdir(d) if x.startswith("ruleset-") and "immutable" in j(x)["name"]][0]; r = j(f); r["bypass_actors"] = [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}]; w(f, r)'
expect 1 "a bypass actor added to the immutable-tags ruleset (visible) fails" drift "$L"
mklive "$L"
edit_live "$L" 'f = [x for x in os.listdir(d) if x.startswith("ruleset-")][0]; r = j(f); r["current_user_can_bypass"] = "always"; w(f, r)'
expect 1 "a ruleset the workflow token can bypass fails" drift "$L"
mklive "$L"
rm "$L/environment-release.json" "$L/environment-release-policies.json"
expect 1 "no release environment fails" drift "$L"
mklive "$L"
edit_live "$L" 'e = j("environment-release.json"); e["protection_rules"] = [x for x in e["protection_rules"] if x["type"] != "required_reviewers"]; w("environment-release.json", e)'
expect 1 "a release environment without a required reviewer fails" drift "$L"
mklive "$L"
edit_live "$L" 'p = j("environment-release-policies.json"); p["branch_policies"].append({"id": 99, "name": "*", "type": "branch"}); w("environment-release-policies.json", p)'
expect 1 "a release environment that also admits any branch fails" drift "$L"
mklive "$L"
printf '{"message":"Resource not accessible by integration"}' >"$L/rulesets.json"
expect 2 "an API error instead of the ruleset list is an error, never a pass" drift "$L"

echo "== ruleset-drift.py against the live state of 2026-10-25 (Round 39)"
# testdata/ruleset-drift-live-2026-10-25 is GET rulesets and GET rulesets/25817024
# as the owner's token read them on 2026-10-25: one branch ruleset, "Main-review",
# no tag ruleset; 0 required approvals; RepositoryRole 2 and 5 and 24 GitHub Apps
# with bypass_mode "always"; an extra copilot_code_review rule. Round 38's check
# matched rulesets by name and only NOTED one without a committed file, so it
# compared this ruleset with nothing.
SNAP="$here/testdata/ruleset-drift-live-2026-10-25"
L1="$T/live-snap"
rm -rf "$L1" && cp -r "$SNAP" "$L1"
expect 1 "today's live state fails" drift "$L1"
snap_out="$(drift "$L1" 2>&1)"
for needle in "live ruleset 'Main-review' (id 25817024) has no committed file" \
              "named 'Main-review', committed 'main — integrity (Round 30, G-11)'" \
              "live rule 'copilot_code_review' is not in the committed file" \
              "pull_request.required_approving_review_count is 0, committed 1" \
              "pull_request.require_extra_approval_for_unattributed_changes is true live" \
              "bypass actor RepositoryRole 2 (always) is live and not committed" \
              "bypass actor RepositoryRole 5 (always) is live and not committed" \
              "committed bypass actor RepositoryRole 5 (pull_request) is missing" \
              "release-tags.json (release tags — immutable (Round 30, G-11)): not applied" \
              "release-tags-create.json (release tags — only an admin creates one (Round 34, R33-9)): not applied" \
              "environment 'release' does not exist"; do
  grep -qF -- "$needle" <<<"$snap_out" && ok "the live state's difference is named: $needle" || bad "not named: $needle"
done
n_apps="$(grep -cE "vs committed main\.json: bypass actor Integration [0-9]+ \(always\) is live and not committed" <<<"$snap_out")"
[ "$n_apps" = 24 ] && ok "each of the 24 always-bypass GitHub Apps is named" || bad "$n_apps always-bypass apps named, wanted 24"
# The same ruleset as GITHUB_TOKEN reads it: bypass_actors withheld, and the
# workflow token itself cannot bypass.
edit_live "$L1" 'r = j("ruleset-25817024.json"); r.pop("bypass_actors"); r["current_user_can_bypass"] = "never"; w("ruleset-25817024.json", r)'
expect 1 "today's live state as GITHUB_TOKEN reads it (no bypass list) still fails" drift "$L1"
grep -qF "has no committed file" <<<"$(drift "$L1" 2>&1)" && ok "and names the uncommitted ruleset" || bad "the uncommitted ruleset is not named under GITHUB_TOKEN"
# The Round 38 hole itself: every committed ruleset applied exactly, and the
# uncommitted Main-review beside them. Round 38: exit 0 (a notice).
mklive "$L"
cp "$SNAP/ruleset-25817024.json" "$L/"
edit_live "$L" 'l = j("rulesets.json"); l.append(j("ruleset-25817024.json")); w("rulesets.json", l)'
expect 1 "an uncommitted ruleset beside the committed ones fails (Round 38: a notice, exit 0)" drift "$L"
# Main-review renamed to main.json's name, its extra rule and parameter
# removed: only its 26 always-bypass actors still differ.
mk_renamed() { # mk_renamed DIR [hide-bypass]
  mklive "$1" show
  python3 -I - "$1" "$SNAP/ruleset-25817024.json" "${2:-}" <<'PY' || bad "the renamed fixture could not be built"
import json, os, sys
d, snap, hide = sys.argv[1:4]
live = json.load(open(snap))
listing = json.load(open(os.path.join(d, "rulesets.json")))
main = next(x for x in listing if x["name"].startswith("main — integrity"))
live.update(id=main["id"], name=main["name"])
live["rules"] = [r for r in live["rules"] if r["type"] != "copilot_code_review"]
for r in live["rules"]:
    if r["type"] == "pull_request":
        r["parameters"].pop("require_extra_approval_for_unattributed_changes")
live["current_user_can_bypass"] = "never"
if hide:
    for f in os.listdir(d):
        if f.startswith("ruleset-"):
            x = json.load(open(os.path.join(d, f)))
            x.pop("bypass_actors", None)
            json.dump(x, open(os.path.join(d, f), "w"))
    live.pop("bypass_actors")
json.dump(live, open(os.path.join(d, f"ruleset-{main['id']}.json"), "w"))
PY
}
mk_renamed "$L"
expect 1 "main.json applied with Main-review's 26 always-bypass actors (visible) fails" drift "$L"
grep -qF "main.json (main — integrity (Round 30, G-11)): bypass actor Integration 8329 (always) is live and not committed" <<<"$(drift "$L" 2>&1)" \
  && ok "and names the bypass actors" || bad "the bypass actors are not named"
# What GITHUB_TOKEN cannot see stays a limit, said plainly: the weekly run
# passes with the bypass lists NOT VERIFIED, and the owner's run fails.
mk_renamed "$L" hide
expect 0 "the same, bypass lists hidden (GITHUB_TOKEN): passes, but only as far as it can see" drift "$L"
grep -qF "bypass list(s) NOT VERIFIED" <<<"$(drift "$L" 2>&1)" && ok "and says the bypass lists are NOT VERIFIED" || bad "an unverified bypass list was reported as a match"
expect 1 "the same with --require-bypass (the owner's run) fails" "${D[@]}" --live "$L" --require-bypass
mklive "$L"
expect 1 "applied as committed, bypass lists hidden, --require-bypass: fails (cannot verify)" "${D[@]}" --live "$L" --require-bypass
mklive "$L" show
edit_live "$L" 'l = j("rulesets.json"); r = [x for x in l if x["name"].startswith("release tags — only")][0]; f = "ruleset-%d.json" % r["id"]; x = j(f); x["current_user_can_bypass"] = "always"; w(f, x)'
expect 0 "applied as committed, read by an admin (visible lists; it may bypass tag creation): no drift" "${D[@]}" --live "$L" --require-bypass
grep -qF "their bypass lists and the release environment match" <<<"$("${D[@]}" --live "$L" --require-bypass 2>&1)" \
  && ok "and claims the bypass lists only when it read them" || bad "the full-match line is missing"
mklive "$L"
edit_live "$L" 'l = j("rulesets.json"); r = [x for x in l if x["name"].startswith("main — independent review")][0]; os.remove(os.path.join(d, "ruleset-%d.json" % r["id"])); w("rulesets.json", [x for x in l if x is not r])'
expect 1 "main-review.json absent (0 required approvals) fails: it is required since Round 39" drift "$L"

echo "== the release workflows (R37-8, D2-3)"
expect 0 "release.yml: publish re-reads the tag the gate verified, before pushing and around the release" python3 -I - "$root/.github/workflows/release.yml" <<'PY'
import sys, yaml
jobs = yaml.safe_load(open(sys.argv[1]))["jobs"]
gate, pub = jobs["gate"], jobs["publish"]
for k in ("tag_object", "commit"):
    if k not in gate.get("outputs", {}):
        sys.exit(f"gate does not output {k}")
names = [s.get("name") or s.get("uses", "") for s in pub["steps"]]
i_check = next((i for i, s in enumerate(pub["steps"]) if "same-tag" in (s.get("run") or "")), None)
i_push = next((i for i, n in enumerate(names) if n.startswith("Push the image")), None)
if i_check is None or i_push is None or i_check > i_push:
    sys.exit("no same-tag check before the image push")
rel = next(s for s in pub["steps"] if s.get("name") == "GitHub Release")["run"]
a, c = rel.find("same_tag\n"), rel.find("gh release create")
if a < 0 or c < 0 or a > c or "if ! same_tag" not in rel[c:] or "gh release delete" not in rel[c:]:
    sys.exit("the GitHub Release step does not re-check the tag before and after creating the release")
sig = next(s for s in gate["steps"] if s.get("id") == "signature")["run"]
if ".github/revoked_signers" not in sig:
    sys.exit("the gate does not pass the revocation list")
PY
expect 0 "release-guard.yml: runs from main on every Release run, checks read-only, stops a refused one" python3 -I - "$root/.github/workflows/release-guard.yml" "$root/.github/workflows/release.yml" <<'PY'
import sys, yaml
g = yaml.safe_load(open(sys.argv[1]))
rel_name = yaml.safe_load(open(sys.argv[2]))["name"]
on = g.get(True) or g.get("on")
wr = on.get("workflow_run") or sys.exit("not triggered by workflow_run")
if wr.get("workflows") != [rel_name]:
    sys.exit(f"workflow_run.workflows {wr.get('workflows')} is not [{rel_name!r}]")
if not {"requested", "completed"} <= set(wr.get("types", [])):
    sys.exit("must run when a Release run is requested and when it completes")
if set(on) != {"workflow_run"}:
    sys.exit(f"other triggers: {sorted(set(on) - {'workflow_run'})}")
if g.get("permissions") != {}:
    sys.exit("workflow-level permissions must be {}")
check, stop = g["jobs"]["check"], g["jobs"]["stop"]
if check.get("permissions") != {"contents": "read"}:
    sys.exit(f"check job permissions {check.get('permissions')}")
if stop.get("permissions") != {"actions": "write", "contents": "write"}:
    sys.exit(f"stop job permissions {stop.get('permissions')}")
co = next(s for s in check["steps"] if str(s.get("uses", "")).startswith("actions/checkout@"))
if "ref" in (co.get("with") or {}) or (co.get("with") or {}).get("persist-credentials") is not False:
    sys.exit("check must check out main (no ref) without persisted credentials")
run = "\n".join(s.get("run") or "" for s in check["steps"])
for needle in ("release-gate.sh ancestor", "release-gate.sh tag-signature", ".github/revoked_signers"):
    if needle not in run:
        sys.exit(f"check does not run {needle!r}")
if "verdict" not in str(stop.get("if")) or "always()" not in str(stop.get("if")):
    sys.exit("stop must run on any verdict but 'allowed', including a failed check")
srun = "\n".join(s.get("run") or "" for s in stop["steps"])
for needle in ("/cancel", "gh release delete", "exit 1"):
    if needle not in srun:
        sys.exit(f"stop does not {needle!r}")
PY
# Every main commit before the gate carries a release.yml of the name the
# guard watches (it changed only at 99948c6 and at the gate's own commit).
old_name="$(git -C "$root" show 99948c6:.github/workflows/release.yml 2>/dev/null | sed -n 's/^name: //p' | head -n 1)"
[ "$old_name" = "Release" ] && ok "the pre-gate release.yml (99948c6) is named Release, which the guard watches" || bad "99948c6's release.yml is named '${old_name:-?}'"
changes="$(git -C "$root" log --format=%h ad3f7ad9e41e932869a1f68322396b1ef86254f4^ -- .github/workflows/release.yml 2>/dev/null | wc -l)"
[ "$changes" = 1 ] && ok "release.yml changed once before the gate (one pre-gate copy to watch)" || bad "release.yml changed $changes times before the gate"
expect 0 "ruleset-drift.yml: weekly, read-only, GITHUB_TOKEN only" python3 -I - "$root/.github/workflows/ruleset-drift.yml" <<'PY'
import re, sys, yaml
text = open(sys.argv[1]).read()
w = yaml.safe_load(text)
on = w.get(True) or w.get("on")
if not on.get("schedule"):
    sys.exit("no schedule")
perms = [w.get("permissions") or {}] + [j.get("permissions") or {} for j in w["jobs"].values()]
for p in perms:
    if not isinstance(p, dict) or any(v != "read" for v in p.values()):
        sys.exit(f"a permission that is not read: {p}")
if w.get("permissions") != {"contents": "read", "actions": "read"}:
    sys.exit(f"workflow permissions {w.get('permissions')}")
secrets = set(re.findall(r"secrets\.([A-Za-z_]+)", text))
if secrets - {"GITHUB_TOKEN"}:
    sys.exit(f"uses secrets {sorted(secrets)}")
if re.search(r"gh api[^\n]*-X *(POST|PUT|PATCH|DELETE)|--method *(POST|PUT|PATCH|DELETE)", text):
    sys.exit("writes through the API")
if "ruleset-drift.py" not in text:
    sys.exit("does not run ruleset-drift.py")
PY

echo "== test-count.sh per test binary (D2-8)"
TC=(bash "$here/test-count.sh")
cat >"$T/cargo.log" <<'LOG'
     Running unittests src/lib.rs (target/ci-test/deps/graphite_core-0a1b)
test result: ok. 40 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s
     Running tests/alpha.rs (target/ci-test/deps/alpha-1c2d)
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
     Running tests/beta.rs (target/ci-test/deps/beta-3e4f)
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
   Doc-tests graphite_core
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.20s
LOG
: >"$T/allow.txt"
printf '# floor binary\n40 unittests src/lib.rs\n7 tests/alpha.rs\n3 tests/beta.rs\n' >"$T/floors.txt"
expect 0 "the summed floor alone still passes" "${TC[@]}" cargo "$T/cargo.log" 52 "$T/allow.txt"
out="$("${TC[@]}" cargo "$T/cargo.log" 52 "$T/allow.txt" 2>&1)"
grep -q '7 passed  tests/alpha.rs' <<<"$out" && ok "the count of each test binary is printed" || bad "no per-binary table: $out"
expect 0 "every binary at its floor passes" "${TC[@]}" cargo "$T/cargo.log" 52 "$T/allow.txt" "$T/floors.txt"
sed 's/^test result: ok\. 3 passed/test result: ok. 0 passed/' "$T/cargo.log" >"$T/cargo-beta0.log"
sed -i 's/^test result: ok\. 40 passed/test result: ok. 43 passed/' "$T/cargo-beta0.log"
expect 0 "the summed floor misses a binary that fell to 0 while another grew (the D2-8 hole)" "${TC[@]}" cargo "$T/cargo-beta0.log" 52 "$T/allow.txt"
expect 1 "a per-binary floor catches it" "${TC[@]}" cargo "$T/cargo-beta0.log" 52 "$T/allow.txt" "$T/floors.txt"
grep -v 'tests/alpha.rs' "$T/cargo.log" | grep -v '^test result: ok\. 7 passed' >"$T/cargo-noalpha.log"
expect 1 "a listed binary missing from the log fails" "${TC[@]}" cargo "$T/cargo-noalpha.log" 40 "$T/allow.txt" "$T/floors.txt"
expect 1 "a floors file that does not exist fails" "${TC[@]}" cargo "$T/cargo.log" 52 "$T/allow.txt" "$T/no-floors.txt"
printf '# nothing listed\n' >"$T/floors-empty.txt"
expect 1 "a floors file that lists no binary fails (empty is not 'no floor')" "${TC[@]}" cargo "$T/cargo.log" 52 "$T/allow.txt" "$T/floors-empty.txt"
# Round 39: the unlisted-ignored message (rewritten for shellcheck) still names each test.
{ cat "$T/cargo.log"; printf 'test a::one ... ignored\ntest b::two ... ignored, slow\n'; } >"$T/cargo-ign.log"
printf 'a::one  # listed\n' >"$T/allow-one.txt"
out="$("${TC[@]}" cargo "$T/cargo-ign.log" 52 "$T/allow-one.txt" 2>&1)" && bad "an unlisted ignored test passed" || {
  grep -q 'ignored tests not in .*: b::two' <<<"$out" && ! grep -q 'a::one' <<<"$out" \
    && ok "an unlisted ignored test fails, named (the listed one is not)" || bad "unlisted-ignored message: $out"; }

echo "== shellcheck: the CI scripts themselves (Round 39)"
# deploy/tests/run.sh shellchecks deploy/; nothing checked .github/scripts
# (actionlint reads only the workflows' inline run: blocks). shellcheck is on
# the hosted runner image (the deploy job prints its version without installing it).
if command -v shellcheck >/dev/null; then
  expect 0 "shellcheck .github/scripts/*.sh" shellcheck -x "$here"/*.sh
else
  bad "shellcheck is not installed: the CI scripts were not checked (not a pass)"
fi

echo "== Dockerfile: the apt layer is pinned (D-8)"
expect 0 "the runtime image's apt sources are one dated snapshot, recorded in pinned-tools.json" python3 -I - "$root/Dockerfile" "$root/.github/pinned-tools.json" <<'PY'
import json, re, sys
text = open(sys.argv[1]).read()
runtime = text[text.rindex("\nFROM debian:"):]
stamps = set(re.findall(r"snapshot\.debian\.org/archive/debian(?:-security)?/(\d{8}T\d{6}Z)", runtime))
if len(stamps) != 1:
    sys.exit(f"snapshot timestamps in the runtime stage: {sorted(stamps)}")
for needle in ("archive/debian/", "archive/debian-security/", "Check-Valid-Until=false", "/etc/apt/sources.list.d/debian.sources"):
    if needle not in runtime:
        sys.exit(f"the runtime stage lacks {needle!r}")
if "deb.debian.org" in runtime.split("RUN", 1)[1]:
    sys.exit("deb.debian.org is still a source")
apt = [l for l in runtime.splitlines() if "apt-get" in l and not l.lstrip().startswith("#")]
if not apt:
    sys.exit("no apt-get line")
tools = {t["name"]: t for t in json.load(open(sys.argv[2]))["tools"]}
t = tools.get("debian snapshot (runtime image apt layer)") or sys.exit("pinned-tools.json does not list the snapshot")
if t["version"] != next(iter(stamps)):
    sys.exit(f"pinned-tools.json says {t['version']}, the Dockerfile {stamps}")
PY

echo
echo "ci-scripts tests: $pass passed, $fail failed"
[ "$fail" = 0 ]
