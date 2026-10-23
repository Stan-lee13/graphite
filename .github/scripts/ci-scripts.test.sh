#!/usr/bin/env bash
# `A && ok … || bad …` is deliberate: ok always succeeds (SC2015); the
# backticks in single quotes are fixture text, not expansions (SC2016).
# shellcheck disable=SC2015,SC2016
# Tests for the small CI scripts of Round 34: set-rpc-env.sh (D-9),
# pinned-tools.py (R33-20) and check-attestation-commands.py (R33-18).
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
want = {"default": ("", 2322), "lib": ("--no-default-features --lib", 505), "cli": ("--no-default-features --features cli", 1928)}
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

echo
echo "ci-scripts tests: $pass passed, $fail failed"
[ "$fail" = 0 ]
