#!/usr/bin/env bash
# Reads a test run's log and fails unless it shows at least MIN passing tests
# and nothing failed, cancelled or left as todo (Round 30).
#
#   test-count.sh cargo  <log> <min> <ignored-allowlist-file> [per-binary-floors]
#   test-count.sh tap    <log> <min> [max-skipped]      (default 0)
#   test-count.sh go     <log> <min>                    (any skip fails)
#   test-count.sh pytest <log> <min> [max-skipped]      (default 0)
#
# Skips are failures unless allowed explicitly: a cargo `#[ignore]` must be
# named in the committed allowlist, a node:test skip/todo or a pytest skip
# must be within the stated maximum, a Go `t.Skip` always fails.
#
# A green exit status is necessary, not sufficient. Every runner here exits 0
# when it finds no tests (`cargo test` with a filter that matches nothing, a
# `node --test` glob that matches no file, `go test` on a package with no test
# file), so a renamed directory, a broken glob or a test file that stopped
# being picked up turned a gate into a no-op with a green tick. MIN is a floor,
# not an exact count: adding tests never needs an edit here; removing tests
# below the floor does, in a reviewed diff that says why.
#
# cargo, per test binary (Round 38, D2-8). MIN is a sum over every test
# binary, so a binary that stopped running (a file whose tests were cfg'd
# out, a target dropped from the build) is hidden by growth in another. The
# count of each binary is always printed; given a floors file (lines
# `<floor> <binary>`, the binary as cargo names it: `unittests src/lib.rs`,
# `tests/foo.rs`, `doc-tests graphite_core`), every listed binary must be in
# the log with at least its floor. A floors file that is missing or lists
# nothing fails: an empty list is not "no floor". A binary not listed is
# reported, not failed (adding a test file needs no edit here).
set -euo pipefail

format=${1:?format}; log=${2:?log}; min=${3:?min}; max_skipped=${4:-0}
[ -s "$log" ] || { echo "::error::test log $log is missing or empty"; exit 1; }

fail() { echo "::error::$*"; exit 1; }

case "$format" in
  cargo)
    # Round 40: CI runs cargo with CARGO_TERM_COLOR=always, which colours the
    # `Running X (path)` status lines; read a copy with the ANSI escapes
    # removed, or every binary's name is lost.
    plain=$(mktemp)
    trap 'rm -f "$plain"' EXIT
    sed -E $'s/\x1b\\[[0-9;]*[A-Za-z]//g' "$log" >"$plain"
    log=$plain
    # One `test result:` line per test binary (unit, integration, doc).
    passed=$(sed -n -E 's/^test result: (ok|FAILED)\. ([0-9]+) passed.*/\2/p' "$log" | awk '{s+=$1} END {print s+0}')
    failed=$(sed -n -E 's/^test result: [A-Za-z]+\. [0-9]+ passed; ([0-9]+) failed.*/\1/p' "$log" | awk '{s+=$1} END {print s+0}')
    binaries=$(grep -c '^test result:' "$log" || true)
    [ "$binaries" -ge 1 ] || fail "no 'test result:' line in $log: no test binary ran"
    [ "$failed" = "0" ] || fail "$failed tests failed"
    # An `#[ignore]`d test passes `cargo test` silently. Each one that runs
    # ignored must be named in the committed allowlist (the 4th argument),
    # so a new #[ignore] fails here until it is listed in a reviewed diff.
    allow=${4:-}
    [ -n "$allow" ] || fail "cargo: pass the ignored-tests allowlist file"
    [ -f "$allow" ] || fail "ignored-tests allowlist $allow is missing"
    unlisted=$(sed -n -E 's/^test (\S+) \.\.\. ignored.*/\1/p' "$log" | sort -u \
      | comm -23 - <(sed -e 's/#.*//' -e 's/[[:space:]]*$//' "$allow" | grep -v '^$' | sort -u))
    [ -z "$unlisted" ] || fail "ignored tests not in $allow: $(tr '\n' ' ' <<<"$unlisted")"
    # Each `test result:` belongs to the `Running X (path)` / `Doc-tests X`
    # line before it.
    per_binary=$(awk '
      /^ *Running / { b = $0; sub(/^ *Running /, "", b); sub(/ \(.*\)$/, "", b); next }
      /^ *Doc-tests / { b = $0; sub(/^ *Doc-tests /, "doc-tests ", b); next }
      /^test result: / { n = $0; sub(/^test result: [A-Za-z]+\. /, "", n); sub(/ passed.*/, "", n); print n "\t" (b == "" ? "?" : b); b = "" }
    ' "$log")
    echo "per test binary:"
    printf '%s\n' "$per_binary" | awk -F'\t' '{ printf "  %6d passed  %s\n", $1, $2 }'
    floors=${5:-}
    if [ -n "$floors" ]; then
      [ -f "$floors" ] || fail "per-binary floors $floors is missing"
      listed=0
      while IFS= read -r line; do
        line="${line%%#*}"
        [ -n "${line//[[:space:]]/}" ] || continue
        f_min="${line%% *}" f_bin="${line#* }"
        if ! [[ "$f_min" =~ ^[0-9]+$ ]] || [ -z "$f_bin" ] || [ "$f_bin" = "$line" ]; then
          fail "per-binary floors $floors: bad line '$line'"
        fi
        listed=$((listed + 1))
        got=$(printf '%s\n' "$per_binary" | awk -F'\t' -v b="$f_bin" '$2 == b { print $1; n++ } END { if (n != 1) print "x" n }' | tail -n 1)
        case "$got" in
          x0) fail "test binary '$f_bin' (floor $f_min) did not run" ;;
          x*) fail "test binary '$f_bin' ran more than once" ;;
        esac
        [ "$got" -ge "$f_min" ] || fail "test binary '$f_bin': $got passed, below its floor of $f_min"
      done <"$floors"
      [ "$listed" -ge 1 ] || fail "per-binary floors $floors lists no binary"
      echo "per-binary floors ok: $listed binaries at or above their floors"
    fi
    ;;
  tap)
    # node:test's TAP summary; the last one is the run's total.
    tapv() { sed -n -E "s/^# $1 ([0-9]+)$/\1/p" "$log" | tail -n 1; }
    passed=$(tapv pass); tests=$(tapv tests)
    [ -n "$tests" ] || fail "no TAP summary in $log (is the reporter tap?)"
    for k in fail cancelled todo; do
      [ "$(tapv "$k")" = "0" ] || fail "TAP '# $k' is '$(tapv "$k")', expected 0"
    done
    skipped=$(tapv skipped)
    [ "${skipped:-0}" -le "$max_skipped" ] || fail "$skipped tests skipped, at most $max_skipped allowed"
    ;;
  go)
    # Top-level test functions only (subtests are indented).
    passed=$(grep -c -E '^--- PASS: ' "$log" || true)
    if grep -qE '^\s*--- (FAIL|SKIP): ' "$log"; then
      fail "a Go test failed or was skipped"
    fi
    ;;
  pytest)
    # `-q`'s last line: "44 passed in 0.31s" or "1 failed, 43 passed in …".
    summary=$(grep -E '^(=+ )?[0-9]+ (passed|failed|error)' "$log" | tail -n 1)
    [ -n "$summary" ] || fail "no pytest summary line in $log"
    passed=$(echo "$summary" | sed -n -E 's/.*\b([0-9]+) passed.*/\1/p'); passed=${passed:-0}
    if echo "$summary" | grep -qE '[0-9]+ (failed|error)'; then fail "pytest: $summary"; fi
    skipped=$(echo "$summary" | sed -n -E 's/.*\b([0-9]+) (skipped|xfailed|deselected).*/\1/p'); skipped=${skipped:-0}
    [ "$skipped" -le "$max_skipped" ] || fail "pytest: $skipped skipped/xfailed/deselected, at most $max_skipped allowed: $summary"
    ;;
  *) fail "unknown format $format" ;;
esac

[ "$passed" -ge "$min" ] || fail "$passed tests passed, below the floor of $min: tests were removed or stopped running"
echo "test count ok: $passed passed (floor $min)"
