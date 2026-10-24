#!/usr/bin/env bash
# The console's browser smoke test, end to end (Round 32).
#
# Round 30 wrote dashboard/e2e/smoke.mjs and ran it by hand; nothing in CI
# drew a page. This is what the `dashboard-e2e` job runs, and what a
# contributor runs locally, unchanged:
#
#   1. start the Core binary on loopback, keyed, with a throwaway data
#      directory, and the preview's origin as its only CORS origin;
#   2. seed verdicts through POST /verify (dashboard/e2e/seed.mjs), and
#      refuse to go on unless the trail holds them;
#   3. serve the built console (dashboard/dist, `vite preview`, which sends
#      the production security headers);
#   4. walk every view at desktop and phone width in Chromium, axe included
#      (dashboard/e2e/smoke.mjs).
#
# Usage: .github/scripts/dashboard-e2e.sh <path-to-graphite-binary>
# Expects: dashboard/node_modules and dashboard/dist (npm ci && npm run
# build), and Playwright with its Chromium (dashboard/e2e: npm ci, then
# `npx playwright install chromium`; or PLAYWRIGHT_NODE_PATH naming a
# node_modules directory that holds Playwright).
# Optional: AXE_CORE_PATH (default dashboard/e2e/node_modules/axe-core/axe.min.js;
# axe is not optional — a missing file fails the run), CORE_PORT (7331),
# PREVIEW_PORT (4173).
set -euo pipefail

if [ "$#" -ne 1 ] || [ ! -x "$1" ]; then
  echo "usage: $0 <path-to-graphite-binary>" >&2
  exit 2
fi
bin=$(realpath "$1")
root=$(cd "$(dirname "$0")/../.." && pwd)
core_port=${CORE_PORT:-7331}
preview_port=${PREVIEW_PORT:-4173}
core="http://127.0.0.1:${core_port}"
preview="http://127.0.0.1:${preview_port}"
axe=${AXE_CORE_PATH:-$root/dashboard/e2e/node_modules/axe-core/axe.min.js}
if [ ! -f "$axe" ]; then
  echo "::error::axe-core not found at $axe; the smoke runs with axe or not at all" >&2
  exit 1
fi
if [ ! -f "$root/dashboard/dist/index.html" ]; then
  echo "::error::dashboard/dist is not built (cd dashboard && npm ci && npm run build)" >&2
  exit 1
fi

work=$(mktemp -d)
# A key minted for this run only; it never leaves the runner.
key="e2e-$(od -An -tx1 -N24 /dev/urandom | tr -d ' \n')"
core_pid=""
preview_pid=""
cleanup() {
  status=$?
  for pid in "$preview_pid" "$core_pid"; do
    if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; fi
  done
  if [ "$status" -ne 0 ]; then
    echo "--- Core log"; cat "$work/core.log" 2>/dev/null || true
    echo "--- preview log"; cat "$work/preview.log" 2>/dev/null || true
  fi
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

# The Core runs in the scratch directory, so nothing it writes lands in the
# checkout. GRAPHITE_ALLOW_PERMISSIVE_PROFILES=1 on this throwaway Core only:
# with no RPC and no behavioural evidence nothing reaches a built-in
# profile's floor, and the console must be shown approvals to draw them.
(
  cd "$work"
  exec env GRAPHITE_API_KEY="$key" \
    GRAPHITE_ALLOW_PERMISSIVE_PROFILES=1 \
    GRAPHITE_DATA_DIR="$work/data" \
    GRAPHITE_REGISTRY_STATE="$work/data/registry_state.json" \
    GRAPHITE_CORS_ORIGINS="$preview" \
    "$bin" server --host 127.0.0.1 --port "$core_port"
) >"$work/core.log" 2>&1 &
core_pid=$!

wait_for() {
  local what=$1 url=$2
  for _ in $(seq 1 60); do
    if curl -sf -o /dev/null "$url"; then return 0; fi
    sleep 1
  done
  echo "::error::$what did not answer at $url within 60 s" >&2
  return 1
}
wait_for "the Core" "$core/health"

node "$root/dashboard/e2e/seed.mjs" "$core" "$key"

(
  cd "$root/dashboard"
  exec node node_modules/vite/bin/vite.js preview --host 127.0.0.1 --port "$preview_port" --strictPort
) >"$work/preview.log" 2>&1 &
preview_pid=$!
wait_for "the console preview" "$preview/"

AXE_CORE_PATH="$axe" node "$root/dashboard/e2e/smoke.mjs" "$preview/" "$core" "$key" | tee "$work/smoke.log"
# A green exit is necessary, not sufficient: the summary must say axe ran.
grep -q "clean, axe included$" "$work/smoke.log"

# 5. (Round 36) the same console when the Core does not answer well: 401,
#    500, not JSON, down, a /metrics a proxy answers, a Core that stops
#    mid-session, hostile strings, a change of Core, the connection test
#    (dashboard/e2e/states.mjs puts its own fault proxy in front of the Core).
AXE_CORE_PATH="$axe" node "$root/dashboard/e2e/states.mjs" "$preview/" "$core" "$key" | tee "$work/states.log"
grep -q "clean, axe included$" "$work/states.log"
