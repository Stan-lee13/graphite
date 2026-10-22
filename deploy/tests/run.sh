#!/usr/bin/env bash
# `A && ok … || bad …` is deliberate: ok always succeeds (SC2015); the sh -c
# scripts expand their own positional parameters (SC2016).
# shellcheck disable=SC2015,SC2016
# Validates everything under deploy/ with its own tool, then runs it against a
# real Graphite Core and Caddy on loopback:
#
#   static   shellcheck, caddy validate, promtool check/test, systemd-analyze
#            verify, docker compose config, every dashboard query parsed by
#            promtool and every series it or an alert names exported by
#            server.rs
#   edge     Caddy's route allow-list (404 for /health, /metrics, /admin/*),
#            401 passthrough, 413 over the body limit, HSTS, no Server
#            header, X-Forwarded-For spoofing does not escape the rate limit
#   ops      health-textfile.sh, anchor-checkpoints.sh, backup.sh (hot and
#            cold), restore.sh (lock refusal, checksum, stale-restore refusal,
#            tamper refusal), rotate-keys.sh (env, file, audit key + verify),
#            the compose entrypoint's secret handling
#
#   GRAPHITE_BIN CADDY_BIN PROMTOOL_BIN SHELLCHECK_BIN  default: from PATH
#   (systemd-analyze and docker are used when present, reported when not)
#
# Exit 0 only when every check passed.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
deploy="$(dirname "$here")"
repo="$(dirname "$deploy")"
G="${GRAPHITE_BIN:-graphite}"
C="${CADDY_BIN:-caddy}"
P="${PROMTOOL_BIN:-promtool}"
SC="${SHELLCHECK_BIN:-shellcheck}"
export GRAPHITE_BIN="$G"

pass=0
fail=0
skipped=()
ok() { pass=$((pass + 1)); echo "  ok   $*"; }
bad() { fail=$((fail + 1)); echo "  FAIL $*"; }
check() { # check DESCRIPTION COMMAND...
  local d="$1"
  shift
  if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi
}
expect_rc() { # expect_rc RC DESCRIPTION COMMAND...
  local want="$1" d="$2" rc=0
  shift 2
  "$@" >/dev/null 2>&1 || rc=$?
  if [ "$rc" = "$want" ]; then ok "$d (exit $rc)"; else bad "$d (exit $rc, wanted $want)"; fi
}

# Every path below is under $T: stop here rather than run with it empty.
T="$(mktemp -d)" && [ -n "$T" ] && [ -d "$T" ] || { echo "cannot create a scratch directory" >&2; exit 1; }
pids=()
cleanup() {
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done
  wait 2>/dev/null
  rm -rf "$T"
}
trap cleanup EXIT

port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }

echo "== static"
check "shellcheck deploy/scripts deploy/tests" "$SC" -x "$deploy"/scripts/*.sh "$here"/run.sh
check "caddy validate" env GRAPHITE_SITE=graphite.example.com "$C" validate --config "$deploy/caddy/Caddyfile" --adapter caddyfile
check "caddy fmt (already formatted)" sh -c '"$1" fmt "$2" | cmp -s - "$2"' _ "$C" "$deploy/caddy/Caddyfile"
check "promtool check rules" "$P" check rules "$deploy/prometheus/graphite-alerts.yml"
check "promtool test rules" "$P" test rules "$deploy/prometheus/graphite-alerts.test.yml"
check "promtool check config (syntax)" "$P" check config --syntax-only "$deploy/prometheus/prometheus.example.yml"

# Every PromQL expression on the dashboard, as recording rules promtool parses.
python3 - "$deploy/grafana/graphite-dashboard.json" "$T/dash-rules.yml" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
exprs = [t["expr"] for p in d["panels"] for t in p.get("targets", [])]
with open(sys.argv[2], "w") as f:
    f.write("groups:\n  - name: dashboard\n    rules:\n")
    for i, e in enumerate(exprs):
        e = e.replace("$instance", ".*")
        f.write(f"      - record: dashboard:q{i}\n        expr: {json.dumps(e)}\n")
EOF
check "every dashboard query parses (promtool)" "$P" check rules "$T/dash-rules.yml"

# Every graphite_* series named on the dashboard or in an alert is exported
# by the server (or by health-textfile.sh).
missing="$(cat "$deploy/grafana/graphite-dashboard.json" "$deploy/prometheus/graphite-alerts.yml" |
  grep -o 'graphite_[a-z_]*' | sort -u | while read -r m; do
    case "$m" in graphite_health_degraded | graphite_health_up) continue ;; esac
    grep -q "\"$m\"\|\b$m\b" "$repo/graphite-core/src/server.rs" || echo "$m"
  done)"
if [ -z "$missing" ]; then ok "every series named exists in server.rs"; else bad "series not exported by server.rs: $missing"; fi

if command -v systemd-analyze >/dev/null; then
  mkdir -p "$T/sd"
  for u in graphite.service graphite-anchor.service graphite-anchor.timer; do
    sed 's|^ExecStart=/usr/local/[^ ]*|ExecStart=/bin/true|' "$deploy/systemd/$u" >"$T/sd/$u"
  done
  check "systemd-analyze verify" systemd-analyze verify "$T/sd/graphite.service" "$T/sd/graphite-anchor.service" "$T/sd/graphite-anchor.timer"
  score="$(systemd-analyze security --offline=true "$T/sd/graphite.service" 2>/dev/null | sed -n 's/.*exposure level for graphite.service: \([0-9.]*\).*/\1/p')"
  if [ -n "$score" ] && awk -v s="$score" 'BEGIN{exit !(s < 2)}'; then ok "graphite.service exposure $score < 2"; else bad "graphite.service exposure '$score'"; fi
else
  skipped+=("systemd-analyze not installed")
fi

if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
  check "docker compose config (prod)" env GRAPHITE_IMAGE=ghcr.io/o/graphite-core:0@sha256:0000000000000000000000000000000000000000000000000000000000000000 \
    GRAPHITE_SITE=g.example.com ACME_EMAIL=ops@example.com \
    docker compose -f "$deploy/compose/docker-compose.prod.yml" --profile ai config --quiet
  expect_rc 1 "compose refuses to render without GRAPHITE_IMAGE" env -u GRAPHITE_IMAGE GRAPHITE_SITE=g ACME_EMAIL=a \
    docker compose -f "$deploy/compose/docker-compose.prod.yml" config --quiet
else
  skipped+=("docker compose not installed")
fi

echo "== edge (Caddy in front of a live Core)"
key="$(openssl rand -hex 32)"
rkey="$(openssl rand -hex 32)"
mkdir -p "$T/data" "$T/anchors" "$T/keys" "$T/backups"
chmod 700 "$T/keys"
openssl rand -hex 32 >"$T/keys/audit-1.key"
chmod 600 "$T/keys/audit-1.key"
gport="$(port)"
cport="$(port)"

# The Core is started and stopped through two small scripts, so backup.sh's
# STOP_CMD/START_CMD can drive the same server the test does.
mk_start() { # mk_start AUDIT_KEY_FILE -> $T/start.sh
  cat >"$T/start.sh" <<EOF
#!/usr/bin/env bash
GRAPHITE_API_KEY='$key' GRAPHITE_READ_API_KEY='$rkey' GRAPHITE_DATA_DIR='$T/data' \\
  GRAPHITE_REGISTRY_STATE='$T/data/registry_state.json' \\
  GRAPHITE_AUDIT_KEY_FILE='$1' GRAPHITE_AUDIT_ANCHOR_DIR='$T/anchors' \\
  GRAPHITE_AUDIT_ROTATE_BYTES=4096 GRAPHITE_TRUST_PROXY=1 GRAPHITE_RATE_LIMIT=5 \\
  GRAPHITE_WALLET_PROFILE=treasury RUST_LOG=warn \\
  '$G' server --host 127.0.0.1 --port $gport >>'$T/core.log' 2>&1 &
echo \$! >'$T/core.pid'
for _ in \$(seq 1 100); do
  curl -fsS 'http://127.0.0.1:$gport/health' >/dev/null 2>&1 && exit 0
  sleep 0.1
done
echo "core did not start:" >&2
tail -20 '$T/core.log' >&2
exit 1
EOF
  chmod +x "$T/start.sh"
}
cat >"$T/stop.sh" <<EOF
#!/usr/bin/env bash
p="\$(cat '$T/core.pid')"
kill "\$p" 2>/dev/null
for _ in \$(seq 1 300); do kill -0 "\$p" 2>/dev/null || exit 0; sleep 0.1; done
exit 1
EOF
chmod +x "$T/stop.sh"
start_core() { # start_core AUDIT_KEY_FILE
  mk_start "$1"
  "$T/start.sh" || return 1
  pids+=("$(cat "$T/core.pid")")
}
stop_core() { "$T/stop.sh"; }
verify_n() { # verify_n N  — N verifications straight to the Core (no proxy)
  local i
  for i in $(seq 1 "$1"); do
    curl -fsS -o /dev/null -H "Authorization: Bearer $key" -H 'Content-Type: application/json' \
      --data-binary @"$repo/examples/verify-input.json" "http://127.0.0.1:$gport/verify" || return 1
    sleep 0.21 # under the 5/s per-IP limit
  done
}

check "core starts with a keyed trail and an anchor dir" start_core "$T/keys/audit-1.key"

GRAPHITE_SITE="http://127.0.0.1:$cport" GRAPHITE_UPSTREAM="127.0.0.1:$gport" \
  XDG_DATA_HOME="$T/caddy" XDG_CONFIG_HOME="$T/caddy" \
  "$C" run --config "$deploy/caddy/Caddyfile" --adapter caddyfile >"$T/caddy.log" 2>&1 &
pids+=("$!")
for _ in $(seq 1 100); do curl -s -o /dev/null "http://127.0.0.1:$cport/" && break; sleep 0.1; done
E="http://127.0.0.1:$cport"

code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
for r in "GET /health" "GET /metrics" "GET /admin/quarantine" "POST /admin/quarantine" "GET /verify" "GET /" "DELETE /api/graph"; do
  read -r m pth <<<"$r"
  c="$(code -X "$m" -H "Authorization: Bearer $key" "$E$pth")"
  if [ "$c" = 404 ]; then ok "edge: $r -> 404"; else bad "edge: $r -> $c (wanted 404)"; fi
done
c="$(code -X POST -H 'Content-Type: application/json' --data-binary @"$repo/examples/verify-input.json" "$E/verify")"
[ "$c" = 401 ] && ok "edge: POST /verify without a key -> 401 from the Core" || bad "edge: POST /verify without key -> $c"
c="$(code -X POST -H "Authorization: Bearer $key" -H 'Content-Type: application/json' --data-binary @"$repo/examples/verify-input.json" "$E/verify")"
[ "$c" = 200 ] && ok "edge: POST /verify with the key -> 200" || bad "edge: POST /verify with key -> $c"
c="$(code -H "Authorization: Bearer $rkey" "$E/api/graph")"
[ "$c" = 200 ] && ok "edge: GET /api/graph with the read key -> 200" || bad "edge: GET /api/graph -> $c"
c="$(code -H "Authorization: Bearer $rkey" "$E/manifests")"
[ "$c" = 200 ] && ok "edge: GET /manifests with the read key -> 200" || bad "edge: GET /manifests -> $c"
head -c 1100000 /dev/zero | tr '\0' 'a' >"$T/big.json"
c="$(code -X POST -H "Authorization: Bearer $key" -H 'Content-Type: application/json' --data-binary @"$T/big.json" "$E/verify")"
[ "$c" = 413 ] && ok "edge: 1.1 MB body -> 413" || bad "edge: 1.1 MB body -> $c"
# Caddy's own limit, measured against an upstream that accepts any body: the
# Core enforces 1 MiB too, so only this shows the edge does.
cat >"$T/sink.py" <<'EOF'
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.send_response(200); self.send_header("Content-Length", "0"); self.end_headers()
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
EOF
sport="$(port)"
s2port="$(port)"
python3 -I "$T/sink.py" "$sport" 2>/dev/null &
pids+=("$!")
GRAPHITE_SITE="http://127.0.0.1:$s2port" GRAPHITE_UPSTREAM="127.0.0.1:$sport" \
  XDG_DATA_HOME="$T/caddy2" XDG_CONFIG_HOME="$T/caddy2" \
  "$C" run --config "$deploy/caddy/Caddyfile" --adapter caddyfile >"$T/caddy2.log" 2>&1 &
pids+=("$!")
for _ in $(seq 1 100); do curl -s -o /dev/null "http://127.0.0.1:$s2port/" && break; sleep 0.1; done
head -c 1048576 /dev/zero | tr '\0' 'a' >"$T/1mib"
printf 'a' | cat "$T/1mib" - >"$T/1mib1"
c="$(code -X POST --data-binary @"$T/1mib" "http://127.0.0.1:$s2port/verify")"
[ "$c" = 200 ] && ok "edge: exactly 1 MiB passes Caddy" || bad "edge: exactly 1 MiB through Caddy -> $c"
c="$(code -X POST --data-binary @"$T/1mib1" "http://127.0.0.1:$s2port/verify")"
[ "$c" = 413 ] && ok "edge: 1 MiB + 1 byte -> 413 from Caddy itself" || bad "edge: 1 MiB + 1 through Caddy -> $c"

hdr="$(curl -s -D - -o /dev/null -X POST "$E/verify")"
grep -qi '^strict-transport-security: max-age=63072000' <<<"$hdr" && ok "edge: HSTS header" || bad "edge: no HSTS header"
grep -qi '^server:' <<<"$hdr" && bad "edge: Server header present (proxied)" || ok "edge: no Server header (proxied)"
# Caddy's own answers carry `Server: Caddy` unless the Caddyfile removes it.
hdr404="$(curl -s -D - -o /dev/null "$E/no-such-route")"
grep -qi '^server:' <<<"$hdr404" && bad "edge: Server header present (edge 404)" || ok "edge: no Server header (edge 404)"
# A client rotating X-Forwarded-For still hits its own rate limit: Caddy
# replaces the header (no trusted_proxies), so the Core sees one address.
sleep 1.1
limited=0
for i in $(seq 1 25); do
  c="$(code -X POST -H "X-Forwarded-For: 10.0.$i.$i" -H "Authorization: Bearer $key" -H 'Content-Type: application/json' \
    --data-binary @"$repo/examples/verify-input.json" "$E/verify")"
  [ "$c" = 429 ] && limited=$((limited + 1))
done
[ "$limited" -gt 0 ] && ok "edge: spoofed X-Forwarded-For still rate limited ($limited/25 got 429)" || bad "edge: X-Forwarded-For rotation escaped the rate limit"
sleep 1.1

echo "== ops scripts"
check "write verdicts (rotation at 4 KiB)" verify_n 12
ls "$T/data"/audit.jsonl.* >/dev/null 2>&1 && ok "audit rotated into archives" || bad "no audit archive after 12 verdicts"
ls "$T/anchors"/audit.jsonl-checkpoint-*.json >/dev/null 2>&1 && ok "server wrote rotation checkpoints to the anchor dir" || bad "no rotation checkpoint"

mkdir -p "$T/textfile"
check "health-textfile.sh" env TEXTFILE_DIR="$T/textfile" GRAPHITE_HEALTH_URL="http://127.0.0.1:$gport/health" "$deploy/scripts/health-textfile.sh"
grep -qx 'graphite_health_up 1' "$T/textfile/graphite_health.prom" && ok "textfile: up 1" || bad "textfile: up not 1"
[ "$(grep -c '^graphite_health_degraded{reason=".*"} 0$' "$T/textfile/graphite_health.prom")" = 6 ] && ok "textfile: six reasons, all 0" || bad "textfile: reasons wrong"
check "textfile output parses (promtool check metrics)" sh -c "\"$P\" check metrics <\"$T/textfile/graphite_health.prom\""
env TEXTFILE_DIR="$T/textfile" GRAPHITE_HEALTH_URL="http://127.0.0.1:1/health" "$deploy/scripts/health-textfile.sh" >/dev/null 2>&1
grep -qx 'graphite_health_up 0' "$T/textfile/graphite_health.prom" && ! grep -q degraded "$T/textfile/graphite_health.prom" &&
  ok "textfile: unreachable -> up 0, no stale reasons" || bad "textfile: unreachable case"

A=(env GRAPHITE_DATA_DIR="$T/data" GRAPHITE_AUDIT_ANCHOR_DIR="$T/anchors" GRAPHITE_AUDIT_KEY_FILE="$T/keys/audit-1.key" "$deploy/scripts/anchor-checkpoints.sh")
hs="$("$G" audit verify --data-dir "$T/data" --key-file "$T/keys/audit-1.key" --json 2>/dev/null | jq -r .head_seq)"
base="$T/anchors/$(printf 'audit.jsonl-checkpoint-%020d' "$hs")"
had_server=0
[ -e "$base.json" ] && had_server=1
check "anchor-checkpoints.sh beside the running server" "${A[@]}"
if [ "$had_server" = 1 ]; then
  [ ! -e "$base-scheduled.json" ] && ok "anchor: head already anchored by a rotation checkpoint; no duplicate" || bad "anchor: duplicated the server's checkpoint"
  head_cp="$base.json"
else
  [ -e "$base-scheduled.json" ] && ok "anchor: scheduled checkpoint for head seq $hs" || bad "anchor: no checkpoint for head seq $hs"
  head_cp="$base-scheduled.json"
fi
n1="$(find "$T/anchors" -name 'audit.jsonl-checkpoint-*' | wc -l)"
"${A[@]}" >/dev/null 2>&1
n2="$(find "$T/anchors" -name 'audit.jsonl-checkpoint-*' | wc -l)"
[ "$n1" = "$n2" ] && ok "anchor: nothing added when nothing changed" || bad "anchor: $n1 then $n2 checkpoints"
expect_rc 0 "the head checkpoint verifies against the live trail" "$G" audit verify --data-dir "$T/data" --key-file "$T/keys/audit-1.key" --checkpoint "$head_cp"
# Force the scheduled path too: one more verdict moves the head past any
# rotation checkpoint unless that verdict itself rotated.
check "one more verdict" verify_n 1
hs2="$("$G" audit verify --data-dir "$T/data" --key-file "$T/keys/audit-1.key" --json 2>/dev/null | jq -r .head_seq)"
base2="$T/anchors/$(printf 'audit.jsonl-checkpoint-%020d' "$hs2")"
check "anchor-checkpoints.sh after a new verdict" "${A[@]}"
[ -e "$base2-scheduled.json" ] || [ -e "$base2.json" ] && ok "anchor: head seq $hs2 anchored" || bad "anchor: head seq $hs2 not anchored"
[ -e "$base2-scheduled.json" ] && [ -e "$base2.json" ] && bad "anchor: both names for seq $hs2" || ok "anchor: never both names for one seq"

check "backup.sh --hot while serving" "$deploy/scripts/backup.sh" --hot --key-file "$T/keys/audit-1.key" "$T/data" "$T/backups"
hot="$(find "$T/backups" -name 'graphite-*.tar.gz' | head -n 1)"
check "hot backup checksum" sh -c "cd \"$T/backups\" && sha256sum -c \"${hot##*/}.sha256\""
tar -tzf "$hot" | grep -q 'lock' && bad "backup contains lock files" || ok "backup leaves out lock files"
expect_rc 1 "backup.sh refuses a cold backup without STOP_CMD/START_CMD" "$deploy/scripts/backup.sh" "$T/data" "$T/backups"
sleep 1.1
expect_rc 75 "backup.sh refuses a cold copy when STOP_CMD did not stop the server" env STOP_CMD=true START_CMD=true \
  "$deploy/scripts/backup.sh" --key-file "$T/keys/audit-1.key" "$T/data" "$T/backups"

# Cold: backup.sh stops and restarts this test's server ($T/start.sh still
# names audit-1.key).
sleep 1.1
check "backup.sh cold (stop, copy, start)" env STOP_CMD="$T/stop.sh" START_CMD="$T/start.sh" \
  "$deploy/scripts/backup.sh" --key-file "$T/keys/audit-1.key" "$T/data" "$T/backups"
pids+=("$(cat "$T/core.pid")")
check "server is serving again after the cold backup" curl -fsS "http://127.0.0.1:$gport/health"
cold="$(find "$T/backups" -name 'graphite-*.tar.gz' -newer "$hot" | head -n 1)"
[ -n "$cold" ] || cold="$hot"

# Newer verdicts and a newer checkpoint, so the backup is now stale.
check "more verdicts after the backup" verify_n 4
check "anchor a checkpoint newer than the backup" "${A[@]}"

expect_rc 75 "restore.sh refuses while the server holds the lock" "$deploy/scripts/restore.sh" "$cold" "$T/data"
check "stop the server" stop_core

cp "$cold" "$T/nosum.tar.gz"
expect_rc 66 "restore.sh refuses an archive without its .sha256" "$deploy/scripts/restore.sh" "$T/nosum.tar.gz" "$T/data"
cp "$cold" "$T/corrupt.tar.gz"
(cd "$(dirname "$cold")" && sha256sum "${cold##*/}") | sed "s|${cold##*/}|corrupt.tar.gz|" >"$T/corrupt.tar.gz.sha256"
printf 'x' | dd of="$T/corrupt.tar.gz" bs=1 seek=100 conv=notrunc 2>/dev/null
expect_rc 1 "restore.sh refuses an archive that fails its checksum" "$deploy/scripts/restore.sh" "$T/corrupt.tar.gz" "$T/data"

# A tampered trail, packed as a well-formed archive with a matching checksum.
mkdir -p "$T/tamper"
tar -C "$T/tamper" -xzf "$cold"
python3 - "$T/tamper" <<'EOF'
import glob, os, sys
d = sys.argv[1]
# The largest file (the active one can be empty right after a rotation).
f = max(glob.glob(os.path.join(d, "audit.jsonl*")), key=os.path.getsize)
lines = open(f).read().splitlines(keepends=True)
i = len(lines) // 2
lines[i] = lines[i].replace("\"Approved\"", "\"Blocked\"", 1) if "\"Approved\"" in lines[i] else lines[i].replace("2", "3", 1)
open(f, "w").write("".join(lines))
EOF
tar -C "$T/tamper" -czf "$T/tampered.tar.gz" .
(cd "$T" && sha256sum tampered.tar.gz >tampered.tar.gz.sha256)
expect_rc 1 "restore.sh refuses a tampered trail (audit verify fails)" \
  "$deploy/scripts/restore.sh" --key-file "$T/keys/audit-1.key" "$T/tampered.tar.gz" "$T/data"
# Refused before anything moved: the live directory was never set aside.
ls -d "$T"/data.pre-restore-* >/dev/null 2>&1 && bad "a refused restore moved the data directory" || ok "refused restores left the data directory in place"
expect_rc 1 "backup.sh keeps no backup of a trail that does not verify" \
  "$deploy/scripts/backup.sh" --hot --key-file "$T/keys/audit-1.key" "$T/tamper" "$T/backups-bad"
[ -z "$(find "$T/backups-bad" -name '*.tar.gz' 2>/dev/null)" ] && ok "no archive left behind for the broken trail" || bad "an archive of a broken trail was kept"
expect_rc 0 "the live data still verifies after the refused restores" "$G" audit verify --data-dir "$T/data" --key-file "$T/keys/audit-1.key"

expect_rc 1 "restore.sh refuses a stale restore against the newest anchored checkpoint" \
  "$deploy/scripts/restore.sh" --key-file "$T/keys/audit-1.key" --anchor-dir "$T/anchors" "$cold" "$T/data"
expect_rc 0 "restore.sh with ACCEPT_STALE_RESTORE=1" env ACCEPT_STALE_RESTORE=1 \
  "$deploy/scripts/restore.sh" --key-file "$T/keys/audit-1.key" --anchor-dir "$T/anchors" "$cold" "$T/data"
ls -d "$T"/data.pre-restore-* >/dev/null 2>&1 && ok "previous data directory kept aside" || bad "previous data directory not kept"
expect_rc 1 "the restored (older) trail fails the newer checkpoint, as it should" \
  "$G" audit verify --data-dir "$T/data" --key-file "$T/keys/audit-1.key" --checkpoint "$(find "$T/anchors" -name 'audit.jsonl-checkpoint-*' | LC_ALL=C sort | tail -n 1)"
check "server starts on the restored directory" start_core "$T/keys/audit-1.key"

echo "== key rotation"
check "rotate-keys.sh audit-key" "$deploy/scripts/rotate-keys.sh" audit-key "$T/keys"
newkey="$(find "$T/keys" -name 'audit-2*.key' | head -n 1)"
[ "$(stat -c %a "$newkey")" = 600 ] && ok "new audit key is mode 600" || bad "new audit key mode $(stat -c %a "$newkey")"
check "stop for the key switch" stop_core
check "server starts under the new audit key" start_core "$newkey"
check "verdicts under the new key" verify_n 2
expect_rc 0 "rotate-keys.sh verify with old + new keys" "$deploy/scripts/rotate-keys.sh" verify "$T/data" "$T/keys/audit-1.key" "$newkey"
expect_rc 2 "rotate-keys.sh verify with the new key only -> unprovable" "$deploy/scripts/rotate-keys.sh" verify "$T/data" "$newkey"

printf 'A=1\nGRAPHITE_API_KEY=old\n# c\nGRAPHITE_READ_API_KEY=r\n' >"$T/test.env"
check "rotate-keys.sh env" "$deploy/scripts/rotate-keys.sh" env "$T/test.env" GRAPHITE_API_KEY
grep -Eq '^GRAPHITE_API_KEY=[0-9a-f]{64}$' "$T/test.env" && grep -qx 'A=1' "$T/test.env" && grep -qx 'GRAPHITE_READ_API_KEY=r' "$T/test.env" &&
  ok "env: key replaced, other lines unchanged" || bad "env file rewritten wrongly"
[ "$(stat -c %a "$T/test.env")" = 600 ] && ok "env: file mode 600" || bad "env: mode $(stat -c %a "$T/test.env")"
ls "$T"/test.env.2* >/dev/null 2>&1 && ok "env: previous file kept" || bad "env: previous file not kept"
expect_rc 64 "rotate-keys.sh env refuses a non-key variable" "$deploy/scripts/rotate-keys.sh" env "$T/test.env" GRAPHITE_RPC_URL
"$deploy/scripts/rotate-keys.sh" file "$T/keys/api_key" >/dev/null 2>&1
grep -Eqx '[0-9a-f]{64}' "$T/keys/api_key" && ok "rotate-keys.sh file" || bad "rotate-keys.sh file"
if "$deploy/scripts/rotate-keys.sh" env "$T/test.env" GRAPHITE_API_KEY 2>&1 | grep -Eq '[0-9a-f]{64}'; then bad "a secret was printed"; else ok "no secret printed"; fi

echo "== compose entrypoint"
# The Core's entrypoint script from the prod compose file, run against a
# fake /run/secrets: keys exported, an empty admin key leaves /admin/* off.
python3 - "$deploy/compose/docker-compose.prod.yml" "$T/entry.sh" "$T/secrets" <<'EOF'
import sys, yaml
c = yaml.safe_load(open(sys.argv[1]))
script = c["services"]["graphite"]["entrypoint"][2].replace("$$", "$")
script = script.replace("/run/secrets", sys.argv[3])
script = script.replace("exec graphite server --host 0.0.0.0 --port 7331", "exec env")
open(sys.argv[2], "w").write(script)
EOF
mkdir -p "$T/secrets"
echo aaaa >"$T/secrets/api_key"
echo rrrr >"$T/secrets/read_api_key"
: >"$T/secrets/admin_api_key"
out="$(env -i PATH="$PATH" sh -ec "$(cat "$T/entry.sh")")"
grep -qx GRAPHITE_API_KEY=aaaa <<<"$out" && grep -qx GRAPHITE_READ_API_KEY=rrrr <<<"$out" && ! grep -q '^GRAPHITE_ADMIN_API_KEY=' <<<"$out" && ! grep -q '^admin=' <<<"$out" &&
  ok "entrypoint: keys from secrets; empty admin key -> unset" || bad "entrypoint (empty admin)"
echo kkkk >"$T/secrets/admin_api_key"
out="$(env -i PATH="$PATH" sh -ec "$(cat "$T/entry.sh")")"
grep -qx GRAPHITE_ADMIN_API_KEY=kkkk <<<"$out" && ok "entrypoint: admin key exported when set" || bad "entrypoint (admin)"
rm "$T/secrets/api_key"
if env -i PATH="$PATH" sh -ec "$(cat "$T/entry.sh")" >/dev/null 2>&1; then bad "entrypoint ran without the api_key secret"; else ok "entrypoint: missing api_key secret -> refuses"; fi

echo
if [ "${#skipped[@]}" -gt 0 ]; then printf '  skipped: %s\n' "${skipped[@]}"; fi
echo "deploy tests: $pass passed, $fail failed"
[ "$fail" = 0 ]
