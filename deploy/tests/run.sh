#!/usr/bin/env bash
# `A && ok … || bad …` is deliberate: ok always succeeds (SC2015); the sh -c
# scripts expand their own positional parameters (SC2016).
# shellcheck disable=SC2015,SC2016
# Validates everything under deploy/ with its own tool, then runs it against a
# real Graphite Core and Caddy on loopback:
#
#   static   shellcheck, caddy validate, promtool check/test (every alert
#            with a case that fires and one that does not), systemd-analyze
#            verify and exposure of both services, docker compose config, the
#            compose and Dockerfile hardening (one Core replica, non-root,
#            read-only, no capabilities, images pinned by digest, no secret in
#            the environment), every dashboard query parsed by promtool and
#            every series it or an alert names exported by server.rs
#   edge     Caddy's route allow-list (404 for /health, /metrics, /admin/*),
#            401 passthrough, 413 over the body limit, HSTS, no Server
#            header, X-Forwarded-For spoofing does not escape the rate limit,
#            no admin API
#   ops      a second Core (and a writing CLI) on the live data directory
#            refused, health-textfile.sh, anchor-checkpoints.sh, backup.sh (hot
#            and cold, the archive MAC), restore.sh (lock refusal, --anchor-dir
#            required, checksum naming the archive, MAC refusals, stale-restore
#            refusal, tamper refusal), rotate-keys.sh (env, file, audit key +
#            verify; owner and mode kept across a rotation, as root or with
#            passwordless sudo), a lost audit key (adopt-key, then backup and
#            restore with --lost-key), the compose entrypoint's secret handling
#   failure  SIGTERM with a verdict in flight (answered, recorded, exit 0);
#            the data directory full during audit appends (a 256 KiB tmpfs in
#            an unprivileged user+mount namespace: every verdict either on the
#            trail or refused 503, never answered unrecorded)
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
check "shellcheck deploy/scripts deploy/tests" "$SC" -x "$deploy"/scripts/*.sh "$here"/run.sh "$here"/*.test.sh
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
  # Round 36: the anchor unit holds the audit key and the S3 credentials too;
  # it scored 1.7 with half the server's sandbox.
  score="$(systemd-analyze security --offline=true "$T/sd/graphite-anchor.service" 2>/dev/null | sed -n 's/.*exposure level for graphite-anchor.service: \([0-9.]*\).*/\1/p')"
  if [ -n "$score" ] && awk -v s="$score" 'BEGIN{exit !(s < 1.5)}'; then ok "graphite-anchor.service exposure $score < 1.5"; else bad "graphite-anchor.service exposure '$score' (wanted < 1.5)"; fi
else
  skipped+=("systemd-analyze not installed")
fi
# One Core per host: a plain unit, never an instance template (F-019).
[ -z "$(find "$deploy/systemd" -name '*@.service')" ] && grep -q 'ONE instance' "$deploy/systemd/graphite.service" &&
  ok "systemd: one graphite.service, no instance template" || bad "systemd: an instance template (graphite@.service) or no single-instance note"

# Round 36: every alert has a promtool case where it fires and one where it
# does not (11 of 19 had neither).
untested="$(python3 - "$deploy/prometheus/graphite-alerts.yml" "$deploy/prometheus/graphite-alerts.test.yml" <<'EOF'
import sys, yaml
rules = yaml.safe_load(open(sys.argv[1]))
alerts = {r["alert"] for g in rules["groups"] for r in g["rules"] if "alert" in r}
fires, quiet = set(), set()
for t in yaml.safe_load(open(sys.argv[2]))["tests"]:
    for a in t.get("alert_rule_test", []):
        (fires if a.get("exp_alerts") else quiet).add(a["alertname"])
print(" ".join(sorted((alerts - fires) | (alerts - quiet))))
EOF
)"
[ -z "$untested" ] && ok "every alert has a firing and a quiet promtool case" || bad "alerts without a firing and a quiet promtool case: $untested"

# The production compose file and the Dockerfile, read as data: what must stay
# true of them whatever docker is installed.
compose_audit() { # compose_audit WHAT -> prints the violations of WHAT
  python3 - "$deploy/compose/docker-compose.prod.yml" "$repo/Dockerfile" "$1" <<'EOF'
import re, sys, yaml
c = yaml.safe_load(open(sys.argv[1]))
svcs, what, out = c["services"], sys.argv[3], []
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
if what == "replicas":
    # The production file and the build-from-source one at the root alike.
    for f in (sys.argv[1], sys.argv[2].replace("Dockerfile", "docker-compose.yml")):
        g = yaml.safe_load(open(f))["services"]["graphite"]
        if not g.get("container_name"): out.append(f"{f}: graphite has no container_name (replicas > 1 render)")
        if (g.get("deploy") or {}).get("replicas") != 1: out.append(f"{f}: graphite deploy.replicas is not 1")
        if "scale" in g: out.append(f"{f}: graphite sets scale")
elif what == "hardening":
    for n, s in svcs.items():
        if s.get("read_only") is not True: out.append(f"{n}: not read_only")
        if s.get("cap_drop") != ["ALL"]: out.append(f"{n}: cap_drop is not [ALL]")
        if set(s.get("cap_add") or []) - ({"NET_BIND_SERVICE"} if n == "caddy" else set()): out.append(f"{n}: cap_add {s.get('cap_add')}")
        if "no-new-privileges:true" not in (s.get("security_opt") or []): out.append(f"{n}: no no-new-privileges")
        if s.get("privileged") or s.get("network_mode") == "host" or s.get("pid") == "host" or s.get("ipc") == "host": out.append(f"{n}: host namespace or privileged")
        if any("docker.sock" in str(v) for v in s.get("volumes") or []): out.append(f"{n}: mounts the docker socket")
        if n != "caddy" and (s.get("ports") or s.get("network_mode")): out.append(f"{n}: publishes ports")
        if n != "caddy" and str(s.get("user", "")).split(":")[0] in ("", "0", "root"): out.append(f"{n}: runs as root")
elif what == "digests":
    for n, s in svcs.items():
        img = s.get("image", "")
        if n == "graphite":
            if not re.search(r"@\$\{GRAPHITE_IMAGE_DIGEST:\?[^}]*\}$", img): out.append(f"graphite image {img!r} does not require GRAPHITE_IMAGE_DIGEST")
        elif not DIGEST.search(img): out.append(f"{n} image {img!r} is not pinned by digest")
    stages = set()
    for line in open(sys.argv[2]):
        m = re.match(r"FROM\s+(\S+)(?:\s+AS\s+(\S+))?", line, re.I)
        if not m: continue
        ref = m.group(1)
        if not (ref == "scratch" or ref in stages or ref.startswith("binary-$") or DIGEST.search(ref)):
            out.append(f"Dockerfile FROM {ref} is not pinned by digest")
        if m.group(2): stages.add(m.group(2))
    users = [l.split()[1] for l in open(sys.argv[2]) if l.startswith("USER ")]
    if not users or users[-1].split(":")[0] in ("0", "root"): out.append(f"Dockerfile's final USER is {users[-1:] or 'unset'}")
elif what == "secrets":
    for n, s in svcs.items():
        env = s.get("environment") or {}
        if not isinstance(env, dict):
            env = dict((e.split("=", 1) + [""])[:2] for e in env)
        for k, v in env.items():
            if re.search(r"KEY|SECRET|TOKEN|PASSWORD", k) and not k.endswith("_FILE") and v not in (None, ""):
                out.append(f"{n}: {k} has a value in the environment")
    for k in ("api_key", "read_api_key", "admin_api_key", "audit_key"):
        if k not in (c.get("secrets") or {}) or "file" not in c["secrets"][k]: out.append(f"secret {k} is not file-backed")
elif what == "proxy":
    # Round 40 (R39-CB-8): the Core believes X-Forwarded-For only from Caddy's
    # fixed backend address, which no other service can be given.
    import ipaddress
    env = svcs["graphite"].get("environment") or {}
    trusted = [e.strip() for e in str(env.get("GRAPHITE_TRUSTED_PROXIES") or "").split(",") if e.strip()]
    nets = (svcs["caddy"].get("networks") or {})
    caddy = ((nets.get("backend") or {}) if isinstance(nets, dict) else {}).get("ipv4_address")
    ipam = (((c.get("networks") or {}).get("backend") or {}).get("ipam") or {}).get("config") or [{}]
    subnet, dyn = ipam[0].get("subnet"), ipam[0].get("ip_range")
    if str(env.get("GRAPHITE_TRUST_PROXY")) != "1": out.append("graphite: GRAPHITE_TRUST_PROXY is not 1")
    if not caddy: out.append("caddy has no fixed ipv4_address on the backend network")
    if trusted != [caddy]: out.append(f"graphite: GRAPHITE_TRUSTED_PROXIES is {trusted}, not exactly Caddy's address {caddy}")
    if not subnet or not dyn: out.append("the backend network has no fixed subnet and ip_range")
    elif caddy:
        a = ipaddress.ip_address(caddy)
        if a not in ipaddress.ip_network(subnet): out.append(f"Caddy's {caddy} is outside {subnet}")
        if a in ipaddress.ip_network(dyn): out.append(f"Caddy's {caddy} is inside the dynamic range {dyn}: another container could be given it")
    for n, s in svcs.items():
        sn = s.get("networks") or {}
        addr = ((sn.get("backend") or {}) if isinstance(sn, dict) else {}).get("ipv4_address")
        if n != "caddy" and addr and addr in trusted: out.append(f"{n} holds a trusted proxy address")
print("; ".join(out))
EOF
}
for w in replicas hardening digests secrets proxy; do
  v="$(compose_audit "$w" 2>&1)"
  case "$w" in
    proxy) d="compose: X-Forwarded-For believed only from Caddy's fixed backend address, outside the dynamic range" ;;
    replicas) d="compose: one Core replica (container_name and deploy.replicas: 1)" ;;
    hardening) d="compose: every service read-only, cap_drop ALL, no-new-privileges, no host namespaces; Core and AI non-root, unpublished" ;;
    digests) d="compose and Dockerfile: every image pinned by digest; the Dockerfile ends non-root" ;;
    secrets) d="compose: keys only as file-backed secrets, none in the environment" ;;
  esac
  [ -z "$v" ] && ok "$d" || bad "$d: $v"
done

if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
  dcenv=(GRAPHITE_IMAGE=ghcr.io/o/graphite-core:0 GRAPHITE_IMAGE_DIGEST=sha256:0000000000000000000000000000000000000000000000000000000000000000
    GRAPHITE_SITE=g.example.com ACME_EMAIL=ops@example.com)
  dc=(env -u GRAPHITE_IMAGE -u GRAPHITE_IMAGE_DIGEST "${dcenv[@]}" docker compose -f "$deploy/compose/docker-compose.prod.yml")
  dc_without() { # dc_without VAR ARGS... — compose with every variable above but VAR
    local drop="$1" kept=() x
    shift
    for x in "${dcenv[@]}"; do [ "${x%%=*}" = "$drop" ] || kept+=("$x"); done
    env -u "$drop" "${kept[@]}" docker compose -f "$deploy/compose/docker-compose.prod.yml" "$@"
  }
  check "docker compose config (prod)" "${dc[@]}" --profile ai config --quiet
  expect_rc 1 "compose refuses to render without GRAPHITE_IMAGE" dc_without GRAPHITE_IMAGE config --quiet
  # Round 36: a tag alone used to render (and deploy whatever it pointed at).
  expect_rc 1 "compose refuses an image without GRAPHITE_IMAGE_DIGEST (a tag alone)" dc_without GRAPHITE_IMAGE_DIGEST config --quiet
  img="$("${dc[@]}" config --format json 2>/dev/null | jq -r .services.graphite.image)"
  [ "$img" = "ghcr.io/o/graphite-core:0@sha256:0000000000000000000000000000000000000000000000000000000000000000" ] &&
    ok "compose: the Core's image is GRAPHITE_IMAGE@GRAPHITE_IMAGE_DIGEST" || bad "compose: the Core's image renders as '$img'"
  # F-019: an operator's override cannot turn the Core into two replicas.
  printf 'services:\n  graphite:\n    deploy:\n      replicas: 2\n' >"$T/replicas2.yml"
  printf 'services:\n  graphite:\n    scale: 2\n' >"$T/scale2.yml"
  expect_rc 1 "compose refuses a second Core replica (deploy.replicas: 2 override)" "${dc[@]}" -f "$T/replicas2.yml" config --quiet
  expect_rc 1 "compose refuses a second Core replica (scale: 2 override)" "${dc[@]}" -f "$T/scale2.yml" config --quiet
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
mk_start() { # mk_start AUDIT_KEY_FILE [PREVIOUS_AUDIT_KEY_FILE] -> $T/start.sh
  local prev=""
  [ -n "${2:-}" ] && prev="GRAPHITE_AUDIT_PREVIOUS_KEY_FILE='$2' "
  cat >"$T/start.sh" <<EOF
#!/usr/bin/env bash
GRAPHITE_API_KEY='$key' GRAPHITE_READ_API_KEY='$rkey' GRAPHITE_DATA_DIR='$T/data' \\
  GRAPHITE_REGISTRY_STATE='$T/data/registry_state.json' \\
  GRAPHITE_AUDIT_KEY_FILE='$1' ${prev}GRAPHITE_AUDIT_ANCHOR_DIR='$T/anchors' \\
  GRAPHITE_AUDIT_ROTATE_BYTES=4096 GRAPHITE_TRUST_PROXY=1 GRAPHITE_TRUSTED_PROXIES='127.0.0.1,::1' GRAPHITE_RATE_LIMIT=5 \\
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
start_core() { # start_core AUDIT_KEY_FILE [PREVIOUS_AUDIT_KEY_FILE]
  mk_start "$1" "${2:-}"
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
# Round 40 (R39-CB-8): a hop count with no proxy list, or a list entry that is
# not an address, refuses to start (a server that started would be killed by
# the timeout, and that exit is not 1).
mkdir -p "$T/noproxy"
expect_rc 1 "core refuses GRAPHITE_TRUST_PROXY=1 without GRAPHITE_TRUSTED_PROXIES" env GRAPHITE_DEV_MODE=1 \
  GRAPHITE_DATA_DIR="$T/noproxy" GRAPHITE_TRUST_PROXY=1 timeout 20 "$G" server --host 127.0.0.1 --port 0
expect_rc 1 "core refuses a GRAPHITE_TRUSTED_PROXIES entry that is not an address" env GRAPHITE_DEV_MODE=1 \
  GRAPHITE_DATA_DIR="$T/noproxy" GRAPHITE_TRUST_PROXY=1 GRAPHITE_TRUSTED_PROXIES=caddy timeout 20 "$G" server --host 127.0.0.1 --port 0

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
# Thirty times, not once: when Caddy streamed the body, the Core's early 413
# and close raced its writes and about a third came back 502 (Round 34). The
# edge refuses a declared oversized body before proxying, so every one is 413.
codes=""
for _ in $(seq 1 30); do
  codes="$codes $(code -X POST -H "Authorization: Bearer $key" -H 'Content-Type: application/json' --data-binary @"$T/big.json" "$E/verify")"
done
! tr ' ' '\n' <<<"$codes" | grep -v '^$' | grep -qvx 413 && ok "edge: 1.1 MB body -> 413 (30 of 30)" || bad "edge: 1.1 MB body ->$codes"
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
# `admin off`: no config API on Caddy's default localhost:2019 (two Caddys run).
c="$(code "http://127.0.0.1:2019/config/")"
[ "$c" = 000 ] && ok "edge: no Caddy admin API on localhost:2019" || bad "edge: localhost:2019 answered $c"
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
# F-019: one Core per data directory. A second server on the live directory
# (its own port, the same keys) exits at once naming the lock, a writing CLI
# is refused the same way, and neither touched the trail.
head_before="$("$G" audit verify --data-dir "$T/data" --key-file "$T/keys/audit-1.key" --json 2>/dev/null | jq -r .head_hash)"
rc2=0
GRAPHITE_API_KEY="$key" GRAPHITE_READ_API_KEY="$rkey" GRAPHITE_DATA_DIR="$T/data" \
  GRAPHITE_REGISTRY_STATE="$T/data/registry_state.json" GRAPHITE_AUDIT_KEY_FILE="$T/keys/audit-1.key" \
  GRAPHITE_AUDIT_ANCHOR_DIR="$T/anchors" GRAPHITE_WALLET_PROFILE=treasury \
  timeout 20 "$G" server --host 127.0.0.1 --port "$(port)" >"$T/second.log" 2>&1 || rc2=$?
[ "$rc2" != 0 ] && [ "$rc2" != 124 ] && grep -q 'graphite.lock is locked' "$T/second.log" &&
  ok "a second Core on the live data directory refuses to start (exit $rc2, names graphite.lock)" ||
  bad "a second Core on the live data directory: exit $rc2: $(tail -n 1 "$T/second.log")"
rcq=0
outq="$(GRAPHITE_AUDIT_KEY_FILE="$T/keys/audit-1.key" "$G" quarantine add --data-dir "$T/data" \
  --program 11111111111111111111111111111111 --reason "deploy test" 2>&1)" || rcq=$?
[ "$rcq" != 0 ] && grep -q 'graphite.lock is locked' <<<"$outq" && ok "a writing CLI on the live data directory refuses (exit $rcq)" ||
  bad "quarantine add beside the server: exit $rcq: $outq"
check "the first Core still serves" curl -fsS "http://127.0.0.1:$gport/health"
[ -n "$head_before" ] && [ "$head_before" != null ] &&
  [ "$("$G" audit verify --data-dir "$T/data" --key-file "$T/keys/audit-1.key" --json 2>/dev/null | jq -r .head_hash)" = "$head_before" ] &&
  ok "the refused writers left the trail's head where it was" || bad "the trail's head moved while the second writers were refused"

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
grep -Eqx "hmac-sha256-v1 [0-9a-f]{64} ${hot##*/}" "$hot.mac" && [ "$(stat -c %a "$hot.mac")" = 600 ] &&
  ok "backup writes a .mac of the archive (mode 600)" || bad "backup wrote no well-formed .mac"
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

# Every restore below names the keys and the anchors, as an operator must.
R=("$deploy/scripts/restore.sh" --key-file "$T/keys/audit-1.key" --anchor-dir "$T/anchors")
# The MAC and naming refusals run with ACCEPT_STALE_RESTORE=1, so the
# stale-restore refusal (these archives predate the newest checkpoint) cannot
# stand in for them.
RS=(env ACCEPT_STALE_RESTORE=1 "${R[@]}")
# mac_of KEY_FILE ARCHIVE — a .mac line as backup.sh writes it, computed here
# independently of the scripts under test.
mac_of() {
  python3 -I - "$1" "$2" <<'EOF'
import hashlib, hmac, os, sys
key = open(sys.argv[1], "rb").read().strip()
name = os.path.basename(sys.argv[2])
m = hmac.new(key, b"graphite-backup-v1\n" + name.encode() + b"\n" + open(sys.argv[2], "rb").read(), hashlib.sha256)
print(f"hmac-sha256-v1 {m.hexdigest()} {name}")
EOF
}
cmp -s <(mac_of "$T/keys/audit-1.key" "$cold") "$cold.mac" && ok "backup's .mac is HMAC-SHA256(audit key, name + archive)" ||
  bad "backup's .mac is not the documented HMAC"
expect_rc 75 "restore.sh refuses while the server holds the lock" "${R[@]}" "$cold" "$T/data"
check "stop the server" stop_core

# Round 34 (D-6): without the anchors a rolled-back archive is undetectable.
expect_rc 64 "restore.sh refuses without --anchor-dir" "$deploy/scripts/restore.sh" --key-file "$T/keys/audit-1.key" "$cold" "$T/restore-noanchor"
[ ! -e "$T/restore-noanchor" ] && ok "the refused no-anchor restore wrote nothing" || bad "the refused no-anchor restore wrote $T/restore-noanchor"
expect_rc 0 "restore.sh without --anchor-dir under ALLOW_NO_ANCHOR=1" env ALLOW_NO_ANCHOR=1 \
  "$deploy/scripts/restore.sh" --key-file "$T/keys/audit-1.key" "$cold" "$T/restore-noanchor"

cp "$cold" "$T/nosum.tar.gz"
cp "$cold.mac" "$T/nosum.tar.gz.mac"
expect_rc 66 "restore.sh refuses an archive without its .sha256" "${R[@]}" "$T/nosum.tar.gz" "$T/data"
cp "$cold" "$T/corrupt.tar.gz"
(cd "$(dirname "$cold")" && sha256sum "${cold##*/}") | sed "s|${cold##*/}|corrupt.tar.gz|" >"$T/corrupt.tar.gz.sha256"
printf 'x' | dd of="$T/corrupt.tar.gz" bs=1 seek=100 conv=notrunc 2>/dev/null
expect_rc 1 "restore.sh refuses an archive that fails its checksum" "${R[@]}" "$T/corrupt.tar.gz" "$T/data"

# Round 34 (D-6): what the trail check never saw. The archive's other files
# (here registry_state.json, which seeds the manifest registry) changed, the
# archive re-packed and re-checksummed: `audit verify` passes (the trail is
# untouched), so only the MAC can refuse it.
mkdir -p "$T/swap"
tar -C "$T/swap" -xzf "$cold"
printf '{"submissions":[],"reviewers":{"attacker":{"reputation":1000000}}}\n' >"$T/swap/registry_state.json"
tar -C "$T/swap" -czf "$T/backups/swapped.tar.gz" .
(cd "$T/backups" && sha256sum swapped.tar.gz >swapped.tar.gz.sha256)
sed "s| ${cold##*/}\$| swapped.tar.gz|" "$cold.mac" >"$T/backups/swapped.tar.gz.mac"
expect_rc 0 "the swapped archive's trail still verifies (what audit verify cannot see)" "$G" audit verify --data-dir "$T/swap" --key-file "$T/keys/audit-1.key"
expect_rc 1 "restore.sh refuses an archive whose non-trail files changed (MAC)" "${RS[@]}" "$T/backups/swapped.tar.gz" "$T/restore-swapped"
rm -f "$T/backups/swapped.tar.gz.mac"
expect_rc 66 "restore.sh refuses an archive with no .mac" "${RS[@]}" "$T/backups/swapped.tar.gz" "$T/restore-swapped"
# A .sha256 naming ANOTHER archive in the same directory: `sha256sum -c`
# checked that one and passed, whatever this archive held. Run as an unkeyed
# archive (no .mac, ALLOW_UNKEYED_ARCHIVE=1), where the checksum is the only
# integrity check left, so the MAC cannot stand in for the name check.
cp "$cold.sha256" "$T/backups/swapped.tar.gz.sha256"
expect_rc 1 "restore.sh refuses a .sha256 that names another archive" env ALLOW_UNKEYED_ARCHIVE=1 "${RS[@]}" \
  "$T/backups/swapped.tar.gz" "$T/restore-swapped"
[ ! -e "$T/restore-swapped" ] && ok "no refused archive was restored" || bad "a refused archive reached $T/restore-swapped"
# The MAC is keyed: an intact archive whose .mac was made under a key the
# restore is not given (anyone can compute a MAC under a key of their own).
openssl rand -hex 32 >"$T/keys/unrelated.key"
cp "$cold" "$T/backups/othermac.tar.gz"
(cd "$T/backups" && sha256sum othermac.tar.gz >othermac.tar.gz.sha256)
mac_of "$T/keys/unrelated.key" "$T/backups/othermac.tar.gz" >"$T/backups/othermac.tar.gz.mac"
expect_rc 1 "restore.sh refuses a .mac made under a key it was not given" "${RS[@]}" "$T/backups/othermac.tar.gz" "$T/restore-wrongkey"
# An unkeyed deployment's archive (no .mac) is restorable only on request.
cp "$cold" "$T/backups/unkeyed.tar.gz"
(cd "$T/backups" && sha256sum unkeyed.tar.gz >unkeyed.tar.gz.sha256)
expect_rc 0 "restore.sh accepts an archive without a .mac under ALLOW_UNKEYED_ARCHIVE=1" env ALLOW_UNKEYED_ARCHIVE=1 ACCEPT_STALE_RESTORE=1 \
  "${R[@]}" "$T/backups/unkeyed.tar.gz" "$T/restore-unkeyed"

# A tampered trail, packed as a well-formed archive with a matching checksum
# and a valid MAC (made with the key: what an insider holding the key could
# produce), so the refusal below is `audit verify`'s own.
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
mac_of "$T/keys/audit-1.key" "$T/tampered.tar.gz" >"$T/tampered.tar.gz.mac"
expect_rc 1 "restore.sh refuses a tampered trail (audit verify fails)" "${R[@]}" "$T/tampered.tar.gz" "$T/data"
# Refused before anything moved: the live directory was never set aside.
ls -d "$T"/data.pre-restore-* >/dev/null 2>&1 && bad "a refused restore moved the data directory" || ok "refused restores left the data directory in place"
expect_rc 1 "backup.sh keeps no backup of a trail that does not verify" \
  "$deploy/scripts/backup.sh" --hot --key-file "$T/keys/audit-1.key" "$T/tamper" "$T/backups-bad"
[ -z "$(find "$T/backups-bad" -name '*.tar.gz' 2>/dev/null)" ] && ok "no archive left behind for the broken trail" || bad "an archive of a broken trail was kept"
expect_rc 0 "the live data still verifies after the refused restores" "$G" audit verify --data-dir "$T/data" --key-file "$T/keys/audit-1.key"

expect_rc 1 "restore.sh refuses a stale restore against the newest anchored checkpoint" "${R[@]}" "$cold" "$T/data"
expect_rc 0 "restore.sh with ACCEPT_STALE_RESTORE=1" env ACCEPT_STALE_RESTORE=1 "${R[@]}" "$cold" "$T/data"
ls -d "$T"/data.pre-restore-* >/dev/null 2>&1 && ok "previous data directory kept aside" || bad "previous data directory not kept"
expect_rc 1 "the restored (older) trail fails the newer checkpoint, as it should" \
  "$G" audit verify --data-dir "$T/data" --key-file "$T/keys/audit-1.key" --checkpoint "$(find "$T/anchors" -name 'audit.jsonl-checkpoint-*' | LC_ALL=C sort | tail -n 1)"
check "server starts on the restored directory" start_core "$T/keys/audit-1.key"

echo "== key rotation"
rotate_out="$("$deploy/scripts/rotate-keys.sh" audit-key "$T/keys" 2>&1)" && ok "rotate-keys.sh audit-key" || bad "rotate-keys.sh audit-key"
grep -q GRAPHITE_AUDIT_PREVIOUS_KEY_FILE <<<"$rotate_out" && ok "rotate-keys.sh audit-key says to set the previous key" || bad "rotate-keys.sh audit-key does not mention GRAPHITE_AUDIT_PREVIOUS_KEY_FILE"
newkey="$(find "$T/keys" -name 'audit-2*.key' | head -n 1)"
[ "$(stat -c %a "$newkey")" = 600 ] && ok "new audit key is mode 600" || bad "new audit key mode $(stat -c %a "$newkey")"
check "stop for the key switch" stop_core
# Round 34 (R33-13): the new key alone does not continue a trail whose head
# is MAC'd under another key; with the previous key the server checks the
# head under it and writes a key-adoption record.
expect_rc 1 "server refuses the new audit key without the previous key" start_core "$newkey"
grep -q GRAPHITE_AUDIT_PREVIOUS_KEY_FILE "$T/core.log" && ok "the refusal names GRAPHITE_AUDIT_PREVIOUS_KEY_FILE" || bad "the refusal does not name the previous-key variable"
check "server starts under the new audit key with the previous key" start_core "$newkey" "$T/keys/audit-1.key"
check "verdicts under the new key" verify_n 2
expect_rc 0 "rotate-keys.sh verify with old + new keys" "$deploy/scripts/rotate-keys.sh" verify "$T/data" "$T/keys/audit-1.key" "$newkey"
expect_rc 2 "rotate-keys.sh verify with the new key only -> unprovable" "$deploy/scripts/rotate-keys.sh" verify "$T/data" "$newkey"
# An unkeyed trail verified under a key: not covered (exit 4).
mkdir -p "$T/unkeyed"
env -u GRAPHITE_AUDIT_KEY_FILE "$G" quarantine add --data-dir "$T/unkeyed" --program 11111111111111111111111111111111 --reason "deploy test" >/dev/null 2>&1
rc4=0
out4="$("$deploy/scripts/rotate-keys.sh" verify "$T/unkeyed" "$newkey" 2>&1)" || rc4=$?
if [ "$rc4" = 4 ] && grep -q "do not cover the trail" <<<"$out4"; then
  ok "rotate-keys.sh verify of an unkeyed trail under a key -> not covered (exit 4)"
else
  bad "rotate-keys.sh verify of an unkeyed trail under a key (exit $rc4): $out4"
fi

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

# Round 34 (R33-19): a rotated secret keeps its owner. The compose stack reads
# its secrets as the image's user (10001:10001); rotate-keys.sh runs under
# sudo, and a file it wrote used to belong to root, so after the restart the
# Core could not read its key and crash-looped. As root (or with passwordless
# sudo, as on the CI runner) the fixtures belong to 10001:10001.
asroot() {
  if [ "$(id -u)" = 0 ]; then "$@"; elif sudo -n true 2>/dev/null; then sudo -n "$@"; else return 99; fi
}
if asroot true; then
  printf '%s\n' "$(openssl rand -hex 32)" >"$T/keys/owned_secret"
  printf 'GRAPHITE_API_KEY=old\n' >"$T/owned.env"
  asroot chown 10001:10001 "$T/keys/owned_secret" "$T/owned.env"
  asroot chmod 600 "$T/keys/owned_secret" "$T/owned.env"
  check "rotate-keys.sh file, as root, on a 10001-owned secret" asroot "$deploy/scripts/rotate-keys.sh" file "$T/keys/owned_secret"
  [ "$(stat -c '%u:%g %a' "$T/keys/owned_secret")" = "10001:10001 600" ] &&
    ok "file: owner 10001:10001 and mode 600 kept" || bad "file: now $(stat -c '%u:%g %a' "$T/keys/owned_secret"), wanted 10001:10001 600"
  check "rotate-keys.sh env, as root, on a 10001-owned env file" asroot "$deploy/scripts/rotate-keys.sh" env "$T/owned.env" GRAPHITE_API_KEY
  [ "$(stat -c '%u:%g %a' "$T/owned.env")" = "10001:10001 600" ] &&
    ok "env: owner 10001:10001 and mode 600 kept" || bad "env: now $(stat -c '%u:%g %a' "$T/owned.env"), wanted 10001:10001 600"
  check "rotate-keys.sh file with an explicit UID:GID (a new secret)" asroot "$deploy/scripts/rotate-keys.sh" file "$T/keys/new_secret" 10001:10001
  [ "$(stat -c '%u:%g %a' "$T/keys/new_secret")" = "10001:10001 600" ] &&
    ok "file: a new secret takes the UID:GID given" || bad "file: new secret is $(stat -c '%u:%g %a' "$T/keys/new_secret")"
  asroot chown -R "$(id -u):$(id -g)" "$T/keys" "$T"/owned.env*
else
  skipped+=("rotate-keys.sh owner preservation: not root and no passwordless sudo")
fi

echo "== a lost audit key"
# Round 36 (F-021): the key a trail was MAC'd under is gone. The trail goes on
# under a new key through `graphite audit adopt-key` (docs/ops/keys.md); from
# then on `audit verify` exits 2, and backup.sh and restore.sh refused every
# archive of that trail, for good. --lost-key <id> accepts that exit 2 and
# nothing else.
L="$T/lost"
mkdir -p "$L/data" "$L/keys" "$L/anchors" "$L/backups"
chmod 700 "$L/keys"
openssl rand -hex 32 >"$L/keys/old.key"
chmod 600 "$L/keys/old.key"
qadd() { # qadd KEY_FILE PROGRAM — one keyed record, written by the CLI
  GRAPHITE_AUDIT_KEY_FILE="$1" "$G" quarantine add --data-dir "$L/data" --program "$2" --reason "deploy test" >/dev/null 2>&1
}
check "a record under the old key" qadd "$L/keys/old.key" 11111111111111111111111111111111
check "another record under the old key" qadd "$L/keys/old.key" Vote111111111111111111111111111111111111111
mv "$L/keys/old.key" "$L/old.key.lost"
"$deploy/scripts/rotate-keys.sh" audit-key "$L/keys" >/dev/null 2>&1
lnew="$(find "$L/keys" -name 'audit-*.key' | head -n 1)"
expect_rc 1 "the new key alone does not continue the trail" qadd "$lnew" Stake11111111111111111111111111111111111111
check "graphite audit adopt-key under the new key (the old one lost)" "$G" audit adopt-key --data-dir "$L/data" --key-file "$lnew"
check "a record under the new key after the adoption" qadd "$lnew" Stake11111111111111111111111111111111111111
lost_id="$("$G" audit verify --data-dir "$L/data" --key-file "$lnew" --json 2>/dev/null | jq -r '.key_ranges[] | select(.supplied | not) | .key_id')"
[[ "$lost_id" =~ ^[0-9a-f]{16}$ ]] && ok "audit verify names the lost key ($lost_id) as not supplied" || bad "no single lost key id in audit verify: '$lost_id'"
expect_rc 2 "rotate-keys.sh verify with the new key only -> 2 (the lost key's MACs cannot be checked)" \
  "$deploy/scripts/rotate-keys.sh" verify "$L/data" "$lnew"
check "anchor a checkpoint under the new key" env GRAPHITE_DATA_DIR="$L/data" GRAPHITE_AUDIT_ANCHOR_DIR="$L/anchors" \
  GRAPHITE_AUDIT_KEY_FILE="$lnew" "$deploy/scripts/anchor-checkpoints.sh"
LB=("$deploy/scripts/backup.sh" --hot --key-file "$lnew")
expect_rc 1 "backup.sh refuses the trail without --lost-key" "${LB[@]}" "$L/data" "$L/backups"
expect_rc 64 "backup.sh refuses a --lost-key that is not a key id" "${LB[@]}" --lost-key nothex "$L/data" "$L/backups"
expect_rc 1 "backup.sh refuses a --lost-key naming another key" "${LB[@]}" --lost-key 0123456789abcdef "$L/data" "$L/backups"
[ -z "$(find "$L/backups" -name '*.tar.gz')" ] && ok "no archive kept by the refused backups" || bad "a refused lost-key backup kept an archive"
expect_rc 0 "backup.sh --lost-key <the lost key's id>" "${LB[@]}" --lost-key "$lost_id" "$L/data" "$L/backups"
larch="$(find "$L/backups" -name 'graphite-*.tar.gz' | head -n 1)"
grep -q "records chained but not MAC-checked" "${larch%.tar.gz}.verify.txt" 2>/dev/null &&
  ok "the backup's verify report records what --lost-key accepted" || bad "the backup's verify report does not say what --lost-key accepted"
LR=("$deploy/scripts/restore.sh" --key-file "$lnew" --anchor-dir "$L/anchors")
expect_rc 1 "restore.sh refuses the archive without --lost-key" "${LR[@]}" "$larch" "$L/restored"
expect_rc 0 "restore.sh --lost-key (trail, newest checkpoint and in place)" "${LR[@]}" --lost-key "$lost_id" "$larch" "$L/restored"
expect_rc 2 "the restored trail still verifies as 2, not 0: nothing was vouched for" "$G" audit verify --data-dir "$L/restored" --key-file "$lnew"
# --lost-key never covers a rewrite: a record under the lost key changed, the
# archive re-packed with a matching checksum and a MAC under the new key.
mkdir -p "$L/tamper"
tar -C "$L/tamper" -xzf "$larch"
python3 -I - "$L/tamper/audit.jsonl" <<'EOF'
import sys
p = sys.argv[1]
lines = open(p).read().splitlines(keepends=True)
# The first record's reason (under the lost key); left alone if it is not
# there, so the restore below then succeeds and the check fails.
lines[0] = lines[0].replace("deploy test", "deploy tesT", 1)
open(p, "w").write("".join(lines))
EOF
tar -C "$L/tamper" -czf "$L/backups/ltampered.tar.gz" .
(cd "$L/backups" && sha256sum ltampered.tar.gz >ltampered.tar.gz.sha256)
mac_of "$lnew" "$L/backups/ltampered.tar.gz" >"$L/backups/ltampered.tar.gz.mac"
expect_rc 1 "restore.sh --lost-key refuses a rewritten record under the lost key" "${LR[@]}" --lost-key "$lost_id" \
  "$L/backups/ltampered.tar.gz" "$L/restored-tampered"
[ ! -e "$L/restored-tampered" ] && ok "the rewritten archive was not restored" || bad "the rewritten archive reached $L/restored-tampered"

echo "== backup and restore keys (backup-keys.test.sh)"
# Round 38 (R37-11, T-9): the .mac under the current key only, on both sides,
# and the newest anchored checkpoint chosen by content, not by file name.
check "backup.sh / restore.sh key and anchor rules (deploy/tests/backup-keys.test.sh)" bash "$here/backup-keys.test.sh"

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

echo "== failure (SIGTERM, a full disk)"
# Each case runs its own Core on its own data directory, started here, so its
# exit status can be read. The environment every such Core gets:
mkdir -p "$T/fkeys"
chmod 700 "$T/fkeys"
openssl rand -hex 32 >"$T/fkeys/audit.key"
chmod 600 "$T/fkeys/audit.key"
fenv() { # fenv DATA_DIR ANCHOR_DIR -> the env(1) prefix of a Core on DATA_DIR
  fe=(env GRAPHITE_API_KEY="$key" GRAPHITE_DATA_DIR="$1" GRAPHITE_REGISTRY_STATE="$1/registry_state.json"
    GRAPHITE_AUDIT_KEY_FILE="$T/fkeys/audit.key" GRAPHITE_AUDIT_ANCHOR_DIR="$2" GRAPHITE_WALLET_PROFILE=treasury
    GRAPHITE_RATE_LIMIT=1000 RUST_LOG=info)
}
wait_up() { # wait_up PORT PID
  local _
  for _ in $(seq 1 100); do
    curl -fsS "http://127.0.0.1:$1/health" >/dev/null 2>&1 && return 0
    kill -0 "$2" 2>/dev/null || return 1
    sleep 0.1
  done
  return 1
}

# SIGTERM with a verdict in flight: the request's body is still arriving when
# the signal lands. The server stops accepting, answers that request, records
# it, and exits 0 with its lock released (what systemd's and compose's 30 s
# stop grace and backup.sh's STOP_CMD rely on).
mkdir -p "$T/sig/data" "$T/sig/anchors"
fenv "$T/sig/data" "$T/sig/anchors"
sport3="$(port)"
"${fe[@]}" "$G" server --host 127.0.0.1 --port "$sport3" >"$T/sig/core.log" 2>&1 &
spid=$!
pids+=("$spid")
check "a Core for the SIGTERM case" wait_up "$sport3" "$spid"
cat >"$T/slow.py" <<'EOF'
import json, socket, sys, time
port, key, body, pause = int(sys.argv[1]), sys.argv[2], open(sys.argv[3], "rb").read(), float(sys.argv[4])
s = socket.create_connection(("127.0.0.1", port), timeout=20)
s.sendall(b"POST /verify HTTP/1.1\r\nHost: core\r\nAuthorization: Bearer " + key.encode()
          + b"\r\nContent-Type: application/json\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body[:10])
time.sleep(pause)
s.sendall(body[10:])
data = b""
while True:
    c = s.recv(65536)
    if not c:
        break
    data += c
    head, sep, rest = data.partition(b"\r\n\r\n")
    cl = [l for l in head.split(b"\r\n") if l.lower().startswith(b"content-length:")]
    if sep and cl and len(rest) >= int(cl[0].split(b":")[1]):
        break
print(data.split(b"\r\n")[0].decode())
print(json.loads(data.partition(b"\r\n\r\n")[2]).get("audit_trail_id"))
EOF
python3 -I "$T/slow.py" "$sport3" "$key" "$repo/examples/verify-input.json" 1.5 >"$T/sig/slow.out" 2>&1 &
slow=$!
sleep 0.7
kill -TERM "$spid"
sleep 0.3
c="$(code "http://127.0.0.1:$sport3/health")"
[ "$c" = 000 ] && ok "SIGTERM: no new connection is accepted while draining" || bad "SIGTERM: a new request during the drain got $c"
wait "$slow"
src=0
wait "$spid" || src=$?
grep -qx 'HTTP/1.1 200 OK' "$T/sig/slow.out" && ok "SIGTERM: the in-flight verdict was answered (200)" || bad "SIGTERM: the in-flight request got: $(head -n 1 "$T/sig/slow.out")"
sid="$(tail -n 1 "$T/sig/slow.out")"
[ -n "$sid" ] && [ "$sid" != None ] && grep -qF "\"$sid\"" "$T/sig/data/audit.jsonl" && ok "SIGTERM: and is on the trail ($sid)" || bad "SIGTERM: the answered verdict '$sid' is not on the trail"
[ "$src" = 0 ] && ok "SIGTERM: the Core exits 0" || bad "SIGTERM: the Core exited $src"
grep -q 'Received SIGTERM' "$T/sig/core.log" && ok "SIGTERM: logged as a graceful shutdown" || bad "SIGTERM: no shutdown line in the log"
check "SIGTERM: the data directory's lock is free" flock -n "$T/sig/data/graphite.lock" true
expect_rc 0 "SIGTERM: the trail verifies after the shutdown" "$G" audit verify --data-dir "$T/sig/data" --key-file "$T/fkeys/audit.key"

# A full data directory (Constitution P9: no verdict without a durable
# record). A 256 KiB tmpfs is the data directory, mounted in a user+mount
# namespace (no root, no host mount); the Core runs inside it, the network is
# the host's. Filled once the Core runs: every verdict is then either on the
# trail or refused 503 AuditWriteFailed, never answered unrecorded; the trail
# still verifies; /health says audit_writes_failed; freed space is used again.
cat >"$T/diskfull.sh" <<'EOF'
#!/usr/bin/env bash
# diskfull.sh T G KEY VERIFY_INPUT PORT — run inside `unshare --user --map-root-user --mount`
set -u
T="$1" G="$2" key="$3" input="$4" p="$5"
R="$T/full/results"
mkdir -p "$R"
mount -t tmpfs -o size=256k,mode=0700 tmpfs "$T/full/data" || { echo mount >"$R/error"; exit 1; }
GRAPHITE_API_KEY="$key" GRAPHITE_DATA_DIR="$T/full/data" GRAPHITE_REGISTRY_STATE="$T/full/data/registry_state.json" \
  GRAPHITE_AUDIT_KEY_FILE="$T/fkeys/audit.key" GRAPHITE_AUDIT_ANCHOR_DIR="$T/full/anchors" GRAPHITE_WALLET_PROFILE=treasury \
  GRAPHITE_RATE_LIMIT=1000 RUST_LOG=info "$G" server --host 127.0.0.1 --port "$p" >"$T/full/core.log" 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null' EXIT
up=0
for _ in $(seq 1 100); do curl -fsS "http://127.0.0.1:$p/health" >/dev/null 2>&1 && { up=1; break; }; sleep 0.1; done
[ "$up" = 1 ] || { echo "no core" >"$R/error"; exit 1; }
n=0
v() { # one verdict; its status and, when 200, its trail id
  n=$((n + 1))
  local c
  c="$(curl -s -o "$R/resp.$n" -w '%{http_code}' -H "Authorization: Bearer $key" -H 'Content-Type: application/json' \
    --data-binary @"$input" "http://127.0.0.1:$p/verify")"
  echo "$1 $c $(jq -r '.audit_trail_id // .error_type // empty' "$R/resp.$n" 2>/dev/null)" >>"$R/verdicts"
}
v before
dd if=/dev/zero of="$T/full/data/filler" bs=4096 >/dev/null 2>&1
df -k "$T/full/data" | tail -n 1 | awk '{print $4}' >"$R/avail"
for _ in 1 2 3 4 5 6 7 8; do v full; done
curl -s "http://127.0.0.1:$p/health" >"$R/health.full"
curl -s -H "Authorization: Bearer $key" "http://127.0.0.1:$p/metrics" >"$R/metrics.full"
"$G" audit verify --data-dir "$T/full/data" --key-file "$T/fkeys/audit.key" >/dev/null 2>&1
echo $? >"$R/verify.full"
rm -f "$T/full/data/filler"
v freed
v freed
cp "$T/full/data/audit.jsonl" "$R/audit.jsonl"
"$G" audit verify --data-dir "$T/full/data" --key-file "$T/fkeys/audit.key" >/dev/null 2>&1
echo $? >"$R/verify.freed"
echo done >"$R/done"
EOF
mkdir -p "$T/full/data" "$T/full/anchors"
if unshare --user --map-root-user --mount true 2>/dev/null; then
  unshare --user --map-root-user --mount bash "$T/diskfull.sh" "$T" "$G" "$key" "$repo/examples/verify-input.json" "$(port)" >/dev/null 2>&1
  FR="$T/full/results"
  if [ -e "$FR/done" ]; then
    [ "$(cat "$FR/avail")" = 0 ] && ok "disk full: the data directory has 0 KiB free" || bad "disk full: $(cat "$FR/avail") KiB still free"
    grep -q '^before 200 ' "$FR/verdicts" && ok "disk full: verdicts answered before the disk filled" || bad "disk full: no verdict before filling"
    refused="$(grep -c '^full 503 AuditWriteFailed$' "$FR/verdicts")"
    [ "$refused" -gt 0 ] && ok "disk full: verdicts refused 503 AuditWriteFailed ($refused of 8)" || bad "disk full: no 503 AuditWriteFailed: $(grep '^full' "$FR/verdicts" | tr '\n' ' ')"
    other="$(grep -v -e ' 200 gr-' -e ' 503 AuditWriteFailed$' "$FR/verdicts")"
    [ -z "$other" ] && ok "disk full: every answer is a recorded verdict or a 503 refusal" || bad "disk full: other answers: $other"
    unrec=""
    while read -r _ c id; do
      [ "$c" = 200 ] && ! grep -qF "\"$id\"" "$FR/audit.jsonl" && unrec="$unrec $id"
    done <"$FR/verdicts"
    [ -z "$unrec" ] && ok "disk full: every 200 is on the trail (no verdict without a durable record)" || bad "disk full: answered but not on the trail:$unrec"
    jq -e '.degraded == true and (.degraded_reasons | index("audit_writes_failed"))' "$FR/health.full" >/dev/null 2>&1 &&
      ok "disk full: /health degraded: audit_writes_failed" || bad "disk full: /health $(cat "$FR/health.full")"
    wf="$(sed -n 's/^graphite_audit_writes_failed_total \([0-9]*\)$/\1/p' "$FR/metrics.full")"
    [ "$wf" = "$refused" ] && ok "disk full: graphite_audit_writes_failed_total counts the refusals ($wf)" || bad "disk full: writes_failed_total '$wf', refusals $refused"
    blocked="$(sed -n 's/^graphite_verify_blocked_total \([0-9]*\)$/\1/p' "$FR/metrics.full")"
    answered="$(grep -c -e '^before 200 ' -e '^full 200 ' "$FR/verdicts")"
    [ "$blocked" = "$answered" ] && ok "disk full: a refused verdict is not counted as given ($blocked counted, $answered answered)" ||
      bad "disk full: verify_blocked_total $blocked, answered $answered"
    [ "$(cat "$FR/verify.full")" = 0 ] && ok "disk full: the trail verifies while full (the failed appends left nothing)" || bad "disk full: audit verify exit $(cat "$FR/verify.full") while full"
    [ "$(grep -c '^freed 200 gr-' "$FR/verdicts")" = 2 ] && [ "$(cat "$FR/verify.freed")" = 0 ] &&
      ok "disk full: once space is freed, verdicts are recorded again and the trail verifies" || bad "disk full: after freeing: $(grep '^freed' "$FR/verdicts" | tr '\n' ' ') verify $(cat "$FR/verify.freed")"
  else
    bad "disk full: the namespace run did not finish: $(cat "$FR/error" 2>/dev/null) $(tail -n 3 "$T/full/core.log" 2>/dev/null)"
  fi
else
  skipped+=("disk full: unprivileged user namespaces unavailable (unshare --user --map-root-user --mount)")
fi

echo
if [ "${#skipped[@]}" -gt 0 ]; then printf '  skipped: %s\n' "${skipped[@]}"; fi
echo "deploy tests: $pass passed, $fail failed"
[ "$fail" = 0 ]
