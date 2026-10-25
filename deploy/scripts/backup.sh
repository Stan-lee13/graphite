#!/usr/bin/env bash
# Back up a Graphite data directory to a verified, checksummed archive.
#
#   backup.sh [--hot] [--key-file F]... [--lost-key KEY_ID]... DATA_DIR OUT_DIR
#
# Cold (default): STOP_CMD stops the server, the directory is archived, then
# START_CMD starts it again — the archive is exactly the state the server
# left. Set both, e.g.
#   STOP_CMD="systemctl stop graphite"  START_CMD="systemctl start graphite"
#   STOP_CMD="docker compose stop graphite"  START_CMD="docker compose start graphite"
# The script refuses a cold backup while a server still holds the directory's
# lock (graphite.lock), so a STOP_CMD that did not stop it is caught.
#
# --hot: the server keeps running. Rotated archives are immutable and the
# graph snapshot is replaced atomically, so they copy as-is; the active audit
# file is cut at its last complete line. The copy is then walked with
# `graphite audit verify` and retried (3 times) if a rotation raced it, so an
# archive is only kept when its trail verifies.
#
# Every archive is verified before it is kept: `graphite audit verify` exit 0
# on the copy (exit 2 — MACs under a key not supplied — is refused: pass
# every key with --key-file, or GRAPHITE_AUDIT_KEY_FILE; a key that is lost:
# --lost-key below). The audit MAC key is
# NOT in the archive (it lives outside the data directory by design); back it
# up separately, to a different place.
#
# Output: OUT_DIR/graphite-<UTC stamp>.tar.gz, .sha256 and .mac, mode 0600.
#
# The .mac (Round 34, D-6) authenticates the WHOLE archive — the graph
# snapshot and registry_state.json as well as the trail, which `audit verify`
# already covers — under the audit MAC key: HMAC-SHA256 over the archive's
# file name and bytes. A .sha256 is a checksum anyone who can write the
# archive can recompute; the .mac is not. restore.sh refuses an archive
# without a .mac that verifies under the current key. With an unkeyed trail no
# .mac is written, and restoring it needs ALLOW_UNKEYED_ARCHIVE=1.
#
# The .mac is under the CURRENT key only (Round 38, R37-11): the key the copied
# trail's head is MAC'd under, which the verify above checked — the key the
# server writes under now — whatever order the --key-file options come in
# (GRAPHITE_AUDIT_KEY_FILE counts as one of them). It used to be the last
# --key-file given: a retired key whenever it was listed last, and anyone who
# still holds a retired key can compute a MAC under it over any bytes. A
# keyed head whose key is not given refuses the backup.
#
# --lost-key KEY_ID (Round 36, F-021): after an audit key is LOST and the trail
# continues under a new one (`graphite audit adopt-key`, docs/ops/keys.md),
# `audit verify` exits 2 from then on — the records under the lost key cannot
# be MAC-checked — so every backup was refused and a deployment that lost a key
# could never be backed up again. Naming the lost key's id (the 16 hex digits
# `graphite audit verify` prints as NOT SUPPLIED) accepts exactly that exit 2:
# only when every key not given is named here, each is followed by a
# key-adoption record whose MAC verified, the head is under a key given, and
# nothing else (a break, a tear, an unconfirmed checkpoint) is wrong.
# Needs: bash, tar, gzip, sha256sum, flock, python3, graphite (GRAPHITE_BIN).
set -euo pipefail

usage() { sed -n '2,4p' "$0" >&2; exit 64; }

hot=0
keys=()
keyfiles=()
lost=()
while [ $# -gt 0 ]; do
  case "$1" in
    --hot) hot=1; shift ;;
    --key-file) keys+=(--key-file "$2"); keyfiles+=("$2"); shift 2 ;;
    --lost-key)
      [[ "${2:-}" =~ ^[0-9a-f]{16}$ ]] || { echo "backup: --lost-key takes a key id (16 hex digits)" >&2; exit 64; }
      lost+=("$2")
      shift 2
      ;;
    -h | --help) usage ;;
    --) shift; break ;;
    -*) echo "unknown option $1" >&2; usage ;;
    *) break ;;
  esac
done
[ $# -eq 2 ] || usage
data="${1%/}"
out="${2%/}"
bin="${GRAPHITE_BIN:-graphite}"

[ -f "$data/audit.jsonl" ] || { echo "backup: $data has no audit.jsonl; not a Graphite data directory" >&2; exit 66; }
mkdir -p "$out"
umask 077

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
work="$(mktemp -d "$out/.backup-$stamp.XXXXXX")"
restarted=1
cleanup() {
  rm -rf "$work"
  if [ "$restarted" = 0 ]; then
    echo "backup: starting the server again after a failure" >&2
    sh -c "$START_CMD" || echo "backup: START_CMD FAILED — the server is stopped" >&2
  fi
}
trap cleanup EXIT

# only_lost_keys_unchecked REPORT.json KEY_ID... — exit 0 when the only thing
# `audit verify --json` could not prove is the MACs under the named lost keys.
# (restore.sh carries the same check.)
only_lost_keys_unchecked() {
  python3 -I - "$@" <<'PY'
import json, sys
r, lost = json.load(open(sys.argv[1])), set(sys.argv[2:])
def no(why):
    sys.exit(f"lost-key check: {why}; refusing")
if r.get("first_break") is not None: no("the trail has a break")
if r.get("unacknowledged_tears"): no("the trail has an unacknowledged torn write")
if r.get("unparseable_lines"): no("the trail has unparseable lines")
if not r.get("chained_records"): no("no chained record")
cp = r.get("checkpoint")
if cp is not None and cp.get("status") != "confirmed": no(f"checkpoint {cp.get('status')}")
ranges = r.get("key_ranges") or []
if not ranges or not ranges[-1].get("supplied"): no("the head's key was not given")
unchecked = 0
for i, k in enumerate(ranges):
    if k.get("supplied"): continue
    if k.get("key_id") not in lost: no(f"key {k.get('key_id')} was not given and is not named by --lost-key")
    nxt = ranges[i + 1] if i + 1 < len(ranges) else {}
    if nxt.get("introduced_by") != "adoption_checked":
        no(f"lost key {k['key_id']} is not followed by a verified key-adoption record")
    unchecked += k.get("records", 0)
if unchecked != r.get("macs_unverified"): no("MACs unchecked outside the lost keys' ranges")
print(f"lost keys {', '.join(sorted(lost))}: {unchecked} records chained but not MAC-checked (--lost-key)")
PY
}

server_holds_lock() {
  [ -e "$data/graphite.lock" ] && ! flock -n -E 75 "$data/graphite.lock" true 2>/dev/null
}

# Copy the directory into $work/data, leaving out the lock files.
snapshot() {
  rm -rf "$work/data"
  mkdir -p "$work/data"
  local f name
  # Archives (immutable once rotated) and every other file first; the active
  # audit file last, so a rotation during the copy shows up as a chain break
  # that the verify below catches, never as a silently missing archive.
  for f in "$data"/* "$data"/.[!.]*; do
    [ -e "$f" ] || continue
    name="${f##*/}"
    case "$name" in
      graphite.lock | .audit.jsonl.lock | *.lock | audit.jsonl) continue ;;
    esac
    cp -a -- "$f" "$work/data/"
  done
  cp -a -- "$data/audit.jsonl" "$work/data/"
  if [ "$hot" = 1 ]; then
    # Cut at the last newline: a record being appended right now is left out
    # whole rather than copied torn.
    local a="$work/data/audit.jsonl" partial
    if [ -s "$a" ] && [ "$(tail -c 1 "$a" | od -An -tx1 | tr -d ' \n')" != 0a ]; then
      partial="$(tail -n 1 "$a" | wc -c)"
      truncate -s "$(($(wc -c <"$a") - partial))" "$a"
    fi
  fi
}

verify_copy() {
  local rc=0
  "$bin" audit verify --data-dir "$work/data" ${keys[@]+"${keys[@]}"} >"$work/verify.txt" 2>&1 || rc=$?
  if [ "$rc" = 2 ] && [ "${#lost[@]}" -gt 0 ]; then
    "$bin" audit verify --data-dir "$work/data" ${keys[@]+"${keys[@]}"} --json >"$work/verify.json" 2>/dev/null || true
    only_lost_keys_unchecked "$work/verify.json" "${lost[@]}" >>"$work/verify.txt" 2>&1 && rc=0
  fi
  echo "$rc"
}

if [ "$hot" = 0 ]; then
  : "${STOP_CMD:?cold backup: set STOP_CMD and START_CMD, or pass --hot}"
  : "${START_CMD:?cold backup: set STOP_CMD and START_CMD, or pass --hot}"
  restarted=0
  sh -c "$STOP_CMD"
  if server_holds_lock; then
    echo "backup: a server still holds $data/graphite.lock after STOP_CMD; refusing a cold copy" >&2
    exit 75
  fi
  snapshot
  sh -c "$START_CMD"
  restarted=1
  rc="$(verify_copy)"
else
  rc=1
  for attempt in 1 2 3; do
    snapshot
    rc="$(verify_copy)"
    [ "$rc" = 0 ] && break
    echo "backup: hot copy attempt $attempt did not verify (exit $rc); retrying" >&2
    sleep 2
  done
fi

if [ "$rc" != 0 ]; then
  echo "backup: the copy does not verify (graphite audit verify exit $rc); nothing kept:" >&2
  cat "$work/verify.txt" >&2
  exit 1
fi

# The key the copy's head is under (`audit verify --json`: head_key_id), and
# the given key file with that id (the id is derived as the server derives it).
candidates=("${keyfiles[@]+"${keyfiles[@]}"}")
if [ -n "${GRAPHITE_AUDIT_KEY_FILE:-}" ]; then candidates+=("$GRAPHITE_AUDIT_KEY_FILE"); fi
"$bin" audit verify --data-dir "$work/data" ${keys[@]+"${keys[@]}"} --json >"$work/head.json" 2>/dev/null || true
mackey="$(python3 -I - "$work/head.json" ${candidates[@]+"${candidates[@]}"} <<'PY'
import hashlib, json, sys
try:
    head = json.load(open(sys.argv[1])).get("head_key_id")
except Exception:
    sys.exit("backup: cannot read which key the trail's head is under")
if head is None:
    sys.exit(0)  # an unkeyed trail: no .mac
for path in sys.argv[2:]:
    material = bytes.fromhex(open(path).read().strip())
    if hashlib.sha256(b"graphite-audit-key-id-v1\0" + material).hexdigest()[:16] == head:
        print(path)
        sys.exit(0)
sys.exit(f"backup: the trail's head is under key {head} and no key file given is that key; pass the current key with --key-file")
PY
)" || exit 1

archive="$out/graphite-$stamp.tar.gz"
if [ -e "$archive" ]; then
  echo "backup: $archive already exists; not overwriting it" >&2
  exit 73
fi
# Deterministic member order and ownership: two backups of one state are the
# same bytes, and a restore chowns explicitly anyway.
tar --sort=name --owner=0 --group=0 --numeric-owner -C "$work/data" -cf - . | gzip -n -9 >"$archive.partial"
mv "$archive.partial" "$archive"
(cd "$out" && sha256sum -- "${archive##*/}" >"${archive##*/}.sha256")
if [ -n "$mackey" ]; then
  # The key is read from its file by python, never passed on a command line.
  python3 -I - "$mackey" "$archive" >"$archive.mac.partial" <<'PY'
import hashlib, hmac, os, sys
key = open(sys.argv[1], "rb").read().strip()
if len(key) < 32:
    sys.exit("backup: the audit key file is shorter than 32 bytes")
name = os.path.basename(sys.argv[2])
m = hmac.new(key, b"graphite-backup-v1\n" + name.encode() + b"\n", hashlib.sha256)
with open(sys.argv[2], "rb") as f:
    for chunk in iter(lambda: f.read(1 << 20), b""):
        m.update(chunk)
print(f"hmac-sha256-v1 {m.hexdigest()} {name}")
PY
  mv "$archive.mac.partial" "$archive.mac"
else
  echo "backup: the trail is unkeyed: no .mac written; restore.sh will need ALLOW_UNKEYED_ARCHIVE=1" >&2
fi
cp "$work/verify.txt" "$out/graphite-$stamp.verify.txt"
echo "backup: $archive"
sed 's/^/  /' "$work/verify.txt"
