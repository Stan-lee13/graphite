#!/usr/bin/env bash
# Back up a Graphite data directory to a verified, checksummed archive.
#
#   backup.sh [--hot] [--key-file F]... DATA_DIR OUT_DIR
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
# every key with --key-file, or GRAPHITE_AUDIT_KEY_FILE). The audit MAC key is
# NOT in the archive (it lives outside the data directory by design); back it
# up separately, to a different place.
#
# Output: OUT_DIR/graphite-<UTC stamp>.tar.gz and .sha256, mode 0600.
# Needs: bash, tar, gzip, sha256sum, flock, graphite (GRAPHITE_BIN).
set -euo pipefail

usage() { sed -n '2,4p' "$0" >&2; exit 64; }

hot=0
keys=()
while [ $# -gt 0 ]; do
  case "$1" in
    --hot) hot=1; shift ;;
    --key-file) keys+=(--key-file "$2"); shift 2 ;;
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
cp "$work/verify.txt" "$out/graphite-$stamp.verify.txt"
echo "backup: $archive"
sed 's/^/  /' "$work/verify.txt"
