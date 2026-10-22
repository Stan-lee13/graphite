#!/usr/bin/env bash
# Restore a Graphite data directory from an archive made by backup.sh, and
# prove the restored trail before the server sees it.
#
#   restore.sh [--key-file F]... [--anchor-dir D] [--owner UID:GID] ARCHIVE DATA_DIR
#
# 1. Refuses while a server holds DATA_DIR/graphite.lock (stop it first).
# 2. Checks ARCHIVE against ARCHIVE.sha256.
# 3. Unpacks into a staging directory beside DATA_DIR and runs
#    `graphite audit verify` on it: exit 0 is required (every link, and every
#    MAC under the keys given). Nothing is touched if it fails.
# 4. With --anchor-dir, also verifies against the newest anchored checkpoint.
#    A restore from a backup older than that checkpoint FAILS this check —
#    that is the checkpoint doing its job: the verdicts recorded after the
#    backup are gone. The script then stops unless ACCEPT_STALE_RESTORE=1,
#    which you set only after recording the loss in the incident log.
# 5. Moves the current DATA_DIR aside to DATA_DIR.pre-restore-<stamp> (never
#    deleted) and the staging directory into place; chowns it to --owner
#    (10001:10001 for the container image), then verifies once more in place.
#
# Needs: bash, tar, gzip, sha256sum, flock, graphite (GRAPHITE_BIN).
set -euo pipefail

usage() { sed -n '5p' "$0" >&2; exit 64; }

keys=()
anchors=""
owner=""
while [ $# -gt 0 ]; do
  case "$1" in
    --key-file) keys+=(--key-file "$2"); shift 2 ;;
    --anchor-dir) anchors="$2"; shift 2 ;;
    --owner) owner="$2"; shift 2 ;;
    -h | --help) usage ;;
    --) shift; break ;;
    -*) echo "unknown option $1" >&2; usage ;;
    *) break ;;
  esac
done
[ $# -eq 2 ] || usage
archive="$1"
data="${2%/}"
bin="${GRAPHITE_BIN:-graphite}"

if [ -e "$data/graphite.lock" ] && ! flock -n -E 75 "$data/graphite.lock" true 2>/dev/null; then
  echo "restore: a server holds $data/graphite.lock; stop it first" >&2
  exit 75
fi

[ -f "$archive.sha256" ] || { echo "restore: $archive.sha256 is missing; refusing an unchecked archive" >&2; exit 66; }
(cd "$(dirname "$archive")" && sha256sum --quiet -c -- "$(basename "$archive").sha256") || {
  echo "restore: $archive does not match its checksum" >&2
  exit 1
}

parent="$(dirname "$data")"
mkdir -p "$parent"
umask 077
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
stage="$(mktemp -d "$parent/.restore-$stamp.XXXXXX")"
trap 'rm -rf "$stage"' EXIT

tar -C "$stage" --no-same-owner -xzf "$archive"

verify() { # verify DIR [--checkpoint F]
  local dir="$1"
  shift
  "$bin" audit verify --data-dir "$dir" ${keys[@]+"${keys[@]}"} "$@"
}

echo "restore: verifying the unpacked trail"
if ! verify "$stage"; then
  echo "restore: the archive's trail does not verify with the keys given; nothing changed" >&2
  exit 1
fi

if [ -n "$anchors" ]; then
  # Checkpoint files are named audit.jsonl-checkpoint-<20-digit seq>[-scheduled].json
  # (the server's and anchor-checkpoints.sh's), so the lexically last one is
  # the newest.
  newest="$(find "$anchors" -maxdepth 1 -type f -name 'audit.jsonl-checkpoint-*.json' | LC_ALL=C sort | tail -n 1)"
  if [ -z "$newest" ]; then
    echo "restore: no checkpoint in $anchors; a stale restore cannot be detected" >&2
  else
    echo "restore: verifying against the newest anchored checkpoint ${newest##*/}"
    if ! verify "$stage" --checkpoint "$newest"; then
      if [ "${ACCEPT_STALE_RESTORE:-0}" = 1 ]; then
        echo "restore: ACCEPT_STALE_RESTORE=1 — restoring a trail that ends before ${newest##*/}" >&2
      else
        echo "restore: this archive ends before the anchored checkpoint ${newest##*/}: records after the backup are lost." >&2
        echo "         Record that in the incident log, then re-run with ACCEPT_STALE_RESTORE=1." >&2
        exit 1
      fi
    fi
  fi
fi

if [ -e "$data" ]; then
  mv -- "$data" "$data.pre-restore-$stamp"
  echo "restore: previous directory kept at $data.pre-restore-$stamp"
fi
mv -- "$stage" "$data"
trap - EXIT
chmod 0700 "$data"
[ -n "$owner" ] && chown -R -- "$owner" "$data"

echo "restore: verifying in place"
verify "$data" >/dev/null
echo "restore: $data restored from $archive"
