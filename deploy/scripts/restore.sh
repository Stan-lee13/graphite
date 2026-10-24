#!/usr/bin/env bash
# Restore a Graphite data directory from an archive made by backup.sh, and
# prove the restored trail before the server sees it.
#
#   restore.sh [--key-file F]... --anchor-dir D [--owner UID:GID] ARCHIVE DATA_DIR
#
# 1. Refuses while a server holds DATA_DIR/graphite.lock (stop it first).
#    Refuses without --anchor-dir (exit 64) unless ALLOW_NO_ANCHOR=1: without
#    the anchored checkpoints a stale or rolled-back archive cannot be told
#    from a current one (Round 34, D-6).
# 2. Checks ARCHIVE against ARCHIVE.sha256, which must name ARCHIVE itself
#    (one line, its own file name): `sha256sum -c` checks whatever file the
#    list names, so a list naming another archive "verified" this one.
#    Then ARCHIVE.mac (backup.sh): an HMAC-SHA256 of the archive's name and
#    bytes under the audit key, so the graph snapshot and registry_state.json
#    are authenticated too, not only the trail `audit verify` walks. It must
#    verify under one of the --key-file keys (or GRAPHITE_AUDIT_KEY_FILE).
#    An archive with no .mac (an unkeyed trail) needs ALLOW_UNKEYED_ARCHIVE=1.
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
# Needs: bash, tar, gzip, sha256sum, flock, python3, graphite (GRAPHITE_BIN).
set -euo pipefail

usage() { sed -n '5p' "$0" >&2; exit 64; }

keys=()
keyfiles=()
anchors=""
owner=""
while [ $# -gt 0 ]; do
  case "$1" in
    --key-file) keys+=(--key-file "$2"); keyfiles+=("$2"); shift 2 ;;
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

if [ -z "$anchors" ] && [ "${ALLOW_NO_ANCHOR:-0}" != 1 ]; then
  echo "restore: --anchor-dir is required: without the anchored checkpoints a stale or rolled-back archive" >&2
  echo "         cannot be detected. Set ALLOW_NO_ANCHOR=1 only for a deployment that has never anchored one." >&2
  exit 64
fi

[ -f "$archive.sha256" ] || { echo "restore: $archive.sha256 is missing; refusing an unchecked archive" >&2; exit 66; }
# The list must name this archive and nothing else.
name="$(basename "$archive")"
line=""
[ "$(wc -l <"$archive.sha256")" = 1 ] && IFS= read -r line <"$archive.sha256"
if ! [[ "$line" =~ ^[0-9a-f]{64}\ [\ *](.*)$ ]] || [ "${BASH_REMATCH[1]}" != "$name" ]; then
  echo "restore: $archive.sha256 does not name $name alone; refusing it" >&2
  exit 1
fi
(cd "$(dirname "$archive")" && sha256sum --quiet -c -- "$name.sha256") || {
  echo "restore: $archive does not match its checksum" >&2
  exit 1
}

# The archive's MAC under the audit key (backup.sh writes it).
mackeys=("${keyfiles[@]+"${keyfiles[@]}"}")
if [ -n "${GRAPHITE_AUDIT_KEY_FILE:-}" ]; then mackeys+=("$GRAPHITE_AUDIT_KEY_FILE"); fi
if [ ! -f "$archive.mac" ]; then
  if [ "${ALLOW_UNKEYED_ARCHIVE:-0}" = 1 ]; then
    echo "restore: ALLOW_UNKEYED_ARCHIVE=1 — $archive has no .mac; only its trail is checked" >&2
  else
    echo "restore: $archive.mac is missing; refusing an archive nothing authenticates" >&2
    echo "         (an unkeyed deployment's backup: ALLOW_UNKEYED_ARCHIVE=1)" >&2
    exit 66
  fi
elif [ "${#mackeys[@]}" -eq 0 ]; then
  echo "restore: $archive.mac cannot be checked without the audit key; pass --key-file" >&2
  exit 1
elif ! python3 -I - "$archive" "${mackeys[@]}" <<'PY'
import hashlib, hmac, os, sys
archive, keys = sys.argv[1], sys.argv[2:]
name = os.path.basename(archive)
fields = open(archive + ".mac").read().split()
if len(fields) != 3 or fields[0] != "hmac-sha256-v1" or fields[2] != name:
    sys.exit(f"restore: {archive}.mac is not a MAC of {name}")
macs = []
for k in keys:
    key = open(k, "rb").read().strip()
    macs.append(hmac.new(key, b"graphite-backup-v1\n" + name.encode() + b"\n", hashlib.sha256))
with open(archive, "rb") as f:
    for chunk in iter(lambda: f.read(1 << 20), b""):
        for m in macs:
            m.update(chunk)
sys.exit(0 if any(hmac.compare_digest(m.hexdigest(), fields[1]) for m in macs) else 1)
PY
then
  echo "restore: $archive does not match its MAC under any key given; refusing it" >&2
  exit 1
fi

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
