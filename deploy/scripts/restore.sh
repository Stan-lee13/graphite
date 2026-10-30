#!/usr/bin/env bash
# Restore a Graphite data directory from an archive made by backup.sh, and
# prove the restored trail before the server sees it.
#
#   restore.sh [--key-file F]... [--current-key-file F] [--lost-key KEY_ID]... --anchor-dir D [--owner UID:GID] ARCHIVE DATA_DIR
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
#    verify under the CURRENT key (Round 38, R37-11): --current-key-file, else
#    GRAPHITE_AUDIT_KEY_FILE, else the --key-file when exactly one is given;
#    with several keys and none named current the restore refuses (exit 64).
#    A .mac under any other key given — a retired one — is refused: whoever
#    still holds a retired key can MAC any bytes under it, so it could forge
#    registry_state.json or the graph snapshot (it used to be accepted under
#    ANY key given). backup.sh MACs under the key the trail's head is under.
#    A backup taken before a key rotation is therefore refused after it; take
#    a fresh backup after every rotation. Restoring such a backup anyway is
#    naming its key with --current-key-file, your explicit decision (record it
#    in the incident log).
#    An archive with no .mac (an unkeyed trail) needs ALLOW_UNKEYED_ARCHIVE=1.
# 3. Unpacks into a staging directory beside DATA_DIR and runs
#    `graphite audit verify` on it: exit 0 is required (every link, and every
#    MAC under the keys given). Nothing is touched if it fails.
# 4. With --anchor-dir, also verifies against the newest anchored checkpoint:
#    the one with the highest seq by its CONTENT (Round 38, T-9), never by
#    its file name, which nothing authenticates (an old checkpoint copied
#    under a name that sorts last made a stale archive pass). A checkpoint
#    file that cannot be read refuses the restore. A restore from a backup older than that checkpoint FAILS this check —
#    that is the checkpoint doing its job: the verdicts recorded after the
#    backup are gone. The script then stops unless ACCEPT_STALE_RESTORE=1,
#    which you set only after recording the loss in the incident log.
# 5. Moves the current DATA_DIR aside to DATA_DIR.pre-restore-<stamp> (never
#    deleted) and the staging directory into place; chowns it to --owner
#    (10001:10001 for the container image), then verifies once more in place.
#
# --lost-key KEY_ID: a trail continued under a new key after the old one was
# lost (`graphite audit adopt-key`) verifies with exit 2 from then on; see
# backup.sh. The same check: that exit 2 is accepted only when the only
# records not MAC-checked are under the keys named here, each followed by a
# verified key-adoption record, in steps 3 to 5 alike.
#
# Needs: bash, tar, gzip, sha256sum, flock, python3, graphite (GRAPHITE_BIN).
set -euo pipefail

usage() { sed -n '5p' "$0" >&2; exit 64; }

keys=()
keyfiles=()
lost=()
anchors=""
owner=""
current=""
while [ $# -gt 0 ]; do
  case "$1" in
    --key-file) keys+=(--key-file "$2"); keyfiles+=("$2"); shift 2 ;;
    --current-key-file) current="$2"; keys+=(--key-file "$2"); shift 2 ;;
    --lost-key)
      [[ "${2:-}" =~ ^[0-9a-f]{16}$ ]] || { echo "restore: --lost-key takes a key id (16 hex digits)" >&2; exit 64; }
      lost+=("$2")
      shift 2
      ;;
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

# The archive's MAC under the current audit key (backup.sh writes it).
if [ -z "$current" ]; then
  if [ -n "${GRAPHITE_AUDIT_KEY_FILE:-}" ]; then
    current="$GRAPHITE_AUDIT_KEY_FILE"
  elif [ "${#keyfiles[@]}" -eq 1 ]; then
    current="${keyfiles[0]}"
  fi
fi
mackeys=()
[ -n "$current" ] && mackeys=("$current")
if [ ! -f "$archive.mac" ]; then
  if [ "${ALLOW_UNKEYED_ARCHIVE:-0}" = 1 ]; then
    echo "restore: ALLOW_UNKEYED_ARCHIVE=1 — $archive has no .mac; only its trail is checked" >&2
  else
    echo "restore: $archive.mac is missing; refusing an archive nothing authenticates" >&2
    echo "         (an unkeyed deployment's backup: ALLOW_UNKEYED_ARCHIVE=1)" >&2
    exit 66
  fi
elif [ "${#mackeys[@]}" -eq 0 ] && [ "${#keyfiles[@]}" -gt 1 ]; then
  echo "restore: several keys given and none named current: the .mac is accepted only under the key the" >&2
  echo "         server writes under now. Pass it with --current-key-file (or set GRAPHITE_AUDIT_KEY_FILE)" >&2
  exit 64
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
  echo "restore: $archive does not match its MAC under the current key ($current); refusing it" >&2
  echo "         (a .mac under a retired key is never accepted: docs/ops/backup-restore.md)" >&2
  exit 1
fi

parent="$(dirname "$data")"
mkdir -p "$parent"
umask 077
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
stage="$(mktemp -d "$parent/.restore-$stamp.XXXXXX")"
report="$(mktemp "$parent/.restore-$stamp.report.XXXXXX")"
trap 'rm -rf "$stage" "$report"' EXIT

tar -C "$stage" --no-same-owner -xzf "$archive"

# only_lost_keys_unchecked REPORT.json KEY_ID... — the check backup.sh makes:
# exit 0 when the only thing `audit verify --json` could not prove is the MACs
# under the named lost keys.
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

verify() { # verify DIR [--checkpoint F]
  local dir="$1" rc=0
  shift
  "$bin" audit verify --data-dir "$dir" ${keys[@]+"${keys[@]}"} "$@" || rc=$?
  if [ "$rc" = 2 ] && [ "${#lost[@]}" -gt 0 ]; then
    "$bin" audit verify --data-dir "$dir" ${keys[@]+"${keys[@]}"} "$@" --json >"$report" 2>/dev/null || true
    only_lost_keys_unchecked "$report" "${lost[@]}" && rc=0
  fi
  return "$rc"
}

echo "restore: verifying the unpacked trail"
if ! verify "$stage"; then
  echo "restore: the archive's trail does not verify with the keys given; nothing changed" >&2
  exit 1
fi

if [ -n "$anchors" ]; then
  # The newest checkpoint is the one whose CONTENT has the highest seq (Round
  # 38, T-9): a file name is not authenticated, and the checkpoint's own MAC
  # is checked by `audit verify --checkpoint` below. Every checkpoint with that
  # seq is checked. A checkpoint file that cannot be read refuses the restore:
  # it could be the newest.
  if ! newest_list="$(python3 -I - "$anchors" <<'PY'
import json, os, sys
d = sys.argv[1]
found = []
for name in sorted(os.listdir(d)):
    if not (name.startswith("audit.jsonl-checkpoint-") and name.endswith(".json")):
        continue
    path = os.path.join(d, name)
    if not os.path.isfile(path):
        continue
    try:
        with open(path, "rb") as f:
            cp = json.loads(f.read(1 << 16))
        seq = cp["seq"]
        if cp.get("kind") != "graphite-audit-checkpoint" or not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
            raise ValueError("not a checkpoint")
    except Exception as e:
        sys.exit(f"restore: anchored checkpoint {name} cannot be read ({e}); refusing: it could be the newest")
    found.append((seq, path))
if found:
    top = max(s for s, _ in found)
    print("\n".join(p for s, p in found if s == top))
PY
)"; then
    exit 1
  fi
  if [ -z "$newest_list" ]; then
    echo "restore: no checkpoint in $anchors; a stale restore cannot be detected" >&2
  else
    while IFS= read -r newest; do
      echo "restore: verifying against the newest anchored checkpoint ${newest##*/}"
      if ! verify "$stage" --checkpoint "$newest"; then
        if [ "${ACCEPT_STALE_RESTORE:-0}" = 1 ]; then
          echo "restore: ACCEPT_STALE_RESTORE=1 — restoring a trail that does not hold against ${newest##*/}" >&2
        else
          echo "restore: this archive does not hold against the anchored checkpoint ${newest##*/} (it ends before it:" >&2
          echo "         records after the backup are lost; or the checkpoint is not genuine). Record that in the" >&2
          echo "         incident log, then re-run with ACCEPT_STALE_RESTORE=1." >&2
          exit 1
        fi
      fi
    done <<<"$newest_list"
  fi
fi

if [ -e "$data" ]; then
  mv -- "$data" "$data.pre-restore-$stamp"
  echo "restore: previous directory kept at $data.pre-restore-$stamp"
fi
mv -- "$stage" "$data"
trap 'rm -f "$report"' EXIT
chmod 0700 "$data"
[ -n "$owner" ] && chown -R -- "$owner" "$data"

echo "restore: verifying in place"
verify "$data" >/dev/null
echo "restore: $data restored from $archive"
