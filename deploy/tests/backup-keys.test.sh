#!/usr/bin/env bash
# `A && ok … || bad …` is deliberate: ok always succeeds (SC2015).
# shellcheck disable=SC2015
# Which key backup.sh MACs an archive under, which key restore.sh accepts a
# .mac under, and which anchored checkpoint restore.sh checks against
# (Round 39: R37-11, T-9). Needs no server: the trail is written by
# `graphite quarantine add`, which writes the server's trail offline.
#
# The rules under test (docs/ops/backup-restore.md):
#
# - backup.sh MACs the archive under the key the copied trail's head is MAC'd
#   under — the key the server writes under now — whatever order the
#   --key-file options come in. Before, it used the last --key-file given, a
#   retired key whenever the operator listed it last.
# - restore.sh accepts the .mac under the CURRENT key only: --current-key-file,
#   else GRAPHITE_AUDIT_KEY_FILE, else the --key-file when exactly one is
#   given; with several keys and none named current it refuses (exit 64).
#   Before, a .mac under ANY key given was accepted, retired keys included,
#   so whoever held an old key could forge registry_state.json or the graph
#   snapshot. A retired key's MAC is never accepted: a holder of the old key
#   can compute one over any bytes at any time, so nothing about the archive
#   proves it was made before the rotation.
# - restore.sh checks against the anchored checkpoint with the highest seq by
#   CONTENT, not by file name: a file name is not authenticated, so an old
#   checkpoint copied under a name that sorts last made a stale archive pass.
#
#   GRAPHITE_BIN  default: graphite from PATH
#
# Exit 0 only when every check passed.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
deploy="$(dirname "$here")"
G="${GRAPHITE_BIN:-graphite}"
export GRAPHITE_BIN="$G"
unset GRAPHITE_AUDIT_KEY_FILE GRAPHITE_AUDIT_PREVIOUS_KEY_FILE GRAPHITE_DATA_DIR

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "  ok   $*"; }
bad() { fail=$((fail + 1)); echo "  FAIL $*"; }
expect_rc() { # expect_rc RC DESCRIPTION COMMAND...
  local want="$1" d="$2" rc=0
  shift 2
  "$@" >"$T/last.out" 2>&1 || rc=$?
  if [ "$rc" = "$want" ]; then ok "$d (exit $rc)"; else bad "$d (exit $rc, wanted $want)"; sed 's/^/       /' "$T/last.out"; fi
}

T="$(mktemp -d)" && [ -n "$T" ] && [ -d "$T" ] || { echo "cannot create a scratch directory" >&2; exit 1; }
trap 'rm -rf "$T"' EXIT

D="$T/data"
mkdir -p "$D" "$T/keys" "$T/anchors" "$T/backups"
chmod 700 "$T/keys"
openssl rand -hex 32 >"$T/keys/k1.key"
openssl rand -hex 32 >"$T/keys/k2.key"
chmod 600 "$T/keys/k1.key" "$T/keys/k2.key"
K1="$T/keys/k1.key"
K2="$T/keys/k2.key"

qadd() { # qadd KEY_FILE PROGRAM [PREVIOUS_KEY_FILE] — one keyed record
  env GRAPHITE_AUDIT_KEY_FILE="$1" ${3:+GRAPHITE_AUDIT_PREVIOUS_KEY_FILE="$3"} \
    "$G" quarantine add --data-dir "$D" --program "$2" --reason "backup key test" >/dev/null 2>&1
}
# mac_of KEY_FILE ARCHIVE — a .mac line as backup.sh writes it.
mac_of() {
  python3 -I - "$1" "$2" <<'PY'
import hashlib, hmac, os, sys
key = open(sys.argv[1], "rb").read().strip()
name = os.path.basename(sys.argv[2])
m = hmac.new(key, b"graphite-backup-v1\n" + name.encode() + b"\n" + open(sys.argv[2], "rb").read(), hashlib.sha256)
print(f"hmac-sha256-v1 {m.hexdigest()} {name}")
PY
}

echo "== a trail rotated from k1 to k2"
qadd "$K1" 11111111111111111111111111111111 && ok "a record under k1" || bad "a record under k1"
qadd "$K1" Vote111111111111111111111111111111111111111 && ok "another record under k1" || bad "another record under k1"
"$G" audit checkpoint --data-dir "$D" --key-file "$K1" --out "$T/cp-early.json" >/dev/null 2>&1 &&
  ok "an early checkpoint (under k1)" || bad "no early checkpoint"
qadd "$K2" Stake11111111111111111111111111111111111111 "$K1" && ok "rotated to k2 (adoption record)" || bad "rotation to k2"
qadd "$K2" Config1111111111111111111111111111111111111 && ok "a record under k2" || bad "a record under k2"
expect_rc 0 "the trail verifies with both keys" "$G" audit verify --data-dir "$D" --key-file "$K1" --key-file "$K2"

echo "== backup.sh MACs under the head's key, not the last --key-file"
# The retired key listed last, as an operator listing keys newest first would.
expect_rc 0 "backup.sh --key-file k2 --key-file k1" "$deploy/scripts/backup.sh" --hot --key-file "$K2" --key-file "$K1" "$D" "$T/backups"
A="$(find "$T/backups" -name 'graphite-*.tar.gz' | head -n 1)"
[ -n "$A" ] && [ -f "$A.mac" ] || { bad "no archive or no .mac"; echo "$pass passed, $fail failed"; exit 1; }
cmp -s <(mac_of "$K2" "$A") "$A.mac" && ok "the .mac is under k2, the key the trail's head is under" ||
  bad "the .mac is not under k2 (the current key)"
cmp -s <(mac_of "$K1" "$A") "$A.mac" && bad "the .mac is under k1, a retired key" || ok "the .mac is not under k1"

echo "== restore.sh accepts a .mac under the current key only"
R=(env ALLOW_NO_ANCHOR=1 "$deploy/scripts/restore.sh" --key-file "$K1" --key-file "$K2")
expect_rc 0 "the genuine archive restores (current key: GRAPHITE_AUDIT_KEY_FILE=k2)" env GRAPHITE_AUDIT_KEY_FILE="$K2" "${R[@]}" "$A" "$T/r-genuine"
expect_rc 0 "the genuine archive restores (--current-key-file k2)" "${R[@]}" --current-key-file "$K2" "$A" "$T/r-current"
expect_rc 64 "with two keys and none named current, restore.sh refuses" "${R[@]}" "$A" "$T/r-unnamed"
[ ! -e "$T/r-unnamed" ] && ok "the refused restore wrote nothing" || bad "the refused restore wrote $T/r-unnamed"
# Whoever holds the retired k1 forges registry_state.json and MACs the
# archive under k1. The trail inside is genuine, so `audit verify` passes.
mkdir -p "$T/forge"
tar -C "$T/forge" -xzf "$A"
echo '{"forged":true}' >"$T/forge/registry_state.json"
F="$T/backups/forged.tar.gz"
tar -C "$T/forge" -czf "$F" .
(cd "$T/backups" && sha256sum forged.tar.gz >forged.tar.gz.sha256)
mac_of "$K1" "$F" >"$F.mac"
expect_rc 1 "a .mac under the retired k1 is refused (current: GRAPHITE_AUDIT_KEY_FILE=k2)" env GRAPHITE_AUDIT_KEY_FILE="$K2" "${R[@]}" "$F" "$T/r-forged"
expect_rc 1 "a .mac under the retired k1 is refused (current: --current-key-file k2)" "${R[@]}" --current-key-file "$K2" "$F" "$T/r-forged2"
[ ! -e "$T/r-forged" ] && [ ! -e "$T/r-forged2" ] && ok "the forged archive was not restored" || bad "the forged archive was restored"

echo "== restore.sh picks the newest anchored checkpoint by content, not by name"
qadd "$K2" SysvarRent111111111111111111111111111111111 && ok "a record after the backup" || bad "a record after the backup"
"$G" audit checkpoint --data-dir "$D" --key-file "$K2" --out "$T/cp-new.json" >/dev/null 2>&1 &&
  ok "a checkpoint newer than the backup" || bad "no newer checkpoint"
seq_new="$(jq -r .seq "$T/cp-new.json")"
cp "$T/cp-new.json" "$T/anchors/$(printf 'audit.jsonl-checkpoint-%020d-scheduled.json' "$seq_new")"
# The early checkpoint, which the stale archive does contain, copied under a
# name that sorts after every real one.
cp "$T/cp-early.json" "$T/anchors/audit.jsonl-checkpoint-99999999999999999999.json"
RA=(env GRAPHITE_AUDIT_KEY_FILE="$K2" "$deploy/scripts/restore.sh" --key-file "$K1" --key-file "$K2" --anchor-dir "$T/anchors")
expect_rc 1 "the stale archive is refused against the checkpoint with the highest seq" "${RA[@]}" "$A" "$T/r-stale"
[ ! -e "$T/r-stale" ] && ok "the stale archive was not restored" || bad "the stale archive was restored"
expect_rc 0 "ACCEPT_STALE_RESTORE=1 restores it" env ACCEPT_STALE_RESTORE=1 "${RA[@]}" "$A" "$T/r-stale-ok"
echo 'not json' >"$T/anchors/audit.jsonl-checkpoint-00000000000000000000.json"
expect_rc 1 "an anchored checkpoint that is not JSON refuses the restore" env ACCEPT_STALE_RESTORE=1 "${RA[@]}" "$A" "$T/r-badanchor"

echo
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
