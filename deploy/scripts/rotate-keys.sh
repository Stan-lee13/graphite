#!/usr/bin/env bash
# Key rotation helper: generates the new secret where the server reads it,
# keeps the old one, and never prints a secret. The procedure around it
# (client switch-over, restart, confirmation) is docs/ops/keys.md.
#
#   rotate-keys.sh env ENV_FILE VAR       new value for VAR in an env file
#                                         (GRAPHITE_API_KEY, _ADMIN_API_KEY,
#                                         _READ_API_KEY): ENV_FILE is copied to
#                                         ENV_FILE.<stamp> first
#   rotate-keys.sh file PATH              new secret in a one-secret file (the
#                                         compose secrets in deploy/compose/):
#                                         PATH is kept as PATH.<stamp>
#   rotate-keys.sh audit-key DIR [UID:GID]
#                                         a new audit MAC key, DIR/audit-<stamp>.key,
#                                         mode 0600; the old key files stay —
#                                         verifying older records needs them
#   rotate-keys.sh verify DATA_DIR KEY_FILE...
#                                         after an audit-key rotation: every
#                                         link and every MAC, under all keys
#                                         (graphite audit verify; exit 0 = all
#                                         checked, 2 = a key is missing)
#
# A secret is 32 random bytes as 64 hex characters (the server requires 32+
# characters and refuses equal keys). Restart the server afterwards: keys are
# read at startup only, and the old API key stops working at that moment.
set -euo pipefail

usage() { sed -n '6,21p' "$0" >&2; exit 64; }
umask 077
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
secret() { openssl rand -hex 32; }

cmd="${1:-}"
[ $# -gt 0 ] && shift
case "$cmd" in
  env)
    [ $# -eq 2 ] || usage
    file="$1" var="$2"
    case "$var" in
      GRAPHITE_API_KEY | GRAPHITE_ADMIN_API_KEY | GRAPHITE_READ_API_KEY) ;;
      *) echo "rotate: $var is not one of the server's API keys" >&2; exit 64 ;;
    esac
    [ -f "$file" ] || { echo "rotate: $file does not exist" >&2; exit 66; }
    cp -p -- "$file" "$file.$stamp"
    tmp="$(mktemp "$file.XXXXXX")"
    trap 'rm -f "$tmp"' EXIT
    new="$(secret)"
    # Replace the line, or append one; every other line is copied unchanged.
    awk -v var="$var" -v val="$new" '
      BEGIN { done = 0 }
      $0 ~ "^[[:space:]]*" var "=" { if (!done) print var "=" val; done = 1; next }
      { print }
      END { if (!done) print var "=" val }
    ' "$file" >"$tmp"
    chmod 0600 "$tmp"
    mv -f -- "$tmp" "$file"
    trap - EXIT
    echo "rotate: $var replaced in $file (previous file: $file.$stamp)."
    echo "        Hand the new value to its clients from the file, restart the server, then delete $file.$stamp."
    ;;
  file)
    [ $# -eq 1 ] || usage
    path="$1"
    prev=""
    if [ -e "$path" ]; then cp -p -- "$path" "$path.$stamp"; prev=" (previous: $path.$stamp)"; fi
    tmp="$(mktemp "$path.XXXXXX")"
    trap 'rm -f "$tmp"' EXIT
    secret >"$tmp"
    chmod 0600 "$tmp"
    mv -f -- "$tmp" "$path"
    trap - EXIT
    echo "rotate: new secret in $path$prev"
    ;;
  audit-key)
    if [ $# -lt 1 ] || [ $# -gt 2 ]; then usage; fi
    dir="$1" owner="${2:-}"
    [ -d "$dir" ] || { echo "rotate: $dir does not exist" >&2; exit 66; }
    key="$dir/audit-$stamp.key"
    (set -o noclobber; secret >"$key")
    chmod 0600 "$key"
    [ -n "$owner" ] && chown -- "$owner" "$key"
    echo "rotate: new audit key $key"
    echo "        Point GRAPHITE_AUDIT_KEY_FILE (or the credential/secret that feeds it) at it, restart, then:"
    echo "        rotate-keys.sh verify <data dir> <every old key file> $key"
    ;;
  verify)
    [ $# -ge 2 ] || usage
    data="$1"
    shift
    args=()
    for k in "$@"; do args+=(--key-file "$k"); done
    rc=0
    "${GRAPHITE_BIN:-graphite}" audit verify --data-dir "$data" "${args[@]}" || rc=$?
    case "$rc" in
      0) echo "rotate: every link and every MAC verified under the keys given" ;;
      2) echo "rotate: some MACs are under a key not given — pass every key file the trail was written under" >&2 ;;
      *) echo "rotate: the trail does not verify (exit $rc): docs/ops/incidents.md, \"Audit-integrity alert\"" >&2 ;;
    esac
    exit "$rc"
    ;;
  *) usage ;;
esac
