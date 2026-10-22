#!/usr/bin/env bash
# Export a checkpoint of the audit trail's head and ship every checkpoint off
# the host. Run it on a schedule (deploy/systemd/graphite-anchor.timer runs it
# hourly), beside the server: `graphite audit checkpoint` reads the trail and
# takes no lock.
#
#   GRAPHITE_DATA_DIR        the server's data directory
#   GRAPHITE_AUDIT_ANCHOR_DIR where checkpoints are kept on the host (the same
#                            directory the server writes rotation checkpoints to)
#   GRAPHITE_AUDIT_KEY_FILE  the audit MAC key: the checkpoint is MAC'd with it
#   ANCHOR_S3_URI            optional, s3://bucket/prefix — a bucket created
#                            with Object Lock. Each checkpoint not yet uploaded
#                            is put once, in COMPLIANCE mode, retained for
#                            ANCHOR_RETAIN_DAYS (default 400). Needs the aws CLI
#                            and credentials allowed s3:PutObject and
#                            s3:PutObjectRetention on that prefix only — never
#                            delete or bypass-governance.
#
# A checkpoint is what lets `graphite audit verify --checkpoint` detect a
# dropped tail or an older backup restored in place (docs/ops/keys.md). On the
# host it protects nothing against someone who controls the host: the copy
# that counts is the one the host cannot rewrite.
set -euo pipefail

bin="${GRAPHITE_BIN:-graphite}"
data="${GRAPHITE_DATA_DIR:?set GRAPHITE_DATA_DIR}"
anchors="${GRAPHITE_AUDIT_ANCHOR_DIR:?set GRAPHITE_AUDIT_ANCHOR_DIR}"
[ -d "$anchors" ] || { echo "anchor: $anchors does not exist" >&2; exit 66; }

# The server names rotation checkpoints audit.jsonl-checkpoint-<seq 20 digits>.json
# and creates them exclusively. Scheduled ones carry a `-scheduled` suffix: the
# same prefix, so one sort orders them all, but never the server's name — if
# they collided at a rotation, the server's anchor write would fail and
# /health would report audit_anchor_failed.
tmp="$(mktemp "$anchors/.checkpoint.XXXXXX")"
rm -f "$tmp"
trap 'rm -f "$tmp"' EXIT
"$bin" audit checkpoint --data-dir "$data" --out "$tmp"
seq="$(sed -n 's/.*"seq"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$tmp" | head -n 1)"
[ -n "$seq" ] || { echo "anchor: no seq in the exported checkpoint" >&2; exit 1; }
name="$(printf 'audit.jsonl-checkpoint-%020d-scheduled.json' "$seq")"
if [ -e "$anchors/$name" ] || [ -e "$anchors/${name%-scheduled.json}.json" ]; then
  # Nothing appended since the last one; the existing file is the anchor.
  rm -f "$tmp"
else
  chmod 0400 "$tmp"
  mv -n -- "$tmp" "$anchors/$name"
  echo "anchor: $name"
fi
trap - EXIT

[ -n "${ANCHOR_S3_URI:-}" ] || exit 0

uri="${ANCHOR_S3_URI%/}"
bucket="${uri#s3://}"
prefix="${bucket#*/}"
bucket="${bucket%%/*}"
[ "$prefix" = "$bucket" ] && prefix=""
[ -n "$prefix" ] && prefix="$prefix/"
days="${ANCHOR_RETAIN_DAYS:-400}"
until="$(date -u -d "+$days days" +%Y-%m-%dT%H:%M:%SZ)"
sent="$anchors/.uploaded"
touch "$sent"

find "$anchors" -maxdepth 1 -type f -name 'audit.jsonl-checkpoint-*.json' | LC_ALL=C sort | while read -r f; do
  key="$prefix${f##*/}"
  grep -qxF -- "$key" "$sent" && continue
  # --if-none-match: an object already under that key is never replaced; with
  # Object Lock it could not be anyway, but the upload then fails loudly.
  aws s3api put-object --bucket "$bucket" --key "$key" --body "$f" \
    --if-none-match '*' \
    --checksum-algorithm SHA256 \
    --object-lock-mode COMPLIANCE \
    --object-lock-retain-until-date "$until" >/dev/null
  echo "$key" >>"$sent"
  echo "anchor: uploaded s3://$bucket/$key (retained until $until)"
done
