#!/usr/bin/env bash
# Turn Graphite's /health `degraded_reasons` into Prometheus series for the
# node_exporter textfile collector. `simulation_baseline_frozen` (and the
# reasons in general) are reported only on /health, not on /metrics; this is
# what lets deploy/prometheus/graphite-alerts.yml alert on them.
#
#   GRAPHITE_HEALTH_URL  default http://127.0.0.1:7331/health (no key needed)
#   TEXTFILE_DIR         node_exporter --collector.textfile.directory
#
# Run every minute (cron, or a systemd timer). The file is replaced
# atomically, so the collector never reads half of it. When /health cannot be
# reached, graphite_health_up is 0 and no reason series is written: the
# GraphiteDown alert covers that case, not a stale "healthy".
#
# Needs: bash, curl, jq.
set -euo pipefail

url="${GRAPHITE_HEALTH_URL:-http://127.0.0.1:7331/health}"
dir="${TEXTFILE_DIR:?set TEXTFILE_DIR to the node_exporter textfile directory}"
out="$dir/graphite_health.prom"

# Every reason server.rs can report; each is written as 0 when absent so an
# alert can tell "cleared" from "never scraped".
known="audit_writes_failed audit_rotation_failed audit_anchor_failed audit_disabled graph_snapshot_failed simulation_baseline_frozen"

tmp="$(mktemp "$dir/.graphite_health.XXXXXX")"
trap 'rm -f "$tmp"' EXIT

{
  echo "# HELP graphite_health_up 1 when /health answered with a parseable body."
  echo "# TYPE graphite_health_up gauge"
  if body="$(curl -fsS --max-time 5 "$url")" && reasons="$(jq -er '.degraded_reasons | join(" ")' <<<"$body")"; then
    echo "graphite_health_up 1"
    echo "# HELP graphite_health_degraded 1 while /health lists this degraded reason."
    echo "# TYPE graphite_health_degraded gauge"
    for r in $known; do
      v=0
      case " $reasons " in *" $r "*) v=1 ;; esac
      echo "graphite_health_degraded{reason=\"$r\"} $v"
    done
    # A reason added to the server after this script was written still alerts.
    for r in $reasons; do
      case " $known " in *" $r "*) ;; *) echo "graphite_health_degraded{reason=\"$r\"} 1" ;; esac
    done
  else
    echo "graphite_health_up 0"
  fi
} >"$tmp"

chmod 0644 "$tmp"
mv -f "$tmp" "$out"
trap - EXIT
