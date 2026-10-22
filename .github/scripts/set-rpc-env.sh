#!/usr/bin/env bash
# set-rpc-env.sh URL ENV_FILE — hand the live workflows' RPC URL to later steps
# (Round 34, D-9). live-devnet.yml and live-mainnet.yml take the URL from a
# secret or from a workflow_dispatch input; the input was written into
# $GITHUB_ENV as `LIVE_RPC_URL=$rpc`, unchecked, so a value with a newline set
# any further variable for every later step (LD_PRELOAD, NODE_OPTIONS, …), and
# printing it into `::add-mask::` first could also issue a workflow command.
#
# Now: the value must be exactly one http(s) URL with no whitespace (newlines
# included), checked BEFORE anything prints it; it is masked, then written in
# GitHub's `NAME<<DELIMITER` form with a random delimiter. Refused: exit 1,
# nothing written, the value never echoed.
set -euo pipefail

[ $# -eq 2 ] || { echo "usage: set-rpc-env.sh URL ENV_FILE" >&2; exit 64; }
rpc="$1"
out="$2"
if ! [[ "$rpc" =~ ^https?://[^[:space:]]+$ ]]; then
  echo "::error::the RPC URL is not a single http(s) URL without whitespace; refusing it (value not shown)"
  exit 1
fi
echo "::add-mask::$rpc"
delim="LIVE_RPC_URL_$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
printf 'LIVE_RPC_URL<<%s\n%s\n%s\n' "$delim" "$rpc" "$delim" >>"$out"
