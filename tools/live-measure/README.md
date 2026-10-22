# Live measurement (Round 32)

Two manually dispatched workflows that do what CI cannot: put Graphite in
front of a real cluster. Both write a downloadable report (JSON + Markdown)
and a job summary, and both fail only on a Graphite defect: a public
endpoint's rate limit is reported as INCONCLUSIVE or SKIPPED, never as a
pass and never as a failure.

| workflow | what it runs | artifact |
|---|---|---|
| `.github/workflows/live-mainnet.yml` | recent finalized mainnet blocks → the conformance harness (honest intent) → N transactions replayed through a Core **with an RPC attached** (L3 simulation, L4, the execution decision) → L8 on executed ones | `live-mainnet-report` |
| `.github/workflows/live-devnet.yml` | throwaway keypair → faucet → (optional) operator evidence for the System program → Core + AI layer → `integrations/agent-guard/devnet-test.ts` (the full gated path) → SIGTERM → `graphite audit verify` | `live-devnet-report` |

## Triggering

Actions → the workflow → **Run workflow** (or the API:
`POST /repos/{owner}/{repo}/actions/workflows/live-mainnet.yml/dispatches`
with `{"ref": "<branch>", "inputs": {...}}`). The artifact is on the run's
page under **Artifacts**; the report is also the job summary.

Inputs (all optional):

- mainnet: `rpc_url`, `transactions` (200), `blocks` (2), `pace_seconds`
  (1.0), `l8_checks` (10).
- devnet: `rpc_url`, `seed_evidence` (true), `airdrop_lamports` (5×10⁸).

A provider URL that carries a key goes in a repository secret instead —
`GRAPHITE_LIVE_RPC_URL` (mainnet) or `GRAPHITE_DEVNET_RPC_URL` (devnet) —
which overrides the input. The URL is masked, logs name its host only, and
it is scrubbed from every file before upload.

## What fails the run

Mainnet (`live_mainnet.py`):

- `/verify` or `/verify/execution` answered 5xx or dropped the connection;
- a verdict whose `decision` / `executable` contradict its own fields (the
  rule the SDKs recompute), or an unknown decision;
- `executable_approved` for an unmanifested program, with L3 failed or
  flagged, without `scope.simulated`, or for a transaction that failed on
  chain (listed for review: the replay runs against today's state);
- L8 `ApprovedAndExecuted` for a verdict that was not approved;
- the Core not in executable mode, not healthy at the end, or not exiting
  cleanly on SIGTERM;
- the conformance harness failing its invariants on the fresh blocks.

INCONCLUSIVE (exit 0): the block fetch was refused, fewer than a quarter of
the selected transactions were measured, or most verdicts were rate-limited.

Devnet (`live_devnet.py`): the guard failing after funding, a decision
other than `executable_approved` on the executed transfer, L8 reporting
anything but `ApprovedAndExecuted` (a discrepancy, or an `Unavailable` whose
reason is Graphite failing to read the chain's answer), an unclean shutdown,
`graphite audit verify` exiting 1 or 3 (2 — an unkeyed trail,
corruption-evident only — is accepted and reported), or the runner itself
crashing. SKIPPED (exit 0): the faucet refused. INCONCLUSIVE (exit 0): the
transfer executed but L8 could not reach the chain for a transient reason
(429, timeout, connection) or the confirmation was still pending.

`seed_evidence` seeds operator evidence for the System program before the
Core starts, as an operator would: a fresh Core approves nothing until
evidence is earned or seeded. The report says which was used.

## Running locally

Without network access to Solana, `mock_rpc.py` stands in. It is not a
validator and its answers say nothing true about any chain, but it models
enough for the whole path to run: funded accounts, balance arrays derived
from the wire bytes (fees and System transfers), post-state accounts,
`sendTransaction`, signature statuses and `getTransaction`. With a mainnet
sample loaded every account exists; transactions whose accounts come from
lookup tables, or whose layout it does not read, get an incomplete answer —
which the Core refuses, as it should.

```
python3 tools/live-measure/mock_rpc.py --port 8899 \
    --sample graphite-core/fixtures/mainnet/sample-2026-09-23-last-2-blocks.json &
python3 tools/live-measure/live_mainnet.py fetch --rpc http://127.0.0.1:8899 --blocks 2 --out /tmp/s.json
# then the harness, select and replay as in live_mainnet.py's docstring,
# with the Core started with GRAPHITE_RPC_URL=http://127.0.0.1:8899
python3 tools/live-measure/live_devnet.py --graphite graphite-core/target/release/graphite \
    --rpc http://127.0.0.1:8899 --out-dir /tmp/devnet-report
```

`--rate-limit getBlock,requestAirdrop` makes the mock answer those methods
with HTTP 429, to see the INCONCLUSIVE and SKIPPED paths.

Unit tests (no network):

```
python3 -m pytest -q -p no:cacheprovider tools/live-measure/test_live_measure.py
```
