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
  (1.0), `l8_checks` (10), `fresh_transactions` (40), `honest_transfers`
  (40), `seed_evidence` (false; a labelled PR seeds), `whole_census` (true).
- devnet: `rpc_url`, `seed_evidence` (true), `airdrop_lamports` (5×10⁸),
  `cluster` (`devnet`; a labelled PR uses `local-validator`).

## What the reports break down (Round 32, P3b)

- **Why** — every L3/L4 failure and inconclusive, by reason, overall and per
  program: the simulator's own error (`InstructionError{2, Custom(6001)}`,
  `AccountNotFound`, `BlockhashNotFound`, `InsufficientFundsForFee`, …), or
  why no verdict was reached (`no mature baseline`, `incomplete: RPC
  rate-limited`, …), with addresses and numbers normalised out. Printed in the
  job log and the summary.
- **Fresh blockhash** — the first `fresh_transactions` are verified twice,
  back to back: as recorded, and with the unsigned frame's blockhash rewritten
  to a current one from getLatestBlockhash (`wire.py`; legacy, v0 and v1 at
  its fixed offset 8; durable-nonce transactions are skipped and counted —
  their blockhash slot is the nonce). Nothing is signed or sent. The Core
  simulates with `replaceRecentBlockhash: true`, so the two passes are
  expected to agree; the table shows whether they do.
- **Fresh Core** — with no seeded or earned evidence no program can reach
  `executable_approved` and L3 cannot flag; the report says so. With
  `seed_evidence`, the measured census is imported first (`live_mainnet.py
  seed`: `graphite evidence import-census` — Round 40, never typed numbers —
  for System and SPL Token, or with `whole_census` for every program the
  census admits); the report names how many programs were imported, splits
  the replay's decisions by imported / not imported, and gives System and
  SPL Token their own table. Round 40 (measure): no L3 baseline is typed —
  the typed bands made honest System and SPL Token instructions FLAG in run
  40280048548 — so L3 is `no mature baseline` (inconclusive, which does not
  block `executable_approved`) until the Core learns one from 10 clean
  simulated verdicts of the run.
- **Honest transfers** (Round 40, measure) — before the replay, up to
  `honest_transfers` NEW unsigned transactions are built from the sample's
  executed simple transfers (one System `Transfer` or SPL Token
  `TransferChecked` — or `Transfer` when the block names its mint — sent by
  its own fee payer, beside nothing but Compute Budget, an idempotent ATA
  create or a memo): same sender, same recipient, 1 lamport / 1 base unit,
  the original's Compute Budget instructions, a fresh blockhash, a zeroed
  signature slot (`wire.build_legacy`), and verified with the intent
  `transfer` and the amount, recipient and asset stated. The report gives the
  decisions and every non-executable one's reasons. This is the approval-path
  measurement; the replay of other people's transactions is not one. No
  honest swap is built: it would need a route and pool accounts the runner
  would have to invent.
- **Signer debits beyond the fee** — every verdict naming
  `UndeclaredSignerLamportDebit` / `SignerLamportsOutsideDeclaredDebit` is
  printed with Graphite's figure, the signature count, the compute-unit price
  × limit and priority fee, Agave's fee for them, the fee and each signer's
  balance change the block recorded (`fetch` keeps `meta.fee` and the
  balances), and every top-level instruction (a System transfer sibling with
  its amount and destination).
- **Cluster** (devnet) — the public faucet is retried (3 rounds, 30 s / 60 s
  apart, each backing off on 429); when it still refuses, the run falls back
  to a pinned Agave `solana-test-validator` (exact version and archive
  sha256 in `live-devnet.yml`) on loopback, airdrops from it and runs the same
  gated flow. The report names the cluster and why. To bump Agave: download
  the new `solana-release-x86_64-unknown-linux-gnu.tar.bz2`, `sha256sum` it,
  and change `AGAVE_VERSION` and `AGAVE_SHA256` together.

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
crashing, or the local-validator fallback not starting or not paying out.
SKIPPED (exit 0): the faucet refused and no validator binary was given (the
workflow always gives one). INCONCLUSIVE (exit 0): the
transfer executed but L8 could not reach the chain for a transient reason
(429, timeout, connection) or the confirmation was still pending.

`seed_evidence` seeds operator evidence for the System program before the
Core starts, as an operator would (`graphite evidence seed` / `baseline`): a
fresh Core approves nothing until evidence is earned or seeded. The measured
census (`import-census`) is not used here: it is mainnet-beta's, and a server
whose data directory holds it refuses to start on a devnet or local-validator
RPC (Round 40). The report says which was used.

## Running locally

Without network access to Solana, `mock_rpc.py` stands in. It is not a
validator and its answers say nothing true about any chain, but it models
enough for the whole path to run: funded accounts, balance arrays derived
from the wire bytes (Agave's fee — 5,000 per signature plus price × limit — and System transfers), post-state accounts,
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
with HTTP 429, to see the INCONCLUSIVE and SKIPPED paths (and, with
`--validator`, the local-validator fallback). `--fail-programs A,B` makes a
simulation that calls A or B report `InstructionError{i, Custom(6001)}`; a
simulation asked without `replaceRecentBlockhash` on a stale blockhash reports
`BlockhashNotFound`, as a validator does.

With an Agave release unpacked locally, the devnet flow runs on a real
runtime with no network at all:

```
python3 tools/live-measure/live_devnet.py --graphite graphite-core/target/release/graphite \
    --cluster local-validator --validator path/to/solana-release/bin/solana-test-validator --out-dir /tmp/lv
```

Unit tests (no network):

```
python3 -m pytest -q -p no:cacheprovider tools/live-measure/test_live_measure.py
```
