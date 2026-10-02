# graphite-core/scripts

Operator and onboarding tools. None of them runs in the server or in a verdict.

## Which RPC tools see version-1 transactions

Version-1 transactions are live on mainnet (about 17% of the 2026-09-23 sample), and an RPC
asked for `maxSupportedTransactionVersion: 0` refuses each one with an error instead of
returning it. A tool that asks for version 0 therefore measures a sample with v1 removed.

| Tool | Requests | Notes |
|---|---|---|
| `battle_tested_census.py` | version 1 | feeds the BattleTested evidence gate |
| `solana_inventory_census.py` | version 1 | ranks programs by real usage |
| `../../tools/mainnet-sample/fetch_mainnet.py` | version 1 | the mainnet conformance samples |
| `analyze_squads_tx.py`, `census_drift_kamino.py`, `census_metaplex.py`, `census_orca.py`, `fetch_discriminators.py`, `fetch_real_fixtures.py`, `live_revalidate.py`, `probe_dca_pda.py`, `verify_dk_pdas.py` | version 0 | one-off onboarding and census scripts; they read the `json` encoding, whose shape for v1 they do not parse. Their outputs exclude v1 transactions. |

The two TypeScript tools in `integrations/agent-guard` that fetch transactions
(`mainnet-benchmark.ts`, `build_exploit_corpus.mts`) request version 1 since R-P8 phase 4
(2026-10-02): `@solana/web3.js` 1.99 decodes v1 messages (`MessageV1`, with its
`transactionConfig`), checked live against mainnet transaction
`4mQher7pk669NTK78w8Zu4FD8fdWucUTDTL15DbajdkHNZTtRi3zaRF3FBuavQ73FfZvTD3Yy9e7n1YwUQ2Cxx5x`
(slot 449,808,725). Each reports how many v1 transactions it read, and
`env-names.test.ts` fails if either goes back to version 0.

**Rule:** a number that is published, or that gates anything, comes from a tool that requests
version 1. A version-0 tool may be used for onboarding a manifest, where its output is reviewed
by hand, but not to measure traffic.
