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

The two TypeScript tools in `integrations/solana-agent-kit` that fetch transactions
(`mainnet-benchmark.ts`, `build_exploit_corpus.mts`) also ask for version 0, because
`@solana/web3.js` 1.x cannot decode a v1 message; they count and report every v1
transaction they skip. Moving them to version 1 is part of the `@solana/kit` migration
(`AUDIT/02-roadmap-gap.md`, R-P8).

**Rule:** a number that is published, or that gates anything, comes from a tool that requests
version 1. A version-0 tool may be used for onboarding a manifest, where its output is reviewed
by hand, but not to measure traffic.
