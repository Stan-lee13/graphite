# Mainnet sample — Graphite against traffic nobody curated

Every other corpus in this repository was written by somebody who already knew
what the engine does: handcrafted fixtures, recorded mutations, generated
frames. Useful, and all of them share one blind spot — a check that refuses
honest input passes every test written by the person who wrote the check.

This fetches whole finalized mainnet blocks and hands them to
`graphite-core/tests/mainnet_conformance.rs`, which runs every transaction in
them through the full pipeline in **artifact-bound** mode: the real serialized
bytes, the real instruction data, the accounts resolved against the block's own
`loadedAddresses`, every sibling declared.

```bash
python tools/mainnet-sample/fetch_mainnet.py        # writes mainnet_sample.json
GRAPHITE_MAINNET_SAMPLE=$PWD/mainnet_sample.json \
  cargo test --test mainnet_conformance -- --ignored --nocapture
```

`PROBE_BLOCKS` sets how many blocks (default 8, ~10,000 transactions).
`GRAPHITE_RPC_URL` overrides the endpoint; without it the keyless public
mainnet endpoint is used, the same default the other live tests take.

**It reads and nothing else.** One request at a time, a pause between blocks,
and it stops rather than retrying on a 429 — a public endpoint is somebody
else's infrastructure. No credentials are read, written or needed. Nothing
here touches a wallet, a key, a fund or a live protocol, and no transaction is
ever submitted.

## What the test asserts

1. **No honest transaction is refused for contradicting itself.** The
   discriminator is derived from the instruction's own leading bytes, exactly
   as `AuditBind.projectionFromInstruction` and the Go
   `ProjectionFromInstruction` derive it, so an L2 discriminator-contradiction
   failure would be the Round 13 check firing on a request that does not
   contradict itself.
2. **Every known-risky-table block names something that is really there.** The
   block's reason names an instruction; that instruction's own bytes must
   carry one of the table's discriminators. This is what catches the
   regrounded discriminator over-matching.
3. **The parser is not the bottleneck.** A frame the chain accepted and
   executed is one Graphite has to be able to read.

## Why the sample is a file rather than a fetch inside the test

So the same bytes can be run against two builds of the engine and the verdicts
diffed. `GRAPHITE_MAINNET_VERDICTS` writes one line per transaction; Round 13
was measured by reverting the change, re-running over the identical sample, and
diffing — which produced 9,784 identical verdicts, the evidence that the change
moved nothing for honest traffic. "The tests pass" would not have shown that.

## Recorded results (2026-09-22, Round 18)

10,617 transactions from 8 blocks, 195 distinct programs, against the 131-manifest
registry:

| | |
|---|---|
| parse failures | 0 of 8,788 |
| L2 discriminator-contradiction false positives | 0 |
| version-1 transactions (refused by name) | 1,829 (17.2%) |
| reached a verdict | 8,767 |
| risk Clear | 6,190 |
| primary program has a manifest | 1,498 of 8,767 (17.1%) — **1,498 of 3,405 (44.0%) excluding validator votes** |

The last row is the one Round 18 moved. On the **same sample**, against the
33-manifest registry this round started from, it was 708 of 3,405 — **20.8%**.
Onboarding 98 programs from their own on-chain Anchor IDLs roughly doubled the
share of non-vote mainnet traffic whose primary program Graphite can name.

Validator vote transactions are reported separately because no agent ever signs
one; they are 5,362 of the 8,767 and including them moves every percentage
without changing what an agent is protected for.

### What this run found

Running the instrument after onboarding is what exposed two false-positive
classes that a manifest count would never have shown:

1. **An undeclared extra account had a privilege to mismatch.** An account past
   the end of a manifest's declared list is `remaining_accounts` — the manifest
   says nothing about it — but the resolver compared the real `AccountMeta`
   against the `("extra", is_writable: false)` placeholder, so every legitimate
   writable remaining-account became a blocking `AccountIdentityMismatch`. In
   this sample: 429 on Pump AMM, 336 on Pump.fun, 199 on the System Program, 72
   on SPL Token, all on transactions the chain had executed successfully. Fixed
   in `account_resolution.rs`; regression test
   `privilege_mismatch.rs::an_undeclared_extra_account_has_no_privilege_to_mismatch`.
2. **A PDA grounded under the wrong program.** An IDL may state that a PDA is
   derived under a DIFFERENT program — an associated token account is derived
   under the ATA program — and the manifest template grammar always derives
   under the instruction's own program. Three of the six grounded slots on Pump
   AMM's `buy` are of that kind. The generator no longer grounds them, nor any
   seed whose byte offset into the instruction data is not exactly computable.

`AccountIdentityMismatch` fell from 1,022 to 544 across the two fixes. The
remainder is a measured, open finding rather than a closed one: 544 blocks
remain, most of them `kind=privilege` on slots the manifest DOES declare as
signers, and they are recorded in the Round 18 report with their breakdown.

`GRAPHITE_MAINNET_REASONS=<path>` writes one line per blocked transaction with
the risk engine's own words, which is how that breakdown was produced.

## Recorded results (2026-09-17, slots 447885495–447888295)

10,669 transactions from 8 blocks, 189 distinct programs:

| | |
|---|---|
| parse failures | 0 of 9,794 |
| L2 discriminator-contradiction false positives | 0 of 9,784 |
| known-risky-table blocks verified against real bytes | 1,087 of 1,087 |
| verdicts changed by Round 13 | 0 of 9,784 |
| version-1 transactions (refused by name) | 875 (8.2%) |
| primary program has no manifest | 9,053 (92.5%) |

The last two are not results about Round 13; they are what the chain looks
like. Both are recorded in `docs/CURRENT.md` as open items.
