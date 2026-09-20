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
