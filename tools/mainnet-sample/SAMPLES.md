# The mainnet samples behind the published numbers

The samples are not committed (12 MB each; `.gitignore`). Each published table
that measures real traffic names the samples it ran on, and each sample is
identified here by the finalized blocks it holds and the SHA-256 of the file
the run read. A finalized block does not change, so fetching the same slots
gives the same rows:

```bash
python tools/mainnet-sample/fetch_mainnet.py --slots <slots below> --out sample.json
```

`--slots` fails, writing nothing, if any slot it names cannot be fetched
(Round 29: such a slot used to be reported "skipped" and the file written
without it).

**What can and cannot be reproduced.** The ROWS can; the FILE's hash cannot.
The file a fetch writes today does not hash to the values below, for two
reasons: the fetcher now also records its slot list (`"slots"`), which the
files below predate, and those files were fetched head first, so their rows
run newest block first, while `--slots` fetches in the order given. The
hashes identify the exact files the published runs read; the slot lists are
how to get the same transactions; and `verify_sample.py` is how to check
that you did — it refetches a recorded file's slots in its own row order and
compares every row field for field (slot, version, bytes, outcome, compute
units, loaded addresses; none is volatile for a finalized block):

```bash
python tools/mainnet-sample/verify_sample.py <recorded.json>                     # refetch and compare
python tools/mainnet-sample/verify_sample.py <recorded.json> --against <yours.json>  # offline
```

Checked by hand on 2026-10-03, before that tool existed: slot 451887084 of
the 2026-09-30 sample, fetched again from the public endpoint, gave the same
1,242 rows (bytes, outcome, compute units and loaded addresses), in the same
order.

| Sample | Rows | Versions (legacy / v0 / v1) | SHA-256 of the file | Slots |
|---|---:|---|---|---|
| 2026-09-23 | 19,458 | 12,134 / 4,022 / 3,302 | `e954fe3fb584899ecfd30bf42ae55774fd1bb3e426a9ccf9a0ce0bc3523d6feb` | 449802725 to 449808725, every 400th (16 blocks) |
| 2026-09-25 | 10,019 | 5,937 / 2,144 / 1,938 | `7282e268da6f31973aae1c2fb286b9d9c11492b87559d0f733a35f61fb01b95d` | 450453705 to 450456505, every 400th (8 blocks) |
| 2026-09-27 | 10,465 | 7,017 / 2,183 / 1,265 | `68e97212ce7d71cf0df747a80d10c980a062547923effe319d841907b0771352` | 450833240 to 450836040, every 400th (8 blocks) |
| 2026-09-30 | 9,004 | 6,684 / 1,557 / 763 | `751b44aecd246c0f438db054e3b9545c1f219c78783e6682e598889fc3e9104f` | 451884284 to 451887084, every 400th (8 blocks) |

Of the 48,946 rows, 91 (46 + 18 + 21 + 6) have no instruction the harness can
put forward as the primary: none with accounts, or the chosen one carries no
data. The conformance test counts them as "no usable instruction" and verifies
the other 48,855, which are the rows the round reports compare.

`tests/mainnet_conformance.rs` prints the SHA-256 of the sample it measured,
so a run's output names its input.

## The committed slice, run on every commit

`graphite-core/fixtures/mainnet/sample-2026-09-23-last-2-blocks.json` is the last
two blocks of the 2026-09-23 sample (slots 449808325 and 449808725, 2,284
transactions as the chain executed them: legacy, v0 and v1), written by
`make_committed_subset.py`, which refuses a source whose hash is not in the
table above and chooses whole blocks by position, never rows by content.
Regenerating it **from the recorded 2026-09-23 file** gives the same bytes
(SHA-256 `79681f646cda8c3c85da686b27450dda3c69bd0691acc6714b654ab33a4515b0`);
only a holder of that file can do that, because a refetch does not
reproduce the source file's hash (above). Anyone can check the slice's
transactions against the chain itself:

```bash
python tools/mainnet-sample/verify_sample.py graphite-core/fixtures/mainnet/sample-2026-09-23-last-2-blocks.json
```

which refetches slots 449808725 and 449808325 and compares all 2,284 rows.
`tools/mainnet-sample/test_mainnet_sample.py` runs the same comparison on
every CI run against an endpoint stand-in that serves the slice's own blocks,
so the comparison itself is tested; it does not contact mainnet.

`tests/mainnet_conformance.rs::the_committed_mainnet_blocks_give_the_recorded_verdicts_every_run`
runs it through the whole pipeline on every `cargo test`, with no network and no
`#[ignore]`: 0 parse failures, 0 verify errors, two runs identical, and the
SHA-256 of the verdict file pinned. That pin was cross-checked against the
full-sample run of Round 24's final code: the same 2,277 rows hash to the same
value. A change to any verdict on these blocks fails CI until it is attributed
and the pin updated in the same commit.
