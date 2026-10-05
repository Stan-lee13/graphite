# The mainnet samples behind the published numbers

The samples are not committed (12 MB each; `.gitignore`). Each published table
that measures real traffic names the samples it ran on, and each sample is
identified here by the finalized blocks it holds and the SHA-256 of the file
the run read. A finalized block does not change, so fetching the same slots
gives the same rows:

```bash
python tools/mainnet-sample/fetch_mainnet.py --slots <slots below> --out sample.json
```

Checked on 2026-10-03: slot 451887084 of the 2026-09-30 sample, fetched again
from the public endpoint, gave the same 1,242 rows (bytes, outcome, compute
units and loaded addresses), in the same order. The file a fetch writes today
does not hash to the values below: the fetcher now also records its slot list
(`"slots"`), which the files below predate. The hashes identify the exact files
the published runs read; the slot lists are how to get the same transactions.

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
