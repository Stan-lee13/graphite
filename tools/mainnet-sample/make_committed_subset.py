#!/usr/bin/env python3
"""Write the committed mainnet subset: whole finalized blocks of a recorded sample.

Roadmap R-P2/R-P3. The published mainnet numbers come from samples that are not
committed (12-23 MB each); a reviewer can refetch them by slot list
(`fetch_mainnet.py --slots`) but CI cannot gate on them. This writes a small,
committed slice that CI runs on every commit, with no network and no
`#[ignore]`:

  - the source is a sample whose SHA-256 is recorded in SAMPLES.md, and this
    script refuses any other file;
  - the slice is WHOLE blocks chosen by position (the last N of the sample),
    never rows chosen by content, so it is a sample of mainnet and not of
    transactions picked to pass;
  - the output records the source hash and the slots, and is written
    deterministically (sorted keys, LF), so regenerating it gives the same
    bytes.

usage: make_committed_subset.py <sample.json> <blocks> <out.json>
"""
import hashlib
import json
import sys

RECORDED = {
    # tools/mainnet-sample/SAMPLES.md
    "e954fe3fb584899ecfd30bf42ae55774fd1bb3e426a9ccf9a0ce0bc3523d6feb": "2026-09-23",
    "7282e268da6f31973aae1c2fb286b9d9c11492b87559d0f733a35f61fb01b95d": "2026-09-25",
    "68e97212ce7d71cf0df747a80d10c980a062547923effe319d841907b0771352": "2026-09-27",
    "751b44aecd246c0f438db054e3b9545c1f219c78783e6682e598889fc3e9104f": "2026-09-30",
}


def main() -> None:
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    src, blocks, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    raw = open(src, "rb").read()
    digest = hashlib.sha256(raw).hexdigest()
    if digest not in RECORDED:
        sys.exit(f"{src} hashes to {digest}, which SAMPLES.md does not record; refusing.")
    sample = json.loads(raw)
    rows = sample["rows"]
    slots = sorted({r["slot"] for r in rows})
    if blocks < 1 or blocks > len(slots):
        sys.exit(f"the sample has {len(slots)} blocks")
    chosen = slots[-blocks:]
    kept = [r for r in rows if r["slot"] in chosen]
    doc = {
        "about": (
            "Whole finalized mainnet blocks, the last "
            f"{blocks} of the {RECORDED[digest]} sample, written by "
            "tools/mainnet-sample/make_committed_subset.py. Refetch with "
            "fetch_mainnet.py --slots."
        ),
        "source_sample": RECORDED[digest],
        "source_sha256": digest,
        "slots": chosen,
        "count": len(kept),
        "endpoint_kind": sample.get("endpoint_kind"),
        "rows": kept,
    }
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, sort_keys=True, indent=None, separators=(",", ":"))
        f.write("\n")
    print(f"{out}: {len(kept)} rows from slots {chosen}")


if __name__ == "__main__":
    main()
