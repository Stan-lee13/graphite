#!/usr/bin/env python3
"""Recompute the derived fields of `protocols/battle_tested_evidence.json`
from its stored observations and the CURRENT manifests. No network.

Round 29 (audit 2026-10-20, MED-1): a record is a measurement of mainnet
traffic resolved against the manifest as it stood on the day of the census.
Manifests move afterwards — Token-2022's gained the transfer-fee and metadata
instructions, Marginfi's placeholder `onchain_observed_shape_7acct` turned out
to be `lending_account_repay`, seven manifests changed tier — and the records
kept describing the old ones: instructions the manifest now names listed as
"unmatched", a `declared_trust_tier` that is no longer declared.

The raw observation in each record is the histogram of instruction heads (the
first <= 8 data bytes) the census saw: `instructions_by_name` (heads the
manifest of the day named, folded by name) plus `unmatched_leading_bytes` (the
rest; the census keeps the 12 commonest, so `instructions_observed` may exceed
what is listed — the unlisted remainder stays unmatched here, which can only
under-count). This script re-resolves the unmatched heads against the current
manifest with the census's own rule (the first instruction whose discriminator
the head starts with), carries renamed instructions over (`RENAMES`), and
recomputes:

  instructions_named_by_manifest, decode_rate, meets_battle_tested,
  declared_trust_tier.

The volume and identity axes are not touched: they are measurements of the
chain, not of the manifest. `tests/battle_tested_evidence.rs` fails when a
record disagrees with this recomputation.

    python3 graphite-core/scripts/recompute_evidence.py          # rewrite
    python3 graphite-core/scripts/recompute_evidence.py --check  # exit 1 if stale
"""
import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import manifest_json  # noqa: E402

PROTOCOLS = HERE.parent / "protocols"
EVIDENCE = PROTOCOLS / "battle_tested_evidence.json"

# Instructions renamed since a census: (manifest, old name) -> new name.
RENAMES = {
    ("marginfi-v2.json", "onchain_observed_shape_7acct"): "lending_account_repay",
}


def resolve(manifest, head):
    """The census's rule (`battle_tested_census.decode_census`)."""
    head = head.lower()
    for ix in manifest["instructions"]:
        d = ix["discriminator"].lower()
        if d and head.startswith(d):
            return ix["name"]
    return None


def recompute(record, manifest, thresholds):
    dec = record["decode"]
    names = {ix["name"] for ix in manifest["instructions"]}
    by_name = {}
    for name, n in dec["instructions_by_name"].items():
        name = RENAMES.get((record["manifest"], name), name)
        if name not in names:
            raise SystemExit(
                f"{record['manifest']}: the census named {name!r}, which the manifest no longer has; "
                "add it to RENAMES or re-run the census"
            )
        by_name[name] = by_name.get(name, 0) + n
    unmatched = {}
    for head, n in dec["unmatched_leading_bytes"].items():
        name = resolve(manifest, head)
        if name is None:
            unmatched[head] = n
        else:
            by_name[name] = by_name.get(name, 0) + n
    # Commonest first, ties in their recorded order (sorted() is stable).
    by_name = dict(sorted(by_name.items(), key=lambda kv: -kv[1]))
    named = sum(by_name.values())
    observed = dec["instructions_observed"]
    decodable = any(ix["discriminator"] for ix in manifest["instructions"])
    rate = ((named / observed) if observed else None) if decodable else None
    dec["decode_applicable"] = decodable
    dec["instructions_by_name"] = by_name
    dec["unmatched_leading_bytes"] = unmatched
    dec["instructions_named_by_manifest"] = named
    dec["decode_rate"] = rate
    record["declared_trust_tier"] = manifest.get("trust_tier", "")
    record["meets_battle_tested"] = bool(
        record["identity"].get("executable")
        and record["volume"].get("successful_transactions_counted", 0)
        >= thresholds["min_successful_transactions"]
        and observed >= thresholds["min_decoded_instructions"]
        and rate is not None
        and rate >= thresholds["min_decode_rate"]
    )
    return record


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    doc, layout = manifest_json.load(EVIDENCE)
    before = json.dumps(doc, sort_keys=True)
    for record in doc["programs"]:
        manifest = json.loads((PROTOCOLS / record["manifest"]).read_text(encoding="utf-8"))
        old = json.dumps(record, sort_keys=True)
        recompute(record, manifest, doc["thresholds"])
        if json.dumps(record, sort_keys=True) != old:
            print(f"{record['manifest']}: decode_rate {record['decode']['decode_rate']}, "
                  f"declared {record['declared_trust_tier']}, meets {record['meets_battle_tested']}")
    stale = json.dumps(doc, sort_keys=True) != before
    if args.check:
        return 1 if stale else 0
    if stale:
        manifest_json.dump(EVIDENCE, doc, layout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
