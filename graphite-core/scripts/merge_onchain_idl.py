#!/usr/bin/env python3
"""Add instructions a manifest is missing, from the program's own on-chain IDL.

The decode census measures how much of a program's REAL traffic its manifest
can name. Several hand-built manifests came back well under the bar - Meteora
DLMM at 11%, Pump.fun at 23% - not because anything in them was wrong, but
because the deployed programs had grown instructions the manifests never had.

This adds only what is missing:

  * an instruction whose discriminator is already declared is left ALONE, with
    its curated account roles, expected_address pins, risk_rules and verified
    PDA groundings untouched;
  * an instruction whose discriminator would prefix (or be prefixed by) an
    existing one is SKIPPED, because the registry refuses such a manifest -
    a real instruction could resolve to the wrong entry;
  * everything else is appended, generated from the IDL the same way a new
    manifest is.

Nothing here changes a trust tier. Run `battle_tested_census.py` afterwards.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import idl_to_manifest as gen  # noqa: E402

HERE = Path(__file__).resolve().parent
PROTOCOLS = HERE.parent / "protocols"
IDLS = HERE / "out" / "onchain_idls"


def main():
    only = set(sys.argv[1:])
    report = []
    for f in sorted(PROTOCOLS.glob("*.json")):
        if f.name in ("verified_program_ids.json", "battle_tested_evidence.json"):
            continue
        manifest = json.loads(f.read_text(encoding="utf-8"))
        pid = manifest["protocol"]["program_id"]
        if only and pid not in only and f.name not in only:
            continue
        idl_path = IDLS / f"{pid}.json"
        if not idl_path.exists():
            continue
        idl = json.loads(idl_path.read_text(encoding="utf-8"))
        candidate = gen.build(
            idl,
            pid,
            manifest["protocol"]["name"],
            website=manifest["protocol"].get("website", ""),
            github=manifest["protocol"].get("github", ""),
            category=manifest["protocol"].get("category", ""),
            trust_tier=manifest["trust_tier"],
        )
        have = [i["discriminator"].lower() for i in manifest["instructions"]]
        added, skipped = [], []
        for ix in candidate["instructions"]:
            d = ix["discriminator"].lower()
            if not d:
                continue
            conflict = next(
                (h for h in have if h and (h == d or d.startswith(h) or h.startswith(d))),
                None,
            )
            if conflict is not None:
                if conflict != d:
                    skipped.append((ix["name"], d, conflict))
                continue
            manifest["instructions"].append(ix)
            have.append(d)
            added.append(ix["name"])
        if added:
            f.write_text(
                json.dumps(manifest, indent=1, ensure_ascii=False) + "\n", encoding="utf-8"
            )
        report.append((f.name, len(manifest["instructions"]), added, skipped))
        if added or skipped:
            print(
                f"{f.name}: +{len(added)} instruction(s) -> {len(manifest['instructions'])}"
                + (f", {len(skipped)} skipped on a discriminator conflict" if skipped else "")
            )
            for name, d, c in skipped:
                print(f"    skipped {name} ({d}) - conflicts with {c}")
    total = sum(len(a) for _, _, a, _ in report)
    print(f"\n{total} instructions added across {sum(1 for _, _, a, _ in report if a)} manifests")


if __name__ == "__main__":
    main()
