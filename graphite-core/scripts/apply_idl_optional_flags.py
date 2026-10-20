#!/usr/bin/env python3
"""Mark the accounts a program's own IDL declares optional as `optional` in its
shipped manifest.

An Anchor program is told an optional account is absent by being passed its
own program id in the slot (Round 22). A manifest that does not mark such a
slot optional judges the program id there as the account itself — and, for an
optional ADMIN signer, makes every call look like an administrator's: OpenBook
v2's order instructions carry `open_orders_admin` (`isOptional: true`, absent
on ordinary markets), and the admin-signer rule then classed `place_order`,
`place_orders`, `edit_order`, ... as authority changes (Round 29, audit
2026-10-20, LOW-1).

Only a slot whose instruction (snake-case name), position and account name
match the IDL exactly is touched; anything else is reported and left alone.

    python3 graphite-core/scripts/apply_idl_optional_flags.py openbook-v2.json scripts/openbook_idl.json
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import idl_to_manifest as gen  # noqa: E402
import manifest_json  # noqa: E402


def main(manifest_name, idl_path):
    import json

    path = HERE.parent / "protocols" / manifest_name
    data, layout = manifest_json.load(path)
    idl = json.loads((HERE.parent / idl_path).read_text(encoding="utf-8"))
    by_name = {gen.snake(ix["name"]): ix for ix in idl["instructions"]}
    marked, skipped = 0, []
    for ix in data["instructions"]:
        src = by_name.get(gen.snake(ix["name"]))
        if src is None:
            continue
        flat = gen.flatten_accounts(src.get("accounts") or [])
        if len(flat) != len(ix["accounts"]):
            skipped.append(f"{ix['name']}: {len(ix['accounts'])} accounts vs {len(flat)} in the IDL")
            continue
        for slot, ((aname, a), acc) in enumerate(zip(flat, ix["accounts"])):
            if not (a.get("optional") or a.get("isOptional")):
                continue
            if gen.snake(aname) != gen.snake(acc["name"]):
                skipped.append(f"{ix['name']} slot {slot}: {acc['name']} vs {aname}")
                continue
            if not acc.get("optional"):
                acc["optional"] = True
                marked += 1
    manifest_json.dump(path, data, layout)
    print(f"{manifest_name}: {marked} slot(s) marked optional")
    for s in skipped:
        print("  skipped", s)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
