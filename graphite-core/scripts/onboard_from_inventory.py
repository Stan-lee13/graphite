#!/usr/bin/env python3
"""Onboard the programs the chain actually uses.

Reads the usage ranking (scripts/out/inventory_census.json) and the programs'
own published IDLs (scripts/out/idl_index.json + out/onchain_idls/), and writes
one Graphite manifest per program that clears every gate below:

  * the account exists on mainnet and is EXECUTABLE
  * the program publishes its own Anchor IDL, owned by the program itself
  * the IDL declares at least one instruction
  * no two instruction discriminators prefix each other (the registry refuses
    such a manifest, because a real instruction could resolve to the wrong
    entry)
  * the program is not already in the seed set

Every manifest is written at OfficialManifest. Promotion to BattleTested is a
separate step that MEASURES (battle_tested_census.py) - nothing here asserts a
tier.
"""
import json
import re
import sys
import unicodedata
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import idl_to_manifest as gen  # noqa: E402

HERE = Path(__file__).resolve().parent
OUT = HERE.parent / "protocols"
IDX = HERE / "out" / "idl_index.json"
IDLS = HERE / "out" / "onchain_idls"
CENSUS = HERE / "out" / "inventory_census.json"
CURATED = HERE / "inventory_metadata.json"

# Native programs have no IDL and are onboarded from their published
# instruction enums, not from here.
SKIP = {
    "Vote111111111111111111111111111111111111111",
    "Ed25519SigVerify111111111111111111111111111",
    "KeccakSecp256k11111111111111111111111111111",
    "Secp256r1SigVerify1111111111111111111111111",
}


def kebab(name):
    s = unicodedata.normalize("NFKD", name)
    s = re.sub(r"[^A-Za-z0-9]+", "-", s).strip("-").lower()
    return s or "program"


def title(name):
    parts = re.split(r"[^A-Za-z0-9]+", name)
    out = []
    for p in parts:
        if not p:
            continue
        out.append(p.upper() if len(p) <= 3 and p.isalpha() and p.lower() in
                   ("amm", "dca", "dex", "lp", "sol", "nft", "cpi", "idl") else p.capitalize())
    return " ".join(out) or name


_CATEGORY_HINTS = [
    ("swap", ("swap", "amm", "dex", "route", "pool", "clmm", "cpmm", "dlmm", "curve", "trade")),
    ("lending", ("lend", "borrow", "obligation", "reserve", "margin", "loan", "collateral")),
    ("perps", ("perp", "futures", "leverage", "funding_rate", "position")),
    ("staking", ("stake", "validator", "delegat", "unstake", "epoch")),
    ("nft", ("nft", "metadata", "collection", "candy", "compress", "bubblegum", "mint_to")),
    ("bridge", ("bridge", "wormhole", "portal", "relayer", "attest")),
    ("oracle", ("oracle", "price", "feed", "aggregator", "switchboard", "pyth")),
    ("governance", ("govern", "proposal", "vote", "realm", "dao", "multisig", "squad")),
]


def category_of(idl_name, instruction_names):
    blob = (idl_name + " " + " ".join(instruction_names)).lower()
    for cat, hints in _CATEGORY_HINTS:
        if any(h in blob for h in hints):
            return cat
    return ""


REPORT = HERE / "out" / "onboarding_report.json"


def write_report(written, skipped):
    """Write the onboarding report so that it describes the CURRENT tree.

    Round 29 (audit 2026-10-20, LOW-6): the report is the record of this
    tool's runs, and it was read as a list of the onboarded manifests. It
    listed two files that had since been removed (`hylo-router-hyrout.json`,
    `burn-and-claim-abrn44.json`) and did not say that it covers only the
    manifests THIS tool wrote (55 of the 137 present) — none of the ones
    built by `build_manifests.py`, `build_new_manifests.py`, the rebuild
    scripts or by hand. Entries whose manifest no longer exists move to
    `removed_since_onboarding`; the note states the scope with counts read
    from the tree.
    """
    present = {f.name for f in OUT.glob("*.json")} - {"verified_program_ids.json", "battle_tested_evidence.json"}
    kept = [list(w) for w in written if w[0] in present]
    removed = [list(w) for w in written if w[0] not in present]
    note = (
        "Record of scripts/onboard_from_inventory.py runs: the manifests THIS tool wrote from "
        "programs' own on-chain IDLs (columns: file, program id, name, instructions when written, "
        "sampled successful transactions), and the census candidates it skipped with the reason. "
        f"{len(kept)} of the {len(present)} manifests in protocols/ were written by it; the others "
        "come from build_manifests.py, build_new_manifests.py, the rebuild_* scripts and hand "
        "curation. Instruction counts are as written; merge_onchain_idl.py may have added more since. "
        "Refresh without network: python3 graphite-core/scripts/onboard_from_inventory.py --refresh-report"
    )
    out = {"note": note, "written": kept, "removed_since_onboarding": removed, "skipped": [list(x) for x in skipped]}
    REPORT.write_text(json.dumps(out, indent=1), encoding="utf-8", newline="\n")


def main():
    # `--programs <id> ...` onboards exactly those programs (each still has to
    # clear every gate above), for protocols the usage census did not sample;
    # otherwise the top `limit` of the census are considered.
    # `--refresh-report` rewrites the report against the current tree and
    # touches nothing else (no network).
    args = sys.argv[1:]
    if args == ["--refresh-report"]:
        prev = json.loads(REPORT.read_text(encoding="utf-8"))
        write_report(prev["written"] + prev.get("removed_since_onboarding", []), prev["skipped"])
        return
    explicit = args[1:] if args and args[0] == "--programs" else None
    limit = int(args[0]) if args and explicit is None else (len(explicit) if explicit else 90)
    index = {p["program_id"]: p for p in json.loads(IDX.read_text(encoding="utf-8"))["programs"]}
    census = json.loads(CENSUS.read_text(encoding="utf-8"))
    if explicit is not None:
        sampled = {p["program_id"]: p for p in census["programs"]}
        census = {"programs": [sampled.get(pid, {"program_id": pid, "successful_txs": 0}) for pid in explicit]}
    curated = json.loads(CURATED.read_text(encoding="utf-8")) if CURATED.exists() else {}

    existing = {}
    taken_files = set()
    for f in sorted(OUT.glob("*.json")):
        if f.name in ("verified_program_ids.json", "battle_tested_evidence.json"):
            continue
        m = json.loads(f.read_text(encoding="utf-8"))
        existing[m["protocol"]["program_id"]] = f.name
        taken_files.add(f.name)

    written, skipped = [], []
    for p in census["programs"]:
        if len(written) >= limit:
            break
        pid = p["program_id"]
        if pid in existing or pid in SKIP:
            continue
        info = index.get(pid)
        if not info:
            continue
        if not info.get("executable"):
            skipped.append((pid, "not executable"))
            continue
        if not info.get("idl"):
            skipped.append((pid, info.get("idl_error", "no IDL")))
            continue
        idl = json.loads((IDLS / f"{pid}.json").read_text(encoding="utf-8"))
        ixs = idl.get("instructions") or []
        if not ixs:
            skipped.append((pid, "IDL declares no instructions"))
            continue

        meta = curated.get(pid, {})
        idl_name = info["idl"]["name"] or meta.get("name") or pid[:8]
        # The display name is the program's OWN IDL name, always suffixed with
        # the first eight characters of its address.
        #
        # Two reasons, both learned from this data. First, the IDL names are
        # not unique: `pyth_push_oracle`, `pyth_solana_receiver` and
        # `wormhole_core_bridge_solana` each appear at more than one address in
        # a single ten-minute sample of mainnet. Second, and more seriously, a
        # name alone would let a program at an address nobody recognises
        # present itself in the console as the protocol whose name it copied —
        # which is the impersonation Graphite's own CpiTraceAnomaly detector
        # exists to catch. The address is part of the name, so the reader
        # always sees which program this is.
        name = meta.get("name") or f"{title(idl_name)} ({pid[:8]})"
        fname = meta.get("file") or (kebab(idl_name) + "-" + pid[:6].lower() + ".json")
        if fname in taken_files:
            fname = kebab(idl_name) + "-" + pid[:4].lower() + ".json"
        manifest = gen.build(
            idl,
            pid,
            name,
            website=meta.get("website", ""),
            github=meta.get("github", ""),
            category=meta.get("category") or category_of(idl_name, [i["name"] for i in ixs]),
            trust_tier="OfficialManifest",
        )
        conflicts = gen.prefix_conflicts(manifest)
        if conflicts:
            skipped.append((pid, f"discriminator prefix conflict: {conflicts[:2]}"))
            continue
        if not manifest["instructions"]:
            skipped.append((pid, "no usable instructions after de-duplication"))
            continue
        if not any(ix["accounts"] for ix in manifest["instructions"]):
            # A manifest whose IDL names no account anywhere can only name
            # instructions; it cannot check a PDA, a fixed address or a
            # privilege, which is most of what a manifest is for. Two such
            # programs came out of this sweep, and both would have had to be
            # written into an exception list in
            # `deep_extreme_tests::test_all_protocols_verifiable` (every
            # instruction must build a transaction plan) to be carried at all.
            # Not onboarded.
            skipped.append((pid, "IDL declares no accounts for any instruction"))
            continue
        gen.dump(manifest, OUT / fname)
        taken_files.add(fname)
        written.append((fname, pid, name, len(manifest["instructions"]), p["successful_txs"]))
        print(f"wrote {fname:44s} {len(manifest['instructions']):4d} ix  "
              f"{p['successful_txs']:6d} sampled txs  {name}", flush=True)

    print(f"\n{len(written)} manifests written, {len(skipped)} candidates skipped")
    if explicit is not None and REPORT.exists():
        # An explicit run adds to the record of the census runs; it does not
        # replace it. Entries for the named programs are superseded.
        prev = json.loads(REPORT.read_text(encoding="utf-8"))
        named = set(explicit)
        written = [w for w in prev["written"] + prev.get("removed_since_onboarding", [])
                   if w[1] not in named] + written
        skipped = [s for s in prev["skipped"] if s[0] not in named] + skipped
    write_report(written, skipped)


if __name__ == "__main__":
    main()
