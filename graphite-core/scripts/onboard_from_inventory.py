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


def main():
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 90
    index = {p["program_id"]: p for p in json.loads(IDX.read_text(encoding="utf-8"))["programs"]}
    census = json.loads(CENSUS.read_text(encoding="utf-8"))
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
    (HERE / "out" / "onboarding_report.json").write_text(
        json.dumps({"written": written, "skipped": skipped}, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
