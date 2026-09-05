#!/usr/bin/env python3
"""P0-1 fix (2026-09-05 audit, "account identity / positional trust").

Conservatively populates `expected_address` on manifest account-role
entries whose identity is a FIXED, well-known constant program — never a
PDA (no seed formula exists for these) and never legitimately
caller-chosen. Only the small set of unambiguous, universally-known native
program IDs is used; anything remotely uncertain (memo program variants,
sysvars whose exact address wasn't independently re-verified here,
protocol-specific "event_authority"-style PDAs) is deliberately left
alone rather than guessed at — a wrong `expected_address` would cause a
FALSE REJECTION of a legitimate transaction, which is a correctness bug
even though it fails closed.

Matching is on a normalized (lowercased, underscore/space-stripped)
account name, using precise inclusion/exclusion rules chosen after
surveying every account name actually used across all 33 manifests (see
the audit checkpoint) — NOT loose substring matching, to avoid false
positives like "rentpayer"/"rentcollector" (a caller-chosen wallet that
merely mentions "rent") matching the Rent sysvar.

Run with --dry-run first (default) to review the exact diff before
writing. Run with --write to apply.
"""
import json
import glob
import os
import sys

PROTOCOLS_DIR = os.path.join(os.path.dirname(__file__), "..", "protocols")

# Pulled directly from this repo's own already-vetted manifests (not typed
# from memory) so there is zero risk of a typo relative to what the rest
# of the codebase already assumes.
SYSTEM_PROGRAM = "11111111111111111111111111111111"
SPL_TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
ATA_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
COMPUTE_BUDGET = "ComputeBudget111111111111111111111111111111"


def normalize(name: str) -> str:
    return name.lower().replace("_", "").replace(" ", "").replace("-", "")


def classify(name: str):
    """Return the list of acceptable expected_address values for this
    account role name, or None if it should not be constrained."""
    n = normalize(name)

    # Never touch anything metadata-related (Metaplex's "metadata_program"
    # etc. is a real, DIFFERENT program, not SPL Token, despite sometimes
    # containing "token" nearby in longer names).
    if "metadata" in n:
        return None

    if n == "systemprogram":
        return [SYSTEM_PROGRAM]

    if "associatedtoken" in n and "program" in n:
        return [ATA_PROGRAM]

    if "computebudget" in n:
        return [COMPUTE_BUDGET]

    # Generic "token program" slot (any naming variant: token_program,
    # tokenProgram, token_program_a/b, token_x_program, input_token_program,
    # collateral_token_program, token_0_program, ...) — accepts EITHER
    # classic SPL Token or Token-2022, since many CLMM/whirlpool-style
    # protocols legitimately support both per pool side, and this script
    # cannot know which a specific slot requires without per-protocol IDL
    # research. A specific "..._2022_..." name is Token-2022 only.
    if "token" in n and "program" in n and "associated" not in n:
        if "2022" in n:
            return [TOKEN_2022]
        return [SPL_TOKEN, TOKEN_2022]

    return None


def detect_indent(text: str) -> int:
    """Detect the leading-space indent width of the first indented line
    (e.g. `  "protocol": {`) so re-serialization doesn't reformat the whole
    file — manifests in this repo are NOT consistently 2-space (some use 1,
    some use 2), so this must be per-file, not a single hardcoded constant."""
    for line in text.splitlines():
        stripped = line.lstrip(" ")
        if stripped != line and stripped:
            return len(line) - len(stripped)
    return 2


def main():
    write = "--write" in sys.argv
    total_changed_slots = 0
    total_changed_files = 0
    for path in sorted(glob.glob(os.path.join(PROTOCOLS_DIR, "*.json"))):
        fn = os.path.basename(path)
        if fn == "verified_program_ids.json":
            continue
        with open(path, encoding="utf-8") as f:
            original_text = f.read()
            manifest = json.loads(original_text)
        indent = detect_indent(original_text)

        file_changed = False
        for ix in manifest.get("instructions", []):
            for acc in ix.get("accounts", []):
                # Never override an existing PDA (mutually exclusive by
                # design) or an already-declared expected_address.
                if acc.get("pda_seeds"):
                    continue
                if acc.get("expected_address"):
                    continue
                addrs = classify(acc["name"])
                if addrs is None:
                    continue
                acc["expected_address"] = addrs
                total_changed_slots += 1
                file_changed = True
                print(f"{fn}: {ix['name']}.{acc['name']} -> {addrs}")

        if file_changed:
            total_changed_files += 1
            if write:
                new_text = json.dumps(manifest, indent=indent, ensure_ascii=False)
                # Preserve the original file's trailing-newline convention.
                if original_text.endswith("\n") and not new_text.endswith("\n"):
                    new_text += "\n"
                with open(path, "w", encoding="utf-8", newline="\n") as f:
                    f.write(new_text)

    print(
        f"\n{'WROTE' if write else 'WOULD WRITE'}: "
        f"{total_changed_slots} account slots across {total_changed_files} files"
    )


if __name__ == "__main__":
    main()
