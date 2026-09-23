#!/usr/bin/env python3
"""Turn a program's OWN on-chain Anchor IDL into a Graphite protocol manifest.

The input is whatever `fetch_onchain_idls.py` pulled out of the IDL account the
program itself owns, so the instruction surface is the deployed program's own
statement - not a third-party copy that may have drifted.

What is taken from the IDL (ground truth, never invented):
  * instruction names
  * discriminators: the explicit bytes when the IDL carries them (new spec),
    otherwise the Anchor convention sha256("global:" + snake_case(name))[0:8],
    which is the derivation the program's own generated client uses
  * account names, writability, signer-ness, in order
  * PDA seed templates, ONLY where the IDL states the derivation (C26 rule:
    a guessed seed formula false-flags legitimate transactions)

What is inferred, and therefore kept conservative:
  * risk_class / expected_state_changes phrasing, from the instruction name
    (the C46/C56 convention in build_new_manifests.py)
  * allowed_cpis: SPL Token / Token-2022 for value-moving classes. Under-
    declaring hard-blocks legitimate transactions; over-declaring only
    silences a warning for two programs that every DEX legitimately calls.

Manifests generated here are written at the tier the caller passes and never
above it. Promotion to BattleTested is a separate, measured step
(`battle_tested_census.py`).
"""
import hashlib
import json
import re

TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
SYSTEM_PROGRAM = "11111111111111111111111111111111"

# class -> (risk_class, semantic phrase). Wording is constrained by the engine:
# "credit"/"output" only on swaps (FakeSwap contract), "close" only on closes,
# never a signer-trigger word, fund movement phrased as "transfer" so L5 can
# align it with a declared transfer/swap/stake intent.
CLASSES = {
    "create": ("create", "creates the protocol account and transfers any initial funds"),
    "transfer": ("transfer", "transfers funds between the protocol and the involved accounts"),
    "withdraw": ("withdraw", "withdraws funds and transfers them out of the protocol to the involved accounts"),
    "close": ("close", "closes the position or account and transfers remaining funds back to the user"),
    "swap": ("transfer", "credits the output token account with the received amount for the swap"),
    "mint": ("mint", "mints new tokens to the destination token account"),
    "authority": ("authority", "updates protocol configuration or authority"),
    "bookkeeping": ("", "updates protocol accounting state"),
}

_WITHDRAW = ("withdraw", "redeem", "unstake", "claim", "collect", "harvest",
             "decrease", "remove_liquidity", "remove_", "repay", "burn",
             "cash_out", "settle", "payout", "liquidate")
_CREATE = ("create", "init", "open", "new_", "allocate", "register", "add_")
_CLOSE = ("close", "delete", "destroy")
_AUTHORITY = ("set_", "update", "change", "configure", "config", "transfer_authority",
              "transfer_ownership", "admin", "pause", "resume", "freeze", "thaw",
              "approve", "revoke", "migrate", "upgrade", "accept_", "propose")
_SWAP = ("swap", "route", "exchange", "trade", "fill", "buy", "sell", "quote")
_MINT = ("mint",)
_BOOKKEEPING = ("refresh", "crank", "update_price", "log", "emit", "sync",
                "tick", "heartbeat", "idle", "compound")


def snake(name):
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    s = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", s)
    return s.lower()


def anchor_disc(name):
    return hashlib.sha256(("global:" + snake(name)).encode()).hexdigest()[:16]


def classify(name):
    n = snake(name)
    # Order matters: "close_position" is a close, "update_fee" an authority
    # change, and "increase_liquidity" a transfer - the first match wins, so
    # the most specific families are tested first.
    if any(n.startswith(p) or ("_" + p) in n for p in _CLOSE):
        return "close"
    if any(n.startswith(p) for p in _BOOKKEEPING):
        return "bookkeeping"
    if any(p in n for p in _SWAP):
        return "swap"
    if any(n.startswith(p) for p in _WITHDRAW) or any(p in n for p in _WITHDRAW[:8]):
        return "withdraw"
    if any(n.startswith(p) for p in _MINT):
        return "mint"
    if any(n.startswith(p) for p in _CREATE):
        return "create"
    if any(n.startswith(p) for p in _AUTHORITY):
        return "authority"
    return "transfer"


def type_size(t):
    """Exact wire size of an IDL type, or None when it is not exactly known.

    None is the important return. The first version of this function guessed 8
    bytes for anything it did not recognise and 4 for a `vec`, which is fine
    for a size estimate and wrong for a seed offset: every `{instruction_data:
    a:b}` seed after such an argument then pointed at the wrong bytes, derived
    an address the program never derived, and flagged a legitimate account as
    a PDA mismatch. That is the C26 failure mode, and it showed up as 643 of
    790 real mainnet transactions to the newly onboarded programs being
    blocked on `AccountIdentityMismatch`. An offset that cannot be computed
    exactly is not emitted at all.
    """
    if isinstance(t, str):
        return {"u8": 1, "i8": 1, "bool": 1, "u16": 2, "i16": 2, "u32": 4, "i32": 4,
                "f32": 4, "u64": 8, "i64": 8, "f64": 8, "u128": 16, "i128": 16,
                "pubkey": 32, "publicKey": 32}.get(t)
    if isinstance(t, dict):
        if "array" in t:
            inner, n = t["array"]
            size = type_size(inner)
            return None if (size is None or not isinstance(n, int)) else size * n
        # vec, option, defined, generic: a borsh vec is length-prefixed and an
        # option is 1 + payload only when PRESENT, so neither has a fixed
        # width; a `defined` struct would need the whole type table.
    return None


def pda_template(pda, accts, args, program_id_bytes=None):
    """Convert an IDL pda seed definition to the repo's template grammar.

    Returns [] when any seed cannot be expressed exactly. A partial template
    would derive an address nobody authored and flag a legitimate account.

    The `program` key is the one that matters most here. An IDL may say a PDA
    is derived under a DIFFERENT program - an associated token account is
    derived under the ATA program, not under the protocol - and the repo's
    template grammar always derives under the instruction's own program. Three
    of the six grounded slots on Pump AMM's `buy` are of this kind, and
    deriving them under Pump AMM produced a wrong address and a false
    `AccountIdentityMismatch` on 460 real mainnet transactions. A foreign
    derivation program is therefore not grounded at all.
    """
    prog = pda.get("program")
    if prog is not None:
        value = prog.get("value") if isinstance(prog, dict) else None
        if not (prog.get("kind") == "const" and isinstance(value, list)
                and program_id_bytes is not None and bytes(value) == program_id_bytes):
            return []
    out = []
    for seed in pda.get("seeds", []):
        kind = seed.get("kind")
        if kind == "const":
            value = seed.get("value")
            if not isinstance(value, list):
                return []
            b = bytes(value)
            try:
                text = b.decode("ascii")
                if not all(32 <= c < 127 for c in b):
                    raise ValueError
                out.append(text)
            except Exception:
                out.append("0x" + b.hex())
        elif kind == "account":
            path = seed.get("path", "")
            if "." in path:          # a field of another account's state - not derivable here
                return []
            idx = next((i for i, a in enumerate(accts) if a.get("name") == path), None)
            if idx is None:
                return []
            out.append("{account_%d}" % idx)
        elif kind == "arg":
            path = seed.get("path", "")
            idx = next((i for i, a in enumerate(args) if a.get("name") == path), None)
            if idx is None:
                return []
            off = 8
            for a in args[:idx]:
                size = type_size(a.get("type"))
                if size is None:
                    return []          # offset not exactly known - ground nothing
                off += size
            width = type_size(args[idx].get("type"))
            if width is None:
                return []
            out.append("{instruction_data:%d:%d}" % (off, off + width))
        else:
            return []
    return out


def role_of(writable, signer):
    if signer:
        return "signer"
    return "writable" if writable else "readonly"


def state_changes(accts, cls):
    writable = [a["name"] for a in accts if a["is_writable"]]
    out = []
    if writable:
        out.append("modifies writable accounts: " + ", ".join(writable))
    phrase = CLASSES[cls][1]
    if phrase:
        out.append(phrase)
    if not out:
        out.append("no state changes (read-only instruction)")
    return out


def flatten_accounts(raw, prefix=""):
    """Anchor composite account groups nest; the wire format is flat."""
    out = []
    for a in raw:
        if "accounts" in a:
            out.extend(flatten_accounts(a["accounts"], prefix + a.get("name", "") + "_"))
        else:
            out.append((prefix + a["name"], a))
    return out


def build(idl, program_id, name, website="", github="", category="",
          trust_tier="OfficialManifest", version_label=None):
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.insert(0, str(_Path(__file__).resolve().parent))
    from solana_keys import b58decode as _b58decode
    pid_bytes = _b58decode(program_id)
    ixs = idl.get("instructions") or []
    meta = idl.get("metadata") or {}
    manifest = {
        "graphite_manifest_version": "1.0",
        "protocol": {
            "name": name,
            "program_id": program_id,
            "website": website,
            "github": github,
            "category": category,
        },
        "version": {
            "label": version_label or idl.get("version") or meta.get("version") or "1.0.0",
            "effective_from_slot": 0,
            "previous_version_ref": None,
        },
        "instructions": [],
        "trust_tier": trust_tier,
    }
    seen = {}
    for ix in ixs:
        disc = ix.get("discriminator")
        disc_hex = bytes(disc).hex() if isinstance(disc, list) and disc else anchor_disc(ix["name"])
        if disc_hex in seen:
            # Two names on one discriminator cannot both be resolved; the
            # registry refuses the manifest outright, so drop the later one
            # rather than ship something that will not load.
            continue
        seen[disc_hex] = ix["name"]
        flat = flatten_accounts(ix.get("accounts") or [])
        accts = []
        for aname, a in flat:
            writable = bool(a.get("writable") or a.get("isMut"))
            signer = bool(a.get("signer") or a.get("isSigner"))
            accts.append({
                "name": aname,
                "role": role_of(writable, signer),
                "is_writable": writable,
                "is_signer": signer,
                # Seed paths name accounts by their IDL name; the index they
                # resolve to is the FLATTENED wire position, which is the
                # order `flatten_accounts` preserves.
                "pda_seeds": pda_template(
                    a.get("pda") or {}, [x[1] for x in flat], ix.get("args") or [], pid_bytes
                ),
            })
        cls = classify(ix["name"])
        risk_class, _ = CLASSES[cls]
        cpis = [] if cls in ("authority", "bookkeeping") else [TOKEN_PROGRAM, TOKEN_2022]
        if cls == "create":
            cpis = [SYSTEM_PROGRAM] + cpis
        entry = {
            "name": ix["name"],
            "discriminator": disc_hex,
            "accounts": accts,
            "expected_state_changes": state_changes(accts, cls),
            "allowed_cpis": cpis,
            "risk_rules": [],
            "risk_class": risk_class,
        }
        if not accts:
            # An instruction whose IDL declares no accounts takes them from
            # remaining_accounts at runtime (the Kamino refreshReservesBatch /
            # Jupiter route shape). Saying so is what stops the drainer
            # heuristic from false-flagging every legitimate call.
            entry["variable_accounts"] = True
        manifest["instructions"].append(entry)
    return manifest


def prefix_conflicts(manifest):
    """The registry refuses a manifest where one discriminator prefixes another."""
    out = []
    ins = manifest["instructions"]
    for i, a in enumerate(ins):
        for b in ins[i + 1:]:
            x, y = a["discriminator"].lower(), b["discriminator"].lower()
            if x and y and (x == y or x.startswith(y) or y.startswith(x)):
                out.append((a["name"], x, b["name"], y))
    return out


def dump(manifest, path):
    path.write_text(json.dumps(manifest, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
