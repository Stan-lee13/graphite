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
    # Round 29 (audit 2026-10-20, LOW-1): bookkeeping was emitted with NO
    # class, and an unclassed instruction is refused as a declared sibling
    # unless the intent describes it — every `refresh_reserve` beside a
    # deposit. A bookkeeping instruction that writes no value-holding account
    # moves no value and changes no control, which is what `inert` means; one
    # that does is a transfer (see `refine`).
    "bookkeeping": ("inert", "updates protocol accounting state"),
    # A name that opens with "drain" empties a protocol-held account to the
    # destination the caller passes (SAGE `drainMineItemBank`, Crafting
    # `drainCraftableItemBank`). No intent declares `drain`.
    "drain": ("drain", "transfers the funds held by the protocol account to the destination account"),
}

_WITHDRAW = ("withdraw", "redeem", "unstake", "claim", "collect", "harvest",
             "decrease", "remove_liquidity", "remove_", "repay", "burn",
             "cash_out", "settle", "payout", "liquidate")
# Round 29 (audit 2026-10-20, MED-3): a loan pays the protocol's funds out, so
# the WORD `borrow` (`flash_borrow_reserve_liquidity`, not
# `deposit_collateral_for_borrows`) is a withdrawal too.
_WITHDRAW_WORDS = ("borrow",)
_CREATE = ("create", "init", "open", "new_", "allocate", "register", "add_")
_DEPOSIT = ("add_liquidity", "increase_liquidity", "provide_liquidity")
_CLOSE = ("close", "delete", "destroy")
# Setter prefixes, tested BEFORE the swap family (Round 29, MED-3) ...
_AUTHORITY = ("set_", "update", "change", "configure", "config", "transfer_authority",
              "transfer_ownership", "admin", "pause", "resume", "freeze", "thaw",
              "accept_", "fix_")
# ... and the prefixes that keep their old place, last: a migration or an
# upgrade of a pool or a game object is often permissionless
# (`migrate_to_cpswap`, `migrate_meteora_damm_claim_lp_token`), and it is
# the swap/withdraw/create family that says what it does.
_AUTHORITY_LATE = ("approve", "revoke", "migrate", "upgrade", "propose")
# A predicate (`check_admin`, `has_admin`, `is_token_config_enabled`) reads; it
# changes nothing unless a mutating verb says so (the Core's
# `names_an_authority_change` makes the same exception).
_READ_ONLY = ("check", "has", "is", "get", "view")
# Words that, ANYWHERE in a name, make it an operation on who controls a
# protocol or how it behaves (Round 29, audit 2026-10-20, MED-3). The prefix
# list above was tested LAST, after the swap family, which matches anywhere:
# `set_pool_trade_fee_rate` ("trade"), `set_pool_quote_flag` ("quote"),
# `set_swap_dynamic_fee_params` and `change_swap_fee` ("swap") were classed
# swaps — class `transfer` with the swap credit phrase, so a `transfer` or
# `swap` intent declared an administrator's fee setter — and names with no
# prefix at all (`pool_config_update`, `shutdown`, `panic_unpause_permissionless`)
# fell through to `transfer`.
_AUTHORITY_WORDS = ("admin", "admins", "authority", "authorities", "owner", "owners",
                    "ownership", "governance", "config", "configs", "configuration",
                    "shutdown", "panic", "pause", "unpause", "halt",
                    "unhalt", "freeze", "thaw", "whitelist", "allowlist", "blacklist",
                    "denylist", "permission", "permissions")
# A setter verb anywhere together with a word naming a protocol parameter
# (`pool_fee_rate_update`, `market_params_set`) is a parameter change.
_SETTER_VERBS = ("set", "update", "change", "fix", "modify", "edit", "configure",
                 "adjust", "override")
_PARAMETER_WORDS = ("fee", "fees", "rate", "rates", "param", "params", "parameter",
                    "parameters", "flag", "flags", "status", "tier", "limit", "limits",
                    "threshold", "oracle", "curve", "weight", "weights", "ratio")
# A name that opens by switching or editing a setting changes how a protocol or
# an object behaves (Round 24: `unpause_dex`, `toggle_feature`, `editPool` and
# `pause_swap_and_arbitrage` were classed transfers, and `pause_swap...` hit
# the swap family first). Tested before every other family; the Core applies
# the same switch rule to names in `manifest::names_an_authority_change`.
_SWITCH = ("edit", "reset", "enable", "disable", "toggle", "pause", "unpause",
           "halt", "unhalt", "resume")
_SWAP = ("swap", "route", "exchange", "trade", "fill", "buy", "sell", "quote")
_MINT = ("mint",)
_DRAIN = ("drain",)
_BOOKKEEPING = ("refresh", "crank", "update_price", "update_fees_and_rewards", "log",
                "emit", "sync", "tick", "heartbeat", "idle", "compound")
# Writable accounts whose name says they hold value. A bookkeeping instruction
# that writes one is not inert (`refine`).
_VALUE_ACCOUNT_WORDS = ("vault", "vaults", "token", "ata", "treasury", "destination",
                        "recipient", "receiver", "payout", "wallet", "escrow", "funds")


def snake(name):
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    s = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", s)
    return s.lower()


def anchor_disc(name):
    return hashlib.sha256(("global:" + snake(name)).encode()).hexdigest()[:16]


def _names_authority(n, words):
    """The authority family, by name: tested before close, bookkeeping, swap,
    withdraw, mint and create (Round 29, audit 2026-10-20, MED-3)."""
    for i, w in enumerate(words):
        if w in _AUTHORITY_WORDS:
            # `initialize_pool_with_dynamic_config`,
            # `initialize_with_permission`: a pool created WITH a config or a
            # permission is the user's pool, not a change to either.
            if w in ("config", "configs", "permission", "permissions") and "with" in words[:i]:
                continue
            return True
    # An order is the user's own (`instant_update_limit_order`,
    # `modify_order`): editing one changes no protocol parameter.
    if words and words[-1] in ("order", "orders"):
        return False
    # A name that posts or records something (`post_pyth_lazer_oracle_update`)
    # names what it carries, not a parameter it sets.
    if words and words[0] in ("post", "submit", "log", "emit", "write", "push"):
        return False
    for i, w in enumerate(words):
        if w not in _SETTER_VERBS or not any(p in _PARAMETER_WORDS for p in words):
            continue
        # A verb right after a parameter word, and not the last word, is a
        # noun: `post_pyth_pull_oracle_update_atomic` posts an oracle update.
        # `pool_fee_rate_update` and `execute_spending_limit_change` end on
        # the verb and change the parameter.
        if i > 0 and words[i - 1] in _PARAMETER_WORDS and i != len(words) - 1:
            continue
        return True
    return False


def classify(name):
    """The family of an instruction, from its name alone.

    Order matters - the first match wins:

      1. a switch prefix (`pause_`, `toggle_`, `edit_`, ...)       -> authority
         a read-only predicate (`check_`, `has_`, `is_`, `get_`,
         `view_` with no setter verb)                               -> bookkeeping
      2. an authority word anywhere (`admin`, `config`, `shutdown`,
         `panic`, ...) or a setter verb with a parameter word
         (`set_pool_trade_fee_rate`, `change_swap_fee`)             -> authority
      3. `drain...`                                                 -> drain
      4. a close (`close`, `delete`, `destroy`)                     -> close
      5. bookkeeping (`refresh`, `crank`, `sync`, `log`, ...)       -> bookkeeping
      6. an authority prefix (`set_`, `update`, `change`, ...)      -> authority
      7. swap words anywhere (`swap`, `route`, `trade`, `buy`, ...) -> swap
      8. withdraw / mint / create families                          -> that family
      9. `approve`, `revoke`, `migrate`, `upgrade`, `propose`       -> authority
     10. anything else                                              -> transfer

    Round 29 (audit 2026-10-20, MED-3): the authority prefixes were tested
    LAST, after the swap words that match anywhere, so an administrator's fee
    setter (`set_pool_trade_fee_rate`, `set_swap_dynamic_fee_params`,
    `change_swap_fee`, `set_virtual_quote_reserves`) shipped as a swap —
    class `transfer` with the swap credit phrase — and names carrying an
    authority word but no prefix (`pool_config_update`, `shutdown`,
    `panic_unpause_permissionless`) as plain transfers.
    """
    n = snake(name)
    words = [w for w in n.split("_") if w]
    if any(n == p or n.startswith(p + "_") for p in _SWITCH):
        return "authority"
    if words and words[0] in _READ_ONLY and not any(w in _SETTER_VERBS for w in words):
        return "bookkeeping"
    # A crank names what it refreshes (`update_fees_and_rewards`,
    # `refresh_reserve`): tested before the parameter-setter rule, which would
    # read "update ... fees" as a fee change.
    if any(n.startswith(p) for p in _BOOKKEEPING):
        return "bookkeeping"
    if _names_authority(n, words):
        return "authority"
    if any(n == p or n.startswith(p + "_") for p in _DRAIN):
        return "drain"
    if any(n.startswith(p) or ("_" + p) in n for p in _CLOSE):
        return "close"
    if any(n.startswith(p) for p in _AUTHORITY):
        return "authority"
    # A liquidation pays the liquidator out of the protocol whatever it
    # swaps on the way (`liquidate_perp_with_fill`, `liquidate_spot_with_swap_begin`).
    if n.startswith("liquidate"):
        return "withdraw"
    # Adding liquidity is a deposit into an existing pool, not the creation
    # the `add_` prefix would otherwise make it.
    if any(p in n for p in _DEPOSIT):
        return "transfer"
    if any(p in n for p in _SWAP):
        return "swap"
    if (any(n.startswith(p) for p in _WITHDRAW) or any(p in n for p in _WITHDRAW[:8])
            or any(w in _WITHDRAW_WORDS for w in words)):
        return "withdraw"
    if any(n.startswith(p) for p in _MINT):
        return "mint"
    if any(n.startswith(p) for p in _CREATE):
        return "create"
    if any(n.startswith(p) for p in _AUTHORITY_LATE):
        return "authority"
    return "transfer"


def _account_words(name):
    return [w for w in snake(re.sub(r"[^A-Za-z0-9]", "_", name)).split("_") if w]


def refine(cls, accts):
    """Account-aware adjustments to a name's family (Round 29, LOW-1).

    * An instruction that requires a signature from an account the IDL names
      an ADMIN (`admin`, `group_admin`, `secondaryAdmin`, ...) is an operation
      only a protocol's administrator may perform — the registry's definition
      of `authority` — whatever its name suggests (external review R3's
      structural rule; the Core applies it again at load). "authority" is NOT
      used here: in most IDLs it names the user's own key.
    * Bookkeeping that writes a value-holding account (a vault, a token
      account, a fee receiver, a pool) is not inert: it is a transfer.
    """
    # An OPTIONAL admin signer (OpenBook v2's `open_orders_admin` on every
    # order) is absent on an ordinary market, so it does not make the
    # instruction an administrator's.
    if any(
        acc["is_signer"] and not acc.get("optional")
        and "admin" in re.sub(r"[^a-z]", "", acc["name"].lower())
        for acc in accts
    ):
        return "authority"
    if cls == "bookkeeping" and any(
        acc["is_writable"] and any(w in _VALUE_ACCOUNT_WORDS for w in _account_words(acc["name"]))
        for acc in accts
    ):
        return "transfer"
    return cls


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
            acct = {
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
            }
            # An Anchor optional account (`optional` in the new IDL spec,
            # `isOptional` in the old): when absent the program's own id
            # fills the slot, unsigned and read-only. The Core treats that as
            # "absent" only for a slot the manifest marks optional (Round 22);
            # without the flag every call that omits it reads as an unsigned
            # signer or a demoted writable (found grounding Tensor AMM,
            # 2026-10-03).
            if a.get("optional") or a.get("isOptional"):
                acct["optional"] = True
            accts.append(acct)
        # Name heuristics tagged Mango's `groupEdit` and `tokenRegister` and
        # Zeta's `halt` as transfers; `refine` applies the admin-signer rule.
        cls = refine(classify(ix["name"]), accts)
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
