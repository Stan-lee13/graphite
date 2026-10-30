"""The honest-swap pass of live_mainnet.py (Round 41).

Round 40 measured the approval path on constructed honest transfers; no swap
was measured live. This pass does for swaps what that pass did for transfers.

From the fetched blocks it takes the executed swaps a wallet made directly on
a venue whose instruction the Core decodes (the agent guard's set: Jupiter v6
`route` / `shared_accounts_route`, Orca Whirlpools `swap` / `swapV2`, Raydium
CLMM `swap` / `swap_v2`, Raydium CPMM `swap_base_input`, Raydium AMM v4
`SwapBaseIn`, Meteora DLMM `swap` / `swap2`), sent and signed by its own fee
payer alone, beside nothing but what a wallet adds to its own swap: Compute
Budget, an associated-token-account create it pays for, wrapping and
unwrapping its own SOL (a transfer into its own wrapped-SOL account,
`SyncNative`, `CloseAccount` back to itself, a temporary token account it
creates and initializes), or a memo. A swap beside anything else — a tip, a
payment, another program — is set aside and counted by reason.

For each, the honest agent's transaction is the same swap made now: the same
wallet, venue, pool accounts, lookup tables and amount in, with

1. a blockhash just fetched;
2. a minimum output re-quoted against the pool as it stands: the swap is first
   simulated by the RPC with its minimum set to 1 base unit, what it delivers
   to the wallet is read from the simulated accounts, and the minimum is set
   QUOTE_SLIPPAGE_BPS under that (for a Jupiter route: `quoted_out_amount` =
   the quote, `slippage_bps` = QUOTE_SLIPPAGE_BPS);
3. every signature slot zeroed.

It is verified with the intent `swap`: the amount in, the input and output
assets, and `slippage_bps` REQUEST_SLIPPAGE_BPS (the Core's default), under
the built-in Gaming profile. Nothing is signed or sent: the bytes go to the
RPC's simulateTransaction (for the quote, signature verification off) and to
the local Core's /verify only.

What this measures: the decision an honest agent's own direct swap gets from
this Core against today's mainnet state. What it does not measure: routes the
agent would get from an aggregator API today (each swap keeps the route its
wallet chose), swaps beside tips, or anything after signing.
"""
import base64
from collections import Counter

import solrpc
import wire

NATIVE_MINT = "So11111111111111111111111111111111111111112"
SYSTEM_PROGRAM = "11111111111111111111111111111111"
SPL_TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
SPL_TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
TOKEN_PROGRAMS = (SPL_TOKEN_PROGRAM, SPL_TOKEN_2022_PROGRAM)
ATA_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
COMPUTE_BUDGET_PROGRAM = "ComputeBudget111111111111111111111111111111"
MEMO_PROGRAMS = ("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr", "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo")

JUPITER_V6 = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"
ORCA_WHIRLPOOLS = "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc"
RAYDIUM_CPMM = "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C"
RAYDIUM_CLMM = "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK"
RAYDIUM_AMM_V4 = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8"
METEORA_DLMM = "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo"
# The Core's DECODED_SWAP_PROGRAMS (graphite-core/src/intent_binding.rs).
SWAP_PROGRAMS = (JUPITER_V6, ORCA_WHIRLPOOLS, RAYDIUM_CPMM, RAYDIUM_CLMM, RAYDIUM_AMM_V4, METEORA_DLMM)

# (program, selector) → (name, layout), as `intent_binding::decode_swap` reads
# them. Layouts: "jupiter" (in_amount, quoted_out_amount, slippage_bps,
# platform_fee_bps are the data's last 19 bytes); "concentrated" (amount,
# other_amount_threshold, sqrt_price_limit, exact-in flag at byte 40);
# "in_min8" / "in_min1" (amount in, minimum out after an 8- or 1-byte selector).
VENUES = {
    (JUPITER_V6, "e517cb977ae3ad2a"): ("Jupiter v6 route", "jupiter"),
    (JUPITER_V6, "c1209b3341d69c81"): ("Jupiter v6 shared_accounts_route", "jupiter"),
    (ORCA_WHIRLPOOLS, "f8c69e91e17587c8"): ("Orca Whirlpools swap", "concentrated"),
    (ORCA_WHIRLPOOLS, "2b04ed0b1ac91e62"): ("Orca Whirlpools swapV2", "concentrated"),
    (RAYDIUM_CLMM, "f8c69e91e17587c8"): ("Raydium CLMM swap", "concentrated"),
    (RAYDIUM_CLMM, "2b04ed0b1ac91e62"): ("Raydium CLMM swap_v2", "concentrated"),
    (RAYDIUM_CPMM, "8fbe5adac41e33de"): ("Raydium CPMM swap_base_input", "in_min8"),
    (RAYDIUM_AMM_V4, "09"): ("Raydium AMM v4 SwapBaseIn", "in_min1"),
    (METEORA_DLMM, "f8c69e91e17587c8"): ("Meteora DLMM swap", "in_min8"),
    (METEORA_DLMM, "414b3f4ceb5b5b88"): ("Meteora DLMM swap2", "in_min8"),
}

# The minimum is set this far under the quote; the request states the Core's
# default (1%), so the minimum sits inside it while the pool moves less than
# 0.5% between the quote and the Core's own simulation.
QUOTE_SLIPPAGE_BPS = 50
REQUEST_SLIPPAGE_BPS = 100


def _u64(data, at):
    return int.from_bytes(data[at : at + 8], "little")


def _put_u64(data, at, value):
    return data[:at] + int(value).to_bytes(8, "little") + data[at + 8 :]


def venue(program, data):
    """(name, layout) of an exact-in swap instruction the Core decodes; or
    (None, why) for a swap program instruction it does not; or None for any
    other program."""
    if program not in SWAP_PROGRAMS:
        return None
    width = 1 if program == RAYDIUM_AMM_V4 else 8
    found = VENUES.get((program, bytes(data[:width]).hex()))
    if found is None:
        return None, "a swap-program instruction the Core does not decode as an exact-in swap"
    name, kind = found
    need = {"jupiter": 8 + 19, "concentrated": 41, "in_min8": 24, "in_min1": 17}[kind]
    if len(data) < need:
        return None, f"{name}: shorter than its layout"
    if kind == "concentrated" and data[40] != 1:
        return None, "exact-output swap (the Core binds exact-in only)"
    if kind == "jupiter" and data[-1] != 0:
        return None, "Jupiter route with a platform fee (the Core refuses one)"
    return name, kind


def amount_in(kind, data):
    if kind == "jupiter":
        return _u64(data, len(data) - 19)
    if kind == "in_min1":
        return _u64(data, 1)
    return _u64(data, 8)


def with_minimum(kind, data, quoted, slippage_bps):
    """The instruction data with its minimum output set from `quoted` and
    `slippage_bps`: a Jupiter route carries both and the program computes the
    minimum; every other venue carries the minimum itself,
    quoted × (10⁴ − bps) / 10⁴ (at least 1)."""
    data = bytes(data)
    if kind == "jupiter":
        at = len(data) - 11
        return data[:at] + int(quoted).to_bytes(8, "little") + int(slippage_bps).to_bytes(2, "little") + data[at + 10 :]
    minimum = max(1, quoted * (10_000 - slippage_bps) // 10_000)
    return _put_u64(data, 9 if kind == "in_min1" else 16, minimum)


def minimum_of(kind, data):
    """The minimum output the Core decodes from `data`."""
    if kind == "jupiter":
        quoted, bps = _u64(data, len(data) - 11), int.from_bytes(data[-3:-1], "little")
        return quoted * (10_000 - bps) // 10_000
    return _u64(data, 9 if kind == "in_min1" else 16)


def _balances(src, key):
    """account index → (mint, owner, amount, decimals) from the block's token
    balances (`pre_token_balances` / `post_token_balances`)."""
    out = {}
    for b in src.get(key) or []:
        if isinstance(b, dict) and isinstance(b.get("account_index"), int) and b.get("mint"):
            out[b["account_index"]] = (b["mint"], b.get("owner"), b.get("amount"), b.get("decimals"))
    return out


def swap_candidate(src):
    """(candidate, None) for a direct honest swap; (None, why) for a swap set
    aside; (None, None) when the row is not a decoded-venue swap at all."""
    if src.get("err"):
        return None, None
    try:
        msg = wire.message(base64.b64decode(src["b64"]))
    except (KeyError, TypeError, ValueError):
        return None, None
    lw = src.get("loaded_writable") or []
    keys = wire.account_keys(msg, lw, src.get("loaded_readonly") or [])
    if any(ix.program_index >= len(keys) or any(a >= len(keys) for a in ix.accounts) for ix in msg.instructions):
        return None, None
    swaps = [(i, ix) for i, ix in enumerate(msg.instructions) if keys[ix.program_index] in SWAP_PROGRAMS]
    if not swaps:
        return None, None
    if len(swaps) > 1:
        return None, "more than one swap instruction"
    at, sw = swaps[0]
    program = keys[sw.program_index]
    found = venue(program, sw.data)
    if found[0] is None:
        return None, found[1]
    name, kind = found
    if msg.version == "1":
        return None, "v1 frame (not in this pass)"
    if msg.durable_nonce:
        return None, "durable nonce"
    if msg.num_required_signatures != 1:
        return None, "more than one signer"
    sender = keys[0]
    if 0 not in sw.accounts:
        return None, "the fee payer is not an account of the swap"
    pre, post = _balances(src, "pre_token_balances"), _balances(src, "post_token_balances")
    if not pre and not post:
        return None, "the block's token balances were not recorded"
    if any(v[1] is None for v in list(pre.values()) + list(post.values())):
        return None, "the block's token balances name no owners"
    closed = set()
    for i, ix in enumerate(msg.instructions):
        p = keys[ix.program_index]
        if p in TOKEN_PROGRAMS and ix.data[:1] == b"\x09" and len(ix.accounts) >= 3:
            closed.add(keys[ix.accounts[0]])
    owned_wsol = {keys[i] for i, v in list(pre.items()) + list(post.items()) if v[0] == NATIVE_MINT and v[1] == sender}
    for i, ix in enumerate(msg.instructions):
        if i == at:
            continue
        p, data = keys[ix.program_index], ix.data
        accts = [keys[a] for a in ix.accounts]
        if p == COMPUTE_BUDGET_PROGRAM or p in MEMO_PROGRAMS:
            continue
        if p == ATA_PROGRAM and data in (b"", b"\x00", b"\x01"):
            if not accts or accts[0] != sender:
                return None, "ATA created by another payer"
            continue
        if p in TOKEN_PROGRAMS and data[:1] == b"\x11":  # SyncNative
            continue
        if p in TOKEN_PROGRAMS and data[:1] in (b"\x01", b"\x10", b"\x12"):  # InitializeAccount, 2, 3
            continue
        if p in TOKEN_PROGRAMS and data[:1] == b"\x09":  # CloseAccount
            if len(accts) < 3 or accts[1] != sender or accts[2] != sender:
                return None, "an account closed to someone else"
            continue
        if p == SYSTEM_PROGRAM and data[:4] == (2).to_bytes(4, "little") and len(accts) >= 2:
            if accts[0] == sender and (accts[1] in owned_wsol or accts[1] in closed):
                continue  # wrapping its own SOL
            return None, "a SOL transfer beside the swap (a tip or a payment)"
        if p == SYSTEM_PROGRAM and data[:4] in ((0).to_bytes(4, "little"), (3).to_bytes(4, "little")) and accts and accts[0] == sender:
            if data[-32:] in (solrpc.b58decode(SPL_TOKEN_PROGRAM), solrpc.b58decode(SPL_TOKEN_2022_PROGRAM)):
                continue  # a temporary token account it funds
            return None, "an account created beside the swap"
        return None, "another program beside the swap"
    # What the wallet gave and got, from the block's own balances.
    net = Counter()
    for side, sign in ((pre, -1), (post, 1)):
        for v in side.values():
            if v[1] == sender and v[2] is not None:
                net[v[0]] += sign * int(v[2])
    decimals = {v[0]: v[3] for v in list(pre.values()) + list(post.values()) if isinstance(v[3], int)}
    fee = src.get("fee")
    pb, qb = src.get("pre_balances") or [], src.get("post_balances") or []
    if not isinstance(fee, int) or not pb or not qb:
        return None, "the block's fee and balances were not recorded"
    sol = (qb[0] - pb[0] + fee) + net.get(NATIVE_MINT, 0)
    tokens = {m: d for m, d in net.items() if m != NATIVE_MINT and d}
    gave = [m for m, d in tokens.items() if d < 0]
    got = [m for m, d in tokens.items() if d > 0]
    if len(gave) == 1 and len(got) == 1:
        asset_in, asset_out = gave[0], got[0]
    elif not gave and len(got) == 1 and sol < 0:
        asset_in, asset_out = "SOL", got[0]
    elif len(gave) == 1 and not got and sol > 0:
        asset_in, asset_out = gave[0], "SOL"
    else:
        return None, "not a two-asset swap by its balances"
    dec_in = 9 if asset_in == "SOL" else decimals.get(asset_in)
    if not isinstance(dec_in, int):
        return None, "the input mint's decimals were not recorded"
    out_mint = NATIVE_MINT if asset_out == "SOL" else asset_out
    watch = sorted({keys[i] for i, v in list(pre.items()) + list(post.items()) if v[1] == sender and v[0] == out_mint})
    if asset_out == "SOL":
        watch = [sender] + [a for a in watch if a != sender]
    if not watch:
        return None, "no account of the wallet holds the output"
    a_in = amount_in(kind, sw.data)
    if a_in < 1:
        return None, "the input amount is 0"
    return {
        "row": src.get("row"), "slot": src.get("slot"), "sender": sender, "program": program, "venue": name,
        "layout": kind, "index": at, "data": bytes(sw.data), "asset_in": asset_in, "asset_out": asset_out,
        "decimals_in": dec_in, "amount_in": a_in, "watch": watch, "fee": fee, "version": msg.version,
    }, None


def swap_candidates(sample_rows, n):
    """Up to `n` honest direct swaps, venues alternated, one per (sender,
    venue, input, output); and the set-aside counts."""
    found, skipped, seen = {}, Counter(), set()
    for src in sample_rows:
        c, why = swap_candidate(src)
        if why:
            skipped[why] += 1
        if c is None:
            continue
        k = (c["sender"], c["venue"], c["asset_in"], c["asset_out"])
        if k in seen:
            skipped["duplicate sender, venue and pair"] += 1
            continue
        seen.add(k)
        found.setdefault(c["venue"], []).append(c)
    picked, lists = [], list(found.values())
    for i in range(max((len(l) for l in lists), default=0)):
        for l in lists:
            if i < len(l) and len(picked) < n:
                picked.append(l[i])
    return picked, {"swaps on decoded venues": sum(len(l) for l in lists) + sum(skipped.values()),
                    "by venue": {k: len(v) for k, v in found.items()}, "set aside": dict(skipped)}


class QuoteFailed(Exception):
    """No quote; `sim_err` is the simulator's `err` when the swap itself
    failed to simulate."""

    def __init__(self, reason, sim_err=None):
        super().__init__(reason)
        self.sim_err = sim_err


def _held(account, wallet):
    """Base units a token account holds, or lamports for the wallet itself;
    0 for an account that does not exist."""
    if not account:
        return 0
    if account.get("_address") == wallet:
        return int(account.get("lamports") or 0)
    data = account.get("data")
    raw = base64.b64decode(data[0]) if isinstance(data, list) and data else b""
    return int.from_bytes(raw[64:72], "little") if len(raw) >= 72 else 0


def quote(rpc, frame, c, *, call=solrpc.call):
    """What the swap delivers to the wallet now: `frame` (minimum 1) simulated
    by the RPC, the wallet's output accounts read before and after. For SOL
    out, the wallet's own lamports plus the fee (what reached it before the
    fee was taken)."""
    opts = {"encoding": "base64", "commitment": "confirmed"}
    before = call(rpc, "getMultipleAccounts", [c["watch"], opts], attempts=4)
    if "error" in before:
        raise QuoteFailed(f"getMultipleAccounts: {before['error']}")
    sim = call(rpc, "simulateTransaction", [base64.b64encode(bytes(frame)).decode(), {
        "encoding": "base64", "sigVerify": False, "replaceRecentBlockhash": False, "commitment": "confirmed",
        "accounts": {"addresses": c["watch"], "encoding": "base64"}}], attempts=4)
    if "error" in sim:
        raise QuoteFailed(f"simulateTransaction: {sim['error']}")
    value = (sim.get("result") or {}).get("value") or {}
    if value.get("err") is not None:
        raise QuoteFailed("the swap does not simulate now", value["err"])
    pre = (before.get("result") or {}).get("value") or []
    post = value.get("accounts") or []
    if len(pre) != len(c["watch"]) or len(post) != len(c["watch"]):
        raise QuoteFailed("the RPC returned a different number of accounts than asked")
    def tag(a, addr):
        return dict(a, _address=addr) if isinstance(a, dict) else None

    got = sum(_held(tag(b, addr), c["sender"]) - _held(tag(a, addr), c["sender"])
              for addr, a, b in zip(c["watch"], pre, post))
    if c["asset_out"] == "SOL":
        got += c["fee"]
    if got <= 0:
        raise QuoteFailed("the simulation delivered nothing to the wallet")
    return got


def build(frame, c, quoted, slippage_bps, blockhash):
    """The unsigned frame with a fresh blockhash and the minimum set."""
    data = with_minimum(c["layout"], c["data"], quoted, slippage_bps)
    return wire.patch_blockhash(wire.patch_instruction_data(frame, c["index"], data), blockhash), data


def ui(base_units, decimals):
    s = str(base_units).rjust(decimals + 1, "0")
    whole, frac = s[: len(s) - decimals], s[len(s) - decimals :].rstrip("0")
    return f"{whole}.{frac}" if frac else whole


def request(c, harness_input, frame, data):
    """The /verify request: the harness's request for this row, with the
    honest intent, the patched data and the new frame."""
    amount = ui(c["amount_in"], c["decimals_in"])
    body = dict(harness_input)
    body["proposed_intent"] = {
        "intent_type": "swap",
        "raw_natural_language": f"swap {amount} {c['asset_in']} for {c['asset_out']}",
        "confidence_of_parse": 1.0,
        "extracted_parameters": {"amount": amount, "input_token": c["asset_in"], "output_token": c["asset_out"],
                                 "slippage_bps": REQUEST_SLIPPAGE_BPS},
    }
    body["wallet_profile"] = "Gaming"
    body["signed_transaction"] = list(frame)
    if body.get("program_id") == c["program"] and body.get("instruction_data") is not None:
        body["instruction_data"] = list(data)
    return body
