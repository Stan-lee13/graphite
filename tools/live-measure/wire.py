"""Where a serialized Solana transaction keeps its recent blockhash, and a
measurement-side rewrite of it (Round 32, P3b).

The live mainnet replay shows the Core transactions that were built minutes
earlier: their blockhash is stale by the time they are verified. An agent
verifies bytes it is about to sign, with a blockhash it just fetched. To
measure that case, the replay rewrites the 32-byte blockhash of the UNSIGNED
frame it already sends (every signature slot empty) and verifies again. Nothing
is signed and nothing is sent: the bytes go to the local Core's /verify only.

The whole frame is parsed, to its last byte, before anything is rewritten: an
offset read from a frame that does not parse exactly is not trusted.

    legacy  shortvec(sigs) 64×sigs | header(3) shortvec(keys) 32×keys BLOCKHASH ixs
    v0      shortvec(sigs) 64×sigs | 0x80 header(3) shortvec(keys) 32×keys BLOCKHASH ixs lookups
    v1      0x81 header(3) mask(u32) BLOCKHASH ix_count(u8) key_count(u8) keys config ix-headers ix-payloads | sigs

Round 40 (measure): `message` reads every field, and `build_legacy` builds a
new UNSIGNED legacy transaction (zeroed signature slots) for the
honest-transfer pass of live_mainnet.py. Nothing here signs or sends.
"""
from typing import NamedTuple

from solrpc import shortvec

V1_PREFIX = 0x81
V1_MASK_PRIORITY_FEE = 0b11
V1_MASK_COMPUTE_UNIT_LIMIT = 0b100
V1_MASK_LOADED_ACCOUNTS_DATA_SIZE = 0b1000
V1_MASK_HEAP_SIZE = 0b1_0000
V1_MASK_KNOWN = V1_MASK_PRIORITY_FEE | V1_MASK_COMPUTE_UNIT_LIMIT | V1_MASK_LOADED_ACCOUNTS_DATA_SIZE | V1_MASK_HEAP_SIZE
SYSTEM_PROGRAM = bytes(32)
ADVANCE_NONCE_ACCOUNT = (4).to_bytes(4, "little")


class Layout(NamedTuple):
    version: str  # "legacy", "0" or "1"
    blockhash_at: int
    signatures_at: int
    signature_count: int
    durable_nonce: bool  # the blockhash slot holds a nonce value, not a blockhash


class Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, n, what):
        if n < 0 or self.pos + n > len(self.data):
            raise ValueError(f"truncated frame: {what} needs {n} bytes at {self.pos}, {len(self.data) - self.pos} left")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def u8(self, what):
        return self.take(1, what)[0]

    def u16(self, what):
        return int.from_bytes(self.take(2, what), "little")

    def u32(self, what):
        return int.from_bytes(self.take(4, what), "little")

    def compact(self, what):
        try:
            value, self.pos = shortvec(self.data, self.pos)
        except ValueError as e:
            raise ValueError(f"{what}: {e}") from None
        return value


def _durable_nonce(keys, first):
    """Agave's rule: the first instruction is System AdvanceNonceAccount."""
    if first is None:
        return False
    program, data = first
    return program < len(keys) and keys[program] == SYSTEM_PROGRAM and data[:4] == ADVANCE_NONCE_ACCOUNT


def _legacy_or_v0(frame):
    r = Reader(frame)
    nsig = r.compact("signature count")
    sig_at = r.pos
    r.take(64 * nsig, "signatures")
    version = "legacy"
    if r.u8("message header or version prefix") & 0x80:
        v = frame[r.pos - 1] & 0x7F
        if v != 0:
            raise ValueError(f"message version {v} in a signatures-first frame")
        version = "0"
    else:
        r.pos -= 1  # the byte was the header's first
    r.take(3, "message header")
    nkeys = r.compact("account key count")
    keys = [r.take(32, "account key") for _ in range(nkeys)]
    blockhash_at = r.pos
    r.take(32, "recent blockhash")
    first = None
    for i in range(r.compact("instruction count")):
        program = r.u8("program index")
        r.take(r.compact("account index count"), "account indexes")
        data = r.take(r.compact("data length"), "instruction data")
        if i == 0:
            first = (program, data)
    if version == "0":
        for _ in range(r.compact("lookup count")):
            r.take(32, "lookup table")
            r.take(r.compact("writable index count"), "writable indexes")
            r.take(r.compact("readonly index count"), "readonly indexes")
    if r.pos != len(frame):
        raise ValueError(f"{len(frame) - r.pos} trailing bytes after the message")
    return Layout(version, blockhash_at, sig_at, nsig, _durable_nonce(keys, first))


def _v1(frame):
    r = Reader(frame)
    r.u8("version prefix")
    nreq = r.u8("num_required_signatures")
    r.take(2, "header")
    mask = r.u32("config mask")
    if mask & ~V1_MASK_KNOWN:
        raise ValueError(f"v1 config mask {mask:#x} has unknown bits")
    fee = mask & V1_MASK_PRIORITY_FEE
    if fee not in (0, V1_MASK_PRIORITY_FEE):
        raise ValueError(f"v1 config mask {mask:#x} sets half the priority fee")
    blockhash_at = r.pos
    r.take(32, "lifetime specifier")
    nix = r.u8("instruction count")
    nkeys = r.u8("account address count")
    keys = [r.take(32, "account address") for _ in range(nkeys)]
    if fee:
        r.take(8, "priority fee")
    for bit in (V1_MASK_COMPUTE_UNIT_LIMIT, V1_MASK_LOADED_ACCOUNTS_DATA_SIZE, V1_MASK_HEAP_SIZE):
        if mask & bit:
            r.take(4, "config value")
    headers = [(r.u8("program index"), r.u8("account count"), r.u16("data length")) for _ in range(nix)]
    first = None
    for i, (program, naccounts, ndata) in enumerate(headers):
        r.take(naccounts, "account indexes")
        data = r.take(ndata, "instruction data")
        if i == 0:
            first = (program, data)
    sig_at = r.pos
    r.take(64 * nreq, "signatures")
    if r.pos != len(frame):
        raise ValueError(f"{len(frame) - r.pos} trailing bytes after the signatures")
    return Layout("1", blockhash_at, sig_at, nreq, _durable_nonce(keys, first))


def layout(frame):
    """The frame's version and where its blockhash and signatures are.
    ValueError for anything that does not parse to its last byte."""
    frame = bytes(frame)
    if not frame:
        raise ValueError("empty frame")
    return _v1(frame) if frame[0] == V1_PREFIX else _legacy_or_v0(frame)


def blockhash(frame):
    lay = layout(frame)
    return bytes(frame[lay.blockhash_at : lay.blockhash_at + 32])


# ── the whole message (Round 40, measure) ────────────────────────────────────
#
# The honest-transfer pass reads a sampled transaction's instructions (which
# program, which accounts, which data) and builds a NEW unsigned legacy
# transaction from them. Same discipline as `layout`: the frame is parsed to
# its last byte or refused.


class Instruction(NamedTuple):
    program_index: int
    accounts: tuple  # indexes into the transaction's account list
    data: bytes


class Message(NamedTuple):
    version: str  # "legacy", "0" or "1"
    num_required_signatures: int
    num_readonly_signed: int
    num_readonly_unsigned: int
    static_keys: tuple  # 32-byte keys
    blockhash: bytes
    instructions: tuple  # Instruction
    lookups: tuple  # (table key, writable indexes, readonly indexes)
    v1_config: dict  # v1 only: priority_fee_lamports, compute_unit_limit, ...
    durable_nonce: bool


def message(frame):
    """Every field of a legacy, v0 or v1 frame. ValueError for anything that
    does not parse to its last byte."""
    frame = bytes(frame)
    if not frame:
        raise ValueError("empty frame")
    return _message_v1(frame) if frame[0] == V1_PREFIX else _message_legacy_or_v0(frame)


def _message_legacy_or_v0(frame):
    r = Reader(frame)
    nsig = r.compact("signature count")
    r.take(64 * nsig, "signatures")
    version = "legacy"
    if r.u8("message header or version prefix") & 0x80:
        v = frame[r.pos - 1] & 0x7F
        if v != 0:
            raise ValueError(f"message version {v} in a signatures-first frame")
        version = "0"
    else:
        r.pos -= 1
    nreq, ro_signed, ro_unsigned = r.take(3, "message header")
    keys = tuple(r.take(32, "account key") for _ in range(r.compact("account key count")))
    hash_ = r.take(32, "recent blockhash")
    ixs = []
    for _ in range(r.compact("instruction count")):
        program = r.u8("program index")
        accounts = tuple(r.take(r.compact("account index count"), "account indexes"))
        ixs.append(Instruction(program, accounts, r.take(r.compact("data length"), "instruction data")))
    lookups = []
    if version == "0":
        for _ in range(r.compact("lookup count")):
            table = r.take(32, "lookup table")
            w = tuple(r.take(r.compact("writable index count"), "writable indexes"))
            ro = tuple(r.take(r.compact("readonly index count"), "readonly indexes"))
            lookups.append((table, w, ro))
    if r.pos != len(frame):
        raise ValueError(f"{len(frame) - r.pos} trailing bytes after the message")
    if nreq != nsig:
        raise ValueError(f"{nsig} signature slots for {nreq} required signatures")
    first = (ixs[0].program_index, ixs[0].data) if ixs else None
    return Message(version, nreq, ro_signed, ro_unsigned, keys, hash_, tuple(ixs), tuple(lookups), {},
                   _durable_nonce(list(keys), first))


def _message_v1(frame):
    r = Reader(frame)
    r.u8("version prefix")
    nreq, ro_signed, ro_unsigned = r.take(3, "header")
    mask = r.u32("config mask")
    if mask & ~V1_MASK_KNOWN:
        raise ValueError(f"v1 config mask {mask:#x} has unknown bits")
    fee = mask & V1_MASK_PRIORITY_FEE
    if fee not in (0, V1_MASK_PRIORITY_FEE):
        raise ValueError(f"v1 config mask {mask:#x} sets half the priority fee")
    hash_ = r.take(32, "lifetime specifier")
    nix = r.u8("instruction count")
    keys = tuple(r.take(32, "account address") for _ in range(r.u8("account address count")))
    config = {}
    if fee:
        config["priority_fee_lamports"] = int.from_bytes(r.take(8, "priority fee"), "little")
    for bit, name in ((V1_MASK_COMPUTE_UNIT_LIMIT, "compute_unit_limit"),
                      (V1_MASK_LOADED_ACCOUNTS_DATA_SIZE, "loaded_accounts_data_size_limit"),
                      (V1_MASK_HEAP_SIZE, "heap_size")):
        if mask & bit:
            config[name] = r.u32("config value")
    headers = [(r.u8("program index"), r.u8("account count"), r.u16("data length")) for _ in range(nix)]
    ixs = []
    for program, naccounts, ndata in headers:
        accounts = tuple(r.take(naccounts, "account indexes"))
        ixs.append(Instruction(program, accounts, r.take(ndata, "instruction data")))
    r.take(64 * nreq, "signatures")
    if r.pos != len(frame):
        raise ValueError(f"{len(frame) - r.pos} trailing bytes after the signatures")
    first = (ixs[0].program_index, ixs[0].data) if ixs else None
    return Message("1", nreq, ro_signed, ro_unsigned, keys, hash_, tuple(ixs), (), config,
                   _durable_nonce(list(keys), first))


def privileges(msg, index, loaded_writable_count=0):
    """(is_signer, is_writable) of account `index` as the message's header
    sets them; a lookup-table entry is a non-signer, writable when it is one
    of the tables' writable entries."""
    n = len(msg.static_keys)
    if index >= n:
        return False, index < n + loaded_writable_count
    if index < msg.num_required_signatures:
        return True, index < msg.num_required_signatures - msg.num_readonly_signed
    return False, index < n - msg.num_readonly_unsigned


def account_keys(msg, loaded_writable=(), loaded_readonly=()):
    """The transaction's whole account list, as the runtime orders it: static
    keys, then the lookup tables' writable entries, then their read-only ones
    (`loadedAddresses`, base58, from the block that carried it)."""
    import solrpc

    return [solrpc.b58encode(k) for k in msg.static_keys] + list(loaded_writable) + list(loaded_readonly)


# ── a minimal legacy builder (Round 40, measure) ─────────────────────────────


def _compact(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def build_legacy(fee_payer, instructions, recent_blockhash):
    """An UNSIGNED legacy transaction: one zeroed signature slot per required
    signer (the placeholder a wallet fills when it signs — the Core refuses a
    filled one, so nothing here can be submitted), then the message.

    `instructions` is a list of (program, [(account, is_signer, is_writable)],
    data) with base58 addresses. Accounts are ordered as the runtime requires
    and as `@solana/web3.js` `Transaction.compileMessage` orders them: the fee
    payer first, then writable signers, read-only signers, writable
    non-signers, read-only non-signers, each group in first-appearance order;
    programs are read-only non-signers."""
    import solrpc

    if len(recent_blockhash) != 32:
        raise ValueError("a blockhash is 32 bytes")
    metas = {fee_payer: [True, True]}
    order = [fee_payer]

    def note(key, signer, writable):
        if key not in metas:
            metas[key] = [False, False]
            order.append(key)
        metas[key][0] |= signer
        metas[key][1] |= writable

    for program, accounts, _ in instructions:
        for key, signer, writable in accounts:
            note(key, signer, writable)
        note(program, False, False)
    groups = [(True, True), (True, False), (False, True), (False, False)]
    keys = [k for g in groups for k in order if tuple(metas[k]) == g]
    keys.remove(fee_payer)
    keys.insert(0, fee_payer)
    index = {k: i for i, k in enumerate(keys)}
    nreq = sum(1 for k in keys if metas[k][0])
    ro_signed = sum(1 for k in keys if metas[k][0] and not metas[k][1])
    ro_unsigned = sum(1 for k in keys if not metas[k][0] and not metas[k][1])
    msg = bytearray([nreq, ro_signed, ro_unsigned])
    msg += _compact(len(keys))
    for k in keys:
        raw = solrpc.b58decode(k)
        if len(raw) != 32:
            raise ValueError(f"{k} is not a 32-byte address")
        msg += raw
    msg += bytes(recent_blockhash)
    msg += _compact(len(instructions))
    for program, accounts, data in instructions:
        msg.append(index[program])
        msg += _compact(len(accounts)) + bytes(index[a] for a, _, _ in accounts)
        msg += _compact(len(data)) + bytes(data)
    return _compact(nreq) + bytes(64 * nreq) + bytes(msg)


SYSTEM_PROGRAM_ID = "11111111111111111111111111111111"
SPL_TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
COMPUTE_BUDGET_PROGRAM_ID = "ComputeBudget111111111111111111111111111111"


def system_transfer(source, destination, lamports):
    """System `Transfer { lamports }`: bincode u32 2, then u64 LE."""
    return (SYSTEM_PROGRAM_ID, [(source, True, True), (destination, False, True)],
            (2).to_bytes(4, "little") + int(lamports).to_bytes(8, "little"))


def token_transfer_checked(source, mint, destination, authority, amount, decimals):
    """SPL Token `TransferChecked { amount, decimals }` (tag 12):
    [source, mint, destination, authority]."""
    return (SPL_TOKEN_PROGRAM_ID,
            [(source, False, True), (mint, False, False), (destination, False, True), (authority, True, False)],
            bytes([12]) + int(amount).to_bytes(8, "little") + bytes([decimals]))


def patch_blockhash(frame, new_hash):
    """The same unsigned frame with `new_hash` as its recent blockhash. Refuses
    a frame with a filled signature slot (rewriting signed bytes is not
    measurement), and a durable-nonce frame (its blockhash slot is a nonce
    value; "fresh" means nothing for it)."""
    frame = bytes(frame)
    if len(new_hash) != 32:
        raise ValueError("a blockhash is 32 bytes")
    lay = layout(frame)
    sigs = frame[lay.signatures_at : lay.signatures_at + 64 * lay.signature_count]
    if any(sigs):
        raise ValueError("the frame carries a signature; only unsigned bytes are rewritten")
    if lay.durable_nonce:
        raise ValueError("durable nonce: the blockhash slot holds the nonce value")
    return frame[: lay.blockhash_at] + bytes(new_hash) + frame[lay.blockhash_at + 32 :]
