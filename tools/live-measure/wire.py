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
