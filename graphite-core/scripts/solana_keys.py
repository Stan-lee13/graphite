#!/usr/bin/env python3
"""Base58 + Solana address derivation, with a REAL ed25519 on-curve test.

`find_program_address` must reject on-curve candidates the way the runtime
does; approximating that check (e.g. "high bit of the last byte") derives the
wrong address and silently finds nothing. The curve test here decompresses the
point exactly as ed25519 verification does.
"""
import hashlib

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
PDA_MARKER = b"ProgramDerivedAddress"

P = 2**255 - 19
D = (-121665 * pow(121666, P - 2, P)) % P


def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + raw


def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\x00"))) + out


def is_on_curve(pk: bytes) -> bool:
    """True when the 32 bytes decompress to a valid ed25519 point."""
    if len(pk) != 32:
        return False
    y = int.from_bytes(pk, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= P:
        return False
    y2 = (y * y) % P
    u = (y2 - 1) % P
    v = (D * y2 + 1) % P
    if v == 0:
        return False
    # x = u * v^3 * (u * v^7)^((p-5)/8)
    v3 = pow(v, 3, P)
    v7 = pow(v, 7, P)
    x = (u * v3 % P) * pow(u * v7 % P, (P - 5) // 8, P) % P
    vx2 = v * x % P * x % P
    if vx2 == u % P:
        pass
    elif vx2 == (-u) % P:
        x = x * pow(2, (P - 1) // 4, P) % P
    else:
        return False
    if x == 0 and sign:
        return False
    return True


def create_program_address(seeds, program_id: bytes) -> bytes | None:
    h = hashlib.sha256(b"".join(seeds) + program_id + PDA_MARKER).digest()
    return None if is_on_curve(h) else h


def find_program_address(seeds, program_id: bytes):
    for bump in range(255, -1, -1):
        addr = create_program_address(list(seeds) + [bytes([bump])], program_id)
        if addr is not None:
            return addr, bump
    raise RuntimeError("no off-curve bump")


def create_with_seed(base: bytes, seed: str, owner: bytes) -> bytes:
    return hashlib.sha256(base + seed.encode() + owner).digest()


def anchor_idl_address(program_id_b58: str) -> str:
    pid = b58decode(program_id_b58)
    base, _ = find_program_address([], pid)
    return b58encode(create_with_seed(base, "anchor:idl", pid))


if __name__ == "__main__":
    # Known-answer checks against addresses the runtime itself produced.
    ata = b58decode("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
    tok = b58decode("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
    owner = b58decode("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM")
    mint = b58decode("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
    got = b58encode(find_program_address([owner, tok, mint], ata)[0])
    assert got == "FxteHmLwG9nk1eL4pjNve3Eub2goGkkz6g6TbvdmW46a", got
    print("ATA derivation OK")
    assert is_on_curve(b58decode("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"))
    assert not is_on_curve(b58decode("FxteHmLwG9nk1eL4pjNve3Eub2goGkkz6g6TbvdmW46a"))
    print("curve test OK")
