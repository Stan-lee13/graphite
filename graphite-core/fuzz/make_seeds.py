"""Write the committed fuzz seed corpora under fuzz/seeds/.

Run from graphite-core:  python3 fuzz/make_seeds.py

Seeds are real inputs where the repository has them (mainnet transactions from
the committed blocks, the shipped manifests) and hand-built valid layouts where
it does not (lookup tables, token accounts, RPC response objects), so every
target starts from inputs that get past its first refusal.
"""
import base64
import json
import os
import shutil
import struct

core = os.getcwd()
seeds = os.path.join(core, "fuzz", "seeds")
shutil.rmtree(seeds, ignore_errors=True)


def put(target, name, data):
    d = os.path.join(seeds, target)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)


sample = json.load(
    open(os.path.join(core, "fixtures/mainnet/sample-2026-09-23-last-2-blocks.json"))
)
taken = {"legacy": 0, "0": 0}
v0_with_lookups = []
for i, row in enumerate(sample["rows"]):
    version = str(row["version"])
    raw = base64.b64decode(row["b64"])
    if version == "0" and row["loaded_writable"] + row["loaded_readonly"]:
        v0_with_lookups.append(raw)
    if taken.get(version, 99) < 12:
        taken[version] += 1
        put("parse_transaction", f"mainnet-{version}-{i}", raw)

# lookup_table: [n: u16 LE][table: n bytes][v0 transaction]. Table metadata
# is 56 bytes: type tag 1, deactivation slot u64::MAX (active), last-extended
# slot, its start index, an authority option and padding. Audit A002: a table
# of 256 entries, so every index a real lookup can name resolves.
for k, raw in zip((1, 4, 16, 256), v0_with_lookups + v0_with_lookups):
    meta = struct.pack("<IQQB", 1, 2**64 - 1, 0, 0) + b"\x00" + b"\x00" * 32 + b"\x00\x00"
    assert len(meta) == 56
    table = meta + b"".join(bytes([j % 255 + 1, j // 255 + 1]) * 16 for j in range(k))
    put("lookup_table", f"table{k}", struct.pack("<H", len(table)) + table + raw)

small_manifests = 0
for name in (
    "system-program.json",
    "spl-token.json",
    "token-2022.json",
    "stake-program.json",
    "jupiter-v6.json",
):
    with open(os.path.join(core, "protocols", name), "rb") as f:
        whole = f.read()
    put("manifest_json", name, whole)
    # Audit A002: and small documents a mutation can stay valid around: the
    # shipped manifest cut to its first instruction, then to its first two
    # (a discriminator pair for the prefix-ambiguity rule), where the cut is
    # under 4 KiB.
    doc = json.loads(whole)
    for keep in (1, 2):
        small = dict(doc, instructions=doc["instructions"][:keep])
        text = json.dumps(small, separators=(",", ":")).encode()
        if len(text) < 4096:
            put("manifest_json", f"{name[:-5]}-{keep}.json", text)
            small_manifests += 1

assert small_manifests >= 8, small_manifests

mint_key = bytes(range(32))
owner = bytes(range(32, 64))
# SPL token account (165 bytes): mint, owner, amount, delegate option,
# state (1 = initialized), is_native option, delegated amount, close
# authority option.
token = (
    mint_key
    + owner
    + struct.pack("<Q", 1000)
    + struct.pack("<I", 0)
    + b"\x00" * 32
    + b"\x01"
    + struct.pack("<I", 0)
    + struct.pack("<Q", 0)
    + struct.pack("<Q", 0)
    + struct.pack("<I", 0)
    + b"\x00" * 32
)
assert len(token) == 165, len(token)
put("token_extensions", "token-account", token)
# SPL mint (82 bytes): mint authority option, supply, decimals, initialized,
# freeze authority option.
mint = (
    struct.pack("<I", 1)
    + owner
    + struct.pack("<Q", 10**9)
    + b"\x06"
    + b"\x01"
    + struct.pack("<I", 0)
    + b"\x00" * 32
)
assert len(mint) == 82, len(mint)
put("token_extensions", "mint", mint)
# Token-2022 account: the base account, the account-type byte (2), then TLV
# entries TransferFeeAmount (type 2, 8 bytes withheld) and ImmutableOwner
# (type 7, empty).
t22 = token + b"\x02" + struct.pack("<HH", 2, 8) + struct.pack("<Q", 5) + struct.pack("<HH", 7, 0)
put("token_extensions", "t22-account", t22)
# Token-2022 mint: padded to the account size, account type 1, then
# TransferFeeConfig (type 1, 108 bytes).
t22_mint = mint + b"\x00" * (165 - 82) + b"\x01" + struct.pack("<HH", 1, 108) + b"\x00" * 108
put("token_extensions", "t22-mint", t22_mint)

# state_diff is driven through `arbitrary`; any bytes are a valid input, and
# these give the fuzzer a delta with a token-account-sized data field to start
# from.
put("state_diff", "ascending", bytes(range(256)) * 2)
put("state_diff", "token-delta", b"\x01\x00" + struct.pack("<Q", 5) + b"\x00" + token + b"\x01")

docs = {
    "account": {
        "lamports": 2039280,
        "owner": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        "executable": False,
        "rentEpoch": 18446744073709551615,
        "data": [base64.b64encode(token).decode(), "base64"],
    },
    "simulation": {
        "err": None,
        "logs": [
            "Program 11111111111111111111111111111111 invoke [1]",
            "Program 11111111111111111111111111111111 success",
        ],
        "unitsConsumed": 150,
        "returnData": None,
        "preBalances": [10, 0],
        "postBalances": [5, 5],
        "innerInstructions": [{"index": 0, "instructions": []}],
    },
    "epoch": {
        "absoluteSlot": 449808725,
        "epoch": 1041,
        "slotIndex": 92725,
        "slotsInEpoch": 432000,
    },
    "null": None,
}
# Audit A002: the inner instructions in the form Agave returns under
# jsonParsed (`parsed_inner::rebuild`): a parsed System transfer and a parsed
# SPL Token transferChecked, each with its stackHeight, beside a raw one.
docs["simulation-parsed-inner"] = dict(
    docs["simulation"],
    innerInstructions=[
        {
            "index": 0,
            "instructions": [
                {
                    "program": "system",
                    "programId": "11111111111111111111111111111111",
                    "parsed": {
                        "type": "transfer",
                        "info": {
                            "source": "4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T",
                            "destination": "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
                            "lamports": 5,
                        },
                    },
                    "stackHeight": 2,
                },
                {
                    "program": "spl-token",
                    "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                    "parsed": {
                        "type": "transferChecked",
                        "info": {
                            "source": "7UX2i7SucgLMQcfZ75s3VXmZZY4YRUyJN9X1RgfMoDUi",
                            "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                            "destination": "5Q544fKrFoe6tsEbD7S8EmxGTJYAKtTVhAW5Q5pge4j1",
                            "authority": "4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T",
                            "tokenAmount": {"amount": "1000", "decimals": 6, "uiAmount": 0.001, "uiAmountString": "0.001"},
                        },
                    },
                    "stackHeight": 2,
                },
                {
                    "programId": "ComputeBudget111111111111111111111111111111",
                    "accounts": [],
                    "data": "3DTZbgwsozUF",
                    "stackHeight": 2,
                },
            ],
        }
    ],
)
for name, doc in docs.items():
    put("rpc_json", name, json.dumps(doc).encode())

# swap_decoder (audit A045): `[program index][instruction data]`, the index
# into SWAP_DECODER_PROGRAMS (tests/swap_decoder_check/mod.rs). The data is
# every instruction of a decoded program in the committed mainnet sample and
# pinned fixtures, and hand-built valid layouts for the selectors no committed
# transaction carries (Orca's two swaps, Meteora DLMM's two).
SWAP_PROGRAMS = [
    "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
    "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc",
    "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C",
    "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK",
    "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8",
    "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo",
]
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(b):
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + out


def b58decode(text):
    n = 0
    for ch in text:
        n = n * 58 + B58.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(text) - len(text.lstrip("1"))) + body


def compact_u16(b, i):
    value, shift = 0, 0
    while True:
        x = b[i]
        i += 1
        value |= (x & 0x7F) << shift
        shift += 7
        if not x & 0x80:
            return value, i


def instructions(raw):
    """(program id, data) of each top-level instruction of a wire transaction
    whose program is a static key; nothing for one that does not parse."""
    try:
        n, i = compact_u16(raw, 0)
        i += 64 * n
        if raw[i] & 0x80:
            i += 1
        i += 3
        nkeys, i = compact_u16(raw, i)
        keys = [b58encode(raw[i + 32 * k : i + 32 * k + 32]) for k in range(nkeys)]
        i += 32 * nkeys + 32
        nix, i = compact_u16(raw, i)
        out = []
        for _ in range(nix):
            program = raw[i]
            i += 1
            naccounts, i = compact_u16(raw, i)
            i += naccounts
            ndata, i = compact_u16(raw, i)
            data = raw[i : i + ndata]
            i += ndata
            if len(data) != ndata:
                return []
            if program < len(keys):
                out.append((keys[program], data))
        return out
    except IndexError:
        return []


swaps = {}
for row in sample["rows"]:
    for program, data in instructions(base64.b64decode(row["b64"])):
        if program in SWAP_PROGRAMS:
            swaps.setdefault((program, data), f"mainnet-{row['slot']}")
for name in ("jup", "clmm", "cpmm"):
    fixture = json.load(open(os.path.join(core, "tests", "fixtures", f"real_mainnet_{name}.json")))
    message = fixture["transaction"]["message"]
    keys = [k if isinstance(k, str) else k["pubkey"] for k in message["accountKeys"]]
    for ix in message["instructions"]:
        program = keys[ix["programIdIndex"]]
        if program in SWAP_PROGRAMS:
            swaps.setdefault((program, b58decode(ix["data"])), f"fixture-{name}")
amounts = struct.pack("<QQ", 1_000_000, 990_000)
concentrated = amounts + b"\x00" * 16 + b"\x01"
for program, data, name in (
    # Orca swap: amount, threshold, sqrt price limit, exact-in, a_to_b.
    (SWAP_PROGRAMS[1], bytes.fromhex("f8c69e91e17587c8") + concentrated + b"\x01", "built-orca-swap"),
    # Orca swapV2: the same, then an Option<RemainingAccountsInfo> of one slice.
    (
        SWAP_PROGRAMS[1],
        bytes.fromhex("2b04ed0b1ac91e62") + concentrated + b"\x00" + b"\x01" + struct.pack("<I", 1) + b"\x00\x02",
        "built-orca-swapv2",
    ),
    (SWAP_PROGRAMS[5], bytes.fromhex("f8c69e91e17587c8") + amounts, "built-dlmm-swap"),
    # DLMM swap2: and its RemainingAccountsInfo, one slice of type 3 (multi-reward, with its index).
    (
        SWAP_PROGRAMS[5],
        bytes.fromhex("414b3f4ceb5b5b88") + amounts + struct.pack("<I", 1) + b"\x03\x01\x02",
        "built-dlmm-swap2",
    ),
):
    swaps.setdefault((program, data), name)
by_program = {}
for (program, data), origin in sorted(swaps.items(), key=lambda kv: (kv[1], kv[0][1])):
    which = SWAP_PROGRAMS.index(program)
    by_program[which] = by_program.get(which, 0) + 1
    put("swap_decoder", f"{origin}-{which}-{data[:8].hex()}-{len(data)}", bytes([which]) + data)
# Every decoded program has a seed, Jupiter several of each route.
assert sorted(by_program) == list(range(len(SWAP_PROGRAMS))), by_program
assert by_program[0] >= 20, by_program

print({t: len(os.listdir(os.path.join(seeds, t))) for t in sorted(os.listdir(seeds))})
