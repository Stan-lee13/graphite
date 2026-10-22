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

# lookup_table: [n][table: n*8 bytes][v0 transaction]. Table metadata is 56
# bytes: type tag 1, deactivation slot u64::MAX (active), last-extended slot,
# its start index, an authority option and padding.
for k, raw in zip((1, 4, 16), v0_with_lookups):
    meta = struct.pack("<IQQB", 1, 2**64 - 1, 0, 0) + b"\x00" + b"\x00" * 32 + b"\x00\x00"
    assert len(meta) == 56
    table = meta + b"".join(bytes([j + 1]) * 32 for j in range(k))
    put("lookup_table", f"table{k}", bytes([len(table) // 8]) + table + raw)

for name in (
    "system-program.json",
    "spl-token.json",
    "token-2022.json",
    "stake-program.json",
    "jupiter-v6.json",
):
    with open(os.path.join(core, "protocols", name), "rb") as f:
        put("manifest_json", name, f.read())

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
for name, doc in docs.items():
    put("rpc_json", name, json.dumps(doc).encode())

print({t: len(os.listdir(os.path.join(seeds, t))) for t in sorted(os.listdir(seeds))})
