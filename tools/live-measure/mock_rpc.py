"""A loopback Solana JSON-RPC stand-in for dry runs of the live workflows.

Not a validator: just enough of the RPC surface that `live_mainnet.py`, the
Core's simulation path and `live_devnet.py`'s airdrop step can run end to end
on a machine that cannot reach Solana, so the first hosted run is not the
first run. Every answer is plausible in shape and says nothing true about any
chain.

    python3 mock_rpc.py --port 8899 --sample ../../graphite-core/fixtures/mainnet/sample-2026-09-23-last-2-blocks.json

`--rate-limit getBlock,requestAirdrop` answers those methods with HTTP 429, to
exercise the backoff and the honest "inconclusive / skipped" reporting.
"""
import argparse
import base64
import json
import sys
import threading
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEVNET_GENESIS = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"
BLOCKHASH = "4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZAMdL4VZHirAn"
SYSTEM_PROGRAM = "11111111111111111111111111111111"
NATIVE_LOADER = "NativeLoader1111111111111111111111111111111"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(raw):
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


def shortvec(data, at):
    value = shift = 0
    while True:
        b = data[at]
        at += 1
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            return value, at
        shift += 7


def effects(raw):
    """(account keys, lamport deltas, fee) of a wire transaction: the fee (5000 per
    signature) from the payer, and every top-level System transfer. Enough for
    a balance-array answer that is consistent with the bytes; nothing else
    about execution is modelled."""
    nsig, at = shortvec(raw, 0)
    at += 64 * nsig
    if raw[at] & 0x80:  # versioned message prefix
        at += 1
    at += 3  # header
    nkeys, at = shortvec(raw, at)
    keys = [b58encode(raw[at + 32 * i : at + 32 * (i + 1)]) for i in range(nkeys)]
    at += 32 * nkeys + 32  # keys, recent blockhash
    delta = [0] * nkeys
    delta[0] -= 5000 * nsig
    nix, at = shortvec(raw, at)
    for _ in range(nix):
        prog = raw[at]
        at += 1
        nacc, at = shortvec(raw, at)
        accs = list(raw[at : at + nacc])
        at += nacc
        ndata, at = shortvec(raw, at)
        data = raw[at : at + ndata]
        at += ndata
        # An index past the static keys is a lookup-table account: not modelled.
        if prog < nkeys and keys[prog] == SYSTEM_PROGRAM and len(data) == 12 and int.from_bytes(data[:4], "little") == 2 \
                and len(accs) >= 2 and max(accs[:2]) < nkeys:
            lamports = int.from_bytes(data[4:12], "little")
            delta[accs[0]] -= lamports
            delta[accs[1]] += lamports
    return keys, delta, 5000 * nsig


class State:
    def __init__(self, sample_path, rate_limited, genesis):
        self.blocks = defaultdict(list)
        if sample_path:
            with open(sample_path, encoding="utf-8") as f:
                for r in json.load(f)["rows"]:
                    self.blocks[r["slot"]].append(r)
        self.head = (max(self.blocks) + 40) if self.blocks else 400_000_000
        self.rate_limited = set(rate_limited)
        self.genesis = genesis
        self.balances = defaultdict(int)
        # With a mainnet sample loaded, every account other people's
        # transactions touch exists and can pay its fees; without one, only
        # what the faucet funded exists.
        self.default_balance = 10_000_000_000 if self.blocks else 0
        self.calls = defaultdict(int)
        self.sent = {}  # signature -> (slot, base64 transaction)
        self.lock = threading.Lock()

    def balance(self, address):
        return self.balances.get(address, self.default_balance)

    def account(self, address, after=None):
        """A funded address is a System-owned account; the System program is
        the native program; anything else does not exist. `after` maps
        addresses to the lamport change a simulated transaction makes."""
        if address == SYSTEM_PROGRAM:
            return {"lamports": 1, "owner": NATIVE_LOADER, "data": ["", "base64"], "executable": True, "rentEpoch": 0, "space": 0}
        lamports = self.balance(address) + (after or {}).get(address, 0)
        if lamports <= 0:
            return None
        return {"lamports": lamports, "owner": SYSTEM_PROGRAM, "data": ["", "base64"], "executable": False, "rentEpoch": 0, "space": 0}

    def answer(self, method, params):
        if method == "getSlot":
            return self.head
        if method == "getBlock":
            slot = params[0]
            # Fetchers count back from the head in strides; serve the sample's
            # blocks for whatever slots are asked, in order.
            slots = sorted(self.blocks)
            if not slots:
                return None
            pick = slots[(self.head - slot) // 20 % len(slots)] if slot not in self.blocks else slot
            return {
                "blockhash": BLOCKHASH,
                "parentSlot": slot - 1,
                "transactions": [
                    {
                        "transaction": [r["b64"], "base64"],
                        "version": int(r["version"]) if str(r["version"]).isdigit() else "legacy",
                        "meta": {
                            "err": {"InstructionError": [0, "Custom(1)"]} if r["err"] else None,
                            "computeUnitsConsumed": r["cu"],
                            "loadedAddresses": {"writable": r["loaded_writable"], "readonly": r["loaded_readonly"]},
                        },
                    }
                    for r in self.blocks[pick]
                ],
            }
        if method == "getGenesisHash":
            return self.genesis
        if method == "getVersion":
            return {"solana-core": "mock", "feature-set": 0}
        if method == "requestAirdrop":
            with self.lock:
                self.balances[params[0]] += int(params[1])
            return "5" * 87
        if method == "getBalance":
            return {"context": {"slot": self.head}, "value": self.balances[params[0]]}
        if method == "getLatestBlockhash":
            return {"context": {"slot": self.head}, "value": {"blockhash": BLOCKHASH, "lastValidBlockHeight": self.head + 150}}
        if method == "simulateTransaction":
            cfg = params[1] if len(params) > 1 and isinstance(params[1], dict) else {}
            addrs = (cfg.get("accounts") or {}).get("addresses")
            balances, after = {}, {}
            try:
                parsed = effects(base64.b64decode(params[0])) if cfg.get("encoding") == "base64" else None
            except (IndexError, ValueError):
                parsed = None  # a layout this mock does not read: no balance arrays, as an incomplete answer
            if parsed:
                keys, delta, fee = parsed
                pre = [self.balance(k) for k in keys]
                balances = {"preBalances": pre, "postBalances": [a + d for a, d in zip(pre, delta)], "fee": fee,
                            "preTokenBalances": [], "postTokenBalances": [], "loadedAddresses": {"writable": [], "readonly": []}}
                after = dict(zip(keys, delta))
            return {
                "context": {"slot": self.head},
                "value": {
                    "err": None,
                    "logs": [f"Program {SYSTEM_PROGRAM} invoke [1]", f"Program {SYSTEM_PROGRAM} success"],
                    "accounts": [self.account(a, after) for a in addrs] if addrs is not None else None,
                    "unitsConsumed": 150,
                    "returnData": None,
                    "innerInstructions": [],
                    **balances,
                },
            }
        if method == "getMultipleAccounts":
            return {"context": {"slot": self.head}, "value": [self.account(a) for a in params[0]]}
        if method == "getAccountInfo":
            return {"context": {"slot": self.head}, "value": self.account(params[0])}
        if method == "sendTransaction":
            raw = base64.b64decode(params[0]) if (len(params) > 1 and isinstance(params[1], dict) and params[1].get("encoding") == "base64") else None
            if raw is None:
                raise KeyError("sendTransaction (base64 only)")
            sig = b58encode(raw[1:65])
            keys, delta, fee = effects(raw)
            with self.lock:
                pre = [self.balance(k) for k in keys]
                for k, a, d in zip(keys, pre, delta):
                    self.balances[k] = a + d
                self.sent[sig] = (self.head, params[0], pre, [a + d for a, d in zip(pre, delta)], fee)
            return sig
        if method == "getSignatureStatuses":
            return {
                "context": {"slot": self.head},
                "value": [
                    {"slot": self.sent[s][0], "confirmations": None, "err": None, "status": {"Ok": None}, "confirmationStatus": "finalized"} if s in self.sent else None
                    for s in params[0]
                ],
            }
        if method == "getTransaction":
            sent = self.sent.get(params[0])
            if not sent:
                return None
            return {
                "slot": sent[0],
                "blockTime": 1_790_000_000,
                "transaction": [sent[1], "base64"],
                "meta": {"err": None, "status": {"Ok": None}, "fee": sent[4], "computeUnitsConsumed": 150,
                         "logMessages": [], "innerInstructions": [], "preBalances": sent[2], "postBalances": sent[3],
                         "preTokenBalances": [], "postTokenBalances": [], "loadedAddresses": {"writable": [], "readonly": []}},
            }
        if method == "getBlockHeight":
            return self.head
        if method == "isBlockhashValid":
            return {"context": {"slot": self.head}, "value": True}
        if method == "getFeeForMessage":
            return {"context": {"slot": self.head}, "value": 5000}
        if method == "getEpochInfo":
            return {"epoch": 900, "slotIndex": 0, "slotsInEpoch": 432000, "absoluteSlot": self.head, "blockHeight": self.head}
        if method == "getMinimumBalanceForRentExemption":
            return 890880
        raise KeyError(method)


def handler_for(state):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(length) or b"{}")
            batch = isinstance(req, list)
            reqs = req if batch else [req]
            out = []
            for r in reqs:
                method = r.get("method", "")
                with state.lock:
                    state.calls[method] += 1
                if method in state.rate_limited:
                    self.send_response(429)
                    self.end_headers()
                    self.wfile.write(b'{"error":"Too Many Requests"}')
                    return
                try:
                    result = state.answer(method, r.get("params") or [])
                    out.append({"jsonrpc": "2.0", "id": r.get("id"), "result": result})
                except KeyError:
                    out.append({"jsonrpc": "2.0", "id": r.get("id"), "error": {"code": -32601, "message": f"mock: {method} not supported"}})
            body = json.dumps(out if batch else out[0]).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8899)
    ap.add_argument("--sample")
    ap.add_argument("--rate-limit", default="")
    ap.add_argument("--genesis", default=DEVNET_GENESIS)
    args = ap.parse_args(argv)
    state = State(args.sample, [m for m in args.rate_limit.split(",") if m], args.genesis)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler_for(state))
    print(f"mock rpc on 127.0.0.1:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
