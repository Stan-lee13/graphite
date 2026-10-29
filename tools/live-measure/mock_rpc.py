"""A loopback Solana JSON-RPC stand-in for dry runs of the live workflows.

Not a validator: just enough of the RPC surface that `live_mainnet.py`, the
Core's simulation path and `live_devnet.py`'s airdrop step can run end to end
on a machine that cannot reach Solana, so the first hosted run is not the
first run. Every answer is plausible in shape and says nothing true about any
chain.

    python3 mock_rpc.py --port 8899 --sample ../../graphite-core/fixtures/mainnet/sample-2026-09-23-last-2-blocks.json

`--rate-limit getBlock,requestAirdrop` answers those methods with HTTP 429, to
exercise the backoff and the honest "inconclusive / skipped" reporting.

`--fail-programs P1,P2` makes a simulation that calls one of those programs
report `{"InstructionError":[i,{"Custom":6001}]}` (i: that instruction), and a
simulation asked WITHOUT `replaceRecentBlockhash` whose blockhash is not the
mock's current one reports `BlockhashNotFound`, as a validator does — so the
replay's reason breakdown and its stale/fresh comparison have something to
read (Round 32, P3b).
"""
import argparse
import base64
import json
import os
import sys
import threading
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wire  # noqa: E402
from solrpc import b58decode  # noqa: E402

DEVNET_GENESIS = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"
BLOCKHASH = "4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZAMdL4VZHirAn"
SYSTEM_PROGRAM = "11111111111111111111111111111111"
COMPUTE_BUDGET = "ComputeBudget111111111111111111111111111111"
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
    """(account keys, lamport deltas, fee, top-level program ids) of a wire
    transaction: the fee from the payer, and every top-level System transfer.
    Enough for a balance-array answer that is consistent with the bytes;
    nothing else about execution is modelled.

    The fee is Agave's (Round 40, measure: `fee/src/lib.rs` and the bank's
    `simulate_transaction`, whose `fee` is `fee_details.total_fee()`): 5,000
    lamports per signature plus the priority fee, the Compute Budget price ×
    limit / 10^6 rounded up — with no limit set, 200,000 per non-Compute-Budget
    instruction (the default's upper bound; the runtime grants builtins
    less). `preBalances` is before the fee, the post-state after it, as the
    SVM's balance collector records them."""
    nsig, at = shortvec(raw, 0)
    at += 64 * nsig
    if raw[at] & 0x80:  # versioned message prefix
        at += 1
    at += 3  # header
    nkeys, at = shortvec(raw, at)
    keys = [b58encode(raw[at + 32 * i : at + 32 * (i + 1)]) for i in range(nkeys)]
    at += 32 * nkeys + 32  # keys, recent blockhash
    delta = [0] * nkeys
    programs = []
    limit, price, others = None, 0, 0
    nix, at = shortvec(raw, at)
    for _ in range(nix):
        prog = raw[at]
        programs.append(keys[prog] if prog < nkeys else None)
        at += 1
        nacc, at = shortvec(raw, at)
        accs = list(raw[at : at + nacc])
        at += nacc
        ndata, at = shortvec(raw, at)
        data = raw[at : at + ndata]
        at += ndata
        if prog < nkeys and keys[prog] == COMPUTE_BUDGET:
            if data[:1] == b"\x02" and len(data) >= 5:
                limit = int.from_bytes(data[1:5], "little")
            elif data[:1] == b"\x03" and len(data) >= 9:
                price = int.from_bytes(data[1:9], "little")
        else:
            others += 1
        # An index past the static keys is a lookup-table account: not modelled.
        if prog < nkeys and keys[prog] == SYSTEM_PROGRAM and len(data) == 12 and int.from_bytes(data[:4], "little") == 2 \
                and len(accs) >= 2 and max(accs[:2]) < nkeys:
            lamports = int.from_bytes(data[4:12], "little")
            delta[accs[0]] -= lamports
            delta[accs[1]] += lamports
    limit = min(limit if limit is not None else 200_000 * others, 1_400_000)
    fee = 5000 * nsig + (price * limit + 999_999) // 1_000_000
    delta[0] -= fee
    return keys, delta, fee, programs


def recent_blockhash(raw):
    """The frame's blockhash (any version), or None when it does not parse."""
    try:
        return b58encode(wire.blockhash(raw))
    except ValueError:
        return None


class State:
    def __init__(self, sample_path, rate_limited, genesis, fail_programs=()):
        self.blocks = defaultdict(list)
        if sample_path:
            with open(sample_path, encoding="utf-8") as f:
                for r in json.load(f)["rows"]:
                    self.blocks[r["slot"]].append(r)
        self.head = (max(self.blocks) + 40) if self.blocks else 400_000_000
        self.rate_limited = set(rate_limited)
        self.fail_programs = set(fail_programs)
        self.genesis = genesis
        self.balances = defaultdict(int)
        # With a mainnet sample loaded, every account other people's
        # transactions touch exists and can pay its fees; without one, only
        # what the faucet funded exists.
        self.default_balance = 10_000_000_000 if self.blocks else 0
        self.calls = defaultdict(int)
        self.sent = {}  # signature -> (slot, base64 transaction)
        self.lock = threading.Lock()

    def chain_meta(self, r):
        """`fee` and the native balances, as a block records them, for a
        frame this mock reads (Round 40, measure); nothing for one it does
        not. Static keys only: a lookup-table account is not modelled."""
        try:
            raw = base64.b64decode(r["b64"])
            if raw[:1] == bytes([wire.V1_PREFIX]):
                return {}
            keys, delta, fee, _ = effects(raw)
        except (IndexError, ValueError, KeyError):
            return {}
        pre = [self.balance(k) for k in keys]
        return {"fee": fee, "preBalances": pre, "postBalances": [a + d for a, d in zip(pre, delta)]}

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
                            **self.chain_meta(r),
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
            balances, after, err = {}, {}, None
            raw = base64.b64decode(params[0]) if cfg.get("encoding") == "base64" else None
            try:
                parsed = effects(raw) if raw is not None else None
            except (IndexError, ValueError):
                parsed = None  # a layout this mock does not read: no balance arrays, as an incomplete answer
            if raw is not None and not cfg.get("replaceRecentBlockhash") and recent_blockhash(raw) not in (None, BLOCKHASH):
                err = "BlockhashNotFound"
            elif raw is not None and self.fail_programs:
                # The calling instruction's index where this mock can read the
                # instructions (legacy, v0); 0 for a frame it cannot (v1).
                hit = next((i for i, p in enumerate(parsed[3]) if p in self.fail_programs), None) if parsed else None
                if hit is None and any(b58decode(p) in raw for p in self.fail_programs):
                    hit = 0
                if hit is not None:
                    err = {"InstructionError": [hit, {"Custom": 6001}]}
            if parsed:
                keys, delta, fee, _ = parsed
                pre = [self.balance(k) for k in keys]
                balances = {"preBalances": pre, "postBalances": [a + d for a, d in zip(pre, delta)], "fee": fee,
                            "preTokenBalances": [], "postTokenBalances": [], "loadedAddresses": {"writable": [], "readonly": []}}
                after = dict(zip(keys, delta))
            return {
                "context": {"slot": self.head},
                "value": {
                    "err": err,
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
            keys, delta, fee, _ = effects(raw)
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
    ap.add_argument("--fail-programs", default="")
    args = ap.parse_args(argv)
    state = State(args.sample, [m for m in args.rate_limit.split(",") if m], args.genesis,
                  [p for p in args.fail_programs.split(",") if p])
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler_for(state))
    print(f"mock rpc on 127.0.0.1:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
