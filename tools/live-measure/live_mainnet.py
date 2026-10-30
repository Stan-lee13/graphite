"""Graphite against live mainnet traffic, WITH simulation (Round 32, P3).

The committed conformance blocks (`graphite-core/tests/mainnet_conformance.rs`)
run offline: nothing is simulated, so L3, L4 and the execution decision are
never exercised on real traffic there. This replays recent real transactions
through a running Core that has an RPC attached, and reports what the full
pipeline does with them. It is a measurement, not a gate on the traffic:
these are other people's transactions, mostly refused by a fresh Core that
has earned no evidence yet. What it fails on is a Graphite defect:

- the server answered 5xx, dropped the connection, or died;
- a verdict whose `decision` / `executable` contradict its own fields (the
  rule the SDKs recompute);
- `executable_approved` for a program with no manifest, for a transaction
  whose simulation failed or was flagged, or for a transaction that FAILED on
  chain (a replay runs against today's state, so this one is listed for
  review with that caveat — but an approval nobody can explain is a defect
  until it is explained);
- the conformance harness's own invariants on the fresh blocks.

A public endpoint's rate limit is not a defect: calls back off, and what
could not be measured is counted and reported as such.

Every L3/L4 failure and inconclusive is broken down by its reason — the
simulator's error (`InstructionError{2, Custom(6001)}`, `AccountNotFound`, …)
or why no verdict was reached — overall and per program (Round 32, P3b).

`--fresh N` re-verifies the first N transactions with the blockhash of their
unsigned frame rewritten to one just fetched with getLatestBlockhash (see
wire.py: a measurement-side byte rewrite; nothing is signed or sent), each
right after its stale twin, and reports the two passes side by side: the
stale replay is not what an agent submits, the fresh one is.

`seed` imports the measured census (`graphite evidence import-census`) before
the Core starts — for the System and SPL Token programs, or with
`--whole-census` for every record the census admits, as an operator's first
start does — so that a simple transfer can reach `executable_approved`.
Round 40 (measure): it no longer types an L3 baseline. The typed per-program
compute bands (System 150±30 CU, SPL Token 5000±1500 CU) flagged an honest
`AdvanceNonceAccount` (450 CU) at 8σ and SPL Token `TransferChecked` /
`InitializeAccount` (≈400 CU) at −3σ in run 40280048548: refusals the
measurement setup made. With no mature baseline L3 is inconclusive, which
does not prevent `executable_approved` (the committed `executable_approved`
fixture and the Round 40 bootstrap campaign are both such verdicts); a
baseline is learned from the run's own clean simulations.

`--honest N` (Round 40, measure) measures what an honest agent's OWN
transactions get, which a replay of other people's transactions cannot: from
the fetched sample it takes executed simple transfers (one System `Transfer`
or SPL Token `TransferChecked`, nothing else but Compute Budget instructions,
sent by the transaction's own fee payer) and builds, for each, a NEW unsigned
legacy transaction from the same sender to the same recipient for 1 lamport /
1 base unit, with the original's Compute Budget instructions and a fresh
blockhash, and verifies it with the intent `transfer` and the amount, recipient
and asset stated. Never signed (the signature slot is zeroed), never sent:
the bytes go to the local Core's /verify only.

    python3 live_mainnet.py fetch   --rpc URL --blocks 2 --out sample.json
    (graphite-core) GRAPHITE_MAINNET_SAMPLE=sample.json GRAPHITE_MAINNET_HONEST_INTENT=1 \\
        GRAPHITE_MAINNET_REQUESTS=requests.jsonl cargo test --release --test mainnet_conformance \\
        -- --ignored real_mainnet_traffic --nocapture
    python3 live_mainnet.py select  --requests requests.jsonl --n 200 --out selected.jsonl
    python3 live_mainnet.py seed    --graphite graphite --data-dir DATA --out seed.json [--whole-census]  # optional
    GRAPHITE_API_KEY=... LIVE_RPC_URL=... python3 live_mainnet.py replay --selected selected.jsonl \\
        --sample sample.json --core http://127.0.0.1:7331 --fresh 40 --honest 40 [--seeded seed.json] --out-dir report/

No credentials are read but GRAPHITE_API_KEY (the local Core's) and an
optional RPC URL, which is never printed: logs name its host only.
"""
import argparse
import base64
import json
import os
import re
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "mainnet-sample"))

import honest_swaps  # noqa: E402
import solrpc  # noqa: E402
import wire  # noqa: E402

SYSTEM_PROGRAM = "11111111111111111111111111111111"
SPL_TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
# What an operator does before a fresh Core approves anything (Round 40):
# `graphite evidence import-census` — the measured, committed mainnet census
# (protocols/battle_tested_evidence.json), not typed numbers. These two are
# imported by name without `--whole-census`, and reported by name either way.
#
# Round 40 (measure): no typed L3 baseline any more. The runner used to type
# System 150±30 CU and SPL Token 5000±1500 CU; in run 40280048548 that flagged
# an honest System AdvanceNonceAccount (450 CU, +8σ) and SPL Token
# TransferChecked / InitializeAccount (482 / 413 CU, −3σ). A baseline is not
# needed for `executable_approved` (L3 without a mature one is inconclusive,
# not failed), and one typed here measures the typing, not Graphite.
SEEDED_PROGRAMS = (SYSTEM_PROGRAM, SPL_TOKEN_PROGRAM)
COMPUTE_BUDGET_PROGRAM = "ComputeBudget111111111111111111111111111111"
# Agave's signature fee counts these precompiles' signatures too
# (`fee/src/lib.rs`, `calculate_signature_fee`: the first data byte of each).
PRECOMPILES = (
    "Ed25519SigVerify111111111111111111111111111",
    "KeccakSecp256k11111111111111111111111111111",
    "Secp256r1SigVerify1111111111111111111111111",
)
LAMPORTS_PER_SIGNATURE = 5000

INHERENT = {"program_semantics", "inner_instructions"}
DECISIONS = ("executable_approved", "analysis_only", "inconclusive", "blocked")
# "429" only as a standalone number: base58 addresses and hex hashes contain
# the digits, and a verdict quoting one is not a rate-limited verdict.
RATE_LIMIT_RE = re.compile(r"(?<![0-9A-Za-z])429(?![0-9A-Za-z])|too many requests|rate[ -]limit", re.I)


# ── fetch ────────────────────────────────────────────────────────────────────


def fetch(rpc_url, blocks, out, *, min_transactions=1000, max_blocks=8, offset=40, stride=20, sleep=time.sleep,
          call=solrpc.call):
    """Recent finalized blocks, in the shape fetch_mainnet.py writes (so the
    conformance harness reads it unchanged). Close to the head on purpose: a
    replay runs against today's state, and the less of it has moved, the more
    of what is simulated is the transaction as it was.

    At least `blocks` blocks, and more (up to `max_blocks`) until the sample
    holds `min_transactions` rows: the harness refuses a sample with 500
    verdicts or fewer, and block sizes vary (Round 35: two blocks held 493)."""
    from fetch_mainnet import rows_from_block  # the recorded fields, unchanged

    head = call(rpc_url, "getSlot", [{"commitment": "finalized"}])["result"]
    rows, fetched, skipped = [], [], []
    slot = head - offset
    tries = 0
    def wanted():
        return len(fetched) < blocks or (len(rows) < min_transactions and len(fetched) < max_blocks)

    while wanted() and tries < max(blocks, max_blocks) * 6:
        tries += 1
        r = call(
            rpc_url,
            "getBlock",
            [
                slot,
                {
                    "encoding": "base64",
                    "transactionDetails": "full",
                    "rewards": False,
                    "maxSupportedTransactionVersion": 1,
                    "commitment": "finalized",
                },
            ],
            timeout=120,
        )
        if "error" in r or r.get("result") is None:
            skipped.append(slot)  # a leader's skipped slot is ordinary
        else:
            rows.extend(with_chain_meta(rows_from_block(slot, r["result"]), r["result"]))
            fetched.append(slot)
        slot -= stride
        sleep(1.0)
    if not fetched:
        raise solrpc.RpcError("no block could be fetched")
    endpoint_kind = "public mainnet" if rpc_url.rstrip("/") == "https://api.mainnet-beta.solana.com" else "operator-supplied"
    doc = {"endpoint_kind": endpoint_kind, "slots": fetched, "skipped_slots": skipped, "count": len(rows), "rows": rows}
    with open(out, "w", encoding="utf-8") as f:
        json.dump(doc, f)
    return doc


def with_chain_meta(rows, block):
    """`rows_from_block`'s rows, each with what the chain charged and moved
    (Round 40, measure): the block's `meta.fee` and the native balances
    before and after, so a signer debit Graphite reports can be set beside
    the chain's own. Extra fields; the conformance harness ignores them.
    Rows and transactions are paired by the same filter rows_from_block
    applies (base64 payloads, in block order)."""
    txs = [t for t in block.get("transactions", [])
           if isinstance(t.get("transaction"), list) and len(t["transaction"]) >= 2 and t["transaction"][1] == "base64"]
    if len(txs) != len(rows):
        return rows  # not paired: record nothing rather than misattribute
    out = []
    for row, t in zip(rows, txs):
        if t["transaction"][0] != row.get("b64"):
            return rows
        meta = t.get("meta") or {}
        out.append(dict(row, fee=meta.get("fee"), pre_balances=meta.get("preBalances"),
                        post_balances=meta.get("postBalances"),
                        # accountIndex → mint and decimals, for a token
                        # `Transfer` whose bytes name no mint; owner and
                        # amount before and after, for the honest-swap pass
                        # (Round 41: what the wallet gave and got).
                        pre_token_balances=token_balances(meta.get("preTokenBalances")),
                        post_token_balances=token_balances(meta.get("postTokenBalances"))))
    return out


def token_balances(entries):
    return [
        {"account_index": b.get("accountIndex"), "mint": b.get("mint"), "owner": b.get("owner"),
         "amount": (b.get("uiTokenAmount") or {}).get("amount"),
         "decimals": (b.get("uiTokenAmount") or {}).get("decimals")}
        for b in entries or [] if isinstance(b, dict)
    ]


# ── select ───────────────────────────────────────────────────────────────────


def select(lines, n):
    """N requests, spread across programs: round-robin over the programs in
    order of how often they appear, each program's rows in block order. A
    sample of 200 from a block dominated by one bot would otherwise measure
    one bot."""
    by_program = defaultdict(list)
    order = []
    for entry in lines:
        p = entry["program_id"]
        if p not in by_program:
            order.append(p)
        by_program[p].append(entry)
    order.sort(key=lambda p: -len(by_program[p]))
    picked = []
    depth = 0
    while len(picked) < n:
        added = False
        for p in order:
            if depth < len(by_program[p]):
                picked.append(by_program[p][depth])
                added = True
                if len(picked) == n:
                    break
        if not added:
            break
        depth += 1
    return picked


# ── judge one verdict ────────────────────────────────────────────────────────


def layer(result, prefix):
    for l in result.get("layers") or []:
        if str(l.get("layer", "")).startswith(prefix):
            return l
    return None


def recomputed_decision(result):
    """The rule the TypeScript and Go SDKs recompute (Round 30, G-01)."""
    approved = result.get("approved") is True
    if not approved:
        findings = (result.get("risk_verdict") or {}).get("findings") or []
        patterns = {str(f.get("pattern", "")) for f in findings if isinstance(f, dict)}
        return "inconclusive" if patterns and patterns <= {"VerificationIncomplete"} else "blocked"
    scope = result.get("scope") or {}
    # Round 39 (R39-CLIENTS-8): as the SDKs read it — codes present and naming
    # every unobserved entry, a digest of what was bound, layers reported.
    # Missing codes used to read as none, and prose without a code as nothing,
    # so a Core verdict executable over an unnamed residual was not a defect.
    codes = scope.get("unobserved_codes")
    prose = scope.get("unobserved")
    digest = scope.get("transaction_sha256")
    layers = result.get("layers")
    executable = (
        (result.get("risk_verdict") or {}).get("status") == "Clear"
        and result.get("policy_verdict") == "Approved"
        and scope.get("kind") == "artifact_bound"
        and isinstance(digest, str)
        and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
        and scope.get("simulated") is True
        and isinstance(codes, list)
        and isinstance(prose, list)
        and len(codes) == len(prose)
        and all(c in INHERENT for c in codes)
        and isinstance(layers, list)
        and not any(isinstance(l, dict) and l.get("status") == "failed" for l in layers)
    )
    return "executable_approved" if executable else "analysis_only"


def reasons(result):
    """The prose of a verdict: layer and finding reasons, where an RPC
    failure is reported."""
    out = [str(l.get("reason", "")) for l in result.get("layers") or []]
    out += [str(f.get("reason", "")) for f in (result.get("risk_verdict") or {}).get("findings") or []]
    return out


def rate_limited(result):
    return any(RATE_LIMIT_RE.search(r) for r in reasons(result))


def defects_for(entry, result):
    """What in this verdict is a Graphite defect (see the module doc)."""
    out = []
    decision = result.get("decision")
    if decision not in DECISIONS:
        out.append(f"decision {decision!r} is not one of {DECISIONS}")
        return out
    if result.get("executable") is not (decision == "executable_approved"):
        out.append(f"executable={result.get('executable')!r} contradicts decision {decision}")
    mine = recomputed_decision(result)
    # The Core may be stricter than the rule (e.g. a refusal the SDK reads as
    # blocked); it may never be looser.
    if decision == "executable_approved" and mine != "executable_approved":
        out.append(f"decision executable_approved but its own fields make it {mine}")
    if result.get("approved") is True and decision in ("blocked", "inconclusive"):
        out.append(f"approved but decision {decision}")
    if result.get("approved") is not True and decision in ("executable_approved", "analysis_only"):
        out.append(f"refused but decision {decision}")
    if decision == "executable_approved":
        if not result.get("manifest_found", entry.get("manifest_found")):
            out.append("executable_approved for a program with no manifest")
        # L3 may be inconclusive on an executable verdict (no mature
        # baseline yet: nothing to diverge from); it may not have failed —
        # a simulation error or a flagged divergence is a hard gate.
        l3 = layer(result, "L3") or {}
        if l3.get("status") == "failed" or result.get("simulation_flagged") is True:
            out.append(f"executable_approved with L3 {l3.get('status')!r} (simulation_flagged={result.get('simulation_flagged')!r})")
        if (result.get("scope") or {}).get("simulated") is not True:
            out.append("executable_approved for bytes the Core did not simulate")
        if entry.get("failed_on_chain"):
            out.append(
                "executable_approved for a transaction that FAILED on chain — review: a replay "
                "simulates today's state, so state drift can explain it; until it does, it is a defect"
            )
    return out


def l3_class(result):
    l3 = layer(result, "L3")
    if l3 is None:
        return "absent"
    status = l3.get("status", "?")
    reason = str(l3.get("reason", ""))
    low = reason.lower()
    if status == "failed":
        if "anchored band" in low:
            return "failed: outside the anchored band"
        if "divergence" in low:
            return "failed: divergence from baseline"
        return "failed: simulation error"
    if status == "inconclusive":
        if RATE_LIMIT_RE.search(reason):
            return "inconclusive: RPC rate-limited"
        if "no baseline" in low or "baseline" in low:
            return "inconclusive: no mature baseline"
        return "inconclusive: " + reason.split(":")[0][:60]
    if status == "passed":
        return "passed (shape baseline)" if "shape" in low else "passed"
    return status


# ── why: the reason behind every L3/L4 failure and inconclusive ─────────────

ADDRESS_RE = re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b")
HEX_RE = re.compile(r"\b[0-9a-f]{40,}\b")
NUMBER_RE = re.compile(r"\d+(?:\.\d+)?")


def norm(text, limit=90):
    """A reason as a class: its first clause, with addresses, hashes and
    numbers taken out, so that one cause counts once however often it
    occurs."""
    text = re.split(r" \| | — |; ", str(text), maxsplit=1)[0]
    text = ADDRESS_RE.sub("<addr>", text)
    text = HEX_RE.sub("<hash>", text)
    text = NUMBER_RE.sub("N", text)
    text = " ".join(text.split())
    return text[:limit] + ("…" if len(text) > limit else "")


def sim_error_class(err):
    """The simulator's `err`, as the Core quotes it (rpc_client.rs: a string
    variant bare, anything else as compact JSON), named:
    `BlockhashNotFound`, `AccountNotFound`, `InsufficientFundsForFee`,
    `InstructionError{2, Custom(6001)}`, `InstructionError{0, InvalidAccountData}`,
    `InsufficientFundsForRent`, …"""
    err = str(err).strip()
    try:
        value, _ = json.JSONDecoder().raw_decode(err)
    except ValueError:
        m = re.match(r"[A-Za-z][A-Za-z0-9_]*", err)
        return m.group(0) if m else "unparsed: " + norm(err, 60)
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and len(value) == 1:
        name, inner = next(iter(value.items()))
        if name == "InstructionError" and isinstance(inner, list) and len(inner) == 2:
            index, kind = inner
            if isinstance(kind, dict) and len(kind) == 1:
                kname, kval = next(iter(kind.items()))
                kind = f"{kname}({kval})" if kname == "Custom" else kname
            return f"InstructionError{{{index}, {kind}}}"
        return name
    return "unparsed: " + norm(json.dumps(value), 60)


def _after_reported(text):
    i = text.find("reported ")
    return text[i + len("reported ") :] if i >= 0 else None


def incomplete_class(why):
    low = why.lower()
    if RATE_LIMIT_RE.search(why):
        return "RPC rate-limited"
    m = re.search(r"simulation failed: (.*?)\)?$", why)
    if m:
        return "simulation call failed: " + norm(m.group(1), 60)
    if "response was incomplete" in low:
        return "simulator response incomplete"
    if "programs this transaction called" in low:
        return "callee report unreadable"
    if "cpi tree" in low:
        return "CPI tree not rebuilt"
    if "pre/post state diff" in low:
        return "no state diff"
    return norm(why, 60)


def l3_reason(l3):
    text = str(l3.get("reason", ""))
    low = text.lower()
    if text.startswith("Simulation FAILED"):
        return sim_error_class(_after_reported(text) or "")
    if "anchored band" in low:
        return "flagged: outside the anchored band"
    if "flagged" in low:
        return "flagged: divergence from " + ("the shape baseline" if "shape" in low else "the program baseline")
    if text.startswith("Simulation INCOMPLETE"):
        return "incomplete: " + incomplete_class(text.split("—", 1)[-1].strip())
    if "no trusted baseline" in low:
        return "no mature baseline"
    if "no transaction artifact" in low:
        return "no artifact"
    if "no rpc endpoint" in low:
        return "no RPC"
    if RATE_LIMIT_RE.search(text):
        return "RPC rate-limited"
    return norm(text)


def l4_reason(l4):
    text = str(l4.get("reason", ""))
    m = re.search(r"simulation failed: (.*?)\)", text)
    if m:
        inner = m.group(1)
        if RATE_LIMIT_RE.search(inner):
            return "simulation call failed: RPC rate-limited"
        quoted = _after_reported(inner)
        return "simulation failed: " + (sim_error_class(quoted) if quoted else norm(inner, 60))
    if RATE_LIMIT_RE.search(text):
        return "RPC rate-limited"
    return norm(text)


def failure_reasons(result):
    """`["L3 failed: InstructionError{2, Custom(6001)}", "L4 inconclusive: …"]`:
    one entry per L3/L4 layer that did not pass, naming why."""
    out = []
    for prefix, explain in (("L3", l3_reason), ("L4", l4_reason)):
        l = layer(result, prefix)
        if l and l.get("status") in ("failed", "inconclusive"):
            out.append(f"{prefix} {l['status']}: {explain(l)}")
    return out


def finding_patterns(result):
    return sorted({str(f.get("pattern", "")) for f in (result.get("risk_verdict") or {}).get("findings") or [] if isinstance(f, dict)})


# ── replay ───────────────────────────────────────────────────────────────────


def post(url, key, body, timeout=60):
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={"Content-Type": "application/json"})
    if key:
        req.add_header("Authorization", f"Bearer {key}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode() or "null")
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, {"raw": raw[:500]}


def get(url, key=None, timeout=10):
    req = urllib.request.Request(url)
    if key:
        req.add_header("Authorization", f"Bearer {key}")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def percentile(values, p):
    if not values:
        return None
    s = sorted(values)
    k = max(0, min(len(s) - 1, round(p / 100 * (len(s) - 1))))
    return round(s[k], 1)


class FreshBlockhash:
    """getLatestBlockhash, reused for `ttl` seconds (a blockhash stays valid
    for ~60 s; one fetch per transaction would only spend the rate limit)."""

    def __init__(self, rpc, *, ttl=20.0, call=solrpc.call, clock=time.monotonic):
        self.rpc, self.ttl, self.call, self.clock = rpc, ttl, call, clock
        self.value, self.at, self.fetches = None, None, 0

    def __call__(self):
        if self.value is None or self.clock() - self.at > self.ttl:
            r = self.call(self.rpc, "getLatestBlockhash", [{"commitment": "confirmed"}], attempts=4)
            if "error" in r:
                raise solrpc.RpcError(f"getLatestBlockhash: {r['error']}")
            self.value = solrpc.b58decode(r["result"]["value"]["blockhash"])
            if len(self.value) != 32:
                raise solrpc.RpcError("getLatestBlockhash: not a 32-byte hash")
            self.at = self.clock()
            self.fetches += 1
        return self.value


def verify_one(report, entry, body_in, core, key, post_fn, tag=""):
    """One /verify call, judged. Returns the row, or None on a transport
    error (already recorded as a defect)."""
    t0 = time.monotonic()
    try:
        status, body = post_fn(f"{core}/verify", key, body_in)
    except Exception as e:  # connection reset, refused: the server fell over
        report["server_errors"].append({"row": entry["row"], "error": f"{tag}{type(e).__name__}: {e}"})
        report["defects"].append(f"{tag}row {entry['row']}: /verify transport error {type(e).__name__}: {e}")
        return None
    latency = (time.monotonic() - t0) * 1000
    row = {
        "row": entry["row"],
        "slot": entry["slot"],
        "program_id": entry["program_id"],
        "instruction": entry.get("instruction_name") or "",
        "failed_on_chain": bool(entry.get("failed_on_chain")),
        "http": status,
        "latency_ms": round(latency, 1),
    }
    if status >= 500:
        report["server_errors"].append({"row": entry["row"], "status": status, "body": body})
        report["defects"].append(f"{tag}row {entry['row']}: /verify answered {status}")
    elif status != 200:
        # A request the Core refused as malformed (400/422) or throttled
        # (429): counted, not judged. The harness built it, so a 4xx is
        # worth reading, but it is not a verdict.
        report["refused_requests"][str(status)] += 1
        row["refusal"] = (body or {}).get("error") if isinstance(body, dict) else str(body)[:200]
    else:
        result = body
        l3 = layer(result, "L3") or {}
        l4 = layer(result, "L4") or {}
        row.update(
            {
                "decision": result.get("decision"),
                "executable": result.get("executable"),
                "approved": result.get("approved"),
                "manifest_found": result.get("manifest_found"),
                "risk": (result.get("risk_verdict") or {}).get("status"),
                "policy": result.get("policy_verdict"),
                "l3": l3_class(result),
                "l3_reason": str(l3.get("reason", ""))[:240],
                "l4": l4.get("status"),
                "l4_reason": str(l4.get("reason", ""))[:240],
                "l4_reason_full": str(l4.get("reason", ""))[:1200],
                # Classified from the full text, not the truncated copy.
                "reasons": failure_reasons(result),
                "findings": finding_patterns(result),
                "simulation_flagged": result.get("simulation_flagged"),
                "simulation_divergence": result.get("simulation_divergence"),
                "unobserved_codes": (result.get("scope") or {}).get("unobserved_codes"),
                # Round 40 (measure): what the Core read of the fee the bytes
                # ask for, and the standing it gave the verdict.
                "compute_budget": (result.get("scope") or {}).get("compute_budget"),
                "confidence": result.get("confidence"),
                "trust_tier": result.get("trust_tier"),
                "finding_reasons": [
                    f"{f.get('pattern')}: {str(f.get('reason', ''))[:600]}"
                    for f in (result.get("risk_verdict") or {}).get("findings") or [] if isinstance(f, dict)
                ],
                "transaction_sha256": (result.get("scope") or {}).get("transaction_sha256"),
                "audit_trail_id": result.get("audit_trail_id"),
                "rpc_rate_limited": rate_limited(result),
            }
        )
        found = defects_for(entry, result)
        if found:
            row["defects"] = found
            report["defects"].extend(f"{tag}row {entry['row']} ({entry['program_id']}): {d}" for d in found)
    return row


def outcome(row):
    return {"decision": row.get("decision"), "l3": row.get("l3"), "reasons": row.get("reasons") or []}


# L4 findings whose real-traffic cost is worth reading row by row: the
# Round 32 defaults (W19, an unreadable declaration excusing nothing, an
# unbounded withdrawal) and the undeclared signer debits beside them. A
# refusal is a false one when the chain shows an ordinary transaction — a
# tip or a plain SOL transfer beside a swap — so each such row is printed
# with what that judgement needs.
WATCHED_FINDINGS = (
    "SignerLamportsOutsideDeclaredDebit",
    "UndeclaredSignerLamportDebit",
    "UndeclaredTokenDebit",
    "UnboundedWithdrawal",
    "a declaration Graphite cannot read",
)


def watched(row, seeded_programs=()):
    """The watched findings this row's verdict names, plus `seeded` when its
    program was seeded (its approvals and L3 flags are the seeded path's)."""
    text = " ".join([str(row.get("l4_reason_full") or row.get("l4_reason") or ""), " ".join(row.get("findings") or [])])
    hits = [f for f in WATCHED_FINDINGS if f in text]
    if row.get("program_id") in seeded_programs:
        hits.append("seeded")
    return hits


def detail(row, src, input_):
    """What a reader needs to judge one watched row: the signature, the
    chain's outcome and compute, and every top-level program it invoked."""
    out = {"failed_on_chain": row.get("failed_on_chain"), "cu_on_chain": (src or {}).get("cu")}
    try:
        out["signature"] = solrpc.first_signature(base64.b64decode(src["b64"])) if src else None
    except (KeyError, ValueError):
        out["signature"] = None
    programs = []
    for ix in (input_ or {}).get("transaction_instructions") or []:
        p = ix.get("program_id") if isinstance(ix, dict) else None
        if p:
            programs.append(p)
    out["programs"] = programs
    return out


def fresh_one(report, entry, stale_row, core, key, post_fn, blockhash_fn):
    """The same request with a just-fetched blockhash in its unsigned frame,
    verified right after its stale twin (same Core state, seconds apart)."""
    f = report["fresh"]
    f["requested"] += 1
    frame = (entry.get("input") or {}).get("signed_transaction")
    if not frame:
        f["skipped"]["no artifact"] += 1
        return
    try:
        lay = wire.layout(frame)
    except ValueError:
        f["skipped"]["frame does not parse"] += 1
        return
    if lay.durable_nonce:
        # Its blockhash slot is the nonce value: there is no "fresh" for it.
        f["skipped"][f"durable nonce ({lay.version})"] += 1
        return
    if blockhash_fn is None:
        f["skipped"]["no RPC for a fresh blockhash"] += 1
        return
    try:
        new_hash = blockhash_fn()
    except (solrpc.RateLimited, solrpc.RpcError, KeyError, TypeError, ValueError) as e:
        f["skipped"][f"no fresh blockhash ({type(e).__name__})"] += 1
        return
    try:
        patched = wire.patch_blockhash(frame, new_hash)
    except ValueError as e:
        f["skipped"][norm(e, 60)] += 1
        return
    row = verify_one(report, entry, dict(entry["input"], signed_transaction=list(patched)), core, key, post_fn, tag="fresh ")
    if row is None:
        return
    row["version"] = lay.version
    f["patched_by_version"][lay.version] += 1
    f["rows"].append(row)
    if stale_row.get("decision") and row.get("decision"):
        s, n = outcome(stale_row), outcome(row)
        f["pairs"].append({"row": entry["row"], "program_id": entry["program_id"], "version": lay.version, "stale": s, "fresh": n, "changed": s != n})


# ── signer debits beyond the fee: the fee, set beside the chain's (Round 40) ─

SIGNER_LOSS_RE = re.compile(r"signers lose (\d+) lamports beyond the fee|(\d+) lamports left (?:a|this) signer")
SIGNER_DEBIT_FINDINGS = ("UndeclaredSignerLamportDebit", "SignerLamportsOutsideDeclaredDebit")


def short(address, n=8):
    return str(address)[:n]


def describe_instruction(keys, ix):
    """One top-level instruction, as a reader judging a signer debit needs
    it: a System transfer with its amount and destination, a Compute Budget
    value, else the program and the first data byte."""
    program = keys[ix.program_index] if ix.program_index < len(keys) else "?"
    data = ix.data
    acct = [keys[a] if a < len(keys) else "?" for a in ix.accounts]
    if program == SYSTEM_PROGRAM and len(data) == 12 and data[:4] == (2).to_bytes(4, "little") and len(acct) >= 2:
        return f"System Transfer {int.from_bytes(data[4:12], 'little')} lamports {short(acct[0])}→{short(acct[1])}"
    if program == COMPUTE_BUDGET_PROGRAM and data:
        if data[0] == 2 and len(data) >= 5:
            return f"SetComputeUnitLimit {int.from_bytes(data[1:5], 'little')}"
        if data[0] == 3 and len(data) >= 9:
            return f"SetComputeUnitPrice {int.from_bytes(data[1:9], 'little')} µlamports/CU"
        return f"ComputeBudget tag {data[0]}"
    return f"{short(program)} [{data[:1].hex() or '-'}]"


def fee_breakdown(src, row):
    """For a verdict naming a signer lamport debit: Graphite's figure beyond
    the fee; the signature count (and precompile signatures, which Agave also
    charges); the compute-unit price × limit and the priority fee as the Core
    read them from the bytes; the fee Agave's rule gives (5,000 × signatures +
    priority fee, `fee/src/lib.rs`); the fee the chain charged and each
    signer's balance change on chain (when the sample recorded them); and
    every top-level instruction. Read from the sample and the verdict; no
    RPC call."""
    out = {}
    m = SIGNER_LOSS_RE.search(str(row.get("l4_reason_full") or ""))
    out["graphite_beyond_fee"] = int(m.group(1) or m.group(2)) if m else None
    try:
        msg = wire.message(base64.b64decode(src["b64"]))
    except (KeyError, TypeError, ValueError) as e:
        out["error"] = f"frame not read: {e}"
        return out
    keys = wire.account_keys(msg, src.get("loaded_writable") or [], src.get("loaded_readonly") or [])
    precompile = sum(ix.data[0] for ix in msg.instructions
                     if ix.data and ix.program_index < len(keys) and keys[ix.program_index] in PRECOMPILES)
    cb = row.get("compute_budget") or {}
    priority = cb.get("priority_fee_lamports")
    out.update(
        version=msg.version,
        signatures=msg.num_required_signatures,
        precompile_signatures=precompile,
        cu_price_micro_lamports=cb.get("compute_unit_price_micro_lamports"),
        cu_limit=cb.get("effective_compute_unit_limit"),
        priority_fee=priority,
        expected_fee=(LAMPORTS_PER_SIGNATURE * (msg.num_required_signatures + precompile) + priority)
        if priority is not None else None,
        chain_fee=src.get("fee"),
        instructions=[describe_instruction(keys, ix) for ix in msg.instructions],
    )
    pre, post_ = src.get("pre_balances"), src.get("post_balances")
    if isinstance(pre, list) and isinstance(post_, list) and len(pre) == len(post_) >= msg.num_required_signatures:
        fee = src.get("fee") or 0
        out["signer_deltas"] = [
            {"signer": keys[i], "delta": post_[i] - pre[i], "beyond_fee": -(post_[i] - pre[i]) - (fee if i == 0 else 0)}
            for i in range(msg.num_required_signatures)
        ]
    return out


# ── the honest-transfer pass (Round 40, measure) ─────────────────────────────


def ui_amount(base_units, decimals):
    """`base_units` in display units, exactly (intent_binding.rs reads a
    decimal string with at most `decimals` fractional digits)."""
    if decimals == 0:
        return str(base_units)
    s = str(base_units).rjust(decimals + 1, "0")
    whole, frac = s[:-decimals], s[-decimals:].rstrip("0")
    return whole + ("." + frac if frac else "")


ATA_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
SPL_TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
MEMO_PROGRAMS = ("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr", "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo")


def simple_transfer(src):
    """The executed simple transfer a sample row is: (transfer, None), or
    (None, why it was set aside), or (None, None) when the row is not a
    simple transfer at all.

    Simple: exactly one value-moving instruction, a System `Transfer` or an
    SPL Token `TransferChecked`; every other top-level instruction one that
    moves nothing a wallet adds beside a transfer — Compute Budget (copied
    into the new transaction), an associated-token-account `CreateIdempotent`
    paid by the sender (copied: a no-op when the account exists), a memo
    (dropped: its text is the original sender's). Succeeded on chain, not a
    durable-nonce transaction, and sent by its own fee payer (an agent pays
    its own fee). Near misses are counted by reason: an SPL Token `Transfer`
    (its bytes name no mint, so the asset cannot be stated), Token-2022, a
    non-idempotent ATA `Create`."""
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
    ixs = list(msg.instructions)
    if msg.durable_nonce:
        ixs = ixs[1:]  # its AdvanceNonceAccount moves nothing; set aside below
    moving, layout, aside = [], [], None
    for ix in ixs:
        program, data = keys[ix.program_index], ix.data
        accounts = [(keys[a], *wire.privileges(msg, a, len(lw))) for a in ix.accounts]
        if program == COMPUTE_BUDGET_PROGRAM:
            layout.append(("copy", (program, accounts, data)))
        elif program in MEMO_PROGRAMS:
            continue
        elif program == ATA_PROGRAM and data == b"\x01":
            layout.append(("copy", (program, accounts, data)))
        elif program == ATA_PROGRAM and data in (b"", b"\x00"):
            aside = aside or "ATA Create (not idempotent)"
            layout.append(("copy", (program, accounts, data)))
        elif program == SYSTEM_PROGRAM and len(data) == 12 and data[:4] == (2).to_bytes(4, "little") and len(accounts) >= 2:
            moving.append({"kind": "System Transfer", "sender": accounts[0][0], "recipient": accounts[1][0], "asset": "SOL",
                           "original_amount": int.from_bytes(data[4:12], "little"), "decimals": 9})
            layout.append(("transfer",))
        elif program == SPL_TOKEN_PROGRAM and len(data) == 10 and data[0] == 12 and len(accounts) >= 4:
            moving.append({"kind": "SPL Token TransferChecked", "sender": accounts[3][0], "source": accounts[0][0],
                           "mint": accounts[1][0], "recipient": accounts[2][0], "asset": accounts[1][0],
                           "original_amount": int.from_bytes(data[1:9], "little"), "decimals": data[9]})
            layout.append(("transfer",))
        elif program == SPL_TOKEN_PROGRAM and len(data) == 9 and data[0] == 3 and len(accounts) >= 3:
            # Transfer names no mint; the block's own token balances do.
            known = [b for b in src.get("pre_token_balances") or []
                     if b.get("account_index") == ix.accounts[0] and b.get("mint") and isinstance(b.get("decimals"), int)]
            if not known:
                aside = aside or "SPL Token Transfer (no mint recorded for its source)"
                moving.append(None)
                continue
            moving.append({"kind": "SPL Token TransferChecked", "original_kind": "SPL Token Transfer",
                           "sender": accounts[2][0], "source": accounts[0][0], "mint": known[0]["mint"],
                           "recipient": accounts[1][0], "asset": known[0]["mint"],
                           "original_amount": int.from_bytes(data[1:9], "little"), "decimals": known[0]["decimals"]})
            layout.append(("transfer",))
        elif program == SPL_TOKEN_2022_PROGRAM and data[:1] in (b"\x03", b"\x0c"):
            aside = aside or "Token-2022 (not in this pass)"
            moving.append(None)
        else:
            return None, None
    if len(moving) != 1:
        return None, None
    if aside:
        return None, aside
    t = moving[0]
    if msg.durable_nonce:
        return None, "durable nonce"
    if t["sender"] != keys[0]:
        return None, "sender is not the fee payer"
    if t["recipient"] in (t["sender"], t.get("source")):
        return None, "self-transfer"
    if t["original_amount"] < 1:
        return None, "original amount 0"
    for step in layout:
        if step[0] == "copy" and step[1][0] == ATA_PROGRAM and (not step[1][1] or step[1][1][0][0] != t["sender"]):
            return None, "ATA created by another payer"
    if msg.version == "1":
        layout = [s for s in layout if not (s[0] == "copy" and s[1][0] == COMPUTE_BUDGET_PROGRAM)]
    t["layout"] = layout
    copied = Counter("Compute Budget" if s[1][0] == COMPUTE_BUDGET_PROGRAM else "ATA CreateIdempotent"
                     for s in layout if s[0] == "copy")
    t["budget_source"] = ", ".join(f"{v} {k}" for k, v in copied.items()) or (
        "none (a v1 header's values are not translated)" if msg.version == "1" else "none")
    t["version"] = msg.version
    t["cu"] = src.get("cu") or 0
    t["row"] = src.get("row")
    t["slot"] = src.get("slot")
    return t, None


def honest_candidates(sample_rows, n):
    """Up to `n` simple transfers, System and SPL Token alternated, one per
    (sender, recipient, asset); and how many simple transfers were set aside
    and why."""
    found, skipped, seen = {"System Transfer": [], "SPL Token TransferChecked": []}, Counter(), set()
    for src in sample_rows:
        t, why = simple_transfer(src)
        if why:
            skipped[why] += 1
        if t is None:
            continue
        k = (t["sender"], t["recipient"], t["asset"])
        if k in seen:
            skipped["duplicate sender, recipient and asset"] += 1
            continue
        seen.add(k)
        found[t["kind"]].append(t)
    picked, lists = [], list(found.values())
    for i in range(max((len(l) for l in lists), default=0)):
        for l in lists:
            if i < len(l) and len(picked) < n:
                picked.append(l[i])
    return picked, {"simple transfers": sum(len(l) for l in lists) + sum(skipped.values()),
                    "by kind": {k: len(v) for k, v in found.items()}, "set aside": dict(skipped)}


def honest_request(t, recent_blockhash, amount=1):
    """The new transaction and the /verify request an honest agent sends
    for it: `amount` (1 lamport / 1 base unit, never more than the original)
    from the same sender to the same recipient, the original's Compute Budget
    instructions, the given blockhash, one zeroed signature slot."""
    amount = min(amount, t["original_amount"])
    if t["kind"] == "System Transfer":
        primary = wire.system_transfer(t["sender"], t["recipient"], amount)
    else:
        primary = wire.token_transfer_checked(t["source"], t["mint"], t["recipient"], t["sender"], amount, t["decimals"])
    ixs = [primary if step[0] == "transfer" else step[1] for step in t["layout"]]
    siblings = [step[1] for step in t["layout"] if step[0] == "copy"]
    frame = wire.build_legacy(t["sender"], ixs, recent_blockhash)
    program, accounts, data = primary
    stated = ui_amount(amount, t["decimals"])
    body = {
        "proposed_intent": {
            "intent_type": "transfer",
            "raw_natural_language": f"send {stated} {t['asset'] if t['asset'] == 'SOL' else 'of mint ' + t['asset']} to {t['recipient']}",
            "confidence_of_parse": 1.0,
            "extracted_parameters": {"amount": stated, "destination": t["recipient"], "input_token": t["asset"]},
        },
        "program_id": program,
        "protocol_version": "1.0.0",
        "instruction_discriminator": data[:8].hex(),
        "account_addresses": [a for a, _, _ in accounts],
        "instruction_data": list(data),
        "cpi_targets": [],
        # The profile the conformance harness and the replay use: the
        # weakest built-in one.
        "wallet_profile": "Gaming",
        "compute_units": t["cu"],
        "signed_transaction": list(frame),
        "transaction_instructions": [
            {"program_id": p, "instruction_discriminator": d[:8].hex(), "account_addresses": [a for a, _, _ in accts],
             "cpi_targets": []}
            for p, accts, d in siblings
        ],
        "uses_versioned_transaction": False,
        "lookup_table_count": 0,
    }
    return frame, body


def chain_rejects(rpc, frame, call=solrpc.call):
    """Round 41: why the RPC's simulator rejects the unsigned frame now (the
    error class), or None when it runs. Signature verification off; nothing
    is sent."""
    r = call(rpc, "simulateTransaction", [base64.b64encode(bytes(frame)).decode(), {
        "encoding": "base64", "sigVerify": False, "replaceRecentBlockhash": False, "commitment": "confirmed"}],
        attempts=4)
    if "error" in r:
        raise solrpc.RpcError(f"simulateTransaction: {r['error']}")
    err = ((r.get("result") or {}).get("value") or {}).get("err")
    return None if err is None else sim_error_class(json.dumps(err))


def honest_pass(report, sample_rows, n, core, key, post_fn, blockhash_fn, sleep, pace, rpc=None, call=solrpc.call):
    h = report["honest"]
    picked, h["candidates"] = honest_candidates(sample_rows, n)
    for t in picked:
        if blockhash_fn is None:
            h["skipped"]["no RPC for a fresh blockhash"] += 1
            continue
        try:
            new_hash = blockhash_fn()
        except (solrpc.RateLimited, solrpc.RpcError, KeyError, TypeError, ValueError) as e:
            h["skipped"][f"no fresh blockhash ({type(e).__name__})"] += 1
            continue
        frame, body = honest_request(t, new_hash)
        # Round 41: a transfer the chain would reject now is not one an honest
        # agent can send (run 41129142710: 11 of 12 refusals were the
        # sender's account gone, or 1 lamport into an account that does not
        # exist, under the rent minimum). It is counted, not verified: the
        # Core refusing it would be right, and would measure the sender.
        if rpc:
            try:
                why = chain_rejects(rpc, frame, call)
                if why == "InsufficientFundsForRent" and t["original_amount"] > 1:
                    frame, body = honest_request(t, new_hash, amount=t["original_amount"])
                    h["rebuilt_with_original_amount"] = h.get("rebuilt_with_original_amount", 0) + 1
                    why = chain_rejects(rpc, frame, call)
            except (solrpc.RateLimited, solrpc.RpcError, KeyError, TypeError, ValueError) as e:
                h["skipped"][f"not pre-simulated ({type(e).__name__})"] += 1
                sleep(pace)
                continue
            if why:
                h["skipped"][f"the chain would reject it now ({why})"] += 1
                sleep(pace)
                continue
        entry = {"row": t["row"], "slot": t["slot"], "program_id": body["program_id"], "instruction_name": t["kind"],
                 "manifest_found": None, "failed_on_chain": False}
        # Its own 4xx tally; server errors and defects are the run's.
        sink = {"refused_requests": h["refused_requests"], "server_errors": report["server_errors"], "defects": report["defects"]}
        row = verify_one(sink, entry, body, core, key, post_fn, tag="honest ")
        sleep(pace)
        if row is None:
            continue
        h["constructed"] += 1
        row.update(kind=t["kind"], original_kind=t.get("original_kind", t["kind"]), sender=t["sender"], recipient=t["recipient"], asset=t["asset"],
                   amount=body["proposed_intent"]["extracted_parameters"]["amount"], budget=t["budget_source"],
                   original_version=t["version"], transaction_bytes=len(frame))
        h["rows"].append(row)


def swap_pass(report, sample_rows, requests_by_row, n, core, key, post_fn, blockhash_fn, rpc, sleep, pace,
              call=solrpc.call):
    """Round 41: the honest-swap pass (honest_swaps.py says what it builds
    and why). Each candidate costs two RPC calls for its quote."""
    s = report["swaps"]
    picked, s["candidates"] = honest_swaps.swap_candidates(sample_rows, n)
    for c in picked:
        harness = (requests_by_row.get(c["row"]) or {}).get("input")
        frame = (harness or {}).get("signed_transaction")
        if not frame:
            s["skipped"]["the harness built no request for the row"] += 1
            continue
        if blockhash_fn is None or not rpc:
            s["skipped"]["no RPC for a quote and a fresh blockhash"] += 1
            continue
        try:
            new_hash = blockhash_fn()
            probe, _ = honest_swaps.build(frame, c, 1, 0, new_hash)
            quoted = honest_swaps.quote(rpc, probe, c, call=call)
            final, data = honest_swaps.build(frame, c, quoted, honest_swaps.QUOTE_SLIPPAGE_BPS, new_hash)
        except honest_swaps.QuoteFailed as e:
            why = f"{e} ({sim_error_class(json.dumps(e.sim_err))})" if e.sim_err is not None else norm(e, 70)
            s["skipped"][f"no quote: {why}"] += 1
            sleep(pace)
            continue
        except (solrpc.RateLimited, solrpc.RpcError, KeyError, TypeError, ValueError) as e:
            s["skipped"][f"not built ({type(e).__name__}: {norm(e, 60)})"] += 1
            sleep(pace)
            continue
        body = honest_swaps.request(c, harness, final, data)
        entry = {"row": c["row"], "slot": c["slot"], "program_id": c["program"], "instruction_name": c["venue"],
                 "manifest_found": None, "failed_on_chain": False}
        sink = {"refused_requests": s["refused_requests"], "server_errors": report["server_errors"], "defects": report["defects"]}
        row = verify_one(sink, entry, body, core, key, post_fn, tag="swap ")
        sleep(pace)
        if row is None:
            continue
        s["constructed"] += 1
        row.update(venue=c["venue"], sender=c["sender"], asset_in=c["asset_in"], asset_out=c["asset_out"],
                   original_signature=c.get("signature"), swap_accounts=c.get("accounts"),
                   amount=body["proposed_intent"]["extracted_parameters"]["amount"], quoted=quoted,
                   minimum=honest_swaps.minimum_of(c["layout"], data), original_version=c["version"],
                   primary=(harness or {}).get("program_id"))
        s["rows"].append(row)


def replay(selected, sample_rows, core, key, *, pace=1.0, l8=10, fresh=0, blockhash_fn=None, seeded=None,
           honest=0, swaps=0, requests_by_row=None, rpc=None, rpc_call=solrpc.call, sleep=time.sleep, post_fn=post,
           get_fn=get):
    """Every selected request through the Core (the first `fresh` of them
    twice: stale, then with a fresh blockhash), then L8 for a few executed
    ones. Returns the report dict."""
    report = {
        "core": core,
        "health": None,
        "requested": len(selected),
        "rows": [],
        "defects": [],
        "server_errors": [],
        "refused_requests": Counter(),
        "l8": [],
        "seeded": seeded,
        "fresh": {"asked": fresh, "requested": 0, "skipped": Counter(), "patched_by_version": Counter(), "rows": [], "pairs": []},
        "honest": {"asked": honest, "constructed": 0, "skipped": Counter(), "refused_requests": Counter(), "rows": [],
                   "candidates": None},
        "swaps": {"asked": swaps, "constructed": 0, "skipped": Counter(), "refused_requests": Counter(), "rows": [],
                  "candidates": None},
    }
    try:
        report["health"] = get_fn(f"{core}/health")
    except Exception as e:  # the Core is not up: nothing can be measured
        report["defects"].append(f"/health unreachable before the run: {type(e).__name__}: {e}")
        return finish(report)
    if report["health"].get("verification_mode") != "executable" or report["health"].get("rpc_attached") is not True:
        report["defects"].append(
            "the Core is not in executable mode (no RPC attached): every verdict would be analysis_only — "
            f"health says verification_mode={report['health'].get('verification_mode')!r}"
        )
        return finish(report)

    # Round 40 (measure): the honest agent's own transfers first, on the Core
    # as the evidence step left it — before the replay's verdicts can teach
    # it a baseline (a clean simulated verdict of an imported program is an
    # observation, bootstrap G-13).
    if honest:
        honest_pass(report, sample_rows, honest, core, key, post_fn, blockhash_fn, sleep, pace, rpc=rpc, call=rpc_call)
    if swaps:
        swap_pass(report, sample_rows, requests_by_row or {}, swaps, core, key, post_fn, blockhash_fn, rpc, sleep,
                  pace, call=rpc_call)

    for i, entry in enumerate(selected):
        row = verify_one(report, entry, entry["input"], core, key, post_fn)
        sleep(pace)
        if row is None:
            continue
        report["rows"].append(row)
        if i < fresh:
            fresh_one(report, entry, row, core, key, post_fn, blockhash_fn)
            sleep(pace)

    by_row = {r["row"]: r for r in sample_rows}
    seeded_programs = set(((seeded or {}).get("programs") or {}))
    inputs = {e["row"]: e.get("input") for e in selected}
    for r in report["rows"]:
        hits = watched(r, seeded_programs) if r.get("decision") else []
        if hits:
            r["watched"] = hits
            r.update(detail(r, by_row.get(r["row"]), inputs.get(r["row"])))
            if any(f in hits for f in SIGNER_DEBIT_FINDINGS) and by_row.get(r["row"]):
                r["fee_breakdown"] = fee_breakdown(by_row[r["row"]], r)

    # L8: a handful of transactions the chain executed, reconciled against the
    # verdict this run recorded for their exact bytes.
    candidates = [r for r in report["rows"] if r.get("decision") and not r["failed_on_chain"] and r.get("transaction_sha256")]
    for r in candidates[:l8]:
        src = by_row.get(r["row"])
        if src is None:
            continue
        try:
            signature = solrpc.first_signature(base64.b64decode(src["b64"]))
        except ValueError as e:
            report["l8"].append({"row": r["row"], "error": f"no signature: {e}"})
            continue
        body = {"signature": signature, "transaction_sha256": r["transaction_sha256"], "reported_by": "live-measure"}
        try:
            status, ans = post_fn(f"{core}/verify/execution", key, body)
        except Exception as e:
            report["defects"].append(f"L8 row {r['row']}: transport error {type(e).__name__}: {e}")
            continue
        if status >= 500:
            report["defects"].append(f"L8 row {r['row']}: /verify/execution answered {status}")
        entry = {"row": r["row"], "signature": signature, "http": status, "decision": r.get("decision")}
        if status == 200 and isinstance(ans, dict):
            recon = ans.get("reconciliation")
            entry.update(
                {
                    "reconciliation": recon if isinstance(recon, str) else (next(iter(recon)) if isinstance(recon, dict) and recon else recon),
                    "attribution": ans.get("attribution"),
                    "inclusion_assurance": ans.get("inclusion_assurance"),
                    "chain_status": next(iter(ans["chain_status"])) if isinstance(ans.get("chain_status"), dict) else ans.get("chain_status"),
                    "caller_keys_disagree": ans.get("caller_keys_disagree") or [],
                }
            )
            # A refused verdict the chain executed is exactly what L8 must
            # alarm on; an approved one reconciled as executed must say so.
            if entry["reconciliation"] == "ApprovedAndExecuted" and r.get("approved") is not True:
                report["defects"].append(f"L8 row {r['row']}: ApprovedAndExecuted for a verdict that was not approved")
        report["l8"].append(entry)
        sleep(pace)

    try:
        report["health_after"] = get_fn(f"{core}/health")
    except Exception as e:
        report["defects"].append(f"/health unreachable after the run (did the server die?): {type(e).__name__}: {e}")
    return finish(report)


def finish(report):
    rows = [r for r in report["rows"] if r.get("decision")]
    report["measured"] = len(rows)
    report["rate_limited_verdicts"] = sum(1 for r in rows if r.get("rpc_rate_limited"))
    report["decisions"] = dict(Counter(r["decision"] for r in rows))
    by_program = defaultdict(Counter)
    for r in rows:
        by_program[r["program_id"]][r["decision"]] += 1
    report["decisions_by_program"] = {p: dict(c) for p, c in sorted(by_program.items(), key=lambda kv: -sum(kv[1].values()))}
    report["l3"] = dict(Counter(r["l3"] for r in rows))
    report["l4"] = dict(Counter(str(r["l4"]) for r in rows))
    report["risk"] = dict(Counter(str(r["risk"]) for r in rows))
    report["reasons"] = dict(Counter(x for r in rows for x in r.get("reasons") or []).most_common())
    by_reason = defaultdict(Counter)
    for r in rows:
        for x in r.get("reasons") or []:
            by_reason[r["program_id"]][x] += 1
    report["reasons_by_program"] = {p: dict(c.most_common()) for p, c in sorted(by_reason.items(), key=lambda kv: -sum(kv[1].values()))}
    report["finding_patterns"] = dict(Counter(p for r in rows for p in r.get("findings") or []).most_common())
    seeded = (report.get("seeded") or {}).get("programs") or {}
    report["seeded_outcomes"] = {
        p: {
            "verdicts": sum(1 for r in rows if r["program_id"] == p),
            "decisions": dict(Counter(r["decision"] for r in rows if r["program_id"] == p)),
            "l3": dict(Counter(r["l3"] for r in rows if r["program_id"] == p)),
            "reasons": dict(Counter(x for r in rows if r["program_id"] == p for x in r.get("reasons") or []).most_common()),
        }
        for p in seeded
    }
    f = report.get("fresh")
    if f is not None:
        pairs = f["pairs"]
        f["skipped"] = dict(f["skipped"])
        f["patched_by_version"] = dict(f["patched_by_version"])
        f["compared"] = len(pairs)
        f["changed"] = sum(1 for p in pairs if p["changed"])
        for side in ("stale", "fresh"):
            f[f"{side}_decisions"] = dict(Counter(p[side]["decision"] for p in pairs))
            f[f"{side}_l3"] = dict(Counter(p[side]["l3"] for p in pairs))
            f[f"{side}_reasons"] = dict(Counter(x for p in pairs for x in p[side]["reasons"]).most_common())
    imported = set((report.get("seeded") or {}).get("imported") or [])
    if imported:
        report["decisions_by_evidence"] = {
            "census-imported program": dict(Counter(r["decision"] for r in rows if r["program_id"] in imported)),
            "program not imported": dict(Counter(r["decision"] for r in rows if r["program_id"] not in imported)),
        }
    h = report.get("honest")
    if h is not None:
        hrows = [r for r in h["rows"] if r.get("decision")]
        h["skipped"] = dict(h["skipped"])
        h["refused_requests"] = dict(h["refused_requests"])
        h["measured"] = len(hrows)
        h["decisions"] = dict(Counter(r["decision"] for r in hrows))
        h["decisions_by_kind"] = {k: dict(Counter(r["decision"] for r in hrows if r["kind"] == k))
                                  for k in sorted({r["kind"] for r in hrows})}
        h["l3"] = dict(Counter(r["l3"] for r in hrows))
        h["reasons"] = dict(Counter(x for r in hrows for x in r.get("reasons") or []).most_common())
        h["rate_limited_verdicts"] = sum(1 for r in hrows if r.get("rpc_rate_limited"))
    s = report.get("swaps")
    if s is not None:
        srows = [r for r in s["rows"] if r.get("decision")]
        s["skipped"] = dict(s["skipped"])
        s["refused_requests"] = dict(s["refused_requests"])
        s["measured"] = len(srows)
        s["decisions"] = dict(Counter(r["decision"] for r in srows))
        s["decisions_by_venue"] = {v: dict(Counter(r["decision"] for r in srows if r["venue"] == v))
                                   for v in sorted({r["venue"] for r in srows})}
        s["l3"] = dict(Counter(r["l3"] for r in srows))
        s["reasons"] = dict(Counter(x for r in srows for x in r.get("reasons") or []).most_common())
        s["rate_limited_verdicts"] = sum(1 for r in srows if r.get("rpc_rate_limited"))
    report["failed_on_chain"] = sum(1 for r in rows if r["failed_on_chain"])
    lat = [r["latency_ms"] for r in report["rows"] if "latency_ms" in r]
    report["latency_ms"] = {
        "p50": percentile(lat, 50),
        "p90": percentile(lat, 90),
        "p99": percentile(lat, 99),
        "max": max(lat) if lat else None,
        "mean": round(statistics.fmean(lat), 1) if lat else None,
    }
    report["refused_requests"] = dict(report["refused_requests"])
    report["l8_summary"] = {
        "reconciliation": dict(Counter(str(e.get("reconciliation")) for e in report["l8"])),
        "inclusion_assurance": dict(Counter(str(e.get("inclusion_assurance")) for e in report["l8"])),
    }
    measured_enough = report["requested"] == 0 or report["measured"] >= max(1, report["requested"] // 4)
    limited = report["rate_limited_verdicts"] > report["measured"] // 2
    if report["defects"]:
        report["status"] = "DEFECTS"
    elif not measured_enough or limited:
        report["status"] = "INCONCLUSIVE"
    else:
        report["status"] = "OK"
    return report


def markdown(report, harness=None):
    out = [f"# Live mainnet measurement — {report['status']}", ""]
    if report["status"] == "INCONCLUSIVE":
        out += [
            "**Inconclusive:** too few verdicts were measured, or most of them hit the RPC's rate limit. "
            "That is the endpoint, not Graphite; rerun later or set the `GRAPHITE_LIVE_RPC_URL` secret.",
            "",
        ]
    seed_doc = report.get("seeded") or {}
    seeded = sorted(seed_doc.get("programs") or {})
    if seed_doc and not seed_doc.get("ok", True):
        out += [f"**Operator evidence seeding did not complete:** {seed_doc.get('error')}", ""]
    out += evidence_markdown(seed_doc, seeded)
    out += [
        "| | |",
        "|---|---:|",
        f"| requests replayed | {report['requested']} |",
        f"| verdicts measured | {report['measured']} |",
        f"| … of transactions that failed on chain | {report['failed_on_chain']} |",
        f"| verdicts touched by an RPC rate limit | {report['rate_limited_verdicts']} |",
        f"| requests the Core refused (4xx) | {sum(report['refused_requests'].values())} {report['refused_requests'] or ''} |",
        f"| server errors (5xx / transport) | {len(report['server_errors'])} |",
        f"| latency p50 / p90 / p99 / max (ms) | {report['latency_ms']['p50']} / {report['latency_ms']['p90']} / {report['latency_ms']['p99']} / {report['latency_ms']['max']} |",
        "",
    ]
    out += honest_markdown(report.get("honest"))
    out += swaps_markdown(report.get("swaps"))
    out += [
        "## Decisions (the replay of other people's transactions)",
        "",
        "What the replay measures: the pipeline's behaviour on real traffic (no 5xx, no contradictory verdict, "
        "latency) and the simulator's answers. What it does not measure: the approval path. These transactions were "
        "built by other wallets minutes earlier; replayed against today's state many fail simulation (a spent "
        "input, a moved price, a closed account), and some had failed on chain already. The honest-transfer pass "
        "above is the approval-path measurement.",
        "",
        "| decision | count |",
        "|---|---:|",
    ]
    for d in DECISIONS:
        out.append(f"| `{d}` | {report['decisions'].get(d, 0)} |")
    if report.get("decisions_by_evidence"):
        out += ["", "| program's evidence | " + " | ".join(DECISIONS) + " |", "|---|" + "---:|" * len(DECISIONS)]
        for k, c in report["decisions_by_evidence"].items():
            out.append(f"| {k} | " + " | ".join(str(c.get(d, 0)) for d in DECISIONS) + " |")
    out += ["", "## By program (top 25)", "", "| program | " + " | ".join(DECISIONS) + " |", "|---|" + "---:|" * len(DECISIONS)]
    for p, c in list(report["decisions_by_program"].items())[:25]:
        out.append(f"| `{p}` | " + " | ".join(str(c.get(d, 0)) for d in DECISIONS) + " |")
    out += ["", "## L3 (simulation)", "", "| outcome | count |", "|---|---:|"]
    for k, v in sorted(report["l3"].items(), key=lambda kv: -kv[1]):
        out.append(f"| {k} | {v} |")
    out += ["", "## L4 (state diff)", "", "| status | count |", "|---|---:|"]
    for k, v in sorted(report["l4"].items(), key=lambda kv: -kv[1]):
        out.append(f"| {k} | {v} |")
    out += reasons_markdown(report)
    out += fresh_markdown(report.get("fresh"))
    out += seeded_markdown(report)
    out += watched_markdown(report)
    out += ["", "## L8 (inclusion) on transactions the chain executed", "", "| reconciliation | count |", "|---|---:|"]
    for k, v in report["l8_summary"]["reconciliation"].items():
        out.append(f"| `{k}` | {v} |")
    out += ["", "| inclusion_assurance | count |", "|---|---:|"]
    for k, v in report["l8_summary"]["inclusion_assurance"].items():
        out.append(f"| `{k}` | {v} |")
    if harness:
        out += ["", "## Conformance harness on the fresh blocks", "", f"exit status {harness.get('exit')}: {harness.get('note', '')}"]
    out += ["", "## Defects", ""]
    out += [f"- {d}" for d in report["defects"]] or ["None."]
    out += [
        "",
        "## Reading this",
        "",
        "- The replay's transactions are other people's, replayed unsigned against today's state with the "
        "intent an honest agent would declare. A program with no evidence is refused by policy, and a transaction "
        "whose inputs moved since fails simulation; that is the design, not a defect. The honest-transfer pass is "
        "the one that measures approvals.",
        "- A refusal is never counted here as a correct or an incorrect one: this run has no ground truth about "
        "intent. `BlockedButExecuted` (L8) and the *Watched rows* are where a candidate false refusal is shown.",
        "- `BlockedButExecuted` in L8 is the alarm firing as designed: Graphite refused a transaction "
        "somebody else executed.",
        "- `inclusion_assurance` is `single_provider` unless a witness RPC was configured.",
        "- The Core simulates with `replaceRecentBlockhash: true` (graphite-core/src/rpc_client.rs, "
        "`simulate_config`), so a stale blockhash cannot by itself make L3 fail; the fresh pass measures that "
        "rather than assuming it.",
    ]
    return "\n".join(out) + "\n"


def _cell(text):
    return str(text).replace("\n", " ").replace("|", "\\|")


def evidence_markdown(seed_doc, seeded):
    """What evidence the Core started with, said plainly (Round 40, measure:
    the text used to name System and SPL Token alone after a whole-census
    import, and an L3 anchor no longer typed)."""
    out = []
    if seeded and seed_doc.get("ok", True):
        n = seed_doc.get("imported_count")
        if seed_doc.get("whole_census"):
            what = (f"for every program the committed census admits — {n} program(s) imported"
                    if n is not None else "for every program the committed census admits")
        else:
            what = f"for {', '.join(f'`{p}`' for p in seeded)} only"
        typed = [p for p, d in (seed_doc.get("programs") or {}).items() if isinstance(d, dict) and d.get("baseline")]
        l3 = (f"An L3 compute baseline was also typed for {', '.join(f'`{p}`' for p in typed)} (an older seeding record)."
              if typed else
              "No L3 baseline was typed (Round 40): every program starts with no mature baseline, so L3 reads "
              "`no mature baseline` (inconclusive, which does not prevent `executable_approved`) until the Core has "
              "learned one from 10 of this run's own clean simulated verdicts; after that it can FLAG.")
        out += [
            f"**Evidence:** the measured census was imported {what} (`graphite evidence import-census`, from the "
            "committed mainnet census `battle_tested_evidence.json`, census sha256 "
            f"`{seed_doc.get('census_sha256') or 'not reported'}`): the state an operator's first start leaves. An "
            "imported program can reach `executable_approved` under the built-in Gaming profile; it is not thereby "
            f"approved — every other gate still decides. {l3} See *System and SPL Token* below.",
            "",
            "**Programs the import did not cover have no evidence.** No verdict for such a program can be "
            "`executable_approved` (every built-in profile refuses without evidence). What this run measures for "
            "them is the pipeline's behaviour and the simulator's answers, not approvals.",
            "",
        ]
    else:
        out += [
            "**A fresh Core has earned no evidence for any program.** No verdict can be `executable_approved` "
            "(every built-in profile refuses without evidence), and L3 has no baseline to compare against: `no "
            "mature baseline` below is that state, not a measurement failure. What this run measures is the "
            "pipeline's behaviour and the simulator's answers, not approvals.",
            "",
        ]
    return out


def honest_markdown(h):
    if not h or not h.get("asked"):
        return []
    c = h.get("candidates") or {}
    out = [
        "## Honest transfers: what an agent's own transaction gets",
        "",
        "From the fetched blocks, the executed simple transfers were taken — one System `Transfer` or SPL Token "
        "`TransferChecked` (or `Transfer`, when the block names its mint), beside nothing but Compute Budget, an "
        "idempotent associated-token-account create paid by the sender, or a memo; sent by the transaction's own "
        f"fee payer — up to {h['asked']}, one per sender, recipient and asset; and for each a NEW unsigned legacy "
        "transaction was built: the same sender to the same recipient, 1 lamport or 1 base unit (never more than "
        "the original), the original's Compute Budget and ATA-create instructions (a memo is dropped: its text was "
        "the original sender's), a blockhash just fetched, and a zeroed signature slot. Each was first simulated by the "
        "RPC (signature verification off): one the chain would reject now — the sender's account gone or emptied, "
        "or 1 lamport into an account that does not exist, under the rent minimum (that one is rebuilt once with the "
        "original's amount) — is counted under *not built*, never verified, because refusing it would be right and "
        "would measure the sender, not the Core. Each that would land was verified with the intent `transfer` and "
        "its amount, recipient and asset stated, under the built-in Gaming profile. Nothing was signed or sent: the "
        "bytes went to the RPC's simulateTransaction and the local Core's /verify only.",
        "",
        "What this measures: the decision an honest agent's own simple transfer gets from this Core against "
        "today's mainnet state. What it does not measure: swaps (their own section below) or any other protocol, "
        "what happens after signing, or wallets the runner controls — the senders are real wallets as they stand now.",
        "",
        f"- simple transfers in the sample: {c.get('simple transfers', 0)} ({c.get('by kind') or {}}); set aside: "
        f"{c.get('set aside') or {}}",
        f"- constructed and verified: **{h.get('constructed', 0)}** · verdicts: {h.get('measured', 0)} · not built: "
        f"{h.get('skipped') or {}} · refused as requests (4xx): {h.get('refused_requests') or {}} · "
        f"touched by an RPC rate limit: {h.get('rate_limited_verdicts', 0)} · rebuilt with the original's amount "
        f"(rent minimum): {h.get('rebuilt_with_original_amount', 0)}",
        "",
        "| decision | " + " | ".join(sorted(h.get("decisions_by_kind") or {})) + " | all |",
        "|---|" + "---:|" * (len(h.get("decisions_by_kind") or {}) + 1),
    ]
    for d in DECISIONS:
        out.append(f"| `{d}` | " + " | ".join(str(v.get(d, 0)) for _, v in sorted((h.get("decisions_by_kind") or {}).items()))
                   + f" | {(h.get('decisions') or {}).get(d, 0)} |")
    if h.get("l3"):
        out += ["", "L3 on these: " + ", ".join(f"{k}: {v}" for k, v in sorted(h["l3"].items(), key=lambda kv: -kv[1]))]
    rest = [r for r in h.get("rows") or [] if r.get("decision") != "executable_approved"]
    if rest:
        out += [
            "",
            "Every one that was not `executable_approved`, and why:",
            "",
            "| row | kind | sender → recipient | decision | risk · policy · confidence | unobserved | L3 | L3/L4 reasons | findings | L4 |",
            "|---:|---|---|---|---|---|---|---|---|---|",
        ]
        for r in rest:
            out.append(
                f"| {r['row']} | {r.get('kind')} | `{short(r.get('sender'))}` → `{short(r.get('recipient'))}` | "
                f"`{r.get('decision') or r.get('http')}` | {r.get('risk')} · {r.get('policy')} · {r.get('confidence')} | "
                f"{_cell(', '.join(r.get('unobserved_codes') or []))} | "
                f"{_cell(r.get('l3') or '')} | {_cell('; '.join(r.get('reasons') or []))} | "
                f"{_cell('; '.join(r.get('finding_reasons') or []))[:600]} | {_cell(r.get('l4_reason') or r.get('refusal') or '')} |"
            )
    out.append("")
    return out


def swaps_markdown(s):
    if not s or not s.get("asked"):
        return []
    c = s.get("candidates") or {}
    out = [
        "## Honest swaps: what an agent's own direct swap gets",
        "",
        "From the fetched blocks, the executed swaps a wallet made directly on a venue whose instruction the Core "
        "decodes (Jupiter v6 route / shared_accounts_route, Orca Whirlpools, Raydium CLMM, CPMM and AMM v4, Meteora "
        "DLMM), signed by its own fee payer alone, beside nothing but Compute Budget, an ATA create it pays, wrapping "
        "and unwrapping its own SOL, or a memo — up to "
        f"{s['asked']}, venues alternated, one per wallet, venue and pair. For each, the same swap was made again: the "
        "same wallet, pool accounts, lookup tables and amount in, a blockhash just fetched, signatures zeroed, and "
        f"the minimum output re-quoted: the RPC simulated the swap with a minimum of 1, the wallet's output accounts "
        f"were read before and after, and the minimum was set {honest_swaps.QUOTE_SLIPPAGE_BPS} bps under that "
        "quote (a Jupiter route: its quoted output and slippage). Each was verified with the intent `swap` — the "
        f"amount in, the input and output, `slippage_bps` {honest_swaps.REQUEST_SLIPPAGE_BPS} — under the built-in "
        "Gaming profile. Nothing was signed or sent: the bytes went to the RPC's simulateTransaction (for the quote) "
        "and the local Core's /verify only.",
        "",
        "What this measures: the decision an honest agent's own direct swap gets from this Core against today's "
        "mainnet state. What it does not measure: an aggregator's fresh route (each swap keeps the route its wallet "
        "chose), swaps beside a tip or another program (set aside below), or anything after signing.",
        "",
        f"- swaps on decoded venues in the sample: {c.get('swaps on decoded venues', 0)} (candidates by venue: "
        f"{c.get('by venue') or {}}); set aside: {c.get('set aside') or {}}",
        f"- quoted, constructed and verified: **{s.get('constructed', 0)}** · verdicts: {s.get('measured', 0)} · not "
        f"built: {s.get('skipped') or {}} · refused as requests (4xx): {s.get('refused_requests') or {}} · touched "
        f"by an RPC rate limit: {s.get('rate_limited_verdicts', 0)}",
        "",
        "| decision | " + " | ".join(sorted(s.get("decisions_by_venue") or {})) + " | all |",
        "|---|" + "---:|" * (len(s.get("decisions_by_venue") or {}) + 1),
    ]
    for d in DECISIONS:
        out.append(f"| `{d}` | " + " | ".join(str(v.get(d, 0)) for _, v in sorted((s.get("decisions_by_venue") or {}).items()))
                   + f" | {(s.get('decisions') or {}).get(d, 0)} |")
    if s.get("l3"):
        out += ["", "L3 on these: " + ", ".join(f"{k}: {v}" for k, v in sorted(s["l3"].items(), key=lambda kv: -kv[1]))]
    rest = [r for r in s.get("rows") or [] if r.get("decision") != "executable_approved"]
    if rest:
        out += [
            "",
            "Every one that was not `executable_approved`, and why:",
            "",
            "| row | venue | wallet · in → out (amount) | quote · minimum | decision | risk · policy · confidence | "
            "unobserved | L3 | L3/L4 reasons | findings | L4 |",
            "|---:|---|---|---|---|---|---|---|---|---|---|",
        ]
        for r in rest:
            out.append(
                f"| {r['row']} | {r.get('venue')} | `{short(r.get('sender'))}` · {short(r.get('asset_in'))} → "
                f"{short(r.get('asset_out'))} ({r.get('amount')}) | {r.get('quoted')} · {r.get('minimum')} | "
                f"`{r.get('decision') or r.get('http')}` | {r.get('risk')} · {r.get('policy')} · {r.get('confidence')} | "
                f"{_cell(', '.join(r.get('unobserved_codes') or []))} | "
                f"{_cell(r.get('l3') or '')} | {_cell('; '.join(r.get('reasons') or []))} | "
                f"{_cell('; '.join(r.get('finding_reasons') or []))[:600]} | {_cell(r.get('l4_reason') or r.get('refusal') or '')} |"
            )
        out += ["", "The original transaction and the swap instruction's accounts of each (`s` signer, `w` writable), "
                    "and every finding in full:", ""]
        for r in rest:
            accts = ", ".join(f"{i}:`{short(a)}`{'s' if sg else ''}{'w' if w else ''}" for i, (a, sg, w) in enumerate(r.get("swap_accounts") or []))
            out.append(f"- row {r['row']} (`{r.get('original_signature')}`): {accts}")
            for f in r.get("finding_reasons") or []:
                out.append(f"  - {_cell(f)}")
    out.append("")
    return out


def fee_markdown(rows):
    """The signer-debit rows with the fee set beside the chain's (Round 40)."""
    rows = [r for r in rows if r.get("fee_breakdown")]
    if not rows:
        return []
    out = [
        "",
        "### Signer debits beyond the fee: the fee, and what the chain did",
        "",
        "Graphite credits the fee the simulator reports (`simulateTransaction`'s `fee`: Agave's total fee — "
        "5,000 lamports per signature, precompile signatures included, plus the priority fee — charged to the fee "
        "payer). What a signer lost beyond it is value the transaction moved: a sibling System transfer (a tip), or "
        "a transfer the program made. Under a manifest that declares nothing for the instruction it is refused: a "
        "declaration Graphite cannot read does not excuse a signer's loss. `chain fee` and the per-signer change are "
        "the block's own record (`meta`), when this run's sample recorded them; a Graphite figure equal to the "
        "chain's beyond-the-fee figure means the fee was credited as the chain charged it.",
        "",
        "| row | signature | Graphite: beyond the fee | signatures (+precompile) | CU price × limit → priority fee | "
        "expected fee | chain fee | per-signer change on chain (beyond the fee) | instructions |",
        "|---:|---|---:|---|---|---:|---:|---|---|",
    ]
    for r in rows:
        f = r["fee_breakdown"]
        deltas = "; ".join(f"`{short(d['signer'])}` {d['delta']:+d} ({d['beyond_fee']})" for d in f.get("signer_deltas") or []) \
            or "not recorded"
        out.append(
            f"| {r['row']} | `{(r.get('signature') or '')[:16]}` | {f.get('graphite_beyond_fee')} | "
            f"{f.get('signatures')} (+{f.get('precompile_signatures')}) | "
            f"{f.get('cu_price_micro_lamports')} µl × {f.get('cu_limit')} → {f.get('priority_fee')} | "
            f"{f.get('expected_fee')} | {f.get('chain_fee') if f.get('chain_fee') is not None else 'not recorded'} | "
            f"{deltas} | {_cell('; '.join(f.get('instructions') or [f.get('error', '')]))} |"
        )
    return out


def reasons_markdown(report, top=60):
    out = ["", "## Why: every L3/L4 failure and inconclusive, by reason", ""]
    if not report.get("reasons"):
        return out + ["None: every measured L3 and L4 passed (or no verdict was measured)."]
    out += ["| layer · status: reason | count |", "|---|---:|"]
    out += [f"| {_cell(k)} | {v} |" for k, v in report["reasons"].items()]
    out += ["", f"### By program (top {top} rows)", "", "| program | layer · status: reason | count |", "|---|---|---:|"]
    flat = [(p, k, v) for p, c in report["reasons_by_program"].items() for k, v in c.items()]
    flat.sort(key=lambda t: -t[2])
    out += [f"| `{p}` | {_cell(k)} | {v} |" for p, k, v in flat[:top]]
    if len(flat) > top:
        out.append(f"| … | {len(flat) - top} more rows in report.json (`reasons_by_program`) | |")
    if report.get("finding_patterns"):
        out += ["", "### Risk findings behind the refusals", "", "| pattern | verdicts |", "|---|---:|"]
        out += [f"| `{k}` | {v} |" for k, v in report["finding_patterns"].items()]
    return out


def fresh_markdown(f):
    if not f or not f.get("asked"):
        return []
    out = [
        "",
        "## Fresh-blockhash pass (what an agent would actually submit)",
        "",
        f"The first {f['asked']} transactions were verified twice, back to back: as recorded (a blockhash minutes "
        "old) and with the unsigned frame's blockhash rewritten to one just fetched (getLatestBlockhash). "
        "Measurement-side bytes only: nothing was signed or sent.",
        "",
        f"- compared: {f.get('compared', 0)} pairs · outcome changed: **{f.get('changed', 0)}** · "
        f"patched by version: {f.get('patched_by_version') or {}} · skipped: {f.get('skipped') or {}}",
        "",
        "| | stale | fresh |",
        "|---|---:|---:|",
    ]
    for d in DECISIONS:
        out.append(f"| decision `{d}` | {f.get('stale_decisions', {}).get(d, 0)} | {f.get('fresh_decisions', {}).get(d, 0)} |")
    for k in sorted(set(f.get("stale_l3", {})) | set(f.get("fresh_l3", {}))):
        out.append(f"| L3 outcome: {_cell(k)} | {f['stale_l3'].get(k, 0)} | {f['fresh_l3'].get(k, 0)} |")
    for k in sorted(set(f.get("stale_reasons", {})) | set(f.get("fresh_reasons", {}))):
        out.append(f"| reason · {_cell(k)} | {f['stale_reasons'].get(k, 0)} | {f['fresh_reasons'].get(k, 0)} |")
    changed = [p for p in f.get("pairs", []) if p["changed"]]
    if changed:
        out += ["", "| row | program | version | stale | fresh |", "|---:|---|---|---|---|"]
        for p in changed[:30]:
            s, n = p["stale"], p["fresh"]
            out.append(
                f"| {p['row']} | `{p['program_id']}` | {p['version']} | {s['decision']} · {_cell(s['l3'])} · {_cell('; '.join(s['reasons']))} "
                f"| {n['decision']} · {_cell(n['l3'])} · {_cell('; '.join(n['reasons']))} |"
            )
    return out


def seeded_markdown(report):
    outcomes = report.get("seeded_outcomes") or {}
    if not outcomes:
        return []
    out = ["", "## System and SPL Token (census-imported)", ""]
    seed = report.get("seeded") or {}
    if not seed.get("ok", True):
        out += [f"**Seeding did not complete:** {seed.get('error')}", ""]
    out += ["| program | verdicts | " + " | ".join(DECISIONS) + " | L3 | reasons |", "|---|---:|" + "---:|" * len(DECISIONS) + "---|---|"]
    for p, o in outcomes.items():
        out.append(
            f"| `{p}` | {o['verdicts']} | " + " | ".join(str(o["decisions"].get(d, 0)) for d in DECISIONS)
            + f" | {_cell(o['l3'] or '—')} | {_cell(o['reasons'] or '—')} |"
        )
    if all(o["verdicts"] == 0 for o in outcomes.values()):
        out += ["", "No sampled transaction was attributed to a seeded program, so the seeded path was not exercised."]
    return out


def watched_markdown(report):
    rows = [r for r in report["rows"] if r.get("watched")]
    if not rows:
        return ["", "## Watched rows", "", "No verdict named a watched L4 finding or a seeded program."]
    out = [
        "",
        "## Watched rows",
        "",
        "Every verdict naming " + ", ".join(f"`{f}`" for f in WATCHED_FINDINGS) + " or a seeded program, with what the "
        "chain did. A refusal of a transaction that succeeded on chain with an ordinary shape (a swap plus a tip or a "
        "plain SOL transfer) is a candidate false refusal.",
        "",
        "| row | signature | program | decision | chain | CU | why watched | programs invoked | L3 | L4 |",
        "|---:|---|---|---|---|---:|---|---|---|---|",
    ]
    for r in rows:
        sig = (r.get("signature") or "")[:16]
        out.append(
            f"| {r['row']} | `{sig}` | `{r['program_id'][:12]}` {_cell(r.get('instruction') or '')} | `{r.get('decision')}` | "
            f"{'failed' if r.get('failed_on_chain') else 'ok'} | {r.get('cu_on_chain')} | {_cell(', '.join(r['watched']))} | "
            f"{_cell(' '.join(p[:8] for p in r.get('programs') or []))} | {_cell(r.get('l3_reason') or r.get('l3') or '')} | "
            f"{_cell(r.get('l4_reason_full') or '')} |"
        )
    return out + fee_markdown(rows)


# ── seed (operator evidence, before the Core starts) ────────────────────────


IMPORT_LINE_RE = re.compile(r"^IMPORT\s+([1-9A-HJ-NP-Za-km-z]{32,44})\s", re.M)
IMPORTED_RE = re.compile(r"^IMPORTED (\d+) program", re.M)
CENSUS_SHA_RE = re.compile(r"sha256=([0-9a-f]{64})")


def seed(graphite, data_dir, programs=SEEDED_PROGRAMS, *, whole_census=False, run=subprocess.run):
    """`graphite evidence import-census` for the programs (Round 40: their
    measured census volume, never typed numbers) — or, with `whole_census`,
    for every record the census admits, as an operator's first start does —
    then `show` for each of the programs. No L3 baseline is typed (Round 40,
    measure; see SEEDED_PROGRAMS). Returns the record the replay report
    carries, naming every program the import actually imported. Read-only
    towards the chain: nothing here signs or sends."""
    doc = {
        "ok": True,
        "evidence": "census-imported (whole census)" if whole_census else "census-imported",
        "whole_census": bool(whole_census),
        "l3_baselines": "none typed (learned from this run's own clean simulations only)",
        "programs": {},
    }
    imp = [graphite, "evidence", "import-census", "--cluster", "mainnet-beta", "--data-dir", data_dir]
    if not whole_census:
        for p in programs:
            imp += ["--program", p]
    r = run(imp, capture_output=True, text=True)
    if r.returncode != 0:
        doc.update(ok=False, error=f"`graphite evidence import-census` exited {r.returncode}: {(r.stderr or '')[-300:]}")
        return doc
    out = r.stdout or ""
    doc["import"] = out[-1500:]
    doc["imported"] = IMPORT_LINE_RE.findall(out)
    m = IMPORTED_RE.search(out)
    doc["imported_count"] = int(m.group(1)) if m else len(doc["imported"])
    sha = CENSUS_SHA_RE.search(out)
    doc["census_sha256"] = sha.group(1) if sha else None
    for p in programs:
        show = run([graphite, "evidence", "show", "--data-dir", data_dir, "--program", p], capture_output=True, text=True)
        doc["programs"][p] = {"imported": p in doc["imported"], "show": ((show.stdout or show.stderr) or "")[-600:]}
    # Asked for and not in force is a failed seeding (Round 36's rule): the
    # report would otherwise call these programs census-imported.
    missing = [p for p in programs if p not in doc["imported"]]
    if missing:
        doc.update(ok=False, error=f"`graphite evidence import-census` did not import {', '.join(missing)} (see its SKIP lines)")
    return doc


def read_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch")
    f.add_argument("--rpc", default=os.environ.get("LIVE_RPC_URL", "https://api.mainnet-beta.solana.com"))
    f.add_argument("--blocks", type=int, default=2)
    f.add_argument("--min-transactions", type=int, default=1000,
                   help="keep fetching (up to --max-blocks) until the sample holds this many transactions")
    f.add_argument("--max-blocks", type=int, default=8)
    f.add_argument("--out", required=True)
    s = sub.add_parser("select")
    s.add_argument("--requests", required=True)
    s.add_argument("--n", type=int, default=200)
    s.add_argument("--out", required=True)
    r = sub.add_parser("replay")
    r.add_argument("--selected", required=True)
    r.add_argument("--sample", required=True)
    r.add_argument("--core", default="http://127.0.0.1:7331")
    r.add_argument("--pace", type=float, default=1.0)
    r.add_argument("--l8", type=int, default=10)
    r.add_argument("--fresh", type=int, default=0, help="re-verify the first N with a fresh blockhash (needs --rpc)")
    r.add_argument("--honest", type=int, default=0,
                   help="first verify up to N new unsigned 1-lamport / 1-base-unit transfers built from the sample's "
                        "executed simple transfers (needs --rpc for a fresh blockhash; never signed or sent)")
    r.add_argument("--swaps", type=int, default=0,
                   help="then verify up to N honest direct swaps rebuilt from the sample's executed ones, the minimum "
                        "re-quoted by RPC simulation (needs --rpc and --requests; never signed or sent)")
    r.add_argument("--requests", default=None, help="the harness's requests.jsonl (every row's request), for --swaps")
    r.add_argument("--rpc", default=os.environ.get("LIVE_RPC_URL"),
                   help="for getLatestBlockhash, and the swap quotes' simulateTransaction (default: $LIVE_RPC_URL)")
    r.add_argument("--seeded", default=None, help="the record `seed` wrote, when evidence was seeded")
    r.add_argument("--harness-exit", type=int, default=None)
    r.add_argument("--out-dir", required=True)
    sd = sub.add_parser("seed")
    sd.add_argument("--graphite", required=True)
    sd.add_argument("--data-dir", required=True)
    sd.add_argument("--out", required=True)
    sd.add_argument("--whole-census", action="store_true",
                    help="import every record the census admits (an operator's first start), not only System and SPL Token")
    args = ap.parse_args(argv)

    if args.cmd == "seed":
        doc = seed(args.graphite, args.data_dir, whole_census=args.whole_census)
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=1)
        if doc["ok"]:
            print(f"census imported for {doc['imported_count']} program(s) ({doc['evidence']}); no L3 baseline typed")
        for p, d in doc["programs"].items():
            print(f"{p}: imported={d['imported']}\n{d['show']}")
        if not doc["ok"]:
            print(f"SEEDING FAILED: {doc['error']}", flush=True)
            return 1
        return 0

    if args.cmd == "fetch":
        try:
            doc = fetch(args.rpc, args.blocks, args.out, min_transactions=args.min_transactions,
                        max_blocks=args.max_blocks)
        except solrpc.RateLimited as e:
            print(f"RATE-LIMITED: {e} — no sample written; rerun later or set GRAPHITE_LIVE_RPC_URL", flush=True)
            return 3
        except solrpc.RpcError as e:
            print(f"RPC ERROR from {solrpc.host_of(args.rpc)}: {e} — no sample written", flush=True)
            return 3
        print(f"{doc['count']} transactions from slots {doc['slots']} (skipped {doc['skipped_slots']}) from {solrpc.host_of(args.rpc)}")
        return 0
    if args.cmd == "select":
        picked = select(read_jsonl(args.requests), args.n)
        with open(args.out, "w", encoding="utf-8") as f:
            for e in picked:
                f.write(json.dumps(e) + "\n")
        print(f"selected {len(picked)} requests across {len({e['program_id'] for e in picked})} programs")
        return 0

    key = os.environ.get("GRAPHITE_API_KEY", "")
    with open(args.sample, encoding="utf-8") as fh:
        sample_rows = [dict(r, row=i) for i, r in enumerate(json.load(fh)["rows"])]
    seeded = None
    if args.seeded:
        try:
            with open(args.seeded, encoding="utf-8") as fh:
                seeded = json.load(fh)
        except (OSError, ValueError) as e:
            seeded = {"ok": False, "programs": {}, "error": f"no seeding record: {type(e).__name__}: {e}"}
    blockhash_fn = FreshBlockhash(args.rpc) if ((args.fresh or args.honest or args.swaps) and args.rpc) else None
    if args.fresh:
        print(f"fresh pass: {args.fresh} transactions, blockhash from {solrpc.host_of(args.rpc) if args.rpc else '(no RPC: skipped)'}", flush=True)
    if args.honest:
        print(f"honest pass: up to {args.honest} constructed transfers, blockhash from {solrpc.host_of(args.rpc) if args.rpc else '(no RPC: skipped)'}", flush=True)
    if args.swaps:
        print(f"swap pass: up to {args.swaps} honest swaps, quotes and blockhash from {solrpc.host_of(args.rpc) if args.rpc else '(no RPC: skipped)'}", flush=True)
    requests_by_row = {e["row"]: e for e in read_jsonl(args.requests)} if (args.swaps and args.requests) else {}
    report = replay(read_jsonl(args.selected), sample_rows, args.core, key, pace=args.pace, l8=args.l8,
                    fresh=args.fresh, blockhash_fn=blockhash_fn, seeded=seeded, honest=args.honest,
                    swaps=args.swaps, requests_by_row=requests_by_row, rpc=args.rpc)
    if seeded is not None and not seeded.get("ok", True):
        report["defects"].append(f"operator evidence seeding failed: {seeded.get('error')}")
        report["status"] = "DEFECTS"
    harness = None
    if args.harness_exit is not None:
        harness = {
            "exit": args.harness_exit,
            "note": "the conformance invariants held on the fresh blocks"
            if args.harness_exit == 0
            else "the conformance harness FAILED its invariants on the fresh blocks — see its log",
        }
        report["harness"] = harness
        if args.harness_exit != 0:
            report["defects"].append(f"mainnet_conformance invariants failed on the fresh blocks (exit {args.harness_exit})")
            report["status"] = "DEFECTS"
    os.makedirs(args.out_dir, exist_ok=True)
    with open(os.path.join(args.out_dir, "report.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1, default=str)
    md = markdown(report, harness)
    with open(os.path.join(args.out_dir, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(md)
    print(md)
    return 1 if report["status"] == "DEFECTS" else 0


if __name__ == "__main__":
    sys.exit(main())
