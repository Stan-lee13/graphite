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

`seed` seeds operator evidence for the System and SPL Token programs before
the Core starts (as live_devnet.py does for System), so that a simple transfer
can reach `executable_approved` and the L3 anchored-baseline path runs.

    python3 live_mainnet.py fetch   --rpc URL --blocks 2 --out sample.json
    (graphite-core) GRAPHITE_MAINNET_SAMPLE=sample.json GRAPHITE_MAINNET_HONEST_INTENT=1 \\
        GRAPHITE_MAINNET_REQUESTS=requests.jsonl cargo test --release --test mainnet_conformance \\
        -- --ignored real_mainnet_traffic --nocapture
    python3 live_mainnet.py select  --requests requests.jsonl --n 200 --out selected.jsonl
    python3 live_mainnet.py seed    --graphite graphite --data-dir DATA --out seed.json   # optional
    GRAPHITE_API_KEY=... LIVE_RPC_URL=... python3 live_mainnet.py replay --selected selected.jsonl \\
        --sample sample.json --core http://127.0.0.1:7331 --fresh 40 [--seeded seed.json] --out-dir report/

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

import solrpc  # noqa: E402
import wire  # noqa: E402

SYSTEM_PROGRAM = "11111111111111111111111111111111"
SPL_TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
# What an operator does before a fresh Core approves anything (Round 40):
# `graphite evidence import-census` for these programs — the measured,
# committed mainnet census (protocols/battle_tested_evidence.json), not typed
# numbers — and a baseline L3 anchors on. The baseline is the one typed input
# left: an L3 calibration, so the run can show L3 FLAG; it also feeds the
# SimulationMatch signal through its sample count, and the report says so.
# System matches live_devnet.py; SPL Token's band covers Transfer (~4.6k CU)
# through TransferChecked (~6.2k CU) — a whole multi-program transaction
# measured against it is expected to fall outside, which is what the run shows.
SEED_BASELINES = {
    SYSTEM_PROGRAM: {"mean": 150, "std": 30, "samples": 10},
    SPL_TOKEN_PROGRAM: {"mean": 5000, "std": 1500, "samples": 10},
}

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
            rows.extend(rows_from_block(slot, r["result"]))
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


def replay(selected, sample_rows, core, key, *, pace=1.0, l8=10, fresh=0, blockhash_fn=None, seeded=None,
           sleep=time.sleep, post_fn=post, get_fn=get):
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
    seeded = sorted(((report.get("seeded") or {}).get("programs") or {}))
    if report.get("seeded") and not report["seeded"].get("ok", True):
        out += [f"**Operator evidence seeding did not complete:** {report['seeded'].get('error')}", ""]
    if seeded:
        out += [
            f"**Evidence:** operator evidence was seeded for {', '.join(f'`{p}`' for p in seeded)} only "
            "(their measured census volume, `graphite evidence import-census`, and an operator-set anchored compute "
            "baseline, `graphite evidence baseline`, which also feeds the SimulationMatch signal). Those programs "
            "can reach `executable_approved`, and their L3 is judged against the seeded anchor, which can FLAG; every "
            "other program is as on a fresh Core (next paragraph). See *Seeded programs* below.",
            "",
        ]
    out += [
        "**A fresh Core has earned no evidence for "
        + ("any other program" if seeded else "any program")
        + ".** No verdict for such a program can be `executable_approved` (every built-in profile refuses without "
        "evidence), and L3 has no anchored baseline to compare against, so it cannot FLAG a divergence either: "
        "`no mature baseline` below is that state, not a measurement failure. What this run measures for them is the "
        "pipeline's behaviour and the simulator's answers, not approvals.",
        "",
    ]
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
        "## Decisions",
        "",
        "| decision | count |",
        "|---|---:|",
    ]
    for d in DECISIONS:
        out.append(f"| `{d}` | {report['decisions'].get(d, 0)} |")
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
        "- These are other people's transactions, replayed unsigned against today's state with the "
        "intent an honest agent would declare. A fresh Core has earned no evidence, so most verdicts are "
        "policy refusals; that is the design, not a defect.",
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
    out = ["", "## Seeded programs", ""]
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
    return out


# ── seed (operator evidence, before the Core starts) ────────────────────────


def seed(graphite, data_dir, programs=None, *, run=subprocess.run):
    """`graphite evidence import-census` for the programs (Round 40: their
    measured census volume, never typed numbers), then `baseline` (the L3
    anchor) and `show` for each. Returns the record the replay report carries.
    Read-only towards the chain: nothing here signs or sends."""
    programs = programs or SEED_BASELINES
    doc = {"ok": True, "evidence": "census-imported", "programs": {}}
    imp = [graphite, "evidence", "import-census", "--data-dir", data_dir]
    for p in programs:
        imp += ["--program", p]
    r = run(imp, capture_output=True, text=True)
    if r.returncode != 0:
        doc.update(ok=False, error=f"`graphite evidence import-census` exited {r.returncode}: {(r.stderr or '')[-300:]}")
        return doc
    doc["import"] = (r.stdout or "")[-1500:]
    for p, b in programs.items():
        c = [graphite, "evidence", "baseline", "--data-dir", data_dir, "--program", p, "--mean-compute-units", str(b["mean"]),
             "--std-compute-units", str(b["std"]), "--samples", str(b["samples"])]
        r = run(c, capture_output=True, text=True)
        if r.returncode != 0:
            doc.update(ok=False, error=f"`graphite {' '.join(c[1:3])}` for {p} exited {r.returncode}: {(r.stderr or '')[-300:]}")
            return doc
        show = run([graphite, "evidence", "show", "--data-dir", data_dir, "--program", p], capture_output=True, text=True)
        doc["programs"][p] = {"baseline": b, "show": ((show.stdout or show.stderr) or "")[-600:]}
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
    r.add_argument("--rpc", default=os.environ.get("LIVE_RPC_URL"), help="for getLatestBlockhash only (default: $LIVE_RPC_URL)")
    r.add_argument("--seeded", default=None, help="the record `seed` wrote, when evidence was seeded")
    r.add_argument("--harness-exit", type=int, default=None)
    r.add_argument("--out-dir", required=True)
    sd = sub.add_parser("seed")
    sd.add_argument("--graphite", required=True)
    sd.add_argument("--data-dir", required=True)
    sd.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    if args.cmd == "seed":
        doc = seed(args.graphite, args.data_dir)
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=1)
        for p, d in doc["programs"].items():
            print(f"seeded {p}: baseline {d['baseline']}\n{d['show']}")
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
    blockhash_fn = FreshBlockhash(args.rpc) if (args.fresh and args.rpc) else None
    if args.fresh:
        print(f"fresh pass: {args.fresh} transactions, blockhash from {solrpc.host_of(args.rpc) if args.rpc else '(no RPC: skipped)'}", flush=True)
    report = replay(read_jsonl(args.selected), sample_rows, args.core, key, pace=args.pace, l8=args.l8,
                    fresh=args.fresh, blockhash_fn=blockhash_fn, seeded=seeded)
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
