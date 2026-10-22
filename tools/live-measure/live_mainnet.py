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

    python3 live_mainnet.py fetch   --rpc URL --blocks 2 --out sample.json
    (graphite-core) GRAPHITE_MAINNET_SAMPLE=sample.json GRAPHITE_MAINNET_HONEST_INTENT=1 \\
        GRAPHITE_MAINNET_REQUESTS=requests.jsonl cargo test --release --test mainnet_conformance \\
        -- --ignored real_mainnet_traffic --nocapture
    python3 live_mainnet.py select  --requests requests.jsonl --n 200 --out selected.jsonl
    GRAPHITE_API_KEY=... python3 live_mainnet.py replay --selected selected.jsonl \\
        --sample sample.json --core http://127.0.0.1:7331 --out-dir report/

No credentials are read but GRAPHITE_API_KEY (the local Core's) and an
optional RPC URL, which is never printed: logs name its host only.
"""
import argparse
import base64
import json
import os
import re
import statistics
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "mainnet-sample"))

import solrpc  # noqa: E402

INHERENT = {"program_semantics", "inner_instructions"}
DECISIONS = ("executable_approved", "analysis_only", "inconclusive", "blocked")
# "429" only as a standalone number: base58 addresses and hex hashes contain
# the digits, and a verdict quoting one is not a rate-limited verdict.
RATE_LIMIT_RE = re.compile(r"(?<![0-9A-Za-z])429(?![0-9A-Za-z])|too many requests|rate[ -]limit", re.I)


# ── fetch ────────────────────────────────────────────────────────────────────


def fetch(rpc_url, blocks, out, *, offset=40, stride=20, sleep=time.sleep, call=solrpc.call):
    """Recent finalized blocks, in the shape fetch_mainnet.py writes (so the
    conformance harness reads it unchanged). Close to the head on purpose: a
    replay runs against today's state, and the less of it has moved, the more
    of what is simulated is the transaction as it was."""
    from fetch_mainnet import rows_from_block  # the recorded fields, unchanged

    head = call(rpc_url, "getSlot", [{"commitment": "finalized"}])["result"]
    rows, fetched, skipped = [], [], []
    slot = head - offset
    tries = 0
    while len(fetched) < blocks and tries < blocks * 6:
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
    codes = scope.get("unobserved_codes") or []
    executable = (
        (result.get("risk_verdict") or {}).get("status") == "Clear"
        and result.get("policy_verdict") == "Approved"
        and scope.get("kind") == "artifact_bound"
        and scope.get("simulated") is True
        and all(c in INHERENT for c in codes)
        and not any(l.get("status") == "failed" for l in result.get("layers") or [])
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


def replay(selected, sample_rows, core, key, *, pace=1.0, l8=10, sleep=time.sleep, post_fn=post, get_fn=get):
    """Every selected request through the Core, then L8 for a few executed
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
        t0 = time.monotonic()
        try:
            status, body = post_fn(f"{core}/verify", key, entry["input"])
        except Exception as e:  # connection reset, refused: the server fell over
            report["server_errors"].append({"row": entry["row"], "error": f"{type(e).__name__}: {e}"})
            report["defects"].append(f"row {entry['row']}: /verify transport error {type(e).__name__}: {e}")
            sleep(pace)
            continue
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
            report["defects"].append(f"row {entry['row']}: /verify answered {status}")
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
                report["defects"].extend(f"row {entry['row']} ({entry['program_id']}): {d}" for d in found)
        report["rows"].append(row)
        sleep(pace)

    # L8: a handful of transactions the chain executed, reconciled against the
    # verdict this run recorded for their exact bytes.
    by_row = {r["row"]: r for r in sample_rows}
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
    ]
    return "\n".join(out) + "\n"


def read_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch")
    f.add_argument("--rpc", default=os.environ.get("LIVE_RPC_URL", "https://api.mainnet-beta.solana.com"))
    f.add_argument("--blocks", type=int, default=2)
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
    r.add_argument("--harness-exit", type=int, default=None)
    r.add_argument("--out-dir", required=True)
    args = ap.parse_args(argv)

    if args.cmd == "fetch":
        try:
            doc = fetch(args.rpc, args.blocks, args.out)
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
    report = replay(read_jsonl(args.selected), sample_rows, args.core, key, pace=args.pace, l8=args.l8)
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
