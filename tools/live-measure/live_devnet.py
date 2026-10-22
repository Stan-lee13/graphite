"""The gated path end to end on devnet (Round 32, P3).

One run, each step reported:

  1. keys      — two throwaway keypairs (payer, and a second address recorded
                 for the report); the payer's secret goes to a mode-600 file
                 and an environment variable, never to the log.
  2. airdrop   — devnet faucet, with backoff. A faucet that refuses is
                 reported as SKIPPED, honestly: nothing after it is claimed.
  3. evidence  — optional operator seeding for the System program
                 (`graphite evidence seed` / `baseline`), exactly what an
                 operator does before a fresh Core approves anything: without
                 earned or seeded evidence every built-in profile refuses.
  4. core      — the Core, with the devnet RPC attached (executable mode).
  5. ai layer  — python-ai-layer/intent_parser.py --serve.
  6. guard     — integrations/agent-guard/devnet-test.ts: grounded request →
                 spend cap → one transaction → unsigned simulation → Core
                 verdict on the bytes → decision + residual policy →
                 confirmation → signApproved → trail → send → confirm → L8.
  7. shutdown  — SIGTERM to the Core; a clean exit is part of the result.
  8. audit     — `graphite audit verify --json` over the run's trail.

    python3 live_devnet.py --graphite graphite-core/target/release/graphite \\
        --rpc https://api.devnet.solana.com --out-dir report/

Fails (exit 1) on a defect: the guard refusing or failing after funding, an
L8 discrepancy, an unclean Core shutdown, or an audit trail that does not
verify. Exit 0 with status SKIPPED when the faucet refused.
"""
import argparse
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import solrpc  # noqa: E402

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
GUARD_DIR = os.path.join(REPO, "integrations", "agent-guard")
SYSTEM_PROGRAM = "11111111111111111111111111111111"

KEYGEN = r"""
import { Keypair } from "@solana/web3.js";
import bs58 from "bs58";
const payer = Keypair.generate();
const dest = Keypair.generate();
process.stdout.write(JSON.stringify({
  payer_secret: bs58.encode(payer.secretKey),
  payer: payer.publicKey.toBase58(),
  destination: dest.publicKey.toBase58(),
}));
"""


def step(report, name, status, **detail):
    entry = {"step": name, "status": status, **detail}
    report["steps"].append(entry)
    print(f"[{name}] {status} {json.dumps(detail, default=str)[:400]}", flush=True)
    return entry


def gen_keys(work):
    out = subprocess.run(
        ["node", "--input-type=module", "-e", KEYGEN], cwd=GUARD_DIR, capture_output=True, text=True, check=True
    ).stdout
    keys = json.loads(out)
    path = os.path.join(work, "payer.key")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(keys["payer_secret"])
    return keys


def airdrop(rpc, pubkey, lamports, *, wait_s=90, call=solrpc.call, sleep=time.sleep):
    sig = call(rpc, "requestAirdrop", [pubkey, lamports, {"commitment": "confirmed"}], attempts=5, base_pause=5.0)
    if "error" in sig:
        raise solrpc.RpcError(f"requestAirdrop: {sig['error'].get('message', sig['error'])}")
    deadline = time.monotonic() + wait_s
    while time.monotonic() < deadline:
        bal = call(rpc, "getBalance", [pubkey, {"commitment": "confirmed"}])["result"]["value"]
        if bal >= lamports:
            return bal
        sleep(3)
    raise solrpc.RpcError(f"airdrop not visible after {wait_s}s")


def wait_http(url, key=None, timeout=60):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            req = urllib.request.Request(url)
            if key:
                req.add_header("Authorization", f"Bearer {key}")
            with urllib.request.urlopen(req, timeout=5) as r:
                return json.loads(r.read().decode() or "null")
        except Exception as e:  # not up yet
            last = e
            time.sleep(1)
    raise TimeoutError(f"{url} did not answer in {timeout}s ({last})")


def parse_guard_log(text):
    """What devnet-test.ts printed that the report needs."""
    def grab(pattern):
        m = re.search(pattern, text, re.M)
        return m.group(1).strip() if m else None

    return {
        "signature": grab(r"^Signature:\s+(\S+)"),
        "decision": grab(r"^Decision:\s+(\S+)"),
        "reported_decision": grab(r"reported by the Core:\s*([^)]+)\)"),
        "signing_recorded": grab(r"^Signing on trail:\s+(\S+)"),
        "submission_recorded": grab(r"^Submission on trail:\s+(\S+)"),
        "l8": grab(r"^L8 reconciliation:\s+(.+)$"),
        "confirmed": "ON DEVNET!" in text and "CONFIRMED ON DEVNET" in text,
        "discrepancy": "L8 DISCREPANCY" in text,
        "fee_paid": grab(r"^Fee Paid:\s+(\S+)"),
    }


TRANSIENT_MARKERS = ("429", "too many requests", "rate limit", "timed out", "timeout", "not yet", "connection")


def l8_outcome(l8):
    """`reconciled` for ApprovedAndExecuted; `unavailable` when L8 could not
    reach the chain for a transient reason (a public endpoint's problem, not
    Graphite's); anything else — a discrepancy, or an Unavailable whose reason
    is Graphite failing to read the answer — is a defect."""
    text = (l8 or "").lower()
    if "approvedandexecuted" in text:
        return "reconciled"
    if "unavailable" in text and any(m in text for m in TRANSIENT_MARKERS):
        return "unavailable"
    return "defect"


def run(args):
    report = {"rpc_host": solrpc.host_of(args.rpc), "steps": [], "defects": [], "notes": [], "status": None}
    work = tempfile.mkdtemp(prefix="graphite-devnet-")
    data_dir = os.path.join(work, "data")
    os.makedirs(data_dir)
    api_key = secrets.token_hex(32)
    procs = []

    def finish(status):
        report["status"] = status
        for p in procs:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(10)
                except subprocess.TimeoutExpired:
                    p.kill()
        # The throwaway payer key and the run's data dir go with the run.
        shutil.rmtree(work, ignore_errors=True)
        return report

    # A crash in the runner itself is reported, not lost: the report is
    # still written and every process it started is stopped.
    def steps():
        # 1. keys
        try:
            keys = gen_keys(work)
        except (subprocess.CalledProcessError, ValueError) as e:
            step(report, "keys", "FAILED", error=str(e)[:300])
            report["defects"].append("could not generate throwaway keypairs")
            return finish("DEFECTS")
        if os.environ.get("GITHUB_ACTIONS"):
            print(f"::add-mask::{keys['payer_secret']}", flush=True)
        step(report, "keys", "ok", payer=keys["payer"], destination=keys["destination"])
        report["payer"] = keys["payer"]

        # 2. airdrop
        try:
            bal = airdrop(args.rpc, keys["payer"], args.airdrop_lamports)
            step(report, "airdrop", "ok", lamports=bal)
        except (solrpc.RateLimited, solrpc.RpcError, KeyError, TypeError) as e:
            step(report, "airdrop", "SKIPPED", reason=f"the faucet refused or never paid out: {e}")
            return finish("SKIPPED")

        # 3. evidence (operator seeding — what an operator does before a fresh Core
        #    approves anything)
        if args.seed_evidence:
            cmds = [
                [args.graphite, "evidence", "seed", "--data-dir", data_dir, "--program", SYSTEM_PROGRAM, "--simulation-matches", "3"],
                [args.graphite, "evidence", "baseline", "--data-dir", data_dir, "--program", SYSTEM_PROGRAM,
                 "--mean-compute-units", "150", "--std-compute-units", "30", "--samples", "10"],
            ]
            for c in cmds:
                r = subprocess.run(c, capture_output=True, text=True)
                if r.returncode != 0:
                    step(report, "evidence", "FAILED", command=" ".join(c[1:4]), stderr=r.stderr[-400:])
                    report["defects"].append("operator evidence seeding failed")
                    return finish("DEFECTS")
            status = subprocess.run([args.graphite, "evidence", "show", "--data-dir", data_dir, "--program", SYSTEM_PROGRAM],
                                    capture_output=True, text=True)
            step(report, "evidence", "ok", evidence=(status.stdout or status.stderr)[-600:])
        else:
            step(report, "evidence", "not seeded")

        # 4. core
        env = dict(os.environ, GRAPHITE_API_KEY=api_key, GRAPHITE_DATA_DIR=data_dir, GRAPHITE_RPC_URL=args.rpc,
                   GRAPHITE_LOG_FORMAT="json")
        core_log = open(os.path.join(args.out_dir, "core.log"), "w")
        core = subprocess.Popen([args.graphite, "server", "--port", str(args.core_port)], env=env,
                                stdout=core_log, stderr=subprocess.STDOUT)
        procs.append(core)
        core_url = f"http://127.0.0.1:{args.core_port}"
        try:
            health = wait_http(f"{core_url}/health")
        except TimeoutError as e:
            step(report, "core", "FAILED", error=str(e))
            report["defects"].append("the Core did not start")
            return finish("DEFECTS")
        step(report, "core", "ok", verification_mode=health.get("verification_mode"), rpc_attached=health.get("rpc_attached"),
             audit_integrity=(health.get("audit") or {}).get("integrity"))
        if health.get("verification_mode") != "executable":
            report["defects"].append("the Core is not in executable mode with the devnet RPC attached")
            return finish("DEFECTS")

        # 5. ai layer
        ai_log = open(os.path.join(args.out_dir, "ai-layer.log"), "w")
        ai = subprocess.Popen([sys.executable, os.path.join(REPO, "python-ai-layer", "intent_parser.py"), "--serve"],
                              stdout=ai_log, stderr=subprocess.STDOUT, cwd=os.path.join(REPO, "python-ai-layer"))
        procs.append(ai)
        try:
            wait_http("http://127.0.0.1:8081/health", timeout=30)
            step(report, "ai-layer", "ok")
        except TimeoutError as e:
            step(report, "ai-layer", "FAILED", error=str(e))
            report["defects"].append("the AI layer did not start")
            return finish("DEFECTS")

        # 6. guard
        guard_env = dict(os.environ, SOLANA_PRIVATE_KEY=keys["payer_secret"], SOLANA_RPC_URL=args.rpc,
                         GRAPHITE_CORE_URL=core_url, GRAPHITE_API_KEY=api_key,
                         GRAPHITE_AI_LAYER_URL="http://127.0.0.1:8081")
        cmd = args.guard_cmd.split() if args.guard_cmd else ["npx", "tsx", "devnet-test.ts"]
        g = subprocess.run(cmd, cwd=GUARD_DIR, env=guard_env, capture_output=True, text=True, timeout=600)
        log = (g.stdout or "") + (g.stderr or "")
        log = log.replace(keys["payer_secret"], "***")
        with open(os.path.join(args.out_dir, "guard.log"), "w") as f:
            f.write(log)
        parsed = parse_guard_log(log)
        report["guard"] = {"exit": g.returncode, **parsed}
        if g.returncode != 0:
            step(report, "guard", "FAILED", exit=g.returncode, tail=log[-800:])
            report["defects"].append(f"the gated path did not complete (devnet-test exit {g.returncode}); see guard.log")
        elif parsed["discrepancy"]:
            step(report, "guard", "FAILED", **parsed)
            report["defects"].append("L8 reported a discrepancy: Graphite's decision did not govern")
        else:
            step(report, "guard", "ok", **parsed)
            if parsed["decision"] != "executable_approved":
                report["defects"].append(f"the guard executed under decision {parsed['decision']!r}, not executable_approved")
            if not parsed["confirmed"]:
                report["notes"].append("the transfer was submitted but its confirmation was still pending when the guard returned")
            l8_state = l8_outcome(parsed["l8"])
            if l8_state == "unavailable":
                report["notes"].append(f"L8 could not reach the chain ({parsed['l8']}); the execution is not reconciled")
            elif l8_state != "reconciled":
                report["defects"].append(f"L8 did not reconcile the executed transfer as ApprovedAndExecuted: {parsed['l8']}")

        # 7. shutdown
        core.send_signal(signal.SIGTERM)
        try:
            code = core.wait(40)
            step(report, "shutdown", "ok" if code == 0 else "FAILED", exit=code)
            if code != 0:
                report["defects"].append(f"the Core exited {code} on SIGTERM")
        except subprocess.TimeoutExpired:
            step(report, "shutdown", "FAILED", error="no exit 40 s after SIGTERM")
            report["defects"].append("the Core did not shut down on SIGTERM")
        ai.terminate()

        # 8. audit
        a = subprocess.run([args.graphite, "audit", "verify", "--data-dir", data_dir, "--json"], capture_output=True, text=True)
        try:
            audit = json.loads(a.stdout)
        except ValueError:
            audit = {"raw": a.stdout[-600:], "stderr": a.stderr[-600:]}
        report["audit"] = {"exit": a.returncode, "report": audit}
        # 0: nothing failed. 2: could not prove what was asked — an unkeyed trail
        # is corruption-evident only, which this run does not claim more of.
        if a.returncode in (0, 2):
            step(report, "audit", "ok", exit=a.returncode)
        else:
            step(report, "audit", "FAILED", exit=a.returncode)
            report["defects"].append(f"graphite audit verify exited {a.returncode}")

        if report["defects"]:
            return finish("DEFECTS")
        return finish("INCONCLUSIVE" if report["notes"] else "OK")

    try:
        return steps()
    except Exception as e:  # noqa: BLE001
        step(report, "runner", "FAILED", error=f"{type(e).__name__}: {e}"[:400])
        report["defects"].append("the measurement runner crashed; see the runner step")
        return finish("DEFECTS")


def markdown(report):
    out = [f"# Live devnet — gated path end to end: {report['status']}", "", f"RPC host: `{report['rpc_host']}`", ""]
    out += ["| step | status | detail |", "|---|---|---|"]
    for s in report["steps"]:
        detail = {k: v for k, v in s.items() if k not in ("step", "status")}
        text = json.dumps(detail, default=str).replace("|", "\\|")
        out.append(f"| {s['step']} | {s['status']} | `{text[:300]}` |")
    if report.get("guard"):
        g = report["guard"]
        out += ["", f"Signature: `{g.get('signature')}` · decision `{g.get('decision')}` · L8 `{g.get('l8')}`"]
    out += ["", "## Defects", ""] + ([f"- {d}" for d in report["defects"]] or ["None."])
    if report.get("notes"):
        out += ["", "## Not proven by this run", ""] + [f"- {n}" for n in report["notes"]]
    if report["status"] == "SKIPPED":
        out += ["", "The faucet refused; nothing after the airdrop was run or claimed. Rerun later."]
    return "\n".join(out) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--graphite", required=True, help="the graphite binary (server + cli features)")
    ap.add_argument("--rpc", default="https://api.devnet.solana.com")
    ap.add_argument("--airdrop-lamports", type=int, default=500_000_000)
    ap.add_argument("--core-port", type=int, default=7331)
    ap.add_argument("--no-seed-evidence", dest="seed_evidence", action="store_false")
    ap.add_argument("--guard-cmd", default=None, help="override the guard command (dry runs)")
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args(argv)
    os.makedirs(args.out_dir, exist_ok=True)
    report = run(args)
    with open(os.path.join(args.out_dir, "report.json"), "w") as f:
        json.dump(report, f, indent=1, default=str)
    md = markdown(report)
    with open(os.path.join(args.out_dir, "report.md"), "w") as f:
        f.write(md)
    print(md)
    return 1 if report["status"] == "DEFECTS" else 0


if __name__ == "__main__":
    sys.exit(main())
