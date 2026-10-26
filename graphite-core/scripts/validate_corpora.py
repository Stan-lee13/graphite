#!/usr/bin/env python3
"""Validate the committed data corpora, offline (Round 39, brief Phase F).

    python3 -I graphite-core/scripts/validate_corpora.py [--root DIR] [--json OUT] [--skip SECTION ...]

Reads, with the right parser, every JSON file the repository tracks (strict JSON
with duplicate keys refused; `tsconfig*.json` as JSONC, which is what TypeScript
reads), then checks the invariants the files' consumers rely on and that no
single Rust test holds across all of them:

  manifests  graphite-core/protocols/*.json: one manifest per program id, every
             file in SEED_MANIFESTS (src/manifest.rs) and in
             verified_program_ids.json, base58 32-byte keys everywhere a key is
             written (program id, expected_address, allowed_cpis), hex
             discriminators with no prefix collision, unique instruction names,
             a closed risk-class and trust-tier vocabulary, account flags that
             agree with the role, the PDA seed grammar with every
             {account_N} inside the instruction and not the slot itself, and
             a declared BattleTested tier only with a record that meets it.
  evidence   protocols/battle_tested_evidence.json: one record per manifest,
             the derived fields equal to their observations, the records under
             the decode bar named (the 13 of docs/CURRENT.md).
  idls       every committed IDL: its file name is its program, and each
             manifest instruction an IDL names has the IDL's discriminator
             (explicit, or Anchor's sha256("global:<snake>")[:8]) and slot
             count; the slot-count differences are the pinned 75 (K-7); an
             8-byte discriminator in no committed IDL of its program is an
             error (Round 40), one only in an IDL file the pinned 5.
  corpus    fixtures/corpus: entries in the file of their program, unique
             content hashes, meta/corpus_manifest.json one-to-one with them and
             agreeing on provenance; real rows name a real signature.
  artifacts  fixtures/artifacts and fixtures/mainnet: provenance written in the
             file, transaction versions read from the bytes and compared with
             the labels, digests recomputed.
  rewrites   docs/audit-r36/declaration-rewrites.json: each rewrite still in
             its manifest, and the medium-confidence rows listed exactly; a
             Round 36 row promoted to high carries an evidence record that is
             re-checked here (Round 40, F-005). docs/audit-r40/
             declaration-rewrites.json: each swap rewrite still in its
             manifest, made of the old lines that declare nothing plus lines
             that each name an account, every named account in every layout
             and a writable, non-signing account of the cited IDL instruction,
             the layout in the IDL's order, its medium rows pinned; the
             instructions left unchanged still unchanged; the removed
             instructions absent and in no committed IDL of their program.
  schemas    schemas/*.json against their metaschema and the examples against
             the schemas (needs the `jsonschema` package; without it the
             section is BLOCKED, never passed; `--skip schemas` says so).
  coverage   what the fixtures cover, by transaction version, protocol,
             instruction class, provenance, CPI shape, Token-2022 and unknown
             program. Reported, never gated: volume is not coverage.

Exit 0 when every section ran and found no error; 1 on any error; 3 when a
section could not run (BLOCKED). Errors are listed; so are the pinned known
gaps, which fail only when they change (fix the data or move the pin, in one
reviewed change). Python standard library only, apart from `jsonschema`.
"""
import argparse
import base64
import collections
import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ROOT = os.path.dirname(os.path.dirname(HERE))

# Pinned measurements (docs/CURRENT.md; tests/r30_declared_effects_census.rs,
# tests/r30_low_decode_manifests.rs). A change fails here so that it is looked at.
PINNED_LOW_DECODE = 13
PINNED_SLOT_COUNT_DIFFERENCES = 75
# Round 40: Squads v4's transactionBuffer{Create,Close,Extend},
# vaultTransactionCreateFromBuffer and proposalCancelV2 are in
# scripts/squads_v4_idl.json (v2.1.0), not in the on-chain IDL account.
PINNED_NEWER_THAN_ONCHAIN_IDL = 5
PINNED_MEDIUM_REWRITES = [
    ("spl-stake-pool.json", "WithdrawSol"),
    ("spl-stake-pool.json", "WithdrawSolWithSlippage"),
    ("spl-stake-pool.json", "WithdrawStake"),
    ("spl-stake-pool.json", "WithdrawStakeWithSlippage"),
    ("marinade.json", "liquidUnstake"),
    ("raydium-amm-v4.json", "SwapBaseIn"),
    ("raydium-amm-v4.json", "SwapBaseOut"),
    ("raydium-amm-v4.json", "SwapBaseInV2"),
    ("raydium-amm-v4.json", "SwapBaseOutV2"),
]
# Round 40 (F-005): of the nine, these stay medium. Each of the other seven
# carries a promotion record with its evidence (Marinade: the committed IDL;
# Stake Pool WithdrawStake*: spl stake-pool instruction.rs; Raydium AMM v4:
# raydium-amm instruction.rs, each pinned to a commit and a line range), which
# `check_promotion` re-checks. The two WithdrawSol rows are not promoted: the
# source marks slot 12 (the optional SOL withdraw authority) a signer and the
# manifest's layout does not.
PINNED_STILL_MEDIUM_R36 = [
    ("spl-stake-pool.json", "WithdrawSol"),
    ("spl-stake-pool.json", "WithdrawSolWithSlippage"),
]
# Round 40 (R39-CORE-DECISION-4): the swap rewrites whose IDL does not name
# the accounts unambiguously (no docs and a direction set by an argument, or
# names that do not say whose account it is). docs/audit-r40/declaration-rewrites.json.
PINNED_MEDIUM_REWRITES_R40 = [
    ("bonkswap-bswp6b.json", "swap"),
    ("guacswap-gswppe.json", "swap"),
    ("phoenix.json", "Swap"),
    ("dex-jupz4m.json", "swap_in"),
    ("dex-jupz4m.json", "swap_out"),
    ("okx-dex-router-provf4.json", "swap"),
    ("okx-dex-router-provf4.json", "proxy_swap"),
    ("okx-dex-router-provf4.json", "swap_tob"),
    ("okx-dex-router-provf4.json", "swap_tob_enhanced"),
    ("okx-dex-router-provf4.json", "swap_toc"),
    ("okx-dex-router-provf4.json", "swap_tob_with_token_ledger"),
    ("okx-dex-router-provf4.json", "swap_tob_v2"),
    ("okx-dex-router-provf4.json", "swap_toc_v2"),
    ("okx-dex-router-provf4.json", "swap_tob_v3"),
    ("okx-dex-router-provf4.json", "swap_toc_v3"),
    ("okx-dex-router-provf4.json", "swap_tob_with_token_ledger_v3"),
    ("okx-dex-router-provf4.json", "swap_tob_with_receiver"),
    ("okx-dex-router-provf4.json", "swap_tob_with_receiver_token_ledger"),
    ("okx-dex-router-provf4.json", "swap_tob_with_receiver_v3"),
    ("okx-dex-router-provf4.json", "swap_tob_with_receiver_token_ledger_v3"),
    ("debot-router-g7mvcm.json", "swap"),
    ("debot-router-g7mvcm.json", "swap_compact"),
    ("perpetuals-perphj.json", "swap2"),
    ("perpetuals-perphj.json", "swapWithTokenLedger"),
]
TRUST_TIERS = ("Unknown", "HeuristicInferred", "OfficialManifest", "SimulationValidated",
               "CommunityVerified", "BattleTested")
ROLES = ("signer", "writable", "readonly", "pda")
TOKEN_2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
MAX_SEEDS = 16
JSONC = re.compile(r"(^|/)tsconfig[^/]*\.json$")
SKIP_DIRS = {".git", "node_modules", "target", ".claude", ".agents", "dist", "__pycache__"}

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_INDEX = {c: i for i, c in enumerate(B58)}


def b58decode(s):
    if not isinstance(s, str) or not s or any(c not in B58_INDEX for c in s):
        return None
    n = 0
    for c in s:
        n = n * 58 + B58_INDEX[c]
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + body


def is_pubkey(s):
    b = b58decode(s)
    return b is not None and len(b) == 32


def is_signature(s):
    b = b58decode(s)
    return b is not None and len(b) == 64


def snake(name):
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    s = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", s)
    return s.lower()


def norm(name):
    return re.sub(r"[^A-Za-z0-9]", "", name).lower()


def anchor_disc(name):
    return hashlib.sha256(("global:" + snake(name)).encode()).hexdigest()[:16]


class Report:
    def __init__(self):
        self.errors, self.pinned, self.info, self.blocked = [], [], [], []
        self.data = collections.OrderedDict()

    def error(self, section, msg):
        self.errors.append(f"[{section}] {msg}")

    def pin(self, section, msg):
        self.pinned.append(f"[{section}] {msg}")

    def note(self, section, msg):
        self.info.append(f"[{section}] {msg}")


# ---------------------------------------------------------------- parsing

def no_dupes(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate key {k!r}")
        out[k] = v
    return out


def strip_jsonc(text):
    """JSONC as TypeScript reads it: // and /* */ comments, trailing commas."""
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                raise ValueError("unterminated /* comment")
            i = j + 2
        else:
            out.append(c)
            i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def tracked_json(root):
    try:
        out = subprocess.run(["git", "-C", root, "ls-files", "-z", "--", "*.json"], capture_output=True, check=True)
        files = [f for f in out.stdout.decode().split("\0") if f]
        if files:
            return sorted(files)
    except (OSError, subprocess.CalledProcessError):
        pass
    files = []
    for d, subdirs, names in os.walk(root):
        subdirs[:] = [s for s in subdirs if s not in SKIP_DIRS]
        files += [os.path.relpath(os.path.join(d, n), root) for n in names if n.endswith(".json")]
    return sorted(files)


def parse_all(root, rep):
    docs, strict, jsonc = {}, 0, 0
    for rel in tracked_json(root):
        path = os.path.join(root, rel)
        if not os.path.isfile(path):
            continue
        try:
            text = open(path, encoding="utf-8").read()
        except (OSError, UnicodeDecodeError) as e:
            rep.error("parse", f"{rel}: unreadable: {e}")
            continue
        try:
            docs[rel] = json.loads(text, object_pairs_hook=no_dupes)
            strict += 1
        except ValueError as e:
            if JSONC.search(rel):
                try:
                    docs[rel] = json.loads(strip_jsonc(text), object_pairs_hook=no_dupes)
                    jsonc += 1
                    continue
                except ValueError as e2:
                    rep.error("parse", f"{rel}: not valid JSONC either: {e2}")
                    continue
            rep.error("parse", f"{rel}: {e}")
    rep.data["parse"] = {"strict_json": strict, "jsonc": jsonc, "errors": len([e for e in rep.errors if e.startswith("[parse]")])}
    return docs


# ---------------------------------------------------------------- manifests

def seed_list(root):
    src = open(os.path.join(root, "graphite-core", "src", "manifest.rs"), encoding="utf-8").read()
    m = re.search(r"SEED_MANIFESTS: &\[\(&str, &str\)\] = seed_manifests!\[(.*?)\];", src, re.S)
    rc = re.search(r"pub const RISK_CLASSES: &\[&str\] = &\[(.*?)\];", src, re.S)
    seeds = re.findall(r'"([^"]+\.json)"', m.group(1)) if m else []
    classes = re.findall(r'"([^"]*)"', rc.group(1)) if rc else []
    return seeds, classes


def check_seed(seed, slot, nslots):
    """The template grammar of account_resolution.rs::resolve_pda_seed_template."""
    if not isinstance(seed, str):
        return "not a string"
    if seed.startswith("{"):
        if not seed.endswith("}"):
            return "opens with '{' and does not close"
        inner = seed[1:-1]
        if "{" in inner or "}" in inner:
            return "nested braces"
        head, *rng = inner.split(":")
        if len(rng) > 2:
            return "more than a start and an end"
        if any(not r.isdigit() for r in rng if r != "") or (rng and rng[0] == ""):
            return f"byte range {rng} is not decimal"
        if len(rng) == 2 and rng[1] != "" and int(rng[1]) < int(rng[0]):
            return "reversed byte range"
        if head == "program_id":
            return "{program_id} takes no range" if rng else None
        if head == "instruction_data":
            return None
        if head.startswith("account_"):
            idx = head[len("account_"):]
            if not idx.isdigit():
                return f"account index {idx!r} is not digits"
            i = int(idx)
            if i == slot:
                return "derives the account from its own address"
            if i >= nslots:
                return f"reads account {i}; the layout has {nslots}"
            if len(rng) == 2 and rng[1] and int(rng[1]) > 32:
                return "reads past a public key's 32 bytes"
            return None
        return f"{{{head}}} is not in the grammar"
    if "{" in seed or "}" in seed:
        return "brace inside a literal"
    if seed.startswith("0x"):
        try:
            b = bytes.fromhex(seed[2:])
        except ValueError:
            return "0x seed is not even-length hex"
        return "longer than 32 bytes" if len(b) > 32 else None
    if seed == "":
        return "empty seed"
    return "longer than 32 bytes" if len(seed.encode()) > 32 else None


def layouts(ix):
    return [ix.get("accounts") or []] + list(ix.get("account_layouts") or [])


def check_manifests(root, docs, rep):
    S = "manifests"
    seeds, classes = seed_list(root)
    if not seeds or not classes:
        rep.error(S, "could not read SEED_MANIFESTS or RISK_CLASSES from graphite-core/src/manifest.rs")
    pdir = "graphite-core/protocols/"
    files = sorted(f for f in docs if f.startswith(pdir) and f.count("/") == 2)
    manifests = {}
    for f in files:
        d = docs[f]
        if isinstance(d, dict) and "instructions" in d:
            manifests[f[len(pdir):]] = d
    others = sorted(set(f[len(pdir):] for f in files) - set(manifests))
    if others != ["battle_tested_evidence.json", "verified_program_ids.json"]:
        rep.error(S, f"non-manifest files in protocols/: {others}")
    if sorted(seeds) != sorted(manifests):
        rep.error(S, f"SEED_MANIFESTS vs protocols/: only listed {sorted(set(seeds) - set(manifests))}, only on disk {sorted(set(manifests) - set(seeds))}")
    if len(seeds) != len(set(seeds)):
        rep.error(S, "a file is listed twice in SEED_MANIFESTS")
    by_pid = collections.defaultdict(list)
    n_ix = n_slots = 0
    stats = collections.Counter()
    for name, m in sorted(manifests.items()):
        where = name
        for k in ("graphite_manifest_version", "protocol", "version", "instructions", "trust_tier"):
            if k not in m:
                rep.error(S, f"{where}: no {k!r}")
        p = m.get("protocol") or {}
        pid = p.get("program_id")
        if not is_pubkey(pid):
            rep.error(S, f"{where}: program_id {pid!r} is not a base58 32-byte key")
        by_pid[pid].append(name)
        for fld in ("website", "github"):
            v = (p.get(fld) or "").strip()
            if v and not v.startswith(("https://", "http://")):
                rep.error(S, f"{where}: protocol.{fld} {v!r} is not http(s)")
        if m.get("trust_tier") not in TRUST_TIERS:
            rep.error(S, f"{where}: trust_tier {m.get('trust_tier')!r}")
        stats["tier:" + str(m.get("trust_tier"))] += 1
        ixs = m.get("instructions") or []
        if not ixs:
            rep.error(S, f"{where}: no instructions")
        names = collections.Counter(i.get("name") for i in ixs)
        for nm, c in names.items():
            if c > 1:
                rep.error(S, f"{where}: instruction name {nm!r} declared {c} times")
        discs = []
        for ix in ixs:
            n_ix += 1
            iw = f"{where}::{ix.get('name')}"
            if not ix.get("name"):
                rep.error(S, f"{where}: an instruction with no name")
            disc = ix.get("discriminator")
            if not isinstance(disc, str) or (disc and not re.fullmatch(r"(?:[0-9a-f]{2})+", disc)):
                rep.error(S, f"{iw}: discriminator {disc!r} is not lowercase even-length hex")
            elif disc == "" and len(ixs) != 1:
                rep.error(S, f"{iw}: no discriminator beside other instructions")
            elif disc:
                discs.append((disc, ix.get("name")))
            if ix.get("risk_class") not in classes:
                rep.error(S, f"{iw}: risk_class {ix.get('risk_class')!r} is not one of {classes}")
            stats["class:" + (ix.get("risk_class") or "(none)")] += 1
            for line in ix.get("expected_state_changes") or []:
                if line.strip().lower().startswith("graphite:"):
                    rep.error(S, f"{iw}: a declared change begins with 'graphite:'")
            for cpi in ix.get("allowed_cpis") or []:
                if not is_pubkey(cpi):
                    rep.error(S, f"{iw}: allowed_cpis entry {cpi!r} is not a base58 32-byte key")
            lens = []
            for li, lay in enumerate(layouts(ix)):
                lens.append(len(lay))
                seen = collections.Counter(a.get("name") for a in lay)
                dup = sorted(an for an, c in seen.items() if c > 1)
                if dup:
                    # Flattened nested IDL groups (Kamino's deposit/withdraw halves)
                    # repeat names; a declaration naming one would be ambiguous.
                    text = "\n".join(ix.get("expected_state_changes") or [])
                    named = [an for an in dup if re.search(r"accounts\." + re.escape(str(an)) + r"\b", text)]
                    if named:
                        rep.error(S, f"{iw} layout {li}: a declaration names {named}, which the layout repeats")
                    rep.pin(S, f"{iw} layout {li}: {len(dup)} account name(s) repeated, none named by a declaration: {dup}")
                if li == 0:
                    every = {a.get("name") for l2 in layouts(ix) for a in l2}
                    for line in ix.get("expected_state_changes") or []:
                        if line.startswith("modifies writable accounts: "):
                            listed = [x.strip() for x in line[len("modifies writable accounts: "):].split(", ")]
                            stray = [x for x in listed if x and x not in every]
                            if stray:
                                rep.pin(S, f"{iw}: 'modifies writable accounts' lists {stray}, not layout account names (prose; L4 reads only accounts.<name>)")
                for s, a in enumerate(lay):
                    n_slots += 1
                    aw = f"{iw} layout {li} slot {s} ({a.get('name')})"
                    role = a.get("role")
                    if role not in ROLES:
                        rep.error(S, f"{aw}: role {role!r}")
                    if not isinstance(a.get("is_signer"), bool) or not isinstance(a.get("is_writable"), bool):
                        rep.error(S, f"{aw}: is_signer/is_writable are not booleans")
                    if role == "signer" and not a.get("is_signer"):
                        rep.error(S, f"{aw}: role signer but is_signer false")
                    if role == "writable" and not a.get("is_writable"):
                        rep.error(S, f"{aw}: role writable but is_writable false")
                    if role == "readonly" and (a.get("is_writable") or a.get("is_signer")):
                        rep.error(S, f"{aw}: role readonly but flagged signer/writable")
                    if role == "writable" and a.get("is_signer"):
                        # The flags are what the pipeline reads (the role is a label);
                        # recorded so the label can be corrected.
                        rep.pin(S, f"{aw}: role 'writable' on a signer slot (the flags rule; label only)")
                    seeds = a.get("pda_seeds")
                    if not isinstance(seeds, list):
                        rep.error(S, f"{aw}: pda_seeds is not a list")
                        seeds = []
                    if len(seeds) >= MAX_SEEDS:
                        rep.error(S, f"{aw}: {len(seeds)} seeds plus the bump exceed {MAX_SEEDS}")
                    for sd in seeds:
                        why = check_seed(sd, s, len(lay))
                        if why:
                            rep.error(S, f"{aw}: seed {sd!r}: {why}")
                    if role == "pda" and not seeds:
                        rep.pin(S, f"{aw}: role 'pda' with no seeds: its address is not derived or checked by the manifest")
                    ea = a.get("expected_address")
                    if ea is not None:
                        vals = ea if isinstance(ea, list) else [ea]
                        for v in vals:
                            if not is_pubkey(v):
                                rep.error(S, f"{aw}: expected_address {v!r} is not a base58 32-byte key")
            if len(lens) != len(set(lens)):
                rep.error(S, f"{iw}: two layouts of the same length {lens}")
        for i, (a, an) in enumerate(discs):
            for b, bn in discs[i + 1:]:
                if a == b or a.startswith(b) or b.startswith(a):
                    rep.error(S, f"{where}: discriminators {an} ({a}) and {bn} ({b}) are prefix-related")
    for pid, names in by_pid.items():
        if len(names) > 1:
            rep.error(S, f"program id {pid} has {len(names)} manifests: {names}")
    vp = docs.get(pdir + "verified_program_ids.json") or {}
    vids = [x.get("program_id") for x in vp.get("programs") or []]
    mids = sorted(m["protocol"]["program_id"] for m in manifests.values())
    if sorted(vids) != mids:
        rep.error(S, f"verified_program_ids.json vs manifests: only listed {sorted(set(vids) - set(mids))}, only manifests {sorted(set(mids) - set(vids))}")
    for x in vp.get("programs") or []:
        if x.get("verified") is not True or x.get("network") != "mainnet" or not x.get("provenance"):
            rep.error(S, f"verified_program_ids.json: {x.get('program_id')} is not verified on mainnet with a provenance")
    rep.data["manifests"] = {"manifests": len(manifests), "unique_program_ids": len(by_pid), "instructions": n_ix,
                             "account_slots": n_slots, **{k: v for k, v in sorted(stats.items())}}
    return manifests


# ---------------------------------------------------------------- evidence

def check_evidence(docs, manifests, rep):
    S = "evidence"
    ev = docs.get("graphite-core/protocols/battle_tested_evidence.json") or {}
    th = ev.get("thresholds") or {}
    recs = ev.get("programs") or []
    by_file = {}
    for r in recs:
        mf = r.get("manifest")
        if mf in by_file:
            rep.error(S, f"{mf}: two records")
        by_file[mf] = r
    if sorted(by_file) != sorted(manifests):
        rep.error(S, f"records vs manifests: only records {sorted(set(by_file) - set(manifests))}, only manifests {sorted(set(manifests) - set(by_file))}")
    low = []
    for mf, r in sorted(by_file.items()):
        m = manifests.get(mf)
        if not m:
            continue
        w = f"{mf} ({r.get('name')})"
        if r.get("program_id") != m["protocol"]["program_id"]:
            rep.error(S, f"{w}: program_id {r.get('program_id')} is not the manifest's")
        if r.get("declared_trust_tier") != m.get("trust_tier"):
            rep.error(S, f"{w}: declared_trust_tier {r.get('declared_trust_tier')} vs manifest {m.get('trust_tier')}")
        dec, vol, ident = r.get("decode") or {}, r.get("volume") or {}, r.get("identity") or {}
        obs, named = dec.get("instructions_observed") or 0, dec.get("instructions_named_by_manifest") or 0
        if named > obs:
            rep.error(S, f"{w}: {named} named of {obs} observed")
        byname = dec.get("instructions_by_name") or {}
        if sum(byname.values()) != named:
            rep.error(S, f"{w}: instructions_by_name sums to {sum(byname.values())}, named {named}")
        ixnames = {i["name"] for i in m["instructions"]}
        for nm in byname:
            if nm not in ixnames:
                rep.error(S, f"{w}: instructions_by_name {nm!r} is not an instruction of the manifest")
        rate = dec.get("decode_rate")
        if dec.get("decode_applicable", True) and obs:
            if rate is None or abs(rate - named / obs) > 1e-6:
                rep.error(S, f"{w}: decode_rate {rate} is not {named}/{obs}")
        # The rule of scripts/recompute_evidence.py: a program with no
        # discriminator (a memo) has no decode rate and never meets it.
        meets = bool(ident.get("executable")
                     and (vol.get("successful_transactions_counted") or 0) >= th.get("min_successful_transactions", 1 << 60)
                     and obs >= th.get("min_decoded_instructions", 1 << 60)
                     and rate is not None
                     and rate >= th.get("min_decode_rate", 2))
        if bool(r.get("meets_battle_tested")) != meets:
            rep.error(S, f"{w}: meets_battle_tested {r.get('meets_battle_tested')} but the thresholds give {meets}")
        if m.get("trust_tier") == "BattleTested" and not r.get("meets_battle_tested"):
            rep.error(S, f"{w}: declares BattleTested without a record that meets it (P7)")
        if dec.get("decode_applicable", True) and obs and (rate or 0) < th.get("min_decode_rate", 0.9):
            low.append((round(rate or 0, 4), r.get("name"), mf, obs, named))
    low.sort()
    for rate, nm, mf, obs, named in low:
        rep.pin(S, f"below the decode bar: {nm} ({mf}) {named}/{obs} = {rate:.4f}")
    if len(low) != PINNED_LOW_DECODE:
        rep.error(S, f"{len(low)} records under the decode bar; pinned {PINNED_LOW_DECODE} (docs/CURRENT.md, tests/r30_low_decode_manifests.rs)")
    rep.data["evidence"] = {"records": len(recs), "meets_battle_tested": sum(1 for r in recs if r.get("meets_battle_tested")),
                            "below_decode_bar": [x[1] for x in low]}


# ---------------------------------------------------------------- idls

def idl_count(accs):
    n = 0
    for a in accs or []:
        n += idl_count(a["accounts"]) if isinstance(a, dict) and "accounts" in a else 1
    return n


def check_idls(docs, manifests, rep):
    S = "idls"
    by_pid = {m["protocol"]["program_id"]: (f, m) for f, m in manifests.items()}
    sources = []
    for f, d in docs.items():
        if f.startswith("graphite-core/scripts/out/onchain_idls/"):
            pid = os.path.basename(f)[:-5]
            if not is_pubkey(pid):
                rep.error(S, f"{f}: the file name is not a program id")
            addr = d.get("address") or (d.get("metadata") or {}).get("address")
            if addr and addr != pid:
                # The IDL account is the program's own (onboarding gate); its
                # `address` is what its author wrote (a fork's, or a
                # placeholder), so it is reported, not trusted either way.
                rep.pin(S, f"{f}: the IDL's own address field is {addr}, not the program it was read from")
            sources.append((f, pid, d, True))
        elif re.match(r"graphite-core/scripts/(idls/[^/]+|[^/]+_idl)\.json$", f):
            addr = d.get("address") or (d.get("metadata") or {}).get("address")
            if addr:
                sources.append((f, addr, d, False))
            else:
                rep.note(S, f"{f}: names no program address; not compared")
    idx = docs.get("graphite-core/scripts/out/idl_index.json") or {}
    for p in idx.get("programs") or []:
        if p.get("idl") and not any(s[0].endswith(p["program_id"] + ".json") for s in sources if s[3]):
            rep.error(S, f"idl_index.json: {p['program_id']} has an IDL and no out/onchain_idls file")
    # swap-instructions.ts: this IDL's discriminators "are not the deployed
    # ones"; its argument layouts are what it is kept for.
    not_deployed = {"graphite-core/scripts/idls/jupiter_v6_surfpool.json"}
    compared = disc_ok = 0
    phantom = []
    disc_bad, slot_diff = [], []
    # Round 40 (R39-SUPPLY-CHAIN-11): an 8-byte discriminator is evidenced by
    # ANY committed IDL of its program whose discriminators are the deployed
    # ones — the on-chain IDL account or an IDL file naming the program. Squads
    # v4's five buffer/cancel instructions are in scripts/squads_v4_idl.json
    # (v2.1.0) and not in the older on-chain IDL account: kept, reported.
    every_disc = collections.defaultdict(set)
    onchain_disc = collections.defaultdict(set)
    for f, pid, d, onchain in sources:
        if f in not_deployed:
            continue
        for i in d.get("instructions") or []:
            x = bytes(i["discriminator"]).hex() if "discriminator" in i else anchor_disc(i["name"])
            every_disc[pid].add(x)
            if onchain:
                onchain_disc[pid].add(x)
    newer_than_onchain = []
    for f, pid, d, onchain in sorted(sources):
        if pid not in by_pid:
            continue
        mf, m = by_pid[pid]
        ixs = d.get("instructions") or []
        anchor_like = onchain or any("discriminator" in i for i in ixs) or d.get("metadata", {}).get("spec")
        if f in not_deployed:
            rep.note(S, f"{f}: discriminators not compared (documented as not the deployed ones)")
        idl_discs = {bytes(i["discriminator"]).hex() if "discriminator" in i else anchor_disc(i["name"]) for i in ixs}
        for ix in m["instructions"]:
            # Exact (snake-case) name first: `swap_2` and `swap2` are two
            # names, which a punctuation-blind match would conflate. The slot
            # count keeps the Rust test's punctuation-blind match (its pin).
            on = next((i for i in ixs if snake(i.get("name", "")) == snake(ix["name"])), None)
            loose = next((i for i in ixs if norm(i.get("name", "")) == norm(ix["name"])), None)
            if onchain and loose is not None:
                slots = idl_count(loose.get("accounts"))
                if not any(len(l) == slots for l in layouts(ix)):
                    slot_diff.append((mf, ix["name"], [len(l) for l in layouts(ix)], slots))
            if onchain and on is None and len(ix["discriminator"]) == 16 and ix["discriminator"] not in idl_discs:
                if ix["discriminator"] in every_disc[pid]:
                    newer_than_onchain.append(f"{mf}::{ix['name']} ({ix['discriminator']}) is in a committed IDL file of the program but not in its on-chain IDL account (the account's IDL is older)")
                else:
                    phantom.append(f"{mf}::{ix['name']} ({ix['discriminator']}) is in no committed IDL of its program (on-chain account or file): a newer instruction, or one the program never had")
            if on is None or f in not_deployed:
                continue
            compared += 1
            if "discriminator" in on:
                want = bytes(on["discriminator"]).hex()
            elif anchor_like:
                want = anchor_disc(on["name"])
            else:
                want = None
            if want is not None:
                if ix["discriminator"] == want:
                    disc_ok += 1
                else:
                    disc_bad.append(f"{mf}::{ix['name']} discriminator {ix['discriminator']}, {f} gives {want}")
    for x in disc_bad:
        rep.error(S, x)
    # Round 40: the 23 instructions no committed IDL had are removed
    # (docs/audit-r40/declaration-rewrites.json `removed_instructions`); a new
    # one is an error, not a pin.
    for x in phantom:
        rep.error(S, x)
    for x in newer_than_onchain:
        rep.pin(S, x)
    if len(newer_than_onchain) != PINNED_NEWER_THAN_ONCHAIN_IDL:
        rep.error(S, f"{len(newer_than_onchain)} instructions are in an IDL file but not in their on-chain IDL; pinned {PINNED_NEWER_THAN_ONCHAIN_IDL} (Squads v4's five)")
    per = collections.Counter(x[0] for x in slot_diff)
    for mf, c in sorted(per.items()):
        rep.pin(S, f"slot count differs from the on-chain IDL: {mf}: {c} instruction(s) (K-7)")
    if len(slot_diff) != PINNED_SLOT_COUNT_DIFFERENCES:
        rep.error(S, f"{len(slot_diff)} instructions differ from their on-chain IDL's slot count; pinned {PINNED_SLOT_COUNT_DIFFERENCES} (tests/r30_declared_effects_census.rs)")
    rep.data["idls"] = {"idl_files_with_a_program": len(sources), "instructions_compared": compared,
                        "discriminators_equal": disc_ok, "discriminators_differing": len(disc_bad),
                        "manifest_instructions_in_no_committed_idl": len(phantom),
                        "manifest_instructions_only_in_an_idl_file": len(newer_than_onchain),
                        "slot_count_differences": len(slot_diff), "slot_count_differences_by_manifest": dict(sorted(per.items()))}


# ---------------------------------------------------------------- transactions

def compact_u16(b, i):
    v = s = 0
    for k in range(3):
        if i >= len(b):
            raise ValueError("truncated compact-u16")
        x = b[i]
        i += 1
        v |= (x & 0x7F) << s
        s += 7
        if not x & 0x80:
            return v, i
    raise ValueError("compact-u16 longer than 3 bytes")


def tx_version(raw):
    """'legacy' or the version number as a string, read from the wire bytes.
    A v1 (SIMD-0385) frame leads with its version byte (0x81), before the
    signatures; legacy and v0 lead with the compact-u16 signature count, whose
    first byte is below 0x80 for any count a packet can hold."""
    if raw and raw[0] & 0x80:
        return str(raw[0] & 0x7F)
    n, i = compact_u16(raw, 0)
    i += 64 * n
    if i >= len(raw):
        raise ValueError(f"{n} signatures and no message")
    first = raw[i]
    return str(first & 0x7F) if first & 0x80 else "legacy"


# ---------------------------------------------------------------- corpus

def check_corpus(docs, manifests, rep):
    S = "corpus"
    cdir = "graphite-core/fixtures/corpus/"
    entries = []
    for f in sorted(docs):
        if f.startswith(cdir) and f.count("/") == 3:
            pid = os.path.basename(f)[:-5]
            if not is_pubkey(pid):
                rep.error(S, f"{f}: the file name is not a program id")
            d = docs[f]
            if not isinstance(d, list):
                rep.error(S, f"{f}: not a list of entries")
                continue
            for e in d:
                if e.get("program_id") != pid or (e.get("input") or {}).get("program_id") != pid:
                    rep.error(S, f"{f}: an entry for {e.get('program_id')} in the file of {pid}")
                entries.append(e)
    hashes = collections.Counter(e.get("content_hash") for e in entries)
    for h, c in hashes.items():
        if c > 1:
            rep.error(S, f"content_hash {h} appears {c} times")
        if not re.fullmatch(r"[0-9a-f]{64}", str(h)):
            rep.error(S, f"content_hash {h!r} is not sha256 hex")
    for e in entries:
        if not re.fullmatch(r"[0-9a-f]{64}", str(e.get("integrity_hash"))):
            rep.error(S, f"{e.get('content_hash')}: integrity_hash is not sha256 hex")
        src = str(e.get("source"))
        if src.startswith("real-mainnet-exploit:") and not is_signature(src.split(":", 1)[1]):
            rep.error(S, f"{e.get('content_hash')}: {src} does not name a 64-byte signature")
    meta = docs.get(cdir + "meta/corpus_manifest.json")
    if not isinstance(meta, list):
        rep.error(S, "meta/corpus_manifest.json is missing or not a list")
        meta = []
    mh = collections.Counter(x.get("hash") for x in meta)
    for h, c in mh.items():
        if c > 1:
            rep.error(S, f"meta: hash {h} listed {c} times")
    if set(mh) != set(hashes):
        rep.error(S, f"meta vs corpus: {len(set(mh) - set(hashes))} hashes only in meta, {len(set(hashes) - set(mh))} only in the corpus")
    by_hash = {e.get("content_hash"): e for e in entries}
    for x in meta:
        e = by_hash.get(x.get("hash"))
        if e and x.get("provenance") != e.get("source"):
            rep.error(S, f"meta {x.get('hash')}: provenance {x.get('provenance')!r}, the entry says {e.get('source')!r}")
    rep.data["corpus"] = {"files": len({e.get('program_id') for e in entries}), "entries": len(entries),
                          "splits": dict(collections.Counter(x.get("split") for x in meta)),
                          "classes": dict(collections.Counter(x.get("class") for x in meta).most_common()),
                          "holdout_by_provenance": dict(collections.Counter(
                              str(x.get("provenance")).split(":", 1)[0] for x in meta if x.get("split") == "holdout")),
                          "holdout_expected_approved": sum(1 for x in meta if x.get("split") == "holdout"
                                                           and (by_hash.get(x.get("hash")) or {}).get("expected_approved"))}
    return entries, meta


# ---------------------------------------------------------------- artifacts

# Read by hand from each file's own label (Round 39). `real`: bytes from a
# cluster; `reconstructed`: real bytes re-serialized with one field changed;
# `synthetic`: built by an encoder or the TypeScript side with test keys. The
# phrase is the label's own words the class rests on; a relabelled file fails.
ARTIFACT_PROVENANCE = {
    "alt_privilege.json": ("synthetic", ""),
    "devnet_transactions.json": ("real (devnet, placeholder signatures)", "Real serialized Solana transactions built against devnet"),
    "mainnet_v0_alt.json": ("real mainnet + reconstructed mutations", "Real mainnet-beta v0 transactions"),
    "privilege_artifacts.json": ("synthetic (test keys)", "the keys are test keys"),
    "sak_bridge_artifact.json": ("synthetic (emitted by the agent guard)", "Emitted by integrations/agent-guard/emit-artifact-fixture.ts"),
    "sak_bridge_corpus.json": ("synthetic (emitted; one real lookup table)", "Emitted by integrations/agent-guard/emit-corpus.ts"),
    "undescribed_account.json": ("synthetic (test keys)", "the keys are test keys"),
    "sample-2026-09-23-last-2-blocks.json": ("real mainnet", "Whole finalized mainnet blocks"),
}

def check_artifacts(docs, rep):
    S = "artifacts"
    out = {}
    for f in sorted(docs):
        if not f.startswith(("graphite-core/fixtures/artifacts/", "graphite-core/fixtures/mainnet/")):
            continue
        d = docs[f]
        label = d.get("_") or d.get("_source") or d.get("about") or d.get("source") if isinstance(d, dict) else None
        if not label:
            rep.error(S, f"{f}: says nothing of where it comes from (no '_', '_source', 'about' or 'source')")
        name = os.path.basename(f)
        if name not in ARTIFACT_PROVENANCE:
            rep.error(S, f"{f}: not classified real / reconstructed / synthetic in ARTIFACT_PROVENANCE (read its label and add it)")
            continue
        prov, phrase = ARTIFACT_PROVENANCE[name]
        if phrase and phrase not in str(label):
            rep.error(S, f"{f}: its label no longer says {phrase!r}, on which the {prov!r} classification rests (relabelled?)")
        if not phrase:
            rep.pin(S, f"{f}: {prov}, but its own label does not say so")
        out[name] = prov
    sample = docs.get("graphite-core/fixtures/mainnet/sample-2026-09-23-last-2-blocks.json") or {}
    vers, bad = collections.Counter(), 0
    for r in sample.get("rows") or []:
        try:
            v = tx_version(base64.b64decode(r["b64"]))
        except (ValueError, KeyError) as e:
            rep.error(S, f"mainnet sample: a row's bytes do not parse: {e}")
            continue
        vers[v] += 1
        if v != str(r.get("version")):
            bad += 1
    if bad:
        rep.error(S, f"mainnet sample: {bad} rows whose version label is not what their bytes say")
    if sample and sample.get("count") != len(sample.get("rows") or []):
        rep.error(S, f"mainnet sample: count {sample.get('count')} for {len(sample.get('rows') or [])} rows")
    alt = docs.get("graphite-core/fixtures/artifacts/mainnet_v0_alt.json") or {}
    for t in alt.get("transactions") or []:
        if tx_version(base64.b64decode(t["raw_base64"])) != "0":
            rep.error(S, f"mainnet_v0_alt.json {t.get('name')}: not a v0 transaction")
        if not is_signature(t.get("signature")):
            rep.error(S, f"mainnet_v0_alt.json {t.get('name')}: signature is not 64 bytes of base58")
    sak = docs.get("graphite-core/fixtures/artifacts/sak_bridge_artifact.json") or {}
    if sak:
        raw = base64.b64decode(sak["signed_transaction"]) if isinstance(sak.get("signed_transaction"), str) else bytes(sak.get("signed_transaction") or [])
        if hashlib.sha256(raw).hexdigest() != sak.get("transaction_sha256"):
            rep.error(S, "sak_bridge_artifact.json: transaction_sha256 is not the sha256 of signed_transaction")
    corp = docs.get("graphite-core/fixtures/artifacts/sak_bridge_corpus.json") or {}
    cv = collections.Counter()
    for e in corp.get("entries") or []:
        raw = base64.b64decode(e["raw"]) if isinstance(e.get("raw"), str) else bytes(e.get("raw") or [])
        if hashlib.sha256(raw).hexdigest() != e.get("transaction_sha256"):
            rep.error(S, f"sak_bridge_corpus.json {e.get('name')}: transaction_sha256 does not match its bytes")
        v = tx_version(raw)
        cv[v] += 1
        label = "legacy" if e.get("version") is None else str(e.get("version"))
        if label != v:
            rep.error(S, f"sak_bridge_corpus.json {e.get('name')}: labelled {e.get('version')!r}, the bytes say {v}")
    # The two raw getTransaction answers kept beside the scripts: the
    # signature is the one the file is named after.
    exploits = 0
    for f in sorted(docs):
        mt = re.match(r"graphite-core/scripts/real_exploit_([1-9A-HJ-NP-Za-km-z]+)_[^/]*\.json$", f)
        if not mt:
            continue
        exploits += 1
        sigs = ((docs[f].get("transaction") or {}).get("signatures") or [""])
        if not is_signature(sigs[0]) or not sigs[0].startswith(mt.group(1)):
            rep.error(S, f"{f}: its first signature {sigs[0][:20]!r} is not the one the file is named after")
    rep.data["artifacts"] = {"real_exploit_transactions_beside_the_scripts": exploits,"provenance": out, "mainnet_sample_versions": dict(vers), "sak_bridge_corpus_versions": dict(cv),
                             "mainnet_v0_alt_transactions": len(alt.get("transactions") or [])}


# ---------------------------------------------------------------- rewrites

def idl_leaves(accs):
    """An IDL instruction's accounts, nested groups flattened: (name, writable, signer, optional)."""
    out = []
    for a in accs or []:
        if isinstance(a, dict) and "accounts" in a:
            out += idl_leaves(a["accounts"])
        elif isinstance(a, dict):
            out.append((a.get("name"), bool(a.get("writable", a.get("isMut", False))),
                        bool(a.get("signer", a.get("isSigner", False))),
                        bool(a.get("optional", a.get("isOptional", False)))))
    return out


def declares_nothing(line):
    """The lines DeclaredEffects::parse reads as declaring nothing: the
    generated name list, a bare identifier, an explicit 'no state change'."""
    low = line.lower()
    return low.lstrip().startswith("modifies writable accounts") or not re.search(r"\s", low.strip()) or "no state change" in low


ACCOUNT_REF = re.compile(r"accounts\.([A-Za-z0-9_]+)")
UPSTREAM_ROLES = {"": (False, False), "w": (True, False), "s": (False, True), "ws": (True, True)}


def committed_discriminators(docs):
    """Every 8-byte discriminator a committed IDL gives each program (the
    on-chain IDL accounts and the IDL files naming a program), the Surfpool
    file excepted (its discriminators are not the deployed ones)."""
    out = collections.defaultdict(set)
    for f, d in docs.items():
        pid = None
        if not isinstance(d, dict):
            continue
        if f.startswith("graphite-core/scripts/out/onchain_idls/"):
            pid = os.path.basename(f)[:-5]
        elif re.match(r"graphite-core/scripts/(idls/[^/]+|[^/]+_idl)\.json$", f) and f != "graphite-core/scripts/idls/jupiter_v6_surfpool.json":
            pid = d.get("address") or (d.get("metadata") or {}).get("address")
        if not pid:
            continue
        for i in d.get("instructions") or []:
            out[pid].add(bytes(i["discriminator"]).hex() if "discriminator" in i else anchor_disc(i["name"]))
    return out


def find_ix(manifests, mf, name):
    m = manifests.get(mf)
    return m, next((i for i in (m or {}).get("instructions", []) if i["name"] == name), None)


def check_promotion(S, w, x, ix, docs, rep):
    """Round 40 (F-005): a medium rewrite becomes high only with a recorded
    evidence record the validator re-checks here. The technical lead signs off
    a promotion that carries one (the Round 40 decision); nothing less is
    accepted: an upstream source pinned to a full commit SHA, a URL and a line
    range, whose recorded account list matches every layout of the
    instruction slot for slot (names and roles exactly), or a committed IDL
    the validator compares with the layout itself."""
    p = x.get("promotion")
    if not isinstance(p, dict):
        rep.error(S, f"{w}: was medium (pinned) and is {x.get('confidence')!r} with no promotion record")
        return False
    ok = True

    def bad(msg):
        nonlocal ok
        ok = False
        rep.error(S, f"{w}: promotion: {msg}")

    if (p.get("from"), p.get("to"), p.get("round")) != ("medium", "high", 40):
        bad("from/to/round must be medium/high/40")
    if not str(p.get("signed_off") or "").strip():
        bad("no sign-off recorded")
    ev = p.get("evidence") or {}
    lays = layouts(ix)
    if ev.get("kind") == "committed_idl":
        idl = docs.get(ev.get("file") or "")
        iix = next((i for i in (idl or {}).get("instructions") or [] if i.get("name") == ev.get("instruction")), None)
        if iix is None:
            bad(f"{ev.get('file')} has no instruction {ev.get('instruction')!r}")
            return ok
        leaves = idl_leaves(iix.get("accounts"))
        for li, lay in enumerate(lays):
            if len(lay) != len(leaves):
                bad(f"layout {li} has {len(lay)} slots, the IDL {len(leaves)}")
                continue
            for k, (a, (n, wr, sg, _opt)) in enumerate(zip(lay, leaves)):
                if a.get("name") != n or bool(a.get("is_writable")) != wr or bool(a.get("is_signer")) != sg:
                    bad(f"layout {li} slot {k}: {a.get('name')} w={a.get('is_writable')} s={a.get('is_signer')} vs IDL {n} w={wr} s={sg}")
        flags = {n: (wr, sg) for n, wr, sg, _ in leaves}
        for line in x.get("new_lines") or []:
            for ref in ACCOUNT_REF.findall(line):
                if flags.get(ref) != (True, False):
                    bad(f"accounts.{ref} is not a writable, non-signing account of the IDL instruction")
    elif ev.get("kind") == "upstream_source":
        repo, commit, path, lines = ev.get("repository") or "", ev.get("commit") or "", ev.get("path") or "", ev.get("lines") or []
        if not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
            bad(f"repository {repo!r} is not a public GitHub repository URL")
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            bad(f"commit {commit!r} is not a full 40-hex SHA")
        if not (isinstance(lines, list) and len(lines) == 2 and all(isinstance(v, int) for v in lines) and 0 < lines[0] <= lines[1]):
            bad(f"lines {lines!r} is not [first, last]")
        elif ev.get("url") != f"{repo}/blob/{commit}/{path}#L{lines[0]}-L{lines[1]}":
            bad(f"url {ev.get('url')!r} is not {repo}/blob/{commit}/{path}#L{lines[0]}-L{lines[1]}")
        if not re.fullmatch(r"[0-9a-f]{64}", ev.get("file_sha256") or ""):
            bad("no file_sha256 of the fetched file")
        tag = ev.get("tag")
        if not isinstance(tag, int) or ix.get("discriminator") != format(tag, "02x"):
            bad(f"tag {tag!r} is not the manifest's discriminator {ix.get('discriminator')}")
        accs = ev.get("accounts") or []
        if not accs or any(not (isinstance(a, list) and len(a) == 4 and a[1] in UPSTREAM_ROLES and isinstance(a[2], bool)) for a in accs):
            bad("accounts must be [manifest name, role ''|w|s|ws, optional, the source's text] per slot")
            return ok
        for li, lay in enumerate(lays):
            # A layout is the source's list, or the source's list with its
            # optional slots left out.
            want = accs if len(lay) == len(accs) else [a for a in accs if not a[2]]
            if len(want) != len(lay):
                bad(f"layout {li} has {len(lay)} slots; the source has {len(accs)} ({sum(a[2] for a in accs)} optional)")
                continue
            for k, (a, (n, role, _opt, _doc)) in enumerate(zip(lay, want)):
                wr, sg = UPSTREAM_ROLES[role]
                if a.get("name") != n or bool(a.get("is_writable")) != wr or bool(a.get("is_signer")) != sg:
                    bad(f"layout {li} slot {k}: {a.get('name')} w={a.get('is_writable')} s={a.get('is_signer')} vs source {n} [{role}]")
    else:
        bad(f"evidence kind {ev.get('kind')!r} is neither committed_idl nor upstream_source")
    return ok


def check_rewrites(docs, manifests, rep):
    S = "rewrites"
    r = docs.get("docs/audit-r36/declaration-rewrites.json") or {}
    rows = r.get("rewrites") or []
    conf = collections.Counter(x.get("confidence") for x in rows)
    medium, promoted = [], []
    for x in rows:
        mf = os.path.basename(x.get("manifest", ""))
        m, ix = find_ix(manifests, mf, x.get("instruction"))
        w = f"{mf}::{x.get('instruction')}"
        if ix is None:
            rep.error(S, f"{w}: rewritten instruction not in the manifest")
            continue
        if m["protocol"]["program_id"] != x.get("program_id"):
            rep.error(S, f"{w}: program_id is not the manifest's")
        if list(ix.get("expected_state_changes") or []) != list(x.get("new_lines") or []):
            rep.error(S, f"{w}: the manifest no longer carries the rewrite's new_lines")
        if x.get("confidence") not in ("high", "medium"):
            rep.error(S, f"{w}: confidence {x.get('confidence')!r}")
        was_medium = (mf, x.get("instruction")) in PINNED_MEDIUM_REWRITES
        if x.get("confidence") == "medium":
            medium.append((mf, x.get("instruction")))
            if "promotion" in x:
                rep.error(S, f"{w}: a promotion record on a row that is still medium")
            why = (x.get("promotion_review") or {}).get("reason") or f"IDL: {x.get('idl_source')}"
            rep.pin(S, f"medium confidence (Round 36), not promoted: {mf} {x.get('instruction')} ({str(why)[:110]})")
        elif was_medium:
            if check_promotion(S, w, x, ix, docs, rep):
                promoted.append((mf, x.get("instruction")))
        elif "promotion" in x:
            rep.error(S, f"{w}: a promotion record on a row that was never medium")
    if sorted(medium + promoted) != sorted(PINNED_MEDIUM_REWRITES):
        rep.error(S, f"the Round 36 medium-confidence rows changed: medium {sorted(medium)} + promoted {sorted(promoted)}; pinned {sorted(PINNED_MEDIUM_REWRITES)}")
    if sorted(medium) != sorted(PINNED_STILL_MEDIUM_R36):
        rep.error(S, f"the Round 36 rows still medium are {sorted(medium)}; pinned {sorted(PINNED_STILL_MEDIUM_R36)} (a promotion needs a checked evidence record)")
    data = {"rows": len(rows), "by_confidence": dict(conf), "medium": [f"{a} {b}" for a, b in medium],
            "promoted_round_40": [f"{a} {b}" for a, b in promoted]}

    # Round 40 (R39-CORE-DECISION-4): the swap rewrites, held to the Round 36
    # checks and, further, to the IDL each row cites.
    r40 = docs.get("docs/audit-r40/declaration-rewrites.json")
    if r40 is None:
        rep.error(S, "docs/audit-r40/declaration-rewrites.json is missing")
        rep.data["rewrites"] = data
        return
    rows40 = r40.get("rewrites") or []
    medium40, seen = [], set()
    for x in rows40:
        mf = os.path.basename(x.get("manifest", ""))
        m, ix = find_ix(manifests, mf, x.get("instruction"))
        w = f"{mf}::{x.get('instruction')} (R40)"
        if (mf, x.get("instruction")) in seen:
            rep.error(S, f"{w}: two rows")
        seen.add((mf, x.get("instruction")))
        if ix is None:
            rep.error(S, f"{w}: rewritten instruction not in the manifest")
            continue
        if m["protocol"]["program_id"] != x.get("program_id"):
            rep.error(S, f"{w}: program_id is not the manifest's")
        new, old, added = list(x.get("new_lines") or []), list(x.get("old_lines") or []), list(x.get("added") or [])
        if list(ix.get("expected_state_changes") or []) != new:
            rep.error(S, f"{w}: the manifest no longer carries the rewrite's new_lines")
        kept = [l for l in old if declares_nothing(l)]
        if new != kept + added or list(x.get("removed") or []) != [l for l in old if not declares_nothing(l)]:
            rep.error(S, f"{w}: new_lines are not the old lines that declare nothing plus `added`, or `removed` is not the rest")
        if len(new) < len(old):
            rep.error(S, f"{w}: the declaration got shorter ({len(old)} -> {len(new)} lines; the drainer heuristic counts lines)")
        if (x.get("kind"), x.get("intent")) != ("swap", "swap"):
            rep.error(S, f"{w}: kind/intent {x.get('kind')}/{x.get('intent')}")
        if not any("credit" in l.lower() or "output" in l.lower() for l in new):
            rep.error(S, f"{w}: no line mentions a credit or an output (L7 Check 8, FakeSwap)")
        # L4's no-diff structural check (verification.rs verify_state) runs on
        # the words 'debit'/'credit'; a rewrite must not switch it off.
        value_words = lambda ls: any("debit" in l.lower() or "credit" in l.lower() for l in ls)
        if value_words(old) and not value_words(new):
            rep.error(S, f"{w}: the old declaration said debit/credit and the new one does not (L4's structural check would stop running)")
        if x.get("confidence") not in ("high", "medium"):
            rep.error(S, f"{w}: confidence {x.get('confidence')!r}")
        if x.get("confidence") == "medium":
            medium40.append((mf, x.get("instruction")))
        if not x.get("justification") or not x.get("not_excused"):
            rep.error(S, f"{w}: no justification or not_excused")
        idl_file = str(x.get("idl_source") or "").split(" ")[0]
        idl = docs.get(idl_file)
        iix = next((i for i in (idl or {}).get("instructions") or [] if i.get("name") == x.get("idl_instruction")), None)
        if iix is None:
            rep.error(S, f"{w}: the cited IDL {idl_file!r} has no instruction {x.get('idl_instruction')!r}")
            continue
        leaves = idl_leaves(iix.get("accounts"))
        lnorm = {norm(n or ""): (wr, sg) for n, wr, sg, _ in leaves}
        for li, lay in enumerate(layouts(ix)):
            for k, a in enumerate(lay):
                if k >= len(leaves) or norm(a.get("name") or "") != norm(leaves[k][0] or ""):
                    rep.error(S, f"{w}: layout {li} slot {k} {a.get('name')!r} is not the IDL's {(leaves[k][0] if k < len(leaves) else None)!r}")
                    break
        for line in added:
            refs = ACCOUNT_REF.findall(line)
            if not refs:
                rep.error(S, f"{w}: an added line names no account: {line!r}")
            for ref in refs:
                for li, lay in enumerate(layouts(ix)):
                    if ref not in [a.get("name") for a in lay]:
                        rep.error(S, f"{w}: accounts.{ref} is not in layout {li}")
                if lnorm.get(norm(ref)) != (True, False):
                    rep.error(S, f"{w}: accounts.{ref} is not a writable, non-signing account of {idl_file}::{x.get('idl_instruction')}")
    if sorted(medium40) != sorted(PINNED_MEDIUM_REWRITES_R40):
        rep.error(S, f"the Round 40 medium-confidence rewrites changed: {sorted(medium40)}; pinned {sorted(PINNED_MEDIUM_REWRITES_R40)}")
    for mf, ixn in medium40:
        rep.pin(S, f"medium confidence (Round 40): {mf} {ixn}")
    for key, why in (r40.get("left_unchanged") or {}).items():
        mf, _, ixn = key.partition("::")
        m, ix = find_ix(manifests, mf, ixn)
        if ix is None:
            rep.error(S, f"{key}: listed as left unchanged and not in the manifest")
        elif list(ix.get("expected_state_changes") or []) != list((why or {}).get("lines") or []):
            rep.error(S, f"{key}: listed as left unchanged, but its declaration changed")
    discs = committed_discriminators(docs)
    for x in r40.get("removed_instructions") or []:
        mf = os.path.basename(x.get("manifest", ""))
        m = manifests.get(mf) or {}
        if any(i["name"] == x.get("instruction") or i["discriminator"] == x.get("discriminator") for i in m.get("instructions", [])):
            rep.error(S, f"{mf}::{x.get('instruction')}: listed as removed and still in the manifest")
        pid = (m.get("protocol") or {}).get("program_id")
        if x.get("discriminator") in discs.get(pid, set()):
            rep.error(S, f"{mf}::{x.get('instruction')}: removed, but a committed IDL of the program has its discriminator {x.get('discriminator')}")
    data["round_40"] = {"rows": len(rows40), "by_confidence": dict(collections.Counter(x.get("confidence") for x in rows40)),
                        "left_unchanged": len(r40.get("left_unchanged") or {}),
                        "removed_instructions": len(r40.get("removed_instructions") or [])}
    rep.data["rewrites"] = data


# ---------------------------------------------------------------- schemas

def check_schemas(root, docs, rep):
    S = "schemas"
    try:
        import jsonschema  # noqa: F401
        from jsonschema import Draft202012Validator
    except ImportError:
        rep.blocked.append(f"[{S}] BLOCKED: the jsonschema package is not installed (pip install jsonschema); schemas were not validated")
        return
    pairs = {
        "schemas/proposed-intent-v1.json": ["examples/sample-proposed-intent.json"],
        "schemas/verification-result-v1.json": ["examples/sample-verification-result.json",
                                                "examples/decisions/analysis_only.json",
                                                "examples/decisions/blocked.json",
                                                "examples/decisions/executable_approved.json",
                                                "examples/decisions/inconclusive.json"],
    }
    n = 0
    for sch, examples in pairs.items():
        s = docs.get(sch)
        if s is None:
            rep.error(S, f"{sch} is missing")
            continue
        try:
            Draft202012Validator.check_schema(s)
        except jsonschema.exceptions.SchemaError as e:
            rep.error(S, f"{sch}: not a valid 2020-12 schema: {e.message}")
            continue
        v = Draft202012Validator(s)
        for ex in examples:
            errs = sorted(v.iter_errors(docs.get(ex)), key=lambda e: list(e.path))
            n += 1
            for e in errs[:5]:
                rep.error(S, f"{ex} against {sch}: {'/'.join(map(str, e.path))}: {e.message[:200]}")
    rep.data["schemas"] = {"examples_validated": n}


# ---------------------------------------------------------------- coverage

T22_EXTENSION_WORDS = ("TransferFee", "ConfidentialTransfer", "TransferHook", "MetadataPointer", "GroupPointer",
                       "InterestBearing", "DefaultAccountState", "MemoTransfer", "CpiGuard", "PermanentDelegate",
                       "NonTransferable", "Reallocate", "ImmutableOwner", "MintCloseAuthority", "TokenMetadata",
                       "TokenGroup", "ScaledUiAmount", "Pausable", "WithdrawExcess")


def coverage(docs, manifests, entries, meta, rep):
    by_pid = {m["protocol"]["program_id"]: m for m in manifests.values()}
    cls = collections.Counter()
    prov = collections.Counter()
    cpi = collections.Counter()
    ver = collections.Counter()
    t22 = collections.Counter()
    unknown = 0
    per_protocol = collections.Counter()
    meta_by = {x.get("hash"): x for x in meta}
    for e in entries:
        i = e.get("input") or {}
        m = by_pid.get(e.get("program_id"))
        prov[str(e.get("source")).split(":", 1)[0]] += 1
        ver["v0" if i.get("uses_versioned_transaction") else "legacy"] += 1
        if i.get("signed_transaction"):
            ver["with_signed_bytes"] += 1
        hops = i.get("cpi_hops") or 0
        cpi["cpi_trace" if i.get("cpi_trace") else ("cpi_targets" if i.get("cpi_targets") else "none")] += 1
        if hops > 1:
            cpi["cpi_hops>1"] += 1
        if m is None:
            unknown += 1
            cls["(unmanifested program)"] += 1
            continue
        per_protocol[m["protocol"]["name"]] += 1
        disc = (i.get("instruction_discriminator") or "").lower()
        ix = next((x for x in m["instructions"] if x["discriminator"] and disc.startswith(x["discriminator"])), None)
        cls[(ix or {}).get("risk_class") or ("(no class)" if ix else "(unknown discriminator)")] += 1
        if e.get("program_id") == TOKEN_2022 and ix:
            word = next((w for w in T22_EXTENSION_WORDS if w.lower() in ix["name"].lower()), None)
            t22[word or "base instruction"] += 1
    attack_classes = collections.Counter(meta_by[e["content_hash"]].get("class") for e in entries
                                         if e.get("content_hash") in meta_by and not e.get("expected_approved"))
    benign = sum(1 for e in entries if e.get("expected_approved"))
    sample = docs.get("graphite-core/fixtures/mainnet/sample-2026-09-23-last-2-blocks.json") or {}
    rep.data["coverage"] = {
        "regression_corpus": {
            "entries": len(entries),
            "transaction_version": dict(ver),
            "provenance": dict(prov),
            "protocols_with_entries": len(per_protocol),
            "manifests_without_entries": sorted(m["protocol"]["name"] for m in manifests.values() if m["protocol"]["name"] not in per_protocol),
            "instruction_class": dict(cls.most_common()),
            "expected_approved (benign flows)": benign,
            "expected_refused_by_meta_class": dict(attack_classes.most_common()),
            "cpi_shape": dict(cpi),
            "token_2022": dict(t22),
            "unmanifested_program_entries": unknown,
        },
        "mainnet_sample_rows": sample.get("count"),
        "note": "Volume is not coverage: every corpus entry is a description without wire bytes, "
                "all of them legacy; v0/v1 wire forms are covered only by fixtures/artifacts and the "
                "mainnet sample, which carry no expected verdict.",
    }


# ---------------------------------------------------------------- main

SECTIONS = ("manifests", "evidence", "idls", "corpus", "artifacts", "rewrites", "schemas", "coverage")


def run(root, skip=()):
    rep = Report()
    docs = parse_all(root, rep)
    manifests = check_manifests(root, docs, rep) if "manifests" not in skip else {}
    if "evidence" not in skip:
        check_evidence(docs, manifests, rep)
    if "idls" not in skip:
        check_idls(docs, manifests, rep)
    entries, meta = check_corpus(docs, manifests, rep) if "corpus" not in skip else ([], [])
    if "artifacts" not in skip:
        check_artifacts(docs, rep)
    if "rewrites" not in skip:
        check_rewrites(docs, manifests, rep)
    if "schemas" not in skip:
        check_schemas(root, docs, rep)
    if "coverage" not in skip:
        coverage(docs, manifests, entries, meta, rep)
    for s in skip:
        rep.note("main", f"section {s} skipped on request (--skip): not validated by this run")
    return rep


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=DEFAULT_ROOT)
    ap.add_argument("--json", help="write the measurements and every finding here")
    ap.add_argument("--skip", action="append", default=[], choices=SECTIONS)
    ap.add_argument("--quiet", action="store_true", help="print the summary, not the pinned gaps")
    a = ap.parse_args(argv)
    rep = run(os.path.abspath(a.root), tuple(a.skip))
    if a.json:
        with open(a.json, "w") as fh:
            json.dump({"measurements": rep.data, "errors": rep.errors, "pinned": rep.pinned,
                       "notes": rep.info, "blocked": rep.blocked}, fh, indent=1, sort_keys=False)
            fh.write("\n")
    for k, v in rep.data.items():
        if k != "coverage":
            print(f"{k}: {json.dumps(v, sort_keys=False)}")
    if not a.quiet:
        for p in rep.pinned:
            print(f"pinned: {p}")
    for n in rep.info:
        print(f"note: {n}")
    for b in rep.blocked:
        print(b)
    for e in rep.errors:
        print(f"ERROR: {e}")
    if rep.errors:
        print(f"validate_corpora: {len(rep.errors)} error(s)")
        return 1
    if rep.blocked:
        print(f"validate_corpora: no error, but {len(rep.blocked)} section(s) BLOCKED (not a pass)")
        return 3
    print(f"validate_corpora: every section ran, no error ({len(rep.pinned)} pinned known gaps)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
