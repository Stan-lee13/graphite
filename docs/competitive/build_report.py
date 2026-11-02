"""Builds docs/competitive/graphite-competitive-comparison-2026-11.pdf.

Run: python3 docs/competitive/build_report.py
Every competitor claim is from the public sources listed in the report's
Sources section, as of 2026-11-02. Scores are the author's judgment.
"""

from pathlib import Path

from reportlab.graphics.shapes import Drawing, Line, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

OUT = Path(__file__).with_name("graphite-competitive-comparison-2026-11.pdf")

INK = colors.HexColor("#1d2330")
MUTED = colors.HexColor("#5b6475")
ACCENT = colors.HexColor("#2f5d9e")
RULE = colors.HexColor("#d5dae3")
SOFT = colors.HexColor("#f2f4f8")
GOOD = colors.HexColor("#2e7d4f")
WARN = colors.HexColor("#a05a00")

ss = getSampleStyleSheet()
H1 = ParagraphStyle("H1", parent=ss["Heading1"], fontName="Helvetica-Bold", fontSize=20, leading=24, textColor=INK, spaceAfter=6)
H2 = ParagraphStyle("H2", parent=ss["Heading2"], fontName="Helvetica-Bold", fontSize=14, leading=18, textColor=ACCENT, spaceBefore=10, spaceAfter=6)
H3 = ParagraphStyle("H3", parent=ss["Heading3"], fontName="Helvetica-Bold", fontSize=11.5, leading=14, textColor=INK, spaceBefore=8, spaceAfter=3)
BODY = ParagraphStyle("Body", parent=ss["BodyText"], fontName="Helvetica", fontSize=9.6, leading=13.4, textColor=INK, alignment=TA_LEFT, spaceAfter=5)
SMALL = ParagraphStyle("Small", parent=BODY, fontSize=8.2, leading=10.8, textColor=MUTED)
CELL = ParagraphStyle("Cell", parent=BODY, fontSize=8.4, leading=10.8, spaceAfter=0)
CELLB = ParagraphStyle("CellB", parent=CELL, fontName="Helvetica-Bold")
BUL = ParagraphStyle("Bul", parent=BODY, leftIndent=12, bulletIndent=2, spaceAfter=2)


def p(text, style=BODY):
    return Paragraph(text, style)


def bullets(items, style=BUL):
    return [Paragraph(t, style, bulletText="•") for t in items]


def table(rows, widths, header=True, zebra=True):
    data = [[c if not isinstance(c, str) else Paragraph(c, CELLB if (header and i == 0) else CELL) for c in r] for i, r in enumerate(rows)]
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), SOFT), ("LINEBELOW", (0, 0), (-1, 0), 0.8, ACCENT)]
    if zebra:
        for i in range(2 if header else 1, len(rows), 2):
            style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#fafbfd")))
    t.setStyle(TableStyle(style))
    return t


# ---------------------------------------------------------------- scoring
CRITERIA = [
    ("Production maturity and track record", 0.25),
    ("Depth of semantic verification", 0.20),
    ("Solana depth", 0.15),
    ("Fit for AI agents", 0.15),
    ("Independent assurance and trust", 0.10),
    ("Breadth (chains, threat intelligence)", 0.10),
    ("Openness, self-hosting and cost", 0.05),
]

SCORES = {
    "Blockaid": [10, 7, 8, 7, 9, 10, 3],
    "Fireblocks": [10, 5, 7, 7, 10, 9, 2],
    "Turnkey": [8, 4, 8, 8, 8, 6, 5],
    "Hypernative": [8, 7, 6, 4, 8, 9, 2],
    "Coinbase CDP": [9, 3, 6, 8, 9, 6, 3],
    "Graphite": [2, 9, 9, 8, 3, 2, 10],
}


def weighted(name):
    return sum(s * w for s, (_, w) in zip(SCORES[name], CRITERIA))


RANKED = sorted(SCORES, key=weighted, reverse=True)


def bar_chart():
    w, h = 170 * mm, 62 * mm
    d = Drawing(w, h)
    left, top, row_h, bar_h = 32 * mm, h - 6 * mm, 9 * mm, 5.5 * mm
    scale = (w - left - 18 * mm) / 10.0
    for x in range(0, 11, 2):
        xx = left + x * scale
        d.add(Line(xx, 4 * mm, xx, top + 2, strokeColor=RULE, strokeWidth=0.4))
        d.add(String(xx, 0.5 * mm, str(x), fontName="Helvetica", fontSize=7, fillColor=MUTED, textAnchor="middle"))
    for i, name in enumerate(RANKED):
        y = top - (i + 1) * row_h + 2
        v = weighted(name)
        fill = ACCENT if name != "Graphite" else WARN
        d.add(String(left - 3 * mm, y + 1.5, f"{i + 1}. {name}", fontName="Helvetica-Bold" if name == "Graphite" else "Helvetica", fontSize=8.5, fillColor=INK, textAnchor="end"))
        d.add(Rect(left, y, v * scale, bar_h, fillColor=fill, strokeColor=None))
        d.add(String(left + v * scale + 2 * mm, y + 1.5, f"{v:.2f}", fontName="Helvetica", fontSize=8, fillColor=INK))
    return d


# ---------------------------------------------------------------- page chrome
def on_page(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, 10 * mm, "Graphite competitive comparison  |  2 November 2026  |  public sources; scores are judgment, not measurement")
    canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.setStrokeColor(RULE)
    canvas.line(18 * mm, 13 * mm, A4[0] - 18 * mm, 13 * mm)
    canvas.restoreState()


story = []

# ---------------------------------------------------------------- cover / summary
story += [
    p("Graphite and the Five Leaders in Transaction Security", H1),
    p("How Graphite compares with Blockaid, Fireblocks, Turnkey, Hypernative and Coinbase Developer Platform, and where each one ranks", SMALL),
    Spacer(1, 6),
    p("Prepared 2 November 2026 from public sources and from Graphite's own repository (main at 9e60f59). "
      "Competitor internals are not public, so every competitor claim below is what the company or the press has published. "
      "The scores are a reasoned judgment, not a measurement, and no competitor product was tested for this report.", SMALL),
    Spacer(1, 8),
    p("The short answer", H2),
    p("Graphite tries to answer a narrower and harder question than most of the field: <b>does this exact Solana transaction do what the AI agent said it would do, and nothing else?</b> "
      "The five companies here are the strongest players around that question. "
      "Blockaid and Hypernative detect malicious transactions. Fireblocks, Turnkey and Coinbase gate what a key is allowed to sign. "
      "All five are in production at scale. Graphite is not yet."),
    p("<b>Overall ranking today</b>, weighted toward what a team should trust with real money now:"),
]
rank_rows = [["#", "Company", "Score /10", "One-line reason"]]
reasons = {
    "Blockaid": "Market leader in pre-signing transaction scanning, with Solana coverage and agent tooling. Its verdict is benign/malicious, not \"does what you asked\".",
    "Fireblocks": "The institutional standard for custody and policy, with new agentic-payments products. Its policies gate amounts and destinations, not instruction meaning.",
    "Turnkey": "Best signing primitive for agent wallets on Solana: enclave keys plus a policy engine that reads programs and accounts. No simulation of outcomes.",
    "Hypernative": "Strong real-time threat detection and pre-approval simulation for protocols and treasuries. Built for teams, not for AI agents.",
    "Coinbase CDP": "Agentic wallets with enclave keys and spend policies, backed by Coinbase. Solana policies are thin, and there is no semantic check.",
    "Graphite": "Deepest semantic, deterministic verification of Solana agent intent in this group. Unaudited, undeployed and with no users yet.",
}
for i, name in enumerate(RANKED, 1):
    rank_rows.append([str(i), f"<b>{name}</b>", f"{weighted(name):.2f}", reasons[name]])
story.append(table(rank_rows, [8 * mm, 28 * mm, 18 * mm, 120 * mm]))
story += [
    Spacer(1, 6),
    bar_chart(),
    Spacer(1, 4),
    p("<b>The ranking flips on technical depth alone.</b> On depth of semantic verification for Solana agent intent, Graphite ranks first, "
      "Blockaid and Hypernative tie for second, then Fireblocks, Turnkey and Coinbase. Graphite places last overall because maturity, "
      "independent assurance and track record carry 35% of the weight, and Graphite scores only 2 or 3 out of 10 on them today. "
      "That is the honest position: the strongest design in the group, and the least proven product."),
    PageBreak(),
]

# ---------------------------------------------------------------- method
story += [
    p("How the comparison was made", H2),
    p("Each company is scored from 1 to 10 on seven criteria. The weights favour what matters when real funds are at stake: "
      "a product that works in production beats a better design that has not shipped."),
]
crit_rows = [["Criterion", "Weight", "What earns a high score"]]
crit_text = [
    "Years in production, named customers, volume protected, a record without public failures.",
    "Whether the product understands what a transaction does (state changes, instruction meaning) and checks it against what was intended, rather than only flagging known-bad patterns or capping amounts.",
    "Native handling of Solana: versioned transactions, lookup tables, CPI, SPL and Token-2022, program upgrades.",
    "Ready-made pieces for AI agents (SDKs, MCP servers, framework adapters), and a decision an agent cannot talk its way past.",
    "Independent audits, certifications (SOC 2, ISO), funding and the reputation of the people behind it.",
    "Chains covered, threat-intelligence network, monitoring beyond the single transaction.",
    "Open source, self-hostable, free or cheap to start, no vendor lock-in.",
]
for (name, w), t in zip(CRITERIA, crit_text):
    crit_rows.append([name, f"{int(w * 100)}%", t])
story.append(table(crit_rows, [52 * mm, 16 * mm, 106 * mm]))
story += [Spacer(1, 8), p("Score matrix", H3)]
mat = [["Criterion"] + RANKED]
for ci, (name, _) in enumerate(CRITERIA):
    mat.append([name] + [str(SCORES[n][ci]) for n in RANKED])
mat.append(["<b>Weighted score</b>"] + [f"<b>{weighted(n):.2f}</b>" for n in RANKED])
story.append(table(mat, [50 * mm] + [20.6 * mm] * 6))
story += [
    Spacer(1, 6),
    p("Why these five. The brief was the best companies that do, or try to do, what Graphite does. Graphite sits at the point where an agent's "
      "intent meets a signature, so the field splits in two. <b>Transaction-security vendors</b> read a transaction before it is signed: Blockaid and Hypernative. "
      "<b>Signing-policy platforms</b> decide what a key may sign: Fireblocks, Turnkey and Coinbase Developer Platform. "
      "Each of the five is the leader, or close to it, in its lane, and each now sells to AI-agent builders.", BODY),
    p("Also considered and left out: <b>Blowfish</b>, the Solana-native leader in transaction previews, was acquired by Phantom in November 2024 and its "
      "public service was sunset, so it now protects Phantom users only. <b>GoPlus</b> launched AgentGuard for AI agents in February 2026, "
      "but its roadmap still lists full on-chain transaction protection as undelivered.", SMALL),
    PageBreak(),
]

# ---------------------------------------------------------------- feature grid
story += [p("Side by side", H2)]
grid = [
    ["Capability", "Graphite", "Blockaid", "Fireblocks", "Turnkey", "Hypernative", "Coinbase CDP"],
    ["Checks the transaction against the stated intent (amount, recipient, asset)", "Yes, core design", "No (risk verdict)", "Partly (policy rules)", "Partly (policy rules)", "Partly (custom policies)", "Partly (spend caps)"],
    ["Simulates the transaction and diffs account state", "Yes, every account it writes", "Yes", "Policy simulation; tx simulation not documented for Solana", "No", "Yes (Guardian)", "Not documented"],
    ["Binds the verdict to the exact bytes signed", "Yes (SHA-256 and message equality)", "Per request", "Inside its own signer", "Inside its own enclave", "Per request", "Inside its own enclave"],
    ["Deterministic, explainable decision (no ML in the path)", "Yes, by constitution", "No, ML plus intel", "Rules: yes; APA is AI-assisted", "Yes (rules)", "Mixed", "Yes (rules)"],
    ["Threat intelligence (known scams, drainers, phishing)", "No", "Large network", "Via partners", "No", "Large", "KYT screening"],
    ["Holds keys and signs", "No (verifier only)", "No", "Yes (MPC custody)", "Yes (enclaves)", "No", "Yes (MPC + enclave)"],
    ["Chains", "Solana only", "Many, incl. Solana", "Many, incl. Solana", "Many, incl. Solana", "60-70+, incl. Solana", "EVM and Solana"],
    ["AI-agent tooling", "Agent guard, SolanaAgentKit, Vercel AI SDK, MCP", "LangChain tool, MCP server", "Agentic Payments Suite (2026)", "Agentic wallets docs", "None agent-specific found", "AgentKit, Agentic Wallets (2026)"],
    ["Independent audit or certification", "None yet", "Enterprise customers; not public", "SOC 2, ISO (well known)", "Not covered in sources reviewed", "Enterprise customers", "Coinbase controls"],
    ["Open source / self-host", "MIT, self-hosted", "No (API)", "No", "Partly (open parsers)", "No", "No (SDKs open)"],
    ["In production", "No", "Yes", "Yes", "Yes", "Yes", "Yes"],
]
story.append(table(grid, [37 * mm, 25 * mm, 22 * mm, 23 * mm, 22 * mm, 22 * mm, 23 * mm]))
story += [
    Spacer(1, 4),
    p("\"Not documented\" means the public sources reviewed did not describe it. It does not mean the capability is absent.", SMALL),
    PageBreak(),
]

# ---------------------------------------------------------------- profiles
def profile(rank, name, what, strengths, weaknesses, verdict, key=None):
    block = [
        p(f"{rank}. {name}  <font size=9 color='#5b6475'>weighted score {weighted(key or name):.2f}</font>", H2),
        p(what),
        p("Strengths", H3),
        *bullets(strengths),
        p("Weaknesses", H3),
        *bullets(weaknesses),
        p(f"<b>Why it ranks #{rank}.</b> {verdict}"),
    ]
    return block


story += profile(
    1, "Blockaid",
    "Tel Aviv-based Web3 security company founded by former Israeli military-intelligence engineers. It scans transactions, dApps, tokens and addresses "
    "before a user signs, and says whether a transaction is benign, a warning or malicious. It has raised $83M ($33M in 2023, led by Ribbit and Variant "
    "with Sequoia and Greylock; $50M Series B in February 2025). Reported customers include MetaMask, Coinbase, Uniswap, OpenSea, Rainbow and Zerion. "
    "It covers Solana: Backpack is listed as an integration and Portal's SDK exposes a Solana scan.",
    [
        "The widest production footprint in the group. Its checks run inside wallets such as MetaMask and Coinbase's, so it protects a very large user base.",
        "Simulation plus a large threat-intelligence network, so it catches drainers and phishing that a pure correctness check would miss.",
        "Multi-chain, including Solana, with one API for wallets, dApps and exchanges.",
        "Already sells to agent builders: a pre-built LangChain tool and an MCP server give agents its simulation and threat data.",
        "Well funded, with top-tier investors and an experienced security team.",
    ],
    [
        "Its question is \"is this malicious?\", not \"does this do what the agent was asked to do?\". A clean-looking transaction that sends the wrong amount, "
        "to the wrong recipient or in the wrong asset is not what it is built to stop.",
        "The decision relies on ML and intelligence, so it is probabilistic and not fully explainable or reproducible offline.",
        "Closed SaaS: every check is an API call to a vendor, which brings cost, latency and dependency, and it cannot be self-hosted or audited by the user.",
        "Its \"Error\" result has to be handled by the integrator. Portal's docs warn that it must not be treated as safe, which leaves room for fail-open mistakes.",
    ],
    "It is the most proven product for the closest job to Graphite's, and it already covers Solana and agents. It wins on maturity, breadth and trust. It is "
    "not the deepest on intent, but nobody else in the group combines production scale with real transaction understanding.",
)
story += profile(
    2, "Fireblocks",
    "The leading institutional platform for digital-asset custody, settlement and transaction policy, used by banks, exchanges and fintechs. "
    "Its Transaction Authorization Policy decides which transactions may be signed, by whom and under what limits; Policy Inspector simulates how a "
    "policy will judge a transaction. In 2026 it launched an Agentic Payments Suite (May) for agent-initiated stablecoin payments and, reportedly, an "
    "Agentic Policy Analyzer (June) that uses AI to find holes in customers' policies.",
    [
        "The most trusted name for institutional funds, with mature MPC custody, governance and compliance (SOC 2 and ISO are widely known).",
        "A rich policy engine: amounts, destinations, assets, initiators, approval quorums, plus tools to test policies before they go live.",
        "Moving early on agents with a dedicated agentic-payments product and x402 participation.",
        "Many chains, including Solana, and deep integrations with exchanges and banks.",
    ],
    [
        "Its policies are about who, how much and where to, not what each Solana instruction actually does. A transaction can pass every rule and still do "
        "something the agent was not asked to do.",
        "Enterprise pricing, sales cycles and onboarding put it out of reach for most independent agent builders.",
        "Closed and custodial: the user is bound to Fireblocks' signer to get its protection.",
        "The AI policy analyzer is new and documented mainly through press coverage.",
    ],
    "If the question is \"who should hold an institution's keys and enforce its rules\", Fireblocks is first. It ranks second here because its checks are "
    "rule-based rather than semantic, but its maturity and trust are unmatched.",
)
story += profile(
    3, "Turnkey",
    "Key-management and wallet infrastructure built on secure enclaves. Every signing request is "
    "evaluated by Turnkey's policy engine inside the enclave before a signature exists. Its Solana policy engine parses transactions to read the accounts "
    "and programs they touch, and its docs describe \"agentic wallets\" with consensus policies, such as an agent plus a risk service both approving large trades.",
    [
        "The cleanest signing primitive for AI agents: keys never leave the enclave, and policy is enforced where the signature is made.",
        "Real Solana parsing in policy (programs invoked, accounts named, native transfers), with DENY overriding ALLOW.",
        "Fast and developer-friendly, with agent builders such as Spectral Labs named as users.",
        "Some parsers are open source, which helps reviewers.",
    ],
    [
        "No simulation and no state diff: it judges what the transaction says, not what it will do. A program can move funds through a CPI that a "
        "metadata policy never sees.",
        "No intent binding and no threat intelligence. It has to be paired with a verifier to know whether a transaction is what the agent was asked for.",
        "The raw-payload signing path skips parsing entirely, so a misconfigured integration signs blind.",
    ],
    "It is the best foundation for an agent wallet on Solana, which is why it beats Hypernative and Coinbase on agent fit and Solana depth. It sits "
    "below Blockaid and Fireblocks because it checks the transaction's description, not its effects.",
)
story += profile(
    4, "Hypernative",
    "Real-time on-chain threat detection and prevention for protocols, DAOs, funds and exchanges, across 60-70+ chains including Solana (a Solana "
    "ecosystem partnership dates from September 2024). Its Guardian product simulates each transaction before approval and enforces custom policies, "
    "for example in front of a multisig. It raised a $16M Series A and a $40M Series B (June 2025); Ethena is a public customer.",
    [
        "Excellent detection of live attacks, exploits and anomalies, with automated response, beyond the single transaction.",
        "Guardian's pre-approval simulation addresses blind signing for treasuries and multisigs.",
        "Broad chain coverage and strong enterprise references.",
    ],
    [
        "Built for security teams protecting protocols and treasuries, not for AI agents. No agent-specific tooling was found.",
        "Solana-specific Guardian behaviour is thinly documented. Solana's fast finality makes intercept-and-block harder than on EVM.",
        "Closed, enterprise-priced and not self-hostable.",
        "Like Blockaid, it asks \"is this dangerous?\" rather than \"is this what was intended?\".",
    ],
    "It has real depth and maturity, but its product points at a different buyer. For the job Graphite targets, an agent's own transactions on Solana, "
    "it is a weaker fit than the three ranked above.",
)
story += profile(
    5, "Coinbase Developer Platform (AgentKit and Agentic Wallets)",
    "Coinbase's developer platform gives agents wallets whose keys are split with MPC and held in AWS Nitro enclaves. A policy engine checks each signing "
    "request before it is signed. Server Wallets reached general availability in July 2025 with EVM and Solana support. Agentic Wallets launched in "
    "February 2026, according to third-party coverage, with per-token allowances, session caps, allowlists and KYT screening of destinations.",
    [
        "Backed by Coinbase's security organisation, compliance and brand, and very easy for agent builders to adopt through AgentKit.",
        "Hard spending limits and allowlists, enforced at the signer, are an effective blast-radius control for agents.",
        "Fast Solana signing at scale.",
    ],
    [
        "The weakest semantic depth in the group. Its richer data policies are EVM-specific, and contract-level restrictions were still \"coming soon\" on Coinbase's own page.",
        "No documented simulation or state diff for Solana, so it cannot tell whether a permitted transaction does what was asked.",
        "Ties the builder to Coinbase's custody and platform.",
    ],
    "Excellent guard rails, but guard rails are not verification. It ranks above Graphite only because it is in production and trusted today.",
    key="Coinbase CDP",
)
story += profile(
    6, "Graphite",
    "An open-source (MIT) Rust verification gate between an AI agent and its Solana key. The agent states its intent (\"swap 1 SOL for USDC\"). "
    "Graphite parses the exact transaction bytes, simulates them, diffs every account they write, checks the result against the stated amount, recipient "
    "and asset, and returns a decision; only <i>executable_approved</i> may be signed, and the verdict is bound to the bytes by hash. "
    "No AI model is in the decision path. It ships an agent guard, adapters for SolanaAgentKit and the Vercel AI SDK, an MCP server, and TypeScript and Go SDKs. "
    "Version 0.3.0-beta is unreleased.",
    [
        "The deepest intent check in the group: the only product here built to prove that an agent's transaction does what was asked and nothing else, "
        "including value skimmed by a sibling instruction, an authority hand-over, or an overfunded account creation.",
        "Deterministic and explainable: the same input gives the same verdict on any machine, every refusal has a reason, and anything it cannot observe is refused rather than assumed.",
        "Solana-native depth: versioned transactions, lookup tables, CPI rebuilt from Agave's parsed inner instructions, Token-2022, upgrade-aware evidence; "
        "its parser is checked against the Solana runtime's decoder on about 628,500 frames per CI seed. It has 137 protocol manifests.",
        "Measured on mainnet: 147 of 148 honest transfers and 12 of 13 honest swaps approved in live runs (never signed), and tens of thousands of real transactions replayed with zero parse failures.",
        "Open, self-hosted and free. It does not hold keys, so it can sit in front of Turnkey, Coinbase or any wallet.",
    ],
    [
        "Not independently audited. All assurance so far is internal engineering work plus external reviews answered item by item. "
        "Its own internal audits keep finding serious issues: a high-severity finding was fixed in November 2026.",
        "Not deployed and no users. There is no hosted service, no customers and no production track record. Release is blocked on the audit, a hosted "
        "deployment and owner actions.",
        "Solana only, with no threat intelligence, so it will not flag a known scam address if the transaction does exactly what was asked.",
        "Conservative by design: a fresh instance approves nothing until evidence is imported, and new transaction shapes can be refused falsely "
        "(1 of 148 transfers in the latest live run). Coverage depends on its manifests.",
        "A small team against companies with $50M+ rounds and dedicated security organisations.",
    ],
    "On design and depth for Solana AI agents it is first. On everything that earns trust with real money (audit, deployment, users, track record) it is "
    "last, and those criteria carry most of the weight. It is a strong candidate, not yet a proven product.",
)
story.append(PageBreak())

# ---------------------------------------------------------------- what moves graphite
story += [
    p("What would move Graphite up", H2),
    p("The gap is not the engine. Each step below raises a heavily weighted score and none of them needs a redesign."),
]
moves = [
    ["Step", "Criterion it raises", "Effect on the ranking"],
    ["Independent security audit by a recognised Solana auditor, published", "Independent assurance (3 to 8)", "+0.50 (to 6.35)"],
    ["Hosted deployment with its own RPC and monitored uptime (release gate G-5)", "Production maturity (2 to 5)", "+0.75 (with the audit: 7.10, ahead of Turnkey, Hypernative and Coinbase)"],
    ["Two or three design partners running agents through it on mainnet, with published numbers", "Maturity and track record (5 to 7)", "+0.50 (all three: 7.60, level with Fireblocks)"],
    ["Optional threat-intelligence feed (for example, an address-risk lookup) beside the deterministic core", "Breadth (2 to 5)", "+0.3"],
    ["Pair with a signer (Turnkey or Coinbase): \"policy at the key, verification before it\"", "Fit and adoption", "Turns two competitors into channels"],
]
story.append(table(moves, [72 * mm, 48 * mm, 54 * mm]))
story += [
    Spacer(1, 6),
    p("With an audit, a hosted deployment and a few real users, Graphite's weighted score would rise from about 5.9 to about 7.6. That would put it level with "
      "Fireblocks and ahead of Turnkey, Hypernative and Coinbase for Solana agents, while keeping the one thing none of them offers: a deterministic proof that "
      "the transaction is the one the agent was asked to build."),
    p("Positioning", H3),
    p("Graphite is complementary to most of this field, not a replacement. Turnkey, Coinbase and Fireblocks decide what a key may sign. Blockaid and "
      "Hypernative flag what is known to be dangerous. Graphite answers the question in between: <i>is this the transaction that was asked for?</i> "
      "The strongest story for Graphite is as the verification layer an agent wallet calls before its own policy engine signs."),
    Spacer(1, 10),
    p("Limits of this report", H3),
    *bullets([
        "No competitor product was tested. Claims come from company pages, documentation and press coverage. Some of it is secondary (aggregators and news sites), marked in the sources, and could be out of date.",
        "The scores and weights are the author's judgment. Change the weights and the order changes. For example, with the other weights scaled down proportionally, weighting semantic depth at 40% moves Graphite to fourth, and at 50% to second, behind Blockaid.",
        "Graphite facts come from its own repository, which is written by the same team. Its live-run numbers are internal measurements, not audited figures.",
        "This is a market comparison, not a security audit or certification of any product, Graphite included.",
    ], ParagraphStyle("BulS", parent=BUL, fontSize=8.6, leading=11.6)),
    PageBreak(),
]

# ---------------------------------------------------------------- sources
src = [
    ("Blockaid", [
        "Blockaid blog, How to build smarter, safer onchain AI agents with Blockaid: blockaid.io/blog/how-to-build-smarter-safer-onchain-ai-agents-with-blockaid",
        "The Block, Blockaid closes $50 million Series B (18 Feb 2025): theblock.co/post/341601",
        "Fortune, Blockaid $33 million funding round (23 Oct 2023): fortune.com/crypto/2023/10/23/tel-aviv-crypto-security-blockaid-33-million-funding-round-israel-hamas",
        "CoinDesk, Blockaid raises $27M (23 Oct 2023): coindesk.com/business/2023/10/23/web3-security-firm-blockaid-raises-27m-to-help-tackle-industrys-never-ending-challenges",
        "Portal docs, Blockaid integration (Solana scan, result values): docs.portalhq.io/sdks/web/guide/blockaid",
        "Solana Compass, Blockaid project page (secondary): solanacompass.com/projects/blockaid",
    ]),
    ("Fireblocks", [
        "Fireblocks Help Center, Policy Inspector: support.fireblocks.io/hc/en-us/articles/29211960021020",
        "Fireblocks blog, Fireblocks AI suite for digital asset operations: fireblocks.com/blog/fireblocks-ai-suite-digital-asset-operations",
        "The Paypers, Fireblocks launches Agentic Payments Suite (May 2026): thepaypers.com/payments/news/fireblocks-launches-agentic-payments-suite-for-stablecoin-transactions",
        "Blockchain.News, Fireblocks unveils AI tool to thwart transaction policy exploits (June 2026, secondary): blockchain.news/news/fireblocks-ai-tool-digital-asset-exploits",
    ]),
    ("Turnkey", [
        "Turnkey blog, Introducing the Solana policy engine: turnkey.com/blog/introducing-solana-policy-engine",
        "Turnkey blog, Understanding Solana transactions and parsing: turnkey.com/blog/understanding-solana-transactions-and-parsing",
        "Turnkey docs, Agentic wallets: docs.turnkey.com/products/embedded-wallets/features/agentic-wallets",
        "Helius blog, How to build a secure AI agent on Solana: helius.dev/blog/how-to-build-a-secure-ai-agent-on-solana",
    ]),
    ("Hypernative", [
        "Hypernative, Guardian product page: hypernative.io/products/hypernative-guardian",
        "Hypernative blog, Solana network and projects now secured by Hypernative (Sep 2024): hypernative.io/blog/solana-network-and-projects-building-on-it-are-now-secured-by-hypernative",
        "FinTech Global, Hypernative raises $40m (June 2025): fintech.global/2025/06/11/hypernative-raises-40m-to-strengthen-web3-threat-protection",
        "The Block, Hypernative $16 million Series A: theblock.co/post/314305",
        "Hypernative blog, Ethena turns to Hypernative (Sep 2025): hypernative.io/blog/ethena-turns-to-hypernative-to-protect-transactions-across-its-15b-ecosystem",
    ]),
    ("Coinbase Developer Platform", [
        "Coinbase, CDP Server Wallets now available to all (July 2025): coinbase.com/developer-platform/discover/launches/cdp-server-wallets-ga",
        "Coinbase, Introducing CDP Wallets: coinbase.com/developer-platform/discover/launches/cdp-wallets-launch",
        "Eco, Coinbase Agentic Wallets explained (secondary): eco.com/support/en/articles/14845485-coinbase-agentic-wallets-explained",
    ]),
    ("Also considered", [
        "Phantom blog, Phantom acquires Blowfish (Nov 2024): phantom.app/learn/blog/phantom-acquires-blowfish",
        "crypto.news, Phantom acquires Blowfish: crypto.news/phantom-acquires-blowfish-to-boost-wallet-security",
        "KuCoin News, GoPlus launches AgentGuard (Feb 2026, secondary): kucoin.com/news/flash/goplus-launches-agentguard-to-secure-ai-agent-execution",
        "GoPlus whitepaper, roadmap: whitepaper.gopluslabs.io/goplus-network/resources/roadmap",
    ]),
    ("Graphite", [
        "Graphite repository, README.md and docs/CURRENT.md (main at 9e60f59, 2 Nov 2026)",
        "AUDIT/FINAL.md (Round 41 verdict) and docs/audit/RESIDUAL_RISK_AND_OWNER_GATES.md",
        "docs/evidence/live-mainnet/ (live-run reports, 31 Oct 2026)",
    ]),
]
story.append(p("Sources", H2))
story.append(p("All accessed 2 November 2026. \"Secondary\" marks an aggregator or news site rather than the company's own material.", SMALL))
for head, items in src:
    story.append(KeepTogether([p(head, H3), *bullets(items, ParagraphStyle("Src", parent=BUL, fontSize=8, leading=10.4))]))

doc = SimpleDocTemplate(
    str(OUT), pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=18 * mm,
    title="Graphite competitive comparison", author="Graphite", subject="Graphite compared with Blockaid, Fireblocks, Turnkey, Hypernative and Coinbase CDP",
)
doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
print(OUT)
for n in RANKED:
    print(f"{n:14s} {weighted(n):.2f}")
