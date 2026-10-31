# Solana Foundation funding application — form answers

Updated 2026-10-31 to the form and application guide as published, in the form's order. Each
answer is plain text, ready to paste.

- **[OWNER]** marks the details only you can give.
- The form says not to put links in answers that do not ask for them. The only links below are in
  "Website URL" and an optional deck link in "Your project / idea", which the guide invites.

Every figure comes from a committed file, named in the notes under each answer. The notes are for
you; don't paste them.

---

**Company name:** Graphite

**Website URL:** https://github.com/Stan-lee13/graphite

**Country:** **[OWNER: your primary country of operations]**

**First Name / Last Name:** **[OWNER: your legal names, not a handle]**

**Email Address:** **[OWNER: the address you use for the project]**

**Solana On-Chain Accounts:** N/A

> Notes: Graphite runs off-chain and has no program, token or fee-payer wallet. Don't add an
> explanation; the field asks for addresses or "N/A".

**Funding Amount:** $18,000

**Which funding category are you applying for?** Developer Tooling

---

**Your project / idea**

> Graphite is an open-source safety check that sits between an AI agent and its Solana wallet.
> Before the agent's key signs a transaction, Graphite verifies that the exact transaction bytes
> do what the agent says they do, and nothing else.
>
> The agent states its intent, for example "swap 1 SOL for USDC with at least 140 USDC out".
> Graphite then:
> - parses the exact bytes and resolves every account, including address lookup tables;
> - simulates the transaction;
> - compares every account change with the stated intent and with what each instruction of that
>   program is allowed to do;
> - answers with a deterministic verdict.
>
> Only an "executable_approved" verdict lets the agent sign. Every refusal says why. No AI model is
> in the decision, so the same input always gives the same answer.
>
> Why this matters: agents on Solana now hold keys and sign whatever their tools build. A prompt
> injection, a malicious API response or a poisoned document can turn one tool call into a drain.
> Blocklists don't help, because drains go through programs everyone trusts: System, SPL Token
> and the major DEXs. A wallet warning doesn't help either, because no human reads it.
>
> It is built today and ships with:
> - a Rust verification core and HTTP server;
> - TypeScript and Go SDKs;
> - a drop-in signing guard for agents;
> - SolanaAgentKit, Vercel AI SDK and MCP integrations;
> - an operator dashboard and a deployment kit;
> - descriptions of 137 Solana programs covering 3,518 instructions, generated from each program's
>   own IDL.
>
> What it does not have yet is a public deployment that anyone can call without running it
> themselves, and users. That is what this grant funds.
>
> **[OWNER: "Referred by …" if anyone at the Foundation or a partner referred you; otherwise
> "No referral." Optional: "Deck: <link>" if you make one.]**

**Is / will this project be open sourced?** Yes

> Notes: all of it is MIT-licensed today.

---

**Specify the amount of funding you are requesting and list the milestones that will be completed
to unlock each portion of that funding.**

> $18,000 in five milestones over six months: three for product development, two for adoption.
> Hosting and RPC costs for the public endpoint are included.
>
> $4,000 due upon completion of Milestone 1 deliverable (month 2): public mainnet verification
> endpoint live.
> - Graphite is hosted with its own mainnet RPC.
> - It is deployed from a signed release that rebuilds byte-identical.
> - Free API keys are available to any developer.
> - A public status page shows at least 99% uptime over the endpoint's first 30 days.
>
> $3,500 due upon completion of Milestone 2 deliverable (month 3): direct swaps on two more
> venues.
> - Pump AMM and Meteora DAMM v2 swaps called directly can be verified and approved. Today they are
>   approved only when routed through Jupiter.
> - Each venue has an honest-swap test and attack tests.
> - A published live mainnet run shows honest direct swaps on both venues approved.
>
> $3,000 due upon completion of Milestone 3 deliverable (month 3): agent integrations published.
> - The signing guard and the MCP server are published to npm.
> - An integration pull request is opened upstream to SolanaAgentKit.
> - An ElizaOS plugin is released.
> - Each has docs and an example agent that runs end to end on devnet.
>
> $3,500 due upon completion of Milestone 4 deliverable (month 5): adoption by teams.
> - 3 projects (agent frameworks, wallets or agent products) route real transactions through
>   Graphite, each confirmed publicly or in writing.
> - 10 distinct teams hold an API key with at least one verification in the last 30 days.
>
> $4,000 due upon completion of Milestone 5 deliverable (month 6): usage and maintenance.
> - 10,000 transactions are verified on the public endpoint by external API keys, counted by the
>   endpoint's metrics and published.
> - Six monthly public reports are published: issues and security reports handled, program
>   descriptions updated after program upgrades, and endpoint uptime.
>
> An independent security audit is not in this budget. A credible audit costs more than this whole
> grant, so I am pursuing it separately. Until it is done, every public page says Graphite is not
> independently audited.

> Notes:
> - Pump AMM is approvable today inside Jupiter routes (Round 41).
> - `decode_swap` in `graphite-core/src/intent_binding.rs` reads Jupiter v6, Orca Whirlpools,
>   Raydium CLMM, CPMM and AMM v4, and Meteora DLMM. It does not read Pump AMM or Meteora DAMM v2
>   called directly.
> - Adjust the targets to what you can commit to. Keep the total at $18,000.

---

**Relevant metrics about the usage of your project/product**

> Graphite is pre-launch, so it has no production users yet. Milestones 4 and 5 are there to
> change that. What can be measured today, and anyone can reproduce from the repository:
> - Live on Solana mainnet, five runs on 31 October 2026, never signing or sending: 147 of 148
>   honest transfers and 12 of 13 honest swaps were approved for signing. The swaps went through
>   Jupiter v6 (including routes through Pump AMM) and Orca Whirlpools. The two refusals are
>   explained and recorded: a new transaction pattern the system had not seen before, and a
>   program redeployed after its evidence was measured.
> - Real exploits: all 35 labelled mainnet exploit transactions from the public SolPhishHunter
>   research dataset are refused.
> - Real traffic: 48,855 executed mainnet transactions from whole blocks ran through the full
>   pipeline with 0 parse failures and 0 verification errors.
> - Coverage: 137 Solana programs described, covering 3,518 instructions, each measured on
>   mainnet.
> - Quality: 41 recorded rounds of adversarial review. Every security fix has a test that fails
>   without it; 244 such deliberate breaks are logged. Release builds are reproducible
>   byte-for-byte.
>
> **[OWNER: add GitHub stars, forks, or anyone already trying it, if any.]**

> Notes, the sources:
> - live runs: `AUDIT/FINAL.md` and `docs/evidence/live-mainnet/`;
> - exploits and traffic: `docs/CURRENT.md` and `tools/mainnet-sample/SAMPLES.md`;
> - breaks: B01–B244 in `AUDIT/01-findings.md`;
> - reproducible build: `release.yml` run 41190904785.

---

**Competition**

> The closest competitors are transaction-security services for wallets, such as Blowfish and
> Blockaid. They simulate a transaction and show a person a warning. They are closed-source APIs
> and judge mainly by simulation summaries and reputation lists.
>
> On-chain assertion tools such as Lighthouse let a wallet add checks that a transaction's effects
> stay within limits. The limits still have to come from somewhere, and Graphite could supply them.
>
> Graphite is different in five ways:
> 1. It is built for agents: a machine-readable, deterministic decision for software with no
>    human in the loop, not a warning for a person.
> 2. It is open source and self-hostable, so anyone can audit the checker or run their own.
> 3. Its approval is tied to the exact bytes being signed and to the stated amount, recipient and
>    asset. A transaction that does more than it claims is refused.
> 4. It judges each instruction against a description generated from the program's own IDL, not
>    against a reputation score.
> 5. It refuses anything it cannot observe instead of guessing.
>
> **[OWNER: check the competitor names are current before you submit, and add any agent-specific
> security tool you know of.]**

---

**How is this project a public good?**

> All of Graphite is free and open source under the MIT license: the verification core, the SDKs,
> the agent guard, the integrations, and the program descriptions with their mainnet measurements.
> The exploit corpus and the benchmark are open too. There is no token.
>
> Any agent framework, wallet or backend on Solana can run it themselves or embed the SDKs at no
> cost. The descriptions of what 137 Solana programs' instructions do are a reusable, open dataset
> for anyone building safety tooling.
>
> The public endpoint this grant funds will be free for developers and runs the same open-source
> code. Running it yourself stays fully supported.

---

**Why You?**

> I have already built the hard part, in the open, and held it to a standard anyone can check.
>
> Graphite works today. It is a Rust verification core with SDKs, an agent signing guard and
> agent-framework integrations. It has been measured on live Solana mainnet.
>
> It is built on Solana's real runtime behaviour, not a summary of it:
> - its transaction parser is checked in CI against the Anza SDK's own decoder;
> - its rebuild of inner instructions is checked against Agave's parser;
> - it models Token-2022 transfer fees and extensions;
> - it resolves address lookup tables the way the runtime does;
> - it reads legacy, v0 and v1 transactions.
>
> My edge is discipline:
> - 41 rounds of adversarial review and repair, every finding written down with its root cause;
> - every security fix proven with a test that fails without it;
> - outside reviews checked claim by claim against the code, and the true ones fixed;
> - known limitations published next to the features;
> - no performance claim without a run anyone can reproduce.
>
> Most security tools in this space are closed. Graphite can be checked line by line.
>
> **[OWNER: one or two sentences on you: your engineering background, anything you have shipped
> on Solana, and any hackathon placement. Mention the Superteam Solana AI Kit bounty placement if
> it is yours to claim. If this is your third application, you may add: "Since my last
> application I have measured Graphite live on mainnet and cut the request to fit the program."]**
