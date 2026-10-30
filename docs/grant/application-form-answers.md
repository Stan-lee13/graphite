# Solana Foundation funding application — form answers (draft)

The form fields in order, with the answer for each. Fields marked **[OWNER]** need your own
details. The Developer Tooling proposal itself is
[`developer-tooling-proposal.md`](developer-tooling-proposal.md); paste it into a shared Google
Doc and link that doc in the "Developer Tooling Instructions" field.

**Company name:** Graphite

**Website URL:** https://github.com/Stan-lee13/graphite **[OWNER: use the website if it is live
and not broken; the guide accepts a GitHub link when there is none.]**

**Country:** **[OWNER: the primary country of operations]**

**First Name / Last Name:** **[OWNER: your legal names, not a handle]**

**Email Address:** **[OWNER: the address associated with the project]**

**Solana On-Chain Accounts:** N/A

Graphite is off-chain verification infrastructure. It deploys no program, token or fee-payer
wallet.

**Funding Amount:** $18,000

**Which funding category are you applying for?** Developer Tooling

**Developer Tooling Instructions:** **[OWNER: the link to the shared Google Doc containing
`developer-tooling-proposal.md`, shared as "anyone with the link can view".]**

**Why You?**

> I have already built the hard part, in the open, and held it to a standard anyone can check.
>
> Graphite is a working Rust verification core for Solana transactions. It ships with:
> - TypeScript and Go SDKs;
> - an agent signing guard;
> - SolanaAgentKit, Vercel AI SDK and MCP integrations;
> - a dashboard and a deployment kit;
> - 137 protocol manifests covering 3,518 instructions, each generated from the program's own IDL
>   and measured on mainnet.
>
> It is built on Solana's real runtime behaviour, not on a summary of it:
> - Its transaction parser is checked in CI against the Anza SDK's own decoder.
> - Its rebuild of inner instructions is checked against Agave's parser.
> - It models Token-2022 transfer fees and extensions.
> - It resolves address lookup tables the way the runtime does.
> - It reads v0 and v1 transactions.
>
> What sets the work apart is its discipline:
> - 40 recorded rounds of adversarial review and repair, including three deep internal audits.
>   Every finding is written down with its root cause, and every security fix has a test that
>   fails without it. Each fix was then reverted on purpose to prove the test catches it; 244 such
>   breaks are logged in the repository.
> - The open limitations are listed next to the features, not hidden.
> - Nothing about Graphite's performance is claimed without a run anyone can reproduce.
> - The verdict is deterministic, with no model in the decision path.
>
> Existing transaction-security services are closed, built to warn a human in a wallet pop-up,
> and judge by reputation or simulation summaries. Graphite is open-source (MIT), self-hostable,
> and built for agents, which have no human to read a warning. It binds its approval to the exact
> bytes being signed and to what the agent said it was doing, and it fails closed on anything it
> cannot observe.
>
> **[OWNER: add your own background in one or two sentences: Solana projects shipped, hackathon
> placements (e.g. the Superteam Solana AI Kit bounty placement), relevant engineering
> experience.]**

---

## If the form also asks the questions in the application guide

**Your project / idea.**

> Graphite is a deterministic verification gate between an AI agent and its Solana key. The
> agent says what it is doing ("swap 1 SOL for USDC"). Graphite then:
> - parses the exact transaction bytes;
> - resolves every account;
> - simulates the transaction;
> - diffs the account state it would change;
> - compares all of that with the declared intent and with a manifest of what each instruction may
>   do.
>
> It permits signing only when everything matches, and explains every refusal. Agents are
> starting to hold keys and sign whatever their tool calls build. Graphite exists so that a prompt
> injection or a poisoned API response cannot turn that into a drain.
>
> **[OWNER: name any Solana Foundation referral.]**

**Is / will this project be open sourced?** Yes. It is MIT-licensed today, all of it.

**Milestones.** As in the proposal's §4 summary table ($18,000):
- $3,500: public verification endpoint;
- $3,000: honest swaps on at least two more venues;
- $2,500: upstream agent integrations;
- $4,500: six months of maintenance, at $750 a month;
- $4,500: three adoption metrics at $1,500 each (3 projects, 10,000 external verifications,
  10 active teams), paid pro rata.

An independent security audit is not in this budget; it is pursued separately.

**Relevant metrics about usage.**

> Graphite is pre-launch, so there are no production users yet. What can be measured today,
> reproducibly, from the repository:
> - **Real mainnet blocks:** 48,855 executed transactions from four days ran through the full
>   pipeline with 0 parse failures and 0 verify errors.
> - **Real exploits:** all 35 labelled mainnet exploit transactions from the public SolPhishHunter
>   dataset are refused.
> - **Coverage:** 137 manifests covering 3,518 instructions.
> - **Live, on mainnet (2026-10-29):** 27 of 28 honest transfers built from live mainnet accounts
>   were approved for signing (21/21 System, 6/7 SPL Token); the one refusal was a transfer that
>   would have failed on chain. 200 replayed mainnet transactions: 0 server errors, p50 latency
>   208 ms. Report: `docs/evidence/live-mainnet/run-40839253280.md` in the repository.
>
> Adoption is what Milestones 1 and 3 and the adoption metrics pay for.

**Competition.**

> Transaction-security services for wallets: Blowfish (now part of Phantom), Blockaid, and
> others. They simulate a transaction and warn a human. They are closed-source APIs, they judge by
> simulation summaries and reputation lists, and their output is a warning for a person to read.
>
> On-chain assertion tools (e.g. Lighthouse) let a wallet append checks that the transaction's
> effects stay within bounds. That is useful, but the bounds have to come from somewhere.
>
> Graphite differs in five ways:
> 1. It is open-source and self-hostable, so anyone can audit or run the verifier.
> 2. It is built for agents: a machine-readable, deterministic decision with no human in the loop.
> 3. It binds the approval to the exact bytes and to the declared intent (amount, recipient,
>    asset).
> 4. It judges each instruction against a manifest generated from the program's own IDL.
> 5. It fails closed on anything it cannot observe.
>
> It could feed an assertion tool, rather than compete with it.
>
> **[OWNER: verify the competitor list before submitting.]**

**How is this project a public good?**

> All of Graphite is MIT-licensed and free: the code, the protocol manifests, the exploit corpus,
> the benchmark and the audit records. It has no token. Any wallet, agent framework or backend can
> self-host it or embed the SDKs.
>
> The manifests and their mainnet measurements are an open, reusable description of what 137
> Solana programs' instructions do. The planned hosted endpoint is the same MIT code; the
> self-hosted path stays first-class.
