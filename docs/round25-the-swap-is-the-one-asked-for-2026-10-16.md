# Round 25 — the swap is the one asked for

**Date:** 2026-10-16 · **Base:** `d95d37a` (Round 24) · **Scope:** a second external review of the
whole tree (ten items, E1–E10 in `AUDIT/01-findings.md`), each checked against the code before
anything changed; a five-minute section of the README for judges and reviewers.

Internal engineering work. Not an independent audit and not a certification.

## 1. What the review said, and what checking it found

| Item | The review's claim | What the code showed |
|---|---|---|
| E1 | swap amount and tokens not grounded | Confirmed. `groundSwapIntent` checked the verb, the AI layer's label and the program, never the amount or the tokens, and the Core does not compare them. |
| E2 | negated requests execute | Confirmed for transfers and swaps. |
| E3 | L8 misses a blocked transaction when the primary has no bytes | Narrower: with the caller's keys it already alarmed; without them the witness was never asked for the bytes. Writing the regression found a wider case (E3b): a primary serving substituted bytes silenced the witness whatever the keys. |
| E4 | spend cap race | Confirmed: an account read and a later simulation, not one snapshot. |
| E5 | unbounded RPC reads in the guard | Confirmed for the guard's own JSON-RPC reads. |
| E6 | lamports as a JavaScript `number` | Confirmed. |
| E7 | 12-signature limit missing for legacy and v0 | Not a finding: agave derives it from the 1232-byte packet (1232 / 96), and Graphite's bound already refuses a thirteenth signer. Pinned by a test. |
| E8 | instruction-count parity | Confirmed: more than 64 top-level instructions fits in a packet and can only fail. |
| E9 | version-0 research scripts | Already classified in `graphite-core/scripts/README.md`; the scripts themselves did not say so. |
| E10 | stale line in `docs/CURRENT.md` | Confirmed. |

## 2. What changed

**A swap is held to the request.** The amount and both tokens come from the user's own text,
and the AI layer's reading must agree on all three. The text must say what it spends ("swap 1
SOL for USDC", "buy USDC with 1 SOL"); a request that names only what it receives is refused,
because nothing would bound the spend. Token symbols resolve from a fixed table checked against
Jupiter's verified list on 2026-10-16. Any other token is named by its mint address.

The exact transaction is then simulated, unsigned. From the simulation's own pre- and
post-balances (one run, one slot), the wallet must lose no more than the requested amount of the
requested token. A SOL spend is allowed 0.01 SOL over that for fees and rent. No other token may
leave, and the requested token must arrive. All of this happens before the Core is asked.

**Negation refuses.** A request carrying "not", "no", "never", "don't", "do not", "won't",
"cancel", "stop", "abort", "undo", "instead" or any "n't" is refused. The cost is a rephrase.

**The guard's RPC answers are bounded and exact.** Every raw JSON-RPC answer is limited to the
Core's 32 MiB before parsing. A lamport balance that is not a safe integer is refused.

**L8 asks every source for the bytes.** The primary is asked first, then the witness. A source
with no bytes, or with bytes not bound to the signature, does not end the search. A blocked
record alarms on the witness's bound bytes. An approved record is not reconciled as executed
while a source served substituted bytes.

**The instruction trace limit holds for every format.** Legacy and v0 messages with more than
64 top-level instructions are refused at parse.

## 3. Deliberate breaks

Every fix was reverted once, alone, and its named test re-run.

- TypeScript TSB6–TSB11 (swap effect, negation, text grounding, wallet-owner filter, response
  bound, exact lamports): 6 of 6 caught.
- Rust B104–B107 (witness byte source, substituted bytes, approved after substitution, the
  instruction limit): 4 of 4 caught (`AUDIT/01-findings.md`, break log).

## 4. Still open

Unchanged from Round 24 and recorded in `AUDIT/02-roadmap-gap.md`:

- protocol upgrade detection (R-M1);
- per-instruction L3 baselines (A2-08);
- the archive index (R-M11);
- owner configuration (R-M13) and honest intents for withdrawals and claims (R-M14);
- the guard's public API on web3.js 1.x (R-M15), whose own RPC reads this round's bound does not
  cover;
- the owner's items: an independent audit, branch protection, deployment.

Graphite still does not compare a swap's output amount with a minimum. The request rarely
states one, and the route's own minimum is in its instruction data, which the Core reads only for
the protocols it models.
