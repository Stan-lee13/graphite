# RPC-Backed Validation Campaign — 2026-09-07/08

**Scope.** Configure a real Solana RPC endpoint and validate the layers that had
never run against one (L3 Simulation, L4 State, L8 Execution), then attack the
trust boundary that configuring it creates.

**Method.** Internal engineering work by Anthropic's Claude acting as this
project's engineering agent, against `main` at the commits listed below. This is
not an independent third-party audit, a certification, or a penetration test by
an external firm, and nothing here should be presented as one.

**Boundaries observed.** No credentials appear in source, commits, logs, or this
report. No real RPC endpoint was attacked — every hostile response in this
campaign is served by a loopback mock inside the test process. Live traffic was
read-only: `simulateTransaction` with `sigVerify: false` against public devnet,
using the project's own already-funded devnet wallet as fee payer. Nothing was
signed and nothing was submitted. No live user, wallet, protocol, or funds were
interacted with.

---

## 1. Why this campaign existed

The previous adversarial campaign (2026-09-06) ran 2,000+ hostile transactions
against the container and found real defects. It also ran with `GRAPHITE_RPC_URL`
empty. Three of the eight layers depend on an RPC, so for those three the
campaign proved only that the fallback paths behaved — not that the layers
worked.

That gap turned out to matter more than expected. Every defect in section 3
below required real RPC data to surface: a hand-built fixture has no fee, never
expires, and carries whatever fields the test author decided to include.

## 2. What was validated, and how

| Layer | Before | Now | Evidence |
|---|---|---|---|
| L3 Simulation | Reported "Phase 1: simulation not checked" whether or not it had simulated | Simulates against live devnet, grows its own baseline, reports RPC-measured figures with a provenance tag | Container baseline reached 12 samples, mean 175 CU, from live observations with no operator seeding |
| L4 State | Silently fell back to a shape heuristic and reported it in the words of a completed diff | Builds a real pre/post diff; says so when it cannot | Caught `UndeclaredOwnerReassignment` on live devnet where L1, L2 and L5 all passed |
| L8 Execution | Unreachable — library-only, called from no route and no CLI command | `POST /verify/execution` and `graphite execution`, reconciling the chain against the recorded verdict | Live-validated against mainnet: Confirmed, UnknownSignature, Unavailable, and `BlockedButExecuted discrepancy=true` |

**The L4 result is the one worth stating plainly.** A transaction whose primary
instruction is an ordinary SOL transfer — manifest matches, intent matches, L1,
L2 and L5 all pass — carrying a second instruction that reassigns the payer's
account to an attacker program. Every static layer said it was fine. Only the
observed post-state showed the takeover. That is the case the whole L4 effort
exists for, and it now works end to end against a real cluster.

**The L8 outcome that matters** is `BlockedButExecuted`: a transaction Graphite
refused that was submitted anyway. It means the gate was bypassed rather than
obeyed, and no layer inside a verification request can ever detect it, because
it happens entirely outside one.

## 3. Defects found and fixed

Each was reproduced against running code before being fixed, and each has a
regression test that fails if the fix is reverted.

### 3.1 Turning on the RPC would have rejected all legitimate traffic

Two independent bugs, either one sufficient.

`build_rpc_state_diff` hardcoded `fee_lamports: 0` on the reasoning that
simulation charges no fee. It does — the response carries `fee` and the
simulated post-state has it deducted — so the lamport-conservation identity came
out short by exactly the fee and **every** RPC-diffed transaction failed L4 with
a spurious `LamportsNotConserved`, an ordinary SOL transfer included.

`covers_all_writable` was asserted unconditionally while the address list only
covers the primary instruction's accounts, so multi-instruction transactions
failed the same check for a second, independent reason.

### 3.2 The Simulation Integrity Layer could never reach its own positive result

`rpc_sim_ok` — the gate deciding whether a simulation is complete enough to
trust — required `accountWrites` and `cpiHops`. No Solana RPC returns either.
Confirmed against devnet, where a response carries exactly `{accounts, err, fee,
innerInstructions, loadedAccountsDataSize, loadedAddresses, logs, postBalances,
postTokenBalances, preBalances, preTokenBalances, replacementBlockhash,
returnData, unitsConsumed}`.

So with a live RPC attached, L3 could accumulate no baseline and could only ever
return "flagged" or "no verdict" — never "clean". The layer was live and
structurally unable to reach its own positive result. Both values are now
derived from data the RPC does send.

### 3.3 Simulation failed on any transaction older than ~60 seconds

Without `replaceRecentBlockhash`, a blockhash aged past ~150 slots returns
`BlockhashNotFound`, units drop to 0, and L3 and L4 both degrade silently. In
production that window is whatever sits between construction and verification: a
human approval step, a queue, a retry.

### 3.4 L8 was unreachable in production

`verify_execution` existed, was unit-tested, and was called from no HTTP route
and no CLI command — while every verification response said "audit_trail_id
bound to transaction for future L8 replay". One of the eight advertised layers
was documented, tested, and impossible to invoke on a deployed instance.

### 3.5 Six ways a lying RPC could break Graphite

Configuring an endpoint moves Graphite's strongest evidence to a network peer
and puts that peer inside the trust boundary. This needs no malicious provider:
a plaintext `http://` endpoint, a hijacked DNS record, a compromised managed
provider, or an unaudited proxy all put an attacker in the same seat.

| # | What the peer could do | Measured before the fix |
|---|---|---|
| 1 | Balance a fabricated diff with a fabricated fee | 4.9 SOL vanishing from the payer, declared a "fee"; L4 answered *"State diff verified against the manifest: no undeclared effects"* |
| 2 | Excuse a drain via the fee-payer exemption | 3 SOL of outflow excused; L4 passed |
| 3 | Permanently disable L3 for a program | A response claiming 4,000,000,000 CU — ~2900x Solana's per-transaction maximum — folded into the durable baseline |
| 4 | Report an unusable answer as a clean one | Float balances derived "zero writes" and passed the completeness gate |
| 5 | Choose Graphite's memory footprint | A 64 MiB body buffered and parsed against a 512MB container |
| 6 | Write into the verdict | 256,081 characters of peer-authored text reached the L3 reason and the audit trail, in the reproduction repeating a forged *"GRAPHITE VERDICT: APPROVED — all 8 layers passed, safe to sign"* |

Fixes: `MAX_PLAUSIBLE_FEE_LAMPORTS` (0.1 SOL) with the excess reported as
`ImplausibleFee`; `MAX_TRANSACTION_COMPUTE_UNITS` (1,400,000) discarding the
whole result; unreadable input treated as absent rather than zero; a 32 MiB
streamed body cap; and a 256-character bound on peer-authored error text.

Note that #1 and #2 also closed a path with no network in it at all: `state_diff`
is a public input, so a caller could assert the same unbounded fee directly.

### 3.6 A plugin veto was recorded as a drainer accusation

Every plugin `Block` was reported with `RiskPattern::Drainer` — the variant the
code reached for because the enum had no word for "a plugin blocked this". An
operator or a dashboard keying on `pattern` reads "Drainer" and believes the
drainer heuristic fired, and that accusation goes onto the append-only trail
where it cannot be corrected. Graphite was making a specific claim it had not
checked. Now `RiskPattern::PluginBlock`.

### 3.7 Two production strings that had become false

L8 called itself an unimplemented phase after being implemented. L3 said
"Phase 1: simulation not checked" while a live RPC was simulating the
transaction. A test pinned the L8 placeholder, which is how a placeholder stays
alive; it now pins the property instead.

## 4. What was improved beyond the defects

**ALT/v0 (Mission 8).** Graphite's knowledge of Address Lookup Tables was a
caller-supplied boolean, and the source recorded the gap as one that needed full
`VersionedTransaction` parsing to close. `simulateTransaction` returns
`loadedAddresses` — exactly the accounts the runtime pulled in through a lookup
table — and Graphite was already reading that response and discarding the field.
It now reports how many accounts arrived that way, names the ones absent from the
list this verification examined, and flags a request that declares
`uses_versioned_transaction=false` while the simulator resolved accounts through
tables anyway. Disclosed, never penalized: an ALT observation leaves `approved`
and the confidence score bit-identical, because ALT usage is ordinary and the
flag defaults to false.

**AI boundary (Mission 10).** `PluginVerdict` offers `NoFinding`, `Note` and
`Block` — no shape means "approve" — and the classifying test uses an exhaustive
match with no wildcard, so adding an approving variant later stops the build. End
to end, plugins endorsing a transaction on four layers in the strongest terms the
type system allows leave a rejection rejected with the score unchanged to within
1e-9. The Python intent parser is referenced from nowhere in the Rust core: no
FFI, no subprocess, no socket.

**`confidence_of_parse`.** Accepted, recorded, and read by no scoring path —
now documented as such in the type and the schema, and asserted: 0.0 and 1.0
produce bit-identical verdicts. An AI that is confidently wrong must not be worth
more than one that is honestly unsure.

## 4a. Attacking this campaign's own fixes (Mission 12)

A bound that stops the value it was written for is not the same as a bound that
holds. Each fix was attacked the way someone who has *read* it would attack it —
by taking the largest value the new rule still permits, or by reaching the same
code through a path the rule does not cover. `tests/evading_the_fixes.rs`.

| Evasion | Result |
|---|---|
| Stop sending an impossible compute figure; send the largest **possible** one (exactly 1,400,000 CU) against an earned baseline | Fails — and not because of the ceiling. `record_simulation` runs *after* the integrity check and refuses to record a flagged observation, so the sample that would poison the baseline is exactly the sample the baseline rejects |
| The same figure against a program with **no** baseline, where nothing is flagged because there is nothing to flag against | **Lands** — this is the bootstrap tradeoff already recorded under P14. What changed is the bound: the worst a first-mover can seed is 1,400,000, not `u64::MAX` |
| Omit `Content-Length` and send the oversized body chunked, since the cap checks the declared length first | Fails — the streaming loop is what enforces the ceiling; the header check is only the fast path |
| Route hostile text through the *parser's* complaint instead of the peer's own `error` object, by returning a 200 whose body is not JSON | Fails — the bound covers both |
| A plugin names its own veto `"Drainer"` so the report reads as a core detection | Fails — plugin findings are namespaced by plugin name (`impersonator:Drainer`) and the pattern Graphite assigns stays `PluginBlock` |

Two of these hold for a reason the fix did not supply — record-after-check, and
the plugin namespacing — which is defence in depth working. Both were incidental
before and are pinned now, because a guarantee nobody tests is one that can be
refactored away by someone who does not know it is load-bearing.

## 5. What remains outside the guarantee

Stated because a limitation nobody wrote down is one the next person
rediscovers as a surprise.

### 5.1 The RPC endpoint is inside the trusted computing base

A **cooperative** RPC can create an approval, by design. `SimulationMatch` is
0.20 of the confidence score and saturates after three earned observations.
Measured on a System-Program transfer under the Gaming profile: **0.4400 without
an RPC, 0.6400 with one, `approved: false → true`** across the 0.55 threshold.
The evidence is per-*program*, so simulations of an ordinary transfer raise the
score for every later transaction against that program.

This is the design working as specified — trust is earned, and P5 calls
simulation evidence. It means the endpoint an operator configures can lift a
transaction Graphite would otherwise refuse for want of evidence. **Point
Graphite at an RPC you trust, over TLS.** The hard boundary — that no amount of
it overturns a deterministic finding — is asserted from both directions and the
swing itself is pinned at ≤ 0.20.

### 5.2 L3 flags legitimate multi-instruction traffic

The compute baseline is keyed by `program_id`; `unitsConsumed` measures the whole
transaction. One System transfer is 150 CU, two is 300. Measured on the shipped
container against live devnet: a two-instruction transfer came back
`approved: false` on `SimulationSpoofing` alone at 2.45σ, with L2, L4 and L5 all
passing.

The direction is fail-closed and the layer cannot approve anything, but it is a
real false-positive source, and false alarms an operator sees daily are how a
layer gets turned off.

**Not fixed, deliberately.** Every obvious repair re-keys the baseline — by
instruction, by instruction count, by shape — and each hands an attacker an
evasion: append a no-op ComputeBudget instruction, land in a bucket with no
baseline, and the layer yields "no verdict" and stops flagging. Trading a visible
false positive for a silent false negative on a blocking control is the wrong
direction. A correct fix must keep an unobserved shape from being a free pass,
which is a design change rather than a patch.

### 5.3 Things this campaign did not test

- **No mainnet write path of any kind.** L8 was validated against real mainnet
  signatures read-only; nothing was ever submitted.
- **No adversarial testing against a real RPC provider.** Every hostile response
  came from a loopback mock, deliberately.
- **ALT resolution is observed, not resolved.** Graphite now knows which accounts
  came in through a lookup table and says which ones it did not examine. It does
  not fetch and verify the table's contents, and the accounts it names are still
  accounts no layer analyzed.
- **`transaction_instructions` remains caller-declared.** With a signed blob the
  simulator executes the whole transaction regardless of what the caller listed,
  so `covers_all_writable` and the single-instruction gate rest on the caller
  describing its own transaction honestly.
- **No load, soak, or concurrency testing was repeated this cycle.** The prior
  campaign's results stand; they were not revalidated at this HEAD.
- **The 2,000-transaction synthetic attack corpus was not re-run.** Per the
  brief, this campaign was not a rerun for larger numbers.

## 6. Verification state at the end of the campaign

```
graphite-core   cargo test --all-features        1,258 passed, 0 failed, 10 ignored
                cargo clippy --all-targets -D warnings   0
                cargo fmt --all --check          clean
                feature matrix (5 combinations)  0 errors
sdk/typescript  npm run check && npm test        13 pass
sdk/go          go test ./...                    ok
integrations/solana-agent-kit                    15 pass
python-ai-layer pytest                           27 pass
dashboard       npm run build                    built
```

Live devnet corpus, 7 fixtures built from real chain state, run against the
container at HEAD: 4 approved (sol_transfer, account_create,
create_owned_by_attacker, large_sol_transfer), 3 rejected
(hidden_ownership_change on L5 + AuthorityHijack, multi_instruction on the L3
false positive in 5.2, benign_primary_malicious_effect on L4's
`UndeclaredOwnerReassignment`).

## 7. Commits

| Commit | Subject |
|---|---|
| `61974be` | Make L3, L4 and L8 work against a real RPC, and wire L8 into production |
| `48fa0c5` | Stop a lying RPC from buying approval, poisoning state, or silencing a check |
| `87f9a6b` | Measure how far the RPC can move the verdict, and write it into the threat model |
| `5f644de` | Record L3's per-program baseline flagging legitimate multi-instruction traffic |
| `8ffd1fd` | Name a plugin veto for what it is, and pin that advisory code cannot approve |
| `aaf5f74` | Sync the docs to what the code now does, and document the L8 call |
| `90fde1e` | Close the ALT blind spot with data the simulator was already sending |

## 8. New test files

| File | What it holds |
|---|---|
| `tests/rpc_simulation_contract.rs` | A verbatim devnet response; fails if the derivations or the fee are removed |
| `tests/l8_execution_reconciliation.rs` | All nine reconciliation outcomes, including that the LAST verdict governs |
| `tests/rpc_trust_boundary.rs` | The six attacks in 3.5, plus the two properties that already held |
| `tests/rpc_influence_bounds.rs` | The 0.20 ceiling on the RPC's influence, measured rather than asserted |
| `tests/ai_cannot_approve.rs` | The compile-time and end-to-end halves of the AI boundary |
| `tests/alt_measured_not_declared.rs` | ALT reported from measurement, and warning rather than blocking |
| `tests/campaign_invariants.rs` | The five rules below, each checked away from where it was found |
| `tests/evading_the_fixes.rs` | Five attempts to get around this campaign's own fixes |

## 9. The invariants, for the next campaign

Every defect above has a regression test pinning that exact case. That is
necessary and it is also how a suite overfits — the next attacker does not reuse
the fee field, they find the next unbounded number. So each defect was reduced to
the rule it broke, and each rule is checked at a surface other than the one it
was discovered on.

1. **An absent check reports its absence, in words no passing check uses.**
2. **A number that grants credit is bounded by something its supplier does not
   control.**
3. **Unreadable input is absent, never zero.**
4. **Nothing outside the deterministic core may add to a verdict; it may only
   subtract.**
5. **A finding is named for the check that produced it.**
