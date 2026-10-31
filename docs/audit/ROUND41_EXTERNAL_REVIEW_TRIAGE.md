# Round 41 — four external AI reviews, checked claim by claim

Date: 2026-10-31. Base: `main` 3d5cab7 plus PR #61 (head 455de36 when the
checks started). The owner ran four AI models over the repository and passed
on what they returned:

- **R-A**, a written review (one finding);
- **R-B**, a written review (F-001…F-005);
- **R-C** and **R-D**, audit prompts that carry findings inside them (ID-1…ID-5 and
  G-01…G-09, plus areas to sweep).

Nothing they said was taken on trust. Every claim was read against the code;
where the code disagreed, the code won. Each claim below has a verdict:

- **TRUE** — the defect exists;
- **FALSE** — the code disproves it;
- **PARTLY** — part of it holds; the row says which;
- **KNOWN** — true, and already a recorded limitation or decision.

Severity is ours, not the reviewer's. These are AI reviews and our own checks.
None of this is an independent audit.

## Outcome

| | Claims |
|---|---|
| Fixed this round | D-1 (D-29), D-2 (D-28), D-8, the B-2 side finding (D-30), D-5, D-11 |
| Hardened (no defect, a guard against drift) | C-10, D-7 |
| Recorded as accepted limitations (RESIDUAL_RISK §3) | A-1, C-2, D-6; D-1's root cause (the RPC is the trust root for simulated effects) |
| Already known | C-1, C-5, D-4 |
| False | B-1, B-3, B-4, B-5, C-3, C-4, C-6, C-9, D-3, D-9, D-10, and the literal B-2 |

None of the four reviews found a way to get `executable_approved` for a transaction whose bytes do something other than the request, when the RPC is honest.

The two real defects in the approval path are D-1 and D-2. Each needs an RPC that lies:
- **D-1:** the Core's RPC returns an effect-free simulation;
- **D-2:** the guard's own RPC under-reports a swap's outflow.

Both are closed.

## Claims

| ID | Claim (short) | Verdict | Ours | Evidence and action |
|---|---|---|---|---|
| A-1 | Rate limiter: an evicted identity gets a fresh burst | TRUE, as designed | Info | `server.rs` FIFO eviction at 1,000,000 buckets. A new bucket holds one second's refill: 30 requests at the default rate. Evicting one victim needs about a million distinct identities, and no authentication, approval or audit property depends on the limiter. The suggested "refuse new identities" mode lets an attacker lock out new honest clients. **Recorded** in §3. |
| B-1 | SDK: a null `risk_verdict` yields "inconclusive" | FALSE | — | TS `computeExecutionDecision` returns "blocked" or `analysis_only`, never executable. Both SDKs' validators reject a non-object `risk_verdict` before anything is returned (TS `client.ts`, Go `validate.go`). |
| B-2 | First-manifest tier cap applied "too late" | FALSE as stated; side finding TRUE | Medium-Low | The cap sits inside `compute_trust_tier_for`, and every consumer reads it. While checking, we found that an upgrade signed by the **same** reviewers lifted the cap with their own fixtures. **Fixed: D-30.** |
| B-3 | RPC timeout has no minimum; `GRAPHITE_RPC_TIMEOUT_SECS=0` hangs | FALSE | — | No such variable exists, and an unknown `GRAPHITE_*` name refuses to start. The server uses a fixed 3 s per call and a 6 s pipeline budget. The guard's `GRAPHITE_RPC_TIMEOUT_MS` accepts 1–120000 only. |
| B-4 | `ResidualPolicy` accepts `" intent_parameters "` | FALSE | — | `residual-policy.ts` trims first, then refuses `NEVER_ACCEPTABLE` at construction. A probe of every whitespace and NBSP variant throws. |
| B-5 | L6 and the decision rule check failed layers twice | FALSE (not redundant) | — | The decision rule also covers L1, L3, L6, L7 and L8, and it is the rule the SDKs recompute. |
| C-1 | Abandoned plugin threads | KNOWN | Low | §3 "Plugin deadline" and D-10. A plugin that hangs forever saturates the gate; every verification is then refused until restart. Fail-closed. |
| C-2 | Baseline drift; `MIN_SAMPLES` fail-open | PARTLY / KNOWN | Low | Drift is bounded by the anchored band (tests `a_slow_drift_cannot_walk_the_band_past_its_anchor`, `a_slow_drip_cannot_walk_an_anchored_baseline`). Below 10 samples L3 is Inconclusive and can approve, by design. **Recorded** in §3 ("L3 bootstrap"). |
| C-3 | `signApproved` buffer not cloned; freeze bypass | FALSE | — | `#tx` is an ES private field. The signed message is checked against the build-time copy after signing. Instance, prototype and class are frozen; a probe of each injection throws. |
| C-4 | `allowed_cpis` smuggling; discriminator truncation | FALSE | — | Plugin CPI lists are discarded. Seeds always win over registry submissions. L4 and the observed CPI tree judge effects whatever is listed. Matching needs the full discriminator, and prefix-ambiguous manifests are refused. |
| C-5 | Unkeyed trail interleaving; reader sequence check | KNOWN | — | The sequence check already exists (`RecordGate::accept`). The unkeyed trail being only corruption-evident is in §3. |
| C-6 | Parser `unwrap`; v1 mask; absent `loadedAddresses` | FALSE | — | No `unwrap` outside tests. Every `expect` follows a length check. Unknown mask bits are refused. Absent `loadedAddresses` refuses (§3 row, `round39_lookup_table_campaign.rs`). |
| C-7 | `X-Forwarded-For` spoofing; IPv6; 5xx leaks | PARTLY | Low | XFF is believed only from listed proxies, reading the right-most hops; broad or empty lists refuse to start. IPv6 is keyed per /64, a documented tradeoff. 5xx bodies are fixed strings. |
| C-8 | Mutation before signing; `PriorSubmissionUnresolved` DoS | FALSE / PARTLY | Info | No mutation path exists. A lying guard RPC can keep one request key blocked (an unbounded `lastValidBlockHeight`). The same RPC can already drop every send. Not changed. |
| C-9 | Hash chain and HMAC soundness | FALSE | — | Domain-separated, canonical-byte, RFC 2104 HMAC tested against RFC 4231 vectors. Downgrade and retired-key extension are refused. |
| C-10 | Unpinned actions; image tags; compose defaults | FALSE (gap in enforcement) | Low | All 91 `uses:` are SHA-pinned and every image is digest-pinned, but only one job was checked. **Hardened:** `ci-scripts.test.sh` now holds every workflow, with a refused `@v4` case. |
| D-1 | A lying RPC's empty simulation → `executable_approved` | TRUE (narrower than claimed) | Medium | Reproduced: the bound transfer was executable on an effect-free simulation. Transfers and swaps are byte-bound; the gap was effects a program performs by CPI. **Fixed: D-29.** An effect-free RPC diff is now `no_state_diff`, never executable. The root cause (the RPC is the trust root for simulated effects) is now a §3 row, and the handoff's I-8 is reworded. |
| D-2 | The guard's swap cap trusts its RPC's simulation | TRUE | Medium | `guard.ts` ignored the route's decoded `in_amount` under `GRAPHITE_MAX_TRANSFER_LAMPORTS`. **Fixed: D-28.** Two regression tests fail on the old code. |
| D-3 | A declared but unobserved effect is only a note | FALSE (the fix would be wrong) | Info | Bindings that depend on an effect already fail closed when it is missing. Making it Critical would refuse honest no-ops, and a lying RPC defeats it anyway. D-29 covers the empty case. |
| D-4 | Rulesets require 0 approvals; admin bypasses | KNOWN | Low | `main-review.json` requires 1 approval plus code-owner review. The admin's pull-request-only bypass is the solo-maintainer choice in `docs/ops/branch-protection.md`. Owner gate G-1. |
| D-5 | The handoff names a merged branch | TRUE | Low | **Fixed:** names `main` 3d5cab7 plus PR #61. |
| D-6 | Dashboard `connect-src https:`; key in Web Storage | KNOWN | Info | `docs/audit/parts/dashboard.md`. **Recorded** in §3. |
| D-7 | Caddy `/api/*` matches one path segment | FALSE | — | Caddy treats a trailing `*` as a prefix match. **Hardened:** the deploy test asks for `/api/protocols/top` and `/api/../admin/quarantine`. |
| D-8 | MCP prints APPROVED for `analysis_only` | PARTLY | Info | Only for a verdict signed under residuals the deployment accepted by name. **Fixed:** shown as "ANALYSIS ONLY (not executable_approved …)". |
| D-9 | `constant_time_eq` has a length branch | FALSE | — | Every caller compares against a fixed 32-byte value from disk; there is no remote timing oracle. |
| D-10 | TODO, placeholder or "for now" in production paths | FALSE | — | None. Every "placeholder" hit is descriptive (the simulation blockhash, unsigned signature bytes, HTML inputs). |
| D-11 | 137 manifests / 3,518 instructions / 27 grants | PARTLY | Info | The grants count is wrong: **26**. **Fixed** in `docs/CURRENT.md` and the handoff, with a test that counts them. |

## What these reviews were not

- They were not an independent audit.
- Two of the four are prompts that assert findings without evidence. Several of those findings are false.
- Line numbers in all four were against an older `main`.
- The owner gates (the signing key, the independent audit, the live ruleset bypass read) are unchanged; see RESIDUAL_RISK §1.
