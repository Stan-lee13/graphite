# Round 18 — the registry is measured

> **Historical record.** This report describes the codebase at commit `453dd01`
> on 2026-09-22/23, and the changes made on top of it. For the current state of
> Graphite see [`CURRENT.md`](CURRENT.md).

**Date:** 2026-09-22 → 2026-09-23
**Trigger:** "update every single .md file in the repo to its current state;
only 8 out of 33 programs are battle tested, can't you do that; there are many
more programs in the Solana inventory, so at least a minimum of 70 battle-tested
registered programs to start with."
**Starting state:** commit `453dd01` (`main`), CI run 35694122561 green.

---

## 1. What was asked, and what "battle tested" turned out to mean

Three things were asked: bring the documentation up to date, raise the number of
battle-tested programs above eight, and get to at least seventy of them by
onboarding more of the Solana program inventory.

The second of those does not have an honest one-line answer, because before this
round **`trust_tier` was a string in a JSON file and nothing checked it.** Eight
manifests wrote `BattleTested` — the tier the engine's own definition reserves
for "1,000+ verified transactions" — and the engine believed all eight. Raising
the number would have meant typing `BattleTested` into more files.

That is the exact thing Graphite exists not to do. Constitution P7 says a tier is
computed from evidence and never asserted, and `semantic_graph_store` applies
that rule strictly to evidence the node earns at runtime. It was applied to every
source of evidence except the document in this repository.

So the shape of this round is: **make the claim checkable first, then earn it.**

Three numbers say how it went.

| | Before | After |
|---|---:|---:|
| Protocol manifests / instructions | 33 / 803 | 129 / 3,186 |
| Manifests loading as `BattleTested` | 8 (declared, unchecked) | 106 (measured) |
| Non-vote mainnet transactions whose primary program Graphite can name | 20.8% | 44.0% |

The last row is measured by `tools/mainnet-sample` on the **same** 10,617
-transaction sample for both columns, so it is a before/after of the registry,
not of the hour of chain it was taken from. Counted per program invocation
rather than per transaction, over the 80-block census, the same move is 64.5% →
79.5% of non-vote invocations (`docs/protocol-coverage.md`).

---

## 2. The bar, and where it comes from

`protocols/battle_tested_evidence.json` carries a mainnet measurement for every
seed manifest. `load_seed_manifests` lowers a declared `BattleTested` to
`OfficialManifest` unless that record shows all three of:

1. **identity** — the program account exists and is executable
   (`getAccountInfo`);
2. **volume** — at least **1,000 successful transactions** carry the program's
   address over a window the record states (`getSignaturesForAddress`, paged).
   1,000 is not a new number: it is
   `semantic_graph_store::thresholds::BATTLE_TESTED_TX`, the bar the engine
   already applies to evidence it earns itself;
3. **decode** — of at least **20 instructions really observed on chain**, the
   manifest can name at least **90%**, resolved by the same prefix rule the
   engine uses (`getTransaction`, plus a sweep of whole finalized blocks).

Axis 3 is the one a transaction count cannot give you. It is the difference
between "this program is busy" and "this manifest still describes this program",
and it is what caught the defects in §4.

The gate reads the raw measurements and **never** the file's own
`meets_battle_tested` field, so a hand-edited boolean promotes nothing
(`battle_tested_evidence::the_evidence_files_own_verdict_field_is_not_what_the_gate_reads`).
Every axis is proven load-bearing by a test that moves it by one
(`::each_measurement_axis_is_load_bearing`), and every seed manifest must have a
record at all, whatever it says
(`::every_seed_manifest_has_a_measurement_on_record`).

**What the tier does not say.** It says the program is real, heavily used and
accurately described here. It does **not** say the protocol is safe: a heavily
used malicious program would clear the same bar. What judges that is L4, L5 and
L7, which run identically at every tier. The tier moves the confidence ceiling
(0.75 → 1.0) and therefore which wallet profiles can transact at all; it is not
a safety badge.

### Two measurement subtleties that changed the numbers

**`getSignaturesForAddress` returns transactions that CARRY an address, not only
those that invoke it.** Drift's most recent signatures are, in the sample taken
here, transactions that load its address through a lookup table and then call
Kamino and Swig. Volume alone therefore cannot establish use — which is why the
decode axis exists and why a program must clear both. The field is named and
described as what it is.

**An Anchor program emits events by CPI-ing itself** with discriminator
`e445a52e51cb9a1d` (`sha256("anchor:event")[0..8]`). That appears in the trace as
an instruction targeting the program, but no caller ever sends it and no IDL
lists it. Counting it as an instruction the manifest "failed to name" put
Jupiter V6 at a 0.46 decode rate when every instruction anyone actually sent it
was named. It is excluded from the denominator and counted separately.

---

## 3. Where 96 new manifests came from

Not from a curated wish-list. The inventory was **ranked by what the chain
actually ran**: `scripts/solana_inventory_census.py` sampled 80 finalized blocks
spread over ~11 hours of mainnet (77,589 successful transactions, 569 distinct
programs) and counted, per program, the successful transactions that invoke it.

For every program in that ranking, `scripts/fetch_onchain_idls.py` reads the
program's **own on-chain Anchor IDL** — the account at
`create_with_seed(find_program_address([], program), "anchor:idl", program)`,
owned by the program itself. **108 of the 569 publish one.** That account is the
deployed program's own statement about its interface, which is a better source
than any third-party copy: it cannot have drifted from a different repository's
branch.

`scripts/onboard_from_inventory.py` turns each into a manifest, taking from the
IDL only what the IDL actually states — instruction names, discriminators (the
explicit bytes where present, otherwise the Anchor
`sha256("global:" + snake_case(name))[0..8]` derivation the program's own client
uses), account names, order, writability and signer-ness, and PDA seed templates
**only** where the derivation is expressible exactly. Risk class and state-change
phrasing are inferred from the instruction name by the C46/C56 convention and
kept conservative.

96 manifests were written this way (48 from the top 250 by usage, 48 from the
tail), and 216 instructions were merged into six manifests that already existed
and had fallen behind their deployed programs — Marginfi v2 went from 4
instructions to 91, Meteora DLMM from 17 to 84, Pump.fun from 9 to 47.

### Naming, and why every one carries its address

Every auto-onboarded manifest is named `<IDL name> (<first 8 characters of the
address>)`. Two reasons, both from this data:

- the IDL names are **not unique** — `pyth_push_oracle`, `pyth_solana_receiver`
  and `wormhole_core_bridge_solana` each appear at more than one address in a
  single ten-minute sample of mainnet;
- a name alone would let a program at an address nobody recognises present
  itself in the console as the protocol whose name it copied. That is the
  impersonation Graphite's own `CpiTraceAnomaly` detector exists to catch, and
  the registry should not be the thing that supplies the disguise.

No brand attribution is asserted for any program whose identity was not already
in `verified_program_ids.json`.

### What this does NOT reach

The programs that dominate the **remaining** unmanifested traffic do not publish
an on-chain IDL. In the 10,617-transaction sample the largest are
`Prism8hsRo6Ww5jiN5Zeh3YDPLZHqHduCPSAV7JF7qv` (183 transactions),
`Tri3NG4HkZ6DddYPKoX2ehgkqFtDuej9Aspw5BmvSo4` (164) and
`NA777pkN8YYSsQKk1zvwKgJmThtuWbmhonzJxRARQm5` (100). Onboarding them needs a
per-protocol source, not a sweep, and that is recorded as a Phase 3 gate rather
than quietly left out.

---

## 4. Defects the measurement found in Graphite itself

This is the part a manifest count would never have produced. Running the
onboarded registry against real blocks exposed three real defects, two of them
pre-existing and both blocking legitimate traffic.

### R18-01 — an undeclared extra account had a privilege to mismatch (pre-existing, fixed)

An account past the end of a manifest's declared list is `remaining_accounts`:
the manifest says nothing about it. `resolve_accounts` gave such a slot the
placeholder `("extra", is_signer: false, is_writable: false)` and then compared
the real `AccountMeta` against that placeholder, so **every legitimate writable
remaining-account became a blocking `AccountIdentityMismatch`.**

Measured over 10,617 real mainnet transactions: 429 blocks on Pump AMM, 336 on
Pump.fun, 199 on the System Program, 72 on SPL Token — all on transactions the
chain had executed successfully. `remaining_accounts` is how a large part of
Solana works (route hops, batch refreshes, router fee accounts), so this was not
an edge case.

Fixed by computing `privilege_mismatch` only for a slot the manifest declares.
The extra accounts remain visible as `role: extra` and still feed the drainer and
account-count heuristics, which is where an account the manifest did not expect
belongs. Regression:
`privilege_mismatch::an_undeclared_extra_account_has_no_privilege_to_mismatch`
and `::extras_do_not_mask_a_real_privilege_mismatch_on_a_declared_slot`.
Deliberate break: with the fix reverted, the first fails and the other ten in
that file still pass.

### R18-02 — the Wormhole manifest named the wrong instruction for two bytes (pre-existing, fixed)

The decode census reported 29 observed instructions on the Wormhole core bridge
carrying tag `08` that **no manifest entry could name**, while the manifest
declared `PostMessageUnreliable` at `09` and `VerifySignatures` at `03`.

Against the program's own `solitaire!` dispatch order (0 Initialize,
1 PostMessage, 2 PostVAA, 3 SetFees, 4 TransferFees, 5 UpgradeContract,
6 UpgradeGuardianSet, 7 VerifySignatures, 8 PostMessageUnreliable,
9 ClosePostedMessage, 10 CloseSignatureSetAndPostedVAA), both were wrong:
`03` is SetFees and `09` is ClosePostedMessage. Graphite would have named a
`SetFees` instruction "VerifySignatures" — the mislabelled-discriminator class
Round 13 was about, sitting in a shipped manifest.

Corrected to `07` and `08`, with the reason recorded in each instruction's
`risk_rules`. The variants the manifest still does not model are left absent
rather than invented.

### R18-03 — the generator grounded PDAs it could not derive (introduced and fixed in this round)

The first cut of `idl_to_manifest.py` emitted a seed template for every PDA the
IDL declared. Two of those are not expressible in the repo's template grammar,
and both derive a wrong address:

- a seed whose **byte offset** into the instruction data sits after an argument
  of unknown width (`vec`, `option`, a `defined` struct). The first version
  guessed 8 bytes for anything it did not recognise, which is fine for a size
  estimate and wrong for an offset;
- a PDA the IDL says is derived **under a different program** — an associated
  token account is derived under the ATA program, not under the protocol. Three
  of the six grounded slots on Pump AMM's `buy` are of this kind.

Both now ground nothing rather than something wrong, which is the C26 rule the
generator's own docstring cites. Grounded slots fell from 1,571 to 1,140 across
the 96 manifests, and `AccountIdentityMismatch` over the sample fell from 1,022
to 544 across R18-01 and R18-03 together.

### Still open, and measured rather than closed

544 `AccountIdentityMismatch` blocks remain over the sample, most of them
`kind=privilege` on slots the manifest **does** declare as signers — the largest
groups are the System Program (199), Dynamic Bonding Curve (94), SPL Token (63)
and Meteora DAMM v2 (56), plus 85 `expected_address` mismatches on Jupiter V6.
The shape suggests instructions reached through CPI, where a PDA signs via
`invoke_signed` and the message header cannot show it — but that is a hypothesis,
not a diagnosis, and changing a blocking control on a hypothesis is how a gate
gets quietly weakened. It is written down here with its breakdown, reproducible
with `GRAPHITE_MAINNET_REASONS=<path>`, and left for the next round.

---

## 5. Documentation

Every Markdown file in the repository was reviewed. The living documents were
brought to the current state; the dated reports are history and were left
unedited **except** to carry the banner that says so — seven round reports and
two Phase-2 planning documents had no banner at all, which made
`CURRENT.md`'s claim that "every other file in `docs/` carries a banner pointing
here" untrue.

Corrections of substance, not just counts:

- The README's protocol table named the **wrong tier for four programs** (Drift
  and Kamino Lending as `Official Manifest` while their manifests said
  `BattleTested`; Raydium AMM V4 and Squads V4 the other way round). The table
  is now generated — `docs/protocol-coverage.md`, from the manifests and the
  evidence file — and `tests/docs_match_the_registry.rs` compares every row's
  program id, name, instruction count and **applied** tier against
  `load_seed_manifests()`, plus the README's headline counts. A hand edit fails
  CI.
- `ROADMAP.md` stopped at Round 12 and listed two Phase 3 gates that Rounds 9 and
  12 had already closed, contradicting its own entries higher up the page.
  Rounds 13–18 added; the two gates marked done with the round that did them.
- `graphite-core/CHANGELOG.md` stopped at Round 14. Rounds 15–18 added.
- `SECURITY.md`'s v1-message-format limitation said v1 was "live on devnet" and a
  "hard dependency on implementing it before the format reaches mainnet". It is
  on mainnet, and it is 17.2% of the sample. Restated with the measurement, and
  added as a Phase 3 gate.
- `docs/phase2-branch-strategy.md` still described `main` as frozen with all work
  on `phase2-development`. Marked superseded.
- `CONTRIBUTING.md`'s "Adding a Protocol Manifest" section was five lines that
  began "copy an existing manifest". Rewritten around where an instruction
  surface may come from, the registration points that are checked in both
  directions, the measurement step, and the rule that a submission writes
  `OfficialManifest` and nothing more.
- The protocol-manifest issue template and the PR checklist now ask for the same
  things.

---

## 6. What was verified

- `cargo test --all-features`: **1,562 passed, 0 failed, 12 ignored**
  (network-dependent). `--no-default-features --lib`: 320. `--no-default-features
  --features cli`: 1,366. `cargo clippy --all-targets --all-features -D
  warnings` clean; `cargo fmt --all --check` clean.
- The P10 promotion gate over the regenerated corpus: **11,407 of 11,420
  fixtures (99.9%)**, up from 7,537 fixtures before. The corpus grew with the
  registry because its dev split is manifest-driven.
- `tools/mainnet-sample` against 10,617 transactions from 8 finalized blocks
  fetched on 2026-09-22: 0 parse failures, 0 L2 discriminator-contradiction
  false positives, and the coverage figures in §1.
- 100 TypeScript tests in the SAK integration (typecheck clean, and the
  regenerated cross-language corpus shows no diff); 13 in the TypeScript SDK;
  Go `vet` and `go test ./...` clean; the console typechecks; 26 of 27 Python
  tests (see below); the Python AI layer's manifest cross-check extended to all
  129 manifests.
- Deliberate break for R18-01, recorded in §4.

### Honest non-results

- **`approved: 0` over the mainnet sample.** That is the documented cold-start
  contract, not a regression: a fresh core with no earned evidence caps a fully
  manifested protocol at 0.44 while the lowest built-in profile floor is 0.55.
  The sample measures parsing, identity and risk, not approval.
- **The Python `test_performance_smoke` fails on this machine** (6,494 parses/sec
  against a 10,000 threshold) and passed in CI for Round 17. It is machine-
  dependent and was not touched.
- **23 of the 129 manifests do not clear the bar, and are recorded as they
  are.** Eight fall short on volume alone (Marginfi v2 503, Escrow 399, tcomp
  340, Store 253, OCR2 249, Oridion 217, the legacy SPL Memo program 827,
  Tarb 31 successful transactions within the paging budget). Three are the Memo
  family, whose manifests declare no discriminators at all — the whole data
  field IS the memo — so the decode axis does not apply and says so rather than
  reporting 0%. Two could not be sampled: Drift's recent signatures are
  transactions that carry its address without invoking it, and Switchboard v2
  has 59 successful transactions in the window at all. The remaining ten are the
  interesting ones: **their manifests genuinely do not describe what the program
  is being asked to run.** Metaplex Token Metadata names 4% of its observed
  traffic (the unified V2 instruction set — tags 44/45/47/49 — is not modelled),
  Bubblegum 6% (the on-chain IDL predates the V2 instructions in use), Rush 3%,
  Account Compression, Light System Program and Pump Fees 0% each, with one
  unnamed discriminator dominating each of their traffic. Naming those
  instructions needs a source for their account layouts that this round did not
  have, and guessing one is the C26 failure mode. Every unnamed leading byte is
  recorded in `battle_tested_evidence.json`, so the next round starts from a
  list rather than a search.

---

## 7. Files

**New:** `graphite-core/scripts/solana_keys.py`,
`solana_inventory_census.py`, `fetch_onchain_idls.py`, `idl_to_manifest.py`,
`onboard_from_inventory.py`, `merge_onchain_idl.py`, `battle_tested_census.py`,
`render_coverage.py`; `graphite-core/protocols/battle_tested_evidence.json` and
96 manifests; `graphite-core/tests/battle_tested_evidence.rs`,
`tests/docs_match_the_registry.rs`; `docs/protocol-coverage.md`.

**Changed:** `src/manifest.rs` (one `SEED_MANIFESTS` list replacing two
hand-maintained ones, the evidence gate, `load_manifest`),
`src/account_resolution.rs` (R18-01), `src/risk_engine.rs` (`is_swap_program`
reads the manifests), `src/live_corpus.rs`; `tests/privilege_mismatch.rs`,
`tests/regression_corpus.rs`, `tests/mainnet_conformance.rs`,
`tests/deep_extreme_tests.rs`, `tests/protocol_expansion_tests.rs`;
`protocols/verified_program_ids.json`, `spl-token.json`, `token-2022.json`,
`wormhole-core.json` and the six merged manifests;
`python-ai-layer/test_intent_parser.py`; `tools/mainnet-sample/fetch_mainnet.py`;
and the documentation listed in §5.
