# Graphite + Solana Agent Kit Integration

Real, production-ready integration that verifies every SAK transaction through Graphite Core before execution.

## Architecture

```
Natural Language → Python AI Layer (parse intent) → SAK (construct tx) → Graphite Core (verify) → SAK (execute if approved)
```

Constitution P1 (AI assists, never decides): The AI Layer only parses intent — it does not verify or approve. Graphite Core's deterministic verification engine makes all security decisions. SAK only executes if Graphite approves.

## Prerequisites

1. **Graphite Core** running:
   ```bash
   cd graphite-core
   GRAPHITE_API_KEY=$(openssl rand -hex 32) cargo run --release -- server
   # or GRAPHITE_DEV_MODE=1 for an unauthenticated loopback-only instance
   ```

2. **Python AI Layer** running:
   ```bash
   cd python-ai-layer
   python3 intent_parser.py --serve
   ```

3. **Environment variables**:
   ```bash
   export SOLANA_PRIVATE_KEY="your_base58_private_key"
   export SOLANA_RPC_URL="https://api.devnet.solana.com"
   export OPENAI_API_KEY="your_openai_api_key"
   ```

## Installation

```bash
cd integrations/solana-agent-kit
npm install
```

## What the bridge guarantees

The bridge is the reference execution boundary for Graphite. Its invariant, attacked in
Rounds 6–9 (`docs/round6-execution-boundary-2026-09-11.md` onward): **the exact
message Graphite approved is the exact message in the bytes that are signed and
submitted — and nothing is signed under a residual the operator has not accepted.**

- Both `executeTransfer` and `executeSwap` build **one** `BoundTransaction`
  (`artifact.ts`) *before* verification, from deep-copied instructions, and send its
  bytes as `signed_transaction`. No alias to the transaction exists outside it.
- Execution requires `scope.kind === "artifact_bound"`. A descriptive verdict never
  executes.
- **Residual policy (Round 9).** Every verdict names what Graphite did not observe as
  codes (`scope.unobserved_codes`). Two are inherent to every artifact-bound verdict
  (`program_semantics`, `inner_instructions`). Every other code — `no_state_diff`,
  `not_simulated`, `privileges_from_caller`, `privileges_absent`,
  `lookup_tables_unresolved`, `artifact_unparsed`, `account_identity_unparsed`,
  `instruction_not_located` — **refuses execution** unless the operator names it in
  `GRAPHITE_ACCEPT_UNOBSERVED` (comma-separated) or `create({ acceptUnobserved })`. A
  typo in that list is a startup error; a Core that reports no codes (pre-Round-9) is
  refused. The codes accepted for an execution are recorded on
  `outcome.lifecycle.acceptedUnobserved`. See `residual-policy.ts`.
- **The lifecycle is on Graphite's trail, in order (Round 9).** `execution-lifecycle.ts`
  is the only path from verdict to network: policy → `signApproved` → `POST /audit/event`
  `signing` → submit → `POST /audit/event` `submission` → confirm → `POST
  /verify/execution` (L8). A signing that cannot be recorded, or whose
  `verdict_on_record` is not `approved`, aborts *before* submission; after submission
  every failure is reported on `outcome.lifecycle` and none is hidden.
- `bound.signApproved(scope.transaction_sha256, [wallet])` is the only signing path: it
  recomputes the digest of the exact bytes, derives the required signer set from the
  compiled message, refuses any mismatch, and returns the only bytes that go to
  `sendRawTransaction`. A refreshed blockhash, changed fee payer, appended instruction,
  rewritten amount or flipped flag after approval is refused.
- `executeSwap` requires the built payload (program id, discriminator, accounts with
  real flags, data). Without it there is nothing to bind and the bridge aborts. Setting
  `GRAPHITE_SWAP_ALLOW_UNVERIFIED_EXECUTION=I_ACCEPT_UNVERIFIED_SWAP_EXECUTION` — a
  phrase, so it is not set by accident — lets SAK's own builder execute a swap Graphite
  never saw; the outcome then says `verifiedExecution: false` with `unverifiedReason`.
- Durable-nonce shapes are refused at build: `lastValidBlockHeight` does not bound them.
- `scope.unobserved` is printed for every verdict; which residuals a deployment
  accepts is the deployment's decision, made in configuration and enforced by the
  residual policy above.
- `content_hash` / AuditBind (`auditbind.ts`) remains as a secondary instruction-level
  check and the audit/L8 join key; the digest is the authoritative binding.

## Usage

### Run the end-to-end demo:

```bash
# Swap demo
npx tsx demo.ts "Swap 0.1 SOL for USDC"

# Transfer demo
npx tsx demo.ts "Transfer 0.05 SOL to 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
```

### Use the bridge in your own code:

```typescript
import { VerifiedSakAgent } from "./graphite-sak-bridge.js";

const agent = await VerifiedSakAgent.create({
  // or GRAPHITE_CORE_URL / GRAPHITE_API_KEY / GRAPHITE_AI_LAYER_URL / GRAPHITE_WALLET_PROFILE
  graphiteCoreUrl: "http://localhost:7331",
  graphiteApiKey: process.env.GRAPHITE_API_KEY,
});

// Every transaction is built once, verified as those exact bytes, and signed only on
// an artifact_bound approval whose digest matches.
const outcome = await agent.executeTransfer("Transfer 0.05 SOL to <address>");

if (!outcome.executed) {
  console.log("Blocked by Graphite:", outcome.verification.risk_verdict.findings);
} else if (!outcome.verifiedExecution) {
  console.log("Executed WITHOUT verification (opt-out):", outcome.unverifiedReason);
} else {
  console.log("Verified execution:", outcome.signature);
}
```

`ExecutionOutcome` is `{ executed, verifiedExecution, verification, signature?,
unverifiedReason?, lifecycle? }`. Gate on `verifiedExecution`, not on `executed`: the
latter is also true for the opt-out path. `lifecycle` (every verified execution) is
`{ signature, acceptedUnobserved, signingRecorded, verdictOnRecordAtSigning,
submissionRecorded, submissionRecordError?, confirmed, confirmationError?,
reconciliation?, reconciliationError? }` — read `reconciliation.discrepancy` for L8's
verdict on what actually landed.

### Tests and the cross-language corpus

```bash
npm run typecheck
npm test                 # 95 tests: BoundTransaction gate, execution-boundary fuzz,
                         # TOCTOU signing boundary, AuditBind, artifact, nonces,
                         # residual policy, execution lifecycle
npm run emit:corpus      # regenerates graphite-core/fixtures/artifacts/sak_bridge_corpus.json
                         # (12 shapes + 1,647 byte-level mutations); CI fails on drift
npm run emit:artifact-fixture
```

## What Graphite Verifies

Before the bridge signs anything, Graphite checks:

- **L1 Account Resolution**: accounts, PDAs and fixed constants; signer/writable privileges read from the transaction's own header and resolved lookup tables
- **L2 Instruction Verification**: the described instruction is in the bytes, positionally, every sibling is declared, and the transaction is not durable-nonce based
- **L3 Simulation Integrity**: compute/writes/CPI hops against earned baselines (live with `GRAPHITE_RPC_URL`; `Inconclusive` without)
- **L4 State Verification**: Graphite's own pre/post diff against the manifest; Token-2022 extensions classified
- **L5 Semantic Verification**: intent ↔ instruction alignment
- **L6 Policy Verification**: confidence against the wallet profile threshold
- **L7 Risk Verification**: drainers, authority hijacks, fake swaps, impersonation, multi-instruction and CPI-trace patterns

If any hard gate fails, the transaction is NOT signed. After submission, `POST
/verify/execution` reconciles the signature against the recorded verdict (L8).

## Wallet Profiles

Graphite enforces different confidence thresholds per wallet profile:

| Profile | Min Confidence | Min Trust Tier |
|---------|---------------|----------------|
| Treasury | 95% | CommunityVerified |
| TradingBot | 80% | SimulationValidated |
| Gaming | 55% | HeuristicInferred |
| Enterprise | 99% | BattleTested |

Set via `GRAPHITE_WALLET_PROFILE` (or `config.walletProfile`). When the Core pins a
profile server-side with its own `GRAPHITE_WALLET_PROFILE`, the request's profile is
ignored — the operator's policy wins over the agent's.

**Fresh-core calibration:** the evidence-derived confidence signals read the Core's
semantic graph, so on a fresh core (no earned evidence, no RPC) the highest reachable
confidence for a known, clean, intent-aligned protocol is **~0.44** and every built-in
profile blocks. The bridge defaults to `Custom { min_confidence: 0.40, min_trust_tier:
OfficialManifest }` so known transactions can be approved for development; a `Custom`
profile below 0.55 requires `GRAPHITE_ALLOW_PERMISSIVE_PROFILES=1` on the Core. The
engine's confidence score is always the honest number; the profile is the operator's
policy choice.
