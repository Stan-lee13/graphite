# Clean install (single node, Docker Compose)

One node means one Core process. Running several replicas, behind a load
balancer or on one volume, is unsupported: the Core keeps its audit trail's
head, its semantic graph and its rate limiter in its own process and locks its
data directory (`graphite.lock`), so a second copy on the same volume refuses
to start and one on another volume is a second, disjoint trail. Never
`docker compose up --scale graphite=2`. For production use
`deploy/compose/docker-compose.prod.yml` (TLS edge, file-backed secrets, a
release pinned by digest, one replica enforced) and
[production-checklist.md](production-checklist.md); this page is the
build-from-source stack.

1. **Check out a tagged release**, not a branch head:
   `git clone https://github.com/Stan-lee13/graphite && cd graphite && git checkout v<version>`.
   Confirm CI was green on that commit (Actions tab, the `CI gate` check).

2. **Create the environment file** from the template and lock it down:
   ```sh
   cp .env.example .env && chmod 600 .env
   ```
   Set at least:
   - `GRAPHITE_API_KEY` — `openssl rand -hex 32`. Required; fewer than 32
     characters refuses to start.
   - `GRAPHITE_RPC_URL` — your RPC provider. Without it nothing is simulated:
     L3 is inconclusive on every verdict and the `not_simulated` residual is
     reported, so no verdict is safe to sign on. The agent guard refuses such a
     verdict by default; a direct `/verify` caller must refuse it too.
   - `GRAPHITE_RPC_WITNESS_URL` — a second RPC **from a different provider**
     for L8 inclusion checks. Two URLs on one provider are one witness.
   - `GRAPHITE_WALLET_PROFILE` — pin the policy profile whenever the caller is
     not the wallet operator (an agent's request body would otherwise choose it).
   - `GRAPHITE_ADMIN_API_KEY` — only if you will use `/admin/*`; must differ
     from the verify key. Unset disables `/admin/*`.

   Leave `GRAPHITE_DEV_MODE`, `GRAPHITE_ALLOW_PERMISSIVE_PROFILES`,
   `GRAPHITE_ALLOW_DURABLE_NONCE`, the two L4 relaxations
   (`GRAPHITE_ALLOW_UNREADABLE_VALUE_DECLARATIONS`,
   `GRAPHITE_ALLOW_SIGNER_LAMPORTS_OUTSIDE_DECLARED_DEBIT`) and the intent-grant
   relaxation `GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS` unset unless you have read what each
   one opens in `.env.example`. `GRAPHITE_ALLOW_UNBOUNDED_WITHDRAWALS=1` waives two
   checks, not one: the grant refusal `UnboundedWithdrawal` (a zero minimum output) and
   the withdrawal binding `WithdrawalUnderbounded` (minimum outputs held to the simulated
   credit, and a Meteora DLMM remove with no minimum held unbound). It never waives what
   rides beside the withdrawal: a sibling instruction that skims the payout is refused
   either way (Round 38, R37-1).

3. **Validate, then start.** On a new data volume, import the measured
   census first ([below](#first-start-import-the-measured-census)): it takes
   the data directory's lock, so it runs before the Core does (or with the
   Core stopped).
   ```sh
   docker compose config --quiet          # fails on an empty GRAPHITE_API_KEY
   docker compose up -d --build
   docker compose ps                      # wait for (healthy)
   ```
   The compose healthcheck is `graphite healthcheck --strict`: the container is
   `unhealthy` whenever `/health` reports `degraded: true`.

4. **Smoke-test it** from the host:
   ```sh
   curl -s http://127.0.0.1:7331/health                          # degraded: false
   curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:7331/api/graph   # 401
   curl -s -H "Authorization: Bearer $GRAPHITE_API_KEY" http://127.0.0.1:7331/api/graph >/dev/null && echo ok
   ```

5. **Put TLS in front.** The container publishes on host loopback only. Front
   it with a reverse proxy that terminates TLS, then set
   `GRAPHITE_TRUST_PROXY` to the exact number of proxy hops you control
   (`1` for one nginx/ALB). Never higher: an over-count lets a caller choose
   its own rate-limit bucket through `X-Forwarded-For`.

6. **Wire the signals** into your monitoring before taking traffic:
   - `/health` → alert on `degraded: true`; `degraded_reasons` names the cause.
   - `/metrics` (authenticated) → audit write/rotation failures, snapshot
     failures, refusals by layer.
   - A periodic `graphite execution` reconciliation for each signed
     transaction (exit codes in incidents.md), run with the server's
     `GRAPHITE_AUDIT_KEY_FILE`: since Round 38 it reads a keyed trail only
     with its key, and is unavailable (exit 3) without it (keys.md).

7. **Back up the volume** (backup-restore.md) before the first real traffic,
   so a restore procedure has been run once while nothing depends on it.

## First start: import the measured census

A fresh Core approves nothing on the built-in profiles. Half the confidence
weight comes from evidence the Semantic Graph holds (simulation matches,
historical volume, community attestations), and a new data directory holds
none, so a manifested program's verdict sits at 0.44 against the weakest
built-in bar (Gaming, 0.55). `graphite evidence import-census` (Round 40)
fills one of those signals, HistoricalVolume, from a measurement the
repository commits, instead of from a number typed into `graphite evidence
seed --battle-tested`.

**What it does.**

- Reads `graphite-core/protocols/battle_tested_evidence.json` as compiled into
  the binary: a read-only mainnet-beta census of each manifested program
  (successful transactions carrying its address over a stated window, and the
  share of really-observed instructions its manifest names), reproduced by
  `graphite-core/scripts/battle_tested_census.py`. With `--census <file>` it
  checks that file instead, and refuses it unless it is byte-identical to the
  compiled-in copy (SHA-256), so an edited census cannot be imported.
- Checks the census first (schema; the bar it states is the bar the binary
  applies; each record's own verdict agrees with its measurements).
- Imports only records that clear every threshold (1,000 successful
  transactions, 20 instructions observed, a decode rate of 0.9 recomputed
  against the loaded manifest) for a program that exists, is executable and
  has a loaded manifest. Every other record is listed as `SKIP` with its
  reason. At this commit that is 114 of 137 records.
- Appends, per program, the record in force with `battle_tested_tx_count`
  raised to the census count. Every other field is carried over; nothing is
  lowered; no signature is asserted. The trust tier is recomputed from the
  evidence, never set (Constitution P7). The evidence is bound to the census
  window's oldest slot.
- Writes one `operator_action` row per imported program on the audit trail,
  naming the source: `census-measured, battle_tested_evidence.json
  sha256=<hash>, measured_at <time>`. An import the trail cannot record fails
  loudly and says which imports are in force, as `evidence seed` does.

**What it does not do.**

- It changes no floor, ceiling, profile threshold or tier rule, and runs only
  when you run it: a Core that never runs it behaves as before. Nothing on the
  HTTP surface reaches it.
- It does not lift a verdict's tier on a fresh Core: the graph tier it
  produces is HeuristicInferred and a manifested program's verdict tier stays
  OfficialManifest. Confidence rises from 0.44 to 0.59 for a program alone
  (Gaming only; TradingBot, Treasury and Enterprise require a higher tier and
  still refuse). Every other layer (L2 to L8, the intent binding, the risk
  engine, the residual gate) decides as before.
- It does not import a quarantined program, a program the census measured
  below the bar, or a program whose deployment the Core has seen change after
  the census window began (`census predates the program's last observed
  deployment`). An upgrade the Core observes after the import withdraws the
  imported volume like any other evidence (Round 30), and a re-run does not
  bring it back.
- It is mainnet-beta evidence. Do not import it on a Core that verifies
  devnet, testnet or a local validator (the live-devnet runner imports only
  the System program, a builtin that is the same code on every cluster).
- It does not make the census fresher than it is: re-measure with
  `scripts/battle_tested_census.py` (it reads a public RPC) and commit the
  result to move it forward.

**Run it** with the server's environment, the server stopped (it takes the
data directory's lock), and the server's `GRAPHITE_AUDIT_KEY_FILE` when the
trail is keyed ([keys.md](keys.md): an unkeyed import on a keyed trail is
refused before anything changes):

```sh
docker compose run --rm --no-deps graphite graphite evidence import-census --dry-run
docker compose run --rm --no-deps graphite graphite evidence import-census
# Built from source:
graphite evidence import-census --data-dir "$GRAPHITE_DATA_DIR" --dry-run
graphite evidence import-census --data-dir "$GRAPHITE_DATA_DIR"
```

`--dry-run` prints, per program, the census count, the graph tier the
evidence recomputes to, and the verdict tier and confidence before and after,
and writes nothing. `--program <id>` (repeatable) imports only those programs.
Running it again is safe: a program whose record already holds at least the
census count is skipped.

**Verify it.**

1. The hash it printed (`CENSUS battle_tested_evidence.json sha256=…`) is the
   committed file's: `sha256sum graphite-core/protocols/battle_tested_evidence.json`
   in a checkout of the same tag. `--census <that file> --dry-run` makes the
   binary compare them for you.
2. `graphite evidence show --program 11111111111111111111111111111111`
   shows `battle_tested=` the System Program's census count and
   `signed_manifest=false`; the trust tier is HeuristicInferred.
3. `graphite audit verify` (with `--key-file` on a keyed trail) exits 0, and
   the trail holds one `operator_action` row per imported program whose
   `detail` starts `evidence imported for <program> (census-measured, …`.
4. After the server starts, a verdict on an imported program carries the
   breakdown item `HistoricalVolume` with `raw_value` 1.0. For an imported
   program under the upgradeable loader (or loader-v4), the first verdict
   that reads its deployment reports `ProgramEvidenceWithdrawn` when the
   deployment is newer than the census window, and the volume is gone.
