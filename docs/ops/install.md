# Clean install (single node, Docker Compose)

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
   one opens in `.env.example`.

3. **Validate, then start:**
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
     transaction (exit codes in incidents.md).

7. **Back up the volume** (backup-restore.md) before the first real traffic,
   so a restore procedure has been run once while nothing depends on it.
