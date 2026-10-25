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

   RPC egress must be direct (Round 40, R39-CB-13). The Core's RPC and
   witness clients ignore `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and
   `NO_PROXY`: every connection goes straight to the provider's address, and
   the connect-time address guard judges that address. Through an environment
   proxy the guard would judge only the proxy's address, and the proxy would
   resolve the provider's host name itself — a name that resolves to a private,
   loopback or metadata address would reach it without the guard seeing it.
   If the host can only reach the internet through a proxy, allow the RPC
   providers' addresses through the firewall instead; a forward proxy in
   front of the Core's RPC traffic is not supported.
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

   Then set `GRAPHITE_TRUSTED_PROXIES` to the address (or CIDR range) the
   proxy connects to the Core FROM, as the Core sees it (Round 40, R39-CB-8):
   `127.0.0.1,::1` for a proxy on the same host talking to loopback; for a
   proxy outside the container reaching the published port, the address the
   connection arrives from inside the container (the Docker bridge gateway,
   typically `172.17.0.1` — the Core logs the list it trusts at startup and,
   at most once a minute, the address of a peer whose `X-Forwarded-For` it
   ignored). `X-Forwarded-For` is believed only on a connection from a listed
   address; any other peer is rate-limited by its own address. The server
   refuses to start with `GRAPHITE_TRUST_PROXY` of 1 or more and
   `GRAPHITE_TRUSTED_PROXIES` unset or empty, and on an entry that is not an
   IP address or CIDR range. List the proxy only: a range wide enough to
   include other hosts or containers lets each of them choose its own
   rate-limit bucket.

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
