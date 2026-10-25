# Graphite MCP server

Graphite's verified fund-moving tools for any [Model Context Protocol](https://modelcontextprotocol.io)
client — Claude, Cursor, ElizaOS's MCP plugin, LangChain's MCP adapters, the AI SDK's MCP
client. Each tool executes only through [`GraphiteGuard`](../agent-guard/README.md): the
request is grounded in its own words, ONE transaction is built, Graphite Core verifies
those exact bytes, and the guard signs only on an artifact-bound approval. Status is the
project's: security-hardened alpha, no independent third-party audit yet
([docs/CURRENT.md](../../docs/CURRENT.md)).

Built on the official `@modelcontextprotocol/sdk` 1.x (1.32.1 or later: GHSA-22jm-h49p-29qw
and GHSA-6prh-2h8m-c8cw affect earlier versions). Its lockfile has no npm advisory at any
level, and CI fails on any high or critical one (`.github/npm-audit/mcp-server.allow`).

## Running it

```bash
(cd integrations/agent-guard && npm ci --ignore-scripts)
cd integrations/mcp-server && npm ci --ignore-scripts

SOLANA_PRIVATE_KEY=<agent wallet secret key, base58> \
SOLANA_RPC_URL=https://api.devnet.solana.com \
GRAPHITE_CORE_URL=http://127.0.0.1:7331 GRAPHITE_API_KEY=<the Core's key> \
GRAPHITE_MAX_TRANSFER_LAMPORTS=100000000 \
npx tsx server.ts        # or: npm start
```

The package is private and has no `bin`: it is run from source with `tsx`.

A client configuration (for example Claude Desktop's `mcpServers`) runs the same command
with the same environment. This is the real path: a confirmed request that Graphite
approves is signed and submitted on whatever cluster `SOLANA_RPC_URL` names.

| Tool | Input | Hints |
|---|---|---|
| `graphite_wallet` | — | read-only |
| `graphite_transfer_sol` | `request`: the user's request in their own words | destructive |
| `graphite_swap` | `request`, and `route`: the EXACT route instruction from a route API | destructive |

## Bounds that hold whatever the client's model writes

- **Graphite's verdict** on the exact bytes, as in every integration.
- **A per-transaction cap is required** (`GRAPHITE_MAX_TRANSFER_LAMPORTS`); optionally an
  allowlist of destinations (`GRAPHITE_ALLOWED_DESTINATIONS`) and an aggregate limit over a
  rolling window (`GRAPHITE_MAX_TOTAL_LAMPORTS`, `GRAPHITE_SPEND_WINDOW_SECONDS`; durable
  across restarts with `GRAPHITE_GUARD_STATE_FILE`). The server refuses to start without the
  cap, even when the guard has been told to run uncapped. A transfer's amount and
  destination are checked before anything is built. Both limits count what the wallet pays
  (Round 32): a transfer's amount plus its network fee, or what a simulation of the exact
  bytes takes out of the wallet, whichever is larger — so a transfer of exactly the cap is
  refused.
- **One guard per wallet** (Round 32). The aggregate limit is kept per guard, so the server
  takes a lock named for its wallet and refuses to start while another guard (another MCP
  server, a CLI run, an SDK-built guard) holds the same wallet on this host for the same
  OS user. Since Round 34 the lock lives where no temp cleaner removes it, and since
  Round 38 (R37-17) the default is one directory per user that no session variable moves
  (`GRAPHITE_GUARD_LOCK_DIR`, else `<home>/.local/state/graphite-guard`, `<home>` being the
  account's home directory, not `$HOME`; on Windows `<profile>\AppData\Local`), so a
  server started from a login session and a guard started from cron find the same lock.
  It is re-checked before every spend: a server whose lock
  was deleted refuses to move funds until it is restarted. `GRAPHITE_GUARD_ALLOW_SHARED_WALLET=1`
  lets a second guard start, and the limits then hold per guard, not per wallet. Guards
  on other hosts or in other containers are not seen; one per wallet across them is the
  operator's to arrange. See the guard's README. A swap's outflow is measured by simulating the exact transaction (lamports out of
  the wallet, fee and wrapped SOL included) before it is signed: over the cap is refused,
  and so is a swap that spends any other token, which a lamport cap cannot price.
- **The swap must be the one the user asked for.** The amount and both tokens are read
  from the request's own text, and the simulated transaction must spend no more than that
  amount of that token, spend nothing else, and deliver the requested token. A request that
  negates or cancels what it names ("don't send …") is refused, and so is anything that is
  not the accepted form ("send <amount> SOL to <address>"; for swaps "swap <amount> <token>
  for <token>", optionally with "for at least …" and "with <n>% slippage"). A swap's route
  must be an exact-in instruction the guard decodes, and its own minimum output must meet a
  price floor and sit within the allowed slippage of the simulated output.
- **A person confirms every fund-moving call** (`GRAPHITE_MCP_CONFIRMATION=elicit`, the
  default). Since Round 29 (audit 2026-10-20, M7) the person is asked by the guard's
  confirmation hook — after grounding, the spend policy, the build, the simulation,
  Graphite's verdict and the residual policy, immediately before signing — and is shown the
  RESOLVED transaction: destination and amount (or the route's amounts, minimum and price
  floor), the program, the simulated effect on the wallet and the verdict. Nobody is asked
  to approve what the cap or Graphite has already refused, and a decline aborts with
  nothing signed or sent. A client that cannot elicit is refused before anything is built.
  Running without a person in the loop takes `GRAPHITE_MCP_CONFIRMATION=none`, said
  explicitly.
- **stdout carries only the protocol.** Every console method that writes to stdout (`log`,
  `info`, `debug`, `dir`, `table`) is redirected to stderr, the guard's logs included.

## Tests

```bash
npm run typecheck && npm test
```

The tests drive the server through the SDK's own `Client`: the tools a client sees and
their hints, a block that asks nobody, a person approving the resolved transaction (which
then executes against a loopback Core that approves with the real digests) and declining or
cancelling (verified, but nothing signed, recorded or sent), a client that cannot elicit,
the cap, the confirmation setting, and the stdio server started as its own process — which
shows the guard's logs never reach stdout. (Test counts for every package: [docs/CURRENT.md](../../docs/CURRENT.md#numbers-as-of-this-pages-commit).)
