# Graphite MCP server

Graphite's verified fund-moving tools for any [Model Context Protocol](https://modelcontextprotocol.io)
client — Claude, Cursor, ElizaOS's MCP plugin, LangChain's MCP adapters, the AI SDK's MCP
client. Each tool executes only through [`GraphiteGuard`](../agent-guard/README.md): the
request is grounded in its own words, ONE transaction is built, Graphite Core verifies
those exact bytes, and the guard signs only on an artifact-bound approval. Status is the
project's: security-hardened alpha, no independent third-party audit yet
([docs/CURRENT.md](../../docs/CURRENT.md)).

Built on the official `@modelcontextprotocol/sdk` 1.x. Its lockfile has no npm advisory at
any level, and CI fails on any high or critical one (`.github/npm-audit/mcp-server.allow`).

## Running it

```bash
(cd integrations/agent-guard && npm ci --ignore-scripts)
cd integrations/mcp-server && npm ci --ignore-scripts

SOLANA_PRIVATE_KEY=<agent wallet secret key, base58> \
SOLANA_RPC_URL=https://api.devnet.solana.com \
GRAPHITE_CORE_URL=http://127.0.0.1:7331 GRAPHITE_API_KEY=<the Core's key> \
GRAPHITE_MAX_TRANSFER_LAMPORTS=100000000 \
npx tsx server.ts
```

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
  allowlist of destinations (`GRAPHITE_ALLOWED_DESTINATIONS`). The server refuses to start
  without the cap. A transfer's amount and destination are checked before anything is
  built. A swap's outflow is measured by simulating the exact transaction (lamports out of
  the wallet, fee and wrapped SOL included) before it is signed: over the cap is refused,
  and so is a swap that spends any other token, which a lamport cap cannot price.
- **A person confirms every fund-moving call** (`GRAPHITE_MCP_CONFIRMATION=elicit`, the
  default): the server asks through MCP elicitation, showing the request the guard will act
  on. A client that cannot elicit is refused, not executed for. Running without a person in
  the loop takes `GRAPHITE_MCP_CONFIRMATION=none`, said explicitly.
- **stdout carries only the protocol.** Every log line, the guard's included, goes to
  stderr.

## Tests

```bash
npm run typecheck && npm test
```

The tests drive the server through the SDK's own `Client`: the tools a client sees and
their hints, a person approving (the request runs through the guard) and declining or
cancelling (nothing is built, verified or sent), a client that cannot elicit, the cap, the
confirmation setting, and the stdio server started as its own process — which shows the
guard's logs never reach stdout.
