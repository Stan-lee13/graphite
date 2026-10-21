# Key and credential rotation

The server takes exactly one verify key (`GRAPHITE_API_KEY`) and at most one
operator key (`GRAPHITE_ADMIN_API_KEY`), read at startup. There is no overlap
window with two valid keys, so a rotation is a coordinated restart: the old key
stops working the moment the new process starts. Plan it as a short
maintenance window, or put an authenticating proxy in front that can hold two
keys while clients move.

Every key is at least 32 characters; the operator key must differ from the
verify key (the server refuses to start otherwise). Generate with
`openssl rand -hex 32`. Keys never belong in the image, in compose YAML, in a
shell history or in a ticket: `.env` (mode 600) or your secret store only.

## Verify key (`GRAPHITE_API_KEY`)

Held by every client: the agent guard, the SAK/MCP/Vercel adapters, the SDKs,
the dashboard.

1. Generate the new key and stage it in each client's secret store, unused.
2. Set it in `.env`, then `docker compose up -d` (recreates the container).
3. Switch each client to the new key; restart them.
4. Confirm: the old key now gets `401`; each client's next verification
   succeeds; `/metrics` shows no burst of authentication failures beyond the
   switch-over.
5. Rotate immediately, outside any schedule, if the key may have leaked: a
   verify key lets its holder submit verifications (and read the dashboard
   API), so a leaked key is a rate-limit and data-exposure problem first.

## Operator key (`GRAPHITE_ADMIN_API_KEY`)

Used only for `/admin/*` (quarantine add / lift / list). Unset disables those
routes entirely, which is the right state when nobody is using them. The CLI
(`graphite quarantine …`) works on the data directory directly and needs no
key. Rotate it the same way as the verify key; nothing but the operator's own
tooling holds it.

## RPC credentials (`GRAPHITE_RPC_URL`, `GRAPHITE_RPC_WITNESS_URL`)

These URLs usually embed a provider API key. Graphite redacts them from errors
and never logs them, but treat them as secrets. Rotate at the provider, update
`.env`, `docker compose up -d`. Keep the witness on a different provider from
the primary; after the change, `docker compose logs` shows the startup
validation of both URLs.

## Registry signing keys

`graphite registry submit` signs with the ed25519 key in
`GRAPHITE_SIGNER_KEY_FILE` (or `--signer-key-file`). Keep that file mode 600 on
the reviewer's machine, never on the server. A compromised reviewer key is
revoked with `graphite registry revoke-reviewer --pubkey <base58>`; its
signatures and attestations stop counting and the tiers they helped earn are
recomputed.
