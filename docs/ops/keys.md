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

## Read key (`GRAPHITE_READ_API_KEY`)

Optional, Round 30. Opens only `GET /metrics`, `/manifests` and `/api/*` — the
routes the dashboard reads — and cannot submit a verification, record a
lifecycle event or reach `/admin/*`. Give it to the dashboard instead of the
verify key. It must be at least 32 characters, differ from both other keys,
and needs `GRAPHITE_API_KEY` set; the server refuses to start otherwise.
Rotate it the same way as the verify key.

## Audit MAC key (`GRAPHITE_AUDIT_KEY_FILE`)

Round 30. With this set, every audit record's chain link carries an
HMAC-SHA256 under the key, and the trail is tamper-evident against anyone who
does not hold it. The file is hex for at least 32 bytes, mode 600 or
stricter, owned by the server's user (10001 in the image), and outside
`GRAPHITE_DATA_DIR`:

```sh
openssl rand -hex 32 > audit-2026q4.key
chmod 600 audit-2026q4.key        # chown 10001:10001 for the container
```

Each record names the key it was MAC'd under (`key_id`, derived from the key),
so a rotation needs no rewrite:

1. Generate the new key file next to the old one; keep the old one.
2. Point `GRAPHITE_AUDIT_KEY_FILE` at the new file and restart. Records from
   now on are MAC'd under the new key; the chain continues across the switch.
3. Verify the whole trail with both keys:
   `graphite audit verify --key-file audit-2026q3.key --key-file audit-2026q4.key`.
   Exit 0 means every link and every MAC checked; with only the new key the
   older MACs cannot be checked and the walk exits 2.
4. Keep retired keys for as long as you keep the records they cover, off the
   server (an attacker holding a key can rewrite what it covers).

A lost key cannot be replaced silently: the server refuses to continue a keyed
trail without a key ("no key is configured"). Start the new key as in step 2;
the records under the lost key then verify as chained but not MAC'd.

Checkpoints (`graphite audit checkpoint --out <file>`, or automatically at
each rotation into `GRAPHITE_AUDIT_ANCHOR_DIR`) are what catch a dropped tail
or a restored older backup; ship them to storage the server cannot rewrite
(WORM, object lock) and pass one to `graphite audit verify --checkpoint`.

## Registry signing keys

`graphite registry submit` signs with the ed25519 key in
`GRAPHITE_SIGNER_KEY_FILE` (or `--signer-key-file`). Keep that file mode 600 on
the reviewer's machine, never on the server. A compromised reviewer key is
revoked with `graphite registry revoke-reviewer --pubkey <base58>`; its
signatures and attestations stop counting and the tiers they helped earn are
recomputed.
