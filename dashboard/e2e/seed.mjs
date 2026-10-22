// Seeds a running Core with verdicts for the browser smoke test (Round 32).
//
// The smoke checks that every verdict the console draws green is one the
// Core reported `executable_approved`. Against an empty trail that check has
// no rows to look at, so CI seeds one verdict of each kind a Core without an
// RPC can produce, through `POST /verify`, and refuses to go on unless the
// trail holds them:
//   - a descriptive approval (no bytes),
//   - a transaction-bound approval the Core could not simulate — the
//     verdict the colour rule exists for: approved, bound, and NOT
//     executable, so it must be drawn amber,
//   - two refusals (a CPI to an unverified target, an unspendable
//     destination).
// No dependencies: the bound transfer is built byte by byte.
//
// Usage: node e2e/seed.mjs http://127.0.0.1:7331 "$GRAPHITE_API_KEY"

const [coreBase, key = ""] = process.argv.slice(2);
if (!coreBase) {
  console.error("usage: node e2e/seed.mjs <core-base> [api-key]");
  process.exit(2);
}

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58(s) {
  let n = 0n;
  for (const c of s) {
    const d = ALPHABET.indexOf(c);
    if (d < 0) throw new Error(`not base58: ${s}`);
    n = n * 58n + BigInt(d);
  }
  const out = [];
  while (n > 0n) {
    out.unshift(Number(n % 256n));
    n /= 256n;
  }
  for (const c of s) {
    if (c !== "1") break;
    out.unshift(0);
  }
  if (out.length !== 32) throw new Error(`not a 32-byte key: ${s}`);
  return out;
}
const u32 = (v) => [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff];
const u64 = (v) => Array.from({ length: 8 }, (_, i) => Number((BigInt(v) >> BigInt(8 * i)) & 0xffn));

const SYSTEM = "11111111111111111111111111111111";
const FROM = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const TO = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";

const LAMPORTS = 1_000_000;
/** The System transfer instruction's data: tag 2, then the amount. */
const TRANSFER_DATA = [...u32(2), ...u64(LAMPORTS)];

/** An unsigned legacy System transfer: one zeroed signature slot, then the message. */
function unsignedTransfer() {
  const message = [
    1, 0, 1, // one signer (the fee payer), no read-only signer, one read-only unsigned (the program)
    3, ...base58(FROM), ...base58(TO), ...base58(SYSTEM),
    ...new Array(32).fill(7), // a recent blockhash; nothing here is ever submitted
    1, 2, 2, 0, 1, TRANSFER_DATA.length, ...TRANSFER_DATA,
  ];
  return [1, ...new Array(64).fill(0), ...message];
}

// A Core with no behavioural evidence scores a plain transfer at 0.44, below
// every built-in profile, so the approvals ask for a weaker custom profile —
// which the Core refuses unless started with GRAPHITE_ALLOW_PERMISSIVE_PROFILES=1
// (.github/scripts/dashboard-e2e.sh starts its throwaway Core so).
const PERMISSIVE = { Custom: { min_confidence: 0.4, min_trust_tier: "OfficialManifest" } };
const transfer = (destination, extra = {}) => ({
  proposed_intent: { intent_type: "transfer", raw_natural_language: "send SOL", confidence_of_parse: 0.95 },
  program_id: SYSTEM,
  protocol_version: "1.0.0",
  instruction_discriminator: "02000000",
  account_addresses: [FROM, destination],
  wallet_profile: PERMISSIVE,
  ...extra,
});

const REQUESTS = {
  descriptive: transfer(TO),
  bound: transfer(TO, { signed_transaction: unsignedTransfer(), instruction_data: TRANSFER_DATA }),
  refusedCpi: {
    proposed_intent: { intent_type: "transfer", raw_natural_language: "Transfer tokens", confidence_of_parse: 0.7 },
    program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
    protocol_version: "3.0.0",
    instruction_discriminator: "03",
    account_addresses: [FROM, TO, "DEb5yphxEaPc5BN118svVN4R3GFu9jKs31Gcv5yekjZx"],
    cpi_targets: ["unverified_malicious_target"],
    wallet_profile: PERMISSIVE,
  },
  refusedDestination: transfer(SYSTEM),
};

const headers = { "content-type": "application/json", ...(key ? { Authorization: `Bearer ${key}` } : {}) };
const verdicts = {};
for (const [name, body] of Object.entries(REQUESTS)) {
  const r = await fetch(`${coreBase}/verify`, { method: "POST", headers, body: JSON.stringify(body) });
  const v = await r.json();
  if (r.status !== 200) throw new Error(`${name}: /verify answered ${r.status}: ${JSON.stringify(v)}`);
  verdicts[name] = v;
  console.log(`${name}: approved=${v.approved} decision=${v.decision} scope=${v.scope?.kind} ${v.audit_trail_id}`);
  if (!v.approved) {
    console.log(`  ${v.summary}`);
    for (const l of v.layers ?? []) if (l.status !== "passed") console.log(`  ${l.layer ?? l.name}: ${l.status}: ${l.reason}`);
  }
}

const problems = [];
const expect = (ok, what) => ok || problems.push(what);
expect(verdicts.descriptive.approved === true, "the descriptive transfer was not approved");
expect(verdicts.bound.approved === true, "the bound transfer was not approved");
expect(verdicts.bound.scope?.kind === "artifact_bound", "the bound transfer is not artifact-bound");
expect(
  verdicts.bound.executable !== true && verdicts.bound.decision !== "executable_approved",
  "a Core with no RPC reported a bound transfer executable",
);
expect(verdicts.refusedCpi.approved === false, "the CPI to an unverified target was approved");
expect(verdicts.refusedDestination.approved === false, "the transfer to the System Program was approved");

const history = await fetch(`${coreBase}/api/confidence-history`, { headers }).then((r) => r.json());
const ids = new Set(history.series.map((p) => p.audit_trail_id));
for (const [name, v] of Object.entries(verdicts)) expect(ids.has(v.audit_trail_id), `${name} is not in /api/confidence-history`);

if (problems.length) {
  console.error(`seed: ${problems.length} problem(s)`);
  for (const p of problems) console.error(`  ${p}`);
  process.exit(1);
}
console.log(`seed: ${Object.keys(verdicts).length} verdicts on the trail, one of them bound and approved but not executable`);
