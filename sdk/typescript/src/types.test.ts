/**
 * A5-03 (2026-09-29 audit): the Core serializes `AccountIdentity` snake_case
 * (`#[serde(rename_all = "snake_case")]` in
 * graphite-core/src/account_resolution.rs). The SDK type and the published
 * schema said "Pda" | "Constant" | "Unverified", which no real verdict ever
 * carries. This pins the SDK to the wire, the schema, and the committed
 * example.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ACCOUNT_IDENTITIES, type AccountIdentity, type ResolvedAccount, type VerificationResult } from "./types.js";

const repo = (path: string) => new URL(`../../../${path}`, import.meta.url);

test("A5-03: AccountIdentity is the Core's snake_case wire values", () => {
  assert.deepEqual([...ACCOUNT_IDENTITIES], ["pda", "constant", "unverified"]);
  // Type-level pin, checked by `npm run check`: the wire value is assignable
  // and the old PascalCase spelling is not.
  const onTheWire: AccountIdentity = "unverified";
  // @ts-expect-error — "Unverified" is not what the Core serializes.
  const pascal: AccountIdentity = "Unverified";
  assert.ok(ACCOUNT_IDENTITIES.includes(onTheWire));
  assert.ok(!ACCOUNT_IDENTITIES.includes(pascal));
});

test("A5-03: the schema's identity enum is the SDK's", () => {
  const schema = JSON.parse(readFileSync(repo("schemas/verification-result-v1.json"), "utf8"));
  const identityEnum: string[] = schema.properties.resolved_accounts.items.properties.identity.enum;
  assert.deepEqual([...identityEnum].sort(), [...ACCOUNT_IDENTITIES].sort());
});

test("A5-03: every identity in the committed example is an SDK value", () => {
  const example = JSON.parse(
    readFileSync(repo("examples/sample-verification-result.json"), "utf8"),
  ) as VerificationResult & { resolved_accounts?: Array<{ identity: string }> };
  const accounts = example.resolved_accounts ?? [];
  assert.ok(accounts.length > 0, "the example carries resolved accounts");
  for (const a of accounts) {
    assert.ok((ACCOUNT_IDENTITIES as readonly string[]).includes(a.identity), a.identity);
  }
});

// The Core emits the manifest slot's `name` on each resolved account, and
// omits it when empty (`skip_serializing_if = "String::is_empty"`).
test("resolved_accounts[].name is an optional string in the schema and the SDK type", () => {
  const schema = JSON.parse(readFileSync(repo("schemas/verification-result-v1.json"), "utf8"));
  const item = schema.properties.resolved_accounts.items;
  assert.equal(item.properties.name.type, "string");
  assert.ok(!(item.required ?? []).includes("name"), "name is omitted when empty, so it cannot be required");
  const base = {
    address: "11111111111111111111111111111111",
    role: "program",
    is_pda: false,
    is_signer: false,
    is_writable: false,
    pda_seeds: [],
    identity: "constant",
  } satisfies ResolvedAccount;
  const named: ResolvedAccount = { ...base, name: "system_program" };
  assert.equal(named.name, "system_program");
  assert.equal((base as ResolvedAccount).name, undefined);
});
