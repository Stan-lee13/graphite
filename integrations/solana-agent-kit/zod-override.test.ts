/**
 * Round 39 (R39-CLIENTS-2): what the development tree's Zod override costs,
 * stated as a test instead of left for a reader to discover.
 *
 * `package.json` forces `zod` to 4.6.7 across this package's tree (past
 * GHSA-mrhx-c7xc-m3w5, every Zod below 4.6.6). `solana-agent-kit` 2.0.10
 * declares `zod ^3.24.1` and reads Zod 3 internals (`_def.typeName`,
 * `z.ZodEffects`) in its OpenAI tool adapter, so the override is NOT inside the
 * same major line for SAK, as the allowlist used to say of every override:
 * SAK's `createOpenAITools` throws under it. Nothing this package ships loads
 * SAK (`graphite-sak-bridge.test.ts` pins that the adapter's module graph holds
 * no SAK and no Zod); SAK is a development dependency for the tests that prove
 * its signing helpers are refused, which do not reach its tool adapters.
 *
 * A caller who builds a SAK agent installs SAK in its own tree, with SAK's own
 * Zod, and none of this applies to it. When SAK moves to Zod 4 this test fails,
 * and the caveat in `.github/npm-audit/solana-agent-kit.allow` goes with it.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { z } from "zod";
import * as sak from "solana-agent-kit";

test("R39-CLIENTS-2: the Zod override crosses a major line for SAK, and SAK's OpenAI tool adapter breaks under it", async () => {
  const declared = JSON.parse(readFileSync(new URL("./node_modules/solana-agent-kit/package.json", import.meta.url), "utf8")) as {
    dependencies: Record<string, string>;
  };
  const installed = JSON.parse(readFileSync(new URL("./node_modules/zod/package.json", import.meta.url), "utf8")) as { version: string };
  assert.match(declared.dependencies.zod, /^\^3\./, "SAK still declares Zod 3");
  assert.match(installed.version, /^4\./, "the override installs Zod 4");

  const action = { name: "probe", similes: [], description: "d", examples: [], schema: z.object({ a: z.string() }), handler: async () => ({}) };
  const agent = { actions: [action], config: {} } as unknown as Parameters<typeof sak.createOpenAITools>[0];
  await assert.rejects(
    async () => sak.createOpenAITools(agent, [action] as unknown as Parameters<typeof sak.createOpenAITools>[1]),
    TypeError,
    "SAK's Zod 3 JSON-schema mapper meets Zod 4: if this no longer throws, SAK reads Zod 4 and the caveat can go",
  );
});
