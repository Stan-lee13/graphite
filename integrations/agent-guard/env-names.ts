/**
 * The environment names the bridge and its dev scripts read, and what they
 * may print about the RPC endpoint.
 *
 * Dependency-free on purpose: `devnet-test.ts` and `mainnet-benchmark.ts`
 * use these without importing the bridge, and with it the SAK plugin tree.
 */

/**
 * Environment variables the bridge reads, and the names older files used for
 * them.
 *
 * Round 19 (F-19-C6): the example file said `GRAPHITE_SERVER_URL` and
 * `AI_LAYER_URL` while the code read `GRAPHITE_CORE_URL` and
 * `GRAPHITE_AI_LAYER_URL`. An operator who copied the example pointed the
 * bridge at a Core and an AI layer it never used: both silently defaulted to
 * localhost. A legacy name set without its replacement is now a startup error.
 *
 * A5-07 (2026-09-29 audit): `devnet-test.ts` read `GRAPHITE_URL`, a third
 * name for the same thing, and so repeated the pattern. It reads
 * `GRAPHITE_CORE_URL` now, and the old name is refused like the others.
 */
export const LEGACY_ENV_NAMES: ReadonlyArray<readonly [legacy: string, current: string]> = [
  ["GRAPHITE_SERVER_URL", "GRAPHITE_CORE_URL"],
  ["GRAPHITE_URL", "GRAPHITE_CORE_URL"],
  ["AI_LAYER_URL", "GRAPHITE_AI_LAYER_URL"],
];

export function assertNoLegacyEnvNames(env: Record<string, string | undefined> = process.env): void {
  for (const [legacy, current] of LEGACY_ENV_NAMES) {
    if (env[legacy] !== undefined && env[current] === undefined) {
      throw new Error(
        `[Graphite] ${legacy} is set but the bridge reads ${current}. Rename it: without the ` +
          `current name the bridge would silently fall back to its localhost default and talk to ` +
          `a service you did not configure (Round 19, F-19-C6). REFUSING TO START.`,
      );
    }
  }
}

/** Devnet's genesis hash: the one cluster `devnet-test.ts` may move funds on. */
export const DEVNET_GENESIS_HASH = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
/** Mainnet-beta's genesis hash, named in the refusal so the mistake is obvious. */
export const MAINNET_GENESIS_HASH = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";

/**
 * Refuse to run a script that signs and submits anywhere but devnet (or a
 * local test validator on a loopback host, whose genesis is its own).
 *
 * Round 29 (audit 2026-10-20, Info): `devnet-test.ts` signs and submits real
 * transfers on whatever cluster SOLANA_RPC_URL names, and nothing checked
 * that the cluster was devnet — pointed at a mainnet RPC with a funded key it
 * would have moved real funds. The cluster is identified by its genesis hash,
 * not by its URL.
 */
export function assertDevnetCluster(genesisHash: string, rpcUrl: string): void {
  if (genesisHash === DEVNET_GENESIS_HASH) return;
  let loopback = false;
  try {
    const host = new URL(rpcUrl).hostname;
    loopback = host === "localhost" || host === "[::1]" || /^127\./.test(host);
  } catch {
    /* an unparseable URL is not loopback */
  }
  if (loopback && genesisHash !== MAINNET_GENESIS_HASH) return;
  throw new Error(
    `[Graphite] the RPC's cluster has genesis hash ${genesisHash}` +
      (genesisHash === MAINNET_GENESIS_HASH ? " — MAINNET-BETA" : "") +
      `, not devnet's (${DEVNET_GENESIS_HASH}). This script signs and submits real transfers; it runs on ` +
      "devnet or a local test validator only. REFUSING.",
  );
}

/**
 * What a log line may say about an RPC endpoint: its host, nothing else.
 *
 * A5-07 (2026-09-29 audit): the dev scripts printed the first 45 or 50
 * characters of the RPC URL. A provider URL of the `…/?api-key=<key>` shape
 * puts the key from about character 40, so part of it reached the terminal
 * and whatever collects it. The host carries no path, query or userinfo.
 */
export function rpcHostForLog(rpcUrl: string): string {
  try {
    return new URL(rpcUrl).host || "(no host)";
  } catch {
    return "(unparseable RPC URL)";
  }
}
