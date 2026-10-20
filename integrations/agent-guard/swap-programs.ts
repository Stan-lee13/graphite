/**
 * The programs a swap may be built against.
 *
 * A5-01 (2026-09-29 audit): `executeSwap` accepted a payload for any program.
 * An SPL Token `Approve` of u64::MAX to an attacker delegate, handed in as the
 * "route" for "Swap 1 SOL for USDC", went to the Core as a swap request. A
 * payload the bridge will sign as a swap must at least be addressed to a
 * program that swaps.
 *
 * Round 29 (audit 2026-10-20, L3 with H2/H4): this list used to be every seed
 * manifest tagged `"category": "swap"` — 46 programs, among them DCA and
 * limit-order programs, perpetuals, a bridge, liquidity lockers, Arcium,
 * Helium sub-DAOs, a futarchy program, GMX-Solana's store and launchpads.
 * None of their instructions is a swap the guard can bound, and "is in the
 * Core's swap set" was never a reason to sign. The set is now exactly the
 * programs whose exact-in swap instruction the guard decodes, minimum output
 * included (`swap-instructions.ts`): Jupiter v6, Orca Whirlpools, Raydium
 * CPMM, CLMM and AMM v4, and Meteora DLMM.
 *
 * `swap-programs.test.ts` checks that every one of them is ALSO in the Core's
 * swap set (a seed manifest tagged swap): the Core's Check 9 refuses a swap
 * intent on a program outside it, so a program here but not there could never
 * be approved. The converse is no longer asserted — the Core's swap set is
 * larger by design.
 *
 * Being on this list earns nothing: the Core still verifies the instruction
 * against the manifest. Being off it is a refusal before anything is asked.
 */
import { DECODED_SWAP_PROGRAMS } from "./swap-instructions.js";

export const SWAP_PROGRAM_IDS: ReadonlySet<string> = DECODED_SWAP_PROGRAMS;
