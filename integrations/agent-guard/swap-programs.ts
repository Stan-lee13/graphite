/**
 * The programs a swap may be built against — the Core's own swap set.
 *
 * A5-01 (2026-09-29 audit): `executeSwap` accepted a payload for any program.
 * An SPL Token `Approve` of u64::MAX to an attacker delegate, handed in as the
 * "route" for "Swap 1 SOL for USDC", went to the Core as a swap request. A
 * payload the bridge will sign as a swap must at least be addressed to a
 * program that swaps.
 *
 * Source: every seed manifest in `graphite-core/protocols/` whose
 * `protocol.category` is `"swap"`. That is exactly the set the Core's
 * `risk_engine::is_swap_program` derives at startup, and so the set Check 9
 * (program supports intent) accepts for a swap intent.
 *
 * Why a constant and not `GET /manifests`: that endpoint serves the runtime
 * registry, which also holds merged community manifests whose category the
 * Core's swap set does not read — it would be a superset. It would also make
 * the bridge's refusal depend on a second network answer. The constant is the
 * seed set, and `swap-programs.test.ts` fails in either direction when a
 * manifest gains or loses the tag without this list following it.
 *
 * Being on this list earns nothing: the Core still verifies the instruction
 * against the manifest. Being off it is a refusal before anything is asked.
 */
export const SWAP_PROGRAM_IDS: ReadonlySet<string> = new Set([
  "Eo7WjKq67rjJQSZxS6z3YkapzY3eMj6Xy8X5EQVn5UaB", // amm-eo7wjk.json
  "REALp6iMBDTctQqpmhBo4PumwJGcybbnDpxtax3ara3", // amm-routing-realp6.json
  "HpNfyc2Saw7RKkQd8nEL4khUcuPhQ7WwY1B2qjx8jxFq", // amm-v3-hpnfyc.json
  "Arcj82pX7HxYKLR92qvgZUAd7vGS1k4hQvAFcPATFdEQ", // arcium-arcj82.json
  "MAN1CxT5Hh2J7pyLB7Fu4P7TNvQ1d1NSLcKbgSGrhLZ", // bo-sc-man1cx.json
  "BSwp6bEBihVLdqJRKGgzjcGLHkcTuzmSo1TQkHepzH8p", // bonkswap-bswp6b.json
  "FCW1uBM3pZ7fQWvEL9sxTe4fNiH41bu9DWX4ErTZ6aMq", // bridge-fcw1ub.json
  "REALQqNEomY6cQGZJUGwywTBD2UmDT32rZcNnfxQ5N2", // byreal-clmm-realqq.json
  "cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG", // cp-amm-cpamdp.json
  "G7MVcM9YzGxrmLtmobUgyt8A6WhQ2dgQX3aSJcPejdEp", // debot-router-g7mvcm.json
  "jupZ4m2GqUCJ5iueMfzQf8khFfH31d4XAQt3RzCT9Vd", // dex-jupz4m.json
  "dbcij3LWUppWqq96dh6gJWwBifmcGfLSB5D4DuSMaqN", // dynamic-bonding-curve-dbcij3.json
  "fUSioN9YKKSa3CUC2YUc4tPkHJ5Y6XW1yz8y6F7qWz9", // fusionamm-fusion.json
  "FUTARELBfJfQ8RDGhg1wdhddq1odMAJUePHFuBYfUxKq", // futarchy-futare.json
  "GAMMA7meSFWaBXF25oSUgmGRwaW6sCMFLmBNiMSdbHVT", // gamma-gamma7.json
  "Gmso1uvJnLbawvw7yezdfCDcPydwW2s2iqG3w6MDucLo", // gmsol-store-gmso1u.json
  "Gswppe6ERWKpUTXvRPfXdzHhiCyJvLadVvXGfdpBqcE1", // guacswap-gswppe.json
  "hdaoVTCqhfHHo75XdAMxBKdUqvq1i5bF23sisBqVgGR", // helium-sub-daos-hdaovt.json
  "HysTabVUfmQBFcmzu1ctRd1Y1fxd66RBpboy1bmtDSQQ", // hylo-earn-pool-hystab.json
  "DCA265Vj8a9CEuX1eb1LWRnDT7uK6q1xMipnNyatn23M", // jupiter-dca.json
  "jupoNjAxXgZ4rjzxzPMP4oxduvQsQtZzyknqvzYNrNu", // jupiter-limit.json
  "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4", // jupiter-v6.json
  "LiMoM9rMhrdYrfzUCxQppvxCSG1FcrUK9G8uLq4A1GF", // limo-limom9.json
  "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo", // meteora-dlmm.json
  "EmiytJ3zWX9koH3emPsWDEs9RqNm6NNFp4CkMLoiA1KC", // mintfx-emiytj.json
  "mmm3XBJg5gk8XJxEKBvdgptZz6SgK4tXvn36sodowMc", // mmm-mmm3xb.json
  "proVF4pMXVaYqmy4NjniPh4pqKNfMmsihgd4wdkCX3u", // okx-dex-router-provf4.json
  "omnixgS8fnqHfCcTGKWj6JtKjzpJZ1Y5y9pyFkQDkYE", // omnipair-omnixg.json
  "opnb2LAfJYbRMAHHvqjCwQxanZn7ReEHp1k81EohpZb", // openbook-v2.json
  "9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP", // orca-tokenswap-v2.json
  "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc", // orca-whirlpools.json
  "PERPHjGBqRHArX4DySjwM6UJHiR3sWAatqfdBS2qQJu", // perpetuals-perphj.json
  "PhoeNiXZ8ByJGLkxNfZRnkUfjvmuYqLR89jjFHGqdXY", // phoenix.json
  "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA", // pump-amm-pammba.json
  "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P", // pump-fun.json
  "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8", // raydium-amm-v4.json
  "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK", // raydium-clmm.json
  "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C", // raydium-cpmm.json
  "LanMV9sAd7wArD4vJFi2qDdfnVhFxYSUg6eADduJ3uj", // raydium-launchpad-lanmv9.json
  "LockrWmn6K5twhz3y9w1dQERbmgSaRkfnTeTKbpofwE", // raydium-liquidity-locking-lockrw.json
  "swapNyd8XiQwJ6ianp9snpu4brUqFxadzvHebnAXjJZ", // stable-swap-swapny.json
  "ghosty4ZU1Qk1HN7Ymz4pZ15QfspzJZgSYFkdKN6ZLK", // stableswap-ghosty.json
  "DF1ow4tspfHX9JwWJsAb9epbkA8hmpSEAtxXy1V27QBH", // swap-orchestrator-df1ow4.json
  "J51H4gevuj9sLwp2qvRQMs4fBvZHWebEVeNhdUdPNR1K", // tail-trade-j51h4g.json
  "MoonCVVNZFSYkqNXP6bxHLPL6QQJiMagDL3qcqUQTrG", // token-launchpad-mooncv.json
  "zapvX9M3uf5pvy4wRPAbQgdQsM1xmuiFnkfHKPvwMiz", // zap-zapvx9.json
]);
