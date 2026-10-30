# Round 39 — supply chain, CI, release, deployment, and the data corpora

Workstream `supply-chain` of Round 39 (brief Phases G and F), on `c087bfb` (worktree at
`c087bfb502f5a5c13c12755c719faf54f6c4eec6`; CI's push run of that commit was still `queued` when read
on 2026-10-25, so no green run of it exists to cite). Internal engineering evidence, not an
independent audit. Commits: `79a9f65`, `77b7d88`, `040ad38` and the one that adds this file.

GitHub reads in this section were made through the session's API proxy, which authenticates as the
repository owner (`GET /user` = `Stan-lee13`); every call was a GET. No setting was changed, and
nothing here claims one was.

## 1. Scope read

### Scope A — `.github/`, `deploy/`, container files, manifests and lockfiles

- `.github/workflows/ci.yml`: read fully (1,216 lines); actionlint clean; changed (fuzz lockfile audit; ci-scripts floor 77 → 121).
- `.github/workflows/release.yml`: read fully; actionlint clean; no change (findings 8, §3 R37-8).
- `.github/workflows/release-guard.yml`: read fully; no change (finding 8).
- `.github/workflows/ruleset-drift.yml`: read fully; header changed (R39-SUPPLY-CHAIN-2).
- `.github/workflows/assurance.yml`: read fully; `set +e` at 219 intentional (§3 table).
- `.github/workflows/live-mainnet.yml`: read fully; the coordinator's seed item verified fixed, now pinned by a test (finding 15).
- `.github/workflows/live-devnet.yml`: read fully; no change.
- `.github/workflows/pinned-tools.yml`: read fully; no change.
- `.github/scripts/ruleset-drift.py`: read fully; rewritten (R39-SUPPLY-CHAIN-2, -3).
- `.github/scripts/ci-scripts.test.sh`: read fully; 44 cases added (77 → 121).
- `.github/scripts/release-gate.sh`: read fully; no change (52/52 tests).
- `.github/scripts/release-gate.test.sh`: read fully; run: 52 passed.
- `.github/scripts/test-count.sh`: read fully; SC2086/SC2116 at line 54 fixed (R39-SUPPLY-CHAIN-4).
- `.github/scripts/set-rpc-env.sh`, `pinned-tools.py`, `dependency-holds.py`, `check-attestation-commands.py`, `dashboard-e2e.sh`: read fully; run through their tests; no change.
- `.github/scripts/testdata/ruleset-drift-live-2026-10-25/{rulesets,ruleset-25817024}.json`: NEW, the live API answers of 2026-10-25, a test fixture.
- `.github/rulesets/main.json`, `main-review.json`, `release-tags.json`, `release-tags-create.json`: read fully; unchanged (main-review is now required by the drift check).
- `.github/environments/release.json`: read fully; unchanged.
- `.github/allowed_signers` (empty by design), `.github/revoked_signers`: read fully; unchanged; never add a key here.
- `.github/CODEOWNERS`: read fully; header comment corrected.
- `.github/dependabot.yml`, `.github/dependency-holds.json`, `.github/pinned-tools.json`: read fully; checks pass (25 holds, first due 2027-01-20; 11 pins).
- `.github/npm-audit/gate.mjs`, `gate.test.mjs`, the seven `*.allow` files: read fully; gate tests 10/10; all seven lockfiles pass the gate (agent guard 4 listed, SAK 5 listed, others 0).
- `.github/ISSUE_TEMPLATE/config.yml`, `bug_report.md`, `hardening_suggestion.md`, `protocol_manifest.md`, `.github/PULL_REQUEST_TEMPLATE.md`: read; the security link points at `SECURITY.md` (finding 9).
- `.github/test-allowlists/rust-ignored.txt`: read; unchanged.
- `Dockerfile`: read fully; digests pinned, non-root 10001, apt snapshot pinned; image NOT built (no Docker daemon).
- `docker-compose.yml`: read fully; read-only, `cap_drop: ALL`, no-new-privileges, limits, one replica, strict healthcheck.
- `.dockerignore`: read fully (allowlist of four paths). `.gitignore`: read fully (`.claude/`, `.agents/` not ignored — never stage them).
- `deploy/compose/docker-compose.prod.yml`: read fully; one replica by `container_name` + `replicas: 1`; secrets as files.
- `deploy/systemd/graphite.service`, `graphite-anchor.service`, `graphite-anchor.timer`, `graphite.env.example`: read fully (service, anchor) / in part (env example).
- `deploy/caddy/Caddyfile`, `deploy/prometheus/*.yml`, `deploy/grafana/graphite-dashboard.json`: read in part; validated only by `deploy/tests/run.sh`, whose Caddy and promtool checks are BLOCKED here.
- `deploy/scripts/*.sh` (5), `deploy/tests/run.sh`, `deploy/tests/backup-keys.test.sh`: read in part (run.sh sections static/edge/ops; the scripts' headers and argument handling); shellcheck clean; run.sh run against the release binary.
- `deploy/README.md`, `deploy/compose/.gitignore`, `anchors/.gitignore`, `secrets/.gitignore`: read.
- `graphite-core/Cargo.toml` / `Cargo.lock`, `graphite-core/fuzz/Cargo.{toml,lock}`, `tools/runtime-oracle/Cargo.{toml,lock}`, `tools/inner-instruction-oracle/Cargo.{toml,lock}`: manifests read (dependencies sections); `cargo metadata --locked` consistent for all four; `cargo audit` clean on all four (finding 7: `anyhow` unused).
- The seven npm `package.json` / `package-lock.json` pairs (agent guard, Vercel AI, MCP server, SAK, TypeScript SDK, dashboard, dashboard e2e): machine-validated: lockfile v3 roots equal `package.json`, every package with an integrity hash from registry.npmjs.org.
- `python-ai-layer/requirements.txt`, `requirements-lock.txt`: read; `pip-audit 2.9.0 -r … --require-hashes`: no known vulnerability.
- `sdk/go/go.mod`: read (no dependencies).

### Scope B — protocols, fixtures, generators, schemas, examples, evidence, the Round 36 ledger

There is no top-level `fixtures/` directory at `c087bfb`; the fixtures are under `graphite-core/fixtures/`.

- `docs/audit-r36/build_ledger.py`: read in part; RE-RUN (deterministic from the git objects of `2140427`): `file-ledger.json` and `scan-triage.json` rebuilt byte-identical.
- `docs/audit-r36/file-ledger.json`, `scan-triage.json`: machine-validated (rebuilt identical; strict JSON).
- `docs/audit-r36/declaration-rewrites.json`: read in part (all 35 rows' fields; the 9 medium rows fully); machine-validated: every rewrite's `new_lines` are still its manifest's declaration.
- `docs/audit-r36/LEDGER.md`, `mutation-run-40083338181.md`: read in part (what they claim, for §3).
- `docs/evidence/Graphite_Full_Colosseum_Copilot_Deep_Dive.pdf`: binary, a PDF 1.4 of 153,335 bytes; not reviewed (not evidence any code relies on).
- `schemas/proposed-intent-v1.json`, `schemas/verification-result-v1.json`: machine-validated: both valid Draft 2020-12 (`jsonschema` 4.26.0); six examples validate.
- `examples/sample-proposed-intent.json`, `examples/sample-verification-result.json`, `examples/decisions/{analysis_only,blocked,executable_approved,inconclusive}.json`: machine-validated against their schemas, no error.
- `examples/verify-input.json`, `examples/verify-malicious.json`: read; strict JSON; used by CI's container job and the deploy kit.
- `graphite-core/fixtures/artifacts/*.json` (7) and `graphite-core/fixtures/mainnet/sample-2026-09-23-last-2-blocks.json`: labels read by hand and classified (§4 F-3); versions read from the bytes (2,284 sample rows: 1,499 legacy, 472 v0, 313 v1, every label right; SAK corpus 11 legacy / 2 v0 / 2 v1, every digest right).
- `graphite-core/scripts/README.md`: read fully; a validator section added.
- The scripts' own data: `dca_idl.json`, `drift_idl.json`, `jupiter_limit_idl.json`, `klend_idl.json`, `openbook_idl.json`, `phoenix_idl.json`, `pump_idl.json`, `squads_v4_idl.json`, `switchboard_idl.json`, `whirlpool_idl.json`, `idls/{jupiter,jupiter_v6_surfpool,marinade,meteora-dlmm,orca-whirlpools,raydium_clmm,raydium_cpmm}.json`: machine-validated (IDLs with an address compared with their manifest; eight without an address noted, not compared; the surfpool IDL's discriminators are documented as not the deployed ones and are not compared).
- `dca_real_account.json`, `marginfi_shapes.json`, `solend_sdk_layouts.json`, `solend_shapes.json`, `squads_real_pair.json`, `metaplex_discriminators.txt`: read in part; strict JSON (the .txt not parsed).
- `real_exploit_2AWwL6dk_aug2026.json`, `real_exploit_3PbK87_aat_massdrain.json`: raw `getTransaction` answers; machine-validated: each carries the signature it is named after (also in the corpus as `real-mainnet-exploit:` rows).
- `out/idl_index.json` (581 programs), `out/inventory_census.json`, `out/mainnet_sample_named.json`, `out/onboarding_report.json`: machine-validated (every indexed IDL has its `onchain_idls/` file); read in part.

Per file, for the generated directories:

- `graphite-core/fixtures/corpus/11111111111111111111111111111111.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/24Uqj9JCLxUeoC3hGfh5W3s9FM9uCHDS2SG3LYwBpyTi.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/2En5Y11SEAGLNmEezTuRUCwTyzyNReHaMbSnS5gjGsL1.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/3W2y8TuU2rKf4qvrKZAbu8Tu9najg9Bvcwfsf28aW3rs.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/4MangoMjqJ2firMokCjjGgoK8d4MXcrgL7XJaL3w6fVg.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/4R3gSG8BpU4t19KYj8CfnbtRpnT8gtk4dvTHxVRwc2r7.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/5BD9UAUCRCg6Chv6CS5k4sBHGd7CciWpng9u7iJxJFjx.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/61DFfeTKM7trxYcPQCM78bJ794ddZprZpAwAnLiwTpYH.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/67g5HhrzQ2eqqEDJTEogHGBjAfwRD8evD3wg6LTDV8GK.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/8MjG72ZWmkG4SKES7WK2fGrrR14hBhokTJiHgaedqJ5L.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/99vQwtBwYtrqqD9YSXbdum3KBdxPAVxYTaQ3cfnJSrN2.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/9fhQBbumKEFuXtMBDw8AaQyAjCorLGJQiS3skWZdQyQD.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/APR1MEny25pKupwn72oVqMH4qpDouArsX8zX4VwwfoXD.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/Arcj82pX7HxYKLR92qvgZUAd7vGS1k4hQvAFcPATFdEQ.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/BGUMAp9Gq7iTEuizy4pqaxsTyUCBK68MDfK752saRPUY.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/BPFLoader2111111111111111111111111111111111.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/BPFLoaderUpgradeab1e11111111111111111111111.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/BSwp6bEBihVLdqJRKGgzjcGLHkcTuzmSo1TQkHepzH8p.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/BwRZQcpiqQrQkpfWJDxzcpojPRmTB21FoVQYkcZBBReo.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/CLEANALo6FtS6quqTTEXDGFFTuSKMkeKGgcweeiPRJzK.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/CRAFT2RPXPJWCEix4WpJST3E7NLf79GTqZUL75wngXo5.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/CWgkFB7ngUc9cGD1LryyhP7h6xYWtwrAjhSKKCoR1gkz.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/Cargo2VNTPPTi9c1vq1Jw5d3BWUNr18MjRtSupAghKEk.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/CcmRKTuZCGJBWQwMHvDYApBRvSZNHqGJXkznqpDTSQUr.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/ComputeBudget111111111111111111111111111111.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/DCA265Vj8a9CEuX1eb1LWRnDT7uK6q1xMipnNyatn23M.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/DF1ow4tspfHX9JwWJsAb9epbkA8hmpSEAtxXy1V27QBH.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/DoVEsk76QybCEHQGzkvYPWLQu9gzNoZZZt3TPiL597e.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/EmiytJ3zWX9koH3emPsWDEs9RqNm6NNFp4CkMLoiA1KC.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/Eo7WjKq67rjJQSZxS6z3YkapzY3eMj6Xy8X5EQVn5UaB.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/FCW1uBM3pZ7fQWvEL9sxTe4fNiH41bu9DWX4ErTZ6aMq.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/FD1amxhTsDpwzoVX41dxp2ygAESURV2zdUACzxM1Dfw9.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/FLEET1qqzpexyaDpqb2DGsSzE2sDCizewCg9WjrA6DBW.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/FUTARELBfJfQ8RDGhg1wdhddq1odMAJUePHFuBYfUxKq.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/FarmsPZpWu9i7Kky8tPN37rs2TpmMrAZrC7S7vJa91Hr.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/FknMf1SRUnujeyezuvKBQ7T57L2iSGbNd6D3iSrdDUHQ.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/G3v8Wxa6TU8rwjZ4J5ey7zbnp44VxYTyTVESa3P6ByjT.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/G3z6yQqLP1q2JqFqEwND6rTX3vsnzzr3Vv16pMoSdkcx.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/G7MVcM9YzGxrmLtmobUgyt8A6WhQ2dgQX3aSJcPejdEp.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/GAMMA7meSFWaBXF25oSUgmGRwaW6sCMFLmBNiMSdbHVT.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/GaE1XtFQuW3DfNJrsAs5gATT1XeP2K5zipkmUTBqaDfr.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/Gmso1uvJnLbawvw7yezdfCDcPydwW2s2iqG3w6MDucLo.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/Gswppe6ERWKpUTXvRPfXdzHhiCyJvLadVvXGfdpBqcE1.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/Gt9S41PtjR58CbG9JhJ3J6vxesqrNAswbWYbLNTMZA3c.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/HDw2E7P8X1SkCyjvoGsfBGAVUutKcj874bXjHrpVYrVL.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/HDwcJBJXjL9FpJ7UBsYBtaDjsBUhuLCUYoz3zr8SWWaQ.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/HEvSKofvBgfaexv23kMabbYqxasxU3mQ4ibBMEmJWHny.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/HFn8GnPADiny6XqUoWE8uRPPxb29ikn4yTuPa9MF2fWJ.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/HpNfyc2Saw7RKkQd8nEL4khUcuPhQ7WwY1B2qjx8jxFq.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/HysTabVUfmQBFcmzu1ctRd1Y1fxd66RBpboy1bmtDSQQ.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/J51H4gevuj9sLwp2qvRQMs4fBvZHWebEVeNhdUdPNR1K.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/KvauGMspG5k6rtzrqqn7WNn3oZdyKqLKwK2XWQ8FLjd.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/LanMV9sAd7wArD4vJFi2qDdfnVhFxYSUg6eADduJ3uj.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/LiMoM9rMhrdYrfzUCxQppvxCSG1FcrUK9G8uLq4A1GF.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/LockrWmn6K5twhz3y9w1dQERbmgSaRkfnTeTKbpofwE.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/LocpQgucEQHbqNABEYvBvwoxCPsSbG91A1QaQhQQqjn.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/M2mx93ekt1fmXSVkTrUL9xVFHkmME8HTUi5Cyc5aF7K.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/MAN1CxT5Hh2J7pyLB7Fu4P7TNvQ1d1NSLcKbgSGrhLZ.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/MErKy6nZVoVAkryxAejJz2juifQ4ArgLgHmaJCQkU7N.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/MFv2hWf31Z9kbCa1snEPYctwafyhdvnV7FZnsebVacA.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/Memo4c2pN8afCj432Lb7RMVKi9PbQnnW7ewFFaV3oAH.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/MoonCVVNZFSYkqNXP6bxHLPL6QQJiMagDL3qcqUQTrG.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/MzLoYnJ6sF6eeejs4vV95TNmXqS3W4cAtLGKkjT4ZrK.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/PERPHjGBqRHArX4DySjwM6UJHiR3sWAatqfdBS2qQJu.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/PhoeNiXZ8ByJGLkxNfZRnkUfjvmuYqLR89jjFHGqdXY.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/Point2iBvz7j5TMVef8nEgpmz4pDr7tU7v3RjAfkQbM.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/REALQqNEomY6cQGZJUGwywTBD2UmDT32rZcNnfxQ5N2.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/REALp6iMBDTctQqpmhBo4PumwJGcybbnDpxtax3ara3.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/RUsHe5Kt19Koe2stiQuTRS4wkev5QjY5AyatokniGeY.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/RmnXLft1mSEwDgMKu2okYuHkiazxntFFcZFrrcXxYg7.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/SAGE2HAwep459SNq61LHvjxPk4pLPEJLoMETef7f7EE.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/SKRskrmtL83pcL4YqLWt6iPefDqwXQWHSw9S9vz94BZ.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/SMRTzfY6DfH5ik3TKiyLFfXexV8uSG3d2UksSCYdunG.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/SW1TCH7qEPTdLsDHRgPuMQjbQxKdH2aBStViMFnt64f.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/So1endDq2YkqhipRh3WViPa8hdiSpxWy6z3Z6tMCpAo.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/Stake11111111111111111111111111111111111111.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/SySTEM1eSU2p4BGQfQpimFEWWSC1XDFeun3Nqzz3rT7.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/T1pyyaTNZsKv2WcRAB8oVnk93mLJw2XzjtVYqCsaHqt.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/TAMM6ub33ij1mbetoMyVBLeKY5iP41i4UPUJQGkhfsg.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/TCMPhJdwDryooaGtiocG1u3xcYbRpiJzb283XfCZsDp.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/TSWAPaqyCSx2KABk68Shruf4rp7CxcNi8hAsbdwmHbN.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/VRFzZoJdhFWL8rkvu87LpKM3RbcVezpMEc6X5GVDr7y.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/ZETAxsqBRek56DhiGXrn75yj2NHU3aYUnxvHXpkf3aD.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/aMERKpFAWoChCi5oZwPvgsSCoGpZKBiU7fi76bdZjt2.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/cardWArqhdV5jeRXXjUti7cHAa4mj41Nj3Apc6RPZH2.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/ccvrfu3fSpbnPLiUqdWAt85Zn9nq96ekwGTbHqGtdgQ.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/cjg3oHmg9uuPsP8D6g29NWvhySJkdYdAo9D25PRbKXJ.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/cmtDvXumGCrqC1Age74AVPhSRVXJMd8PJS91L8KbNCK.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/compr6CUsB5m2jS4Y3831ztGSTnDpnKJTKS95d64XVq.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/credMBJhYFzfn7NxBMdU4aUqFggAjgztaCcv2Fo6fPT.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/dbcij3LWUppWqq96dh6gJWwBifmcGfLSB5D4DuSMaqN.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/fUSioN9YKKSa3CUC2YUc4tPkHJ5Y6XW1yz8y6F7qWz9.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/ghosty4ZU1Qk1HN7Ymz4pZ15QfspzJZgSYFkdKN6ZLK.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/hdaoVTCqhfHHo75XdAMxBKdUqvq1i5bF23sisBqVgGR.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/jupZ4m2GqUCJ5iueMfzQf8khFfH31d4XAQt3RzCT9Vd.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/jupoNjAxXgZ4rjzxzPMP4oxduvQsQtZzyknqvzYNrNu.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/mayan34VedncxdK2XobtvWFDXQASUTBXhUVzt2kKgny.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/meta/corpus_manifest.json`: machine-validated: 13,013 rows one-to-one with the corpus by hash; provenance agrees
- `graphite-core/fixtures/corpus/metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/mmm3XBJg5gk8XJxEKBvdgptZz6SgK4tXvn36sodowMc.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/nosJhNRqr2bc9g1nfGDcXXTXvYUmxD4cVwy2pMWhrYM.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/offqSMQWgQud6WJz694LRzkeN5kMYpCHTpXQr3Rkcjm.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/omnixgS8fnqHfCcTGKWj6JtKjzpJZ1Y5y9pyFkQDkYE.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/opnb2LAfJYbRMAHHvqjCwQxanZn7ReEHp1k81EohpZb.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/ord1qJZ3DB52s9NoG8nuoacW85aCyNvECa5kAqcBVBu.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/proVF4pMXVaYqmy4NjniPh4pqKNfMmsihgd4wdkCX3u.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/pv1ttom8tbyh83C1AVh6QH2naGRdVQUVt3HY1Yst5sv.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/pyt2F414BA6dPttK6RddPZUdHfapoBN24GL5wbrPCou.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/pytd2yyk641x7ak7mkaasSJVXh6YYZnC7wTmtgAyxPt.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/pythWSnswVUd12oZpeFP8e9CVaEqJg25g1Vtc2biRsT.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/rec2HHDDnjLfj4kE7VyEtFA1HPGQLK33259532cRyHp.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/strmRqUCoQUgGUan5YhzUZa6KqdzwX5L6FpUxfmKg5m.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/swapNyd8XiQwJ6ianp9snpu4brUqFxadzvHebnAXjJZ.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/traderDnaR5w6Tcoi3NFm53i48FTDNbGjBSZwWXDRrg.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/ttaiNybR4ncnBFsBCQKdVus8BNHepErToRp5cuULduL.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/tuktukUrfhXT6ZT77QTU8RQtvgL967uRuVagWF57zVA.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/tuna4uSQZncNeeiAMKbstuxA9CUkHH6HmC64wgmnogD.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/vo1tWgqZMjG61Z2T9qUaMYKqZ75CYzMuaZ2LZP1n7HV.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/fixtures/corpus/zapvX9M3uf5pvy4wRPAbQgdQsM1xmuiFnkfHKPvwMiz.json`: machine-validated: entries filed under their program, unique content hashes, provenance equal to the meta manifest
- `graphite-core/protocols/account-compression-compr6.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/aligned-distributor-amerkp.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/amm-eo7wjk.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/amm-program-tamm6u.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/amm-routing-realp6.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/amm-v3-hpnfyc.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/arcium-arcj82.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/ata-program.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/atlas-fee-payer-apr1me.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/battle_tested_evidence.json`: machine-validated: 137 records recomputed against their counts and recompute_evidence.py's rule; 13 below the decode bar listed
- `graphite-core/protocols/bo-sc-man1cx.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/bonkswap-bswp6b.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/bpf-loader-upgradeable.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/bpf-loader.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/bridge-cards-cardwa.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/bridge-fcw1ub.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/brrr-lend-g3v8wx.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/bubblegum-bgumap.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/byreal-clmm-realqq.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/cargo-cargo2.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/cc-vrf-ccvrfu.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/ccip-offramp-offqsm.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/coinflow-fd1amx.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/compute-budget.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/cp-amm-cpamdp.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/crafting-craft2.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/crash-game-g3z6yq.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/data-credits-credmb.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/debot-router-g7mvcm.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/dex-jupz4m.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/donau-fknmf1.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/doorcash-67g5hh.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/doves-dovesk.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/drift.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/dynamic-bonding-curve-dbcij3.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/escrow-5bd9ua.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/farms-farmsp.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/fusionamm-fusion.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/futarchy-futare.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/gamma-gamma7.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/gmsol-store-gmso1u.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/guacswap-gswppe.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/helium-sub-daos-hdaovt.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/hylo-earn-pool-hystab.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/jito-tip-distribution-4r3gsg.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/jito-tip-payment-t1pyya.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/jupiter-dca.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/jupiter-limit.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/jupiter-v6.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/kamino-lending.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/kamino-vault-kvaugm.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/legacy-memo-program.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/light-system-program-system.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/limo-limom9.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/locker-locpqg.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/m2-m2mx93.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/main-cwgkfb.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/mango-v4-4mango.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/marginfi-v2.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/marinade.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/marketplace-ccmrkt.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/marketplace-trader.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/memo-program.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/merkle-distributor-merky6.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/metaplex-token-metadata.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/meteora-dlmm.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/mintfx-emiytj.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/mmm-mmm3xb.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/nosana-jobs-nosjhn.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/ocr2-cjg3oh.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/okx-dex-router-provf4.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/omnipair-omnixg.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/openbook-v2.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/orao-vrf-vrfzzo.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/orca-tokenswap-v2.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/orca-whirlpools.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/order-book-mzloyn.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/order-engine-2en5y1.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/order-engine-61dffe.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/oridion-ord1qj.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/perpetuals-perphj.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/phoenix.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/points-point2.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/profile-vault-pv1tto.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/pump-amm-pammba.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/pump-fees-pfeeux.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/pump-fun.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/pyth-lazer-solana-contract-pytd2y.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/pyth-push-oracle-pyt2f4.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/pyth-push-oracle-pythws.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/pyth-solana-receiver-rec2hh.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/pyth-solana-receiver-rec5ek.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/raydium-amm-v4.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/raydium-clmm.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/raydium-cpmm.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/raydium-launchpad-lanmv9.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/raydium-liquidity-locking-lockrw.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/relay-depository-99vqwt.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/rmn-remote-rmnxlf.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/rush-rushe5.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/safecinerator-cleana.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/sage-sage2h.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/scope-hfn8gn.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/score-fleet1.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/solend.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/spl-account-compression-cmtdvx.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/spl-memo-program.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/spl-stake-pool.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/spl-token.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/squads-smart-account-program-smrtzf.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/squads-v4.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/stable-swap-swapny.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/stableswap-ghosty.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/stake-program.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/staking-skrskr.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/store-hevsko.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/swap-orchestrator-df1ow4.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/swift-mayan3.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/switchboard-v2.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/system-program.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/tail-trade-j51h4g.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/tarb-bwrzqc.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/tcomp-tcmphj.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/tensorswap-tswapa.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/timelock-strmrq.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/token-2022.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/token-launchpad-mooncv.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/tuktuk-tuktuk.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/tuna-tuna4u.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/vault-24uqj9.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/vault-vo1twg.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/verified_program_ids.json`: machine-validated: 137 ids equal the manifests' program ids, each verified/mainnet/provenance
- `graphite-core/protocols/verifier-gt9s41.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/verifier-ttainy.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/wormhole-core-bridge-solana-hdw2e7.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/wormhole-core-bridge-solana-hdwcjb.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/wormhole-core.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/zap-zapvx9.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/protocols/zeta-zetaxs.json`: machine-validated only (validate_corpora.py manifests/evidence/idls; JSON strict, no duplicate key)
- `graphite-core/scripts/analyze_squads_tx.py`: read in part (header, RPC request version); NOT run: it reads a public RPC, which this audit may not contact
- `graphite-core/scripts/apply_idl_optional_flags.py`: read fully; re-run on a copy for openbook-v2: 0 slots marked, no diff
- `graphite-core/scripts/battle_tested_census.py`: read in part (header, RPC request version); NOT run: it reads a public RPC, which this audit may not contact
- `graphite-core/scripts/build_new_manifests.py`: read in part (header); one-off onboarding generator; validated through its outputs
- `graphite-core/scripts/census_drift_kamino.py`: read in part (header, RPC request version); NOT run: it reads a public RPC, which this audit may not contact
- `graphite-core/scripts/census_metaplex.py`: read in part (header, RPC request version); NOT run: it reads a public RPC, which this audit may not contact
- `graphite-core/scripts/census_orca.py`: read in part (header, RPC request version); NOT run: it reads a public RPC, which this audit may not contact
- `graphite-core/scripts/fetch_discriminators.py`: read in part (header, RPC request version); NOT run: it reads a public RPC, which this audit may not contact
- `graphite-core/scripts/fetch_onchain_idls.py`: read in part (header, RPC request version); NOT run: it reads a public RPC, which this audit may not contact
- `graphite-core/scripts/fetch_real_fixtures.py`: read in part (header, RPC request version); NOT run: it reads a public RPC, which this audit may not contact
- `graphite-core/scripts/idl_to_manifest.py`: read in part (snake(), anchor_disc(), classify()); its discriminator rule re-implemented independently in validate_corpora.py: 3,117 equal, 0 differ
- `graphite-core/scripts/live_revalidate.py`: read in part (header, RPC request version); NOT run: it reads a public RPC, which this audit may not contact
- `graphite-core/scripts/manifest_json.py`: read in part (layout-preserving writer used by the three generators above)
- `graphite-core/scripts/merge_onchain_idl.py`: read in part (header); generator for an onboarding step, outputs since hand-edited; validated through its outputs
- `graphite-core/scripts/mutation_floor.py`: read fully; exercised by ci-scripts.test.sh (8 cases pass)
- `graphite-core/scripts/onboard_from_inventory.py`: read in part; NOT re-runnable from committed inputs: it reads scripts/inventory_metadata.json, which is not committed, and its outputs were edited afterwards (reclassify, F-005 rewrites)
- `graphite-core/scripts/out/onchain_idls/24Uqj9JCLxUeoC3hGfh5W3s9FM9uCHDS2SG3LYwBpyTi.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/2En5Y11SEAGLNmEezTuRUCwTyzyNReHaMbSnS5gjGsL1.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/4MangoMjqJ2firMokCjjGgoK8d4MXcrgL7XJaL3w6fVg.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/4R3gSG8BpU4t19KYj8CfnbtRpnT8gtk4dvTHxVRwc2r7.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/5BD9UAUCRCg6Chv6CS5k4sBHGd7CciWpng9u7iJxJFjx.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/61DFfeTKM7trxYcPQCM78bJ794ddZprZpAwAnLiwTpYH.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/67g5HhrzQ2eqqEDJTEogHGBjAfwRD8evD3wg6LTDV8GK.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/99vQwtBwYtrqqD9YSXbdum3KBdxPAVxYTaQ3cfnJSrN2.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/9ddjzqYhSTMHaBrrKukRXRfy4WzHUPjdX88uPXZ7MXyn.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/APR1MEny25pKupwn72oVqMH4qpDouArsX8zX4VwwfoXD.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/Arcj82pX7HxYKLR92qvgZUAd7vGS1k4hQvAFcPATFdEQ.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/BGUMAp9Gq7iTEuizy4pqaxsTyUCBK68MDfK752saRPUY.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/BSwp6bEBihVLdqJRKGgzjcGLHkcTuzmSo1TQkHepzH8p.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/BwRZQcpiqQrQkpfWJDxzcpojPRmTB21FoVQYkcZBBReo.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/CLEANALo6FtS6quqTTEXDGFFTuSKMkeKGgcweeiPRJzK.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/CRAFT2RPXPJWCEix4WpJST3E7NLf79GTqZUL75wngXo5.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/CWgkFB7ngUc9cGD1LryyhP7h6xYWtwrAjhSKKCoR1gkz.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/Cargo2VNTPPTi9c1vq1Jw5d3BWUNr18MjRtSupAghKEk.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/CcmRKTuZCGJBWQwMHvDYApBRvSZNHqGJXkznqpDTSQUr.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/DF1ow4tspfHX9JwWJsAb9epbkA8hmpSEAtxXy1V27QBH.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/DoVEsk76QybCEHQGzkvYPWLQu9gzNoZZZt3TPiL597e.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/EmiytJ3zWX9koH3emPsWDEs9RqNm6NNFp4CkMLoiA1KC.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/Eo7WjKq67rjJQSZxS6z3YkapzY3eMj6Xy8X5EQVn5UaB.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/FCW1uBM3pZ7fQWvEL9sxTe4fNiH41bu9DWX4ErTZ6aMq.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/FD1amxhTsDpwzoVX41dxp2ygAESURV2zdUACzxM1Dfw9.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/FLEET1qqzpexyaDpqb2DGsSzE2sDCizewCg9WjrA6DBW.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/FUTARELBfJfQ8RDGhg1wdhddq1odMAJUePHFuBYfUxKq.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/FarmsPZpWu9i7Kky8tPN37rs2TpmMrAZrC7S7vJa91Hr.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/FewRXXTzV2WwigvTQNsVanhEmCM9wzfNvoT1divNtbVH.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/FknMf1SRUnujeyezuvKBQ7T57L2iSGbNd6D3iSrdDUHQ.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/G3v8Wxa6TU8rwjZ4J5ey7zbnp44VxYTyTVESa3P6ByjT.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/G3z6yQqLP1q2JqFqEwND6rTX3vsnzzr3Vv16pMoSdkcx.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/G7MVcM9YzGxrmLtmobUgyt8A6WhQ2dgQX3aSJcPejdEp.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/GAMMA7meSFWaBXF25oSUgmGRwaW6sCMFLmBNiMSdbHVT.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/Gmso1uvJnLbawvw7yezdfCDcPydwW2s2iqG3w6MDucLo.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/Gswppe6ERWKpUTXvRPfXdzHhiCyJvLadVvXGfdpBqcE1.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/Gt9S41PtjR58CbG9JhJ3J6vxesqrNAswbWYbLNTMZA3c.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/HDw2E7P8X1SkCyjvoGsfBGAVUutKcj874bXjHrpVYrVL.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/HDwcJBJXjL9FpJ7UBsYBtaDjsBUhuLCUYoz3zr8SWWaQ.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/HEvSKofvBgfaexv23kMabbYqxasxU3mQ4ibBMEmJWHny.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/HFn8GnPADiny6XqUoWE8uRPPxb29ikn4yTuPa9MF2fWJ.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/HpNfyc2Saw7RKkQd8nEL4khUcuPhQ7WwY1B2qjx8jxFq.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/HysTabVUfmQBFcmzu1ctRd1Y1fxd66RBpboy1bmtDSQQ.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/J51H4gevuj9sLwp2qvRQMs4fBvZHWebEVeNhdUdPNR1K.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/KvauGMspG5k6rtzrqqn7WNn3oZdyKqLKwK2XWQ8FLjd.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/LanMV9sAd7wArD4vJFi2qDdfnVhFxYSUg6eADduJ3uj.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/LiMoM9rMhrdYrfzUCxQppvxCSG1FcrUK9G8uLq4A1GF.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/LockrWmn6K5twhz3y9w1dQERbmgSaRkfnTeTKbpofwE.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/LocpQgucEQHbqNABEYvBvwoxCPsSbG91A1QaQhQQqjn.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/M2mx93ekt1fmXSVkTrUL9xVFHkmME8HTUi5Cyc5aF7K.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/MAN1CxT5Hh2J7pyLB7Fu4P7TNvQ1d1NSLcKbgSGrhLZ.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/MErKy6nZVoVAkryxAejJz2juifQ4ArgLgHmaJCQkU7N.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/MFv2hWf31Z9kbCa1snEPYctwafyhdvnV7FZnsebVacA.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/MoonCVVNZFSYkqNXP6bxHLPL6QQJiMagDL3qcqUQTrG.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/MzLoYnJ6sF6eeejs4vV95TNmXqS3W4cAtLGKkjT4ZrK.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/PERPHjGBqRHArX4DySjwM6UJHiR3sWAatqfdBS2qQJu.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/Point2iBvz7j5TMVef8nEgpmz4pDr7tU7v3RjAfkQbM.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/REALQqNEomY6cQGZJUGwywTBD2UmDT32rZcNnfxQ5N2.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/REALp6iMBDTctQqpmhBo4PumwJGcybbnDpxtax3ara3.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/RUsHe5Kt19Koe2stiQuTRS4wkev5QjY5AyatokniGeY.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/RmnXLft1mSEwDgMKu2okYuHkiazxntFFcZFrrcXxYg7.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/SAGE2HAwep459SNq61LHvjxPk4pLPEJLoMETef7f7EE.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/SKRskrmtL83pcL4YqLWt6iPefDqwXQWHSw9S9vz94BZ.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/SMRTzfY6DfH5ik3TKiyLFfXexV8uSG3d2UksSCYdunG.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/SySTEM1eSU2p4BGQfQpimFEWWSC1XDFeun3Nqzz3rT7.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/T1pyyaTNZsKv2WcRAB8oVnk93mLJw2XzjtVYqCsaHqt.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/TAMM6ub33ij1mbetoMyVBLeKY5iP41i4UPUJQGkhfsg.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/TCMPhJdwDryooaGtiocG1u3xcYbRpiJzb283XfCZsDp.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/TSWAPaqyCSx2KABk68Shruf4rp7CxcNi8hAsbdwmHbN.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/VRFzZoJdhFWL8rkvu87LpKM3RbcVezpMEc6X5GVDr7y.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/ZETAxsqBRek56DhiGXrn75yj2NHU3aYUnxvHXpkf3aD.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/aMERKpFAWoChCi5oZwPvgsSCoGpZKBiU7fi76bdZjt2.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/abrn446KXzKZxSowJdHN9XumbGfQi4DdAfWHBT7X81r.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/cardWArqhdV5jeRXXjUti7cHAa4mj41Nj3Apc6RPZH2.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/ccvrfu3fSpbnPLiUqdWAt85Zn9nq96ekwGTbHqGtdgQ.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/cjg3oHmg9uuPsP8D6g29NWvhySJkdYdAo9D25PRbKXJ.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/cmtDvXumGCrqC1Age74AVPhSRVXJMd8PJS91L8KbNCK.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/compr6CUsB5m2jS4Y3831ztGSTnDpnKJTKS95d64XVq.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/credMBJhYFzfn7NxBMdU4aUqFggAjgztaCcv2Fo6fPT.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/dbcij3LWUppWqq96dh6gJWwBifmcGfLSB5D4DuSMaqN.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/fUSioN9YKKSa3CUC2YUc4tPkHJ5Y6XW1yz8y6F7qWz9.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/ghosty4ZU1Qk1HN7Ymz4pZ15QfspzJZgSYFkdKN6ZLK.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/hdaoVTCqhfHHo75XdAMxBKdUqvq1i5bF23sisBqVgGR.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/hyRouTRDAgn65xyyJ3L5c4k5SFmSdr3NxDV8Euzjy3f.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/jupZ4m2GqUCJ5iueMfzQf8khFfH31d4XAQt3RzCT9Vd.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/mayan34VedncxdK2XobtvWFDXQASUTBXhUVzt2kKgny.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/mmm3XBJg5gk8XJxEKBvdgptZz6SgK4tXvn36sodowMc.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/nosJhNRqr2bc9g1nfGDcXXTXvYUmxD4cVwy2pMWhrYM.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/offqSMQWgQud6WJz694LRzkeN5kMYpCHTpXQr3Rkcjm.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/omnixgS8fnqHfCcTGKWj6JtKjzpJZ1Y5y9pyFkQDkYE.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/ord1qJZ3DB52s9NoG8nuoacW85aCyNvECa5kAqcBVBu.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/proVF4pMXVaYqmy4NjniPh4pqKNfMmsihgd4wdkCX3u.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/pv1ttom8tbyh83C1AVh6QH2naGRdVQUVt3HY1Yst5sv.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/pyt2F414BA6dPttK6RddPZUdHfapoBN24GL5wbrPCou.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/pytd2yyk641x7ak7mkaasSJVXh6YYZnC7wTmtgAyxPt.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/pythWSnswVUd12oZpeFP8e9CVaEqJg25g1Vtc2biRsT.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/rec2HHDDnjLfj4kE7VyEtFA1HPGQLK33259532cRyHp.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/strmRqUCoQUgGUan5YhzUZa6KqdzwX5L6FpUxfmKg5m.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/swapNyd8XiQwJ6ianp9snpu4brUqFxadzvHebnAXjJZ.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/traderDnaR5w6Tcoi3NFm53i48FTDNbGjBSZwWXDRrg.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/ttaiNybR4ncnBFsBCQKdVus8BNHepErToRp5cuULduL.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/tuktukUrfhXT6ZT77QTU8RQtvgL967uRuVagWF57zVA.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/tuna4uSQZncNeeiAMKbstuxA9CUkHH6HmC64wgmnogD.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/vo1tWgqZMjG61Z2T9qUaMYKqZ75CYzMuaZ2LZP1n7HV.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/out/onchain_idls/zapvX9M3uf5pvy4wRPAbQgdQsM1xmuiFnkfHKPvwMiz.json`: machine-validated: file name is a program id; discriminators and slot counts compared with its manifest
- `graphite-core/scripts/populate_expected_addresses.py`: read in part (header); validated through its outputs (624 expected_address values, all base58 32-byte)
- `graphite-core/scripts/probe_dca_pda.py`: read in part (header, RPC request version); NOT run: it reads a public RPC, which this audit may not contact
- `graphite-core/scripts/rebuild_account_lists.py`: read in part (header); one-off; validated through its outputs
- `graphite-core/scripts/rebuild_drift_kamino_manifest.py`: read in part (header); needs an RPC for its census input; validated through its outputs
- `graphite-core/scripts/rebuild_orca_manifest.py`: read in part (header); one-off; validated through its outputs (the 65 Orca slot-count pins)
- `graphite-core/scripts/reclassify_manifests.py`: read in part (docstring, rules, --check path); re-run `--check`: 0 instructions would change
- `graphite-core/scripts/recompute_evidence.py`: read fully (recompute rule mirrored in validate_corpora.py); re-run `--check`: clean
- `graphite-core/scripts/render_coverage.py`: read in part; re-run to scratch: byte-identical to docs/protocol-coverage.md
- `graphite-core/scripts/solana_inventory_census.py`: read in part (header, RPC request version); NOT run: it reads a public RPC, which this audit may not contact
- `graphite-core/scripts/solana_keys.py`: read in part (base58/PDA helpers for the scripts); not on any verdict path
- `graphite-core/scripts/validate_corpora.py`: NEW (Round 39): the corpus validator; run with every section, exit 0
- `graphite-core/scripts/verify_dk_pdas.py`: read in part (header, RPC request version); NOT run: it reads a public RPC, which this audit may not contact

## 2. Findings

| ID | Sev | One line | Status |
|---|---|---|---|
| R39-SUPPLY-CHAIN-1 | P1 (owner gate, STOP-SHIP) | The live ruleset is not the committed one: one uncommitted `Main-review`, 26 `always` bypass actors (admin and maintain roles, 24 GitHub Apps), 0 approvals, an extra Copilot rule; no tag ruleset; private vulnerability reporting off; `release` environment unreadable | owner action; docs give exact steps |
| R39-SUPPLY-CHAIN-2 | P2 | `ruleset-drift.py` matched by name and only noted a live ruleset without a committed file, so none of `Main-review`'s differences was compared; `main-review.json` optional, so 0 approvals was never a gap; an invisible bypass list was a notice under a "match" | fixed with tests (B1–B4) |
| R39-SUPPLY-CHAIN-3 | P3 | The drift check failed an admin token's read of a correct state (`current_user_can_bypass: always` on `release-tags-create`), so the owner's own verification could not pass | fixed with test |
| R39-SUPPLY-CHAIN-4 | P3 | `.github/scripts/*.sh` were never shellchecked; `test-count.sh:54` had SC2086/SC2116 | fixed with test (B5) |
| R39-SUPPLY-CHAIN-5 | P3 | `graphite-core/fuzz/Cargo.lock` (204 crates, built and run on every PR by `assurance.yml`) was the one Cargo lockfile no job audited | fixed (CI step; clean locally) |
| R39-SUPPLY-CHAIN-6 | P3 | No workflow runs actionlint, and it is not pinned; actionlint 1.7.7 rejects `release.yml:419` `artifact-metadata: write`, 1.7.11 is clean | open (recommendation) |
| R39-SUPPLY-CHAIN-7 | P3 | `graphite-core/Cargo.toml:32` `anyhow = "1"` is referenced nowhere in `src/`, `tests/` or `benches/` and pulled in by nothing else, yet ships in the SBOM | open (needs a Cargo.lock change and a build) |
| R39-SUPPLY-CHAIN-8 | P3 | `release-guard.yml` checks only tag-push runs; a writer's branch copy of `release.yml` that publishes on `workflow_dispatch` is outside it | accepted limitation, documented; `--source-ref` verification refuses its attestations |
| R39-SUPPLY-CHAIN-9 | P3 | `SECURITY.md`'s only contact is an e-mail address and the issue template links to it; private vulnerability reporting is off | owner action (`SECURITY.md` not edited) |
| R39-SUPPLY-CHAIN-10 | P3 | Checklist item 13 said the nine medium rewrites have no IDL; Marinade's has one (with no docs) | fixed (docs) |
| R39-SUPPLY-CHAIN-11 | P3 | Meteora DLMM ships a phantom `swap_2` (`df7e2d55564d1fc2` = sha256("global:swap_2")) beside the real `swap2`; 27 more 8-byte discriminators (Jupiter 15, Meteora 7, Squads 5) are in no instruction of their committed on-chain IDL | open (manifest change; owner/next round) |
| R39-SUPPLY-CHAIN-12 | P3 | Manifest data labels: ATA `associated_account_address` is role `pda` with no seeds; ATA `funding_account` role `writable` on a signer; Kamino and Solend layouts repeat account names; Solend `FlashLoan` lists two truncated names | open (pinned; none reaches a declaration) |
| R39-SUPPLY-CHAIN-13 | P3 | Two on-chain IDLs carry an `address` field that is not the program they were read from | informational, pinned |
| R39-SUPPLY-CHAIN-14 | P3 | `docs/CURRENT.md` K-7 says 64 Orca + 10 Kamino; the pinned list is 65 + 10 = 75 | main session (CURRENT not edited) |
| R39-SUPPLY-CHAIN-15 | — | Coordinator item: `live-mainnet.yml` seed exit read from `outcome` | not reproduced at `c087bfb` (fixed in Round 36); now pinned by a test (B8, B9) |

### R39-SUPPLY-CHAIN-1 — the live rulesets (P1, owner gate)

- **Where:** repository settings, read 2026-10-25: `GET repos/Stan-lee13/graphite/rulesets` lists one
  ruleset, `Main-review` (id 25817024, created 2026-10-25T10:51+01:00); `GET …/rulesets/25817024`
  (saved as `.github/scripts/testdata/ruleset-drift-live-2026-10-25/`). `GET …/rules/branches/main` =
  that ruleset's rules only. No tag ruleset. `GET …/private-vulnerability-reporting` =
  `{"enabled": false}`. `GET …/environments` and `…/environments/release`: 403 from the session's
  proxy, so the `release` environment is **not verified**; `GET …/deployments?environment=release` = [].
- **The differences from the committed files**, all named by the fixed drift check (71 in all):
  name (`Main-review` vs the committed names); 0 required approvals, no code-owner or last-push
  review (`main-review.json`: 1, both on); `require_extra_approval_for_unattributed_changes: true`
  (not committed); an extra `copilot_code_review` rule; bypass actors RepositoryRole 2 (maintain)
  and 5 (admin) and Integrations 8329, 13473, 14658, 29110, 85455, 330661, 646161, 811515, 818760,
  842251, 946600, 1095633, 1143301, 1144995, 1201222, 1210556, 1236702, 1690828, 1734312, 1869309,
  2413863, 3810936, 4229212, 4518051, every one `always` (24 apps, not about 15; the app names are
  not readable through this session's API proxy, the Settings page shows them); `release-tags.json`
  and `release-tags-create.json` absent; the `release` environment absent as far as can be read.
- **Impact:** each of the 26 actors (an app only where it holds write access) can push to `main`,
  force-push or delete it without a pull request or `CI gate`; no change is reviewed; any writer can
  create, move or delete a `v*` tag, so the pre-gate `release.yml` path of R37-8 is open (the release
  guard is the only line, and it is defence in depth). The empty `allowed_signers` still refuses
  every gated release.
- **Owner steps:** `docs/ops/branch-protection.md` §1–§3 and checklist R1/R5: import the four
  committed files under their exact names (`gh api -X POST …/rulesets --input …` or Settings → Rules
  → Rulesets → New ruleset ▾ → Import a ruleset), then delete ruleset 25817024; create the `release`
  environment (R2); read back with `ruleset-drift.py --live <dir> --require-bypass` as admin, which
  must exit 0. Then enable private vulnerability reporting.
- Reproduced (API read). Confidence high.

### R39-SUPPLY-CHAIN-2 — the drift check compared nothing it could not name (P2, fixed)

- **Where:** `.github/scripts/ruleset-drift.py` at `c087bfb`: lines 174–176 (`live ruleset … has no
  committed file` was a `notes.append`), line 34 (`REQUIRED` without `main-review.json`), lines
  91–95 (an invisible `bypass_actors` was a note, and the final line said "match").
- **Preconditions:** the real state: an uncommitted ruleset doing `main`'s job. Or an owner who
  renames `Main-review` to `main.json`'s name and drops the Copilot rule: under GITHUB_TOKEN the old
  check then reported **no drift** for `main.json` with 26 always-bypass actors still on it.
- **Fix:** an uncommitted live ruleset is a difference and is compared field by field with every
  committed ruleset for the same target and refs (name, rules, parameters, each bypass actor added
  or missing); `main-review.json` is required; `--require-bypass` turns an invisible bypass list into
  a difference (the owner's admin run); the weekly run's green says "bypass lists NOT VERIFIED".
- **Tests** (`ci-scripts.test.sh`, section "ruleset-drift.py against the live state of
  2026-10-25"): today's live state fails and names each of the 11 difference kinds and all 24 apps;
  the GITHUB_TOKEN view of it fails; an uncommitted ruleset beside the committed ones fails
  (Round 38: exit 0); `main.json` carrying the 26 actors fails when visible, passes NOT VERIFIED when
  hidden, and fails with `--require-bypass`; `main-review.json` absent fails. Benign controls: the
  committed state applied passes (hidden and visible).
- **Breaks** (copies under `/home/user/brk-supply-chain-1`, deleted): B1 the Round 38 script against
  the new tests: 18 drift cases fail. B2 uncommitted back to a notice: 11 fail. B3 `main-review.json`
  optional again: 1 fails ("main-review.json absent"). B4 `--require-bypass` ignored: 2 fail.
- Reproduced. Confidence high.

### R39-SUPPLY-CHAIN-3 — an admin's read of a correct state failed (P3, fixed)

`ruleset-drift.py:96–100` at `c087bfb` required `current_user_can_bypass == "never"` on every ruleset,
including when `bypass_actors` was visible. An admin token reads `always` on `release-tags-create`
(its bypass is the admin role), so the owner's R5 read could never pass. Now a visible list is the
authority and the caller's own answer is reported. Test: "applied as committed, read by an admin …
no drift". Code-reviewed (the Round 38 script also rejects the new flag, so the old behaviour is not
separately reproduced). Confidence high.

### R39-SUPPLY-CHAIN-4 — the CI scripts were never shellchecked (P3, fixed)

`deploy/tests/run.sh:77` shellchecks `deploy/` only, and actionlint reads only inline `run:` blocks.
`shellcheck -x .github/scripts/*.sh` at `c087bfb`: exit 1, `test-count.sh:54` SC2116 and SC2086
(`$(echo $unlisted)`). Fixed (`tr '\n' ' '`), and `ci-scripts.test.sh` now shellchecks the directory
(a missing shellcheck is a failure, not a skip; the hosted image ships it). Test: the unlisted-ignored
message still names the test (and not the listed one). B5: the original line fails shellcheck.

### R39-SUPPLY-CHAIN-5 — the fuzz lockfile was not audited (P3, fixed)

`ci.yml` audited `graphite-core`, both oracles and seven npm lockfiles, not
`graphite-core/fuzz/Cargo.lock`, which `assurance.yml`'s fuzz job builds and runs on every pull
request. `cargo audit --deny warnings` there: 204 crates, clean (cargo-audit 0.22.2, 1,352 advisories,
2026-10-25). A step was added to the `supply-chain` job. Not yet run on GitHub.

### R39-SUPPLY-CHAIN-6 — actionlint is not part of CI (P3, open)

No workflow runs actionlint and `pinned-tools.json` lists none. Locally (Go 1.24.7 build):
actionlint 1.7.7 reports `release.yml:419` "unknown permission scope `artifact-metadata`" and an
SC2153 info at `live-mainnet.yml:207`; 1.7.11 is clean on every workflow. Round 38's "actionlint
clean" was a local run of an unrecorded version. Recommendation: a pinned actionlint (release binary
by checksum, or `go install …@v1.7.11` with the checksum database) in the `ci-scripts` job, listed in
`pinned-tools.json`. Not wired here because the install path could not be exercised on a hosted runner.

### R39-SUPPLY-CHAIN-7 — an unused crate ships (P3, open)

`graphite-core/Cargo.toml:32` `anyhow = "1"`: `grep` finds no `anyhow` in `src/`, `tests/`, `benches/`
or `examples/` (no `bail!`/`ensure!` either), and `cargo tree -i anyhow` shows only `graphite-core`.
It ships in the CycloneDX SBOM and the binary's dependency set. Removing it changes `Cargo.lock`,
which needs a `cargo check` of every feature leg; left for a workstream that builds Rust.

### R39-SUPPLY-CHAIN-8 — the guard watches tag pushes only (P3, accepted)

`release-guard.yml:48,86` run only for `workflow_run.event == 'push'`. A collaborator with write access
can push a branch whose `release.yml` (named `Release`) publishes on `workflow_dispatch` and drops the
`release` environment; the guard skips it. Its attestations name `refs/heads/<branch>`, so the
documented attestation check (`--source-ref refs/tags/v<version>`, in `docs/ops/production-checklist.md`) refuses them, but a GHCR push
would land. This is the same class as "a workflow under another name": write access runs workflows.
Documented in the checklist's release-integrity paragraph. Code-reviewed.

### R39-SUPPLY-CHAIN-9 — the security contact (P3, owner)

`SECURITY.md` "Reporting a Vulnerability": e-mail only. `.github/ISSUE_TEMPLATE/config.yml` links to
`…/blob/main/SECURITY.md`. Private vulnerability reporting: off (verified). What `SECURITY.md` needs
once the owner enables it: the advisory form `https://github.com/Stan-lee13/graphite/security/advisories/new`
first, the e-mail as fallback, and the issue template's link pointed at the form, in one pull request.

### R39-SUPPLY-CHAIN-10 — item 13's reason (P3, fixed)

`docs/ops/production-checklist.md` item 13 said all nine medium rewrites lack an IDL file. Eight do;
Marinade `liquidUnstake`'s `idl_source` is `graphite-core/scripts/idls/marinade.json`, medium because
"the IDL carries no docs". Corrected; the item now also names `validate_corpora.py`.

### R39-SUPPLY-CHAIN-11 — manifest instructions no IDL has (P3, open)

`validate_corpora.py` (idls section) matches instructions by exact snake-case name, then compares
discriminators: 3,117 equal, 0 differ. 28 manifest instructions with an 8-byte discriminator are in no
instruction of their program's committed on-chain IDL:
- `meteora-dlmm.json::swap_2` (`df7e2d55564d1fc2` = sha256("global:swap_2")), unclassed, with an old
  unscoped declaration, beside the real `swap2` (`414b3f4ceb5b5b88`, rewritten in Round 36). A
  punctuation-blind match conflates the two. `docs/CURRENT.md` and the Round 38 report say "Meteora
  DLMM's swaps except `swap_2`"; the instruction that works is `swap2`.
- Meteora also: `initialize_pool`, `initialize_pool_with_custom_curve`, `add_pool_fee`,
  `remove_pool_fee`, `remove_liquidity_by_strategy`, `claim_all_reward`, `add_liquidity_single_side`.
- Jupiter v6: the four `*AccountCompressionRoute`, the eight `*RouteCheck`, `closeTokenLedger`,
  `route_with_token_ledger_v2`, `shared_accounts_route_with_token_ledger_v2`.
- Squads v4: `transactionBufferCreate`, `transactionBufferClose`, `transactionBufferExtend`,
  `vaultTransactionCreateFromBuffer`, `proposalCancelV2`.

These may be newer than the committed IDL or may never have existed. Impact: none on a verdict that
matters (the program refuses data it has no instruction for, and nothing here approves value), but a
declaration nobody can exercise is unreviewed surface and misleads documentation. Removing one changes
the instruction count (3,541) and the regenerated corpus: a Rust change for the owner or a later
round, with on-chain evidence per instruction.

### R39-SUPPLY-CHAIN-12 — manifest labels (P3, open, pinned)

- `ata-program.json` `CreateAssociatedTokenAccount{,Idempotent}` slot 1 `associated_account_address`:
  role `pda`, `pda_seeds: []`, so the manifest neither derives nor checks it (the ATA program does).
  Seeds `{account_2}`, `{account_5}`, `{account_3}` under the ATA program would ground it; that is a
  manifest change with tests.
- the same instructions' slot 0 `funding_account`: role `writable`, `is_signer: true`. The pipeline
  reads the flags; the role is a label (`grep '\.role'` in `src/` finds display uses only).
- `kamino-lending.json` `depositAndWithdraw` (13 names) and `repayAndWithdrawAndRedeem` (7) repeat
  account names (flattened IDL groups); `solend.json` `FlashLoan` repeats `Token program id`. No
  declaration names a repeated account (`accounts.<name>`); the validator fails if one ever does.
- `solend.json` `FlashLoan`'s "modifies writable accounts" line lists two names truncated at a comma.

### R39-SUPPLY-CHAIN-13 — IDL `address` fields (P3, informational)

`out/onchain_idls/61DFfeTKM7trxYcPQCM78bJ794ddZprZpAwAnLiwTpYH.json` says `RderEngine…2`;
`cardWArqhdV5jeRXXjUti7cHAa4mj41Nj3Apc6RPZH2.json` says `E7vM2t…`. The IDL accounts are the programs'
own (the onboarding gate); the field is what their authors wrote. Pinned, not trusted either way.

### R39-SUPPLY-CHAIN-14 — K-7 count in CURRENT (P3, main session)

`docs/CURRENT.md:833–836`: "75 instructions … (64 Orca … 10 Kamino …)". The pinned list in
`tests/r30_declared_effects_census.rs:282–358` and `validate_corpora.py` both count 65 Orca + 10 Kamino.

### R39-SUPPLY-CHAIN-15 — the live-mainnet seed (coordinator item 1)

At `c087bfb`, `live-mainnet.yml:175–179` records the exit and then `exit "$code"` on failure, and the
replay's `SEEDED` (line 206) is `steps.seed.outputs.exit == '0'`; nothing reads `steps.seed.outcome`.
Round 36's ledger hit described the earlier file. Not reproduced. Pinned by a new test ("a failed
seeding is never reported as seeded"); B8 (the `exit` removed) and B9 (`SEEDED` from the outcome)
both fail it.

### Coordinator item 2 — `needs-review` hits under `.github/` and `deploy/`

| File:line | Pattern | Disposition |
|---|---|---|
| `.github/scripts/release-gate.sh:186` | `\|\| true` | intentional: `find-principals` exits non-zero when no key matches; the empty result is then refused with the reason (expired/not-yet-valid or unknown key) |
| `.github/scripts/test-count.sh:43` | `\|\| true` | intentional: `grep -c` exits 1 on a count of 0; the next line refuses a log with no `test result:` |
| `.github/scripts/test-count.sh:98` | `\|\| true` | intentional: same for the Go `--- PASS` count, compared with the floor below |
| `.github/workflows/assurance.yml:219` | `set +e` | intentional: cargo-mutants exits non-zero on a missed mutant; the next step judges `outcomes.json` against the floor, INCOMPLETE included |
| `.github/workflows/ci.yml:509` | `TODO` | benign: the step greps the TAP log for `# SKIP`/`# TODO` and fails on one; it is a check, not a marker |
| `.github/workflows/ci.yml:575, 595, 609` | `\|\| true` | benign cleanup: `docker rm -f` of a container that may not exist |
| `.github/workflows/ci.yml:576` | `set +e` | intentional: the keyless container must exit non-zero; its code is captured and judged (124/137 = started, 0 = wrong, no "refusing to" = wrong) |
| `.github/workflows/ci.yml:582` | `\|\| true` | intentional: logs of a container that may have died; judged by `grep` |
| `.github/workflows/ci.yml:698, 699, 703, 704` | `\|\| true` | benign cleanup in `if: always()` steps |
| `.github/workflows/live-mainnet.yml:170` | `set +e` | intentional, and correct at `c087bfb`: finding 15 |
| `.github/workflows/live-mainnet.yml:210` | `set +e` | intentional: the replay's exit goes to `outputs.exit`, which the Verdict step requires to be `0` |
| `.github/workflows/live-mainnet.yml:224` | `\|\| true` | intentional: a missing pid file is "the Core was not running", reported `clean=false`, which the Verdict step fails |

No hit under `deploy/` was in the file.

## 3. Prior findings re-verified

| ID | Status at `c087bfb`, re-checked |
|---|---|
| R37-8 (release integrity) | Code half holds: `release-gate.test.sh` 52/52 (ancestry from `ad3f7ad`, pre-gate `99948c6` refused, revoked and expired signers, same-tag); the guard's structure test passes. Owner half OPEN and worse than documented: R39-SUPPLY-CHAIN-1 |
| D2-3 (same-tag before publish) | holds: structure test; `same-tag` cases pass |
| D2-4 (main-review admin bypass by PR only) | committed and tested; not live; now required by the drift check |
| D2-5 (revoked/expired signers) | holds (release-gate tests) |
| D2-6 (one pin everywhere) | holds: 11 pins consistent |
| D2-7 (dependency holds) | holds: 25 holds current, first review due 2027-01-20 |
| D2-8 (per-binary test floors) | still open: `ci.yml:218–224` prints per binary but passes no floors file (no Rust build here to measure them) |
| D-8 (image apt layer) | the snapshot pin holds (structure test); the image was not built here |
| D-9 (RPC env injection) | holds: `set-rpc-env.sh` tests pass |
| R33-18 (attestation commands pin the signer) | holds: all 8 commands |
| A6-05 (lockfiles audited) | holds, extended to the fuzz lockfile (R39-SUPPLY-CHAIN-5) |
| A6-10 (no persisted credentials) | holds: each of the 26 checkouts has `persist-credentials: false`; no `pull_request_target`; every action pinned by commit |
| R36-L2 / checklist item 6 (paired oracle crates) | holds: PRs #46 (closed 2026-10-22), #47, #48 (2026-10-24, each bumping one of `solana-transaction`/`solana-message` in `tools/runtime-oracle`), #52 (`solana-message` 6 alone in `tools/inner-instruction-oracle`, whose `solana-message` must be what `solana-transaction-status =4.3.2` resolves) all closed unmerged by Dependabot; the semver-major ignores and holds are in place. The owner's confirmation is still the item |
| F-019 (one Core replica) | holds: deploy kit's compose checks (container_name + `replicas: 1`; `replicas: 2` and `scale: 2` refused), the plain systemd unit, a second Core on the live directory refused |
| F-005 (nine medium rewrites) | holds: exactly the nine of the brief, each still in its manifest; none promoted |
| K-7 (75 slot-count differences) | holds: 75 recomputed independently (65 Orca, 10 Kamino); CURRENT's 64 is wrong (R39-SUPPLY-CHAIN-14) |
| Round 29 MED-1 (evidence derived fields) | holds: `recompute_evidence.py --check` clean; 13 under the decode bar, the brief's 13 |
| Round 29 (coverage page deterministic) | holds: rebuilt byte-identical |
| Round 36 ledger (deterministic) | holds: rebuilt byte-identical |
| Brief §2.2 item 3 (private vulnerability reporting) | verified off |
| Brief §2.2 item 15 (`publish = false`) | still absent; owner decision |
| Brief §2.2 item 16 (empty `allowed_signers`) | holds: empty, every gated release refused |

## 4. Attack campaigns and Phase F checks

Campaign 13 (registry/manifest content) and the Phase G/F checks are what this scope reaches; the
other campaigns are other workstreams'.

- **F-1 manifest invariants.** Preconditions: a manifest edited by hand or by a generator. Command:
  `python3 -I graphite-core/scripts/validate_corpora.py`. Expected and observed: 137 manifests, 137
  unique program ids, 3,541 instructions, 26,475 account slots; no prefix-related discriminators, no
  malformed base58 (program ids, 624 `expected_address`, every `allowed_cpis`), every PDA seed in the
  grammar and inside its layout, 46 unclassed instructions, tiers 113 BattleTested / 24
  OfficialManifest, each BattleTested with a record that meets the thresholds. Seeded faults
  (`ci-scripts.test.sh`): prefix collision, bad CPI key, `{account_99}`, a duplicate program id, an
  unearned BattleTested — each fails. Breaks B6 (prefix check off) and B7 (medium-rewrite check off)
  pass the fault, the real validator fails it.
- **F-2 evidence and decode counts.** 137 records, each equal to its own counts; 114 meet the
  thresholds, 113 declare BattleTested (Metaplex Token Metadata meets them and declares
  OfficialManifest, which is allowed: a tier is never raised by the record); the 13 under the decode bar: Account
  Compression 0/45, Light System Program 0/45, Ocr2 0/40, Oridion 0/40, Pump Fees 0/4,195, Rush
  1/40, Bubblegum 3/53, Merkle Distributor 22/45, Coinflow 45/90, Zeta 63/94, Doorcash 27/40, Main
  29/40, Timelock 38/49. Their unknown bytes stay refused; nothing was promoted.
- **F-3 provenance labels.** Corpus: 12,943 `synthetic-manifest`, 28 `synthetic-attack`, 4
  `synthetic-benign`, 37 `real-mainnet-exploit:<signature>` (each a valid 64-byte signature), 1
  `real-mainnet-tx`; the meta manifest agrees row for row (a relabel fails). Holdout 38 = 37 real
  exploits + 1 real transaction (expected approved: 1). Artifacts, from their own labels: real
  mainnet (sample), real mainnet + reconstructed mutations (`mainnet_v0_alt.json`), real devnet with
  placeholder signatures (`devnet_transactions.json`), synthetic (`privilege_artifacts`,
  `undescribed_account`, both SAK files, `alt_privilege` — whose label does not say so, pinned).
- **F-4 generators reproduced** from committed inputs: `reclassify_manifests.py --check` (0
  changes), `recompute_evidence.py --check` (clean), `render_coverage.py` (identical),
  `apply_idl_optional_flags.py` on a copy (no diff), `docs/audit-r36/build_ledger.py` (both outputs
  identical). Not reproducible: `onboard_from_inventory.py` (uncommitted `inventory_metadata.json`),
  and every census/fetch script (a public RPC).
- **F-5 coverage** (reported, not gated; volume is not coverage):
  - by transaction version: the 13,013 corpus entries are all legacy descriptions without wire bytes;
    wire forms are only in the artifacts (v0: 3 mainnet + mutations, SAK 2; v1: SAK 2) and the
    mainnet sample (1,499 legacy, 472 v0, 313 v1), none of which carries an expected verdict;
  - by protocol: every one of the 137 manifests has entries; 5 entries name an unmanifested program;
  - by instruction class: authority 4,847, transfer 3,705, create 1,774, withdraw 1,480, close 582,
    inert 195, unknown discriminator 152, unclassed 120, mint 84, stake 35, drain 34;
  - by exploit family / refusal class: no-intent 3,541, account-overflow 3,113, intent-mismatch
    2,186, near-prefix 157, padded-width 138, unknown-instruction 137, real-exploit 37, P0 width 9,
    sweep 5, risk-class 5, multi-instruction 4, traversal 2, custom repeats 1, CPI trace 1, P12 1;
  - benign flows: 1,108 expected approved (offline approvals are `analysis_only`);
  - CPI shape: 4,472 none, 8,536 with declared CPI targets, 5 with a CPI trace;
  - Token-2022: 220 base-instruction entries and 146 across 16 extension instruction families;
  - unknown program: 5.
- **F-6 schemas.** Both schemas are valid 2020-12; the six examples validate.

## 5. Invariant evidence

| Invariant | Implementation | Tests | Gap |
|---|---|---|---|
| Operational integrity: release provenance | `release-gate.sh`, `release.yml` gate/publish, `release-guard.yml` | `release-gate.test.sh` 52; ci-scripts structure tests | the rulesets and environment are not live (R39-SUPPLY-CHAIN-1); signer list empty by design |
| Operational integrity: the settings are as committed | `ruleset-drift.py` (weekly) | 40 drift cases incl. the live snapshot | bypass lists need an admin read (`--require-bypass`) |
| Supply chain: dependencies | `cargo audit` ×4 lockfiles (fuzz added), `gate.mjs` ×7, `pip-audit` | gate tests 10; all clean 2026-10-25 | actionlint not in CI; `anyhow` unused |
| Single Core replica | compose `container_name` + `replicas: 1`; plain systemd unit; data-dir locks | `deploy/tests/run.sh` (compose and second-Core checks pass) | — |
| Evidence integrity (manifest data) | Rust `validate_manifest`; `validate_corpora.py` across files | 13 seeded faults; Rust suites not run here | phantom/unevidenced instructions (R39-SUPPLY-CHAIN-11) |
| Honest labels | corpus `source`, meta `provenance`, artifact labels | validator relabel faults | `alt_privilege.json` label silent on provenance |

## 6. Commands run

| Command | Result |
|---|---|
| `bash .github/scripts/release-gate.test.sh` | 52 passed, 0 failed |
| `bash .github/scripts/ci-scripts.test.sh` (before / after) | 77 / 121 passed, 0 failed |
| `node --test .github/npm-audit/gate.test.mjs` | 10 passed |
| `python3 .github/scripts/pinned-tools.py check-pins` / `dependency-holds.py check` / `check-attestation-commands.py` | 11 pins / 25 holds / 8 commands: pass |
| `actionlint -shellcheck shellcheck` (1.7.11; 1.7.7) | clean; 1.7.7: 1 error, 1 info (R39-SUPPLY-CHAIN-6) |
| `shellcheck -x` on all 13 tracked `.sh` (0.11.0) | before: 1 file with 2 findings; after: clean |
| `GRAPHITE_BIN=/home/user/bin/graphite-c087bfb bash deploy/tests/run.sh` | 139 passed, 24 failed — all 24 need Caddy or promtool (6 static, 16 edge, the trail-head check whose verdicts go through Caddy, 1 promtool metrics): **BLOCKED**, not passing |
| `cargo audit --deny warnings` (0.22.2): graphite-core, fuzz; both oracles with `--ignore RUSTSEC-2025-0141` | 262 / 204 / 79 / 438 crates: no advisory |
| `cargo metadata --locked` ×4 | consistent |
| `npm audit --json` + `gate.mjs`, seven lockfiles | all pass the gate |
| npm lockfile/`package.json` consistency (script in the scratchpad) | 7/7 consistent, every package hashed from registry.npmjs.org |
| `pip-audit -r python-ai-layer/requirements-lock.txt --require-hashes` (2.9.0) | no known vulnerability |
| `python3 -I graphite-core/scripts/validate_corpora.py` (3.11, 3.12, 3.13) | exit 0; 495 strict JSON + 2 JSONC; 63 pinned known gaps |
| generators: reclassify, recompute, render_coverage, optional flags, build_ledger | all reproduce |
| read-only `curl api.github.com`: rulesets, ruleset 25817024, rules/branches/main, private-vulnerability-reporting, pulls, tags, releases, check-runs/actions runs of `c087bfb` | as reported; environments: 403 (not verified) |

BLOCKED: `caddy validate`/`fmt` and every edge check (`CADDY_BIN`; command: `deploy/tests/run.sh`
with `CADDY_BIN` and `PROMTOOL_BIN` set, as `ci.yml`'s deploy job does); `promtool check rules`,
`test rules`, `check config`, `check metrics` (same); `docker build`/`docker compose up` (no Docker
daemon: `docker build -t graphite-core:ci .`); the `release` environment read (`gh api
repos/Stan-lee13/graphite/environments/release`, admin token); the GitHub App names of the 24 bypass
actors; Rust builds and tests (not run by rule). None is counted as passing.

## 7. For the main session

- `docs/CURRENT.md`: the live ruleset state (one uncommitted `Main-review`, 26 always-bypass actors,
  0 approvals, Copilot rule, no tag rulesets), PVR verified off, the release environment not
  verifiable; K-7 is 65 Orca + 10 Kamino; "Meteora DLMM's swaps except `swap_2`" should name `swap2`;
  the ci-scripts floor is 121; `validate_corpora.py` exists.
- `SECURITY.md` (not edited): once PVR is on, the advisory form first and the address as fallback.
- `graphite-core/CHANGELOG.md`: the drift-check change (main-review required; uncommitted rulesets
  fail; `--require-bypass`), the fuzz lockfile audit, the validator.
- Break log: B1–B9 above.
- Owner: R39-SUPPLY-CHAIN-1 steps; confirm PRs #46–#48/#52; sign off or correct the nine medium
  rewrites; decide `publish = false`; decide on the 28 unevidenced manifest instructions.
