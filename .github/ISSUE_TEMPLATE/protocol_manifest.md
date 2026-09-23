---
name: Protocol Manifest Submission
about: Submit a new protocol manifest for the Graphite knowledge base
title: "[MANIFEST] "
labels: protocol-manifest
---
## Protocol Information
- **Name:**
- **Program ID:**
- **Where the instruction surface came from:** (the program's own on-chain
  Anchor IDL account, the published IDL, or program source — say which, and
  link it)

## Manifest
```json
{
  "graphite_manifest_version": "1.0",
  "protocol": { ... },
  "version": { ... },
  "instructions": [ ... ],
  "trust_tier": "OfficialManifest"
}
```

## Verification
- [ ] Program ID confirmed **executable on mainnet** (`getAccountInfo`), not
      just read off an explorer page
- [ ] Discriminators come from the program's own IDL, or are derived the way
      its generated client derives them, and were **confirmed against real
      mainnet transactions**
- [ ] Account names, order, writability and signer-ness are the IDL's, not
      transcribed from documentation
- [ ] PDA seed templates are declared **only** where the deployed program
      seed-constrains the account (a guessed template flags legitimate
      transactions)
- [ ] `allowed_cpis` declares what the program really calls
- [ ] `trust_tier` is `OfficialManifest` — `BattleTested` is not something a
      submission may claim; it is measured
      (`graphite-core/scripts/battle_tested_census.py`) and the loader lowers
      an unsupported claim

## Measurement (run this and paste the line)
```
python graphite-core/scripts/battle_tested_census.py <PROGRAM_ID> --merge
```
- Successful transactions counted / window:
- Instructions observed / share the manifest can name:

## References
- Protocol docs:
- Source or IDL:
- Audit reports (if any):
