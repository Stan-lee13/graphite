---
name: Hardening Suggestion (no exploit details)
about: Suggest defence-in-depth, a stricter default, or a missing test. NOT for vulnerabilities — those go through SECURITY.md privately.
title: "[HARDENING] "
labels: hardening
---
<!--
STOP if what you have is a way to get a transaction approved that should be
blocked, to bypass authentication, to corrupt the audit trail, or anything
else an attacker could use today. This issue is PUBLIC. Report it privately
as described in SECURITY.md:
https://github.com/Stan-lee13/graphite/blob/main/SECURITY.md

This template is for suggestions that are safe to discuss in the open: a
stricter default, an extra check, a missing test, a documentation gap. Do not
include a proof of concept, a crafted transaction, or reproduction steps for
a bypass.
-->

## Suggestion
What should be stricter, checked, or tested, and why?

## Affected Component
- [ ] Risk Engine
- [ ] Confidence Engine
- [ ] Protocol Manifest
- [ ] Policy Engine
- [ ] CPI Validation
- [ ] Account Resolution
- [ ] Transaction artifact / wire-format parser
- [ ] Execution boundary (signing, L8 attribution, the SAK bridge)
- [ ] Trust-tier evidence (`battle_tested_evidence.json` and the loader gate)
- [ ] CI / supply chain / container
- [ ] Other

## Current behaviour
What Graphite does today, described at the level of documented behaviour
(no exploit details).

## Proposed behaviour
What it should do instead, and what it would cost (false refusals, latency,
compatibility).

## Confirmation
- [ ] This is not an exploitable vulnerability. If it were, I would have
      reported it privately through SECURITY.md instead.
