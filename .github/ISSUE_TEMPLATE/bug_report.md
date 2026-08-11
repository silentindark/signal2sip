---
name: Bug report
about: Something doesn't work the way it should
title: ""
labels: bug
assignees: ""
---

<!--
Before you paste any logs below: signal2sip logs can contain phone
numbers, Signal account identifiers (ACI/PNI), SIP credentials, or
other account-identifying info. Please redact those before posting -
replace with something like [REDACTED] rather than deleting the whole
line, so the surrounding context is still readable.
-->

**What happened**

**What you expected instead**

**Steps to reproduce**

1.
2.
3.

**Environment**

- signal2sip version / commit: `git rev-parse HEAD` output, or the
  release/tag you're on
- Build type: Debug / Release, built via `build-from-scratch.sh` or
  manually
- OS / distro:
- SIP transport in use: `udp` / `tls`, and `sip_srtp` mode
  (`disabled`/`optional`/`mandatory`)
- Account type: `gendb register` (primary) or `gendb link` (linked
  device)

**Relevant log output**

```
paste here (redacted, see note above)
```
