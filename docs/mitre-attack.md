# MITRE ATT&CK Enterprise data

CyberRecon reads the official MITRE Enterprise ATT&CK STIX 2.1 bundle from:

```text
data/mitre/enterprise-attack.json
```

The local snapshot identifies the Enterprise ATT&CK matrix as version `2.0`
(modified `2026-07-31T18:48:31.315Z`). It is treated as read-only reference
knowledge; the original JSON is never modified.

The loader normalizes active attack patterns, tactics, mitigations, tactic
kill-chain phases, and STIX mitigation relationships. ATT&CK identifiers such
as `T1059` and `T1059.001` are preserved. ATT&CK lookup results are not
incident findings: any candidate mapping must still cite actual incident event
IDs and explain its evidence-based reasoning.
