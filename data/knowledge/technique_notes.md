# Technique notes for RAG (descriptive, not a how-to)

## Unusual child process from an office document

When an endpoint log shows a document application starting a scripting host (for example Word then PowerShell), analysts treat that parent-child pair as suspicious because it is uncommon in routine editing. Map this only when those process events actually appear in the evidence store. This is consistent with living-off-the-land scripting categories in ATT&CK-style taxonomies (for example T1059 at a high level). Do not invent command lines.

## Repeated outbound HTTPS to a rare IP

Repeated short connections from a workstation to an address that is not on the corporate allowlist, especially if threat-intel confidence is high, support a hypothesis of unwanted external communication. This is not proof of a named malware family.

## Impossible travel

Two successful authentications for one user from distant regions within minutes, without a corresponding local workstation story, support a credential or session-reuse hypothesis. Workstation process trees do not have to look malicious for this identity finding to stand.

## Existing session vs stolen password

A clean MFA login from the usual office IP, followed by suspicious processes on that same host, often means the account was already signed in. Identity evidence may stay "normal" while endpoint and network evidence carry the case.
