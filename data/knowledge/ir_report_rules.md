# Incident report rules (CyberRecon)

- Quote `event_id` values that tools returned. Never invent IDs, IPs, users, or processes.
- Counts and joins come from tools. The model only interprets conflicts.
- If identity looks normal but endpoint and network do not, do not conclude account takeover. Say the session may already have been authenticated.
- If identity shows implausible travel but the workstation is quiet, lead with identity risk, not a host malware story.
- Recommended response is advice for a human analyst (reset session, isolate for review, collect more logs). Do not claim a firewall change was performed.
- Confidence must drop when sources disagree and extra investigation did not close the gap.
