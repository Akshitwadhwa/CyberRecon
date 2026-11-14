# MITRE ATT&CK document builder

`cyberrecon.rag.documents.build_attack_documents()` converts the local
Enterprise ATT&CK STIX bundle into one deterministic `AttackDocument` per
active `attack-pattern`. Revoked and deprecated objects are excluded by the
existing `load_catalog()` normalization.

Each document has a stable ID such as `attack-pattern:T1059.001`, readable
embedding text, and scalar-only metadata suitable for ChromaDB. The text
contains the ATT&CK description, parent technique, tactics, platforms,
mitigations, and source references when those fields exist in the dataset.
Detection guidance is included only when the source object provides it.

This phase does not create embeddings, write a vector database, expose an MCP
tool, or change the ADK/CrewAI/A2A workflow.

Phase 4.3 adds `cyberrecon.rag.index.build_mitre_index()` and the
`scripts/build_mitre_index.py` command. It writes the persistent index to
`data/rag/chroma/` and its reproducibility manifest to
`data/rag/manifest.json`.

Example:

```powershell
$env:PYTHONPATH = "$PWD\src;$PWD"
.\.venv-rag\Scripts\python.exe -c "from cyberrecon.rag.documents import build_attack_documents; print(len(build_attack_documents()))"
```

