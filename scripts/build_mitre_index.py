"""Build the persistent local MITRE ATT&CK vector index."""

from __future__ import annotations

from cyberrecon.rag.index import build_mitre_index


def main() -> None:
    print("Building MITRE ATT&CK index...")
    manifest = build_mitre_index()
    print(f"Indexed {manifest.document_count} documents")
    print(f"Embedding model: {manifest.embedding_model}")
    print(f"Embedding dimensions: {manifest.embedding_dimensions}")
    print(f"ATT&CK version: {manifest.attack_version}")
    print(f"Manifest: data/rag/manifest.json")


if __name__ == "__main__":
    main()

