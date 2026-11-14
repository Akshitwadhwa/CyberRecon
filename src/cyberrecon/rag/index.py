"""Persistent ChromaDB indexing for the local MITRE ATT&CK catalog."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol, Sequence

from cyberrecon.mcp_server.mitre import MITRE_DATA_PATH, MitreDataError
from cyberrecon.paths import ROOT
from cyberrecon.rag.documents import AttackDocument, build_attack_documents


DEFAULT_INDEX_PATH = ROOT / "data" / "rag" / "chroma"
DEFAULT_MANIFEST_PATH = ROOT / "data" / "rag" / "manifest.json"
DEFAULT_COLLECTION_NAME = "mitre_attack_enterprise"
EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
SCHEMA_VERSION = "1"


class Encoder(Protocol):
    def encode(self, texts: Sequence[str], **kwargs: Any) -> Any: ...


@dataclass(frozen=True)
class IndexManifest:
    """Reproducibility metadata for a persisted ATT&CK index."""

    dataset_sha256: str
    attack_version: str
    embedding_model: str
    embedding_dimensions: int
    document_count: int
    schema_version: str
    collection_name: str

    def __post_init__(self) -> None:
        if len(self.dataset_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.dataset_sha256
        ):
            raise ValueError("dataset_sha256 must be a lowercase SHA-256 hex digest")
        if not self.embedding_model.strip():
            raise ValueError("embedding_model must not be empty")
        if self.embedding_dimensions <= 0 or self.document_count < 0:
            raise ValueError("embedding dimensions and document count are invalid")
        if not self.schema_version.strip() or not self.collection_name.strip():
            raise ValueError("schema_version and collection_name must not be empty")

    def save(self, path: str | Path) -> None:
        manifest_path = Path(path)
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(
            json.dumps(asdict(self), indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    @classmethod
    def load(cls, path: str | Path) -> "IndexManifest":
        manifest_path = Path(path)
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, json.JSONDecodeError) as exc:
            raise ValueError("index manifest could not be read") from exc
        if not isinstance(data, dict):
            raise ValueError("index manifest must be a JSON object")
        try:
            return cls(**data)
        except (TypeError, ValueError) as exc:
            raise ValueError("index manifest is invalid") from exc


def dataset_sha256(path: str | Path = MITRE_DATA_PATH) -> str:
    digest = hashlib.sha256()
    try:
        with Path(path).open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
    except (FileNotFoundError, OSError) as exc:
        raise MitreDataError("Local ATT&CK dataset could not be hashed") from exc
    return digest.hexdigest()


def _encoder(model_name: str) -> Encoder:
    from sentence_transformers import SentenceTransformer

    return SentenceTransformer(model_name)


def _vectors(encoder: Encoder, texts: Sequence[str]) -> list[list[float]]:
    values = encoder.encode(texts, normalize_embeddings=True, show_progress_bar=False)
    return [[float(value) for value in vector] for vector in values]


def _upsert_batch(collection: Any, documents: list[AttackDocument], encoder: Encoder) -> None:
    vectors = _vectors(encoder, [document.text for document in documents])
    collection.upsert(
        ids=[document.document_id for document in documents],
        documents=[document.text for document in documents],
        metadatas=[document.metadata for document in documents],
        embeddings=vectors,
    )


def build_mitre_index(
    dataset_path: str | Path = MITRE_DATA_PATH,
    index_path: str | Path = DEFAULT_INDEX_PATH,
    manifest_path: str | Path = DEFAULT_MANIFEST_PATH,
    *,
    model_name: str = EMBEDDING_MODEL,
    collection_name: str = DEFAULT_COLLECTION_NAME,
    batch_size: int = 64,
    encoder: Encoder | None = None,
) -> IndexManifest:
    """Build or rebuild the persistent ATT&CK index deterministically."""

    if batch_size <= 0:
        raise ValueError("batch_size must be positive")
    documents = build_attack_documents(dataset_path)
    if not documents:
        raise ValueError("ATT&CK dataset produced no documents")

    import chromadb

    index_directory = Path(index_path)
    index_directory.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(index_directory))
    collection = client.get_or_create_collection(collection_name)
    active_ids = {document.document_id for document in documents}
    existing_ids = set(collection.get(include=[]).get("ids", []))
    stale_ids = sorted(existing_ids - active_ids)
    if stale_ids:
        collection.delete(ids=stale_ids)

    active_encoder = encoder or _encoder(model_name)
    for start in range(0, len(documents), batch_size):
        _upsert_batch(collection, documents[start : start + batch_size], active_encoder)

    first_vector = _vectors(active_encoder, [documents[0].text])[0]
    client.close()
    source_version = str(documents[0].metadata.get("source_version", ""))
    manifest = IndexManifest(
        dataset_sha256=dataset_sha256(dataset_path),
        attack_version=source_version,
        embedding_model=model_name,
        embedding_dimensions=len(first_vector),
        document_count=len(documents),
        schema_version=SCHEMA_VERSION,
        collection_name=collection_name,
    )
    manifest.save(manifest_path)
    return manifest

