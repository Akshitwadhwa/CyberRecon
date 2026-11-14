"""Semantic retrieval over the persisted MITRE ATT&CK Chroma index."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from cyberrecon.rag.index import (
    DEFAULT_COLLECTION_NAME,
    DEFAULT_INDEX_PATH,
    EMBEDDING_MODEL,
)


_TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
_TACTIC_ID = re.compile(r"^TA\d{4}$", re.IGNORECASE)
_HEADINGS = (
    "Parent technique:",
    "Tactics:",
    "Description:",
    "Detection guidance:",
    "Platforms:",
    "Mitigations:",
    "References:",
)


class RetrievalError(RuntimeError):
    """Raised when the persisted retrieval index cannot be used."""


@dataclass(frozen=True)
class AttackKnowledgeResult:
    technique_id: str
    name: str
    parent_id: str | None
    tactics: list[str]
    description: str
    detection_guidance: str
    mitigations: list[str]
    references: list[str]
    distance: float


def _section(text: str, heading: str) -> str:
    marker = f"{heading}\n"
    start = text.find(marker)
    if start < 0:
        return ""
    start += len(marker)
    end = len(text)
    for next_heading in _HEADINGS:
        if next_heading == heading:
            continue
        position = text.find(f"\n\n{next_heading}\n", start)
        if position >= 0:
            end = min(end, position)
    return text[start:end].strip()


def _parse_document(text: str, metadata: dict[str, Any], distance: float) -> AttackKnowledgeResult:
    first_line = text.splitlines()[0] if text.splitlines() else ""
    match = re.match(r"ATT&CK technique: (.+) \((T\d{4}(?:\.\d{3})?)\)$", first_line)
    if not match:
        raise RetrievalError("Stored ATT&CK document has an invalid heading")

    tactics = [item.strip() for item in str(metadata.get("tactics", "")).split(",") if item.strip()]
    mitigation_ids = [
        item.strip() for item in str(metadata.get("mitigation_ids", "")).split(",") if item.strip()
    ]
    mitigation_text = _section(text, "Mitigations:")
    mitigations = mitigation_text.splitlines() if mitigation_text else mitigation_ids
    references_text = _section(text, "References:")
    references = [line[2:].strip() for line in references_text.splitlines() if line.startswith("- ")]
    parent_id = str(metadata.get("parent_id", "")).strip() or None
    return AttackKnowledgeResult(
        technique_id=match.group(2).upper(),
        name=match.group(1),
        parent_id=parent_id,
        tactics=tactics,
        description=_section(text, "Description:"),
        detection_guidance=_section(text, "Detection guidance:"),
        mitigations=mitigations,
        references=references,
        distance=float(distance),
    )


@lru_cache(maxsize=1)
def _resources(index_path: str, collection_name: str, model_name: str) -> tuple[Any, Any]:
    index_directory = Path(index_path)
    if not index_directory.is_dir():
        raise RetrievalError(f"MITRE index is missing: {index_directory}")
    try:
        import chromadb
        from sentence_transformers import SentenceTransformer

        client = chromadb.PersistentClient(path=str(index_directory))
        collection = client.get_collection(collection_name)
        model = SentenceTransformer(model_name)
    except Exception as exc:
        raise RetrievalError("MITRE retrieval index could not be opened") from exc
    return collection, model


def _validate(query: str, top_k: int, tactic_id: str | None, technique_id: str | None) -> None:
    if not isinstance(query, str) or not query.strip():
        raise ValueError("query must not be empty")
    if not isinstance(top_k, int) or isinstance(top_k, bool) or not 1 <= top_k <= 100:
        raise ValueError("top_k must be an integer between 1 and 100")
    if tactic_id is not None and (not isinstance(tactic_id, str) or not _TACTIC_ID.fullmatch(tactic_id)):
        raise ValueError("tactic_id must match TA####")
    if technique_id is not None and (
        not isinstance(technique_id, str) or not _TECHNIQUE_ID.fullmatch(technique_id)
    ):
        raise ValueError("technique_id must match T#### or T####.###")


def search_attack_knowledge(
    query: str,
    top_k: int = 5,
    *,
    tactic_id: str | None = None,
    technique_id: str | None = None,
    index_path: str | Path = DEFAULT_INDEX_PATH,
    collection_name: str = DEFAULT_COLLECTION_NAME,
    model_name: str = EMBEDDING_MODEL,
) -> list[AttackKnowledgeResult]:
    """Return semantically similar ATT&CK knowledge records.

    ``distance`` is the raw Chroma retrieval distance. It is not an attack
    probability, confidence score, or evidence-grounded technique decision.
    """

    _validate(query, top_k, tactic_id, technique_id)
    collection, model = _resources(str(index_path), collection_name, model_name)
    vector = model.encode([query.strip()], normalize_embeddings=True, show_progress_bar=False)
    where: dict[str, Any] | None = None
    if technique_id:
        where = {"technique_id": {"$eq": technique_id.upper()}}
    # tactic_ids are stored as a comma-separated scalar for Chroma metadata
    # compatibility. Chroma's string $contains behavior is version-dependent,
    # so retrieve the ranked collection results and apply an exact token filter.
    candidate_count = collection.count() if tactic_id else top_k
    try:
        result = collection.query(
            query_embeddings=[[float(value) for value in vector[0]]],
            n_results=candidate_count,
            where=where,
            include=["documents", "metadatas", "distances"],
        )
    except Exception as exc:
        raise RetrievalError("MITRE retrieval query failed") from exc

    documents = result.get("documents", [[]])[0]
    metadatas = result.get("metadatas", [[]])[0]
    distances = result.get("distances", [[]])[0]
    results: list[AttackKnowledgeResult] = []
    if tactic_id:
        expected = tactic_id.upper()
    else:
        expected = ""
    for text, metadata, distance in zip(documents, metadatas, distances, strict=True):
        item_metadata = metadata or {}
        if expected and expected not in {
            item.strip().upper() for item in str(item_metadata.get("tactic_ids", "")).split(",")
        }:
            continue
        results.append(_parse_document(text, item_metadata, distance))
    return results[:top_k]

