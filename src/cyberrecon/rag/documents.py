"""Build deterministic, embedding-ready documents from local ATT&CK data.

This module prepares text and Chroma-compatible metadata only. It does not
create embeddings or write to a vector database.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cyberrecon.mcp_server.mitre import MITRE_DATA_PATH, MitreDataError, load_catalog


Scalar = str | int | float | bool


@dataclass(frozen=True)
class AttackDocument:
    """One normalized ATT&CK technique document and scalar metadata."""

    document_id: str
    text: str
    metadata: dict[str, Scalar]

    def __post_init__(self) -> None:
        if not self.document_id.startswith("attack-pattern:"):
            raise ValueError("document_id must use the attack-pattern:<ID> format")
        if not self.text.strip():
            raise ValueError("text must not be empty")
        if any(not isinstance(value, (str, int, float, bool)) for value in self.metadata.values()):
            raise TypeError("metadata values must be Chroma-compatible scalar values")


def _raw_objects(path: Path) -> tuple[dict[str, dict[str, Any]], str]:
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError) as exc:
        raise MitreDataError("Local ATT&CK dataset could not be read") from exc
    if not isinstance(bundle, dict) or not isinstance(bundle.get("objects"), list):
        raise MitreDataError("ATT&CK dataset does not contain an objects list")

    objects = {
        obj["id"]: obj
        for obj in bundle["objects"]
        if isinstance(obj, dict) and isinstance(obj.get("id"), str)
    }
    collection_versions = [
        obj.get("x_mitre_version")
        for obj in bundle["objects"]
        if isinstance(obj, dict)
        and obj.get("type") == "x-mitre-collection"
        and isinstance(obj.get("x_mitre_version"), str)
    ]
    return objects, sorted(collection_versions)[0] if collection_versions else ""


def _clean(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _unique_sorted(values: list[str]) -> list[str]:
    return sorted({value for value in values if value})


def _references(raw: dict[str, Any]) -> list[str]:
    return _unique_sorted(
        [
            reference["url"]
            for reference in raw.get("external_references", [])
            if isinstance(reference, dict) and isinstance(reference.get("url"), str)
        ]
    )


def _mitigation_lines(catalog: Any, mitigation_ids: list[str]) -> list[str]:
    lines = []
    for mitigation_id in sorted(mitigation_ids):
        mitigation = catalog.mitigations.get(mitigation_id)
        if not mitigation:
            continue
        line = f"- {mitigation_id}: {mitigation['name']}"
        if mitigation["description"]:
            line += f" — {mitigation['description']}"
        lines.append(line)
    return lines


def _text_for(technique: dict[str, Any], raw: dict[str, Any], catalog: Any) -> str:
    sections = [f"ATT&CK technique: {technique['name']} ({technique['attack_id']})"]
    if technique.get("parent_id"):
        sections.append(f"Parent technique: {technique['parent_id']}")
    if technique.get("tactics"):
        sections.append(f"Tactics: {', '.join(sorted(technique['tactics']))}")

    description = technique.get("description", "")
    if description:
        sections.append(f"Description:\n{description}")

    detection = _clean(raw.get("x_mitre_detection"))
    if detection:
        sections.append(f"Detection guidance:\n{detection}")

    platforms = _unique_sorted(
        [platform for platform in raw.get("x_mitre_platforms", []) if isinstance(platform, str)]
    )
    if platforms:
        sections.append(f"Platforms: {', '.join(platforms)}")

    mitigation_lines = _mitigation_lines(catalog, technique.get("mitigation_ids", []))
    if mitigation_lines:
        sections.append("Mitigations:\n" + "\n".join(mitigation_lines))

    references = _references(raw)
    if references:
        sections.append("References:\n" + "\n".join(f"- {reference}" for reference in references))
    return "\n\n".join(sections)


def build_attack_documents(path: str | Path = MITRE_DATA_PATH) -> list[AttackDocument]:
    """Build one deterministic document for every active ATT&CK technique."""

    dataset_path = Path(path)
    catalog = load_catalog(dataset_path)
    raw_by_stix_id, source_version = _raw_objects(dataset_path)
    documents: list[AttackDocument] = []

    for attack_id in sorted(catalog.techniques):
        technique = catalog.techniques[attack_id]
        raw = raw_by_stix_id.get(technique["stix_id"], {})
        platforms = _unique_sorted(
            [platform for platform in raw.get("x_mitre_platforms", []) if isinstance(platform, str)]
        )
        mitigation_ids = sorted(technique.get("mitigation_ids", []))
        tactics = sorted(technique.get("tactics", []))
        tactic_ids = sorted(technique.get("tactic_ids", []))
        references = _references(raw)
        metadata: dict[str, Scalar] = {
            "technique_id": attack_id,
            "name": technique["name"],
            "parent_id": technique.get("parent_id") or "",
            "is_subtechnique": bool(technique.get("is_subtechnique")),
            "tactics": ", ".join(tactics),
            "tactic_ids": ", ".join(tactic_ids),
            "mitigation_ids": ", ".join(mitigation_ids),
            "platforms": ", ".join(platforms),
            "reference_count": len(references),
            "object_type": "attack-pattern",
            "source_version": source_version,
        }
        documents.append(
            AttackDocument(
                document_id=f"attack-pattern:{attack_id}",
                text=_text_for(technique, raw, catalog),
                metadata=metadata,
            )
        )
    return documents

