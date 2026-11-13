from __future__ import annotations

import shutil
import tempfile
import json
from pathlib import Path

import pytest

from cyberrecon.rag.documents import AttackDocument, build_attack_documents


DATASET = Path("data/mitre/enterprise-attack.json")


@pytest.fixture(scope="module")
def documents() -> list[AttackDocument]:
    return build_attack_documents(DATASET)


def test_builds_one_document_per_active_attack_pattern(documents: list[AttackDocument]) -> None:
    assert len(documents) == 718
    assert documents[0].document_id == "attack-pattern:T1001"
    assert all(document.document_id.startswith("attack-pattern:T") for document in documents)


def test_ids_and_content_are_deterministic(documents: list[AttackDocument]) -> None:
    second = build_attack_documents(DATASET)
    assert [(item.document_id, item.text, item.metadata) for item in documents] == [
        (item.document_id, item.text, item.metadata) for item in second
    ]


def test_subtechnique_parent_and_relationships_are_preserved(documents: list[AttackDocument]) -> None:
    powershell = next(item for item in documents if item.document_id == "attack-pattern:T1059.001")
    assert powershell.metadata["parent_id"] == "T1059"
    assert powershell.metadata["is_subtechnique"] is True
    assert "T1059.001" in powershell.text
    assert "T1059" in powershell.text
    assert "Execution" in powershell.text


def test_platforms_mitigations_and_references_are_available(documents: list[AttackDocument]) -> None:
    command = next(item for item in documents if item.document_id == "attack-pattern:T1059")
    assert command.metadata["platforms"]
    assert command.metadata["reference_count"] > 0
    assert "Platforms:" in command.text
    assert "References:" in command.text


def test_missing_optional_fields_are_not_invented() -> None:
    source = json.loads(DATASET.read_text(encoding="utf-8"))
    source["objects"] = [
        {
            "type": "x-mitre-collection",
            "id": "x-mitre-collection--test",
            "x_mitre_version": "test",
        },
        {
            "type": "x-mitre-tactic",
            "id": "x-mitre-tactic--test",
            "name": "Execution",
            "external_references": [{"source_name": "mitre-attack", "external_id": "TA0002"}],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--test",
            "name": "Minimal",
            "description": "Only a description.",
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}],
        },
    ]
    temp_dir = Path(tempfile.mkdtemp(prefix="cyberrecon-rag-", dir=Path.cwd()))
    try:
        path = temp_dir / "minimal.json"
        path.write_text(json.dumps(source), encoding="utf-8")
        documents = build_attack_documents(path)
    finally:
        shutil.rmtree(temp_dir)
    assert len(documents) == 1
    assert "Detection guidance:" not in documents[0].text
    assert documents[0].metadata["platforms"] == ""
    assert documents[0].metadata["mitigation_ids"] == ""


def test_metadata_uses_only_chroma_scalar_values(documents: list[AttackDocument]) -> None:
    scalar_types = (str, int, float, bool)
    assert all(isinstance(value, scalar_types) for item in documents for value in item.metadata.values())


def test_document_rejects_non_scalar_metadata() -> None:
    with pytest.raises(TypeError):
        AttackDocument("attack-pattern:T0001", "text", {"tactics": ["Execution"]})

