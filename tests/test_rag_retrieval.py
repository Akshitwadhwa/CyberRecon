from __future__ import annotations

from pathlib import Path

import pytest

from cyberrecon.rag.retrieval import RetrievalError, search_attack_knowledge


INDEX = Path("data/rag/chroma")


def test_retrieval_returns_relevant_structured_results() -> None:
    results = search_attack_knowledge("PowerShell command and script execution", top_k=5)
    assert results
    assert any(result.technique_id == "T1059.001" for result in results)
    assert all(result.distance >= 0 for result in results)
    result = next(item for item in results if item.technique_id == "T1059.001")
    assert result.parent_id == "T1059"
    assert result.description
    assert result.tactics
    assert result.references


def test_technique_and_tactic_filters() -> None:
    technique_results = search_attack_knowledge("PowerShell", technique_id="T1059.001")
    assert [result.technique_id for result in technique_results] == ["T1059.001"]

    tactic_results = search_attack_knowledge("command execution", tactic_id="TA0002", top_k=20)
    assert tactic_results
    assert all("Execution" in result.tactics for result in tactic_results)


def test_unknown_query_is_safe() -> None:
    results = search_attack_knowledge("qzxv-unknown-incident-token", top_k=3)
    assert len(results) <= 3


@pytest.mark.parametrize(
    ("query", "kwargs"),
    [
        ("", {}),
        ("query", {"top_k": 0}),
        ("query", {"top_k": 101}),
        ("query", {"tactic_id": "T1059"}),
        ("query", {"technique_id": "TA0002"}),
    ],
)
def test_invalid_inputs_fail_without_querying(query: str, kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        search_attack_knowledge(query, **kwargs)


def test_missing_index_is_reported() -> None:
    with pytest.raises(RetrievalError, match="missing"):
        search_attack_knowledge("PowerShell", index_path=Path("data/rag/no-such-index"))


def test_persistent_index_can_be_reused() -> None:
    first = search_attack_knowledge("PowerShell", top_k=1)
    second = search_attack_knowledge("PowerShell", top_k=1)
    assert first[0].technique_id == second[0].technique_id
    assert first[0].distance == second[0].distance

