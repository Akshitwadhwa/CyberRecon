from __future__ import annotations

import pytest

from cyberrecon.mcp_server.mitre import MitreDataError, load_catalog


def test_real_enterprise_dataset_is_loaded_and_normalized() -> None:
    catalog = load_catalog()
    assert len(catalog.techniques) == 718
    assert len(catalog.tactics) == 15
    assert len(catalog.mitigations) == 268


def test_technique_and_subtechnique_preserve_official_ids() -> None:
    catalog = load_catalog()
    technique = catalog.get_technique("T1059")
    subtechnique = catalog.get_technique("t1059.001")
    assert technique and technique["attack_id"] == "T1059"
    assert subtechnique and subtechnique["attack_id"] == "T1059.001"
    assert subtechnique["parent_id"] == "T1059"
    assert "Execution" in subtechnique["tactics"]


def test_search_and_mitigation_relationships_use_local_data() -> None:
    catalog = load_catalog()
    matches = catalog.search_techniques("PowerShell")
    assert any(item["attack_id"] == "T1059.001" for item in matches)
    assert catalog.get_technique("T1059.001")["mitigation_ids"]


def test_missing_dataset_is_reported_without_fallback() -> None:
    with pytest.raises(MitreDataError):
        load_catalog("data/mitre/missing.json")
