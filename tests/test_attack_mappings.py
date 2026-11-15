from __future__ import annotations

import pytest

from cyberrecon.guardrails import ensure_attack_mapping_section, parse_attack_mappings


def test_missing_mapping_section_gets_empty_mapping_block() -> None:
    output = ensure_attack_mapping_section("Network evidence only.")
    assert output.endswith("### ATT&CK candidate mappings\n[]")
    assert parse_attack_mappings("case-b", output) == []


def test_mapping_section_is_added_without_changing_structured_mapping() -> None:
    output = ensure_attack_mapping_section(
        "Observed PowerShell.\n- T1059.001 | PowerShell | ep-11 | candidate | Script execution."
    )
    assert "### ATT&CK candidate mappings" in output
    mappings = parse_attack_mappings("case-b", output)
    assert len(mappings) == 1
    assert mappings[0].technique_id == "T1059.001"
    assert mappings[0].supporting_event_ids == ["ep-11"]


def test_valid_candidate_mapping_is_evidence_grounded() -> None:
    text = """### ATT&CK candidate mappings
- T1059.001 | PowerShell | ep-11, ep-12 | candidate | Hidden PowerShell created a file in the same sequence.
"""
    mappings = parse_attack_mappings("case-b", text)
    assert mappings[0].technique_id == "T1059.001"
    assert mappings[0].supporting_event_ids == ["ep-11", "ep-12"]
    assert mappings[0].status == "candidate"


def test_bracketed_technique_id_is_accepted() -> None:
    text = """### ATT&CK candidate mappings
- [T1059.001] | PowerShell | ep-11, ep-12 | candidate | Hidden PowerShell created a file in the same sequence.
"""
    mappings = parse_attack_mappings("case-b", text)
    assert mappings[0].technique_id == "T1059.001"


def test_explicit_empty_mapping_is_valid() -> None:
    assert parse_attack_mappings("case-b", "### ATT&CK candidate mappings\n[]") == []


def test_markdown_bold_fields_are_normalized_and_unsupported_entries_are_ignored() -> None:
    text = """### ATT&CK Candidate Mappings
- **T1059.001** | **PowerShell** | **ep-11** | candidate | Hidden PowerShell execution.
- **T1563** | Remote Service Session Hijacking | [no events] | candidate | No incident event supports this.
"""
    mappings = parse_attack_mappings("case-b", text)
    assert [mapping.technique_id for mapping in mappings] == ["T1059.001"]


def test_confirmed_mapping_requires_multiple_events() -> None:
    text = """### ATT&CK candidate mappings
- T1059.001 | PowerShell | ep-11 | confirmed | One observed process event.
"""
    with pytest.raises(ValueError, match="at least two"):
        parse_attack_mappings("case-b", text)


def test_unknown_evidence_reference_is_rejected() -> None:
    text = """### ATT&CK candidate mappings
- T1059.001 | PowerShell | ep-999 | candidate | Unsupported event reference.
"""
    with pytest.raises(ValueError, match="unknown event ids"):
        parse_attack_mappings("case-b", text)


def test_unknown_attack_technique_is_rejected() -> None:
    text = """### ATT&CK candidate mappings
- T9999 | Nonexistent Technique | ep-11 | candidate | This must not be accepted.
"""
    with pytest.raises(ValueError, match="Unknown ATT&CK technique"):
        parse_attack_mappings("case-b", text)


def test_missing_section_is_rejected() -> None:
    with pytest.raises(ValueError, match="missing"):
        parse_attack_mappings("case-b", "PowerShell may be relevant.")

