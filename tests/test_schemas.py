from __future__ import annotations

import pytest
from pydantic import ValidationError

from cyberrecon.schemas import (
    EvidenceReference,
    IncidentAssessment,
    InvestigationFindings,
    SpecialistFinding,
)


def test_incident_assessment_validates_and_renders_markdown() -> None:
    assessment = IncidentAssessment(
        incident_id="case-b",
        severity="high",
        confidence="high",
        what_happened="Suspicious endpoint behavior followed a normal office login.",
        supporting_evidence=[
            EvidenceReference(
                event_id="ep-11",
                source="endpoint",
                summary="WINWORD.EXE launched PowerShell.",
            )
        ],
        conflicts=["Identity activity was normal while endpoint activity was suspicious."],
        most_likely_explanation="Suspicious behavior occurred during an already-authenticated session.",
        recommended_response=["Collect and analyze the created executable."],
    )

    markdown = assessment.to_markdown()
    assert "# CyberRecon Assessment: case-b" in markdown
    assert "ep-11" in markdown
    assert "Severity:** high" in markdown


def test_evidence_reference_rejects_unknown_event_id_format() -> None:
    with pytest.raises(ValidationError):
        EvidenceReference(
            event_id="unknown-999",
            source="endpoint",
            summary="Not a repository event ID.",
        )


def test_evidence_reference_accepts_optional_timestamp() -> None:
    evidence = EvidenceReference(
        event_id="net-22",
        timestamp="2025-01-01T12:00:00Z",
        source="network",
        summary="Outbound connection was observed.",
    )
    assert evidence.timestamp == "2025-01-01T12:00:00Z"


def test_missing_required_incident_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        IncidentAssessment(
            incident_id="case-b",
            severity="high",
            confidence="medium",
            supporting_evidence=[],
            most_likely_explanation="Uncertain.",
            recommended_response=["Review evidence."],
        )


def test_investigation_findings_accepts_partial_current_pipeline_output() -> None:
    findings = InvestigationFindings(
        incident_id="case-b",
        specialist_findings=[
            SpecialistFinding(
                role="endpoint",
                summary="A process chain requires review.",
                evidence=[
                    EvidenceReference(
                        event_id="ep-11",
                        source="endpoint",
                        summary="PowerShell was launched.",
                    )
                ],
                uncertainty="The event does not establish intent.",
            )
        ],
        raw_report="Existing Markdown output remains available.",
    )
    assert findings.reconciliation is None
    assert findings.raw_report is not None


def test_incident_assessment_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        IncidentAssessment(
            incident_id="case-b",
            severity="high",
            confidence="high",
            what_happened="A finding.",
            supporting_evidence=[
                EvidenceReference(event_id="ep-11", source="endpoint", summary="Finding")
            ],
            most_likely_explanation="An explanation.",
            recommended_response=["Review the endpoint."],
            unsupported_field="should fail",
        )
