"""Typed investigation results shared by CrewAI, ADK, and transport adapters."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]


class EvidenceReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(pattern=r"^(?:id|ep|net|al)-\d+$")
    timestamp: str | None = None
    source: Literal["identity", "endpoint", "network", "alert_image"]
    summary: str = Field(min_length=1)


class SpecialistFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["coordinator", "network", "endpoint", "identity"]
    summary: str = Field(min_length=1)
    evidence: list[EvidenceReference] = Field(default_factory=list)
    uncertainty: str = Field(default="", max_length=2000)
    confidence: Confidence | None = None


class ReconciliationFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1)
    conflicts: list[str] = Field(default_factory=list)
    likely_explanation: str = Field(min_length=1)
    uncertainty: str = Field(min_length=1)
    evidence: list[EvidenceReference] = Field(default_factory=list)


class InvestigationFindings(BaseModel):
    """Structured container for the findings produced by an investigation run."""

    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(min_length=1)
    evidence: list[EvidenceReference] = Field(default_factory=list)
    specialist_findings: list[SpecialistFinding] = Field(default_factory=list)
    reconciliation: ReconciliationFinding | None = None
    raw_report: str | None = None


class IncidentAssessment(BaseModel):
    """Validated final assessment before Markdown or transport serialization."""

    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(min_length=1)
    severity: Severity
    confidence: Confidence
    what_happened: str = Field(min_length=1)
    supporting_evidence: list[EvidenceReference] = Field(min_length=1)
    conflicts: list[str] = Field(default_factory=list)
    most_likely_explanation: str = Field(min_length=1)
    recommended_response: list[str] = Field(min_length=1)
    uncertainties: list[str] = Field(default_factory=list)

    def to_markdown(self) -> str:
        evidence = "\n".join(
            f"- **{item.event_id}** ({item.source}): {item.summary}"
            for item in self.supporting_evidence
        )
        conflicts = "\n".join(f"- {item}" for item in self.conflicts) or "- None identified."
        response = "\n".join(f"- {item}" for item in self.recommended_response)
        uncertainties = "\n".join(f"- {item}" for item in self.uncertainties) or "- None stated."
        return (
            f"# CyberRecon Assessment: {self.incident_id}\n\n"
            "## What happened\n"
            f"{self.what_happened}\n\n"
            "## Supporting evidence\n"
            f"{evidence}\n\n"
            "## Where evidence conflicts\n"
            f"{conflicts}\n\n"
            "## Most likely explanation\n"
            f"{self.most_likely_explanation}\n\n"
            "## Recommended response\n"
            f"{response}\n\n"
            "## Uncertainties\n"
            f"{uncertainties}\n\n"
            f"**Severity:** {self.severity}  \n**Confidence:** {self.confidence}\n"
        )


class FollowupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(min_length=1)
    question: str = Field(min_length=1, max_length=2000)
    sources: list[Literal["identity", "endpoint", "network", "alert_image"]] = Field(
        min_length=1
    )
    reason: str = Field(min_length=1, max_length=2000)
