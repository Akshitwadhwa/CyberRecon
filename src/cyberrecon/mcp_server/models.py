"""Pydantic input and output models for CyberRecon MCP tools."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Source = Literal["network", "endpoint", "identity", "alert_image"]
IncidentId = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")]
Indicator = Annotated[str, Field(min_length=1, max_length=512)]


class IncidentEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1)
    timestamp: str = Field(min_length=1)
    source: Source
    event_type: str = Field(min_length=1)
    payload: dict[str, Any]


class IncidentEventsResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(min_length=1)
    events: list[IncidentEvent]


class ThreatIntelRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    indicator: str = Field(min_length=1)
    indicator_type: str = Field(min_length=1)
    confidence: str = Field(min_length=1)
    note: str = Field(min_length=1)


class ThreatIntelResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    indicator: str = Field(min_length=1)
    found: bool
    record: ThreatIntelRecord | None = None


class AttackTechnique(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_id: str = Field(min_length=2)
    name: str = Field(min_length=1)
    description: str
    tactics: list[str]
    tactic_ids: list[str]
    is_subtechnique: bool
    parent_id: str | None = None
    mitigation_ids: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class AttackSearchResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=1)
    matches: list[AttackTechnique]


class AttackTechniqueResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_id: str = Field(min_length=2)
    found: bool
    technique: AttackTechnique | None = None
    parent: AttackTechnique | None = None


class AttackMitigation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_id: str = Field(min_length=2)
    name: str = Field(min_length=1)
    description: str
    references: list[str] = Field(default_factory=list)


class AttackMitigationsResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    technique_id: str = Field(min_length=2)
    mitigations: list[AttackMitigation]


class AttackTactic(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_id: str = Field(min_length=2)
    name: str = Field(min_length=1)
    description: str
    technique_ids: list[str]
    references: list[str] = Field(default_factory=list)


class AttackTacticsResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tactics: list[AttackTactic]


class AttackKnowledgeItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    technique_id: str = Field(min_length=2)
    name: str = Field(min_length=1)
    parent_id: str | None = None
    tactics: list[str]
    description: str
    detection_guidance: str
    mitigations: list[str]
    references: list[str]
    distance: float


class AttackKnowledgeSearchResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=1)
    results: list[AttackKnowledgeItem]
