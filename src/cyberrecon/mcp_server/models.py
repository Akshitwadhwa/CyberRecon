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
