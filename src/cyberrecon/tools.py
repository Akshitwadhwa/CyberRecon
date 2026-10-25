from __future__ import annotations

from typing import Type

from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from cyberrecon.queries import events_text, intel_text, ticket_text


class GetEventsInput(BaseModel):
    incident_id: str = Field(..., description="Incident id such as case-a or case-b")
    source: str = Field(
        ...,
        description="Evidence source: network, endpoint, identity, or alert_image",
    )


class GetEventsTool(BaseTool):
    name: str = "GetEventsTool"
    description: str = (
        "Returns timestamped evidence rows for one incident and one source "
        "(network, endpoint, identity). Use this instead of guessing logs."
    )
    args_schema: Type[BaseModel] = GetEventsInput

    def _run(self, incident_id: str, source: str) -> str:
        return events_text(incident_id, source)


class GetIntelInput(BaseModel):
    indicator: str = Field(..., description="IP, domain, or other indicator to look up")


class GetIntelTool(BaseTool):
    name: str = "GetIntelTool"
    description: str = "Looks up an IP or domain in the local threat-intel snapshot."
    args_schema: Type[BaseModel] = GetIntelInput

    def _run(self, indicator: str) -> str:
        return intel_text(indicator)


class GetTicketInput(BaseModel):
    incident_id: str = Field(..., description="Incident id")


class GetTicketTool(BaseTool):
    name: str = "GetTicketTool"
    description: str = "Returns the analyst ticket text and time window for an incident."
    args_schema: Type[BaseModel] = GetTicketInput

    def _run(self, incident_id: str) -> str:
        return ticket_text(incident_id)
