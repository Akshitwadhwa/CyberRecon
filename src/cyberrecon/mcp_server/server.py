"""Read-only MCP server exposing CyberRecon's local evidence store."""

from __future__ import annotations

import re
from typing import Any

from mcp.server.mcpserver import MCPServer

from cyberrecon.mcp_server.models import (
    IncidentEvent,
    IncidentEventsResult,
    IncidentId,
    Indicator,
    Source,
    ThreatIntelRecord,
    ThreatIntelResult,
)
from cyberrecon.store import connect, get_events, get_incident, get_intel

_INCIDENT_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_ALLOWED_SOURCES = {"network", "endpoint", "identity", "alert_image"}


def _validate_incident_id(incident_id: str) -> str:
    value = incident_id.strip()
    if not value or len(value) > 128 or not _INCIDENT_ID_RE.fullmatch(value):
        raise ValueError("incident_id must contain only letters, numbers, '_' or '-'")
    return value


def _validate_source(source: Source | None) -> str | None:
    if source is not None and source not in _ALLOWED_SOURCES:
        raise ValueError("source must be network, endpoint, identity, or alert_image")
    return source


def get_incident_events(
    incident_id: IncidentId,
    source: Source | None = None,
) -> IncidentEventsResult:
    """Return read-only structured evidence rows for one local incident."""
    incident_key = _validate_incident_id(incident_id)
    source_key = _validate_source(source)
    conn = connect()
    try:
        if get_incident(conn, incident_key) is None:
            raise ValueError("Unknown incident id")
        rows = get_events(conn, incident_key, source=source_key)
    finally:
        conn.close()

    return IncidentEventsResult(
        incident_id=incident_key,
        events=[
            IncidentEvent(
                event_id=row["id"],
                timestamp=row["timestamp"],
                source=row["source"],
                event_type=row["event_type"],
                payload=row["payload"],
            )
            for row in rows
        ],
    )


def lookup_threat_intel(indicator: Indicator) -> ThreatIntelResult:
    """Return one read-only record from the local IOC snapshot."""
    value = indicator.strip()
    if not value or len(value) > 512:
        raise ValueError("indicator must be between 1 and 512 characters")
    conn = connect()
    try:
        row = get_intel(conn, value)
    finally:
        conn.close()

    record = ThreatIntelRecord.model_validate(row) if row else None
    return ThreatIntelResult(indicator=value, found=record is not None, record=record)


def create_server() -> MCPServer:
    """Create a server with exactly the two read-only CyberRecon tools."""
    server = MCPServer(
        name="CyberRecon Evidence Server",
        version="0.1.0",
        instructions="Read-only incident evidence and local threat intelligence tools.",
    )
    server.tool(
        name="get_incident_events",
        description="Retrieve structured evidence events for one local incident.",
        structured_output=True,
    )(get_incident_events)
    server.tool(
        name="lookup_threat_intel",
        description="Look up one indicator in the local CyberRecon IOC snapshot.",
        structured_output=True,
    )(lookup_threat_intel)
    return server
