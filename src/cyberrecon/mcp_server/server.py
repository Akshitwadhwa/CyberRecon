"""Read-only MCP server exposing CyberRecon's local evidence store."""

from __future__ import annotations

import re
from typing import Any, Annotated

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from cyberrecon.mcp_server.models import (
    IncidentEvent,
    IncidentEventsResult,
    IncidentId,
    Indicator,
    Source,
    ThreatIntelRecord,
    ThreatIntelResult,
    AttackMitigation,
    AttackMitigationsResult,
    AttackSearchResult,
    AttackTactic,
    AttackTacticsResult,
    AttackTechnique,
    AttackTechniqueResult,
)
from cyberrecon.mcp_server.mitre import MitreDataError, load_catalog
from cyberrecon.store import connect, get_events, get_incident, get_intel

_INCIDENT_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_ALLOWED_SOURCES = {"network", "endpoint", "identity", "alert_image"}
_ATTACK_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
AttackQuery = Annotated[str, Field(min_length=1, max_length=256)]
AttackTechniqueId = Annotated[
    str,
    Field(min_length=5, max_length=9, pattern=r"^T\d{4}(?:\.\d{3})?$"),
]
AttackLimit = Annotated[int, Field(ge=1, le=50)]


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


def _validate_attack_id(technique_id: str) -> str:
    value = technique_id.strip().upper()
    if not _ATTACK_TECHNIQUE_RE.fullmatch(value):
        raise ValueError("technique_id must be an ATT&CK technique id such as T1059.001")
    return value


def _technique_model(item: dict[str, Any]) -> AttackTechnique:
    return AttackTechnique.model_validate(
        {key: value for key, value in item.items() if key != "stix_id"}
    )


def search_attack_techniques(query: AttackQuery, limit: AttackLimit = 20) -> AttackSearchResult:
    """Search local ATT&CK techniques without mapping incident evidence."""
    value = query.strip()
    if not value:
        raise ValueError("query must not be empty")
    if not 1 <= limit <= 50:
        raise ValueError("limit must be between 1 and 50")
    try:
        matches = load_catalog().search_techniques(value, limit=limit)
    except MitreDataError as exc:
        raise ValueError(str(exc)) from exc
    return AttackSearchResult(query=value, matches=[_technique_model(item) for item in matches])


def get_attack_technique(technique_id: AttackTechniqueId) -> AttackTechniqueResult:
    """Retrieve one local ATT&CK technique and its parent, when applicable."""
    value = _validate_attack_id(technique_id)
    try:
        item = load_catalog().get_technique(value)
    except MitreDataError as exc:
        raise ValueError(str(exc)) from exc
    if item is None:
        return AttackTechniqueResult(attack_id=value, found=False)
    parent = load_catalog().get_technique(item["parent_id"]) if item.get("parent_id") else None
    return AttackTechniqueResult(
        attack_id=value,
        found=True,
        technique=_technique_model(item),
        parent=_technique_model(parent) if parent else None,
    )


def get_attack_mitigations(technique_id: AttackTechniqueId) -> AttackMitigationsResult:
    """Retrieve mitigations linked to one local ATT&CK technique."""
    value = _validate_attack_id(technique_id)
    try:
        catalog = load_catalog()
        item = catalog.get_technique(value)
        if item is None:
            raise ValueError("Unknown ATT&CK technique id")
        mitigations = [catalog.mitigations[mid] for mid in item["mitigation_ids"]]
    except MitreDataError as exc:
        raise ValueError(str(exc)) from exc
    return AttackMitigationsResult(
        technique_id=value,
        mitigations=[
            AttackMitigation.model_validate(
                {key: value for key, value in item.items() if key != "stix_id"}
            )
            for item in mitigations
        ],
    )


def get_attack_tactics() -> AttackTacticsResult:
    """Return local ATT&CK tactics and their associated technique IDs."""
    try:
        catalog = load_catalog()
    except MitreDataError as exc:
        raise ValueError(str(exc)) from exc
    tactics = sorted(catalog.tactics.values(), key=lambda item: item["attack_id"])
    return AttackTacticsResult(tactics=[AttackTactic.model_validate(item) for item in tactics])


def create_server() -> MCPServer:
    """Create the read-only evidence, intel, and ATT&CK MCP tools."""
    server = MCPServer(
        name="CyberRecon Evidence Server",
        version="0.2.0",
        instructions=(
            "Read-only incident evidence, local threat intelligence, and MITRE ATT&CK knowledge. "
            "ATT&CK results are reference knowledge and do not confirm incident technique mappings."
        ),
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
    server.tool(
        name="search_attack_techniques",
        description="Search the local MITRE ATT&CK Enterprise technique catalog.",
        structured_output=True,
    )(search_attack_techniques)
    server.tool(
        name="get_attack_technique",
        description="Retrieve one local MITRE ATT&CK technique or sub-technique.",
        structured_output=True,
    )(get_attack_technique)
    server.tool(
        name="get_attack_mitigations",
        description="Retrieve mitigations linked to a local MITRE ATT&CK technique.",
        structured_output=True,
    )(get_attack_mitigations)
    server.tool(
        name="get_attack_tactics",
        description="Retrieve local MITRE ATT&CK tactics and technique IDs.",
        structured_output=True,
    )(get_attack_tactics)
    return server
