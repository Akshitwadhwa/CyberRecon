from __future__ import annotations

import json

from cyberrecon.store import connect, get_events, get_incident, get_intel

ALLOWED_SOURCES = {"network", "endpoint", "identity", "alert_image"}


def format_events(events: list[dict]) -> str:
    if not events:
        return "No events matched the query."
    lines = []
    for event in events:
        payload = json.dumps(event["payload"], ensure_ascii=True)
        lines.append(
            f"- {event['id']} | {event['timestamp']} | {event['source']} | "
            f"{event['event_type']} | {payload}"
        )
    return "\n".join(lines)


def events_text(incident_id: str, source: str) -> str:
    key = source.strip().lower()
    if key not in ALLOWED_SOURCES:
        raise ValueError(
            f"Unknown source '{source}'. Use network, endpoint, identity, or alert_image."
        )
    conn = connect()
    try:
        if not get_incident(conn, incident_id):
            return f"No incident named {incident_id}."
        return format_events(get_events(conn, incident_id, source=key))
    finally:
        conn.close()


def intel_text(indicator: str) -> str:
    conn = connect()
    try:
        row = get_intel(conn, indicator)
        if not row:
            return f"No intel record for '{indicator}'."
        return json.dumps(row, ensure_ascii=True)
    finally:
        conn.close()


def ticket_text(incident_id: str) -> str:
    conn = connect()
    try:
        incident = get_incident(conn, incident_id)
        if not incident:
            return f"No incident named {incident_id}."
        return json.dumps(incident, ensure_ascii=True)
    finally:
        conn.close()
