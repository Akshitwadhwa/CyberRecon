from __future__ import annotations

import re

from cyberrecon.store import connect, get_events

_ID_RE = re.compile(r"\b((?:id|ep|net|al)-\d+)\b", re.IGNORECASE)


def cited_event_ids(text: str) -> list[str]:
    return sorted({m.group(1).lower() for m in _ID_RE.finditer(text)})


def unknown_citations(incident_id: str, text: str) -> list[str]:
    conn = connect()
    try:
        known = {row["id"].lower() for row in get_events(conn, incident_id)}
    finally:
        conn.close()
    return [eid for eid in cited_event_ids(text) if eid not in known]


def assert_grounded(incident_id: str, text: str) -> str:
    bad = unknown_citations(incident_id, text)
    if bad:
        raise ValueError(
            f"Report cited event ids that are not in SQLite for {incident_id}: {bad}"
        )
    return text
