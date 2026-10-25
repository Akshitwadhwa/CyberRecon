from __future__ import annotations

import json
import sqlite3

import pytest

from cyberrecon.guardrails import assert_grounded, cited_event_ids, unknown_citations
from cyberrecon.queries import events_text, intel_text, ticket_text
from cyberrecon.store import get_events, get_incident, get_intel


def test_incident_ingestion_and_sqlite_storage(seeded_db) -> None:
    conn = sqlite3.connect(seeded_db, uri=True)
    conn.row_factory = sqlite3.Row
    incident = get_incident(conn, "case-b")
    events = get_events(conn, "case-b")
    intel = get_intel(conn, "203.0.113.88")
    conn.close()

    assert incident["title"] == "Suspicious outbound traffic after document open"
    assert len(events) == 8
    assert events[0]["id"] == "id-10"
    assert intel["confidence"] == "high"


def test_source_filtering_returns_only_requested_source(seeded_db) -> None:
    conn = sqlite3.connect(seeded_db, uri=True)
    conn.row_factory = sqlite3.Row
    network = get_events(conn, "case-b", source="network")
    endpoint = get_events(conn, "case-b", source="endpoint")
    identity = get_events(conn, "case-b", source="identity")
    conn.close()

    assert [event["id"] for event in network] == ["net-10", "net-11", "net-12", "net-13"]
    assert [event["id"] for event in endpoint] == ["ep-10", "ep-11", "ep-12"]
    assert [event["id"] for event in identity] == ["id-10"]


def test_query_backends_used_by_tools_return_grounded_text(seeded_db) -> None:
    network_text = events_text("case-b", "NETWORK")
    ticket = json.loads(ticket_text("case-b"))
    intel = json.loads(intel_text(" 203.0.113.88 "))

    assert "net-10" in network_text
    assert "ep-11" not in network_text
    assert ticket["id"] == "case-b"
    assert intel["confidence"] == "high"


def test_query_rejects_unknown_source(seeded_db) -> None:
    with pytest.raises(ValueError, match="Unknown source"):
        events_text("case-b", "wifi")


def test_evidence_id_validation_accepts_known_ids_and_rejects_unknown(seeded_db) -> None:
    grounded = "Evidence: id-10, ep-11, and net-10."
    ungrounded = grounded + " Also see net-999."

    assert cited_event_ids(grounded) == ["ep-11", "id-10", "net-10"]
    assert unknown_citations("case-b", grounded) == []
    assert unknown_citations("case-b", ungrounded) == ["net-999"]
    assert assert_grounded("case-b", grounded) == grounded
    with pytest.raises(ValueError, match="net-999"):
        assert_grounded("case-b", ungrounded)
