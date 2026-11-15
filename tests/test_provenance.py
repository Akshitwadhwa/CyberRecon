from __future__ import annotations

import sqlite3

import pytest

from cyberrecon import guardrails
from cyberrecon.schemas import EvidenceReference, InvestigationFindings
from cyberrecon.store import get_events, init_db, ingest_incident


def test_old_database_migrates_with_seeded_verified_defaults() -> None:
    conn = sqlite3.connect(":memory:")
    conn.executescript("""
        CREATE TABLE incidents (id TEXT PRIMARY KEY, title TEXT, t_start TEXT, t_end TEXT, ticket_text TEXT);
        CREATE TABLE events (id TEXT PRIMARY KEY, incident_id TEXT, timestamp TEXT, source TEXT, event_type TEXT, payload TEXT);
    """)
    init_db(conn)
    incident_columns = {row[1] for row in conn.execute("PRAGMA table_info(incidents)")}
    event_columns = {row[1] for row in conn.execute("PRAGMA table_info(events)")}
    assert {"provenance", "verification_status"} <= incident_columns
    assert {"provenance", "verification_status"} <= event_columns
    conn.execute("INSERT INTO incidents (id, title, t_start, t_end, ticket_text) VALUES (?, ?, ?, ?, ?)", ("case-old", "Old", "2026-01-01", "2026-01-01", "ticket"))
    conn.execute("INSERT INTO events (id, incident_id, timestamp, source, event_type, payload) VALUES (?, ?, ?, ?, ?, ?)", ("ep-1", "case-old", "2026-01-01T00:00:00", "endpoint", "process_create", "{}"))
    conn.commit()
    assert conn.execute("SELECT provenance, verification_status FROM incidents").fetchone() == ("seeded", "verified")
    assert conn.execute("SELECT provenance, verification_status FROM events").fetchone() == ("seeded", "verified")


def test_user_submitted_provenance_survives_storage() -> None:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    ingest_incident(conn, {
        "id": "submitted-test", "title": "Submitted", "t_start": "2026-01-01", "t_end": "2026-01-01",
        "ticket_text": "input", "provenance": "user_submitted", "verification_status": "unverified",
        "events": [{"id": "net-1", "timestamp": "2026-01-01T00:00:00", "source": "network", "event_type": "connection", "payload": {"x": 1}, "provenance": "user_submitted", "verification_status": "unverified"}],
    })
    conn.commit()
    incident = conn.execute("SELECT provenance, verification_status FROM incidents").fetchone()
    event = get_events(conn, "submitted-test")[0]
    assert tuple(incident) == ("user_submitted", "unverified")
    assert event["provenance"] == "user_submitted"
    assert event["verification_status"] == "unverified"


def test_original_event_id_resolves_to_canonical_id(monkeypatch) -> None:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    ingest_incident(conn, {
        "id": "submitted-test", "title": "Submitted", "t_start": "2026-01-01", "t_end": "2026-01-01",
        "ticket_text": "input", "events": [{"id": "ep-900", "timestamp": "2026-01-01T00:00:00", "source": "endpoint", "event_type": "process", "payload": {"_original_event_id": "ep-1"}}],
    })
    conn.commit()
    monkeypatch.setattr(guardrails, "connect", lambda: conn)
    assert guardrails.resolve_event_ids("submitted-test", ["ep-1"]) == ["ep-900"]


def test_canonical_event_id_remains_valid(monkeypatch) -> None:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    ingest_incident(conn, {
        "id": "case-test", "title": "Case", "t_start": "2026-01-01", "t_end": "2026-01-01",
        "ticket_text": "input", "events": [{"id": "ep-900", "timestamp": "2026-01-01T00:00:00", "source": "endpoint", "event_type": "process", "payload": {}}],
    })
    conn.commit()
    monkeypatch.setattr(guardrails, "connect", lambda: conn)
    assert guardrails.resolve_event_ids("case-test", ["EP-900"]) == ["ep-900"]


def test_unknown_and_cross_incident_aliases_are_rejected(monkeypatch) -> None:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    for incident_id, event_id, original_id in [("case-a", "ep-901", "ep-a"), ("case-b", "ep-902", "ep-b")]:
        ingest_incident(conn, {
            "id": incident_id, "title": incident_id, "t_start": "2026-01-01", "t_end": "2026-01-01",
            "ticket_text": "input", "events": [{"id": event_id, "timestamp": "2026-01-01T00:00:00", "source": "endpoint", "event_type": "process", "payload": {"_original_event_id": original_id}}],
        })
    conn.commit()
    class NoCloseConnection:
        def __getattr__(self, name):
            return getattr(conn, name)

        def close(self):
            pass

    monkeypatch.setattr(guardrails, "connect", lambda: NoCloseConnection())
    with pytest.raises(ValueError, match="unknown event id"):
        guardrails.resolve_event_ids("case-a", ["ep-missing"])
    with pytest.raises(ValueError, match="unknown event id"):
        guardrails.resolve_event_ids("case-a", ["ep-b"])


def test_ambiguous_alias_is_rejected(monkeypatch) -> None:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    ingest_incident(conn, {
        "id": "case-ambiguous", "title": "Case", "t_start": "2026-01-01", "t_end": "2026-01-01",
        "ticket_text": "input", "events": [
            {"id": "ep-903", "timestamp": "2026-01-01T00:00:00", "source": "endpoint", "event_type": "process", "payload": {"_original_event_id": "ep-same"}},
            {"id": "ep-904", "timestamp": "2026-01-01T00:00:01", "source": "endpoint", "event_type": "process", "payload": {"_original_event_id": "ep-same"}},
        ],
    })
    conn.commit()
    monkeypatch.setattr(guardrails, "connect", lambda: conn)
    with pytest.raises(ValueError, match="Ambiguous event id alias"):
        guardrails.resolve_event_ids("case-ambiguous", ["ep-same"])


def test_unverified_events_cannot_support_confirmed_attack_mapping(monkeypatch) -> None:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    ingest_incident(conn, {
        "id": "submitted-test", "title": "Submitted", "t_start": "2026-01-01", "t_end": "2026-01-01", "ticket_text": "input",
        "provenance": "user_submitted", "verification_status": "unverified",
        "events": [
            {"id": "ep-1", "timestamp": "2026-01-01T00:00:00", "source": "endpoint", "event_type": "process_create", "payload": {}, "provenance": "user_submitted", "verification_status": "unverified"},
            {"id": "ep-2", "timestamp": "2026-01-01T00:00:01", "source": "endpoint", "event_type": "file_create", "payload": {}, "provenance": "user_submitted", "verification_status": "unverified"},
        ],
    })
    conn.commit()
    monkeypatch.setattr(guardrails, "connect", lambda: conn)
    text = "### ATT&CK candidate mappings\n- T1059.001 | PowerShell | ep-1, ep-2 | confirmed | test"
    with pytest.raises(ValueError, match="verified supporting evidence"):
        guardrails.parse_attack_mappings("submitted-test", text)


def test_a2a_findings_schema_keeps_backward_compatible_defaults() -> None:
    findings = InvestigationFindings(
        incident_id="case-b",
        evidence=[EvidenceReference(event_id="ep-11", source="endpoint", summary="process")],
    )
    assert findings.evidence[0].provenance == "seeded"
    assert findings.evidence[0].verification_status == "verified"
