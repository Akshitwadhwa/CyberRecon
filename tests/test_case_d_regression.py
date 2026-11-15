from __future__ import annotations

import json
import sqlite3

from cyberrecon.guardrails import ensure_attack_mapping_section, parse_attack_mappings
from cyberrecon.paths import INCIDENTS_DIR
from cyberrecon.store import ingest_incident, init_db


def test_case_d_fixture_supports_empty_and_structured_attack_sections(monkeypatch) -> None:
    incident = json.loads((INCIDENTS_DIR / "case-d.json").read_text(encoding="utf-8"))
    assert incident["id"] == "case-d"
    assert len(incident["events"]) == 5
    assert {event["source"] for event in incident["events"]} == {
        "identity",
        "endpoint",
        "network",
    }

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    init_db(connection)
    ingest_incident(connection, incident)
    connection.commit()
    monkeypatch.setattr("cyberrecon.guardrails.connect", lambda: connection)

    empty_output = ensure_attack_mapping_section("The update activity is consistent with normal software.")
    assert parse_attack_mappings("case-d", empty_output) == []

    mapped_output = ensure_attack_mapping_section(
        "Observed a process event.\n"
        "- T1059.001 | PowerShell | ep-30 | candidate | No PowerShell event is present; this is only a schema check."
    )
    mappings = parse_attack_mappings("case-d", mapped_output)
    assert mappings[0].technique_id == "T1059.001"
    assert mappings[0].supporting_event_ids == ["ep-30"]
