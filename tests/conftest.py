from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cyberrecon.paths import INCIDENTS_DIR, INTEL_PATH
from cyberrecon.store import ingest_incident, ingest_intel, init_db


@pytest.fixture
def seeded_db(monkeypatch: pytest.MonkeyPatch) -> str:
    """Seed an isolated SQLite database and point query helpers at it."""
    uri = f"file:cyberrecon_tests_{id(monkeypatch)}?mode=memory&cache=shared"
    keeper = sqlite3.connect(uri, uri=True)
    keeper.row_factory = sqlite3.Row
    init_db(keeper)
    incident = json.loads((INCIDENTS_DIR / "case-b.json").read_text(encoding="utf-8"))
    intel = json.loads(INTEL_PATH.read_text(encoding="utf-8"))
    ingest_incident(keeper, incident)
    ingest_intel(keeper, intel)
    keeper.commit()

    def connect_to_seeded_db() -> sqlite3.Connection:
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        return conn

    monkeypatch.setattr("cyberrecon.queries.connect", connect_to_seeded_db)
    monkeypatch.setattr("cyberrecon.guardrails.connect", connect_to_seeded_db)
    yield uri
    keeper.close()
