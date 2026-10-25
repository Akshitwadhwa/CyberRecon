from __future__ import annotations

import json
import sqlite3
from typing import Any

from cyberrecon.paths import DB_PATH, SCHEMA_PATH


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection | None = None) -> sqlite3.Connection:
    own = conn is None
    conn = conn or connect()
    conn.executescript(SCHEMA_PATH.read_text())
    conn.commit()
    if own:
        return conn
    return conn


def _dumps(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=True)


def ingest_incident(conn: sqlite3.Connection, incident: dict) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO incidents (id, title, t_start, t_end, ticket_text) VALUES (?, ?, ?, ?, ?)",
        (
            incident["id"],
            incident["title"],
            incident["t_start"],
            incident["t_end"],
            incident["ticket_text"],
        ),
    )
    conn.execute("DELETE FROM events WHERE incident_id = ?", (incident["id"],))
    for event in incident["events"]:
        conn.execute(
            """
            INSERT INTO events (id, incident_id, timestamp, source, event_type, payload)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                event["id"],
                incident["id"],
                event["timestamp"],
                event["source"],
                event["event_type"],
                _dumps(event["payload"]),
            ),
        )


def ingest_intel(conn: sqlite3.Connection, rows: list[dict]) -> None:
    conn.execute("DELETE FROM intel")
    for row in rows:
        conn.execute(
            "INSERT INTO intel (indicator, indicator_type, confidence, note) VALUES (?, ?, ?, ?)",
            (row["indicator"], row["indicator_type"], row["confidence"], row["note"]),
        )


def get_incident(conn: sqlite3.Connection, incident_id: str) -> dict | None:
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    return dict(row) if row else None


def get_events(
    conn: sqlite3.Connection,
    incident_id: str,
    source: str | None = None,
    t0: str | None = None,
    t1: str | None = None,
) -> list[dict]:
    sql = "SELECT * FROM events WHERE incident_id = ?"
    args: list[Any] = [incident_id]
    if source:
        sql += " AND source = ?"
        args.append(source)
    if t0:
        sql += " AND timestamp >= ?"
        args.append(t0)
    if t1:
        sql += " AND timestamp <= ?"
        args.append(t1)
    sql += " ORDER BY timestamp"
    rows = conn.execute(sql, args).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        item["payload"] = json.loads(item["payload"])
        out.append(item)
    return out


def get_intel(conn: sqlite3.Connection, indicator: str) -> dict | None:
    row = conn.execute(
        "SELECT * FROM intel WHERE lower(indicator) = lower(?)",
        (indicator.strip(),),
    ).fetchone()
    return dict(row) if row else None


def list_incident_ids(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute("SELECT id FROM incidents ORDER BY id").fetchall()
    return [r["id"] for r in rows]
