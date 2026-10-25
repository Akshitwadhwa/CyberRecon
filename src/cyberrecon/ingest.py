from __future__ import annotations

import json

from cyberrecon.paths import INCIDENTS_DIR, INTEL_PATH
from cyberrecon.store import connect, ingest_incident, ingest_intel, init_db, list_incident_ids


def run() -> list[str]:
    conn = init_db()
    for path in sorted(INCIDENTS_DIR.glob("*.json")):
        ingest_incident(conn, json.loads(path.read_text()))
    ingest_intel(conn, json.loads(INTEL_PATH.read_text()))
    conn.commit()
    ids = list_incident_ids(conn)
    conn.close()
    return ids


if __name__ == "__main__":
    loaded = run()
    print(f"Ingested incidents: {', '.join(loaded)}")
    print("Intel table loaded from data/intel/iocs.json")
