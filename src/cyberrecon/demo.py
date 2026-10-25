"""Phase 1-2 demo: ingest + queries, no CrewAI required."""

from __future__ import annotations

import argparse
import json

from cyberrecon.ingest import run as ingest
from cyberrecon.queries import events_text, intel_text, ticket_text
from cyberrecon.store import connect, get_events, get_incident, get_intel


def print_case(incident_id: str) -> None:
    ingest()
    conn = connect()
    try:
        incident = get_incident(conn, incident_id)
        if not incident:
            raise SystemExit(f"Unknown incident: {incident_id}")
        print("=== TICKET ===")
        print(json.dumps(incident, indent=2))
        for source in ("identity", "endpoint", "network"):
            print(f"\n=== {source.upper()} EVENTS ===")
            print(events_text(incident_id, source))
        events = get_events(conn, incident_id, source="network")
        indicators = []
        for event in events:
            payload = event["payload"]
            if "dst_ip" in payload:
                indicators.append(payload["dst_ip"])
            if "query" in payload:
                indicators.append(payload["query"])
        print("\n=== INTEL LOOKUPS ===")
        for indicator in dict.fromkeys(indicators):
            print(indicator, "->", get_intel(conn, indicator) or "no record")
    finally:
        conn.close()


def demo_tool_failure() -> None:
    print("=== TOOL FAILURE (invalid source) ===")
    try:
        events_text("case-b", "wifi")
    except Exception as exc:
        print({"input": "wifi", "error_type": type(exc).__name__, "message": str(exc)})
    print("RECOVERY CALL:")
    print(events_text("case-b", "network")[:400], "...")
    print("TICKET:", ticket_text("case-b")[:200], "...")
    print("INTEL:", intel_text("203.0.113.88"))


def main() -> None:
    parser = argparse.ArgumentParser(description="CyberRecon evidence demo (no LLM)")
    parser.add_argument("incident_id", nargs="?", default="case-b")
    parser.add_argument("--failure-demo", action="store_true")
    args = parser.parse_args()
    print_case(args.incident_id)
    if args.failure_demo:
        print()
        demo_tool_failure()


if __name__ == "__main__":
    main()
