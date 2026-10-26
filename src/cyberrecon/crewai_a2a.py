"""CrewAI adapter and localhost A2A-compatible HTTP service."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import urlparse

from cyberrecon.a2a_contract import (
    CARD_PATHS,
    RPC_PATH,
    agent_card,
    error_response,
    extract_incident_id,
    success_response,
)
from cyberrecon.guardrails import cited_event_ids
from cyberrecon.schemas import EvidenceReference, InvestigationFindings
from cyberrecon.store import connect, get_events

_CLIENT_DISCONNECT_ERRORS = (BrokenPipeError, ConnectionAbortedError, ConnectionResetError)


def findings_from_report(incident_id: str, report: str) -> InvestigationFindings:
    """Wrap existing CrewAI Markdown without inventing evidence."""
    conn = connect()
    try:
        events = {row["id"].lower(): row for row in get_events(conn, incident_id)}
    finally:
        conn.close()

    evidence: list[EvidenceReference] = []
    for event_id in cited_event_ids(report):
        event = events.get(event_id)
        if event is None:
            raise ValueError(f"CrewAI report cited unknown event id: {event_id}")
        evidence.append(
            EvidenceReference(
                event_id=event["id"],
                timestamp=event["timestamp"],
                source=event["source"],
                summary=f"{event['event_type']}: {json.dumps(event['payload'], ensure_ascii=True)}",
            )
        )
    return InvestigationFindings(incident_id=incident_id, evidence=evidence, raw_report=report)


class CrewAIInvestigationAdapter:
    def __init__(self, runner: Callable[[str], tuple[str, Any]] | None = None) -> None:
        self._runner = runner

    def run(self, incident_id: str) -> InvestigationFindings:
        if self._runner is None:
            from cyberrecon.crew import investigate

            runner = investigate
        else:
            runner = self._runner
        report, _folder = runner(incident_id)
        return findings_from_report(incident_id, report)


class CrewAIA2AHandler(BaseHTTPRequestHandler):
    adapter: CrewAIInvestigationAdapter
    base_url: str

    def _send_json(self, payload: dict[str, Any], status: int = 200) -> bool:
        body = json.dumps(payload).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except _CLIENT_DISCONNECT_ERRORS:
            return False
        return True

    def do_GET(self) -> None:  # noqa: N802
        if self.path in CARD_PATHS:
            self._send_json(agent_card(self.base_url))
        else:
            self._send_json({"error": "not found"}, status=404)

    def do_POST(self) -> None:  # noqa: N802
        if urlparse(self.path).path != RPC_PATH:
            self._send_json({"error": "not found"}, status=404)
            return
        request_id: Any = None
        try:
            length = int(self.headers.get("Content-Length", "0"))
            request = json.loads(self.rfile.read(length))
            request_id = request.get("id")
            if request.get("jsonrpc") != "2.0" or request.get("method") != "message/send":
                raise ValueError("Only JSON-RPC 2.0 message/send is supported")
            incident_id = extract_incident_id(request.get("params") or {})
            findings = self.adapter.run(incident_id)
            self._send_json(success_response(request_id, findings))
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            self._send_json(error_response(request_id, -32600, str(exc)), status=400)
        except Exception as exc:  # keep service errors inside JSON-RPC
            self._send_json(error_response(request_id, -32000, f"CrewAI investigation failed: {exc}"), status=500)

    def log_message(self, _format: str, *_args: Any) -> None:
        return


def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    base_url = f"http://{host}:{port}"
    handler = type("BoundCrewAIA2AHandler", (CrewAIA2AHandler,), {"base_url": base_url, "adapter": CrewAIInvestigationAdapter()})
    with ThreadingHTTPServer((host, port), handler) as server:
        print(f"CrewAI A2A service listening at {base_url}{RPC_PATH}")
        server.serve_forever()


if __name__ == "__main__":
    serve()
