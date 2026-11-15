"""CrewAI adapter and localhost A2A-compatible HTTP service."""

from __future__ import annotations

import json
import hmac
import logging
import os
import re
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
from cyberrecon.guardrails import cited_event_ids, resolve_event_ids
from cyberrecon.schemas import EvidenceReference, InvestigationFindings
from cyberrecon.store import connect, get_events
from cyberrecon.tracing import extract_context, traced_span

_CLIENT_DISCONNECT_ERRORS = (BrokenPipeError, ConnectionAbortedError, ConnectionResetError)
MAX_A2A_REQUEST_BYTES = 64 * 1024
A2A_TOKEN_ENV = "CYBERRECON_A2A_TOKEN"
LOGGER = logging.getLogger("cyberrecon.a2a.server")
_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


def _authorized(headers: Any) -> bool:
    expected = os.getenv(A2A_TOKEN_ENV, "").strip()
    if not expected:
        return True
    supplied = headers.get("Authorization", "")
    prefix = "Bearer "
    return supplied.startswith(prefix) and hmac.compare_digest(supplied[len(prefix):], expected)


def _safe_request_id(value: Any) -> str:
    candidate = str(value) if isinstance(value, (str, int, float)) else ""
    return candidate if _SAFE_REQUEST_ID.fullmatch(candidate) else "none"


def _log_validation_failure(stage: str, request_id: Any = None) -> None:
    LOGGER.warning(
        "a2a_invalid_request stage=%s request_id=%s",
        stage,
        _safe_request_id(request_id),
    )


def findings_from_report(incident_id: str, report: str) -> InvestigationFindings:
    """Wrap existing CrewAI Markdown without inventing evidence."""
    conn = connect()
    try:
        events = {row["id"].lower(): row for row in get_events(conn, incident_id)}
    finally:
        conn.close()

    evidence: list[EvidenceReference] = []
    for event_id in resolve_event_ids(incident_id, cited_event_ids(report)):
        event = events.get(event_id.lower())
        if event is None:
            raise ValueError(f"CrewAI report cited unknown event id: {event_id}")
        evidence.append(
            EvidenceReference(
                event_id=event["id"],
                timestamp=event["timestamp"],
                source=event["source"],
                summary=f"{event['event_type']}: {json.dumps(event['payload'], ensure_ascii=True)}",
                provenance=event["provenance"],
                verification_status=event["verification_status"],
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
        carrier = {key.lower(): value for key, value in self.headers.items()}
        parent_context = extract_context(carrier)
        with traced_span(
            "a2a.server.request",
            component="a2a-server",
            operation="message/send",
            parent_context=parent_context,
        ):
            self._do_post()

    def _do_post(self) -> None:
        if urlparse(self.path).path != RPC_PATH:
            self._send_json({"error": "not found"}, status=404)
            return
        if not _authorized(self.headers):
            self._send_json({"error": "unauthorized"}, status=401)
            return
        request_id: Any = None
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > MAX_A2A_REQUEST_BYTES:
                _log_validation_failure("oversized_request")
                raise ValueError("Request body is too large")
            try:
                request = json.loads(self.rfile.read(length))
            except json.JSONDecodeError:
                _log_validation_failure("invalid_json")
                raise
            if not isinstance(request, dict):
                _log_validation_failure("non_object_body")
                raise ValueError("Request must be a JSON object")
            request_id = request.get("id")
            if request.get("jsonrpc") != "2.0" or request.get("method") != "message/send":
                stage = "invalid_jsonrpc_version" if request.get("jsonrpc") != "2.0" else "invalid_method"
                _log_validation_failure(stage, request_id)
                raise ValueError("Only JSON-RPC 2.0 message/send is supported")
            params = request.get("params") or {}
            try:
                incident_id = extract_incident_id(params)
            except ValueError:
                metadata = params.get("metadata") if isinstance(params, dict) else None
                candidate = metadata.get("incident_id") if isinstance(metadata, dict) else None
                stage = "invalid_incident_id" if candidate is not None else "missing_incident_id"
                _log_validation_failure(stage, request_id)
                raise
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            self._send_json(error_response(request_id, -32600, "Invalid A2A request"), status=400)
            return

        # Keep failures after request validation separate from malformed requests.
        # In particular, findings conversion can raise ValueError when a CrewAI
        # report cites an event that is not present in the incident store.
        try:
            findings = self.adapter.run(incident_id)
            self._send_json(success_response(request_id, findings))
        except Exception:  # keep service errors inside JSON-RPC without leaking internals
            self._send_json(
                error_response(request_id, -32000, "CrewAI investigation failed"),
                status=500,
            )

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
