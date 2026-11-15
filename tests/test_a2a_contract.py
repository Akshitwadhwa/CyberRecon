from __future__ import annotations

import json
import io
import logging
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from cyberrecon import guardrails
import cyberrecon.crewai_a2a as crewai_a2a
from cyberrecon.a2a_client import (
    A2AClientError,
    DEFAULT_A2A_TIMEOUT_SECONDS,
    get_a2a_timeout,
    invoke_crewai,
)
from cyberrecon.a2a_contract import CARD_PATHS, RPC_PATH, agent_card
from cyberrecon.crewai_a2a import (
    MAX_A2A_REQUEST_BYTES,
    CrewAIA2AHandler,
    CrewAIInvestigationAdapter,
    _authorized,
)
from cyberrecon.ingest import run as ingest


def test_a2a_timeout_uses_default_and_environment(monkeypatch) -> None:
    monkeypatch.delenv("CREWAI_A2A_TIMEOUT_SECONDS", raising=False)
    assert get_a2a_timeout() == DEFAULT_A2A_TIMEOUT_SECONDS == 600.0

    monkeypatch.setenv("CREWAI_A2A_TIMEOUT_SECONDS", "42.5")
    assert get_a2a_timeout() == 42.5


def test_a2a_timeout_rejects_invalid_values(monkeypatch) -> None:
    monkeypatch.setenv("CREWAI_A2A_TIMEOUT_SECONDS", "not-a-number")
    with pytest.raises(A2AClientError, match="CREWAI_A2A_TIMEOUT_SECONDS"):
        get_a2a_timeout()

    monkeypatch.setenv("CREWAI_A2A_TIMEOUT_SECONDS", "0")
    with pytest.raises(A2AClientError, match="CREWAI_A2A_TIMEOUT_SECONDS"):
        get_a2a_timeout()


def test_send_json_handles_client_disconnect_without_masking_other_errors() -> None:
    handler = object.__new__(CrewAIA2AHandler)
    handler.send_response = lambda _status: None
    handler.send_header = lambda _name, _value: None
    handler.end_headers = lambda: None

    class DisconnectedWriter:
        def write(self, _body):
            raise ConnectionAbortedError(10053, "client disconnected")

    handler.wfile = DisconnectedWriter()
    assert handler._send_json({"ok": True}) is False

    class BrokenWriter:
        def write(self, _body):
            raise RuntimeError("unexpected write failure")

    handler.wfile = BrokenWriter()
    with pytest.raises(RuntimeError, match="unexpected write failure"):
        handler._send_json({"ok": True})


def test_a2a_validation_failures_log_only_safe_stage_and_request_id(caplog) -> None:
    cases = [
        (b"{", "invalid_json", None),
        (json.dumps(["not", "object"]).encode(), "non_object_body", None),
        (json.dumps({"id": "req-version", "jsonrpc": "1.0", "method": "message/send", "params": {}}).encode(), "invalid_jsonrpc_version", "req-version"),
        (json.dumps({"id": "req-method", "jsonrpc": "2.0", "method": "wrong", "params": {}}).encode(), "invalid_method", "req-method"),
        (json.dumps({"id": "req-missing", "jsonrpc": "2.0", "method": "message/send", "params": {}}).encode(), "missing_incident_id", "req-missing"),
        (json.dumps({"id": "req-invalid", "jsonrpc": "2.0", "method": "message/send", "params": {"metadata": {"incident_id": "../../secret"}}}).encode(), "invalid_incident_id", "req-invalid"),
        (b"x" * (MAX_A2A_REQUEST_BYTES + 1), "oversized_request", None),
    ]
    with caplog.at_level(logging.WARNING, logger="cyberrecon.a2a.server"):
        for body, stage, request_id in cases:
            handler = object.__new__(CrewAIA2AHandler)
            statuses = []
            handler.path = RPC_PATH
            handler.headers = {
                "Content-Length": str(len(body)),
                "Content-Type": "application/json",
                "X-Secret": "secret-header",
            }
            handler.rfile = io.BytesIO(body)
            handler.wfile = io.BytesIO()
            handler.send_response = statuses.append
            handler.send_header = lambda *_args: None
            handler.end_headers = lambda: None
            handler._do_post()
            assert statuses == [400]

    messages = [record.getMessage() for record in caplog.records]
    for stage, request_id in [(item[1], item[2]) for item in cases]:
        matching = [message for message in messages if f"stage={stage}" in message]
        assert matching
        if request_id:
            assert f"request_id={request_id}" in matching[0]
    output = "\n".join(messages)
    assert "secret-header" not in output
    assert "../../secret" not in output
    assert "not" not in output


@pytest.fixture()
def a2a_server():
    ingest()
    calls: list[str] = []

    def fake_runner(incident_id: str):
        calls.append(incident_id)
        return "Report cites ep-11 and net-12.", None

    class Handler(CrewAIA2AHandler):
        adapter = CrewAIInvestigationAdapter(runner=fake_runner)
        base_url = ""

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    base_url = f"http://127.0.0.1:{server.server_port}"
    Handler.base_url = base_url
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield base_url, calls
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def test_agent_card_is_available_and_describes_jsonrpc_endpoint(a2a_server) -> None:
    base_url, _calls = a2a_server
    with urllib.request.urlopen(base_url + CARD_PATHS[0]) as response:
        card = json.load(response)
    assert card["name"] == "CyberRecon CrewAI Investigator"
    assert card["url"] == base_url + RPC_PATH
    assert card["skills"][0]["id"] == "investigate-incident"
    assert agent_card(base_url)["capabilities"]["streaming"] is False


def test_network_request_reaches_crewai_adapter_and_validates_findings(a2a_server) -> None:
    base_url, calls = a2a_server
    findings = invoke_crewai(base_url, "case-b")
    assert calls == ["case-b"]
    assert findings.incident_id == "case-b"
    assert {item.event_id for item in findings.evidence} == {"ep-11", "net-12"}
    assert findings.raw_report is not None


def test_invalid_request_returns_jsonrpc_error(a2a_server) -> None:
    base_url, calls = a2a_server
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": 7, "method": "message/send", "params": {}}
    ).encode()
    request = urllib.request.Request(
        base_url + RPC_PATH,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as error:
        urllib.request.urlopen(request)
    body = json.load(error.value)
    assert body["error"]["code"] == -32600
    assert calls == []


def test_unknown_event_in_adapter_response_fails_validation(a2a_server) -> None:
    _base_url, _calls = a2a_server
    adapter = CrewAIInvestigationAdapter(lambda _incident: ("Report cites ep-999.", None))
    with pytest.raises(ValueError, match="unknown event id"):
        adapter.run("case-b")


def test_findings_from_report_resolves_original_event_alias(monkeypatch) -> None:
    row = {
        "id": "ep-900",
        "timestamp": "2026-01-01T00:00:00",
        "source": "endpoint",
        "event_type": "process",
        "payload": {"_original_event_id": "ep-1"},
        "provenance": "user_submitted",
        "verification_status": "unverified",
    }
    class NoCloseConnection:
        def close(self):
            pass

    monkeypatch.setattr(crewai_a2a, "connect", lambda: NoCloseConnection())
    monkeypatch.setattr(crewai_a2a, "get_events", lambda _conn, _incident_id: [row])
    monkeypatch.setattr(guardrails, "connect", lambda: NoCloseConnection())
    monkeypatch.setattr(guardrails, "get_events", lambda _conn, _incident_id: [row])

    findings = crewai_a2a.findings_from_report("submitted-test", "Report cites ep-1.")

    assert [item.event_id for item in findings.evidence] == ["ep-900"]
    assert findings.evidence[0].provenance == "user_submitted"
    assert findings.evidence[0].verification_status == "unverified"


def test_post_execution_findings_error_is_not_reported_as_invalid_request() -> None:
    calls: list[str] = []

    def runner(incident_id: str):
        calls.append(incident_id)
        return "Report cites ep-999.", None

    adapter = CrewAIInvestigationAdapter(runner)
    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 8,
            "method": "message/send",
            "params": {"metadata": {"incident_id": "case-b"}},
        }
    ).encode()
    handler = object.__new__(CrewAIA2AHandler)
    handler.path = RPC_PATH
    handler.headers = {"Content-Length": str(len(payload))}
    handler.rfile = io.BytesIO(payload)
    handler.wfile = io.BytesIO()
    handler.adapter = adapter
    statuses: list[int] = []
    handler.send_response = statuses.append
    handler.send_header = lambda *_args: None
    handler.end_headers = lambda: None

    handler._do_post()

    body = json.loads(handler.wfile.getvalue())
    assert statuses == [500]
    assert body["error"]["code"] == -32000
    assert calls == ["case-b"]


def test_service_does_not_expose_internal_failure_text(a2a_server) -> None:
    class FailingAdapter:
        def run(self, _incident_id):
            raise RuntimeError("provider secret and internal path")

    class Handler(CrewAIA2AHandler):
        adapter = FailingAdapter()
        base_url = ""

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    base_url = f"http://127.0.0.1:{server.server_port}"
    Handler.base_url = base_url
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "message/send",
                "params": {"metadata": {"incident_id": "case-b"}},
            }
        ).encode()
        request = urllib.request.Request(
            base_url + RPC_PATH,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request)
        body = json.load(error.value)
        assert body["error"]["message"] == "CrewAI investigation failed"
        assert "provider secret" not in json.dumps(body)
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def test_a2a_request_limit_is_bounded() -> None:
    assert MAX_A2A_REQUEST_BYTES == 64 * 1024


def test_a2a_auth_rejects_missing_and_invalid_tokens(monkeypatch) -> None:
    monkeypatch.setenv("CYBERRECON_A2A_TOKEN", "internal-test-token")
    assert _authorized({}) is False
    assert _authorized({"Authorization": "Bearer wrong-token"}) is False
    assert _authorized({"Authorization": "Bearer internal-test-token"}) is True


def test_a2a_handler_rejects_unauthorized_post_without_running_adapter(monkeypatch) -> None:
    monkeypatch.setenv("CYBERRECON_A2A_TOKEN", "internal-test-token")
    handler = object.__new__(CrewAIA2AHandler)
    handler.path = RPC_PATH
    handler.headers = {"Content-Length": "0"}
    responses = []
    handler._send_json = lambda payload, status=200: responses.append((payload, status))
    handler._do_post()
    assert responses == [({"error": "unauthorized"}, 401)]
