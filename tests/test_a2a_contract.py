from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from cyberrecon.a2a_client import (
    A2AClientError,
    DEFAULT_A2A_TIMEOUT_SECONDS,
    get_a2a_timeout,
    invoke_crewai,
)
from cyberrecon.a2a_contract import CARD_PATHS, RPC_PATH, agent_card
from cyberrecon.crewai_a2a import CrewAIA2AHandler, CrewAIInvestigationAdapter
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
