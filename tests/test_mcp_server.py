from __future__ import annotations

import asyncio
import hashlib
import os
import sys
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from cyberrecon.ingest import run as ingest
from cyberrecon.paths import DB_PATH

ROOT = Path(__file__).resolve().parents[1]
MCP_TEST_TIMEOUT_SECONDS = float(os.environ.get("MCP_TEST_TIMEOUT_SECONDS", "90"))


def _db_digest() -> str:
    return hashlib.sha256(DB_PATH.read_bytes()).hexdigest()


async def _mcp_call(name: str, arguments: dict):
    async with asyncio.timeout(MCP_TEST_TIMEOUT_SECONDS):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT / "src")
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "cyberrecon.mcp_server"],
            cwd=ROOT,
            env=env,
        )
        async with stdio_client(params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                tools = await session.list_tools()
                result = await session.call_tool(name, arguments)
                return tools, result


def test_mcp_server_startup_and_tool_discovery() -> None:
    ingest()
    tools, _result = asyncio.run(_mcp_call("lookup_threat_intel", {"indicator": "missing.test"}))
    assert {tool.name for tool in tools.tools} == {
        "get_incident_events",
        "lookup_threat_intel",
        "search_attack_techniques",
        "get_attack_technique",
        "get_attack_mitigations",
        "get_attack_tactics",
        "search_attack_knowledge",
    }
    assert len(tools.tools) == 7


def test_mcp_input_schemas_are_published() -> None:
    ingest()
    tools, _result = asyncio.run(_mcp_call("lookup_threat_intel", {"indicator": "missing.test"}))
    by_name = {tool.name: tool for tool in tools.tools}
    events_schema = by_name["get_incident_events"].input_schema
    intel_schema = by_name["lookup_threat_intel"].input_schema
    assert set(events_schema["properties"]) == {"incident_id", "source"}
    assert events_schema["required"] == ["incident_id"]
    assert intel_schema["required"] == ["indicator"]
    assert intel_schema["properties"]["indicator"]["maxLength"] == 512
    assert by_name["search_attack_techniques"].input_schema["required"] == ["query"]
    assert by_name["get_attack_technique"].input_schema["required"] == ["technique_id"]
    knowledge_schema = by_name["search_attack_knowledge"].input_schema
    assert knowledge_schema["required"] == ["query"]
    assert set(knowledge_schema["properties"]) == {"query", "top_k", "tactic_id", "technique_id"}


def test_get_incident_events_returns_all_case_b_events() -> None:
    ingest()
    before = _db_digest()
    _tools, result = asyncio.run(_mcp_call("get_incident_events", {"incident_id": "case-b"}))
    assert result.is_error is False
    assert result.structured_content["incident_id"] == "case-b"
    assert len(result.structured_content["events"]) == 8
    assert {event["event_id"] for event in result.structured_content["events"]} == {
        "id-10",
        "ep-10",
        "ep-11",
        "ep-12",
        "net-10",
        "net-11",
        "net-12",
        "net-13",
    }
    assert _db_digest() == before


def test_get_incident_events_filters_network_and_endpoint() -> None:
    ingest()
    _tools, network = asyncio.run(
        _mcp_call("get_incident_events", {"incident_id": "case-b", "source": "network"})
    )
    _tools, endpoint = asyncio.run(
        _mcp_call("get_incident_events", {"incident_id": "case-b", "source": "endpoint"})
    )
    assert [event["event_id"] for event in network.structured_content["events"]] == [
        "net-10",
        "net-11",
        "net-12",
        "net-13",
    ]
    assert [event["event_id"] for event in endpoint.structured_content["events"]] == [
        "ep-10",
        "ep-11",
        "ep-12",
    ]


def test_lookup_known_and_unknown_indicators() -> None:
    ingest()
    _tools, known = asyncio.run(
        _mcp_call("lookup_threat_intel", {"indicator": "203.0.113.88"})
    )
    _tools, unknown = asyncio.run(
        _mcp_call("lookup_threat_intel", {"indicator": "not-in-local-snapshot.test"})
    )
    assert known.structured_content["found"] is True
    assert known.structured_content["record"]["confidence"] == "high"
    assert unknown.structured_content == {
        "indicator": "not-in-local-snapshot.test",
        "found": False,
        "record": None,
    }


def test_invalid_inputs_return_safe_mcp_errors() -> None:
    ingest()
    _tools, bad_incident = asyncio.run(
        _mcp_call("get_incident_events", {"incident_id": "../../secrets"})
    )
    _tools, unknown_incident = asyncio.run(
        _mcp_call("get_incident_events", {"incident_id": "case-unknown"})
    )
    _tools, bad_indicator = asyncio.run(_mcp_call("lookup_threat_intel", {"indicator": ""}))
    assert bad_incident.is_error is True
    assert unknown_incident.is_error is True
    assert bad_indicator.is_error is True
    for result in (bad_incident, unknown_incident, bad_indicator):
        text = str(result.content)
        assert "OPENAI_API_KEY" not in text
        assert "C:\\Users" not in text


def test_attack_tools_return_structured_local_results() -> None:
    ingest()
    _tools, search = asyncio.run(
        _mcp_call("search_attack_techniques", {"query": "PowerShell"})
    )
    _tools, technique = asyncio.run(
        _mcp_call("get_attack_technique", {"technique_id": "T1059.001"})
    )
    _tools, mitigations = asyncio.run(
        _mcp_call("get_attack_mitigations", {"technique_id": "T1059.001"})
    )
    _tools, tactics = asyncio.run(_mcp_call("get_attack_tactics", {}))
    assert search.structured_content["matches"]
    assert any(item["attack_id"] == "T1059.001" for item in search.structured_content["matches"])
    assert technique.structured_content["found"] is True
    assert technique.structured_content["technique"]["attack_id"] == "T1059.001"
    assert technique.structured_content["parent"]["attack_id"] == "T1059"
    assert mitigations.structured_content["mitigations"]
    assert len(tactics.structured_content["tactics"]) == 15


def test_attack_tools_reject_unknown_and_invalid_ids() -> None:
    _tools, unknown = asyncio.run(
        _mcp_call("get_attack_technique", {"technique_id": "T9999"})
    )
    _tools, bad = asyncio.run(
        _mcp_call("get_attack_mitigations", {"technique_id": "../../secret"})
    )
    assert unknown.structured_content["attack_id"] == "T9999"
    assert unknown.structured_content["found"] is False
    assert bad.is_error is True
