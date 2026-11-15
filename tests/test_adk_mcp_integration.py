"""Real local stdio checks for the ADK-to-MCP toolset boundary."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

from adk_app.agent import (
    IDENTITY_MCP_TOOLSET,
    MCP_TOOLSET,
    create_mcp_toolset,
    endpoint_agent,
    identity_agent,
    network_agent,
)
from adk_app.agent_session_runner import STATE_KEYS
from cyberrecon.a2a_client import invoke_crewai


def _run(coro):
    return asyncio.run(coro)


def test_mcp_toolset_uses_adk_interpreter_and_project_paths():
    params = MCP_TOOLSET.connection_params
    server = params.server_params

    project_root = Path(server.cwd).resolve()
    python_relative_path = (
        Path(".venv-rag") / "Scripts" / "python.exe"
        if os.name == "nt"
        else Path(".venv-rag") / "bin" / "python"
    )
    expected_mcp_python = (project_root / python_relative_path).resolve()
    assert Path(server.command).resolve() == expected_mcp_python
    assert expected_mcp_python.is_file()
    assert server.args == ["-m", "cyberrecon.mcp_server"]
    assert Path(server.cwd).name == "CyberRecon"
    assert str(Path(server.cwd) / "src") in server.env["PYTHONPATH"]


def test_adk_discovers_and_invokes_both_real_stdio_mcp_tools():
    async def scenario():
        toolset = create_mcp_toolset()
        try:
            tools = await toolset.get_tools()
            assert {tool.name for tool in tools} == {
                "get_incident_events",
                "lookup_threat_intel",
                "search_attack_techniques",
                "get_attack_technique",
                "get_attack_mitigations",
                "get_attack_tactics",
                "search_attack_knowledge",
            }

            # The call goes through ADK's session manager and the live stdio
            # MCP subprocess; it is not a mocked tool result.
            session = await toolset._mcp_session_manager.create_session()  # noqa: SLF001
            events = await session.call_tool(
                "get_incident_events",
                {"incident_id": "case-b", "source": "network"},
            )
            intel = await session.call_tool(
                "lookup_threat_intel",
                {"indicator": "203.0.113.88"},
            )
            attack = await session.call_tool(
                "get_attack_technique",
                {"technique_id": "T1059.001"},
            )
            knowledge = await session.call_tool(
                "search_attack_knowledge",
                {"query": "PowerShell command execution", "top_k": 5},
            )
            assert events.structured_content["incident_id"] == "case-b"
            assert len(events.structured_content["events"]) == 4
            assert intel.structured_content["found"] is True
            assert attack.structured_content["technique"]["attack_id"] == "T1059.001"
            assert attack.structured_content["parent"]["attack_id"] == "T1059"
            assert any(
                item["technique_id"] == "T1059.001"
                for item in knowledge.structured_content["results"]
            )
        finally:
            await toolset.close()

    _run(scenario())


def test_only_network_and_endpoint_receive_rag_mcp_tool():
    assert MCP_TOOLSET in network_agent.tools
    assert MCP_TOOLSET in endpoint_agent.tools
    assert IDENTITY_MCP_TOOLSET in identity_agent.tools
    assert IDENTITY_MCP_TOOLSET not in network_agent.tools
    assert IDENTITY_MCP_TOOLSET not in endpoint_agent.tools
    assert callable(invoke_crewai)
    assert "crewai_findings" in STATE_KEYS


def test_identity_mcp_toolset_excludes_rag_tool():
    async def scenario():
        try:
            identity_tools = await IDENTITY_MCP_TOOLSET.get_tools()
            assert {tool.name for tool in identity_tools} == {
                "get_incident_events",
                "lookup_threat_intel",
                "search_attack_techniques",
                "get_attack_technique",
                "get_attack_mitigations",
                "get_attack_tactics",
            }
        finally:
            await IDENTITY_MCP_TOOLSET.close()

    _run(scenario())

