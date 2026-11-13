"""Real local stdio checks for the ADK-to-MCP toolset boundary."""

from __future__ import annotations

import asyncio
from pathlib import Path

from adk_app.agent import (
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

    assert server.command.endswith("python.exe")
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
            assert events.structured_content["incident_id"] == "case-b"
            assert len(events.structured_content["events"]) == 4
            assert intel.structured_content["found"] is True
        finally:
            await toolset.close()

    _run(scenario())


def test_evidence_agents_share_mcp_toolset_and_a2a_state_contract():
    assert all(MCP_TOOLSET in agent.tools for agent in (network_agent, endpoint_agent, identity_agent))
    assert callable(invoke_crewai)
    assert "crewai_findings" in STATE_KEYS

