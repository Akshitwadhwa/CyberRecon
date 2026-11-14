from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

ROOT = Path(__file__).resolve().parents[1]
MCP_TEST_TIMEOUT_SECONDS = float(os.environ.get("MCP_TEST_TIMEOUT_SECONDS", "90"))


async def _call(name: str, arguments: dict):
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


def test_rag_tool_is_discoverable_and_invokable() -> None:
    tools, result = asyncio.run(
        _call("search_attack_knowledge", {"query": "PowerShell command execution", "top_k": 5})
    )
    assert "search_attack_knowledge" in {tool.name for tool in tools.tools}
    assert result.is_error is False
    assert result.structured_content["query"] == "PowerShell command execution"
    assert any(item["technique_id"] == "T1059.001" for item in result.structured_content["results"])
    assert all("distance" in item for item in result.structured_content["results"])


def test_rag_tool_filters() -> None:
    _tools, technique = asyncio.run(
        _call("search_attack_knowledge", {"query": "PowerShell", "technique_id": "T1059.001"})
    )
    assert [item["technique_id"] for item in technique.structured_content["results"]] == [
        "T1059.001"
    ]

    _tools, tactic = asyncio.run(
        _call("search_attack_knowledge", {"query": "command execution", "tactic_id": "TA0002"})
    )
    assert tactic.is_error is False
    assert tactic.structured_content["results"]
    assert all("Execution" in item["tactics"] for item in tactic.structured_content["results"])


def test_rag_tool_invalid_inputs_return_safe_errors() -> None:
    _tools, empty = asyncio.run(_call("search_attack_knowledge", {"query": ""}))
    _tools, bad_tactic = asyncio.run(
        _call("search_attack_knowledge", {"query": "PowerShell", "tactic_id": "T1059"})
    )
    _tools, bad_technique = asyncio.run(
        _call("search_attack_knowledge", {"query": "PowerShell", "technique_id": "../../secret"})
    )
    assert empty.is_error is True
    assert bad_tactic.is_error is True
    assert bad_technique.is_error is True
    for result in (empty, bad_tactic, bad_technique):
        assert "C:\\Users" not in str(result.content)
        assert "OPENAI_API_KEY" not in str(result.content)

