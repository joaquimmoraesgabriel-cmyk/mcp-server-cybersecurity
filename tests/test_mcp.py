from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from cyber_rag.mcp_server import create_server
from cyber_rag.runtime import TOOLS


class FakeClient:
    def call(self, name, arguments):
        return {"schema_version": "1.0", "status": "ok", "results": [{"tool": name, "arguments": arguments}]}


@pytest.mark.asyncio
async def test_mcp_contract_has_only_five_readonly_tools(tmp_path):
    server = create_server(tmp_path, client=FakeClient())
    tool_list = await server.list_tools()
    assert {tool.name for tool in tool_list} == TOOLS
    for tool in tool_list:
        assert tool.annotations.readOnlyHint is True
        assert tool.annotations.destructiveHint is False
        assert tool.annotations.openWorldHint is False
    search = next(tool for tool in tool_list if tool.name == "knowledge_search")
    assert search.inputSchema["required"] == ["query"]
    assert search.inputSchema["properties"]["limit"]["default"] == 5


@pytest.mark.asyncio
async def test_real_stdio_initialization_listing_and_query(tmp_path):
    # Use a fixture client so this tests the wire protocol without spawning a daemon
    # or assuming that a real knowledge corpus has already been installed.
    script = """
from pathlib import Path
from cyber_rag.mcp_server import create_server
class FixtureClient:
    def call(self, name, arguments):
        return {"schema_version": "1.0", "status": "ok", "results": [{"tool": name}]}
create_server(Path('.'), client=FixtureClient()).run(transport='stdio')
"""
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    params = StdioServerParameters(command=sys.executable, args=["-c", script], env=environment)
    async with stdio_client(params) as (reader, writer), ClientSession(reader, writer) as session:
        initialized = await session.initialize()
        assert initialized.serverInfo.name == "Cyber RAG Local"
        tools = await session.list_tools()
        assert {tool.name for tool in tools.tools} == TOOLS
        result = await session.call_tool("knowledge_status", {})
        assert not result.isError
        assert result.structuredContent["status"] == "ok"
        assert result.structuredContent["results"][0]["tool"] == "knowledge_status"
        invalid = await session.call_tool("knowledge_search", {})
        assert invalid.isError
