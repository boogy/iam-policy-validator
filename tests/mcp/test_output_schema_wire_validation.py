"""tools/list must validate against the real MCP wire model, not just FastMCP's in-memory Client.

FastMCP's in-memory ``Client`` (used elsewhere in tests/mcp) always negotiates the
latest protocol version and never routes through ``mcp.server.runner``, so it can't
catch an ``outputSchema`` that fails the wire model FastMCP validates against for a
real stdio/HTTP connection. This drives the same validation call
(``mcp_types.methods.serialize_server_result``, reached from
``mcp.server.runner.ServerRunner._serialize`` when it raises
"Handler returned an invalid result") against a real ``ListToolsResult`` built from the
registered tool catalog.
"""

import pytest
from fastmcp.client import Client
from mcp.types import ListToolsResult
from mcp_types import methods as _methods

from iam_validator.mcp.build import build_server
from iam_validator.mcp.settings import ServerSettings

pytest.importorskip("fastmcp", reason="MCP tests require 'pip install iam-policy-validator[mcp]'")

# outputSchema.type == "object" is required through this protocol version; a client
# that negotiates down to it is exactly what a real (non-in-memory) connection can do.
_LEGACY_PROTOCOL_VERSION = "2025-11-25"


async def _list_tools_dumped(settings: ServerSettings) -> dict:
    mcp_server = build_server(settings)
    async with Client(mcp_server) as client:
        tools = await client.list_tools()
    assert tools, "expected at least one registered tool"
    return ListToolsResult(tools=tools).model_dump(by_alias=True, mode="json", exclude_none=True)


async def test_local_tools_list_validates_against_legacy_wire_model():
    dumped = await _list_tools_dumped(ServerSettings(mode="local"))
    _methods.validate_server_result("tools/list", _LEGACY_PROTOCOL_VERSION, dumped)


async def test_hosted_tools_list_validates_against_legacy_wire_model(tmp_path):
    config_file = tmp_path / "iam-validator.yaml"
    config_file.write_text("settings:\n  fail_on_severity: [error, critical]\n")
    settings = ServerSettings(mode="hosted", auth="none", auth_explicitly_set=True, config_source=config_file)
    dumped = await _list_tools_dumped(settings)
    _methods.validate_server_result("tools/list", _LEGACY_PROTOCOL_VERSION, dumped)
