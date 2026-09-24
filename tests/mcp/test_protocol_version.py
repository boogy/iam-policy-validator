"""The negotiated MCP protocol version is invariant across every server mode."""

import pytest
from fastmcp.client import Client

from iam_validator.mcp.build import build_server
from iam_validator.mcp.settings import ServerSettings


@pytest.mark.parametrize("mode", ["local", "hosted"])
async def test_negotiated_protocol_version_is_current_in_every_mode(mode, tmp_path):
    kwargs = {"mode": mode}
    if mode == "hosted":
        config_file = tmp_path / "iam-validator.yaml"
        config_file.write_text("settings:\n  fail_on_severity: [error, critical]\n")
        kwargs.update(auth="none", auth_explicitly_set=True, config_source=config_file)
    mcp = build_server(ServerSettings(**kwargs))
    async with Client(mcp) as client:
        assert client.protocol_version == "2026-07-28"
