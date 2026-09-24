"""Every tool declares an output_schema; responses round-trip against it."""

import json

import jsonschema
from fastmcp.client import Client
from mcp.types import TextContent

from iam_validator.mcp.build import build_server
from iam_validator.mcp.settings import ServerSettings

mcp = build_server(ServerSettings(mode="local"))


async def test_every_registered_tool_declares_an_output_schema():
    async with Client(mcp) as client:
        tools = await client.list_tools()
    assert tools
    for tool in tools:
        assert tool.output_schema, f"{tool.name} has no output_schema"


async def test_result_validates_against_its_output_schema_and_mirrors_text_content():
    async with Client(mcp) as client:
        tools = {t.name: t for t in await client.list_tools()}
        result = await client.call_tool("describe_checks", {})

    assert result.is_error is False
    assert result.structured_content is not None
    jsonschema.validate(instance=result.structured_content, schema=tools["describe_checks"].output_schema)

    text_blocks = [block for block in result.content if isinstance(block, TextContent)]
    assert text_blocks, "structuredContent must be mirrored in a TextContent block"
    assert json.loads(text_blocks[0].text) == result.structured_content
