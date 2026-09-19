"""Tests for build_server() and the ComponentSpec filtering it applies uniformly
across tools, resources, and prompts.
"""

import types

import pytest
from mcp.types import ToolAnnotations

from iam_validator.mcp import build
from iam_validator.mcp.build import build_server, spec_survives
from iam_validator.mcp.component_spec import PromptSpec, ResourceSpec, ToolSpec
from iam_validator.mcp.settings import ServerSettings

pytest.importorskip("fastmcp", reason="MCP tests require 'pip install iam-policy-validator[mcp]'")


def _noop() -> None:
    return None


def _tool_spec(name: str, **kwargs) -> ToolSpec:
    return ToolSpec(
        tag="validate",
        name=name,
        fn=_noop,
        annotations=ToolAnnotations(readOnlyHint=True),
        output_schema={"type": "object"},
        **kwargs,
    )


def _fixture_module(*names: str) -> types.ModuleType:
    module = types.ModuleType("fixture")
    module.TOOLS = [_tool_spec(name) for name in names]
    return module


class TestBuildServerDeterminism:
    async def test_registers_tools_in_declared_module_order(self, monkeypatch):
        modules = (_fixture_module("e", "c", "a"), _fixture_module("d", "b"))
        expected = [spec.name for module in modules for spec in module.TOOLS]
        monkeypatch.setattr(build, "_TOOL_MODULES", modules)

        mcp = build_server(ServerSettings(mode="local"))
        tools = await mcp.list_tools()
        assert [t.name for t in tools] == expected


class TestReadOnlyProfileExcludesMutating:
    def test_spec_survives_excludes_mutating_resource(self):
        mutating = ResourceSpec(tag="orgconfig", uri="iam://x", name="x", fn=_noop, mutating=True)
        assert spec_survives(mutating, ServerSettings(profile="read-only")) is False

    def test_spec_survives_excludes_mutating_prompt(self):
        mutating = PromptSpec(tag="orgconfig", name="p", fn=_noop, mutating=True)
        assert spec_survives(mutating, ServerSettings(profile="read-only")) is False

    def test_spec_survives_keeps_non_mutating_resource(self):
        readonly = ResourceSpec(tag="orgconfig", uri="iam://x", name="x", fn=_noop, mutating=False)
        assert spec_survives(readonly, ServerSettings(profile="read-only")) is True


class TestTransportGating:
    def test_spec_survives_excludes_stdio_only_tool_under_http(self):
        stdio_only = _tool_spec("set_config", transports=frozenset({"stdio"}))
        assert spec_survives(stdio_only, ServerSettings(transport="http")) is False
        assert spec_survives(stdio_only, ServerSettings(transport="stdio")) is True
