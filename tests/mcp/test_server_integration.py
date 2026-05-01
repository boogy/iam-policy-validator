"""Integration tests for MCP server.

This module tests the MCP server configuration, including:
- Cached check registry
- Server metadata (name, instructions)
- Tool registration
- MCP resource registration

Note: These tests require the optional 'mcp' extra (fastmcp package).
"""

import json

import pytest

# Skip all tests in this module if fastmcp is not installed
fastmcp = pytest.importorskip("fastmcp", reason="MCP tests require 'pip install iam-policy-validator[mcp]'")

from iam_validator.mcp.server import _get_cached_checks, mcp  # noqa: E402


class TestCachedChecks:
    """Test the cached check registry."""

    def test_cached_checks_returns_all_checks(self):
        """Cached checks should return all 20 validation checks."""
        checks = _get_cached_checks()
        assert len(checks) >= 15  # At least 15 checks exist
        assert all("check_id" in c for c in checks)
        assert all("description" in c for c in checks)
        assert all("default_severity" in c for c in checks)

    def test_cached_checks_is_idempotent(self):
        """Calling _get_cached_checks twice returns same object."""
        checks1 = _get_cached_checks()
        checks2 = _get_cached_checks()
        # Should be the exact same list object (cached)
        assert checks1 is checks2

    def test_cached_checks_sorted_by_id(self):
        """Checks should be sorted by check_id."""
        checks = _get_cached_checks()
        check_ids = [c["check_id"] for c in checks]
        assert check_ids == sorted(check_ids)


class TestMCPServer:
    """Test MCP server configuration."""

    def test_server_has_name(self):
        """Server should have a name configured."""
        assert mcp.name == "IAM Policy Validator"

    def test_server_has_instructions(self):
        """Server should have instructions for AI assistants."""
        assert mcp.instructions is not None
        assert len(mcp.instructions) > 100  # Should be substantial


class TestServerTools:
    """Test that all expected tools are registered."""

    @pytest.mark.asyncio
    async def test_validation_tools_registered(self):
        """Validation tools should be registered."""
        tool_names = [t.name for t in await mcp.list_tools()]
        assert "validate_policy" in tool_names
        assert "quick_validate" in tool_names
        assert "validate_policies_batch" in tool_names

    @pytest.mark.asyncio
    async def test_generation_tools_registered(self):
        """Generation tools should be registered.

        Note: list_templates was demoted to the iam://templates resource in
        v1.20.0 — it must NOT appear as a tool.
        """
        tool_names = [t.name for t in await mcp.list_tools()]
        assert "generate_policy_from_template" in tool_names
        assert "build_minimal_policy" in tool_names
        assert "suggest_actions" in tool_names
        assert "list_templates" not in tool_names

    @pytest.mark.asyncio
    async def test_query_tools_registered(self):
        """Query tools should be registered.

        Note: list_checks was demoted to the iam://checks resource in v1.20.0 —
        it must NOT appear as a tool.
        """
        tool_names = [t.name for t in await mcp.list_tools()]
        assert "query_service_actions" in tool_names
        assert "query_action_details" in tool_names
        assert "expand_wildcard_action" in tool_names
        assert "list_checks" not in tool_names

    @pytest.mark.asyncio
    async def test_org_config_tools_registered(self):
        """Organization config tools should be registered."""
        tool_names = [t.name for t in await mcp.list_tools()]
        assert "set_organization_config" in tool_names
        assert "get_organization_config" in tool_names
        assert "clear_organization_config" in tool_names


class TestServerResources:
    """Test MCP resources."""

    @pytest.mark.asyncio
    async def test_templates_resource(self):
        """Templates resource should return JSON list."""
        templates_resource = next(
            (r for r in await mcp.list_resources() if "templates" in str(r.uri)),
            None,
        )
        assert templates_resource is not None
        content = await templates_resource.fn()
        data = json.loads(content)
        assert isinstance(data, list)
        assert len(data) > 0

    @pytest.mark.asyncio
    async def test_checks_resource(self):
        """Checks resource should return JSON list."""
        checks_resource = next(
            (r for r in await mcp.list_resources() if "checks" in str(r.uri)),
            None,
        )
        assert checks_resource is not None
        content = await checks_resource.fn()
        data = json.loads(content)
        assert isinstance(data, list)
        assert len(data) >= 15
