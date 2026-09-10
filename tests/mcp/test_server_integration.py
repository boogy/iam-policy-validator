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

from iam_validator.mcp.server import _get_check_catalog, mcp  # noqa: E402
from iam_validator.mcp.session_config import SessionConfigManager  # noqa: E402


class TestCheckCatalog:
    """Test the check catalog backing the iam://checks resources."""

    @pytest.fixture(autouse=True)
    def _no_session_config(self):
        SessionConfigManager.clear_config()
        yield
        SessionConfigManager.clear_config()

    def test_catalog_returns_all_checks(self):
        checks = _get_check_catalog()
        assert len(checks) >= 15  # At least 15 checks exist
        assert all("check_id" in c for c in checks)
        assert all("description" in c for c in checks)
        assert all("default_severity" in c for c in checks)

    def test_catalog_sorted_by_id(self):
        checks = _get_check_catalog()
        check_ids = [c["check_id"] for c in checks]
        assert check_ids == sorted(check_ids)

    def test_catalog_defaults_to_enabled_at_default_severity(self):
        entry = next(c for c in _get_check_catalog() if c["check_id"] == "wildcard_action")
        assert entry["enabled"] is True
        assert entry["severity"] == entry["default_severity"]

    def test_catalog_reflects_session_config_disable_and_override(self):
        SessionConfigManager.set_config(
            {
                "checks": {
                    "wildcard_action": {"enabled": False},
                    "wildcard_resource": {"severity": "critical"},
                }
            }
        )
        by_id = {c["check_id"]: c for c in _get_check_catalog()}

        assert by_id["wildcard_action"]["enabled"] is False
        assert by_id["wildcard_resource"]["severity"] == "critical"
        assert by_id["wildcard_resource"]["default_severity"] != "critical"

    def test_registry_is_not_built_at_import_time(self):
        """Entry-point plugin imports must not be a side effect of importing the server."""
        import subprocess
        import sys

        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import iam_validator.mcp.server as s; print(s._get_registry.cache_info().currsize)",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        assert result.stdout.strip() == "0"

    def test_catalog_follows_a_config_change(self):
        before = next(c for c in _get_check_catalog() if c["check_id"] == "wildcard_action")
        SessionConfigManager.set_config({"checks": {"wildcard_action": {"enabled": False}}})
        after = next(c for c in _get_check_catalog() if c["check_id"] == "wildcard_action")

        assert before["enabled"] is True
        assert after["enabled"] is False


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
