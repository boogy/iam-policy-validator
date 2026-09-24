"""Integration tests for MCP server.

This module tests the MCP server configuration, including:
- Check catalog (session-config-aware, ServerContext-driven)
- Server metadata (name, instructions)
- Tool registration
- MCP resource registration

Note: These tests require the optional 'mcp' extra (fastmcp package).
"""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

# Skip all tests in this module if fastmcp is not installed
fastmcp = pytest.importorskip("fastmcp", reason="MCP tests require 'pip install iam-policy-validator[mcp]'")

from iam_validator.core.check_registry import create_default_registry  # noqa: E402
from iam_validator.core.config.config_loader import ValidatorConfig  # noqa: E402
from iam_validator.mcp.build import build_server  # noqa: E402
from iam_validator.mcp.context import ServerContext, SessionState, get_check_catalog  # noqa: E402
from iam_validator.mcp.settings import ServerSettings  # noqa: E402

mcp = build_server(ServerSettings())


def _fake_ctx(session: SessionState) -> SimpleNamespace:
    """A fake MCP ``Context`` wrapping a real ServerContext with the given session.

    ``config`` is a real (empty) ValidatorConfig, not a MagicMock: get_active_config()
    falls back to it whenever the session has no override, so it must behave like the
    ambient startup baseline (every check enabled at its default severity) rather than
    a mock whose truthy-by-default methods would silently pass every assertion.
    """
    context = ServerContext(
        config=ValidatorConfig({}),
        registry=create_default_registry(),
        formatters=MagicMock(),
        fetcher=MagicMock(),
        aws_sessions={},
        settings=MagicMock(),
        mutable=session,
    )
    return SimpleNamespace(request_context=SimpleNamespace(lifespan_context=context))


class TestCheckCatalog:
    """Test the check catalog backing the iam://checks resources."""

    def test_catalog_returns_all_checks(self):
        checks = get_check_catalog()
        assert len(checks) >= 15  # At least 15 checks exist
        assert all("check_id" in c for c in checks)
        assert all("description" in c for c in checks)
        assert all("default_severity" in c for c in checks)

    def test_catalog_sorted_by_id(self):
        checks = get_check_catalog()
        check_ids = [c["check_id"] for c in checks]
        assert check_ids == sorted(check_ids)

    def test_catalog_defaults_to_enabled_at_default_severity(self):
        entry = next(c for c in get_check_catalog() if c["check_id"] == "wildcard_action")
        assert entry["enabled"] is True
        assert entry["severity"] == entry["default_severity"]

    def test_catalog_reflects_session_config_disable_and_override(self):
        session = SessionState()
        session.set_config(
            {
                "checks": {
                    "wildcard_action": {"enabled": False},
                    "wildcard_resource": {"severity": "critical"},
                }
            }
        )
        ctx = _fake_ctx(session)
        by_id = {c["check_id"]: c for c in get_check_catalog(ctx)}

        assert by_id["wildcard_action"]["enabled"] is False
        assert by_id["wildcard_resource"]["severity"] == "critical"
        assert by_id["wildcard_resource"]["default_severity"] != "critical"

    def test_registry_is_not_built_at_import_time(self):
        """Entry-point plugin loading must not be a side effect of importing the server."""
        import subprocess
        import sys

        script = (
            "import iam_validator.core.check_registry as cr\n"
            "calls = []\n"
            "orig = cr.create_default_registry\n"
            "def wrapper(*a, **kw):\n"
            "    calls.append(1)\n"
            "    return orig(*a, **kw)\n"
            "cr.create_default_registry = wrapper\n"
            "import iam_validator.mcp.build\n"
            "print(len(calls))\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            check=True,
        )
        assert result.stdout.strip() == "0"

    def test_catalog_follows_a_config_change(self):
        session = SessionState()
        ctx = _fake_ctx(session)

        before = next(c for c in get_check_catalog(ctx) if c["check_id"] == "wildcard_action")
        session.set_config({"checks": {"wildcard_action": {"enabled": False}}})
        after = next(c for c in get_check_catalog(ctx) if c["check_id"] == "wildcard_action")

        assert before["enabled"] is True
        assert after["enabled"] is False

    def test_catalog_reflects_hosted_baseline_not_stock_defaults(self):
        """Regression: hosted mode (mutable=None) must report the hosted baseline's
        enabled/severity, not always fall back to (True, default_severity).
        """
        context = ServerContext(
            config=ValidatorConfig(
                {"checks": {"wildcard_action": {"enabled": False}, "wildcard_resource": {"severity": "critical"}}}
            ),
            registry=create_default_registry(),
            formatters=MagicMock(),
            fetcher=MagicMock(),
            aws_sessions={},
            settings=MagicMock(),
            mutable=None,
        )
        ctx = SimpleNamespace(request_context=SimpleNamespace(lifespan_context=context))

        by_id = {c["check_id"]: c for c in get_check_catalog(ctx)}

        assert by_id["wildcard_action"]["enabled"] is False
        assert by_id["wildcard_resource"]["severity"] == "critical"


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

    async def test_validation_tools_registered(self):
        """Validation tools should be registered."""
        tool_names = [t.name for t in await mcp.list_tools()]
        assert "validate_policies" in tool_names

    async def test_query_tools_registered(self):
        tool_names = [t.name for t in await mcp.list_tools()]
        assert "query" in tool_names
        assert "list_checks" not in tool_names
        assert "query_service_actions" not in tool_names

    async def test_org_config_tools_registered(self):
        """Consolidated organization config tools should be registered."""
        tool_names = [t.name for t in await mcp.list_tools()]
        assert "get_config" in tool_names
        assert "set_config" in tool_names


class TestServerResources:
    """Test MCP resources."""

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
