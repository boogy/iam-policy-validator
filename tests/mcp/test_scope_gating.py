"""Component-level scope gating: out-of-scope tools/resources/prompts must be
hidden from list responses and unreachable by direct access -- never merely refused.
"""

import json

import pytest

from iam_validator.mcp.build import build_server
from iam_validator.mcp.settings import ServerSettings

from .conftest import as_caller

pytest.importorskip("fastmcp", reason="MCP tests require 'pip install iam-policy-validator[mcp]'")


@pytest.fixture
def hosted_settings(monkeypatch) -> ServerSettings:
    monkeypatch.setenv(
        "IAM_VALIDATOR_MCP_AUTH_TOKENS",
        json.dumps(
            {
                "query-only": {"client_id": "query-only", "scopes": ["iam:query"]},
                "analyze-only": {"client_id": "analyze-only", "scopes": ["iam:analyze"]},
                "all-scopes": {
                    "client_id": "all-scopes",
                    "scopes": ["iam:validate", "iam:query", "iam:analyze", "iam:config"],
                },
            }
        ),
    )
    return ServerSettings(mode="hosted", transport="http", auth="token", auth_explicitly_set=True)


class TestToolScopeGating:
    async def test_no_token_sees_no_scoped_tools(self, hosted_settings):
        mcp = build_server(hosted_settings)
        names = {t.name for t in await mcp.list_tools()}
        assert names == set()

    async def test_query_only_token_sees_only_query(self, hosted_settings):
        mcp = build_server(hosted_settings)
        with as_caller("iam:query"):
            names = {t.name for t in await mcp.list_tools()}
        assert names == {"query"}

    async def test_query_only_token_cannot_reach_analyze_policy_directly(self, hosted_settings):
        """A hidden tool must be unreachable, not merely absent from list_tools()."""
        mcp = build_server(hosted_settings)
        with as_caller("iam:query"):
            assert await mcp.get_tool("analyze_policy") is None

    async def test_all_scopes_token_sees_full_surface(self, hosted_settings):
        mcp = build_server(hosted_settings)
        with as_caller("iam:validate", "iam:query", "iam:analyze", "iam:config"):
            names = {t.name for t in await mcp.list_tools()}
        assert names == {"describe_checks", "validate_policies", "query", "analyze_policy", "get_config"}


class TestResourceScopeGating:
    """Resources mirror gated tools (iam://checks ~= describe_checks) and must be
    gated identically -- otherwise they're a bypass for a tool the caller can't see.
    """

    async def test_query_only_token_cannot_list_or_read_checks_resource(self, hosted_settings):
        mcp = build_server(hosted_settings)
        with as_caller("iam:query"):
            uris = {str(r.uri) for r in await mcp.list_resources()}
            assert "iam://checks" not in uris
            assert await mcp.get_resource("iam://checks") is None

    async def test_query_only_token_cannot_read_config_schema_resource(self, hosted_settings):
        mcp = build_server(hosted_settings)
        with as_caller("iam:query"):
            assert await mcp.get_resource("iam://config-schema") is None

    async def test_validate_scope_can_read_checks_resource(self, hosted_settings):
        mcp = build_server(hosted_settings)
        with as_caller("iam:validate"):
            assert await mcp.get_resource("iam://checks") is not None


class TestPromptScopeGating:
    async def test_query_only_token_cannot_see_or_get_validate_tagged_prompt(self, hosted_settings):
        mcp = build_server(hosted_settings)
        with as_caller("iam:query"):
            names = {p.name for p in await mcp.list_prompts()}
            assert "generate_secure_policy" not in names
            assert await mcp.get_prompt("generate_secure_policy") is None

    async def test_untagged_scope_prompt_stays_visible_to_any_token(self, hosted_settings):
        """fix_policy_issues_workflow is tagged "fix", which has no scope mapping."""
        mcp = build_server(hosted_settings)
        with as_caller("iam:query"):
            names = {p.name for p in await mcp.list_prompts()}
        assert "fix_policy_issues_workflow" in names


class TestScopeGatingDeterminismAndIsolation:
    async def test_same_token_always_sees_same_list(self, hosted_settings):
        mcp = build_server(hosted_settings)
        with as_caller("iam:query"):
            first = [t.name for t in await mcp.list_tools()]
            second = [t.name for t in await mcp.list_tools()]
        assert first == second

    async def test_two_tokens_against_same_server_see_different_lists(self, hosted_settings):
        mcp = build_server(hosted_settings)
        with as_caller("iam:query"):
            query_view = {t.name for t in await mcp.list_tools()}
        with as_caller("iam:analyze"):
            analyze_view = {t.name for t in await mcp.list_tools()}
        assert query_view == {"query"}
        assert analyze_view == {"analyze_policy"}
        assert query_view != analyze_view


class TestAuthNoneUnaffected:
    """auth="none" (the default) must keep today's behavior: nothing hidden by scope."""

    async def test_default_settings_list_tools_unaffected(self):
        mcp = build_server(ServerSettings())
        names = {t.name for t in await mcp.list_tools()}
        assert names == {
            "describe_checks",
            "validate_policies",
            "query",
            "analyze_policy",
            "get_config",
            "set_config",
        }
