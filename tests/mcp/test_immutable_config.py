"""Hosted-mode config immutability: no client-reachable tool call may mutate the baseline."""

import asyncio
from collections.abc import Awaitable, Callable
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from iam_validator.mcp.build import spec_survives
from iam_validator.mcp.context import build_context
from iam_validator.mcp.settings import ServerSettings
from iam_validator.mcp.tools import analyze, checks, config, query, validate

pytest.importorskip("fastmcp", reason="MCP tests require 'pip install iam-policy-validator[mcp]'")

_TOOL_MODULES = (validate, query, checks, config, analyze)

# One caller per hosted-surviving tool name; a name missing here fails `missing_callers` below.
_TOOL_CALLERS: dict[str, Callable[[Any, dict], Awaitable[Any]]] = {
    "validate_policies": lambda ctx, policy: validate._validate_policies_hosted(policies=[policy], ctx=ctx),
    "get_config": lambda ctx, _policy: config.get_config(ctx),
    "query": lambda ctx, _policy: query.query(kind="service_actions", service="s3", ctx=ctx),
    "describe_checks": lambda ctx, _policy: checks.describe_checks(ctx=ctx),
    "analyze_policy": lambda ctx, policy: analyze._analyze_policy_tool_hosted(policy=policy, ctx=ctx),
}


def _fake_ctx(context):
    # get_config() calls ctx.fastmcp.list_tools(); the tool catalog itself is
    # irrelevant to what these tests assert, so an empty stub is enough.
    async def _list_tools():
        return []

    return SimpleNamespace(
        request_context=SimpleNamespace(lifespan_context=context),
        fastmcp=SimpleNamespace(list_tools=_list_tools),
    )


def _mock_boto_session() -> MagicMock:
    """boto3.Session stub whose accessanalyzer client returns zero findings."""
    client = MagicMock()
    client.validate_policy.return_value = {"findings": []}
    session = MagicMock()
    session.client.return_value = client
    return session


@pytest.fixture
def hosted_context(tmp_path):
    config_file = tmp_path / "iam-validator.yaml"
    config_file.write_text("settings:\n  fail_on_severity: [error, critical]\n")
    settings = ServerSettings(
        mode="hosted",
        auth="token",
        auth_explicitly_set=True,
        config_source=config_file,
        allowed_regions=frozenset(),  # unrestricted, so analyze_policy's default region always passes
    )
    return build_context(settings), settings


def test_mutating_orgconfig_tools_excluded_from_hosted_registration(hosted_context):
    """set_config and friends must never be registered when mode='hosted'."""
    context, settings = hosted_context
    assert context.mutable is None

    excluded = {
        spec.name
        for module in _TOOL_MODULES
        for spec in getattr(module, "TOOLS", ())
        if spec.mutating and not spec_survives(spec, settings)
    }
    assert excluded == {"set_config"}


def test_hosted_config_unchanged_after_every_surviving_tool_call(hosted_context, simple_policy_dict, mock_fetcher):
    """The surviving-tool set is derived via spec_survives(), not hand-listed, to include new tools automatically."""
    context, settings = hosted_context
    context.fetcher = mock_fetcher  # query's tool would otherwise hit the real AWS service-reference API
    context.aws_sessions[("us-east-1", None)] = _mock_boto_session()  # analyze_policy's default region/profile
    baseline_config = context.config
    baseline_digest = context.config_digest
    ctx = _fake_ctx(context)

    surviving_names = {
        spec.name for module in _TOOL_MODULES for spec in getattr(module, "TOOLS", ()) if spec_survives(spec, settings)
    }
    assert "set_config" not in surviving_names

    missing_callers = surviving_names - _TOOL_CALLERS.keys()
    assert not missing_callers, f"add a _TOOL_CALLERS entry for newly hosted-surviving tool(s): {missing_callers}"

    async def _exercise():
        for name in sorted(surviving_names):
            await _TOOL_CALLERS[name](ctx, simple_policy_dict)

    asyncio.run(_exercise())

    assert context.config is baseline_config
    assert context.config_digest == baseline_digest
    assert context.mutable is None


def test_get_config_reports_hosted_baseline_and_digest(hosted_context):
    context, _settings = hosted_context
    ctx = _fake_ctx(context)

    result = asyncio.run(config.get_config(ctx))

    assert result["has_config"] is True
    assert result["config_digest"] == context.config_digest
