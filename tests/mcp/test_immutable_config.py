"""Hosted-mode config immutability: no client-reachable tool call may mutate the baseline."""

import asyncio
from types import SimpleNamespace

import pytest

from iam_validator.mcp.build import spec_survives
from iam_validator.mcp.context import build_context
from iam_validator.mcp.settings import ServerSettings
from iam_validator.mcp.tools import analyze, config, query, validate

pytest.importorskip("fastmcp", reason="MCP tests require 'pip install iam-policy-validator[mcp]'")

_TOOL_MODULES = (validate, query, config, analyze)


def _fake_ctx(context):
    return SimpleNamespace(request_context=SimpleNamespace(lifespan_context=context))


@pytest.fixture
def hosted_context(tmp_path):
    config_file = tmp_path / "iam-validator.yaml"
    config_file.write_text("settings:\n  fail_on_severity: [error, critical]\n")
    settings = ServerSettings(
        mode="hosted",
        auth="token",
        auth_explicitly_set=True,
        config_source=config_file,
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
    assert excluded == {
        "set_organization_config",
        "clear_organization_config",
        "load_organization_config_from_yaml",
        "set_custom_instructions",
        "clear_custom_instructions",
    }


def test_hosted_config_unchanged_after_every_surviving_tool_call(hosted_context, simple_policy_dict):
    """Invoking every client-reachable (hosted-surviving) tool must not touch the baseline."""
    context, settings = hosted_context
    baseline_config = context.config
    baseline_digest = context.config_digest
    ctx = _fake_ctx(context)

    surviving_names = {
        spec.name for module in _TOOL_MODULES for spec in getattr(module, "TOOLS", ()) if spec_survives(spec, settings)
    }
    assert "set_organization_config" not in surviving_names

    async def _exercise():
        await validate.validate_policy(policy=simple_policy_dict, ctx=ctx)
        await validate._validate_policy_tool(policy=simple_policy_dict, ctx=ctx)
        await config.get_organization_config(ctx)
        await config.get_custom_instructions(ctx)
        await config.check_org_compliance(policy=simple_policy_dict, ctx=ctx)

    asyncio.run(_exercise())

    assert context.config is baseline_config
    assert context.config_digest == baseline_digest
    assert context.mutable is None


def test_get_config_reports_hosted_baseline_and_digest(hosted_context):
    context, _settings = hosted_context
    ctx = _fake_ctx(context)

    result = asyncio.run(config.get_organization_config(ctx))

    assert result["has_config"] is True
    assert result["config_digest"] == context.config_digest
