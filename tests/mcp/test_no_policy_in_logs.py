"""Submitted policy content never reaches the logs, beyond the hosted-validate slice test_audit.py already covers."""

import logging
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

pytest.importorskip("fastmcp", reason="MCP tests require 'pip install iam-policy-validator[mcp]'")

from iam_validator.mcp import context as context_module  # noqa: E402
from iam_validator.mcp.context import build_context  # noqa: E402
from iam_validator.mcp.settings import ServerSettings  # noqa: E402
from iam_validator.mcp.tools import analyze, validate  # noqa: E402
from tests.mcp.conftest import as_caller  # noqa: E402

_MARKER = "NOPOLICYINLOGSMARKER7a2e91"


def _fake_ctx(context):
    async def _list_tools():
        return []

    return SimpleNamespace(
        request_context=SimpleNamespace(lifespan_context=context),
        fastmcp=SimpleNamespace(list_tools=_list_tools),
    )


def _marker_policy() -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "MarkerStatement",
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": [f"not-a-valid-arn-{_MARKER}"],
            }
        ],
    }


async def test_local_mode_validate_leaks_no_marker_at_any_level(caplog):
    caplog.set_level(logging.DEBUG)
    context = build_context(ServerSettings(mode="local"))
    ctx = _fake_ctx(context)

    result = await validate.validate_policies(policies=[_marker_policy()], ctx=ctx)

    assert result["results"]
    for record in caplog.records:
        assert _MARKER not in record.getMessage()


async def test_hosted_analyze_policy_leaks_no_marker_at_any_level(tmp_path, monkeypatch, mock_fetcher, caplog):
    caplog.set_level(logging.DEBUG)
    monkeypatch.setattr(context_module, "AWSServiceFetcher", lambda *a, **k: mock_fetcher)
    config_file = tmp_path / "iam-validator.yaml"
    config_file.write_text("settings:\n  fail_on_severity: [error, critical]\n")
    hosted_context = build_context(
        ServerSettings(mode="hosted", auth="token", auth_explicitly_set=True, config_source=config_file)
    )
    client = MagicMock()
    client.validate_policy.return_value = {"findings": []}
    session = MagicMock()
    session.client.return_value = client
    monkeypatch.setattr(analyze, "get_aws_session", lambda ctx, region, profile: session)
    ctx = _fake_ctx(hosted_context)

    with as_caller("iam:analyze"):
        await analyze._analyze_policy_tool_hosted(policy=_marker_policy(), ctx=ctx)

    for record in caplog.records:
        assert _MARKER not in record.getMessage()
