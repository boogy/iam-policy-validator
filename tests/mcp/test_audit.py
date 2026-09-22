"""Tests for hosted-mode audit logging (iam_validator/mcp/audit.py)."""

import asyncio
import json
import logging
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

pytest.importorskip("fastmcp", reason="MCP tests require 'pip install iam-policy-validator[mcp]'")

from fastmcp.exceptions import ToolError  # noqa: E402

from iam_validator.core.constants import (  # noqa: E402
    MCP_AUDIT_LOGGER_NAME,
    MCP_AUDIT_OUTCOME_CANCELLED,
    MCP_AUDIT_OUTCOME_SUCCESS,
    MCP_AUDIT_OUTCOME_TOOL_ERROR,
)
from iam_validator.mcp import audit as audit_module  # noqa: E402
from iam_validator.mcp.context import build_context  # noqa: E402
from iam_validator.mcp.settings import ServerSettings  # noqa: E402
from iam_validator.mcp.tools import analyze, checks, config, query, validate  # noqa: E402
from tests.mcp.conftest import as_caller  # noqa: E402

_RECORD_FIELDS = (
    "timestamp",
    "tool",
    "subject",
    "scopes",
    "config_digest",
    "policy_count",
    "duration_s",
    "outcome",
    "severity_counts",
)


def _fake_ctx(context):
    async def _list_tools():
        return []

    return SimpleNamespace(
        request_context=SimpleNamespace(lifespan_context=context),
        fastmcp=SimpleNamespace(list_tools=_list_tools),
    )


def _audit_records(caplog) -> list[dict]:
    return [
        json.loads(r.getMessage())
        for r in caplog.records
        if r.name == MCP_AUDIT_LOGGER_NAME and r.levelno == logging.INFO
    ]


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
    return build_context(settings)


async def test_validate_policies_hosted_emits_one_record_with_every_field(hosted_context, simple_policy_dict, caplog):
    caplog.set_level(logging.DEBUG)
    ctx = _fake_ctx(hosted_context)

    with as_caller("iam:validate", client_id="caller-1"):
        result = await validate._validate_policies_hosted(policies=[simple_policy_dict], ctx=ctx)

    assert result["results"]

    records = _audit_records(caplog)
    assert len(records) == 1
    record = records[0]
    for field in _RECORD_FIELDS:
        assert field in record, f"missing field {field!r}"
    assert record["tool"] == "validate_policies"
    assert record["subject"] == "caller-1"
    assert record["scopes"] == ["iam:validate"]
    assert record["config_digest"] == hosted_context.config_digest
    assert record["policy_count"] == 1
    assert record["outcome"] == MCP_AUDIT_OUTCOME_SUCCESS
    assert isinstance(record["duration_s"], float)
    assert isinstance(record["severity_counts"], dict)


async def test_no_audit_record_contains_submitted_policy_content(hosted_context, caplog):
    """The redaction test: a marker unique to the request must reach no emitted record.

    Run at DEBUG (the most verbose level), not just the default -- a debug-level
    leak from anywhere in the request path is just as bad as one on the audit
    record itself.
    """
    caplog.set_level(logging.DEBUG)
    ctx = _fake_ctx(hosted_context)
    marker = "AUDITMARKERSECRET9f3c2b1e"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "MarkerStatement",
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": [f"not-a-valid-arn-{marker}"],
            }
        ],
    }

    with as_caller("iam:validate"):
        await validate._validate_policies_hosted(policies=[policy], ctx=ctx)

    assert _audit_records(caplog), "expected at least one audit record to check"
    for record in caplog.records:
        assert marker not in record.getMessage()


async def test_tool_error_still_emits_record_with_matching_outcome(hosted_context, simple_policy_dict, caplog):
    caplog.set_level(logging.DEBUG)
    ctx = _fake_ctx(hosted_context)

    with as_caller("iam:validate"), pytest.raises(ToolError):
        await validate._validate_policies_hosted(policies=[simple_policy_dict], policy_type="not-a-real-type", ctx=ctx)

    records = _audit_records(caplog)
    assert len(records) == 1
    assert records[0]["outcome"] == MCP_AUDIT_OUTCOME_TOOL_ERROR
    assert records[0]["tool"] == "validate_policies"


async def test_analyze_policy_hosted_records_subject(hosted_context, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    client = MagicMock()
    client.validate_policy.return_value = {"findings": []}
    session = MagicMock()
    session.client.return_value = client
    monkeypatch.setattr(analyze, "get_aws_session", lambda ctx, region, profile: session)
    ctx = _fake_ctx(hosted_context)

    with as_caller("iam:analyze", client_id="analyzer-caller"):
        await analyze._analyze_policy_tool_hosted(policy={"Version": "2012-10-17", "Statement": []}, ctx=ctx)

    records = _audit_records(caplog)
    assert len(records) == 1
    assert records[0]["tool"] == "analyze_policy"
    assert records[0]["subject"] == "analyzer-caller"


async def test_local_mode_emits_no_audit_record(simple_policy_dict, caplog):
    caplog.set_level(logging.DEBUG)
    context = build_context(ServerSettings(mode="local"))
    ctx = _fake_ctx(context)

    result = await validate.validate_policies(policies=[simple_policy_dict], ctx=ctx)

    assert result["results"]
    assert _audit_records(caplog) == []


async def test_query_describe_checks_get_config_hosted_each_emit_one_record(hosted_context, mock_fetcher, caplog):
    """The headline requirement is one record per tool call, not just validate/analyze."""
    caplog.set_level(logging.DEBUG)
    hosted_context.fetcher = mock_fetcher
    ctx = _fake_ctx(hosted_context)

    with as_caller("iam:query", client_id="query-caller"):
        await query.query(kind="service_actions", ctx=ctx, service="s3")
    with as_caller("iam:validate", client_id="checks-caller"):
        await checks.describe_checks(ctx=ctx)
    with as_caller("iam:orgconfig", client_id="config-caller"):
        await config.get_config(ctx)

    records = {r["tool"]: r for r in _audit_records(caplog)}
    assert set(records) == {"query", "describe_checks", "get_config"}
    for tool_name, record in records.items():
        for field in _RECORD_FIELDS:
            assert field in record, f"{tool_name}: missing field {field!r}"
        assert record["policy_count"] == 0
        assert record["severity_counts"] == {}
        assert record["outcome"] == MCP_AUDIT_OUTCOME_SUCCESS


async def test_local_mode_query_describe_checks_get_config_emit_no_audit_record(caplog, mock_fetcher):
    caplog.set_level(logging.DEBUG)
    context = build_context(ServerSettings(mode="local"))
    context.fetcher = mock_fetcher
    ctx = _fake_ctx(context)

    await query.query(kind="service_actions", ctx=ctx, service="s3")
    await checks.describe_checks(ctx=ctx)
    await config.get_config(ctx)

    assert _audit_records(caplog) == []


async def test_logging_failure_does_not_break_the_call(hosted_context, simple_policy_dict, monkeypatch, caplog):
    """The audit path must never fail the tool call it observes."""
    caplog.set_level(logging.DEBUG)
    ctx = _fake_ctx(hosted_context)

    def _raise(*_args, **_kwargs):
        raise RuntimeError("log sink is down")

    monkeypatch.setattr(audit_module.logger, "info", _raise)

    with as_caller("iam:validate"):
        result = await validate._validate_policies_hosted(policies=[simple_policy_dict], ctx=ctx)

    assert result["results"]
    assert _audit_records(caplog) == []
    assert any(r.levelno == logging.WARNING and r.name == audit_module.logger.name for r in caplog.records)


async def test_malformed_response_shape_does_not_break_the_call(hosted_context, caplog):
    """A non-dict entry under 'results' must not raise inside the audit finally-block."""
    caplog.set_level(logging.DEBUG)
    ctx = _fake_ctx(hosted_context)

    async def _bad_call():
        return {"results": ["not-a-dict"]}

    result = await audit_module.audited_call("bogus_tool", ctx, 0, _bad_call)

    assert result == {"results": ["not-a-dict"]}
    records = _audit_records(caplog)
    assert len(records) == 1
    assert records[0]["severity_counts"] == {}


async def test_cancelled_call_records_cancelled_outcome_not_success(hosted_context, caplog):
    caplog.set_level(logging.DEBUG)
    ctx = _fake_ctx(hosted_context)

    async def _slow_call():
        await asyncio.sleep(10)
        return {"results": []}

    task = asyncio.ensure_future(audit_module.audited_call("slow_tool", ctx, 0, _slow_call))
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    records = _audit_records(caplog)
    assert len(records) == 1
    assert records[0]["outcome"] == MCP_AUDIT_OUTCOME_CANCELLED
    assert records[0]["outcome"] != MCP_AUDIT_OUTCOME_SUCCESS
