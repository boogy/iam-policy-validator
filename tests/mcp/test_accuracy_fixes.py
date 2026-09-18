"""Production-readiness fixes for MCP tools.

Tests the accuracy / robustness improvements made on top of v1.20.0:

- ``quick_validate`` includes ``full_wildcard`` in wildcards_detected.
- ``aws_access_analyzer_validate`` defaults region per partition + timeout.
- Malformed input → clean ``ToolError`` (not Pydantic stacktrace).
"""

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastmcp.exceptions import ToolError

from iam_validator.core.constants import PARTITION_DEFAULT_REGION
from iam_validator.mcp import server


@pytest.fixture
def stub_ctx_no_fetcher():
    """Context where get_shared_fetcher returns None (forces fallback paths)."""
    return SimpleNamespace(request_context=None)


# ---------------------------------------------------------------------------
# quick_validate — wildcards_detected must include full_wildcard
# ---------------------------------------------------------------------------


async def test_quick_validate_detects_full_wildcard(monkeypatch):
    """A policy emitting a full_wildcard issue must report wildcards_detected=True."""
    from iam_validator.core.models import ValidationIssue
    from iam_validator.mcp.models import ValidationResult
    from iam_validator.mcp.tools import validation as validation_mod

    fake_result = ValidationResult(
        is_valid=False,
        issues=[
            ValidationIssue(
                severity="critical",
                statement_index=0,
                issue_type="overly_permissive",
                message="Action and Resource are both '*'",
                suggestion="...",
                check_id="full_wildcard",
            )
        ],
        policy_file="inline-policy",
    )

    async def fake_validate(**kwargs):
        return fake_result

    monkeypatch.setattr(validation_mod, "validate_policy", fake_validate)

    result = await validation_mod.quick_validate({"Version": "2012-10-17", "Statement": []})
    assert result["wildcards_detected"] is True


# ---------------------------------------------------------------------------
# aws_access_analyzer_validate — partition→region defaulting + bad partition
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "partition,expected_region",
    [
        ("aws", "us-east-1"),
        ("aws-cn", "cn-north-1"),
        ("aws-us-gov", "us-gov-west-1"),
    ],
)
def test_partition_default_region_table(partition: str, expected_region: str):
    assert PARTITION_DEFAULT_REGION[partition] == expected_region


async def test_aws_access_analyzer_validate_rejects_bad_partition(monkeypatch):
    """Unknown partition raises ToolError before touching boto3."""
    # Stub get_aws_session so we can confirm it's never reached.
    called = {"hit": False}

    def fake_get_aws_session(ctx, region, profile):
        called["hit"] = True
        return MagicMock()

    monkeypatch.setattr(server, "get_aws_session", fake_get_aws_session)

    with pytest.raises(ToolError, match="Unsupported partition"):
        await server.aws_access_analyzer_validate(
            policy={"Version": "2012-10-17", "Statement": []},
            ctx=SimpleNamespace(request_context=None),
            partition="aws-bogus",
        )
    assert called["hit"] is False


async def test_aws_access_analyzer_validate_uses_partition_default_region(monkeypatch):
    """When region is omitted, defaults to PARTITION_DEFAULT_REGION[partition]."""
    captured_region: dict[str, Any] = {}

    def fake_get_aws_session(ctx, region, profile):
        captured_region["region"] = region
        return MagicMock()

    async def fake_analyze(**kwargs):
        captured_region["analyze_region"] = kwargs.get("region")
        return {"findings": [], "finding_count": 0}

    monkeypatch.setattr(server, "get_aws_session", fake_get_aws_session)
    monkeypatch.setattr("iam_validator.mcp.tools.analyze.analyze_policy", fake_analyze)

    await server.aws_access_analyzer_validate(
        policy={"Version": "2012-10-17", "Statement": []},
        ctx=SimpleNamespace(request_context=None),
        partition="aws-cn",
    )
    assert captured_region["region"] == "cn-north-1"
    assert captured_region["analyze_region"] == "cn-north-1"


async def test_aws_access_analyzer_validate_timeout(monkeypatch):
    """Hung AWS API call surfaces as a ToolError, not an open hang."""
    import asyncio

    def fake_get_aws_session(ctx, region, profile):
        return MagicMock()

    async def slow_analyze(**kwargs):
        await asyncio.sleep(5)
        return {"findings": [], "finding_count": 0}

    monkeypatch.setattr(server, "get_aws_session", fake_get_aws_session)
    monkeypatch.setattr("iam_validator.mcp.tools.analyze.analyze_policy", slow_analyze)

    with pytest.raises(ToolError, match="timed out"):
        await server.aws_access_analyzer_validate(
            policy={"Version": "2012-10-17", "Statement": []},
            ctx=SimpleNamespace(request_context=None),
            timeout_seconds=0.1,
        )


# ---------------------------------------------------------------------------
# Malformed input → clean ToolError
# ---------------------------------------------------------------------------


async def test_validate_policy_malformed_raises_tool_error():
    """Schema-violating policy dict raises ToolError, not a Pydantic stacktrace."""
    from iam_validator.mcp.tools import validation as validation_mod

    # Statement set to a non-list/dict value triggers a Pydantic ValidationError
    # because the IAMPolicy model rejects scalars there.
    with pytest.raises(ToolError, match="Malformed IAM policy"):
        await validation_mod.validate_policy(policy={"Version": "2012-10-17", "Statement": 12345})


# ---------------------------------------------------------------------------
# DRY: issue_to_dict helper produces the documented shapes
# ---------------------------------------------------------------------------


def test_issue_to_dict_lean_shape():
    from iam_validator.core.models import ValidationIssue
    from iam_validator.mcp.tools.validation import issue_to_dict

    issue = ValidationIssue(
        severity="medium",
        statement_index=0,
        issue_type="overly_permissive",
        message="m",
        suggestion="s",
        check_id="wildcard_action",
    )
    lean = issue_to_dict(issue, verbose=False)
    assert set(lean.keys()) == {"severity", "message", "suggestion", "check_id"}


def test_issue_to_dict_verbose_includes_all_fields():
    from iam_validator.core.models import ValidationIssue
    from iam_validator.mcp.tools.validation import issue_to_dict

    issue = ValidationIssue(
        severity="medium",
        statement_index=0,
        issue_type="overly_permissive",
        message="m",
        suggestion="s",
        check_id="wildcard_action",
    )
    verbose = issue_to_dict(issue, verbose=True)
    expected = {
        "severity",
        "message",
        "suggestion",
        "example",
        "check_id",
        "statement_index",
        "action",
        "resource",
        "field_name",
        "risk_explanation",
        "documentation_url",
        "remediation_steps",
    }
    assert set(verbose.keys()) == expected
