"""Production-readiness fixes for MCP tools.

Tests the accuracy / robustness improvements made on top of v1.20.0:

- ``explain_policy`` uses authoritative access_level from the live service ref
  and surfaces NotAction / NotResource / Principal anti-patterns.
- ``quick_validate`` includes ``full_wildcard`` in wildcards_detected.
- ``compare_policies`` uses canonical statement signatures (not stmt_idx).
- ``fix_policy_issues`` normalizes ``NotAction`` (not just ``Action``).
- ``aws_access_analyzer_validate`` defaults region per partition + timeout.
- Malformed input → clean ``ToolError`` (not Pydantic stacktrace).
- ``unfixed_issues`` always returns a list with separate count.
"""

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastmcp.exceptions import ToolError

from iam_validator.core.constants import PARTITION_DEFAULT_REGION
from iam_validator.mcp import server


@pytest.fixture
def stub_ctx_no_fetcher():
    """Context where get_shared_fetcher returns None (forces fallback paths)."""
    return SimpleNamespace(request_context=None)


# ---------------------------------------------------------------------------
# explain_policy — authoritative access-level + NotAction/NotResource handling
# ---------------------------------------------------------------------------


@pytest.fixture
def explain_ctx(monkeypatch):
    """Stub a fetcher returning authoritative access_level metadata."""

    # Build a service_detail mock whose .actions dict matches what
    # _get_access_level expects (annotations.Properties flags).
    def make_action(props: dict[str, bool]):
        m = MagicMock()
        m.annotations = {"Properties": props}
        return m

    s3 = MagicMock()
    s3.actions = {
        "GetObject": make_action({"IsRead": True}),
        "PutObject": make_action({"IsWrite": True}),
        "ListBucket": make_action({"IsList": True}),
    }
    iam = MagicMock()
    iam.actions = {
        "AttachUserPolicy": make_action({"IsPermissionManagement": True}),
        "TagUser": make_action({"IsTaggingOnly": True}),
    }

    fetcher = MagicMock()

    async def fake_fetch(name: str):
        return {"s3": s3, "iam": iam}[name]

    fetcher.fetch_service_by_name = AsyncMock(side_effect=fake_fetch)

    # Patch get_shared_fetcher to return this fetcher.
    monkeypatch.setattr(server, "get_shared_fetcher", lambda ctx: fetcher)

    return SimpleNamespace(request_context=None)


async def test_explain_policy_uses_authoritative_access_level(explain_ctx):
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "iam:AttachUserPolicy"],
                "Resource": "arn:aws:s3:::b/*",
            }
        ],
    }
    result = await server.explain_policy(policy, ctx=explain_ctx, verbose=True)
    services = {s["service"]: set(s["access_types"]) for s in result["services_accessed"]}
    # _get_access_level returns "read" for IsRead, "write" for IsWrite, "permissions-management" for IsPermissionManagement
    assert services["s3"] == {"read", "write"}
    assert services["iam"] == {"permissions-management"}


async def test_explain_policy_flags_not_action(explain_ctx):
    """Effect:Allow + NotAction is an anti-pattern; must show up in concerns."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "NotAction": "iam:CreateUser",
                "Resource": "*",
            }
        ],
    }
    result = await server.explain_policy(policy, ctx=explain_ctx, verbose=True)
    concerns = " ".join(result["security_concerns"])
    assert "NotAction" in concerns
    assert any("Effect:Allow with NotAction" in c for c in result["security_concerns"])
    assert result["statements"][0]["uses_not_action"] is True


async def test_explain_policy_flags_principal_wildcard(explain_ctx):
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "sts:AssumeRole",
                "Resource": "*",
            }
        ],
    }
    result = await server.explain_policy(policy, ctx=explain_ctx, verbose=True)
    concerns = " ".join(result["security_concerns"])
    assert "Principal AWS:*" in concerns


async def test_explain_policy_case_insensitive_effect(explain_ctx):
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "allow", "Action": "s3:GetObject", "Resource": "*"}],
    }
    result = await server.explain_policy(policy, ctx=explain_ctx, verbose=True)
    assert "1 Allow" in result["summary"]


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
# compare_policies — canonical signatures, NotAction/NotResource/Principal
# ---------------------------------------------------------------------------


async def test_compare_policies_no_phantom_diff_when_only_sids_change():
    """Re-ordering statements (no Sids) must not be reported as a change."""
    a = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::a/*"},
            {"Effect": "Deny", "Action": "iam:*", "Resource": "*"},
        ],
    }
    b = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Deny", "Action": "iam:*", "Resource": "*"},
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::a/*"},
        ],
    }
    result = await server.compare_policies(a, b, verbose=True)
    assert result["statements_added"] == 0
    assert result["statements_removed"] == 0
    assert result["added_actions"] == []
    assert result["removed_actions"] == []


async def test_compare_policies_diffs_not_action_independently():
    a = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "NotAction": "iam:CreateUser", "Resource": "*"}],
    }
    b = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "NotAction": ["iam:CreateUser", "s3:DeleteBucket"], "Resource": "*"}],
    }
    result = await server.compare_policies(a, b, verbose=True)
    assert "s3:DeleteBucket" in result["added_not_actions"]
    assert result["added_actions"] == []  # not the same field


async def test_compare_policies_diffs_principal():
    a = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::111:role/A"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    b = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": ["arn:aws:iam::111:role/A", "arn:aws:iam::222:role/B"]},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    result = await server.compare_policies(a, b, verbose=True)
    assert "AWS:arn:aws:iam::222:role/B" in result["added_principals"]


# ---------------------------------------------------------------------------
# fix_policy_issues — NotAction case normalization
# ---------------------------------------------------------------------------


async def test_fix_policy_issues_normalizes_not_action_case(monkeypatch):
    """NotAction prefixes must be lowercased like Action."""
    from iam_validator.core.models import ValidationIssue
    from iam_validator.mcp.models import ValidationResult
    from iam_validator.mcp.tools import validation as validation_mod

    # Force action_validation to fire so the case-fix runs.
    fake_initial = ValidationResult(
        is_valid=False,
        issues=[
            ValidationIssue(
                severity="error",
                statement_index=0,
                issue_type="invalid_action",
                message="Service prefix must be lowercase",
                suggestion="lowercase service",
                check_id="action_validation",
            )
        ],
        policy_file="inline-policy",
    )
    fake_final = ValidationResult(is_valid=True, issues=[], policy_file="inline-policy")

    calls = {"n": 0}

    async def fake_validate(**kwargs):
        calls["n"] += 1
        return fake_initial if calls["n"] == 1 else fake_final

    monkeypatch.setattr(validation_mod, "validate_policy", fake_validate)
    monkeypatch.setattr(validation_mod, "_detect_policy_type", lambda _p: "identity")

    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "NotAction": "S3:GetObject", "Resource": "*"}],
    }
    result = await server.fix_policy_issues(policy)
    assert result["fixed_policy"]["Statement"][0]["NotAction"] == "s3:GetObject"
    assert any("NotAction" in fix for fix in result["fixes_applied"])


async def test_fix_policy_issues_returns_consistent_unfixed_shape(monkeypatch):
    """unfixed_issues is always a list; unfixed_count is always an int."""
    from iam_validator.core.models import ValidationIssue
    from iam_validator.mcp.models import ValidationResult
    from iam_validator.mcp.tools import validation as validation_mod

    fake = ValidationResult(
        is_valid=False,
        issues=[
            ValidationIssue(
                severity="medium",
                statement_index=0,
                issue_type="overly_permissive",
                message="wildcard",
                suggestion="...",
                check_id="wildcard_action",
            )
        ],
        policy_file="inline-policy",
    )
    finals = [fake, fake]

    async def fake_validate(**kwargs):
        return finals.pop(0) if finals else fake

    monkeypatch.setattr(validation_mod, "validate_policy", fake_validate)
    monkeypatch.setattr(validation_mod, "_detect_policy_type", lambda _p: "identity")

    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}

    lean = await server.fix_policy_issues(policy, verbose=False)
    verbose = await server.fix_policy_issues(policy, verbose=True)
    assert isinstance(lean["unfixed_issues"], list)
    assert isinstance(verbose["unfixed_issues"], list)
    assert lean["unfixed_count"] == verbose["unfixed_count"]


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
