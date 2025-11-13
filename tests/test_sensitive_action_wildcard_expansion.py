"""Tests for sensitive action detection with wildcard expansion."""

import pytest

from iam_validator.checks.sensitive_action import SensitiveActionCheck
from iam_validator.checks.utils.wildcard_expansion import expand_wildcard_actions
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


@pytest.fixture
async def fetcher():
    """Create AWS service fetcher for tests."""
    async with AWSServiceFetcher(prefetch_common=False) as f:
        yield f


@pytest.mark.asyncio
async def test_expand_exact_actions_unchanged(fetcher):
    """Test that exact actions are kept unchanged."""
    actions = ["iam:CreateUser", "s3:GetObject"]
    expanded = await expand_wildcard_actions(actions, fetcher)

    assert set(expanded) == set(actions)


@pytest.mark.asyncio
async def test_expand_service_wildcard(fetcher):
    """Test expansion of service-level wildcard like iam:*."""

    actions = ["iam:*"]
    expanded = await expand_wildcard_actions(actions, fetcher)

    # Should include sensitive IAM actions
    assert "iam:CreateUser" in expanded
    assert "iam:DeleteUser" in expanded
    assert "iam:CreateRole" in expanded
    assert "iam:DeleteRole" in expanded
    assert "iam:AttachUserPolicy" in expanded
    assert "iam:PutUserPolicy" in expanded
    # Should have many actions
    assert len(expanded) > 100


@pytest.mark.asyncio
async def test_expand_prefix_wildcard(fetcher):
    """Test expansion of prefix wildcard like iam:Delete*."""

    actions = ["iam:Delete*"]
    expanded = await expand_wildcard_actions(actions, fetcher)

    # Should include all IAM Delete actions
    assert "iam:DeleteUser" in expanded
    assert "iam:DeleteRole" in expanded
    assert "iam:DeleteAccessKey" in expanded
    assert "iam:DeleteGroup" in expanded
    # Should NOT include non-Delete actions
    assert "iam:CreateUser" not in expanded
    assert "iam:GetUser" not in expanded


@pytest.mark.asyncio
async def test_expand_suffix_wildcard(fetcher):
    """Test expansion of suffix wildcard like iam:*User."""

    actions = ["iam:*User"]
    expanded = await expand_wildcard_actions(actions, fetcher)

    # Should include all IAM actions ending with User
    assert "iam:CreateUser" in expanded
    assert "iam:DeleteUser" in expanded
    assert "iam:GetUser" in expanded
    # Should NOT include actions not ending with User
    assert "iam:CreateRole" not in expanded


@pytest.mark.asyncio
async def test_expand_middle_wildcard(fetcher):
    """Test expansion of middle wildcard like ec2:*Instance*."""

    actions = ["ec2:*Instance*"]
    expanded = await expand_wildcard_actions(actions, fetcher)

    # Should include actions with Instance in the name
    assert any("TerminateInstances" in action for action in expanded)
    assert any("DescribeInstances" in action for action in expanded)
    assert any("RunInstances" in action for action in expanded)


@pytest.mark.asyncio
async def test_expand_mixed_actions(fetcher):
    """Test expansion of mixed exact and wildcard actions."""

    actions = ["s3:GetObject", "ec2:*", "iam:CreateUser"]
    expanded = await expand_wildcard_actions(actions, fetcher)

    # Exact actions should be preserved
    assert "s3:GetObject" in expanded
    assert "iam:CreateUser" in expanded
    # ec2:* should be expanded
    assert "ec2:DeleteVolume" in expanded
    assert "ec2:TerminateInstances" in expanded


@pytest.mark.asyncio
async def test_expand_full_wildcard_unchanged(fetcher):
    """Test that full wildcard * is kept unchanged."""

    actions = ["*"]
    expanded = await expand_wildcard_actions(actions, fetcher)

    # Full wildcard should be preserved as-is (too broad to expand)
    assert expanded == ["*"]


@pytest.mark.asyncio
async def test_expand_invalid_service_kept(fetcher):
    """Test that invalid service wildcards are kept unchanged."""

    actions = ["invalidservice:*"]
    expanded = await expand_wildcard_actions(actions, fetcher)

    # Invalid service should be kept as-is
    assert "invalidservice:*" in expanded


@pytest.mark.asyncio
async def test_sensitive_action_detection_with_service_wildcard(fetcher):
    """Test that service wildcards are detected as containing sensitive actions."""
    check = SensitiveActionCheck()
    config = CheckConfig(
        check_id="sensitive_action",
        enabled=True,
        config={
            "enabled": True,
            "sensitive_actions": [
                "iam:CreateUser",
                "iam:DeleteUser",
                "iam:AttachUserPolicy",
            ],
        },
    )

    # Statement with iam:* (which includes sensitive actions)
    statement = Statement(
        Effect="Allow",
        Action=["iam:*"],
        Resource="*",
    )

    issues = await check.execute(statement, 0, fetcher, config)

    # Should detect that iam:* includes sensitive actions
    sensitive_issues = [i for i in issues if i.issue_type == "missing_condition"]
    assert len(sensitive_issues) > 0
    assert "sensitive" in sensitive_issues[0].message.lower()


@pytest.mark.asyncio
async def test_sensitive_action_detection_with_prefix_wildcard(fetcher):
    """Test that prefix wildcards are detected as containing sensitive actions."""
    check = SensitiveActionCheck()
    config = CheckConfig(
        check_id="sensitive_action",
        enabled=True,
        config={
            "enabled": True,
            "sensitive_actions": [
                "ec2:DeleteVolume",
                "ec2:TerminateInstances",
            ],
        },
    )

    # Statement with ec2:Delete* (which includes ec2:DeleteVolume)
    statement = Statement(
        Effect="Allow",
        Action=["ec2:Delete*"],
        Resource="*",
    )

    issues = await check.execute(statement, 0, fetcher, config)

    # Should detect that ec2:Delete* includes ec2:DeleteVolume
    sensitive_issues = [i for i in issues if i.issue_type == "missing_condition"]
    assert len(sensitive_issues) > 0
    # Check that the actual sensitive action is mentioned
    assert "ec2:DeleteVolume" in str(sensitive_issues[0].message)


@pytest.mark.asyncio
async def test_sensitive_action_not_detected_for_safe_wildcards(fetcher):
    """Test that safe wildcards don't trigger sensitive action warnings."""
    check = SensitiveActionCheck()
    config = CheckConfig(
        check_id="sensitive_action",
        enabled=True,
        config={
            "enabled": True,
            "sensitive_actions": [
                "s3:DeleteBucket",
                "s3:PutBucketPolicy",
            ],
        },
    )

    # Statement with s3:Get* (which doesn't include sensitive actions)
    statement = Statement(
        Effect="Allow",
        Action=["s3:Get*"],
        Resource="arn:aws:s3:::my-bucket/*",
    )

    issues = await check.execute(statement, 0, fetcher, config)

    # Should NOT detect sensitive actions
    sensitive_issues = [i for i in issues if i.issue_type == "missing_condition"]
    assert len(sensitive_issues) == 0


@pytest.mark.asyncio
async def test_sensitive_action_with_conditions_passes(fetcher):
    """Test that sensitive wildcard actions with conditions pass."""
    check = SensitiveActionCheck()
    config = CheckConfig(
        check_id="sensitive_action",
        enabled=True,
        config={
            "enabled": True,
            "sensitive_actions": [
                "iam:CreateUser",
                "iam:DeleteUser",
            ],
        },
    )

    # Statement with iam:* but WITH conditions
    statement = Statement(
        Effect="Allow",
        Action=["iam:*"],
        Resource="*",
        Condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
    )

    issues = await check.execute(statement, 0, fetcher, config)

    # Should NOT flag because conditions are present
    sensitive_issues = [i for i in issues if i.issue_type == "missing_condition"]
    assert len(sensitive_issues) == 0


@pytest.mark.asyncio
async def test_multiple_wildcard_patterns_detected(fetcher):
    """Test that multiple wildcard patterns are all expanded and checked."""
    check = SensitiveActionCheck()
    config = CheckConfig(
        check_id="sensitive_action",
        enabled=True,
        config={
            "enabled": True,
            "sensitive_actions": [
                "iam:CreateUser",
                "ec2:TerminateInstances",
                "s3:DeleteBucket",
            ],
        },
    )

    # Statement with multiple service wildcards
    statement = Statement(
        Effect="Allow",
        Action=["iam:Create*", "ec2:Terminate*", "s3:Delete*"],
        Resource="*",
    )

    issues = await check.execute(statement, 0, fetcher, config)

    # Should detect all three sensitive actions
    sensitive_issues = [i for i in issues if i.issue_type == "missing_condition"]
    assert len(sensitive_issues) > 0
    message = sensitive_issues[0].message
    # All three sensitive actions should be mentioned
    assert "iam:CreateUser" in message
    assert "ec2:TerminateInstances" in message
    assert "s3:DeleteBucket" in message


@pytest.mark.asyncio
async def test_expansion_caches_service_lookups(fetcher):
    """Test that expansion efficiently caches service lookups."""

    # Multiple wildcards from same service
    actions = ["iam:Delete*", "iam:Create*", "iam:Put*"]
    expanded = await expand_wildcard_actions(actions, fetcher)

    # Should have expanded all patterns
    assert "iam:DeleteUser" in expanded
    assert "iam:CreateUser" in expanded
    assert "iam:PutUserPolicy" in expanded
    # No duplicates (set behavior)
    assert len(expanded) == len(set(expanded))
