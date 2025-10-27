"""Tests for action resource constraint check."""

import pytest

from iam_validator.checks.action_resource_constraint import ActionResourceConstraintCheck
from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


@pytest.fixture
async def fetcher():
    """Create AWS service fetcher for tests."""
    async with AWSServiceFetcher(prefetch_common=False) as f:
        yield f


@pytest.mark.asyncio
async def test_action_without_required_resources_with_specific_resource(fetcher):
    """Test that actions without required resources with specific ARN fail."""
    check = ActionResourceConstraintCheck()
    config = CheckConfig(check_id="action_resource_constraint", enabled=True)

    # iam:ListRoles has no required resources, but statement uses specific resource
    statement = Statement(
        Effect="Allow",
        Action=["iam:ListRoles"],
        Resource="arn:aws:iam::123456789012:role/MyRole",
    )

    issues = await check.execute(statement, 0, fetcher, config)

    assert len(issues) == 1
    assert issues[0].severity == "error"
    assert issues[0].issue_type == "invalid_resource_constraint"
    assert "does not operate on specific resources" in issues[0].message
    assert "iam:ListRoles" in issues[0].message


@pytest.mark.asyncio
async def test_action_without_required_resources_with_wildcard(fetcher):
    """Test that actions without required resources with wildcard resource pass."""
    check = ActionResourceConstraintCheck()
    config = CheckConfig(check_id="action_resource_constraint", enabled=True)

    # iam:ListRoles has no required resources and uses wildcard - should pass
    statement = Statement(
        Effect="Allow",
        Action=["iam:ListRoles"],
        Resource="*",
    )

    issues = await check.execute(statement, 0, fetcher, config)

    assert len(issues) == 0


@pytest.mark.asyncio
async def test_action_with_required_resources_with_specific_resource(fetcher):
    """Test that actions with required resources with specific ARN pass."""
    check = ActionResourceConstraintCheck()
    config = CheckConfig(check_id="action_resource_constraint", enabled=True)

    # iam:GetRole has required resources (role) and uses specific resource - should pass
    statement = Statement(
        Effect="Allow",
        Action=["iam:GetRole"],
        Resource="arn:aws:iam::123456789012:role/MyRole",
    )

    issues = await check.execute(statement, 0, fetcher, config)

    assert len(issues) == 0


@pytest.mark.asyncio
async def test_multiple_actions_mixed_requirements(fetcher):
    """Test statement with both actions that need and don't need specific resources."""
    check = ActionResourceConstraintCheck()
    config = CheckConfig(check_id="action_resource_constraint", enabled=True)

    # Mix of actions: iam:ListRoles (no required resources) and iam:GetRole (has required resources)
    statement = Statement(
        Effect="Allow",
        Action=["iam:ListRoles", "iam:GetRole"],
        Resource="arn:aws:iam::123456789012:role/MyRole",
    )

    issues = await check.execute(statement, 0, fetcher, config)

    # Should flag ListRoles since it doesn't operate on specific resources
    assert len(issues) == 1
    assert "iam:ListRoles" in issues[0].message
    assert "does not operate on specific resources" in issues[0].message


@pytest.mark.asyncio
async def test_s3_list_all_my_buckets_with_specific_bucket(fetcher):
    """Test s3:ListAllMyBuckets with specific bucket ARN."""
    check = ActionResourceConstraintCheck()
    config = CheckConfig(check_id="action_resource_constraint", enabled=True)

    # s3:ListAllMyBuckets has no required resources
    statement = Statement(
        Effect="Allow",
        Action=["s3:ListAllMyBuckets"],
        Resource="arn:aws:s3:::my-bucket",
    )

    issues = await check.execute(statement, 0, fetcher, config)

    assert len(issues) == 1
    assert "s3:ListAllMyBuckets" in issues[0].message
    assert "does not operate on specific resources" in issues[0].message


@pytest.mark.asyncio
async def test_s3_list_all_my_buckets_with_wildcard(fetcher):
    """Test s3:ListAllMyBuckets with wildcard resource."""
    check = ActionResourceConstraintCheck()
    config = CheckConfig(check_id="action_resource_constraint", enabled=True)

    # s3:ListAllMyBuckets with wildcard - should pass
    statement = Statement(
        Effect="Allow",
        Action=["s3:ListAllMyBuckets"],
        Resource="*",
    )

    issues = await check.execute(statement, 0, fetcher, config)

    assert len(issues) == 0


@pytest.mark.asyncio
async def test_deny_statement_ignored(fetcher):
    """Test that Deny statements are ignored."""
    check = ActionResourceConstraintCheck()
    config = CheckConfig(check_id="action_resource_constraint", enabled=True)

    # Deny statements should be ignored
    statement = Statement(
        Effect="Deny",
        Action=["iam:ListRoles"],
        Resource="arn:aws:iam::123456789012:role/MyRole",
    )

    issues = await check.execute(statement, 0, fetcher, config)

    assert len(issues) == 0


@pytest.mark.asyncio
async def test_wildcard_action_ignored(fetcher):
    """Test that wildcard actions are ignored."""
    check = ActionResourceConstraintCheck()
    config = CheckConfig(check_id="action_resource_constraint", enabled=True)

    # Wildcard action should be ignored
    statement = Statement(
        Effect="Allow",
        Action=["*"],
        Resource="arn:aws:iam::123456789012:role/MyRole",
    )

    issues = await check.execute(statement, 0, fetcher, config)

    assert len(issues) == 0


@pytest.mark.asyncio
async def test_multiple_resources_one_action_no_required_resources(fetcher):
    """Test action without required resources with multiple specific resources."""
    check = ActionResourceConstraintCheck()
    config = CheckConfig(check_id="action_resource_constraint", enabled=True)

    # iam:ListRoles with multiple specific resources
    statement = Statement(
        Effect="Allow",
        Action=["iam:ListRoles"],
        Resource=[
            "arn:aws:iam::123456789012:role/Role1",
            "arn:aws:iam::123456789012:role/Role2",
            "arn:aws:iam::123456789012:role/Role3",
        ],
    )

    issues = await check.execute(statement, 0, fetcher, config)

    assert len(issues) == 1
    assert "iam:ListRoles" in issues[0].message
    assert "does not operate on specific resources" in issues[0].message
    # Should show sample of resources
    assert "Role1" in issues[0].resource


@pytest.mark.asyncio
async def test_custom_severity_override(fetcher):
    """Test that custom severity can be configured."""
    check = ActionResourceConstraintCheck()
    config = CheckConfig(
        check_id="action_resource_constraint",
        enabled=True,
        severity="warning",  # Override default error
    )

    statement = Statement(
        Effect="Allow",
        Action=["iam:ListRoles"],
        Resource="arn:aws:iam::123456789012:role/MyRole",
    )

    issues = await check.execute(statement, 0, fetcher, config)

    assert len(issues) == 1
    assert issues[0].severity == "warning"


@pytest.mark.asyncio
async def test_ec2_describe_instances_without_wildcard(fetcher):
    """Test ec2:DescribeInstances without wildcard resource."""
    check = ActionResourceConstraintCheck()
    config = CheckConfig(check_id="action_resource_constraint", enabled=True)

    # ec2:DescribeInstances has no required resources
    statement = Statement(
        Effect="Allow",
        Action=["ec2:DescribeInstances"],
        Resource="arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
    )

    issues = await check.execute(statement, 0, fetcher, config)

    assert len(issues) == 1
    assert "ec2:DescribeInstances" in issues[0].message


@pytest.mark.asyncio
async def test_invalid_action_format_ignored(fetcher):
    """Test that invalid action formats are ignored."""
    check = ActionResourceConstraintCheck()
    config = CheckConfig(check_id="action_resource_constraint", enabled=True)

    # Invalid action format (no colon)
    statement = Statement(
        Effect="Allow",
        Action=["InvalidAction"],
        Resource="arn:aws:iam::123456789012:role/MyRole",
    )

    issues = await check.execute(statement, 0, fetcher, config)

    # Should not crash, just skip the invalid action
    assert len(issues) == 0


@pytest.mark.asyncio
async def test_nonexistent_action_ignored(fetcher):
    """Test that non-existent actions are ignored."""
    check = ActionResourceConstraintCheck()
    config = CheckConfig(check_id="action_resource_constraint", enabled=True)

    # Action that doesn't exist
    statement = Statement(
        Effect="Allow",
        Action=["iam:NonExistentAction"],
        Resource="arn:aws:iam::123456789012:role/MyRole",
    )

    issues = await check.execute(statement, 0, fetcher, config)

    # Should not crash, just skip the non-existent action
    assert len(issues) == 0
