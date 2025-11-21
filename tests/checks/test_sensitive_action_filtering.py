"""Test that sensitive_action check filters out actions covered by action_condition_enforcement.

This prevents duplicate warnings when an action is in both:
1. condition_requirements.py (action_condition_enforcement check)
2. sensitive_actions list (sensitive_action check)
"""

import pytest

from iam_validator.checks.sensitive_action import SensitiveActionCheck
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.config.category_suggestions import DEFAULT_CATEGORY_SUGGESTIONS
from iam_validator.core.config.condition_requirements import CONDITION_REQUIREMENTS
from iam_validator.core.config.defaults import get_default_config
from iam_validator.core.models import Statement


@pytest.fixture
async def fetcher():
    """Create AWS service fetcher for tests."""
    async with AWSServiceFetcher(prefetch_common=False) as f:
        yield f


@pytest.mark.asyncio
async def test_s3_getobject_filtered_when_in_condition_requirements(fetcher):
    """Test that s3:GetObject is filtered out when it's in condition_requirements.

    s3:GetObject is in S3_READ_ORG_ID (condition_requirements.py), so even if a user
    adds it to sensitive_actions, it should be filtered to prevent duplicate warnings.
    """
    check = SensitiveActionCheck()

    # Create config that includes s3:GetObject in sensitive_actions
    # AND simulates root_config with action_condition_enforcement requirements
    default_config = get_default_config()
    config = CheckConfig(
        check_id="sensitive_action",
        enabled=True,
        config={
            **default_config["sensitive_action"],
            "sensitive_actions": ["s3:GetObject"],  # User adds this
            "category_suggestions": DEFAULT_CATEGORY_SUGGESTIONS,
        },
        root_config={
            "action_condition_enforcement": {
                "requirements": CONDITION_REQUIREMENTS,  # Contains S3_READ_ORG_ID
            }
        },
    )

    # Statement with s3:GetObject and NO conditions
    statement = Statement(
        Effect="Allow",
        Action=["s3:GetObject"],
        Resource="arn:aws:s3:::my-bucket/*",
    )

    issues = await check.execute(statement, 0, fetcher, config)

    # Should NOT generate any issues because s3:GetObject is filtered
    # (action_condition_enforcement will handle it)
    assert len(issues) == 0


@pytest.mark.asyncio
async def test_custom_action_not_filtered(fetcher):
    """Test that custom actions NOT in condition_requirements still generate issues."""
    check = SensitiveActionCheck()

    default_config = get_default_config()
    config = CheckConfig(
        check_id="sensitive_action",
        enabled=True,
        config={
            **default_config["sensitive_action"],
            "sensitive_actions": ["customservice:CustomAction"],
            "category_suggestions": DEFAULT_CATEGORY_SUGGESTIONS,
        },
        root_config={
            "action_condition_enforcement": {
                "requirements": CONDITION_REQUIREMENTS,
            }
        },
    )

    statement = Statement(
        Effect="Allow",
        Action=["customservice:CustomAction"],
        Resource="*",
    )

    issues = await check.execute(statement, 0, fetcher, config)

    # Should generate an issue because customservice:CustomAction is NOT filtered
    assert len(issues) == 1
    issue = issues[0]
    assert issue.action == "customservice:CustomAction"
    assert "ABAC" in issue.suggestion


@pytest.mark.asyncio
async def test_mixed_actions_partial_filtering(fetcher):
    """Test that only covered actions are filtered, others still generate issues."""
    check = SensitiveActionCheck()

    default_config = get_default_config()
    config = CheckConfig(
        check_id="sensitive_action",
        enabled=True,
        config={
            **default_config["sensitive_action"],
            # Mix of actions: s3:GetObject (covered) + customservice:Action (not covered)
            "sensitive_actions": ["s3:GetObject", "customservice:CustomAction"],
            "category_suggestions": DEFAULT_CATEGORY_SUGGESTIONS,
        },
        root_config={
            "action_condition_enforcement": {
                "requirements": CONDITION_REQUIREMENTS,
            }
        },
    )

    # Statement with BOTH actions
    statement = Statement(
        Effect="Allow",
        Action=["s3:GetObject", "customservice:CustomAction"],
        Resource="*",
    )

    issues = await check.execute(statement, 0, fetcher, config)

    # Should generate ONE issue for customservice:CustomAction only
    # s3:GetObject should be filtered
    assert len(issues) == 1
    issue = issues[0]
    assert issue.action == "customservice:CustomAction"


@pytest.mark.asyncio
async def test_iam_passrole_filtered(fetcher):
    """Test that iam:PassRole is filtered (it's in IAM_PASS_ROLE_REQUIREMENT)."""
    check = SensitiveActionCheck()

    default_config = get_default_config()
    config = CheckConfig(
        check_id="sensitive_action",
        enabled=True,
        config={
            **default_config["sensitive_action"],
            "sensitive_actions": ["iam:PassRole"],
            "category_suggestions": DEFAULT_CATEGORY_SUGGESTIONS,
        },
        root_config={
            "action_condition_enforcement": {
                "requirements": CONDITION_REQUIREMENTS,
            }
        },
    )

    statement = Statement(
        Effect="Allow",
        Action=["iam:PassRole"],
        Resource="arn:aws:iam::*:role/*",
    )

    issues = await check.execute(statement, 0, fetcher, config)

    # Should NOT generate issues - iam:PassRole is in IAM_PASS_ROLE_REQUIREMENT
    assert len(issues) == 0


@pytest.mark.asyncio
async def test_no_filtering_when_no_root_config(fetcher):
    """Test graceful fallback when root_config is not provided."""
    check = SensitiveActionCheck()

    default_config = get_default_config()
    config = CheckConfig(
        check_id="sensitive_action",
        enabled=True,
        config={
            **default_config["sensitive_action"],
            "sensitive_actions": ["s3:GetObject"],
            "category_suggestions": DEFAULT_CATEGORY_SUGGESTIONS,
        },
        root_config={},  # No action_condition_enforcement config
    )

    statement = Statement(
        Effect="Allow",
        Action=["s3:GetObject"],
        Resource="arn:aws:s3:::my-bucket/*",
    )

    issues = await check.execute(statement, 0, fetcher, config)

    # Should generate issue because no filtering occurs without root_config
    assert len(issues) == 1
