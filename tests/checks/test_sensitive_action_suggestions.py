"""Tests for sensitive action suggestion system (two-tier lookup).

The sensitive_action check provides suggestions when actions have NO conditions.
It uses a two-tier system:
- Tier 1: Action-specific overrides (action_overrides in category_suggestions.py)
- Tier 2: Category-level defaults

Note: Validation of specific required conditions (like iam:PassRole requiring
iam:PassedToService) is handled by the action_condition_enforcement check, not here.
"""

import pytest

from iam_validator.checks.sensitive_action import SensitiveActionCheck
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.config.category_suggestions import DEFAULT_CATEGORY_SUGGESTIONS
from iam_validator.core.config.defaults import get_default_config
from iam_validator.core.models import Statement


@pytest.fixture
async def fetcher():
    """Create AWS service fetcher for tests."""
    async with AWSServiceFetcher(prefetch_common=False) as f:
        yield f


@pytest.fixture
def full_config():
    """Create a full config with category suggestions."""
    default_config = get_default_config()
    return CheckConfig(
        check_id="sensitive_action",
        enabled=True,
        config={
            **default_config["sensitive_action"],
            "category_suggestions": DEFAULT_CATEGORY_SUGGESTIONS,
        },
    )


@pytest.mark.asyncio
async def test_tier2_category_default_s3_getobject(fetcher):
    """Test that s3:GetObject uses Tier 2 (category default) since action override was removed.

    Note: s3:GetObject is now handled by S3_READ_ORG_ID in condition_requirements.py,
    so it should NOT be added to sensitive_actions in production. This test shows what
    happens if a user explicitly adds it anyway - they'll get the category default suggestion.
    """
    check = SensitiveActionCheck()

    # Create config that includes s3:GetObject as a sensitive action
    default_config = get_default_config()
    config = CheckConfig(
        check_id="sensitive_action",
        enabled=True,
        config={
            **default_config["sensitive_action"],
            "sensitive_actions": ["s3:GetObject"],  # Add it explicitly for this test
            "category_suggestions": DEFAULT_CATEGORY_SUGGESTIONS,
        },
    )

    # Statement with s3:GetObject (no action_override, falls back to category default)
    statement = Statement(
        Effect="Allow",
        Action=["s3:GetObject"],
        Resource="arn:aws:s3:::my-bucket/*",
    )

    issues = await check.execute(statement, 0, fetcher, config)

    assert len(issues) == 1
    issue = issues[0]

    # Should use category default suggestion (data_access)
    assert "retrieves sensitive data" in issue.suggestion
    assert "ABAC" in issue.suggestion
    assert "aws:PrincipalTag" in issue.suggestion or "principal tags" in issue.suggestion

    # Should have example from category default
    assert issue.example is not None
    assert "aws:PrincipalTag/owner" in issue.example or "aws:ResourceTag" in issue.example


@pytest.mark.asyncio
async def test_tier1_action_override_suggestion_iam_createaccesskey(fetcher):
    """Test that iam:CreateAccessKey uses Tier 1 (action override) suggestion."""
    check = SensitiveActionCheck()

    # Create config that includes iam:CreateAccessKey as a sensitive action
    default_config = get_default_config()
    config = CheckConfig(
        check_id="sensitive_action",
        enabled=True,
        config={
            **default_config["sensitive_action"],
            "sensitive_actions": ["iam:CreateAccessKey"],  # Add it explicitly for this test
            "category_suggestions": DEFAULT_CATEGORY_SUGGESTIONS,
        },
    )

    # Statement with iam:CreateAccessKey (has action_override in credential_exposure category)
    statement = Statement(
        Effect="Allow",
        Action=["iam:CreateAccessKey"],
        Resource="*",
    )

    issues = await check.execute(statement, 0, fetcher, config)

    assert len(issues) == 1
    issue = issues[0]

    # Should use suggestion from action_override
    assert "long-term credentials" in issue.suggestion
    assert "aws:MultiFactorAuthPresent" in issue.suggestion
    assert "aws:PrincipalTag/role" in issue.suggestion

    # Should have example from override
    assert issue.example is not None
    assert "security-admin" in issue.example
    assert "aws:MultiFactorAuthPresent" in issue.example


@pytest.mark.asyncio
async def test_tier2_category_default_suggestion(fetcher):
    """Test that actions without Tier 1 override use Tier 2 (category default)."""
    check = SensitiveActionCheck()

    # Create config that includes cognito-identity:GetCredentialsForIdentity as a sensitive action
    default_config = get_default_config()
    config = CheckConfig(
        check_id="sensitive_action",
        enabled=True,
        config={
            **default_config["sensitive_action"],
            "sensitive_actions": ["cognito-identity:GetCredentialsForIdentity"],  # Add it explicitly
            "category_suggestions": DEFAULT_CATEGORY_SUGGESTIONS,
        },
    )

    # Statement with cognito-identity:GetCredentialsForIdentity
    # (in credential_exposure category but no specific override)
    statement = Statement(
        Effect="Allow",
        Action=["cognito-identity:GetCredentialsForIdentity"],
        Resource="*",
    )

    issues = await check.execute(statement, 0, fetcher, config)

    assert len(issues) == 1
    issue = issues[0]

    # Should use category default suggestion (credential_exposure)
    assert "credentials or secrets" in issue.suggestion
    assert "aws:PrincipalTag" in issue.suggestion or "principal tags" in issue.suggestion

    # Should have example from category default
    assert issue.example is not None
    assert "aws:PrincipalTag/owner" in issue.example or "aws:ResourceTag" in issue.example


@pytest.mark.asyncio
async def test_ultimate_fallback_uncategorized_action(fetcher):
    """Test that uncategorized actions use ultimate fallback suggestion."""
    check = SensitiveActionCheck()

    # Create config with a custom action that's not in any category
    default_config = get_default_config()
    config = CheckConfig(
        check_id="sensitive_action",
        enabled=True,
        config={
            **default_config["sensitive_action"],
            "sensitive_actions": ["customservice:CustomAction"],
            "category_suggestions": DEFAULT_CATEGORY_SUGGESTIONS,
        },
    )

    statement = Statement(
        Effect="Allow",
        Action=["customservice:CustomAction"],
        Resource="*",
    )

    issues = await check.execute(statement, 0, fetcher, config)

    assert len(issues) == 1
    issue = issues[0]

    # Should use ultimate fallback (generic ABAC guidance)
    assert "ABAC" in issue.suggestion
    assert "aws:PrincipalTag" in issue.suggestion
    assert "aws:ResourceTag" in issue.suggestion

    # Should have generic example
    assert issue.example is not None
    assert "aws:PrincipalTag/owner" in issue.example


@pytest.mark.asyncio
async def test_no_issue_when_conditions_present(fetcher):
    """Test that actions with conditions don't generate issues (no suggestion needed)."""
    check = SensitiveActionCheck()

    # Create config with s3:PutObject as sensitive
    default_config = get_default_config()
    config = CheckConfig(
        check_id="sensitive_action",
        enabled=True,
        config={
            **default_config["sensitive_action"],
            "sensitive_actions": ["s3:PutObject"],
            "category_suggestions": DEFAULT_CATEGORY_SUGGESTIONS,
        },
    )

    statement = Statement(
        Effect="Allow",
        Action=["s3:PutObject"],
        Resource="arn:aws:s3:::my-bucket/*",
        Condition={
            "StringEquals": {
                "aws:ResourceOrgID": "${aws:PrincipalOrgID}",
                "aws:ResourceAccount": "${aws:PrincipalAccount}",
            }
        },
    )

    issues = await check.execute(statement, 0, fetcher, config)

    # No issues should be generated when conditions are present
    assert len(issues) == 0
