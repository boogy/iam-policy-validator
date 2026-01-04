"""Tests for WildcardResourceCheck."""

import pytest

from iam_validator.checks.wildcard_resource import WildcardResourceCheck
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


@pytest.fixture
async def fetcher():
    """Create AWS service fetcher for tests."""
    async with AWSServiceFetcher(prefetch_common=False) as f:
        yield f


@pytest.fixture
def check():
    """Create WildcardResourceCheck instance."""
    return WildcardResourceCheck()


@pytest.fixture
def config():
    """Create default check config."""
    return CheckConfig(check_id="wildcard_resource", enabled=True, config={})


class TestWildcardResourceCheck:
    """Tests for WildcardResourceCheck."""

    @pytest.mark.asyncio
    async def test_wildcard_resource_detected(self, check, fetcher, config):
        """Test that Resource:* is detected for actions that support resource-level permissions."""
        statement = Statement(Effect="Allow", Action=["s3:GetObject"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "overly_permissive"

    @pytest.mark.asyncio
    async def test_specific_resources_not_flagged(self, check, fetcher, config):
        """Test that specific resources are not flagged."""
        statement = Statement(
            Effect="Allow", Action=["s3:GetObject"], Resource=["arn:aws:s3:::bucket/*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_deny_statement_ignored(self, check, fetcher, config):
        """Test that Deny statements are ignored."""
        statement = Statement(Effect="Deny", Action=["s3:*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_allowed_wildcards_config(self, check, fetcher):
        """Test allowed_wildcards configuration."""
        config = CheckConfig(
            check_id="wildcard_resource",
            enabled=True,
            config={"allowed_wildcards": ["iam:Get*"]},
        )
        # Action matching allowed pattern passes
        statement = Statement(Effect="Allow", Action=["iam:GetUser"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

        # Action not matching allowed pattern fails
        statement2 = Statement(Effect="Allow", Action=["iam:DeleteUser"], Resource=["*"])
        issues2 = await check.execute(statement2, 0, fetcher, config)
        assert len(issues2) == 1

    @pytest.mark.asyncio
    async def test_list_level_actions_not_flagged(self, check, fetcher, config):
        """Test that list-level actions don't flag wildcards (they don't support resource-level)."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:ListAllMyBuckets", "iam:ListUsers", "ec2:DescribeInstances"],
            Resource=["*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_mixed_list_and_write_actions(self, check, fetcher, config):
        """Test that mixed list and write actions flag the write action."""
        statement = Statement(
            Effect="Allow", Action=["s3:ListAllMyBuckets", "s3:PutObject"], Resource=["*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
