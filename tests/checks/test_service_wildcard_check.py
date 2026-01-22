"""Tests for ServiceWildcardCheck."""

import pytest

from iam_validator.checks.service_wildcard import ServiceWildcardCheck
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
    return ServiceWildcardCheck()


@pytest.fixture
def config():
    return CheckConfig(check_id="service_wildcard", enabled=True, config={})


class TestServiceWildcardCheck:
    """Tests for ServiceWildcardCheck."""

    @pytest.mark.asyncio
    async def test_service_wildcard_detected(self, check, fetcher, config):
        """Test that service-level wildcards are detected."""
        statement = Statement(Effect="Allow", Action=["iam:*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "overly_permissive"
        assert issues[0].action == "iam:*"

    @pytest.mark.asyncio
    async def test_multiple_service_wildcards(self, check, fetcher, config):
        """Test that multiple service wildcards are all detected."""
        statement = Statement(Effect="Allow", Action=["iam:*", "s3:*", "ec2:*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 3
        actions = {issue.action for issue in issues}
        assert actions == {"iam:*", "s3:*", "ec2:*"}

    @pytest.mark.asyncio
    async def test_full_wildcard_skipped(self, check, fetcher, config):
        """Test that full wildcard Action:* is skipped (handled by wildcard_action check)."""
        statement = Statement(Effect="Allow", Action=["*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_prefix_wildcard_not_flagged(self, check, fetcher, config):
        """Test that prefix wildcards like iam:Get* are not flagged."""
        statement = Statement(Effect="Allow", Action=["iam:Get*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_deny_statement_ignored(self, check, fetcher, config):
        """Test that Deny statements are ignored."""
        statement = Statement(Effect="Deny", Action=["iam:*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_allowed_services_configuration(self, check, fetcher):
        """Test that configured allowed services are not flagged."""
        config = CheckConfig(
            check_id="service_wildcard",
            enabled=True,
            config={"allowed_services": ["logs", "cloudwatch"]},
        )
        statement = Statement(
            Effect="Allow", Action=["logs:*", "cloudwatch:*", "iam:*"], Resource=["*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)
        # Only iam:* should be flagged
        assert len(issues) == 1
        assert issues[0].action == "iam:*"
