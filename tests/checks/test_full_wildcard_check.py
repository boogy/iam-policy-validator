"""Tests for FullWildcardCheck."""

import pytest

from iam_validator.checks.full_wildcard import FullWildcardCheck
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
    return FullWildcardCheck()


@pytest.fixture
def config():
    return CheckConfig(check_id="full_wildcard", enabled=True, config={})


class TestFullWildcardCheck:
    """Tests for FullWildcardCheck."""

    @pytest.mark.asyncio
    async def test_full_wildcard_detected(self, check, fetcher, config):
        """Test that both Action:* and Resource:* together is detected."""
        statement = Statement(Effect="Allow", Action=["*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "critical"
        assert issues[0].issue_type == "security_risk"

    @pytest.mark.asyncio
    async def test_only_action_wildcard_no_issue(self, check, fetcher, config):
        """Test that only Action:* without Resource:* is not flagged."""
        statement = Statement(
            Effect="Allow", Action=["*"], Resource=["arn:aws:s3:::my-bucket/*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_only_resource_wildcard_no_issue(self, check, fetcher, config):
        """Test that only Resource:* without Action:* is not flagged."""
        statement = Statement(Effect="Allow", Action=["s3:GetObject"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_deny_statement_ignored(self, check, fetcher, config):
        """Test that Deny statements are ignored."""
        statement = Statement(Effect="Deny", Action=["*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_wildcard_in_list(self, check, fetcher, config):
        """Test that wildcard is detected even when in a list with other items."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject", "*"],
            Resource=["arn:aws:s3:::my-bucket/*", "*"],
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "critical"
