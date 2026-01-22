"""Tests for WildcardActionCheck."""

import pytest

from iam_validator.checks.wildcard_action import WildcardActionCheck
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
    """Create WildcardActionCheck instance."""
    return WildcardActionCheck()


@pytest.fixture
def config():
    """Create default check config."""
    return CheckConfig(check_id="wildcard_action", enabled=True, config={})


class TestWildcardActionCheck:
    """Tests for WildcardActionCheck."""

    @pytest.mark.asyncio
    async def test_wildcard_action_detected(self, check, fetcher, config):
        """Test that Action:* is detected."""
        statement = Statement(Effect="Allow", Action=["*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "overly_permissive"

    @pytest.mark.asyncio
    async def test_specific_actions_not_flagged(self, check, fetcher, config):
        """Test that specific actions are not flagged."""
        statement = Statement(
            Effect="Allow", Action=["s3:GetObject"], Resource=["*"]
        )
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_service_wildcard_not_flagged(self, check, fetcher, config):
        """Test that service wildcards like s3:* are not flagged by this check."""
        statement = Statement(Effect="Allow", Action=["s3:*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_deny_statement_ignored(self, check, fetcher, config):
        """Test that Deny statements are ignored."""
        statement = Statement(Effect="Deny", Action=["*"], Resource=["*"])
        issues = await check.execute(statement, 0, fetcher, config)
        assert len(issues) == 0
