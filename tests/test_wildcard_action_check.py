"""Tests for WildcardActionCheck."""

import pytest

from iam_validator.checks.wildcard_action import WildcardActionCheck
from iam_validator.core.aws_fetcher import AWSServiceFetcher
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

    def test_check_id(self, check):
        """Test check ID."""
        assert check.check_id == "wildcard_action"

    def test_description(self, check):
        """Test check description."""
        assert "wildcard actions" in check.description.lower()

    def test_default_severity(self, check):
        """Test default severity is medium."""
        assert check.default_severity == "medium"

    @pytest.mark.asyncio
    async def test_wildcard_action_detected(self, check, fetcher, config):
        """Test that Action:* is detected."""
        statement = Statement(
            Effect="Allow",
            Action=["*"],
            Resource=["arn:aws:s3:::my-bucket/*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].severity == "medium"
        assert issues[0].issue_type == "overly_permissive"
        assert "all actions" in issues[0].message.lower()

    @pytest.mark.asyncio
    async def test_specific_actions_not_flagged(self, check, fetcher, config):
        """Test that specific actions are not flagged."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject", "s3:PutObject"],
            Resource=["arn:aws:s3:::my-bucket/*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_service_wildcard_not_flagged(self, check, fetcher, config):
        """Test that service wildcards like s3:* are not flagged by this check."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:*"],
            Resource=["arn:aws:s3:::my-bucket/*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_prefix_wildcard_not_flagged(self, check, fetcher, config):
        """Test that prefix wildcards like s3:Get* are not flagged."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:Get*"],
            Resource=["arn:aws:s3:::my-bucket/*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_deny_statement_ignored(self, check, fetcher, config):
        """Test that Deny statements are ignored."""
        statement = Statement(
            Effect="Deny",
            Action=["*"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_wildcard_in_list_with_other_actions(self, check, fetcher, config):
        """Test that wildcard is detected even when mixed with other actions."""
        statement = Statement(
            Effect="Allow",
            Action=["s3:GetObject", "*", "iam:GetUser"],
            Resource=["arn:aws:s3:::my-bucket/*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert "all actions" in issues[0].message.lower()

    @pytest.mark.asyncio
    async def test_statement_with_sid(self, check, fetcher, config):
        """Test that statement SID is captured in issue."""
        statement = Statement(
            Sid="AllowAllActions",
            Effect="Allow",
            Action=["*"],
            Resource=["arn:aws:s3:::my-bucket/*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].statement_sid == "AllowAllActions"

    @pytest.mark.asyncio
    async def test_statement_index(self, check, fetcher, config):
        """Test that statement index is captured."""
        statement = Statement(
            Effect="Allow",
            Action=["*"],
            Resource=["arn:aws:s3:::my-bucket/*"],
        )

        issues = await check.execute(statement, 3, fetcher, config)

        assert len(issues) == 1
        assert issues[0].statement_index == 3

    @pytest.mark.asyncio
    async def test_line_number_captured(self, check, fetcher, config):
        """Test that line number is captured when available."""
        statement = Statement(
            Effect="Allow",
            Action=["*"],
            Resource=["arn:aws:s3:::my-bucket/*"],
            line_number=25,
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].line_number == 25

    @pytest.mark.asyncio
    async def test_custom_severity(self, check, fetcher):
        """Test custom severity override."""
        config = CheckConfig(
            check_id="wildcard_action",
            enabled=True,
            severity="high",
        )

        statement = Statement(
            Effect="Allow",
            Action=["*"],
            Resource=["arn:aws:s3:::my-bucket/*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].severity == "high"

    @pytest.mark.asyncio
    async def test_custom_message(self, check, fetcher):
        """Test custom message configuration."""
        config = CheckConfig(
            check_id="wildcard_action",
            enabled=True,
            config={"message": "Custom wildcard action warning"},
        )

        statement = Statement(
            Effect="Allow",
            Action=["*"],
            Resource=["arn:aws:s3:::my-bucket/*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert issues[0].message == "Custom wildcard action warning"

    @pytest.mark.asyncio
    async def test_custom_suggestion(self, check, fetcher):
        """Test custom suggestion configuration."""
        config = CheckConfig(
            check_id="wildcard_action",
            enabled=True,
            config={"suggestion": "Please use specific actions"},
        )

        statement = Statement(
            Effect="Allow",
            Action=["*"],
            Resource=["arn:aws:s3:::my-bucket/*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert "Please use specific actions" in issues[0].suggestion

    @pytest.mark.asyncio
    async def test_suggestion_with_example(self, check, fetcher):
        """Test suggestion includes example when configured."""
        config = CheckConfig(
            check_id="wildcard_action",
            enabled=True,
            config={
                "suggestion": "Use specific actions instead of wildcard",
                "example": "Action: ['s3:GetObject', 's3:PutObject']",
            },
        )

        statement = Statement(
            Effect="Allow",
            Action=["*"],
            Resource=["arn:aws:s3:::my-bucket/*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 1
        assert "Use specific actions instead of wildcard" in issues[0].suggestion
        assert "Example:" in issues[0].suggestion
        assert "Action: ['s3:GetObject', 's3:PutObject']" in issues[0].suggestion

    @pytest.mark.asyncio
    async def test_wildcard_with_resource_wildcard(self, check, fetcher, config):
        """Test wildcard action with wildcard resource (should still be flagged)."""
        statement = Statement(
            Effect="Allow",
            Action=["*"],
            Resource=["*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        # This check only flags the action wildcard
        # full_wildcard check handles the combination
        assert len(issues) == 1
        assert issues[0].issue_type == "overly_permissive"

    @pytest.mark.asyncio
    async def test_empty_actions_not_flagged(self, check, fetcher, config):
        """Test that empty actions list doesn't cause issues."""
        statement = Statement(
            Effect="Allow",
            Action=[],
            Resource=["arn:aws:s3:::my-bucket/*"],
        )

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_none_actions_not_flagged(self, check, fetcher, config):
        """Test that None actions doesn't cause issues."""
        statement = Statement(
            Effect="Allow",
            Resource=["arn:aws:s3:::my-bucket/*"],
        )
        # Manually set Action to None to test edge case
        statement.action = None

        issues = await check.execute(statement, 0, fetcher, config)

        assert len(issues) == 0
